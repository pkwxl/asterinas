// SPDX-License-Identifier: MPL-2.0

//! Directory walks for erofs inodes.
//!
//! This module hosts the on-disk dirent record (`RawDirent`, the
//! sole packed structure on the erofs main column), the by-name
//! lookup (the `erofs_namei` binary-search homologue, namei.c), and
//! the getdents iteration (the `erofs_readdir` homologue, dir.c). It
//! deliberately does not consume `xxh32` — the bloom gate lives in
//! the xattr get chain — and it never updates atime on lookups or
//! reads (G-N07 family: the whole module is read-only).
//!
//! `.` and `..` are ordinary on-disk entries (the disk-read shape;
//! ramfs-style synthesis is deliberately not transcribed): the
//! lookup half applies no special-casing to dot names — every name
//! reaching it is compared byte-wise like any other — and the
//! iteration half emits them like any other slot.
//!
//! # Two strictness domains (r1-baseline-matrix §3.4 — hard constraint)
//!
//! This file hosts BOTH dirent walks; they MUST NOT share derivation:
//!
//! * Lookup half (`lookup`/`lookup_nid`/`find_target_block`/
//!   `find_target_dirent`/`dirnamecmp`/`lookup_nameoff`/
//!   `read_name_region`): every on-disk nameoff is consumed through
//!   `lookup_nameoff` — masked into [0, bs), high bits folding
//!   silently (mask tolerance); the name boundary is the block
//!   structure (next masked nameoff / block end), never i_size.
//! * Iteration half (S06, `readdir_at` family): derives names through
//!   its OWN strictly bounds-checked path; it must NOT call
//!   `lookup_nameoff`/`read_name_region`, and its name boundary is
//!   additionally capped by i_size (maxsize).
//!
//! The only shared surface is the `RawDirent` layout decode
//! (`read_val::<RawDirent>`) — layout is data, not derivation. A
//! malformed nameoff therefore yields DIFFERENT visible results by
//! design (silent fold vs EUCLEAN): r1-baseline-matrix §3.4 rows
//! (`docs/R-01/phase-docs/a-analysis/r1-baseline-matrix.md`).
//!
//! The on-disk NUL-truncation fact is likewise consumed twice,
//! independently (S06 §3.2): the lookup side truncates inside
//! `dirnamecmp`, while the iteration side strnlens only the trailing
//! entry (non-trailing names are emitted at full length). What is
//! shared is the disk fact, never the derivation — do not extract a
//! common helper; that would erase the strictness difference above.

#![short_vis_path::add(erofs)]

use core::{
    cmp::Ordering,
    mem::{offset_of, size_of},
};

use ostd::{const_assert, mm::VmIo};

use super::{
    super::{prelude::*, super_block::NAME_LEN},
    FileKind, Inode,
};
use crate::vm::page_cache::PageCache;

/// The erofs on-disk dirent (`erofs_dirent`,
/// linux/fs/erofs/erofs_fs.h:276-281; field semantics single-sourced
/// in `docs/T-001/analysis.md` §6.3).
///
/// A directory block is the index array (12 × N records) followed by
/// the name area: entry starts are always multiples of 12,
/// N = nameoff[0] / 12, names sort in strict alphabetical order, and
/// the format itself validates none of this — the two walks below
/// keep their own bound checks (the two-domains contract in the
/// module doc). Consumers read the record by value only; taking a
/// reference to a field of a packed structure is forbidden (A3).
// No deadness attribute: the permanent `const_assert!` layout
// anchors below reference the type and each of its fields, so both
// stay live in every cfg and an `#[expect(dead_code)]` would only be
// reported unfulfilled (same rationale as `RawDeviceSlot` in
// `super_block.rs`).
//
// `#[repr(C, packed)]` is load-bearing (A3): under the natural
// layout the le64 `nid` member would tail-pad the record to 16
// bytes, while the C side is `__packed` down to 12 (BUILD_BUG_ON at
// erofs_fs.h:451) — a plain `#[repr(C)]` would fail the size
// assertion below. This is the only packed structure on the erofs
// main column.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct RawDirent {
    /// The target inode number; no bound or existence check of any
    /// kind — iget is the backstop.
    pub nid: u64, // @0  __le64
    /// The in-block start offset of this entry's name. The two walk
    /// paths keep different strictnesses — readdir bounds-checks
    /// strictly while lookup masks with `blocksize - 1` (G8; each
    /// path preserves its own form, the two-domains contract).
    pub nameoff: u16, // @8  __le16
    /// Generic FT_* value domain, unchecked: readdir converts to
    /// DT_* through `file_type_to_dtype` (values ≥ 8 silently
    /// degrade to Unknown) while lookup never reads the field.
    /// The field stays a raw u8 (T-011 §2.2: no enum-ization of the
    /// disk field).
    pub file_type: u8, // @10 __u8
    /// Reserved; never read (G5).
    pub reserved: u8, // @11 __u8
}

// Layout triple and per-field offsets (A1), each anchored to
// linux/fs/erofs/erofs_fs.h; the source-side counterpart of the size
// assertion is BUILD_BUG_ON at erofs_fs.h:451.
const_assert!(size_of::<RawDirent>() == 12); // erofs_fs.h:451
const_assert!(align_of::<RawDirent>() == 1); // __packed pins the alignment to 1
const_assert!(offset_of!(RawDirent, nid) == 0); // erofs_fs.h:277
const_assert!(offset_of!(RawDirent, nameoff) == 8); // erofs_fs.h:278
const_assert!(offset_of!(RawDirent, file_type) == 10); // erofs_fs.h:279
const_assert!(offset_of!(RawDirent, reserved) == 11); // erofs_fs.h:280

// ---------------------------------------------------------------------------
// Lookup half — the erofs_namei homologue (linux/fs/erofs/namei.c:16-215;
// `docs/T-013/S05/index.md` §2–§4, §7.1). Seven functions: the comparison
// semantics with the prefix carry, the single-point mask helper, the name
// region read, the two binary-search layers, the walk entry, and the
// namei+iget assembly. Private family + one entry; every on-disk nameoff
// consumption goes through `lookup_nameoff` (the two-domains contract).
// No linear scan anywhere: the two search layers are faithful binary
// searches (hard constraint 3, S05-R1).
// ---------------------------------------------------------------------------

/// Three-way comparison of the query name `qn` against one on-disk
/// name region `qd` (bytes [start, end) of the block, see
/// `read_name_region`). Byte-wise, unsigned, case-sensitive, no
/// normalization (EROFS has no s_encoding). `matched` is the
/// prefix-carry in/out index — it is part of the baseline semantics,
/// NOT a pure optimization (S05-R1: the carry reproduces Linux's
/// binary-search trajectory pointwise on out-of-order images).
///
/// NUL inside `qd` truncates the on-disk name silently
/// (namei.c:29-31); an inverted/empty region skips the loop and
/// compares as an empty name (namei.c:22-27 drift, no error).
fn dirnamecmp(qn: &[u8], qd: &[u8], matched: &mut usize) -> Ordering {
    let mut i = *matched;
    // qd could not have trailing '\0'; a mid-name NUL ends the loop.
    while i < qd.len() && qd[i] != b'\0' {
        // C reads qn->name[i] off a NUL-terminated buffer: past-the-end
        // reads as '\0' (the smallest byte).
        let qc = qn.get(i).copied().unwrap_or(b'\0');
        if qc != qd[i] {
            *matched = i;
            return if qc > qd[i] {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        i += 1;
    }
    *matched = i;
    // Equal iff the query is exhausted at the same position (an
    // exact-C port: a hypothetical embedded NUL in `qn` would exhaust
    // here too). (`is_none_or` = the sample's `map_or(true, …)`; the
    // nightly clippy `unnecessary_map_or` lint forbids the latter
    // form.)
    if qn.get(i).is_none_or(|&c| c == b'\0') {
        Ordering::Equal
    } else {
        Ordering::Greater
    }
}

/// `nameoff_from_disk` homologue (namei.c:43): decode + mask the raw
/// le16 nameoff into [0, bs). Out-of-range high bits FOLD SILENTLY
/// (mask tolerance). LOOKUP SIDE ONLY — the iteration half (the
/// `readdir_at` family below) derives nameoffs through its own
/// strictly bounds-checked path and must NOT call this helper
/// (r1-baseline-matrix §3.4; see the module doc "Two strictness
/// domains").
#[inline]
fn lookup_nameoff(raw: u16, bs: usize) -> usize {
    (u16::from_le(raw) as usize) & (bs - 1)
}

/// Reads the on-disk name at block-relative [start, end). Bounds:
/// start, end ∈ [0, bs] (both derived via `lookup_nameoff`, or
/// end = bs for the 1st/last entry) — always inside the probed
/// block. An INVERTED interval (start > end, malformed nameoff
/// chain) reads zero bytes and yields an empty slice: the
/// empty-name comparison drift of namei.c:22-27, no error. Allocation
/// failure is the aster abort family (F4/G-M21) — no Err arm.
fn read_name_region(
    page_cache: &PageCache,
    block_off: usize,
    start: usize,
    end: usize,
) -> Result<Vec<u8>> {
    let len = end.saturating_sub(start); // inverted → 0, no read at all
    let mut buf = vec![0u8; len];
    page_cache.read_bytes(block_off + start, &mut buf)?; // N7 passthrough
    Ok(buf)
}

/// Outcome of the block-level binary search (namei.c:95,143-158).
enum TargetBlock {
    /// Block-head hit: diff == 0 against the block's FIRST name —
    /// the head dirent IS the match (namei.c:143-146,
    /// `*_ndirents = 0` skips the in-block search).
    HeadHit { de: RawDirent },
    /// Last probed block whose first name compared Greater
    /// (namei.c:147-151 `candidate`): the in-block search runs here.
    /// `ndirents` = masked nameoff0 / 12 of THAT block.
    Candidate { block_off: usize, ndirents: usize },
}

/// Block-level binary search with the candidate retention
/// (namei.c:89-159). Three-way dispatch per probe: Less descends,
/// Equal returns the block-head hit, Greater records the candidate
/// and ascends; loop exhausted with no candidate → ENOENT.
fn find_target_block(
    page_cache: &PageCache,
    bs: usize,
    size: u64, // desc.size; > 0 guaranteed by the N4 gate
    qn: &[u8],
) -> Result<TargetBlock> {
    // N6 — the block count derives from i_size (round_up/bs); the
    // int-domain mirror of `int back = erofs_iblks(dir) - 1`
    // (S05-D4): the 32-bit truncation is Linux-DEFINED behavior on
    // crafted giant-size dirs and is reproduced here (a negative
    // back skips the loop → ENOENT, same as C).
    let nblocks = size.div_ceil(bs as u64);
    let mut head: i64 = 0;
    let mut back: i64 = ((nblocks - 1) & 0xFFFF_FFFF) as u32 as i32 as i64;
    let (mut startprfx, mut endprfx) = (0usize, 0usize); // S05-R1 carry
    let mut candidate: Option<(usize, usize)> = None;

    while head <= back {
        let mid = head + (back - head) / 2;
        let block_off = (mid as usize) * bs; // erofs_pos(sb, mid)
        let de0: RawDirent = page_cache.read_val(block_off)?; // N7
        let nameoff0 = lookup_nameoff(de0.nameoff, bs); // N8 mask
        let ndirents = nameoff0 / size_of::<RawDirent>();
        if ndirents == 0 {
            // N8
            return_errno_with_message!(Errno::EUCLEAN, "corrupted dir block");
        }
        let name_end = if ndirents == 1 {
            // N9
            bs
        } else {
            let de1: RawDirent = page_cache.read_val(block_off + size_of::<RawDirent>())?;
            lookup_nameoff(de1.nameoff, bs)
        };
        let mut matched = startprfx.min(endprfx); // S05-R1
        let qd = read_name_region(page_cache, block_off, nameoff0, name_end)?;
        match dirnamecmp(qn, &qd, &mut matched) {
            Ordering::Less => {
                // N10a
                back = mid - 1;
                endprfx = matched;
            }
            Ordering::Equal => {
                // N10b
                return Ok(TargetBlock::HeadHit { de: de0 });
            }
            Ordering::Greater => {
                // N10c
                candidate = Some((block_off, ndirents));
                head = mid + 1;
                startprfx = matched;
            }
        }
    }
    match candidate {
        // namei.c:158
        Some((block_off, ndirents)) => Ok(TargetBlock::Candidate {
            block_off,
            ndirents,
        }),
        None => return_errno_with_message!(Errno::ENOENT, "name not found"),
    }
}

/// In-block binary search over dirent slots 1..=ndirents-1
/// (namei.c:45-87; slot 0 was already evaluated by the block level,
/// namei.c:54-56). The last entry's name ends at the block end
/// (`end = bs`); loop exhausted → None (ENOENT at the caller).
fn find_target_dirent(
    page_cache: &PageCache,
    block_off: usize,
    bs: usize,
    ndirents: usize, // from the Candidate outcome
    qn: &[u8],
) -> Result<Option<RawDirent>> {
    // The 1st dirent was already evaluated by the block level
    // (namei.c:54-56) — search slots 1..=ndirents-1.
    let mut head: i64 = 1;
    let mut back: i64 = ndirents as i64 - 1;
    let (mut startprfx, mut endprfx) = (0usize, 0usize);

    while head <= back {
        let mid = head + (back - head) / 2;
        let de_mid: RawDirent =
            page_cache.read_val(block_off + mid as usize * size_of::<RawDirent>())?;
        let nameoff = lookup_nameoff(de_mid.nameoff, bs);
        // `mid >= ndirents - 1` in C; mid <= ndirents-1 here, so >= is ==.
        let name_end = if mid >= ndirents as i64 - 1 {
            bs
        } else {
            let de_next: RawDirent =
                page_cache.read_val(block_off + (mid as usize + 1) * size_of::<RawDirent>())?;
            lookup_nameoff(de_next.nameoff, bs)
        };
        let mut matched = startprfx.min(endprfx);
        let qd = read_name_region(page_cache, block_off, nameoff, name_end)?;
        match dirnamecmp(qn, &qd, &mut matched) {
            Ordering::Equal => return Ok(Some(de_mid)), // :75-76
            Ordering::Greater => {
                head = mid + 1;
                startprfx = matched;
            }
            Ordering::Less => {
                back = mid - 1;
                endprfx = matched;
            }
        }
    }
    Ok(None) // :86 ENOENT
}

impl Inode {
    /// `erofs_namei` homologue (namei.c:161-191). Returns the hit nid
    /// FULL-WIDTH and UNVALIDATED (N13: out-of-range nids are caught
    /// by the iget read errors; nid = 0 proceeds like any nid).
    /// Err face: ENOTDIR (N1 depth guard) / ENOENT (N4 empty dir,
    /// N10/N11 miss) / EUCLEAN (N8) / read passthrough (N7).
    /// Reads go through the DIR payload's page cache; zero atime
    /// writes (G-N07 family).
    fn lookup_nid(&self, name: &str) -> Result<ErofsNid> {
        // N1 defensive depth: non-DIR replicates the trait default
        // face (vfs inode.rs:447-449; ext2 find_entry_info:682-684);
        // the regular flow never reaches it (the resolver checks
        // first).
        if self.kind() != FileKind::Dir {
            return_errno_with_message!(Errno::ENOTDIR, "inode is not a directory");
        }
        let desc = self.desc();
        // N4 (S05-D2): an empty directory answers ENOENT before any
        // block read (namei.c:169-170).
        if desc.size == 0 {
            return_errno_with_message!(Errno::ENOENT, "empty directory");
        }
        let fs = self.fs()?;
        let qn = name.as_bytes(); // N5 (four premises hold at the VFS)
        // DIR payload is DataBacked by construction (S02 §3.1 DIR
        // row: compressed layouts never survive iget — S02-R1).
        let page_cache = self.page_cache().expect("DIR payload is DataBacked");
        let bs = fs.super_block().block_size();

        match find_target_block(page_cache, bs, desc.size, qn)? {
            TargetBlock::HeadHit { de } => Ok(u64::from_le(de.nid)), // N10b/N13
            TargetBlock::Candidate {
                block_off,
                ndirents,
            } => {
                match find_target_dirent(page_cache, block_off, bs, ndirents, qn)? {
                    Some(de) => Ok(u64::from_le(de.nid)), // N13
                    None => return_errno_with_message!(Errno::ENOENT, "name not found"),
                }
            }
        }
    }

    /// `erofs_lookup` body (namei.c:193-215): namei, then iget. The
    /// hit/ENOENT result face is handled by the framework (a miss
    /// inserts the negative dentry; errors are never cached and
    /// replay on every call, N14). `./..` carry no special-casing —
    /// a dot name reaching here is compared byte-wise like any other
    /// (the VFS consumes path dots before the FS lookup).
    // Bridging expect: the trait face still returns the transitional
    // EOPNOTSUPP until the S05 rewrite forwards `Ok(self.lookup(name)?)`
    // — first consumer: S05.
    #[expect(dead_code)]
    pub(in crate::fs::fs_impls::erofs) fn lookup(&self, name: &str) -> Result<Arc<Inode>> {
        let nid = self.lookup_nid(name)?; // erofs_namei
        self.fs()?.iget(nid) // erofs_iget (N14; I-family incl. I12)
    }
}

// ---------------------------------------------------------------------------
// Iteration half — the erofs_readdir homologue (linux/fs/erofs/dir.c:9-102;
// `docs/T-013/S06/index.md` §2–§3). Three functions: the cursor-walk entry,
// the per-window fill loop, and the d_type conversion. Name derivation is
// STRICTLY bounds-checked (R5/R10, EUCLEAN) on the RAW le16 nameoffs — no
// mask, no call into the lookup half's helpers (the two-domains contract).
// ---------------------------------------------------------------------------

/// Outcome of the fill loop for one block window (dir.c:9-45).
/// `Stopped` = the visitor refused an entry (buffer full / embedded
/// NUL / user-buffer fault) — NOT an error: the walk halts with the
/// cursor at the refused entry's header (dir_emit false / return 1).
enum FillOutcome {
    Complete,
    Stopped,
}

impl Inode {
    /// `erofs_readdir` homologue (dir.c:47-96). The call is a cursor
    /// walk over the directory byte stream starting at `offset`; the
    /// return value is the BYTE ADVANCE to be added by the caller
    /// (inode_handle.rs:132-135) — it includes block jumps and the
    /// EOF fold to i_size (seven-element cookie model, element 7).
    ///
    /// Err face: ENOTDIR (depth guard) / EUCLEAN (R5/R10) / EIO
    /// (G-N04 non-UTF-8 name, G-N05 slash name) / read passthrough
    /// (R4). Zero atime writes (G-N07); no iget, no I-family errors
    /// (the walk emits whatever the slots say, nid = 0 included).
    // Bridging expect: the trait face still returns the transitional
    // EOPNOTSUPP until the S05 rewrite forwards to this inherent
    // method — first consumer: S05.
    #[expect(dead_code)]
    pub(in crate::fs::fs_impls::erofs) fn readdir_at(
        &self,
        offset: usize,
        visitor: &mut dyn DirentVisitor,
    ) -> Result<usize> {
        // Depth guard replicating the FileOps default face (the
        // two-layer guard narrative belongs to S07; the syscall
        // layer checks first).
        if self.kind() != FileKind::Dir {
            return_errno_with_message!(Errno::ENOTDIR, "inode is not a directory");
        }
        let desc = self.desc();
        let size = desc.size; // u64 (R3 bound)
        // DIR payload is DataBacked by construction (S02 §3.1).
        let page_cache = self.page_cache().expect("DIR payload is DataBacked");
        let bs = self.fs()?.super_block().block_size();

        let start = offset;
        let mut pos = offset;
        let mut ofs = pos % bs; // erofs_blkoff (R3)
        let mut initial = true;

        while (pos as u64) < size {
            // R3 (usize→u64 lossless on 64-bit targets)
            let dbstart = pos - ofs; // block window base
            // R4 — first-touch read of the window head; page-
            // granularity fill makes the error face whole-block (the
            // S05 §4.4 argument applies verbatim).
            let de0: RawDirent = page_cache.read_val(dbstart)?;
            // R5 — STRICT check on the RAW le16 (NO mask here; the
            // lookup half masks via lookup_nameoff — the two
            // strictness domains of the module doc).
            let nameoff0 = u16::from_le(de0.nameoff) as usize;
            if nameoff0 == 0 || nameoff0 >= bs || !nameoff0.is_multiple_of(size_of::<RawDirent>()) {
                return_errno_with_message!(Errno::EUCLEAN, "invalid de[0].nameoff");
            }
            // R6 — min_t(unsigned int, size - dbstart, bsz): the u32
            // TRUNCATION is mirrored (S06-D4); size - dbstart >= 1
            // in-loop (pos < size, dbstart <= pos).
            let maxsize = ((size - dbstart as u64) as u32).min(bs as u32) as usize;

            if initial {
                // R7
                initial = false;
                // roundup(ofs, 12) — the kernel `align_up` helpers
                // are power-of-two-only, so the division form of the
                // C `roundup` macro is written out.
                ofs = ofs.div_ceil(size_of::<RawDirent>()) * size_of::<RawDirent>();
                pos = dbstart + ofs;
            }

            match fill_dentries(
                page_cache, dbstart, ofs, nameoff0, maxsize, &mut pos, visitor,
            )? {
                FillOutcome::Stopped => return Ok(pos - start), // R11: halt here
                FillOutcome::Complete => {}
            }
            // R13 — block tail jump (folds into the advance and into
            // the last visit offset, the cookie model elements 3/4).
            pos = dbstart + maxsize;
            ofs = 0;
        }
        Ok(pos - start) // R14 shape
    }
}

/// `erofs_fill_dentries` homologue (dir.c:9-45). Walks dirent slots
/// [start_off, nameoff0) of the window at `dbstart`, maintaining
/// `*pos` = dbstart + current slot header (R11/R12: advanced only
/// after a successful visit — a refused entry is retried verbatim by
/// the next call).
fn fill_dentries(
    page_cache: &PageCache,
    dbstart: usize,
    start_off: usize, // 12-aligned cursor (R7 roundup applied)
    nameoff0: usize,  // STRICT-decoded index-area bound
    maxsize: usize,   // R6 (u32-mirrored)
    pos: &mut usize,
    visitor: &mut dyn DirentVisitor,
) -> Result<FillOutcome> {
    const DIRENT_SIZE: usize = size_of::<RawDirent>(); // 12

    let mut de_off = start_off;
    debug_assert_eq!(de_off % DIRENT_SIZE, 0); // R5+R7 premises
    debug_assert_eq!(*pos, dbstart + de_off);

    while de_off < nameoff0 {
        // de < end
        let de: RawDirent = page_cache.read_val(dbstart + de_off)?; // R4 family
        let nameoff = u16::from_le(de.nameoff) as usize; // RAW

        // R9 — namelen derivation.
        let de_namelen: u32 = if de_off + DIRENT_SIZE < nameoff0 {
            // non-trailing: RAW difference, the u32 wrap mirrors the
            // C int→unsigned demotion (inverted chains go huge and
            // fall to R10 below).
            let next: RawDirent = page_cache.read_val(dbstart + de_off + DIRENT_SIZE)?;
            (u16::from_le(next.nameoff) as u32).wrapping_sub(nameoff as u32)
        } else if maxsize <= nameoff {
            // trailing with the name start beyond the window bound —
            // bogus (dir.c:24-25).
            return_errno_with_message!(Errno::EUCLEAN, "bogus dirent");
        } else {
            // trailing: strnlen(de_name, maxsize - nameoff) — the
            // ONLY NUL scan on the iteration side (the two-domains
            // note in the module doc).
            let scan = maxsize - nameoff;
            let mut buf = vec![0u8; scan]; // F4 abort family
            page_cache.read_bytes(dbstart + nameoff, &mut buf)?;
            buf.iter().position(|&b| b == 0).unwrap_or(scan) as u32
        };

        // R10 — in_range32(namelen, 1, NAME_LEN) with the SAME
        // short-circuit order (the `nameoff + de_namelen` compare
        // only runs once namelen ∈ [1,255], hence no wrap).
        let name_len = de_namelen as usize;
        if !(1..=(NAME_LEN as u32)).contains(&de_namelen)
            || nameoff as u32 + de_namelen > maxsize as u32
        {
            return_errno_with_message!(Errno::EUCLEAN, "bogus dirent");
        }

        // R11 pre-entry reads (bounded: [nameoff, nameoff+len) ⊆
        // [dbstart, dbstart+maxsize) — reads never leave the window).
        let mut name_buf = vec![0u8; name_len]; // F4 abort family
        page_cache.read_bytes(dbstart + nameoff, &mut name_buf)?;

        // Prechecks AFTER the structural gate — order pinned by
        // S06-D5: R5 → R9 → R10 → slash (G-N05) → UTF-8 (G-N04) →
        // visit. The slash goes first: byte judgement, no dependency
        // on the UTF-8 decode (the two checks' relative order is
        // unobservable anyway — same errno, same stop point).
        if name_buf.contains(&b'/') {
            // G-N05 (first)
            return_errno_with_message!(Errno::EIO, "entry name contains slash");
        }
        let name = core::str::from_utf8(&name_buf).map_err(|_| {
            // G-N04 — ext2 precedent ext2/inode/dir/mod.rs:557-558.
            Error::with_message(Errno::EIO, "invalid dir entry name")
        })?;

        // R8 — d_type from the dirent byte only, no cross-check.
        let dtype = file_type_to_dtype(de.file_type);
        let nid = u64::from_le(de.nid); // full-width, nid=0 ok

        // F18 visit-offset synthesis — NEXT basis (S06-D1): the next
        // slot header, or the block tail (= next block start /
        // i_size at EOF) for the window's last entry.
        let visit_off = if de_off + DIRENT_SIZE < nameoff0 {
            dbstart + de_off + DIRENT_SIZE
        } else {
            dbstart + maxsize
        };

        if visitor.visit(name, nid, dtype, visit_off).is_err() {
            // dir_emit false ≈ (dir.c:36 `return 1`): success-return
            // with the cursor at THIS entry. All visit errors are
            // swallowed identically — buffer full (EINVAL), embedded
            // NUL (EINVAL, W-N07), user-buffer fault (EFAULT) — the
            // FS cannot and must not distinguish them (hard
            // constraint 3; W-N05/W-N06 family).
            return Ok(FillOutcome::Stopped);
        }
        de_off += DIRENT_SIZE; // R12
        *pos = dbstart + de_off;
    }
    Ok(FillOutcome::Complete)
}

/// `fs_ftype_to_dtype` homologue (linux/fs/fs_types.c:8-17,37-43;
/// the on-disk FT_* values are the generic fs types, erofs_fs.h:283-287
/// comment). FT 1..=7 map one-to-one; 0 and >= 8 degrade to Unknown
/// SILENTLY — the parity point of r1-baseline-matrix §3.5 row 1.
/// Raw u8 in, no enum-ization of the disk field (T-011 §2.2).
#[inline]
fn file_type_to_dtype(file_type: u8) -> InodeType {
    match file_type {
        1 => InodeType::File,        // FT_REG_FILE  → DT_REG
        2 => InodeType::Dir,         // FT_DIR       → DT_DIR
        3 => InodeType::CharDevice,  // FT_CHRDEV    → DT_CHR
        4 => InodeType::BlockDevice, // FT_BLKDEV    → DT_BLK
        5 => InodeType::NamedPipe,   // FT_FIFO      → DT_FIFO
        6 => InodeType::Socket,      // FT_SOCK      → DT_SOCK
        7 => InodeType::SymLink,     // FT_SYMLINK   → DT_LNK
        _ => InodeType::Unknown,     // 0 & >= 8     → DT_UNKNOWN
    }
}

#[cfg(ktest)]
mod tests {
    use core::{cmp::Ordering, mem::size_of};

    use ostd::prelude::*;

    use super::*;
    use crate::fs::file::InodeType;

    /// Pointwise comparison-semantics table (LKP-11, `docs/T-013/S05/
    /// index.md` §9): NUL truncation, inverted/empty regions, query
    /// exhaustion, unsigned byte order, case sensitivity, and the
    /// prefix-carry in/out index.
    #[ktest]
    fn dirnamecmp_pointwise_vectors() {
        let cmp = |qn: &[u8], qd: &[u8], matched: usize| {
            let mut m = matched;
            let ord = dirnamecmp(qn, qd, &mut m);
            (ord, m)
        };

        // Exact hit: both sides exhausted at the same position.
        assert_eq!(cmp(b"ab", b"ab", 0), (Ordering::Equal, 2));
        // On-disk NUL truncates: "ab\0c" compares as "ab".
        assert_eq!(cmp(b"ab", b"ab\0c", 0), (Ordering::Equal, 2));
        // ... against the longer query: qn[2] = 'c' > '\0' → Greater.
        assert_eq!(cmp(b"abc", b"ab\0c", 0), (Ordering::Greater, 2));
        // Query past-the-end reads as '\0' (the C NUL-terminated
        // buffer, namei.c:33-35).
        assert_eq!(cmp(b"a", b"ab", 0), (Ordering::Less, 1));
        // Empty region: compares as an empty name (the namei.c:22-27
        // drift — no error).
        assert_eq!(cmp(b"", b"", 0), (Ordering::Equal, 0));
        assert_eq!(cmp(b"a", b"", 0), (Ordering::Greater, 0));
        // Case-sensitive, unsigned byte order: 'A' (0x41) < 'a' (0x61).
        assert_eq!(cmp(b"A", b"a", 0), (Ordering::Less, 0));
        // High-bit bytes compare UNSIGNED: 0xFF > 0x80.
        assert_eq!(cmp(b"\xff", b"\x80", 0), (Ordering::Greater, 0));
        // The carry skips the matched prefix (entry point i = matched).
        assert_eq!(cmp(b"ab", b"abz", 1), (Ordering::Less, 2));

        // --- The three-probe counterexample of S05 §2.2 (q = "ab") ---
        // probe 1, block head "aa", matched = min(0, 0) = 0:
        //   i=1: 'b' > 'a' → Greater, carry 1 (startprfx = 1).
        assert_eq!(cmp(b"ab", b"aa", 0), (Ordering::Greater, 1));
        // probe 2, block head "abz", matched = min(1, 0) = 1:
        //   i=1: 'b' = 'b'; i=2: '\0' < 'z' → Less, carry 2
        //   (endprfx = 2).
        assert_eq!(cmp(b"ab", b"abz", 1), (Ordering::Less, 2));
        // probe 3, block head "bb", matched = min(1, 2) = 1 — the
        // index-0 mismatch ('b' vs 'a') is NEVER compared: the loop
        // validates [1, 2) only and runs off the region end → Equal,
        // the prefix-carry FALSE HIT (a naive from-zero comparison
        // would answer Less and end the walk in ENOENT — the S05-R1
        // parity point on out-of-order images).
        assert_eq!(cmp(b"ab", b"bb", 1), (Ordering::Equal, 2));
    }

    /// The two-strictness-domains pin (LKP-04 + LKR-03/06 shape, hard
    /// constraint 2 / analysis.md §4.4 means 3): ONE raw nameoff
    /// input, TWO pinned behaviors. The lookup-domain columns are
    /// EXECUTED against `lookup_nameoff` (the mask fold, and the N8
    /// door it feeds: ndirents = fold/12, zero → "corrupted dir
    /// block"); the iteration-domain column pins the R5 expectation
    /// table (RAW le16, NO mask: nameoff0 ∈ {0, ≥ bs, non-multiple-
    /// of-12} → EUCLEAN). Executing the R5 column needs a malformed-
    /// dirent fixture (T-027, IMG-CRAFT-DIRENT / LKR-06); the
    /// predicate transcription inside only keeps the TABLE
    /// self-consistent — the visible-divergence row (lookup ACCEPTS
    /// while iteration REJECTS the same bytes) is asserted now, as
    /// the mechanical carrier of the two-domains contract.
    #[ktest]
    fn lookup_nameoff_fold_and_two_domain_pin() {
        let bs = 4096usize;
        // (raw le16, lookup fold, lookup accepts (N8 off), iteration R5 rejects)
        const TWO_DOMAINS: &[(u16, usize, bool, bool)] = &[
            (12, 12, true, false),       // healthy in both domains (ndirents 1)
            (24, 24, true, false),       // healthy both (ndirents 2)
            (4096 + 24, 24, true, true), // VISIBLE DIVERGENCE: high
            // bits fold to 24 — lookup takes ndirents = 2 and reads
            // on; the RAW value ≥ bs → iteration EUCLEAN.
            (8192 + 12, 12, true, true), // same shape, one block up
            (13, 13, true, true),        // LKP-06: non-multiple of 12 —
            // lookup takes it (ndirents = 1) while iteration rejects
            (25, 25, true, true),       // non-multiple below bs, same split
            (4096 + 8, 8, false, true), // LKP-04 verbatim fold: 8 →
            // ndirents = 0 → lookup N8 EUCLEAN (SAME errno as the
            // iteration side's ≥ bs — different mechanism row, the
            // matrix §3.4 same-errno-different-row family)
            (0, 0, false, true),    // lookup: fold 0 → N8; iteration: == 0
            (4096, 0, false, true), // folds to 0 (N8); raw == bs → R5
        ];

        let mut visible_divergence = 0;
        for &(raw, fold, lookup_accepts, iter_rejects) in TWO_DOMAINS {
            let folded = lookup_nameoff(raw, bs);
            assert_eq!(folded, fold, "fold of raw = {}", raw);
            // The lookup-domain acceptance derives from the fold
            // alone (N8 fires iff ndirents == 0) — executed behavior.
            assert_eq!(
                folded / size_of::<RawDirent>() >= 1,
                lookup_accepts,
                "lookup acceptance of raw = {}",
                raw
            );
            // Table self-consistency against the R5 predicate
            // transcription (implementation-side execution = T-027).
            let r5 = raw as usize == 0
                || raw as usize >= bs
                || raw as usize % size_of::<RawDirent>() != 0;
            assert_eq!(r5, iter_rejects, "R5 expectation of raw = {}", raw);
            if lookup_accepts && iter_rejects {
                visible_divergence += 1;
            }
        }
        // The two-domains contract is ALIVE: at least one same-input
        // row where the two walks disagree visibly (silent fold vs
        // EUCLEAN) — r1-baseline-matrix §3.4.
        assert!(visible_divergence >= 1);
    }

    /// Full-domain d_type table (LKR-03): 0 → Unknown, 1..=7 → the
    /// seven one-to-one mappings, ≥ 8 → Unknown (silent degradation,
    /// R8 — no cross-check against the inode, no error).
    #[ktest]
    fn file_type_to_dtype_full_domain() {
        assert_eq!(file_type_to_dtype(0), InodeType::Unknown);
        let seven: [(u8, InodeType); 7] = [
            (1, InodeType::File),
            (2, InodeType::Dir),
            (3, InodeType::CharDevice),
            (4, InodeType::BlockDevice),
            (5, InodeType::NamedPipe),
            (6, InodeType::Socket),
            (7, InodeType::SymLink),
        ];
        for &(ft, want) in &seven {
            assert_eq!(file_type_to_dtype(ft), want, "ft = {}", ft);
        }
        for ft in 8u8..=255 {
            assert_eq!(file_type_to_dtype(ft), InodeType::Unknown, "ft = {}", ft);
        }
    }
}
