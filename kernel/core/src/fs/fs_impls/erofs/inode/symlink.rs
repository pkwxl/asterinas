// SPDX-License-Identifier: MPL-2.0

//! The erofs symlink faces: the fast/slow split judgement and the
//! inline-target read, both consumed by the LNK arm of the payload
//! assembly (`InodePayload::new`, `inode/mod.rs`), plus the unified
//! `read_link` exit that serves both payload forms (below).
//!
//! What "slow symlinks are cut" means (C-6g, `docs/T-013/analysis.md`
//! §3.2 — the correct reading of the early skeleton note): the cut
//! is the ext2-style *dedicated slow-symlink mechanism* — the
//! fixed-size inline target array (`FastSymlinkTarget`), the
//! `MAX_FAST_SYMLINK_LEN` gate, and the write-side split. It is NOT
//! a behavior cut: slow symlinks (LNK × FLAT_PLAIN / CHUNK_BASED,
//! and FLAT_INLINE failing the criterion) are fully preserved
//! through the DataBacked payload and the page cache — `read_link`
//! reads the very same bytes through that path. The fast/slow split
//! is purely an internal payload choice; both arms produce the same
//! readlink output.
//!
//! The precise inline start is `inline_data_start` — inode end plus
//! the inline-xattr area — never a bare "just past the inode body":
//! a read anchored at the inode body would fetch the wrong bytes on
//! any image whose inodes carry inline xattrs.

#![short_vis_path::add(erofs)]

use ostd::mm::VmIo;

use super::{
    super::{fs::Erofs, prelude::*},
    DataLayout, FileKind, Inode, InodeDesc, InodePayload,
};

/// L3 three-element fast/slow criterion in absolute byte-offset form
/// (the terminal rewrite of the T-011 S07 §5.1 sketch anchor, S04-D1;
/// `docs/T-013/analysis.md` §3.1, `docs/T-013/S04/index.md` §1.2–1.3):
/// the aster homologue of `erofs_fill_symlink`'s decision
/// (linux inode.c:15-21), evaluated in absolute device coordinates.
///
/// Pure in-memory geometry: no device I/O, no locks (R1-safe inside
/// the iget critical section). The call site is the LNK arm of
/// `InodePayload::new`, strictly AFTER the I12 arm-head gate, so the
/// datalayout here is one of {0, 2, 4}:
///
/// 1. `datalayout == FLAT_INLINE`, otherwise slow ({0, 4} → slow;
///    {1, 3} were already rejected by the gate);
/// 2. `inline_start.checked_add(size)` — `None` → slow (the
///    `check_add_overflow` homologue; the u64-vs-i64 algebraic
///    difference is registered, S04 §1.4: the i64 sign-bit overflow
///    Linux can take is unreachable at u64 width after a successful
///    decode, and every value the i64 path rejects also fails
///    element ③, so the two forms agree pointwise);
/// 3. `end ≤ round_up(inode_end, bs)` — the boundary anchor is the
///    block containing the inode's LAST byte (F-1′: NOT
///    `round_up(inline_data_start)` — that sketch anchor diverges on
///    the giant-xattr corner), boundary-exact end allowed (the
///    `off > i_blocksize` mirror, `≤` passes).
pub(super) fn is_fast_symlink(fs: &Erofs, nid: ErofsNid, desc: &InodeDesc) -> bool {
    // Element ① — datalayout == FLAT_INLINE (inode.c:18).
    if desc.datalayout != DataLayout::FlatInline {
        return false;
    }
    let bs = fs.super_block().block_size() as u64;
    let inode_end = super::suffix_xattr_start(fs.super_block(), nid, desc);
    // Geometry adds are structurally wrap-free at this point: the
    // decode already read [iloc, iloc + inode_isize) off the device,
    // so inode_end is device-bounded; xattr_isize ≤ 262148 (the le16
    // icount bound) cannot push past u64 on any real device (see
    // S04 §1.4 for the reachability accounting).
    let inline_start = inode_end + desc.xattr_isize as u64;
    // Elements ② (no overflow) and ③ (end within the block holding
    // the inode's last byte, boundary-exact allowed).
    match inline_start.checked_add(desc.size) {
        // Element ③: end within the block holding the inode's last
        // byte, boundary-exact allowed — `div_ceil(bs) * bs` is
        // round_up(inode_end, bs).
        Some(end) => end <= inode_end.div_ceil(bs) * bs,
        // Element ② failed: overflow → slow.
        None => false,
    }
}

/// Reads the FLAT_INLINE symlink target bytes (read site #14,
/// `docs/T-011/S07/index.md` §3.2): `desc.size` bytes at
/// `inline_data_start` — the aster homologue of the `kmemdup_nul`
/// copy (linux inode.c:23-24).
///
/// Byte-stream read, naturally cross-block (RD3): covers the
/// cross-block slot whose target lives in the second metadata
/// block. Err face = the I2 device read, passed through as-is (C2 —
/// no message added, no errno folding). `i_size == 0` → empty vec,
/// zero allocations (the F4/I9 abort-family note: a non-empty
/// allocation failure is an abort, never an Err arm, G-M21).
///
/// Only ever called on the fast arm (the criterion proved
/// `size < block_size`), so the buffer is bounded by the fast-path
/// upper limit.
pub(super) fn read_inline_target(fs: &Erofs, nid: ErofsNid, desc: &InodeDesc) -> Result<Vec<u8>> {
    let start = super::inline_data_start(fs.super_block(), nid, desc);
    // size ≤ i64::MAX (the decode invariant), so the usize cast is
    // loss-free on 64-bit targets.
    let mut buf = vec![0u8; desc.size as usize];
    fs.block_device().read_bytes(start as usize, &mut buf)?; // I2 passthrough
    Ok(buf)
}

impl Inode {
    /// Reads the symlink target as a UTF-8 string — the unified exit
    /// for both payload forms (the aster homologue of the erofs iops
    /// split: fast = `simple_get_link` returning `i_link` directly,
    /// slow = `page_get_link`; the two iops are absorbed by "payload
    /// choice + one exit", T-003 §2.1 L5). EROFS always yields
    /// `SymbolicLink::Plain` at the dispatch face (the Path variant
    /// is procfs-only, `vfs/fs_apis/inode.rs:729-742`).
    ///
    /// Err face: EISDIR (non-LNK, below) / page-read passthrough
    /// (slow arm) / EIO (non-UTF-8 target, G-N02 candidate ①).
    // Live since T-024 S05: the VFS adapter forwards
    // `self.read_link().map(SymbolicLink::Plain)` through its
    // `read_link` override.
    pub(in crate::fs::fs_impls::erofs) fn read_link(&self) -> Result<String> {
        // Kind guard first: non-LNK replicates the trait default
        // face (EISDIR, `vfs/fs_apis/inode.rs:461-463`) — this IS
        // the readlink(2)-on-non-LNK errno (SYM-08). A Rust trait
        // impl is all-or-nothing for the single inode type, so
        // "taking the default" for the non-LNK kinds means
        // re-issuing it here (Linux's EINVAL there is a registered
        // framework-default difference, analysis.md §9.1 — not
        // simulated; the ext2 EINVAL form at
        // `ext2/inode/symlink.rs:60-62` is not transcribed).
        if self.kind() != FileKind::Lnk {
            return_errno_with_message!(Errno::EISDIR, "inode is not a symbolic link");
        }
        let bytes: Vec<u8> = match &self.payload {
            // Fast arm: the construction-time inline copy, raw
            // bytes (the UTF-8 judgement is deferred to this exit,
            // S02-D2).
            InodePayload::FastSymlink { target } => target.clone(),
            InodePayload::DataBacked { page_cache, .. } => {
                let mut buf = vec![0u8; self.desc().size as usize];
                // Slow arm: read errors pass through unchanged (L5)
                // — no blanket-EIO mapping; the ext2 form at
                // `ext2/inode/symlink.rs:136-138` would collapse
                // the EUCLEAN/EINVAL family onto EIO (S04-D4).
                page_cache.read_bytes(0, &mut buf)?;
                buf
            }
            // LNK payload ∈ {FastSymlink, DataBacked} by
            // construction (the LNK arm of `InodePayload::new`).
            _ => unreachable!("LNK payload is either FastSymlink or DataBacked"),
        };
        // G-N02 candidate ①: non-UTF-8 target → EIO — the single
        // conversion point shared by both arms (S04-D5; message
        // precedent `ext2/inode/symlink.rs:131-132,140-141`).
        String::from_utf8(bytes)
            .map_err(|_| Error::with_message(Errno::EIO, "symlink target is not valid UTF-8"))
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::*;

    use super::*;
    use crate::fs::fs_impls::erofs::{
        Erofs,
        inode::{DataLayout, InodeVersion},
        test_utils::{
            assert_errno, fx_name_non_utf8_symlink_target, ktest_lnk_desc, ktest_super_block,
        },
    };

    /// Three-element criterion vectors (SYM-06/SYM-07, `docs/T-013/
    /// S04/index.md` §9). The expectation single source is the
    /// three-case table of S04 §1.3 — middle slot, cross-block slot
    /// nid≡127 (extended), boundary-exact slot nid≡126 (extended) —
    /// 4k-specialized with meta_blkaddr = 0, so inode_end(nid) =
    /// nid·32 + inode_isize. Element-② `checked_add` overflow (None →
    /// slow) is deliberately NOT probed: it is unreachable at this
    /// layer for every constructible descriptor (inline_start is
    /// device-bounded, size ≤ i64::MAX — the S04 §1.4 accounting);
    /// a u64-boundary xattr_isize would only exercise the wrap-free
    /// premise, not the criterion.
    #[ktest]
    fn is_fast_symlink_three_case_vectors() {
        // (nid, version, datalayout, xattr_isize, size, expected)
        const CASES: &[(u64, InodeVersion, DataLayout, usize, u64, bool)] = &[
            // --- Middle slot: nid = 64 compact → inode_end = 2080,
            //     boundary anchor = round_up(2080) = 4096. ---
            // fast ⟺ 2080 + xattr + size ≤ 4096.
            (
                64,
                InodeVersion::Compact,
                DataLayout::FlatInline,
                0,
                2016,
                true,
            ), // exact boundary
            (
                64,
                InodeVersion::Compact,
                DataLayout::FlatInline,
                0,
                2017,
                false,
            ), // one past
            (
                64,
                InodeVersion::Compact,
                DataLayout::FlatInline,
                32,
                1984,
                true,
            ), // xattr + data fills to the boundary
            (
                64,
                InodeVersion::Compact,
                DataLayout::FlatInline,
                32,
                1985,
                false,
            ),
            // SYM-06 giant-xattr corner (§1.2 tail example):
            // inline_start = 2080 + 262148 ≫ 4096 → slow.
            (
                64,
                InodeVersion::Compact,
                DataLayout::FlatInline,
                262_148,
                0,
                false,
            ),
            // Element ① — every other datalayout is slow, including
            // the compressed pair the I12 gate would have rejected
            // earlier in the real assembly (pure function here).
            (
                64,
                InodeVersion::Compact,
                DataLayout::FlatPlain,
                0,
                1,
                false,
            ),
            (
                64,
                InodeVersion::Compact,
                DataLayout::ChunkBased,
                0,
                1,
                false,
            ),
            (
                64,
                InodeVersion::Compact,
                DataLayout::CompressedFull,
                0,
                1,
                false,
            ),
            (
                64,
                InodeVersion::Compact,
                DataLayout::CompressedCompact,
                0,
                1,
                false,
            ),
            // --- Cross-block slot (SYM-07): nid = 127 extended →
            //     inode_end = 4064 + 64 = 4128 (next block + 32),
            //     boundary anchor = 8192 (the NEXT block's end). ---
            (
                127,
                InodeVersion::Extended,
                DataLayout::FlatInline,
                0,
                4064,
                true,
            ), // ends exactly at 8192
            (
                127,
                InodeVersion::Extended,
                DataLayout::FlatInline,
                0,
                4065,
                false,
            ),
            (
                127,
                InodeVersion::Extended,
                DataLayout::FlatInline,
                32,
                4032,
                true,
            ),
            (
                127,
                InodeVersion::Extended,
                DataLayout::FlatInline,
                32,
                4033,
                false,
            ),
            // --- Boundary-exact slot (SYM-07): nid = 126 extended →
            //     inode_end = 4032 + 64 = 4096 (exactly the block
            //     boundary), anchor = 4096 — the `≤` allows data to
            //     end exactly at the boundary, so fast ⟺ xattr = 0
            //     ∧ size = 0 (the empty-symlink-zero-xattr face, the
            //     ONLY fast possibility at this slot). ---
            (
                126,
                InodeVersion::Extended,
                DataLayout::FlatInline,
                0,
                0,
                true,
            ),
            (
                126,
                InodeVersion::Extended,
                DataLayout::FlatInline,
                0,
                1,
                false,
            ),
            (
                126,
                InodeVersion::Extended,
                DataLayout::FlatInline,
                1,
                0,
                false,
            ),
            (
                126,
                InodeVersion::Extended,
                DataLayout::FlatInline,
                1,
                1,
                false,
            ),
        ];

        // blkszbits = 12 (bs = 4096, the G-M08 pin), meta_blkaddr = 0.
        let fs = Erofs::ktest_new(ktest_super_block(12, 0));
        for &(nid, version, datalayout, xattr_isize, size, expected) in CASES {
            let desc = ktest_lnk_desc(version, datalayout, xattr_isize, size);
            assert_eq!(
                is_fast_symlink(&fs, nid, &desc),
                expected,
                "nid = {}, dl = {:?}, xattr = {}, size = {}",
                nid,
                datalayout,
                xattr_isize,
                size,
            );
        }
    }

    /// T-027 S06 (FX-NAME, matrix §3.3 G-N02): a non-UTF-8 symlink
    /// target fails `read_link` with EIO — the registered candidate-①
    /// face, asserted at the aster side per the matrix. The fixture
    /// carries both payload arms plus ASCII controls: the raw 0xFF/0x80
    /// (fast, inline) and 0xFE/0xFF (slow, DataBacked over a whole
    /// block) targets reach this exit UNJUDGED (S02-D2: the UTF-8
    /// judgement is deferred here from iget), so both arms fail at the
    /// single shared conversion point while both controls read back
    /// verbatim — the EIO is the UTF-8 judgement, not the arm
    /// machinery. (The fixture binding stays alive for the whole
    /// block: `Inode` holds only a `Weak<Erofs>`.)
    #[ktest]
    fn non_utf8_symlink_target_eio_both_arms() {
        let fixture = fx_name_non_utf8_symlink_target();
        let root = fixture.mounted().root_inode().unwrap();

        // Controls: ASCII targets through BOTH arms, verbatim.
        assert_eq!(
            root.lookup("fastgood").unwrap().read_link().unwrap(),
            "ok-target"
        );
        assert_eq!(
            root.lookup("slowgood").unwrap().read_link().unwrap(),
            "page-target"
        );

        // G-N02: the raw-byte targets, both arms, one errno.
        assert_errno!(
            root.lookup("fastbad").unwrap().read_link(),
            Errno::EIO,
            "G-N02: the fast inline arm's non-UTF-8 target"
        );
        assert_errno!(
            root.lookup("slowbad").unwrap().read_link(),
            Errno::EIO,
            "G-N02: the slow DataBacked arm likewise"
        );
    }
}
