// SPDX-License-Identifier: MPL-2.0

//! Erofs inode family.
//!
//! The central type, `Inode`, represents one in-memory erofs inode and
//! is the concrete inode object exposed to the VFS adapter. Inodes are
//! identified by nid — erofs has no block groups, so inode numbers are
//! linear and the FS-level cache in `fs.rs` is keyed by nid directly.
//!
//! Bring-up state (T-022 S05–S08 + T-023 S04 + T-024 S01): the decode
//! half is complete —
//! the two raw inode records (`RawInodeCompact` 32B /
//! `RawInodeExtended` 64B, sharing the discriminating prefix at
//! offsets 0/2/4/16), the chunk-domain record `RawInodeChunkInfo`
//! (a registration-only host for its layout assertions; the
//! element-wise `RawInodeChunkIndex` lives in `inode/data.rs` since
//! T-025 S01), the `i_format` bit
//! family with the two extraction helpers and the entry's
//! `parse_i_format` validation, the inode-domain constants — 13 + 15
//! + 4 layout assertions here (5 more moved with the chunk index) —
//! plus the four vocabulary
//! enums (`InodeVersion`, `DataLayout`, `FileKind`, `AddrState`),
//! the decoded `InodeDesc` mirror with its 13-field set, the
//! `xattr_ibody_size` helper, the dual `TryFrom` decode with the
//! I7/I8/I10 guards and the G-Z02 dual-caliber `nr_sectors`
//! accounting, the two ID4 `i_u` accessors, and the decode entry
//! `read_inode_desc` — the five-step sequence from the 2-byte
//! pre-read through the `TryFrom`.
//!
//! Since T-024 S01 the handle below is the final assembly shape:
//! nid, decoded descriptor, type-specific payload (`InodePayload`),
//! weak back-pointer, and the VFS extension slot, all constructed by
//! `Inode::new` — the decode + assembly chain that the slow path of
//! `Erofs::iget` (`fs.rs`) drives inside its write-guard critical
//! section. The payload assembly carries the I12 arm-head gate
//! (S02-R1: compressed REG/DIR/LNK fail iget with EOPNOTSUPP,
//! uncached and replayed on every call) and the fast/slow symlink
//! split (the judgement and the inline-target read live in
//! `inode/symlink.rs`); the data backend in `inode/data.rs` carries
//! the final data geometry since T-025 S01 (the mapping faces land
//! with the remaining slices). Since
//! T-024 S02 the cross-seven-kind inherent faces are in place: the
//! statx assembly (`metadata`), the open dispatch (`open`), and the
//! SEEK_END anchor (`seek_end`) live on the handle below, the
//! unified `read_link` exit in `inode/symlink.rs`, and the `read_at`
//! guard positions in `inode/file.rs` (the data body itself is
//! T-025). Since T-024 S03 both dirent walks live in `inode/dir.rs`
//! — the namei binary search (lookup) and the getdents iteration
//! (readdir), kept apart by the two-strictness-domains contract of
//! that module — and since T-024 S05 the VFS adapter
//! (`impl_for_vfs/inode.rs`) forwards to every inherent face above
//! as a dispatch-only surface.
//!
//! # Submodules
//!
//! | Submodule | Responsibility                                                   |
//! |-----------|------------------------------------------------------------------|
//! | `mod`     | The inode handle, payload assembly, and decoding (T-022 + T-024) |
//! | `data`    | Flat page-cache backend on the final geometry (T-025)           |
//! | `file`    | `read_at` guards; the data body lands with T-025                  |
//! | `dir`     | Both dirent walks: namei lookup + getdents (T-024 S03)           |
//! | `symlink` | Fast/slow split, inline target reads, `read_link` (T-024)         |
//!
//! # Locking
//!
//! An `Inode` is immutable once constructed: the nid, the decoded
//! `InodeDesc`, the type-specific payload, and the weak back-reference
//! to the filesystem are all fixed by `erofs_iget` and never change,
//! because erofs is read-only and never updates atime. There is no
//! per-inode lock and no cross-inode lock order. Data-backed payloads
//! own a framework `PageCache` that synchronizes itself, and the VFS
//! `Extension` slot is self-synchronizing as well.
//!
//! The only lock on this path is `Erofs::inode_cache`, an nid-keyed map
//! under an `RwMutex` with double-checked locking (see `fs.rs`). The
//! slow path constructs the inode — including its metadata reads from
//! the block device — while holding the write guard, inserts it only
//! on success (failures are never cached and replay on every call),
//! and releases the guard as soon as the `Arc<Inode>` clone is handed
//! out; every inode operation runs outside the guard. While
//! `inode_cache` is held, no other lock may be acquired (in particular
//! not `mount_options`), no VFS callback may run, and page-cache
//! completion callbacks (interrupt context) must never acquire it.

#![short_vis_path::add(erofs)]

mod data;
mod dir;
mod file;
mod symlink;

use core::mem::offset_of;

use align_ext::AlignExt;
use device_id::{DeviceId, MajorId, MinorId};
use ostd::{const_assert, mm::VmIo};

// The erofs-level name of the data backend: `Inode::data_backend`
// and the `DataBacked` payload field expose the type at `pub(super)`
// (erofs) scope, so the declaration in `data.rs` carries
// `pub(in crate::fs::fs_impls::erofs)` and this re-export provides
// the short erofs-level path (the `private_interfaces` contract;
// visibility-form precedent `virtiofs/inode/page_cache.rs:175`,
// re-export precedent `ext2/inode/block_manager/mod.rs:13`).
pub(super) use self::data::DataBackend;
// The ktest fixture face of the geometry names: `test_utils`
// (T-025 S02) constructs `DataGeometry`/`ChunkGeometry` literals
// directly. The re-export is cfg-gated because production code
// consumes the names only inside this module — the plain `use`
// below carries the non-ktest builds, and an ungated
// `pub(super) use` would have no non-ktest reader and would trip
// `unused_imports` under `make check` (the same reason S01 left
// the re-export unlanded).
#[cfg(ktest)]
pub(super) use self::data::{ChunkGeometry, DataGeometry};
#[cfg(not(ktest))]
use self::data::{ChunkGeometry, DataGeometry};
use self::{
    data::RawInodeChunkIndex,
    symlink::{is_fast_symlink, read_inline_target},
};
use super::{fs::Erofs, prelude::*, super_block::SuperBlock};
use crate::{
    device,
    fs::{
        file::{AccessMode, PerOpenFileOps, StatusFlags},
        pipe::Pipe,
        vfs::inode::{Extension, Metadata},
    },
    process::{Gid, Uid},
    vm::page_cache::{PageCache, PageCacheBackend},
};

/// An erofs inode number (`nid`): the linear on-disk inode identifier.
pub(super) type ErofsNid = u64;

/// An in-memory erofs inode.
///
/// Final assembly shape (T-024 S01, `docs/T-013/analysis.md` §1.1):
/// the nid, the decoded descriptor, the type-specific payload, the
/// weak filesystem back-pointer, and the VFS extension slot — all
/// immutable after construction (read-only filesystem, no atime
/// updates; see the module-level `# Locking` section). The weak
/// back-pointer discipline: `self_ref` is the only link back to the
/// filesystem handle (strong reference cycles are forbidden
/// family-wide) and the upgrade path carries an `EIO` guard that is
/// structurally unreachable under the strong inode cache (the mount
/// always outlives the inodes it handed out).
pub struct Inode {
    nid: ErofsNid,
    desc: InodeDesc,
    payload: InodePayload,
    self_ref: Weak<Erofs>,
    extension: Extension,
}

impl Inode {
    /// Constructs the inode for `nid`: decode (the five-step entry)
    /// then payload assembly, returning the shared handle (S01 §4.2
    /// sample). The sole constructor — every `Inode` comes from the
    /// slow path of `Erofs::iget` (`fs.rs`), which runs this inside
    /// its write-guard critical section (S01-D7). Plain `Arc::new`,
    /// not `new_cyclic`: no field of this handle references the
    /// inode itself (S01-D2; `self_ref` points at `Erofs` and is
    /// supplied by the caller).
    ///
    /// Eager by design (X16, both halves: decode S01-D3, payload
    /// S02-D7): once this returns Ok, no later operation re-decodes
    /// or re-assembles anything, and `metadata()` never fails.
    ///
    /// Error face = {I2 device reads, I3/I4 EOPNOTSUPP, I7/I8
    /// EUCLEAN, I10 EOPNOTSUPP} ∪ {I12 EOPNOTSUPP — the arm-head
    /// gate inside `InodePayload::new`, S02-R1}; every failure is
    /// returned before the `Arc` literal and leaves no cache entry,
    /// so the error replays on each iget call (G5). Construction
    /// consumes the device, the immutable superblock geometry, and
    /// the weak self reference only — never `mount_options` (R1,
    /// analysis.md §1.3). No ENOMEM arm anywhere on the chain
    /// (allocation failure aborts in this tree, G-M21/F4).
    ///
    /// (G-M10 family read point: an inode-record interval extending
    /// past the device end fails the read with EINVAL from the
    /// device stack where Linux fails the metabuf read with EIO —
    /// the registered-drift family collected by the drift-ledger
    /// summary; the same note anchored this read when it lived in
    /// `Erofs::iget`, T-023 S04.)
    pub(super) fn new(fs: &Erofs, nid: ErofsNid) -> Result<Arc<Self>> {
        // Steps 1–5 of the five-step decode: the iloc base point
        // (step 1, `inode_location` below) feeding the decode entry
        // (steps 2–5). Errors pass through unchanged (C2).
        let desc = read_inode_desc(
            &**fs.block_device(),
            fs.super_block(),
            inode_location(fs.super_block(), nid) as usize,
        )?;
        // The payload assembly (the `erofs_fill_inode` A2–A5
        // homologue) — the I12 arm-head gate and the per-kind
        // payloads.
        let payload = InodePayload::new(fs, nid, &desc)?;
        Ok(Arc::new(Self {
            nid,
            desc,
            payload,
            self_ref: fs.self_ref().clone(),
            extension: Extension::new(),
        }))
    }

    /// Returns the inode number (nid) — the linear on-disk inode
    /// identifier as resolved by `Erofs::iget` (st_ino derives from
    /// it, X2; the on-disk `i_ino` compat field is never consumed).
    pub(super) fn ino(&self) -> ErofsNid {
        self.nid
    }

    /// Returns the decoded file kind — the typed type face, single
    /// data source `desc.kind` (S01-D1: the handle keeps no separate
    /// type field, so there is exactly one judgement path). The
    /// framework-type view goes through the `From<FileKind> for
    /// InodeType` bijection below (S03-D3).
    ///
    /// Runtime invariant: the returned kind is never `Other` — the
    /// I8 guard rejects it with `EUCLEAN` before a descriptor
    /// escapes the decode; the `Other` arm of the conversion below
    /// is the only place that knowledge is relied upon.
    pub(super) fn kind(&self) -> FileKind {
        self.desc.kind
    }

    /// Whether this inode carries compressed data — the handle-side
    /// forwarder of the rejection-chain layer-3 predicate (G-M15).
    ///
    /// Pure forwarding, no criteria here: the judgement lives on the
    /// descriptor (`InodeDesc::is_data_compressed`, the single
    /// source) and must not be rewritten at any forwarding face —
    /// the mount-time site gates of `Erofs::open` (F10/F11) and the
    /// runtime map_blocks half share it.
    pub(super) fn is_data_compressed(&self) -> bool {
        self.desc.is_data_compressed()
    }

    /// Whether this inode is a directory — the `desc.kind`
    /// judgement (same single data source as `kind()`), consumed by
    /// the F12 mount door.
    pub(super) fn is_dir(&self) -> bool {
        matches!(self.desc.kind, FileKind::Dir)
    }

    /// Returns a reference to the owning `Erofs` filesystem.
    ///
    /// The weak-upgrade failure guard is defensive by design: with the
    /// strong inode cache the mount always outlives the inodes it
    /// handed out, so the `EIO` below is structurally unreachable.
    pub(super) fn fs(&self) -> Result<Arc<Erofs>> {
        self.self_ref
            .upgrade()
            .ok_or_else(|| Error::with_message(Errno::EIO, "filesystem already dropped"))
    }

    /// Returns a reference to the VFS extension slot.
    pub(super) fn extension(&self) -> &Extension {
        &self.extension
    }

    /// Returns a reference to the decoded descriptor — the single
    /// decode-side data source every downstream face reads through
    /// (`self.desc` stays the only copy; the seek/`read_link`
    /// geometry consumers join through this view, S01-D1).
    pub(super) fn desc(&self) -> &InodeDesc {
        &self.desc
    }

    // -------------------------------------------------------------------
    // Payload accessor face (S02-D5: the Option face — a missing
    // payload is an internal shape fact, never an errno; the trait
    // guards EISDIR/ENOTDIR/ENODEV arise at their own sites,
    // decoupled from this internal shape).
    // -------------------------------------------------------------------

    /// Data-backed page-cache view; `None` for every other payload
    /// (the Some/None mapping is locked by the S02 §2.6 table:
    /// DataBacked only).
    // Live since T-024 S03: both directory walks (the namei binary
    // search and the getdents iteration in `inode/dir.rs`) read
    // through this face; the dispatch face joined with S05. (The
    // slow-symlink read arm matches the payload field in place
    // instead of going through this Option face — the S04 §4.1
    // terminal sample.)
    pub(super) fn page_cache(&self) -> Option<&PageCache> {
        match &self.payload {
            InodePayload::DataBacked { page_cache, .. } => Some(page_cache),
            _ => None,
        }
    }

    /// Data-mapping backend handle (DataBacked only).
    // First consumer: the final data-path face (T-025) — the
    // minimal backend is consumed through the page cache meanwhile.
    #[expect(dead_code)]
    pub(super) fn data_backend(&self) -> Option<&Arc<DataBackend>> {
        match &self.payload {
            InodePayload::DataBacked { backend, .. } => Some(backend),
            _ => None,
        }
    }

    /// Fast-symlink inline copy, stored as raw bytes — the UTF-8
    /// judgement is deferred to `read_link` (G-N02 error timing is
    /// an assertion face; S02-D2). `FastSymlink` only.
    // No consumer as of T-024 S02: the `read_link` unified exit
    // matches the payload field in place (the S04 §4.1 terminal
    // sample), superseding this face's anticipated first consumer.
    // Kept as the FastSymlink view of the locked C-5b five-accessor
    // face; later consumers join through it.
    #[expect(dead_code)]
    pub(super) fn fast_symlink_target(&self) -> Option<&[u8]> {
        match &self.payload {
            InodePayload::FastSymlink { target } => Some(target),
            _ => None,
        }
    }

    /// Decoded device number (CHR/BLK only; decoded once through
    /// `desc.rdev()` at construction, S02-D3 — open never re-decodes).
    // Live since T-024 S02: the metadata assembly (`self_dev_id`)
    // and the open CHR/BLK arm read it. The bridging `expect` was
    // removed when those consumers landed.
    pub(super) fn device_id(&self) -> Option<DeviceId> {
        match &self.payload {
            InodePayload::Device { device_id } => Some(*device_id),
            _ => None,
        }
    }

    /// FIFO pipe host (FIFO only; constructed eagerly at assembly —
    /// the strong-Arc identity convergence carries the POSIX
    /// open-pairing semantics, S07-D2/C-5a).
    // Live since T-024 S02: the FIFO open arm reads it. The
    // bridging `expect` was removed when that consumer landed.
    pub(super) fn fifo_pipe(&self) -> Option<&Pipe> {
        match &self.payload {
            InodePayload::Fifo { pipe } => Some(pipe),
            _ => None,
        }
    }

    // -------------------------------------------------------------------
    // Cross-seven-kind inherent faces (T-024 S02; `docs/T-013/
    // analysis.md` §2/§6). Hosted on the handle — not in the VFS
    // adapter — because each face spans kinds and payloads across
    // the submodule domains (S03-D1/S07-D1/S06-D6); the VFS adapter
    // (impl_for_vfs/inode.rs, since T-024 S05) forwards to each of
    // them with one line.
    // -------------------------------------------------------------------

    /// Assembles the statx snapshot — the `erofs_getattr` homologue
    /// (linux inode.c:316-346; the G-Z02 accounting itself is done
    /// at decode time, T-011 §4.5). Infallible by construction
    /// (X16, assembly half): the descriptor and payload are eagerly
    /// decoded in `Inode::new`, so this reads in-memory state only —
    /// no device I/O, no `?`, no error face.
    ///
    /// Field notes (`docs/T-013/S03/index.md` §1): the three times
    /// are one `Duration` copied three times (D10, zero arithmetic —
    /// the framework's `as i64` truncation at the statx exit is then
    /// bit-level parity); `nr_sectors_allocated` takes
    /// `desc.nr_sectors` verbatim — the decode-time dual caliber
    /// with no per-kind branch here (G-Z02; the ext2 single
    /// round_up caliber at `ext2/inode/attrs.rs:68` is the negative
    /// sample — copying it would drift st_blocks on compressed
    /// special files); `birth_at` is `None` (no on-disk source).
    // Live since T-024 S05: the VFS adapter forwards
    // `Ok(self.metadata())` through its same-name trait face.
    pub(super) fn metadata(&self) -> Metadata {
        let desc = &self.desc;
        // The only fallible input: the weak-upgrade for the two
        // fs-derived fields. Unreachable under the strong-Arc inode
        // cache (the mount always outlives the inodes it handed
        // out); degrades gracefully to a null identity (S03-D2;
        // ext2 precedent `ext2/inode/attrs.rs:54-57`).
        let (container_dev_id, optimal_block_size) = match self.fs() {
            Ok(fs) => (
                fs.block_device().id(),        // X1: the mount block device
                fs.super_block().block_size(), // X11: 1 << blkszbits (4096, G-M08)
            ),
            Err(_) => (DeviceId::null(), 0),
        };
        Metadata {
            ino: self.nid,            // X2: st_ino = nid, 64-bit identity
            size: desc.size as usize, // X7: I7 caps at i64::MAX
            optimal_block_size,       // X11
            // X10/G-Z02: the decode-time single source, used as-is.
            nr_sectors_allocated: desc.nr_sectors,
            // X8: three times, one source (D10) — zero arithmetic.
            last_access_at: desc.time,
            last_modify_at: desc.time,
            last_meta_change_at: desc.time,
            type_: desc.kind.into(),            // X3 half: the S_IFMT segment
            mode: desc.mode,                    // X3 half: the 12 permission bits
            nr_hard_links: desc.nlink as usize, // X4: raw value incl. 0
            uid: Uid::new(desc.uid),            // X5: zero-extended at decode
            gid: Gid::new(desc.gid),
            container_dev_id,              // X1
            self_dev_id: self.device_id(), // X6: payload Option face
            birth_at: None,                // X9: no birth-time source
        }
    }

    /// Opens this inode as a file, device, or pipe — the VFS
    /// `Inode::open` dispatch target (G-N03). `None` = open through
    /// the inode's own `FileOps` (REG/DIR); `Some(Err(ENODEV))` =
    /// kinds with no Linux file_operations (LNK/SOCK).
    ///
    /// The LNK/SOCK arm is the only parity shape and stays even
    /// though the regular open(2) channel never reaches it
    /// (`Path::open` ELOOPs on O_NOFOLLOW and the resolver follows
    /// the link otherwise; S07-D4 — dropping the arm would revive
    /// the None semantics and drift). O_PATH bypasses this face
    /// entirely. CHR/BLK go through `device::lookup` with the
    /// payload's construction-time `device_id` (S02-D3 — the same
    /// single consumption face as X6's `self_dev_id`; no ext2-style
    /// decode-failure arm exists: `new_decode_dev` has no error
    /// path); a missing device is ENODEV, a found one opens through
    /// `Device::open`. FIFO opens the payload's eagerly constructed
    /// `Pipe` (C-5a/S07-D2: the strong-Arc identity convergence
    /// carries the POSIX open-pairing semantics).
    // Live since T-024 S05: the VFS adapter forwards to this
    // inherent body through its `open` override.
    pub(super) fn open(
        &self,
        access_mode: AccessMode,
        status_flags: StatusFlags,
    ) -> Option<Result<Box<dyn PerOpenFileOps>>> {
        match self.kind() {
            // REG/DIR: per-open stateless — opened through this
            // inode's own `FileOps` (A2a/A2b: fops attached directly).
            FileKind::Reg | FileKind::Dir => None,
            // LNK/SOCK: no Linux file_operations exist for the kind
            // (A2c/A3) — the inode's own open is ENODEV
            // (linux/fs/open.c:933-937).
            FileKind::Lnk | FileKind::Sock => Some(Err(Error::with_message(
                Errno::ENODEV,
                "opening a symlink or socket inode is not supported",
            ))),
            FileKind::Chr | FileKind::Blk => {
                let device_id = self
                    .device_id()
                    .expect("chr/blk inode must carry a Device payload");
                // device_type single source: the S03-D3 bijection
                // (no second Chr→Char mapping, drift-proof).
                let device_type = InodeType::from(self.kind())
                    .device_type()
                    .expect("chr/blk kind always maps to a device type");
                match device::lookup(device_type, device_id) {
                    None => Some(Err(Error::with_message(
                        Errno::ENODEV,
                        "the required device ID does not exist",
                    ))),
                    Some(device) => Some(device.open()),
                }
            }
            FileKind::Fifo => {
                let pipe = self
                    .fifo_pipe()
                    .expect("fifo inode must carry a Fifo payload");
                Some(pipe.open_named(access_mode, status_flags))
            }
            // Unreachable: the I8 guard ("bogus i_mode", EUCLEAN)
            // rejects the Other kind at the decode, so a runtime
            // descriptor never carries it.
            FileKind::Other(_) => unreachable!("I8 rejects the Other kind at decode"),
        }
    }

    /// SEEK_END anchor: directories report `i_size` (G-N06,
    /// candidate ①) — replicating the framework default's File arm
    /// (`vfs/fs_apis/inode.rs:532-543`), which an override would
    /// otherwise lose. usize is lossless for u64 sizes on 64-bit
    /// targets (I7 caps size at i64::MAX). The remaining kinds keep
    /// the default face (`None`).
    // Live since T-024 S05: the VFS adapter forwards to this
    // inherent body through its `seek_end` override.
    pub(super) fn seek_end(&self) -> Option<usize> {
        match self.kind() {
            FileKind::Dir | FileKind::Reg => Some(self.desc().size as usize),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// The base-point collapse formula family (S04-D3 single source,
// `docs/T-013/analysis.md` §3.1): the three absolute byte offsets
// every inline-suffix consumer derives from — the fast/slow symlink
// judgement and read point (S04), the data-backend tail geometry
// (T-024 S01), the T-025 extent base, and the T-026 ibody walk.
// Hosted here (not in symlink.rs) so the family stays one module
// away from every consumer.
// ---------------------------------------------------------------------------

/// Byte offset of the inode slot for `nid` within the metadata area
/// (`erofs_iloc`, linux internal.h:288-294). Step 1 of the five-step
/// decode sequence. The slot invariant `iloc & (bs - 1) ∈ {0, 32, …,
/// bs − 32}` and the cross-block slot (bs−32; RD1) belong to the
/// decoder analysis (T-011 §5.1), not to this formula.
///
/// The shift amounts are pinned by the mount gate (blkszbits = 12
/// under the 4k-only scope, so `u64::from` can never reach the shift
/// overflow domain); the addition is `wrapping_add` to mirror the
/// defined unsigned wrap of the C original (S01-D9): a crafted
/// garbage `packed_nid` (le64 full domain, reaching iget through
/// F10) wraps into a bogus offset whose subsequent device read then
/// fails — the passthrough path by which "garbage packed_nid must
/// fail the mount" is honored. No `checked_add`, no self-made
/// EOVERFLOW (Linux has no such branch). Returns u64; the read site
/// narrows to usize (64-bit targets, lossless).
pub(super) fn inode_location(sb: &SuperBlock, nid: ErofsNid) -> u64 {
    debug_assert!(u32::from(sb.blkszbits) < u64::BITS);
    (u64::from(sb.meta_blkaddr) << u32::from(sb.blkszbits)).wrapping_add(nid << ISLOT_BITS)
}

/// Byte offset just past the on-disk inode body = start of the inline
/// xattr suffix region (`iloc + inode_isize`; linux semantics: the
/// `(kaddr, ofs)` base handed to `erofs_fill_symlink`,
/// `docs/T-003/analysis.md` §2.1 L1). Also the `inode_end` of the
/// fast/slow judgement (the offset of the inode's last byte sits in
/// the block this points back into).
///
/// Plain (non-wrapping) addition by design: the decode already read
/// `[iloc, iloc + inode_isize)` off the device, so the sum is
/// device-bounded and cannot wrap u64 on any real device (S04 §1.4
/// reachability accounting).
pub(super) fn suffix_xattr_start(sb: &SuperBlock, nid: ErofsNid, desc: &InodeDesc) -> u64 {
    inode_location(sb, nid) + desc.inode_isize() as u64
}

/// Byte offset of the FLAT_INLINE payload region (read site #14,
/// `docs/T-011/S07/index.md` §3.2) = inode end + xattr_isize. The
/// xattr size is the unvalidated decoded value — the boundary guard
/// belongs to the consumer (T-026), not to this formula.
pub(super) fn inline_data_start(sb: &SuperBlock, nid: ErofsNid, desc: &InodeDesc) -> u64 {
    suffix_xattr_start(sb, nid, desc) + desc.xattr_isize as u64
}

// ---------------------------------------------------------------------------
// The type-specific payload (T-024 S01; `docs/T-013/analysis.md`
// §1.4, `docs/T-013/S02/index.md` §1–§3). Assembled once, eagerly,
// inside the iget critical section; never mutated afterwards
// (read-only filesystem).
// ---------------------------------------------------------------------------

/// Type-specific in-memory state, assembled once at construction
/// time by `InodePayload::new` (the `erofs_fill_inode` A2–A5
/// homologue; ext2 precedent `ext2/inode/mod.rs:427-440`). Never
/// mutated afterwards (read-only filesystem). No `Debug` derive:
/// `Pipe` carries none, and the framework keeps no debug consumer
/// of this type (the S02 §2.1 sample's derive predates the C-5
/// `Fifo` split).
///
/// Variant set (C-5 final): DataBacked / FastSymlink / Device /
/// Fifo / NoPayload — the seven-kind × five-datalayout assembly
/// outcome matrix of `docs/T-013/S02/index.md` §3.1.
pub(super) enum InodePayload {
    /// REG / DIR / slow LNK (datalayout ∈ {0, 2, 4}): data reachable
    /// through the framework page cache; mapping mechanics live in
    /// `inode/data.rs` (final geometry since T-025 S01; the mapping
    /// faces land with the remaining slices).
    DataBacked {
        page_cache: PageCache,
        /// Ownership root of the data-mapping backend — the page
        /// cache holds only a `Weak<dyn PageCacheBackend>` to it.
        backend: Arc<DataBackend>,
    },
    /// Fast symlink (LNK × FLAT_INLINE passing the L3 criterion):
    /// inline copy of the target, stored as RAW BYTES — the UTF-8
    /// judgement is deferred to `read_link` (G-N02 error timing is
    /// an assertion face; S02-D2). Empty target (`i_size` = 0) =
    /// empty vec (readlink reports an empty string, L4).
    FastSymlink { target: Vec<u8> },
    /// CHR / BLK: the `new_decode_dev` decoding of `i_u`, done once
    /// through `desc.rdev()` at construction (S02-D3; X6's
    /// `self_dev_id` and the open arm consume it).
    Device { device_id: DeviceId },
    /// FIFO: no erofs on-disk payload for the type face, but the
    /// pipe is a live runtime facility — constructed eagerly here so
    /// the strong-Arc inode identity convergence carries the POSIX
    /// open-pairing semantics (C-5a/S07-D2: two openers of one FIFO
    /// rendezvous on the same `Pipe`).
    Fifo { pipe: Pipe },
    /// SOCK: no payload at all (the `i_u` type face is not read;
    /// linux `init_special_inode` leaves `i_rdev` 0 — X6 → None).
    NoPayload,
}

impl InodePayload {
    /// Assembles the type-specific payload for inode `nid` from the
    /// decoded `desc` (S02 §2.2; the `nid` parameter is the S02-D4
    /// addition — the inline read point and the fast/slow judgement
    /// need the iloc base, which the descriptor does not carry).
    /// Runs as step 2 of `Inode::new`, inside the iget write-guard
    /// critical section: consumes only the device, the immutable
    /// superblock geometry, and `fs.self_ref` — never
    /// `mount_options` (R1, analysis.md §1.3).
    ///
    /// Err face = {I2 device reads (the LNK fast arm's inline
    /// target read)} ∪ {I12} (C-1); every other arm has no error
    /// exit (allocation failure is the aster abort family,
    /// F4/G-M21; `desc.rdev()` decodes any le32 without a failure
    /// path).
    ///
    /// The I12 gate sits at the HEAD of the REG/DIR/LNK arms
    /// (S02-R1/S02-D1), before any payload construction and before
    /// the fast/slow judgement: a compressed REG/DIR/LNK fails the
    /// whole iget with EOPNOTSUPP — uncached, replayed on every
    /// call (G5) — which is exactly the matrix §5.1 ⑦ assertion
    /// surface. The special-file arms (Chr/Blk/Fifo/Sock) never
    /// touch the gate (the A3 early-return exemption, predicate
    /// homologue). The F10/F11 mount-site gates stay as unreachable
    /// defenses (C-3/C-4: same outcome, see S02 §1.4).
    pub(super) fn new(fs: &Erofs, nid: ErofsNid, desc: &InodeDesc) -> Result<Self> {
        match desc.kind {
            FileKind::Reg | FileKind::Dir => {
                // I12 arm-head gate (S02-R1). For {1, 3} this fires
                // before the PageCache exists — no construction is
                // wasted (S02-D1).
                if desc.is_data_compressed() {
                    return_errno_with_message!(
                        Errno::EOPNOTSUPP,
                        "compressed inode data is not supported"
                    );
                }
                Ok(Self::new_data_backed(fs, nid, desc))
            }
            FileKind::Lnk => {
                // I12 first (S02 §1.4 point 3): a compressed LNK
                // never reaches the criterion — element ① is false
                // for {1, 3} anyway, so no read happens on either
                // side; gating first just skips the useless
                // judgement.
                if desc.is_data_compressed() {
                    return_errno_with_message!(
                        Errno::EOPNOTSUPP,
                        "compressed inode data is not supported"
                    );
                }
                if is_fast_symlink(fs, nid, desc) {
                    Ok(Self::FastSymlink {
                        target: read_inline_target(fs, nid, desc)?,
                    })
                } else {
                    Ok(Self::new_data_backed(fs, nid, desc))
                }
            }
            FileKind::Chr | FileKind::Blk => Ok(Self::Device {
                device_id: desc.rdev(),
            }),
            FileKind::Fifo => Ok(Self::Fifo { pipe: Pipe::new() }),
            FileKind::Sock => Ok(Self::NoPayload),
            // Unreachable: the I8 guard ("bogus i_mode", EUCLEAN)
            // rejects the Other kind at the decode, so a runtime
            // descriptor never carries it.
            FileKind::Other(_) => unreachable!("I8 rejects the Other kind at decode"),
        }
    }

    /// The REG/DIR/slow-LNK data payload (S02 §2.2): page cache +
    /// data backend. The `nid` parameter (beyond the S02 §2.2
    /// sample signature) feeds the geometry collapse, which derives
    /// from the iloc base — zero behavior change.
    ///
    /// Since T-025 S01 the geometry collapse happens once here —
    /// the private pure function `data_geometry` below — and the
    /// backend re-derives its flat-region arithmetic from the
    /// bundle at read time (the consumer-side recompute, per the
    /// §1.1 seam; the flat_blocks/tail precomputation of the
    /// T-024 minimal face is gone).
    fn new_data_backed(fs: &Erofs, nid: ErofsNid, desc: &InodeDesc) -> InodePayload {
        let geom = data_geometry(fs.super_block(), nid, desc);
        // Page-cache capacity aligned with the inode size from
        // mount time (ext2 precedent `ext2/inode/mod.rs:614-627`);
        // the npages bound handed to the backend is the same value
        // in page units.
        let page_cache_size = (desc.size as usize).align_up(PAGE_SIZE);
        let backend = Arc::new(DataBackend::new(
            fs.self_ref().clone(),
            fs.block_device().clone(),
            geom,
            page_cache_size / PAGE_SIZE,
        ));
        let page_cache_backend: Weak<dyn PageCacheBackend> = Arc::downgrade(&backend) as _;
        // Allocation failure is the aster abort family — no Err arm
        // (F4/G-M21).
        let page_cache = PageCache::new_with_backend(page_cache_size, page_cache_backend)
            .expect("erofs inode page cache allocation failed");
        InodePayload::DataBacked {
            page_cache,
            backend,
        }
    }
}

// ---------------------------------------------------------------------------
// The geometry collapse (T-025 S01; `docs/T-014/analysis.md` §1.1/
// §1.2, S01-D2/D3): one private PURE function folding the decoded
// descriptor plus the superblock geometry into the plain-value
// bundle `DataGeometry` — zero I/O, zero locks (R1-safe inside the
// iget critical section), the L3 half of the acyclic L2/L3 edge
// (rule 5: data.rs never sees the descriptor itself).
// ---------------------------------------------------------------------------

/// Collapses the desc/sb-derived data geometry of one DataBacked
/// inode into plain values (S01-D2). Field notes:
///
/// - `raw_blkaddr` goes through the ID4 accessor — the kind premise
///   ({Reg, Dir, Lnk}) holds on every production call site (only
///   the DataBacked arm of `InodePayload::new` lands here);
/// - `tail_inline` mirrors the datalayout BIT only and never
///   predicts whether an inline tail EXISTS: the size=0 and
///   exact-block-size corners keep the bit set with an empty tail
///   region (the M2 positioning is arithmetic in the consumer,
///   context.md risk 2);
/// - `chunk` carries the Chunked unit (through `chunk_unit()`, the
///   INDEXES single source) and chunkbits; Flat/Compressed → None;
/// - `compressed` is the single consumption snapshot of the
///   layer-3 predicate (S01-D3): `is_data_compressed()` evaluated
///   once here — the map_blocks entry guard (S03) reads the stored
///   bit, never re-derives.
fn data_geometry(sb: &SuperBlock, nid: ErofsNid, desc: &InodeDesc) -> DataGeometry {
    let chunk = match &desc.addr_state {
        AddrState::Chunked { bits, .. } => Some(ChunkGeometry {
            // The INDEXES-bit single source (the derived supply of
            // T-011 §6.3): the Chunked state always maps to a unit.
            unit: desc
                .addr_state
                .chunk_unit()
                .expect("the Chunked state always yields a chunk unit"),
            chunkbits: *bits,
        }),
        AddrState::Flat | AddrState::Compressed => None,
    };
    DataGeometry {
        size: desc.size,
        block_bits: u32::from(sb.blkszbits),
        raw_blkaddr: desc.raw_blkaddr(),
        tail_inline: desc.datalayout == DataLayout::FlatInline,
        inline_data_start: inline_data_start(sb, nid, desc),
        chunk,
        compressed: desc.is_data_compressed(),
    }
}

// ---------------------------------------------------------------------------
// On-disk raw records: the dual-format inode family (T-022 S05;
// `docs/T-011/S03/index.md` §3/§4/§6, `docs/T-011/analysis.md` §2.1).
// ---------------------------------------------------------------------------

/// The erofs on-disk compact inode (`erofs_inode_compact`,
/// linux/fs/erofs/erofs_fs.h:156-171; field semantics single-sourced
/// in `docs/T-001/analysis.md` §4.3).
///
/// The 32-byte reduced form of the dual on-disk inode formats. The
/// layout invariant shared with the extended form (asserted on both
/// sides below): `i_format`/`i_xattr_icount`/`i_mode`/`i_u` sit at
/// the same offsets @0/@2/@4/@16 — the structural premise that lets
/// the decode entry pre-read the 2-byte `i_format`, run the I3/I4
/// guards, and pick the layout before reading the full record (the
/// source side sequences the same way: inode.c:53-67 ahead of :69;
/// the entry read itself lands with T-022 S08).
///
/// Being a le32, `i_size` can never exceed `i64::MAX`, so the
/// negative-size guard I7 is structurally unreachable on this form
/// and no fake guard is fabricated (G7) — the guard lives on the
/// extended form only.
// No deadness attribute: the permanent `const_assert!` layout anchors
// below reference the type and each of its 11 fields, so both stay
// live in every cfg and an `#[expect(dead_code)]` would only be
// reported unfulfilled (same rationale as `RawDeviceSlot` in
// `super_block.rs`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct RawInodeCompact {
    /// The inode format hints: bit 0 = version, bits 1-3 = datalayout,
    /// bits 4-15 reserved — a 1 + 3 bit split, not half-nibbles (the
    /// bit family constants live below). Its single E1 conversion is
    /// the entry's 2-byte pre-read; no conversion point re-reads it.
    pub i_format: u16, // @0  __le16
    /// The inline-xattr size in 4-byte units (0 = none); converted
    /// through the `xattr_ibody_size` helper at the decode (T-022
    /// S06/S07).
    pub i_xattr_icount: u16, // @2  __le16
    /// The raw mode word (S_IFMT nibble + permission bits), carried
    /// as-is; the `FileKind::from_raw_i_mode` discrimination lands
    /// with T-022 S06.
    pub i_mode: u16, // @4  __le16
    /// The hard-link count, carried as-is including 0 (the ext2
    /// link-count ESTALE door is an ext2-specific defense and is
    /// deliberately not transcribed).
    pub i_nlink: u16, // @6  __le16
    /// The file size; the le32 domain caps it at 4GiB - 1.
    pub i_size: u32, // @8  __le32
    /// Reserved; never read (G5).
    pub i_reserved: u32, // @12 __le32
    /// The C union `i_u` (erofs_fs.h:141-153), carried as the minimal
    /// common width integer (U1: Rust unions are structurally excluded
    /// in the safe-Rust kernel tree). Four readings of one 32-bit
    /// value, discriminated by the consumer — never by this record:
    ///
    /// - `compressed_blocks` __le32 (:143): the total compressed
    ///   block count of a compressed inode;
    /// - `raw_blkaddr` __le32 (:146): the data start block of an
    ///   uncompressed flat inode;
    /// - `rdev` __le32 (:149): the device number of a CHR/BLK inode
    ///   (decoded through the new_decode_dev bit pattern);
    /// - `c` `erofs_inode_chunk_info` (:152): the chunk summary of a
    ///   chunk-based inode.
    ///
    /// Fidelity is the two-independent-passes discipline (T-003 §1.4):
    /// the single `u32::from_le` at the decode yields the one
    /// host-order `iu` every reading is a view of — pathological
    /// kind x datalayout combinations (CHR x compressed, FIFO x
    /// chunk, ...) are accepted parity behavior. The chunk-info
    /// reading decomposes as `chunkformat = iu as u16` (format@0 in
    /// LE means the low half, and the 4-byte size of
    /// `RawInodeChunkInfo` means the bit widths coincide — both
    /// mechanically proven by its layout assertions), while the
    /// reserved half (`iu >> 16`) is never read or checked (G5).
    pub i_u: u32, // @16
    /// 32-bit stat compatibility field; deliberately not consumed —
    /// st_ino derives from the nid (X2).
    pub i_ino: u32, // @20 __le32
    /// The 16-bit uid (zero-extended at the decode).
    pub i_uid: u16, // @24 __le16
    /// The 16-bit gid (zero-extended at the decode).
    pub i_gid: u16, // @26 __le16
    /// Reserved; never read (G5).
    pub i_reserved2: u32, // @28 __le32
}

// Layout triple and per-field offsets (A1), each anchored to
// linux/fs/erofs/erofs_fs.h; the source-side counterpart of the size
// assertion is BUILD_BUG_ON at erofs_fs.h:443.
const_assert!(size_of::<RawInodeCompact>() == 32); // erofs_fs.h:443
const_assert!(align_of::<RawInodeCompact>() == 4); // the le32 members pin the alignment
const_assert!(offset_of!(RawInodeCompact, i_format) == 0); // erofs_fs.h:157
const_assert!(offset_of!(RawInodeCompact, i_xattr_icount) == 2); // erofs_fs.h:160
const_assert!(offset_of!(RawInodeCompact, i_mode) == 4); // erofs_fs.h:161
const_assert!(offset_of!(RawInodeCompact, i_nlink) == 6); // erofs_fs.h:162
const_assert!(offset_of!(RawInodeCompact, i_size) == 8); // erofs_fs.h:163
const_assert!(offset_of!(RawInodeCompact, i_reserved) == 12); // erofs_fs.h:164
const_assert!(offset_of!(RawInodeCompact, i_u) == 16); // erofs_fs.h:165
const_assert!(offset_of!(RawInodeCompact, i_ino) == 20); // erofs_fs.h:167
const_assert!(offset_of!(RawInodeCompact, i_uid) == 24); // erofs_fs.h:168
const_assert!(offset_of!(RawInodeCompact, i_gid) == 26); // erofs_fs.h:169
const_assert!(offset_of!(RawInodeCompact, i_reserved2) == 28); // erofs_fs.h:170

/// The erofs on-disk extended inode (`erofs_inode_extended`,
/// linux/fs/erofs/erofs_fs.h:174-191; field semantics single-sourced
/// in `docs/T-001/analysis.md` §4.4).
///
/// The 64-byte complete form of the dual on-disk inode formats,
/// sharing the discriminating prefix with the compact form
/// (`i_format`/`i_xattr_icount`/`i_mode`/`i_u` at @0/@2/@4/@16 — see
/// the compact form's doc). Two form-specific facts: the negative-
/// size guard I7 is reachable only here (the le64 domain; the guard
/// itself lands with the TryFrom decode, T-022 S07), and this record
/// is the only inode structure whose read may cross a block boundary
/// — the single 64-byte device-stream read handles that internally
/// (RD0; the entry read lands with T-022 S08).
// No deadness attribute — same const_assert liveness rationale as
// `RawInodeCompact` above.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct RawInodeExtended {
    /// The inode format hints — the shared discriminating prefix (see
    /// the compact form's `i_format` doc for the bit layout).
    pub i_format: u16, // @0  __le16
    /// The inline-xattr size in 4-byte units (0 = none).
    pub i_xattr_icount: u16, // @2  __le16
    /// The raw mode word (S_IFMT nibble + permission bits), carried
    /// as-is.
    pub i_mode: u16, // @4  __le16
    /// Reserved; never read (G5). Beware the cross-form name trap:
    /// this field is @6 __le16 here, while the compact form packs
    /// `i_nlink` into that slot and puts its own `i_reserved` at @12
    /// __le32 — same name, different slot and width (T-001 §4.4).
    pub i_reserved: u16, // @6  __le16
    /// The file size, le64 domain; the negative-size guard I7
    /// (`> i64::MAX` -> EUCLEAN) is reachable on this form only and
    /// lands with the TryFrom decode (T-022 S07). The giant-second
    /// domain is carried unchanged through the `Duration` decode
    /// (F6; the `as i64` truncation happens at the statx exit).
    pub i_size: u64, // @8  __le64
    /// The C union `i_u` — the same U1 carrier, four-reading table,
    /// two-passes discipline, and chunk-info decomposition as on the
    /// compact form's field (erofs_fs.h:141-153).
    pub i_u: u32, // @16
    /// 32-bit stat compatibility field; deliberately not consumed —
    /// st_ino derives from the nid (X2).
    pub i_ino: u32, // @20 __le32
    /// The 32-bit uid.
    pub i_uid: u32, // @24 __le32
    /// The 32-bit gid.
    pub i_gid: u32, // @28 __le32
    /// The modification time, seconds part; decoded with the nsec
    /// field through `utils::duration_from_parts` — F6 full-domain
    /// seconds plus the F6n giant-nsec normalization known-diff
    /// (reachable only from malformed images).
    pub i_mtime: u64, // @32 __le64
    /// The modification time, nanoseconds part.
    pub i_mtime_nsec: u32, // @40 __le32
    /// The hard-link count, carried as-is including 0 (no ESTALE
    /// door, same as the compact form).
    pub i_nlink: u32, // @44 __le32
    /// Reserved; never read (G5). A fixed byte array carried as-is
    /// (U2).
    pub i_reserved2: [u8; 16], // @48 __u8[16]
}

// Layout triple and per-field offsets (A1), each anchored to
// linux/fs/erofs/erofs_fs.h; the source-side counterpart of the size
// assertion is BUILD_BUG_ON at erofs_fs.h:444.
const_assert!(size_of::<RawInodeExtended>() == 64); // erofs_fs.h:444
const_assert!(align_of::<RawInodeExtended>() == 8); // the le64 members pin the alignment
const_assert!(offset_of!(RawInodeExtended, i_format) == 0); // erofs_fs.h:175
const_assert!(offset_of!(RawInodeExtended, i_xattr_icount) == 2); // erofs_fs.h:178
const_assert!(offset_of!(RawInodeExtended, i_mode) == 4); // erofs_fs.h:179
const_assert!(offset_of!(RawInodeExtended, i_reserved) == 6); // erofs_fs.h:180
const_assert!(offset_of!(RawInodeExtended, i_size) == 8); // erofs_fs.h:181
const_assert!(offset_of!(RawInodeExtended, i_u) == 16); // erofs_fs.h:182
const_assert!(offset_of!(RawInodeExtended, i_ino) == 20); // erofs_fs.h:184
const_assert!(offset_of!(RawInodeExtended, i_uid) == 24); // erofs_fs.h:185
const_assert!(offset_of!(RawInodeExtended, i_gid) == 28); // erofs_fs.h:186
const_assert!(offset_of!(RawInodeExtended, i_mtime) == 32); // erofs_fs.h:187
const_assert!(offset_of!(RawInodeExtended, i_mtime_nsec) == 40); // erofs_fs.h:188
const_assert!(offset_of!(RawInodeExtended, i_nlink) == 44); // erofs_fs.h:189
const_assert!(offset_of!(RawInodeExtended, i_reserved2) == 48); // erofs_fs.h:190

/// The erofs on-disk chunk info (`erofs_inode_chunk_info`,
/// linux/fs/erofs/erofs_fs.h:136-139; field semantics single-sourced
/// in `docs/T-001/analysis.md` §4.5.1).
///
/// A registration-only record (IN2): on disk these 4 bytes live
/// inside the `i_u` union slot and always arrive through the
/// decomposition documented on the `i_u` fields above (`iu as u16`),
/// so this structure never enters a read path, is never constructed,
/// and derives no `Pod`. The layout assertions below are the
/// mechanical proof of that decomposition — `format` at offset 0
/// means the low 16 bits in LE, and the 4-byte size means the bit
/// widths coincide with `i_u`; the runtime consumer is the
/// decomposition itself, not a constructor. The reserved half is
/// never read or checked (G5), and no helper exists for it (no
/// consumer-less functions).
// No deadness attribute — same const_assert liveness rationale as
// `RawInodeCompact` above.
#[repr(C)]
pub(super) struct RawInodeChunkInfo {
    /// The chunk format: bits 0-4 = the chunk-blkbits shift, bit 5 =
    /// INDEXES (the `CHUNK_FORMAT_*` constants below). The I10
    /// unknown-bit guard consumes `CHUNK_FORMAT_ALL` at the decode
    /// (T-022 S07).
    pub format: u16, // @0 __le16
    /// Reserved; never read (G5).
    pub reserved: u16, // @2 __le16
}

// Layout triple and per-field offsets (A1), each anchored to
// linux/fs/erofs/erofs_fs.h; the source-side counterpart of the size
// assertion is BUILD_BUG_ON at erofs_fs.h:447.
const_assert!(size_of::<RawInodeChunkInfo>() == 4); // erofs_fs.h:447
const_assert!(align_of::<RawInodeChunkInfo>() == 2); // the le16 members pin the alignment
const_assert!(offset_of!(RawInodeChunkInfo, format) == 0); // erofs_fs.h:137
const_assert!(offset_of!(RawInodeChunkInfo, reserved) == 2); // erofs_fs.h:138

// The element-wise chunk record `RawInodeChunkIndex` (with its 5
// layout assertions) and the `NULL_ADDR` hole sentinel live in
// `inode/data.rs` since T-025 S01 (S01-D6): their only runtime
// consumers are the map-path reads hosted there.

// ---------------------------------------------------------------------------
// The i_format bit family and the inode-domain constants (T-011 §2.2;
// on-disk facts transcribed from linux/fs/erofs/erofs_fs.h, referenced
// by path at their consumption sites, never forwarded through the
// prelude).
// ---------------------------------------------------------------------------

/// The version bit position within `i_format`
/// (`EROFS_I_VERSION_BIT`, erofs_fs.h:117).
// Live through the extraction helpers at the bottom of this file: an
// item carrying `#[expect(dead_code)]` is a dead-code-analysis root,
// and its references count (same rationale as `SUPER_OFFSET` in
// `super_block.rs`).
pub(super) const I_VERSION_BIT: u16 = 0;

/// The version bit mask (`EROFS_I_VERSION_MASK`, erofs_fs.h:114).
// Live through `inode_version` — same rationale as `I_VERSION_BIT`.
pub(super) const I_VERSION_MASK: u16 = 0x01;

/// The datalayout bit position within `i_format`
/// (`EROFS_I_DATALAYOUT_BIT`, erofs_fs.h:118).
// Live through `inode_datalayout` — same rationale as
// `I_VERSION_BIT`.
pub(super) const I_DATALAYOUT_BIT: u16 = 1;

/// The datalayout bit mask (`EROFS_I_DATALAYOUT_MASK`,
/// erofs_fs.h:115).
// Live through `inode_datalayout` — same rationale as
// `I_VERSION_BIT`.
pub(super) const I_DATALAYOUT_MASK: u16 = 0x07;

/// The full low-bit domain of `i_format` (`EROFS_I_ALL` =
/// `(1 << EROFS_I_ALL_BIT) - 1`, erofs_fs.h:121): version +
/// datalayout, bits 0-3. The I3 guard mask — any bit above it (the
/// 0xFFF0 remainder of the le16 domain) is "unsupported i_format"
/// (EOPNOTSUPP, inode.c:53-59).
// Live since T-022 S06: consumed by the I3 guard of `parse_i_format`
// below — an `#[expect(dead_code)]` function is a dead-code-analysis
// root, and its references count. The bridging `expect` was removed
// when that consumer landed.
pub(super) const I_ALL: u16 = 0x0F;

/// The compact-layout discriminant (`EROFS_INODE_LAYOUT_COMPACT`,
/// erofs_fs.h:132): the version-bit value selecting the 32-byte
/// on-disk form.
// Live since T-022 S06: referenced by the compile-time discriminant
// lock beside `InodeVersion` (and spelled on the else arm of the
// version construction in `parse_i_format` — the 1-bit extraction
// domain makes that arm exactly this value).
pub(super) const INODE_LAYOUT_COMPACT: u8 = 0;

/// The extended-layout discriminant (`EROFS_INODE_LAYOUT_EXTENDED`,
/// erofs_fs.h:134): the version-bit value selecting the 64-byte
/// on-disk form.
// Live since T-022 S06: referenced by the compile-time discriminant
// lock beside `InodeVersion` and compared directly by the version
// construction in `parse_i_format`.
pub(super) const INODE_LAYOUT_EXTENDED: u8 = 1;

/// The datalayout sentinel (`EROFS_INODE_DATALAYOUT_MAX`,
/// erofs_fs.h:104) — the I4 criterion: an extracted datalayout >= 5
/// (the reserved values 5-7) is "unsupported datalayout" (EOPNOTSUPP,
/// inode.c:61-67). The five legitimate discriminants 0-4 land as the
/// `DataLayout` enum variants below, not as constants here —
/// the enum carries the disk values itself.
// Live since T-022 S06: consumed by the I4 guard of `parse_i_format`
// below — same root-reference rationale as `I_ALL`.
pub(super) const INODE_DATALAYOUT_MAX: u8 = 5;

/// The chunk-blkbits field mask within the chunk-info format
/// (`EROFS_CHUNK_FORMAT_BLKBITS_MASK`, erofs_fs.h:124): chunksize =
/// blocksize << chunk-blkbits. The 5-bit domain is carried in full,
/// with no upper-bound check (T-001 §6.6).
// Live since T-022 S07: consumed by the chunkbits formula of the D9
// decode — `blkszbits + (format & CHUNK_FORMAT_BLKBITS_MASK)`. The
// bridging `expect` was removed when the first consumer landed.
pub(super) const CHUNK_FORMAT_BLKBITS_MASK: u16 = 0x001F;

/// The chunk-index flag (`EROFS_CHUNK_FORMAT_INDEXES`,
/// erofs_fs.h:126): extent area made of 8-byte chunk indexes versus a
/// bare 4-byte blkaddr array.
// Live since T-022 S06: consumed by `AddrState::chunk_unit` below —
// live since T-025 S01 through `data_geometry` (the chunk unit of
// `ChunkGeometry`); the chunked map path (`inode/data.rs`, S04)
// joins through the stored unit.
pub(super) const CHUNK_FORMAT_INDEXES: u16 = 0x0020;

/// The union of the known chunk-format bits
/// (`EROFS_CHUNK_FORMAT_ALL`, erofs_fs.h:128-129) — the I10 guard
/// mask: any bit outside it is "unsupported chunk format"
/// (EOPNOTSUPP, inode.c:170-175).
// Live since T-022 S07: consumed by the I10 guard of the TryFrom
// decode. The bridging `expect` was removed when the first consumer
// landed.
pub(super) const CHUNK_FORMAT_ALL: u16 = 0x003F;

/// `EROFS_BLOCK_MAP_ENTRY_SIZE = sizeof(__le32)` (erofs_fs.h:266):
/// the element width of the INDEXES=0 bare block-address array. The
/// bare `__le32[]` stream has no structure to host a layout
/// assertion (U3 — no fabricated structures), so this constant is
/// its only registered form.
// Live since T-022 S06: consumed by `AddrState::chunk_unit` below
// (the INDEXES=0 unit of that accessor); the chunked extent walk
// (`inode/data.rs`, T-025) joins through it. The bridging `expect`
// was removed when the first consumer landed.
pub(super) const BLOCK_MAP_ENTRY_SIZE: usize = 4;

/// islotbits = ilog2(sizeof(erofs_inode_compact)) = 5 (super.c:336):
/// the inode-slot width is the fixed 32-byte stride, independent of
/// whether the inode actually stored in a slot is compact or extended
/// (T-001 §4.1). Derived from the structure size — same-sourced with
/// the layout assertions above (C5) — and never written as the
/// literal 5.
// Live since T-023 S04 (the iloc formula of `Erofs::iget`); since
// T-024 S01 the formula lives here as `inode_location` above — the
// step-1 base point of the five-step decode, consumed on every slow
// iget path.
pub(super) const ISLOT_BITS: u32 = size_of::<RawInodeCompact>().ilog2();

// ---------------------------------------------------------------------------
// i_format extraction (parity with internal.h:296-304). The input is
// the host-order value after the entry pre-read's single `from_le` —
// bit-domain decomposition always happens after the endianness
// conversion (E1).
// ---------------------------------------------------------------------------

/// Extracts the version bit from `i_format` (the parity of
/// `erofs_inode_version`, internal.h:296-299).
// Live since T-022 S06: called by `parse_i_format` below; the entry
// read (T-022 S08) joins through it.
fn inode_version(ifmt: u16) -> u8 {
    ((ifmt >> I_VERSION_BIT) & I_VERSION_MASK) as u8
}

/// Extracts the datalayout bits from `i_format` (the parity of
/// `erofs_inode_datalayout`, internal.h:301-304).
// Live since T-022 S06: called twice by `parse_i_format` below (the
// I4 guard and the `DataLayout` construction).
fn inode_datalayout(ifmt: u16) -> u8 {
    ((ifmt >> I_DATALAYOUT_BIT) & I_DATALAYOUT_MASK) as u8
}

// ---------------------------------------------------------------------------
// The typed vocabulary: four enums, the InodeDesc mirror, the
// xattr-size helper, and the entry's one-shot i_format validation
// (T-022 S06; `docs/T-011/S05/index.md` §2/§3, `docs/T-011/S03/
// index.md` §2.2, `docs/T-011/S06/index.md` §1.1, `docs/T-011/
// analysis.md` §3.2).
// ---------------------------------------------------------------------------

/// The inode layout version (i_format bit 0; the discriminants are
/// the on-disk `EROFS_INODE_LAYOUT_*` values).
///
/// No `Invalid` variant: the 1-bit domain has exactly two values, and
/// the sole construction entrance is `parse_i_format` below — the
/// source-side version switch default (inode.c:126-130,
/// -EOPNOTSUPP) is structurally unreachable and is not fabricated as
/// an error arm (G7, T-001 §9.7.1). The TryFrom conversions
/// additionally carry the version statically in their input types,
/// so no dispatch on it can miss a case.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InodeVersion {
    /// The 32-byte on-disk form (`EROFS_INODE_LAYOUT_COMPACT`).
    Compact = 0, // erofs_fs.h:132
    /// The 64-byte on-disk form (`EROFS_INODE_LAYOUT_EXTENDED`).
    Extended = 1, // erofs_fs.h:134
}

// The on-disk layout discriminants and the enum's own discriminants
// are the same values — locked here at compile time so the version
// construction of `parse_i_format` and the disk layout stay
// same-sourced (C5). Underscore-named consts are dead-code-exempt
// themselves yet count as uses of the referenced items.
const _: () = {
    assert!(INODE_LAYOUT_COMPACT == InodeVersion::Compact as u8);
    assert!(INODE_LAYOUT_EXTENDED == InodeVersion::Extended as u8);
};

/// The data layout (i_format bits 1-3; the discriminants are the
/// on-disk values, erofs_fs.h:98-104).
///
/// The reserved values 5-7 never become variants: the I4 guard of
/// the entry validation rejects them before construction
/// (EOPNOTSUPP, inode.c:61-67), so the type carries no
/// reserved-value or `Invalid` variants and no unreachable match arm
/// exists anywhere (T-001 §9.7.1). The exhaustive classification of
/// the low nibble — 16 combinations, 0x0-0x9 passing (ten) and
/// 0xA-0xF rejected by I4 (six) — is the design/verification ledger
/// (`docs/T-011/S06/index.md` §3.2), not a runtime surface.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DataLayout {
    /// Data sits at the `i_u` flat block address.
    FlatPlain = 0, // erofs_fs.h:99
    /// Compressed data, full form (`EROFS_INODE_FLAT_COMPRESSED`).
    CompressedFull = 1, // erofs_fs.h:100
    /// The file tail is inline after the inode record.
    FlatInline = 2, // erofs_fs.h:101
    /// Compressed data, compact form
    /// (`EROFS_INODE_COMPACT_COMPRESSED`).
    CompressedCompact = 3, // erofs_fs.h:102
    /// The extent area is a chunk-index or block-map array.
    ChunkBased = 4, // erofs_fs.h:103
}

impl DataLayout {
    /// The parity of `erofs_is_data_compressed` (erofs_fs.h:107-111):
    /// datalayout ∈ {1, 3}. The single source of this predicate —
    /// the TryFrom D9/D12 accounting consumes it first, and the
    /// layer-3 rejection site `inode/data.rs::map_blocks`
    /// (datalayout ≠ flat → EOPNOTSUPP, T-025) forwards through it,
    /// never rewrites it.
    // Live since T-022 S07: consumed by the D9/D12 segments of the
    // TryFrom bodies. The bridging `expect` was removed when the
    // first consumer landed.
    pub(super) fn is_compressed(&self) -> bool {
        matches!(self, Self::CompressedFull | Self::CompressedCompact)
    }
}

// The `i_mode` type-bit constants (include/uapi/linux/stat.h facts,
// transcribed as the module-private host — no framework-wide host
// exists: `InodeType` carries its own local `TYPE_MASK`, and its
// `from_raw_mode` is the rejected precedent documented on `FileKind`).
const S_IFMT: u16 = 0o170000;
const S_IFIFO: u16 = 0o010000;
const S_IFCHR: u16 = 0o020000;
const S_IFDIR: u16 = 0o040000;
const S_IFBLK: u16 = 0o060000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;
const S_IFSOCK: u16 = 0o140000;

/// The S_IFMT type segment of `i_mode`, typed (T-001 §9.7.4 full
/// form; the parity of the source switch, inode.c:138-155).
///
/// The sole construction entrance is `from_raw_i_mode`. The
/// framework's `InodeType::from_raw_mode`
/// (`file/inode_attr/type.rs:38-48`) is deliberately not used: it
/// special-cases mode==0 to `File` (linux reports -EFSCORRUPTED
/// there) and reports unknown types as EINVAL — a double drift from
/// the linux behavior this decode mirrors (the ext2 negative
/// precedent, G-N01 candidate 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FileKind {
    /// S_IFREG.
    Reg,
    /// S_IFDIR.
    Dir,
    /// S_IFLNK.
    Lnk,
    /// S_IFCHR.
    Chr,
    /// S_IFBLK.
    Blk,
    /// S_IFIFO.
    Fifo,
    /// S_IFSOCK.
    Sock,
    /// Any S_IFMT value outside the seven kinds — nine of the
    /// sixteen nibble values. The I8 guard rejects this variant with
    /// EUCLEAN at construction, so a runtime `InodeDesc` never
    /// carries it; the variant itself is the guard-carrying face and
    /// keeps every kind match default-free (T-001 §9.7.4). The
    /// payload is the nibble value, kept for diagnostics.
    // AUTO-DECISION: no dead-code suppression on the payload — the
    // in-crate clippy -Dwarnings run (T-022 S06 test round) proved
    // the field-never-read finding does not fire at this position
    // (the standalone-probe prediction diverged: the sole
    // construction site lives inside the not-yet-called
    // `from_raw_i_mode`), so an expect here stays unfulfilled.
    Other(u8),
}

impl FileKind {
    /// Types the S_IFMT segment of `i_mode`. Exhaustive over the 16
    /// nibble values: the seven kinds {1, 2, 4, 6, 8, A, C} pass and
    /// the other nine land in `Other` (the low 12 permission bits
    /// are irrelevant here — they are carried losslessly by the
    /// `mode` field, X3).
    // Live since T-022 S07: consumed by the kind decode and the I8
    // guard of the TryFrom bodies. The bridging `expect` was removed
    // when the first consumer landed.
    fn from_raw_i_mode(i_mode: u16) -> Self {
        match i_mode & S_IFMT {
            S_IFIFO => Self::Fifo,
            S_IFCHR => Self::Chr,
            S_IFDIR => Self::Dir,
            S_IFBLK => Self::Blk,
            S_IFREG => Self::Reg,
            S_IFLNK => Self::Lnk,
            S_IFSOCK => Self::Sock,
            other => Self::Other((other >> 12) as u8),
        }
    }
}

/// The framework-type view of a decoded kind (S03-D3): the
/// seven-kind bijection, the single source behind the trait
/// `type_()` face and the metadata assembly (one conversion, no
/// per-site re-mapping). The `Other` arm is structurally unreachable
/// — the I8 guard rejects it with `EUCLEAN` before a descriptor
/// escapes the decode — and exists only to keep the match
/// exhaustive.
impl From<FileKind> for InodeType {
    fn from(kind: FileKind) -> Self {
        match kind {
            FileKind::Reg => Self::File,
            FileKind::Dir => Self::Dir,
            FileKind::Lnk => Self::SymLink,
            FileKind::Chr => Self::CharDevice,
            FileKind::Blk => Self::BlockDevice,
            FileKind::Fifo => Self::NamedPipe,
            FileKind::Sock => Self::Socket,
            // Unreachable: the I8 guard ("bogus i_mode", EUCLEAN)
            // rejects the Other kind at the decode, so a runtime
            // descriptor never carries it.
            FileKind::Other(_) => unreachable!("I8 rejects the Other kind at decode"),
        }
    }
}

/// The D9 cross-cutting discrimination product — the decoded form of
/// the second, datalayout-driven reading of `i_u` (T-001 §9.7.3,
/// archive-A form).
///
/// The source-side `vi` union "one storage overwritten per stage"
/// cannot exist under decode-once plus mutually-exclusive-layer
/// trimming: the enum makes the alias-overwrite unrepresentable, and
/// the D9 discrimination is driven by `datalayout` alone — it is
/// structurally never placed inside a kind branch (the pathological
/// kind x datalayout combinations are accepted parity behavior,
/// T-003 §1.4).
// The variants are constructed by the TryFrom D9 segments below. The
// enum-level bridging `expect` was removed in the T-022 S07 test
// round: trait impls are live roots of the in-crate dead-code
// analysis, so the conversions' constructions are already visible
// and the expectation came out unfulfilled (the standalone probe had
// predicted the bodies stay invisible — it diverged). The `bits`
// payload is read by the geometry collapse (`data_geometry`,
// T-025 S01); the map-path dispatch joins through the stored
// chunkbits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AddrState {
    /// FLAT_PLAIN / FLAT_INLINE: the data start is the `raw_blkaddr`
    /// reading of `i_u` (accessor landing with T-022 S07). Carries
    /// no copy of the u32 — the value is always `i_u`, and a
    /// duplicate would violate the single-data-source discipline.
    Flat,
    /// CHUNK_BASED: the chunk metadata materialized once at the
    /// decode. `format` keeps the raw chunk-format word (the INDEXES
    /// bit is consumed by `chunk_unit()`); `bits` = sb.blkszbits +
    /// (format & CHUNK_FORMAT_BLKBITS_MASK) (inode.c:176-177; the
    /// 5-bit domain is carried in full, no upper-bound check). The
    /// I10 guard runs before the materialization, so a format with
    /// unknown bits never enters this variant.
    Chunked { format: u16, bits: u32 },
    /// Compressed (archive A): decoded and accepted (T-003 §1.4),
    /// with the `compressed_blocks` reading of `i_u` consumed inside
    /// the conversion body by the nr_sectors accounting (D12) — no
    /// post-decode consumer copy remains, and the layer-3 rejection
    /// (I12) belongs to `inode/data.rs::map_blocks` (T-025).
    /// Revival note: this variant gains its z_* payload with the
    /// G-Z01 archive-C takeover.
    Compressed,
}

impl AddrState {
    /// The extent element unit of the chunked map path (the derived
    /// supply of `docs/T-011/S03/index.md` §6.3): INDEXES (format
    /// bit 5) set → `size_of::<RawInodeChunkIndex>()` (the record
    /// migrated to `inode/data.rs`, T-025 S01), otherwise
    /// `BLOCK_MAP_ENTRY_SIZE`; `None` outside the chunked state.
    /// `data.rs` takes the unit through this accessor and does not
    /// reference the mod.rs domain constants directly (the
    /// cross-file discipline, T-010 §3.2).
    // Live since T-025 S01: consumed by `data_geometry` (the chunk
    // unit of `ChunkGeometry`); the chunked extent walk
    // (`inode/data.rs`, S04) joins through the stored unit.
    pub(super) fn chunk_unit(&self) -> Option<usize> {
        match self {
            Self::Flat | Self::Compressed => None,
            Self::Chunked { format, .. } => Some(if format & CHUNK_FORMAT_INDEXES != 0 {
                size_of::<RawInodeChunkIndex>()
            } else {
                BLOCK_MAP_ENTRY_SIZE
            }),
        }
    }
}

/// The erofs in-memory inode descriptor — the decoded mirror of the
/// dual-format on-disk records (the ext2 counterpart is
/// `ext2/inode/mod.rs:233-254`).
///
/// Decoded once, wholly immutable after construction (the
/// mutually-exclusive-layer-trim model, T-010 §5.3 D2); the resident
/// `Inode` handle (T-024) carries one. The sole construction
/// entrances are the two TryFrom conversions (T-022 S07) — the
/// filesystem is read-only, so there is no ext2-style `new()`
/// creator and no write-direction `From<&InodeDesc>` either.
///
/// # Field liveness (dead-code ledger)
///
/// The same discipline as the `SuperBlock` mirror. Trait impls are
/// live roots of the in-crate dead-code analysis, so the two
/// conversion bodies (S07) are already visible — every helper they
/// reference stays live through them (the S07 test round removed the
/// eight first-consumer expects that came out unfulfilled). Writes
/// are not reads, though: a field is only live once live code reads
/// it. `version` (through `inode_isize()`), `datalayout`, `kind`,
/// `i_u`, `size`, `xattr_isize`, and `addr_state` (read by
/// `data_geometry` since T-025 S01) are live through the decode /
/// payload-assembly chain (the iget slow path reads them all since
/// T-024 S01), while the remaining fields carry their own
/// `#[expect(dead_code)]` with the first consumer annotated, firing
/// `unfulfilled` as the removal prompt when that consumer lands.
///
/// # Not-mirrored ledger (explicit, `docs/T-011/analysis.md` §3.2)
///
/// `nid` (st_ino derives from it on the handle, X2), `i_ino` (never
/// read, X2), `i_reserved`/`i_reserved2` (G5), `nblks` (the
/// compressed-blocks reading is consumed inside the conversion body
/// by the D12 accounting — no post-decode consumer exists in
/// archive A), the `rdev` bit pattern (an accessor face, not a
/// field), separate ctime/atime copies (D10: the three times are
/// one field), and btime (no on-disk source, X9 — the assembler
/// fills `None`).
#[derive(Clone, Copy, Debug)]
pub(super) struct InodeDesc {
    /// The on-disk layout version (carried statically by the TryFrom
    /// input type; read by `inode_isize()` below).
    pub(super) version: InodeVersion,
    /// The data layout — the entry's one-shot discrimination product,
    /// flowing in as a conversion parameter (I3/I4 are never
    /// re-judged here).
    // Live since T-023 S04 (the layer-3 predicate); the payload
    // dispatch and the backend-geometry discrimination joined with
    // T-024 S01 (`InodePayload::new` / `new_data_backed` above).
    pub(super) datalayout: DataLayout,
    /// Runtime invariant: never `Other` — the I8 guard rejects at
    /// construction, so `Other` exists only on the guard-carrying
    /// face.
    // Live since T-022 S07: read by the accessor premises below; the
    // framework-type mapping and the payload dispatch joined with
    // T-024 S01 (`From<FileKind>` above, `InodePayload::new` below).
    pub(super) kind: FileKind,
    /// The 12 permission bits, carried losslessly (X3: no permission
    /// canonicalization at the decode).
    // Live since T-024 S02: read by the metadata assembly
    // (`Inode::metadata`, the Metadata.mode field).
    pub(super) mode: InodeMode,
    /// The owner id (zero-extended from le16 on the compact form).
    // Live since T-024 S02: the Uid wrapper in the metadata assembly.
    pub(super) uid: u32,
    /// The group id (zero-extended from le16 on the compact form).
    // Live since T-024 S02: the Gid wrapper in the metadata assembly.
    pub(super) gid: u32,
    /// The hard-link count, carried as-is including 0 — the ext2
    /// link-count ESTALE door is an ext2-specific defense and is
    /// deliberately not transcribed.
    // Live since T-024 S02: Metadata.nr_hard_links (as usize).
    pub(super) nlink: u32,
    /// The file size. Construction invariant: <= i64::MAX (the
    /// extended form via the I7 guard, the compact form by the le32
    /// width).
    // Live since T-024 S01: read by the payload assembly (the
    // page-cache capacity, the flat geometry, the fast/slow
    // judgement, and the inline-target read length); the metadata
    // face (S02, as usize) joins next.
    pub(super) size: u64,
    /// The inline-xattr area size, as converted by
    /// `xattr_ibody_size` — an unvalidated value carried in the
    /// mirror; the boundary guard belongs to the consumer (T-026).
    // Live since T-024 S01: read by `inline_data_start` (the
    // base-point formula family) — the fast/slow criterion and the
    // inline read point consume the same single source; the
    // three-state gate / ibody location (T-026) joins through it.
    pub(super) xattr_isize: usize,
    /// The modification time (the F6/F6n carrier discipline: the
    /// le64 seconds domain is carried unchanged — the `as i64`
    /// truncation happens at the statx exit — and a malformed nsec
    /// >= 1e9 normalizes through `duration_from_parts`, the F6n
    /// known-diff, reachable only from malformed images). D10: the
    /// three Metadata times are filled from this one field; the
    /// compact form copies `sb.build_time` (the same-source
    /// derivation).
    // AUTO-TODO(G-M17): Linux assembles sb->s_time_gran at mount; aster's
    // SuperBlock is a statfs result struct with no assembly surface, so the
    // granularity semantics are carried here: timestamps decode into
    // nanosecond-resolution Durations at inode-read time (compact inodes
    // derive ctime from the superblock build time).
    // Live since T-024 S02: the three Metadata times (one Duration,
    // three copies) in the metadata assembly.
    pub(super) time: Duration,
    /// The C union `i_u` as the single host-order source (the
    /// conversion body's one `from_le`); every reading — the
    /// first-pass kind views and the second-pass datalayout views —
    /// is a view of this one value, never a re-interpretation in
    /// place (the two-independent-passes fidelity, T-003 §1.3).
    // Live since T-022 S07: read by the ID4 accessors below.
    pub(super) i_u: u32,
    /// The D9 discrimination product (see `AddrState`).
    // Live since T-025 S01: read by `data_geometry` (the chunk
    // geometry supply and the chunk_unit single source); the
    // map-path dispatch (S03) joins through the stored geometry.
    pub(super) addr_state: AddrState,
    /// The 512-byte-sector accounting — the D12 dual-caliber product
    /// (the formula's single source is the G-Z02 note inside the
    /// conversion bodies, T-022 S07).
    // Live since T-024 S02: Metadata.nr_sectors_allocated reads it
    // verbatim (the G-Z02 assembly-side zero-formula discipline).
    pub(super) nr_sectors: usize,
}

impl InodeDesc {
    /// The per-version on-disk inode size (the source-side
    /// `vi->inode_isize`, inode.c:70/:76): consumes `size_of`
    /// directly — the layout assertions above already prove 32/64,
    /// so no literal is written (C5). The suffix location (inline
    /// xattr / inline data start = inode_isize + xattr_isize) is the
    /// consumer.
    // Live since T-024 S01: consumed by `suffix_xattr_start` (the
    // base-point formula family above); the extent-start location
    // (T-025) and the ibody location (T-026) join through the same
    // single source. The bridging `expect` was removed when the
    // first consumer landed.
    pub(super) fn inode_isize(&self) -> usize {
        match self.version {
            InodeVersion::Compact => size_of::<RawInodeCompact>(),
            InodeVersion::Extended => size_of::<RawInodeExtended>(),
        }
    }

    /// The first-pass `i_u` reading for REG/DIR/LNK: the data start
    /// block (D8, inode.c:142). No range check — out-of-volume and
    /// zero values are carried as-is; the rejection belongs to the
    /// data-path consumer (`inode/data.rs`, T-025).
    ///
    /// The `debug_assert` below pins the discrimination premise, not
    /// a disk value: its target is API misuse (a review-surface
    /// programming error), which is not an error path and never a
    /// parity surface (the DBG_BUGON discipline, G6, bans the
    /// opposite promotion of debug asserts into runtime checks).
    // Live since T-024 S01: the flat-region base of the minimal
    // data-backend geometry (`new_data_backed` above); the flat
    // direct mapping of the final map path (T-025) joins through the
    // same single value. The bridging `expect` was removed when the
    // first consumer landed.
    pub(super) fn raw_blkaddr(&self) -> u32 {
        debug_assert!(matches!(
            self.kind,
            FileKind::Reg | FileKind::Dir | FileKind::Lnk
        ));
        self.i_u
    }

    /// The first-pass `i_u` reading for CHR/BLK: the device number
    /// (D8, inode.c:151), through the `new_decode_dev` bit pattern
    /// (kdev_t.h:46-51): major = (v & 0xfff00) >> 8 (12 bits) and
    /// minor = (v & 0xff) | ((v >> 12) & 0xfff00) (20 bits) — exactly
    /// the full domains of `MajorId`/`MinorId`, so the ranged
    /// constructors have no reachable failure (linux decodes any
    /// le32 into a defined device number). The ext2 extended-branch
    /// precedent (`block_ptr_tree.rs:898-906`) is taken here without
    /// the encode/decode round trip, which is the identity on these
    /// widths. FIFO/SOCK have no reading path at all — the assembly
    /// fills `self_dev_id = None` for them (T-003 X6, T-024). Same
    /// premise-assert discipline as `raw_blkaddr` above.
    // Live since T-024 S01: the CHR/BLK assembly arm
    // (`InodePayload::new` → `Device`); the metadata face (S02)
    // joins through the payload's decoded copy. The bridging
    // `expect` was removed when the first consumer landed.
    pub(super) fn rdev(&self) -> DeviceId {
        debug_assert!(matches!(self.kind, FileKind::Chr | FileKind::Blk));
        let v = self.i_u;
        let major = (v & 0xfff00) >> 8;
        let minor = (v & 0xff) | ((v >> 12) & 0xfff00);
        DeviceId::new(MajorId::new(major as u16), MinorId::new(minor))
    }

    /// I12 predicate — rejection-chain layer 3 (G-M15): whether this
    /// inode carries compressed data whose consumers are shelved under
    /// scope decision AR-S01-5. Mirrors `erofs_fill_inode`: REG/DIR/LNK
    /// flow into the a_ops assignment and a compressed datalayout fails
    /// iget with EOPNOTSUPP under the non-ZIP build, while special
    /// files (CHR/BLK/FIFO/SOCK) return early and stay exempt. The
    /// runtime half of this rejection is lazy (map_blocks, T-014);
    /// this predicate is the single judgement source for both.
    // Live since T-023 S05: the F10/F11 mount-time site gates of
    // `Erofs::open` reach it through the `Inode` forwarder above
    // (which must not rewrite the criteria, single-source
    // contract); later joiners: the I12 assembly arm-first gate
    // (T-024) and the map_blocks defensive half (T-014). The
    // bridging `expect` was removed when the first consumer landed.
    pub(super) fn is_data_compressed(&self) -> bool {
        self.datalayout.is_compressed() // T-011 ID2: ⟺ ∈ {1, 3}
            && matches!(self.kind, FileKind::Reg | FileKind::Dir | FileKind::Lnk)
    }
}

/// The parity of `erofs_xattr_ibody_size` (erofs_fs.h:245-252):
/// icount == 0 → 0, otherwise 12 + 4 × (icount − 1).
///
/// An unconditional conversion with no boundary check: the le16
/// input domain caps the result at 262148 bytes and the mirror
/// deliberately carries the unvalidated value — the boundary guard
/// belongs to the consumption point (T-026). The literal 12 is the
/// `RawXattrIbodyHeader` size, same-valued with its layout
/// assertion in `xattr.rs` (a mutual proof — this file does not
/// reference the xattr.rs type, the L4 direction forbids it). The
/// two branches are exhaustive over the le16 domain, so the
/// (icount == 0, result == 12) corner is structurally unreachable
/// and no third arm exists (G7).
// Live since T-022 S07: consumed by the `xattr_isize` field decode
// of the TryFrom bodies. The bridging `expect` was removed when the
// first consumer landed.
fn xattr_ibody_size(icount: u16) -> usize {
    if icount == 0 {
        0
    } else {
        12 + 4 * (icount as usize - 1)
    }
}

/// The entry's one-shot `i_format` validation (step 3 of the
/// five-step decode, `docs/T-011/S05/index.md` §1.1): the I3/I4
/// guards, then the typed pair.
///
/// Guard order = the source execution order
/// (`docs/T-001/analysis.md` §9.2): I3 first — any bit above `I_ALL`
/// (the 0xFFF0 remainder of the le16 domain) is "unsupported
/// i_format" (EOPNOTSUPP, inode.c:53-59); I4 strictly after — an
/// extracted datalayout of 5..=7 (the reserved discriminants) is
/// "unsupported datalayout" (EOPNOTSUPP, inode.c:61-67). With both
/// malformed values present the first error is I3's (the same-errno
/// ordering, the observable face of the sequence).
///
/// The one-shot-validation defense: the discrimination read set is
/// exactly the 2 pre-read bytes, so a malformed value never triggers
/// the full-record read, any suffix read, or the cross-block stream
/// (`docs/T-011/S06/index.md` §4).
// Live since T-022 S08: called by `read_inode_desc` below; the T-024
// assembly (iloc computation + iget) joins through it.
fn parse_i_format(ifmt: u16) -> Result<(InodeVersion, DataLayout)> {
    if ifmt & !I_ALL != 0 {
        return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported i_format");
    }
    if inode_datalayout(ifmt) >= INODE_DATALAYOUT_MAX {
        return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported datalayout");
    }

    // The two guards above are the whole rejection face, so the
    // catch-all arms below fold only onto values already rejected
    // there: the version extraction masks to its 1-bit domain, and a
    // datalayout of 5..=7 has returned at I4 — no unreachable error
    // arm is fabricated (G7).
    let version = if inode_version(ifmt) == INODE_LAYOUT_EXTENDED {
        InodeVersion::Extended
    } else {
        InodeVersion::Compact // == INODE_LAYOUT_COMPACT (erofs_fs.h:132)
    };
    let datalayout = match inode_datalayout(ifmt) {
        0 => DataLayout::FlatPlain,         // erofs_fs.h:99
        1 => DataLayout::CompressedFull,    // erofs_fs.h:100
        2 => DataLayout::FlatInline,        // erofs_fs.h:101
        3 => DataLayout::CompressedCompact, // erofs_fs.h:102
        _ => DataLayout::ChunkBased,        // == 4 (erofs_fs.h:103); 5..=7 rejected at I4
    };
    Ok((version, datalayout))
}

// ---------------------------------------------------------------------------
// The dual TryFrom decode (T-022 S07; signatures `docs/T-011/S05/
// index.md` §1.2, field table §3.1, accessor shrink §5; guard and
// order spec `docs/T-011/S06/index.md` §1.1/§2.1; G-Z02 note
// `docs/T-011/analysis.md` §4.5). The compressed-blocks and chunk
// readings of `i_u` stay inline in these bodies (ID4: no
// consumer-less functions) — `nblks` is exhausted by the D12
// accounting below, the chunk metadata by the `AddrState::Chunked`
// materialization.
// ---------------------------------------------------------------------------

/// The compact-form decode: the D5 field accounting plus the I8/I10
/// guards.
///
/// The parameter-form triple (ID0): the version is carried statically
/// by the input type, `datalayout` is the entry's one-shot
/// discrimination product flowing in as a parameter (I3/I4 are never
/// re-judged here), and the superblock enters as one whole reference
/// — the three exogenous consumption points are the compact time
/// derivation, the chunkbits shift, and the D12 dual-caliber
/// accounting. The error face is {I8, I10}: the negative-size guard
/// I7 is structurally unreachable on this form — the le32 domain
/// caps `i_size` at 4GiB - 1 — and no fake guard is fabricated (G7;
/// the ext2 precedent `ext2/inode/mod.rs:316-318` is the
/// extended-form counterpart only, and the ext2 ESTALE and
/// symlink-size doors are deliberately not transcribed).
///
/// No I/O arm (the input is already an in-memory image; read errors
/// belong to the entry read, S08), no ENOMEM arm (all-Copy fields,
/// zero allocation, F4/G-M21), and no assembly-face guard (I12 and
/// the blkszbits door belong to the data path and the mount
/// sequence). Half-state invisibility (C1): every guard returns
/// before the `Ok` literal is assembled, so no partially-built
/// descriptor can escape the conversion.
impl TryFrom<(&RawInodeCompact, DataLayout, &SuperBlock)> for InodeDesc {
    type Error = Error;

    fn try_from(
        (raw, datalayout, sb): (&RawInodeCompact, DataLayout, &SuperBlock),
    ) -> Result<Self> {
        // D5 field decode: pure memory, no error exit — the source
        // copies the fields (inode.c:97-124) ahead of every content
        // guard. E1: every little-endian field converts exactly once,
        // here (the 7-field ledger, S05 §6; the `mode` local serves
        // both the kind discrimination and the permission bits).
        let mode = u16::from_le(raw.i_mode);
        let kind = FileKind::from_raw_i_mode(mode);
        let size = u32::from_le(raw.i_size) as u64;
        let xattr_isize = xattr_ibody_size(u16::from_le(raw.i_xattr_icount));
        let iu = u32::from_le(raw.i_u);

        // D8 (I8): the bogus-i_mode guard, strictly before the D9
        // cross-cut (inode.c:157-161 ahead of :164-178).
        if matches!(kind, FileKind::Other(_)) {
            return_errno_with_message!(Errno::EUCLEAN, "bogus i_mode");
        }

        // D9: the second, datalayout-driven reading of `iu` — never
        // inside a kind branch (the pathological kind x datalayout
        // combinations are accepted parity behavior, T-003 §1.4).
        let addr_state = match datalayout {
            DataLayout::FlatPlain | DataLayout::FlatInline => AddrState::Flat,
            DataLayout::CompressedFull | DataLayout::CompressedCompact => AddrState::Compressed,
            DataLayout::ChunkBased => {
                // The chunk-info decomposition (S03 §5): `iu as u16`,
                // mechanically proven by the `RawInodeChunkInfo`
                // layout assertions; the reserved half is never read
                // (G5).
                let chunkformat = iu as u16;
                // I10: unknown chunk-format bits, rejected before the
                // `Chunked` materialization (inode.c:170-175).
                if chunkformat & !CHUNK_FORMAT_ALL != 0 {
                    return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported chunk format");
                }
                // inode.c:176-177: the 5-bit chunk-blkbits domain is
                // carried in full, with no upper-bound check.
                let bits = sb.blkszbits as u32 + (chunkformat & CHUNK_FORMAT_BLKBITS_MASK) as u32;
                AddrState::Chunked {
                    format: chunkformat,
                    bits,
                }
            }
        };

        // AUTO-TODO(G-Z02): The compressed data path is deferred as a whole
        // under archive A, yet this parsing remains a parity bookkeeping
        // duty — a compressed inode reports st_blocks from the on-disk
        // compressed_blocks count (the round_up(i_size) fallback covers
        // every non-compressed layout). Merge it back into the data path
        // when the G-Z01 deferral note is lifted.
        let nblks: u32 = if datalayout.is_compressed() { iu } else { 0 };
        let nr_sectors: usize = if nblks != 0 {
            // The compressed-block count in 512-byte sectors (4k
            // example: << 3). The blkszbits - 9 underflow is
            // structurally prevented by the mount-time door (G-M08),
            // not re-checked here.
            (nblks as usize) << (sb.blkszbits as usize - 9)
        } else {
            // The generic caliber: round_up(size, block_size) >> 9
            // (4k example: round_up(size, 4096) >> 9); size = 0
            // yields 0. usize carries it without overflow (the
            // extreme i64::MAX size lands at ~2^54 sectors).
            (size as usize).align_up(sb.block_size()) >> 9
        };

        Ok(Self {
            version: InodeVersion::Compact,
            datalayout,
            kind,
            mode: InodeMode::from_bits_truncate(mode & 0o7777),
            uid: u16::from_le(raw.i_uid) as u32,
            gid: u16::from_le(raw.i_gid) as u32,
            nlink: u16::from_le(raw.i_nlink) as u32,
            size,
            xattr_isize,
            // D10: the compact form carries no own timestamp; the
            // three Metadata times derive from the superblock build
            // time (the same-source derivation, S02 §5.3).
            time: sb.build_time,
            i_u: iu,
            addr_state,
            nr_sectors,
        })
    }
}

/// The extended-form decode: the full I7 → I8 → I10 guard chain over
/// the D6 field accounting.
///
/// Same parameter-form triple and same boundaries as the compact
/// decode above; the form-specific difference is the error face
/// {I7, I8, I10}: the le64 `i_size` domain makes the negative-size
/// guard reachable here only (inode.c:133-137; the ext2 structural
/// precedent is `ext2/inode/mod.rs:316-318`). The guard order is the
/// source execution order (T-001 §9.2): I7 strictly before I8 and
/// the D9 cross-cut — with I7 and I10 both tripping, the first error
/// is I7's, and swapping that order would drift the errno from
/// EUCLEAN to EOPNOTSUPP (the errno-level ordering pin, S06 §2.2).
impl TryFrom<(&RawInodeExtended, DataLayout, &SuperBlock)> for InodeDesc {
    type Error = Error;

    fn try_from(
        (raw, datalayout, sb): (&RawInodeExtended, DataLayout, &SuperBlock),
    ) -> Result<Self> {
        // D6 field decode: pure memory, no error exit; the 9-field
        // E1 ledger (S05 §6) converts each little-endian field
        // exactly once, here.
        let size = u64::from_le(raw.i_size);
        let mode = u16::from_le(raw.i_mode);
        let kind = FileKind::from_raw_i_mode(mode);
        let xattr_isize = xattr_ibody_size(u16::from_le(raw.i_xattr_icount));
        let iu = u32::from_le(raw.i_u);
        let time = super::utils::duration_from_parts(
            u64::from_le(raw.i_mtime),
            u32::from_le(raw.i_mtime_nsec),
        );

        // D7 (I7): negative i_size, extended-only (inode.c:133-137).
        if size > i64::MAX as u64 {
            return_errno_with_message!(Errno::EUCLEAN, "negative i_size");
        }

        // D8 (I8): the bogus-i_mode guard, strictly before the D9
        // cross-cut (inode.c:157-161 ahead of :164-178).
        if matches!(kind, FileKind::Other(_)) {
            return_errno_with_message!(Errno::EUCLEAN, "bogus i_mode");
        }

        // D9: the second, datalayout-driven reading of `iu` — never
        // inside a kind branch (the pathological kind x datalayout
        // combinations are accepted parity behavior, T-003 §1.4).
        let addr_state = match datalayout {
            DataLayout::FlatPlain | DataLayout::FlatInline => AddrState::Flat,
            DataLayout::CompressedFull | DataLayout::CompressedCompact => AddrState::Compressed,
            DataLayout::ChunkBased => {
                // The chunk-info decomposition (S03 §5): `iu as u16`,
                // mechanically proven by the `RawInodeChunkInfo`
                // layout assertions; the reserved half is never read
                // (G5).
                let chunkformat = iu as u16;
                // I10: unknown chunk-format bits, rejected before the
                // `Chunked` materialization (inode.c:170-175).
                if chunkformat & !CHUNK_FORMAT_ALL != 0 {
                    return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported chunk format");
                }
                // inode.c:176-177: the 5-bit chunk-blkbits domain is
                // carried in full, with no upper-bound check.
                let bits = sb.blkszbits as u32 + (chunkformat & CHUNK_FORMAT_BLKBITS_MASK) as u32;
                AddrState::Chunked {
                    format: chunkformat,
                    bits,
                }
            }
        };

        // The G-Z02 deferral note quoted verbatim in the compact body
        // above covers this caliber as well — one marker per tree, the
        // formula itself is per-form.
        let nblks: u32 = if datalayout.is_compressed() { iu } else { 0 };
        let nr_sectors: usize = if nblks != 0 {
            // The compressed-block count in 512-byte sectors (4k
            // example: << 3). The blkszbits - 9 underflow is
            // structurally prevented by the mount-time door (G-M08),
            // not re-checked here.
            (nblks as usize) << (sb.blkszbits as usize - 9)
        } else {
            // The generic caliber: round_up(size, block_size) >> 9
            // (4k example: round_up(size, 4096) >> 9); size = 0
            // yields 0. usize carries it without overflow (the
            // extreme i64::MAX size lands at ~2^54 sectors).
            (size as usize).align_up(sb.block_size()) >> 9
        };

        Ok(Self {
            version: InodeVersion::Extended,
            datalayout,
            kind,
            mode: InodeMode::from_bits_truncate(mode & 0o7777),
            uid: u32::from_le(raw.i_uid),
            gid: u32::from_le(raw.i_gid),
            nlink: u32::from_le(raw.i_nlink),
            size,
            xattr_isize,
            time,
            i_u: iu,
            addr_state,
            nr_sectors,
        })
    }
}

// ---------------------------------------------------------------------------
// The decode entry (T-022 S08; sequence `docs/T-011/S05/index.md` §1.1,
// read contract `docs/T-011/S07/index.md` §3–§4, D-domain table
// `docs/T-011/analysis.md` §5.2).
// ---------------------------------------------------------------------------

/// Decodes the on-disk inode at byte offset `iloc` into an
/// `InodeDesc` — steps 2–5 of the five-step decode sequence, in the
/// source execution order (`docs/T-001/analysis.md` §9.2; behavioral
/// baseline inode.c:27-197):
///
/// - Step 2, the 2-byte pre-read `read_val::<u16>(iloc)`: the single
///   point where `i_format` enters the decode surface, and its
///   single `u16::from_le` (E1 — the `TryFrom` conversions re-derive
///   nothing from it). Read errors propagate unchanged (C2): `?`
///   passthrough with no FS-layer message, no errno folding — a read
///   past the device end surfaces the aster boundary errno EINVAL,
///   a registered I/O-model known-diff against linux's EIO (RD2),
///   deliberately not simulated here.
/// - Step 3, `parse_i_format`: the I3 → I4 guards plus the typed
///   pair. The discrimination read set is exactly the 2 pre-read
///   bytes — a malformed value returns before any full-record read,
///   any suffix read, or the cross-block region is touched.
/// - Step 4, the version dispatch: one single-point read of the
///   selected record straight at `iloc`. The extended record is
///   *always* fetched by the one 64-byte `read_val` (RD0):
///   cross-block fetch is built into the byte-stream primitive (the
///   device address space knows no block boundaries), so the
///   source-side boundary test and two-segment splice (inode.c:72-96)
///   exist as no code here; the compact record never crosses a block
///   (32 always divides the block size). Fixture note for the
///   regression family (T-027, RD1): on a 4k volume the unique
///   cross-block slot is ofs = 4064 (nid ≡ 127 mod 128), while
///   ofs = 4032 (nid ≡ 126) is the exact-block-boundary corner and
///   does *not* cross — the landed single-form read treats both
///   slots identically.
/// - Step 5, `InodeDesc::try_from((&raw, datalayout, sb))`: the pure
///   in-memory conversion carrying the I7/I8/I10 guards (T-022 S07).
///
/// Step 1 — the iloc location
/// `(meta_blkaddr << blkszbits) + (nid << ISLOT_BITS)` — lives in
/// `inode_location` above (the base-point formula family; landed
/// with T-024 S01, migrated from the iget body); `Inode::new` drives
/// this entry with the already-computed byte offset, and the
/// nid-keyed iget cache lives in `Erofs::iget` (`fs.rs`). No
/// decoder-side caching (RD3): every call reads the device directly,
/// so repeat reads of one nid are the iget caller's business.
// I6 (kmalloc ENOMEM) unreachable: no heap allocation on this path (F4/G-M21)
//
// Live since T-023 S04: called by `Erofs::iget` (`fs.rs`), which
// computes the `iloc` argument (step 1 of the five-step sequence).
// The bridging `expect` was removed when the first consumer landed.
pub(super) fn read_inode_desc(
    device: &dyn BlockDevice,
    sb: &SuperBlock,
    iloc: usize,
) -> Result<InodeDesc> {
    // Step 2: the 2-byte pre-read of `i_format` — an I2 read error
    // propagates before any guard runs (the source's first metabuf
    // read, inode.c:45-50, holds the same position).
    let ifmt = u16::from_le(device.read_val::<u16>(iloc)?);
    // Step 3: the one-shot I3 -> I4 validation plus the typed pair;
    // on a malformed value the read set stays at the 2 pre-read
    // bytes.
    let (version, datalayout) = parse_i_format(ifmt)?;
    // Step 4: the version dispatch — one single-point read per form,
    // straight at `iloc` (RD0: no boundary test, no two-segment
    // splice, either form).
    match version {
        InodeVersion::Compact => {
            let raw = device.read_val::<RawInodeCompact>(iloc)?;
            InodeDesc::try_from((&raw, datalayout, sb))
        }
        InodeVersion::Extended => {
            let raw = device.read_val::<RawInodeExtended>(iloc)?;
            InodeDesc::try_from((&raw, datalayout, sb))
        }
    }
}

/// A directly-constructed `Inode` over a literal descriptor (ktest-only,
/// T-025 S06; the subtasks decision-2 fixture). The five-step device decode
/// of `Inode::new` is replaced by the caller's `desc` literal — staging a
/// full raw inode record on the disk is the image-builder fixture's
/// business (T-027) — while the payload assembly stays the PRODUCTION
/// `InodePayload::new`: the I12 arm-head gate, the fast/slow symlink
/// criterion, and `new_data_backed` (page cache + `DataBackend`) all run
/// for real, so a slow-LNK handle built here walks the exact production
/// chain `read_link → page_cache → submit_read_bio` that the S06-IF
/// assertion family pins. Private-field visibility keeps it in this
/// module (decision 2); it stays OUTSIDE `mod tests` so later slices
/// (S07's DIO suite hosts `inode/file.rs`) can consume it too.
#[cfg(ktest)]
fn ktest_inode_from_desc(fs: &Erofs, nid: ErofsNid, desc: InodeDesc) -> Arc<Inode> {
    let payload = InodePayload::new(fs, nid, &desc)
        .expect("ktest fixture: payload assembly of an uncompressed fixture cannot fail");
    Arc::new(Inode {
        nid,
        desc,
        payload,
        self_ref: fs.self_ref().clone(),
        extension: Extension::new(),
    })
}

#[cfg(ktest)]
mod tests {
    use aster_block::{
        SECTOR_SIZE,
        bio::{BioSegment, BioStatus, BioType},
    };
    use ostd::{mm::VmIo, prelude::*};

    use super::*;
    use crate::{
        fs::fs_impls::erofs::test_utils::{
            BioRequest, ErofsMemoryDisk, ktest_bio_trio, ktest_flat_geometry, ktest_fs_on,
            ktest_single_device_table, ktest_super_block,
        },
        vm::page_cache::BlockAsPageCacheBackend,
    };

    /// A knob-complete `InodeDesc` literal for the geometry suites:
    /// the `ktest_lnk_desc` fixture is LNK-shaped with a fixed Flat
    /// addr state and a zero `i_u`; the data-geometry vectors need
    /// the addr-state, kind, and i_u knobs too.
    fn geometry_desc(
        version: InodeVersion,
        datalayout: DataLayout,
        kind: FileKind,
        size: u64,
        xattr_isize: usize,
        addr_state: AddrState,
        i_u: u32,
    ) -> InodeDesc {
        InodeDesc {
            version,
            datalayout,
            kind,
            mode: InodeMode::from_bits_truncate(0o644),
            uid: 0,
            gid: 0,
            nlink: 1,
            size,
            xattr_isize,
            time: Duration::ZERO,
            i_u,
            addr_state,
            nr_sectors: 0,
        }
    }

    /// S01-IF-2 (anchor `docs/T-014/S01/index.md` §9): `data_geometry`
    /// pointwise over layout {0, 2, 4} × version {C, E}. The
    /// inline_data_start oracle is pinned by hand — (meta_blkaddr <<
    /// 12) + (nid << ISLOT_BITS) + inode_isize + xattr_isize with
    /// meta = 3, nid = 64, blkszbits = 12 (iloc = 14336; compact
    /// suffix 14368, extended 14400) — not by calling the formula
    /// family: a circular oracle would pin nothing.
    #[ktest]
    fn data_geometry_pointwise_vectors() {
        use DataLayout::{ChunkBased, FlatInline, FlatPlain};
        use InodeVersion::{Compact, Extended};

        let sb = ktest_super_block(12, 3);
        type Case = (
            InodeVersion,
            DataLayout,
            u64,
            usize,
            AddrState,
            u32,
            bool,
            u64,
            Option<(usize, u32)>,
        );
        // (version, datalayout, size, xattr_isize, addr_state, i_u,
        //  exp_tail_inline, exp_inline_data_start, exp_chunk)
        let cases: &[Case] = &[
            (
                Compact,
                FlatPlain,
                10_000,
                0,
                AddrState::Flat,
                7,
                false,
                14_368,
                None,
            ),
            (
                Compact,
                FlatInline,
                5_000,
                32,
                AddrState::Flat,
                9,
                true,
                14_400,
                None,
            ),
            // The risk-2 corners: tail_inline is the LAYOUT BIT only —
            // size = 0 (empty tail) and the exact-block size keep the
            // bit set; existence is consumer arithmetic, not stored.
            (
                Compact,
                FlatInline,
                0,
                0,
                AddrState::Flat,
                0,
                true,
                14_368,
                None,
            ),
            (
                Compact,
                FlatInline,
                4_096,
                0,
                AddrState::Flat,
                2,
                true,
                14_368,
                None,
            ),
            (
                Extended,
                FlatPlain,
                200_000,
                4,
                AddrState::Flat,
                123,
                false,
                14_404,
                None,
            ),
            (
                Extended,
                FlatInline,
                1,
                0,
                AddrState::Flat,
                5,
                true,
                14_400,
                None,
            ),
            // Chunked: unit 4 vs 8 by the INDEXES bit, chunkbits =
            // 12 + (format & 0x1F) as the decode would carry it.
            (
                Compact,
                ChunkBased,
                1 << 20,
                0,
                AddrState::Chunked {
                    format: 0x00,
                    bits: 12,
                },
                0x0000,
                false,
                14_368,
                Some((4, 12)),
            ),
            (
                Compact,
                ChunkBased,
                1 << 20,
                0,
                AddrState::Chunked {
                    format: 0x20,
                    bits: 12,
                },
                0x0020,
                false,
                14_368,
                Some((8, 12)),
            ),
            (
                Extended,
                ChunkBased,
                1 << 20,
                0,
                AddrState::Chunked {
                    format: 0x25,
                    bits: 17,
                },
                0x0025,
                false,
                14_400,
                Some((8, 17)),
            ),
            (
                Extended,
                ChunkBased,
                1 << 20,
                0,
                AddrState::Chunked {
                    format: 0x1F,
                    bits: 43,
                },
                0x001F,
                false,
                14_400,
                Some((4, 43)),
            ),
        ];
        for &(ver, dl, size, xattr, st, iu, exp_tail, exp_ids, exp_chunk) in cases {
            let desc = geometry_desc(ver, dl, FileKind::Reg, size, xattr, st, iu);
            let geom = data_geometry(&sb, 64, &desc);
            assert_eq!(geom.size, size, "size (dl = {:?})", dl);
            assert_eq!(geom.block_bits, 12, "block_bits (dl = {:?})", dl);
            assert_eq!(geom.raw_blkaddr, iu, "raw_blkaddr (dl = {:?})", dl);
            assert_eq!(geom.tail_inline, exp_tail, "tail_inline (dl = {:?})", dl);
            assert_eq!(geom.inline_data_start, exp_ids, "ids (dl = {:?})", dl);
            assert_eq!(
                geom.chunk.map(|cg| (cg.unit, cg.chunkbits)),
                exp_chunk,
                "chunk (dl = {:?})",
                dl
            );
            assert!(!geom.compressed, "compressed (dl = {:?})", dl);
        }
    }

    /// S01-IF-3 (anchor S01 §9): the construction snapshot equals the
    /// single-source predicate on its whole production domain
    /// (REG/DIR/LNK × every datalayout — the compressed rows are the
    /// bypass-the-assembly-gate pure-function form: the real I12
    /// gate rejects them before construction), and the predicate
    /// matches the T-013 §1.2 table over the full seven-kind ×
    /// five-datalayout grid. The special-file rows assert the
    /// predicate only: `data_geometry` never runs for them (the
    /// payload matrix routes Chr/Blk/Fifo/Sock away from
    /// new_data_backed, and `raw_blkaddr`'s kind premise pins the
    /// same domain).
    #[ktest]
    fn data_geometry_predicate_consistency() {
        let sb = ktest_super_block(12, 3);
        let addr_state_for = |datalayout: DataLayout| match datalayout {
            DataLayout::FlatPlain | DataLayout::FlatInline => AddrState::Flat,
            DataLayout::CompressedFull | DataLayout::CompressedCompact => AddrState::Compressed,
            DataLayout::ChunkBased => AddrState::Chunked {
                format: 0,
                bits: 12,
            },
        };
        const KINDS: [FileKind; 7] = [
            FileKind::Reg,
            FileKind::Dir,
            FileKind::Lnk,
            FileKind::Chr,
            FileKind::Blk,
            FileKind::Fifo,
            FileKind::Sock,
        ];
        const DATALAYOUTS: [DataLayout; 5] = [
            DataLayout::FlatPlain,
            DataLayout::CompressedFull,
            DataLayout::FlatInline,
            DataLayout::CompressedCompact,
            DataLayout::ChunkBased,
        ];
        for kind in KINDS {
            for datalayout in DATALAYOUTS {
                // The T-013 §1.2 oracle: dl ∈ {1, 3} ∧ kind ∈
                // {Reg, Dir, Lnk}.
                let expected = matches!(
                    datalayout,
                    DataLayout::CompressedFull | DataLayout::CompressedCompact
                ) && matches!(kind, FileKind::Reg | FileKind::Dir | FileKind::Lnk);
                let desc = geometry_desc(
                    InodeVersion::Compact,
                    datalayout,
                    kind,
                    4_096,
                    0,
                    addr_state_for(datalayout),
                    5,
                );
                assert_eq!(
                    desc.is_data_compressed(),
                    expected,
                    "predicate (kind = {:?}, dl = {:?})",
                    kind,
                    datalayout
                );
                if matches!(kind, FileKind::Reg | FileKind::Dir | FileKind::Lnk) {
                    let geom = data_geometry(&sb, 64, &desc);
                    assert_eq!(
                        geom.compressed, expected,
                        "snapshot (kind = {:?}, dl = {:?})",
                        kind, datalayout
                    );
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // The INLINE assertion face (T-025 S06; `docs/T-014/S06/index.md`
    // §9): the full-page META corner and the start-offset grid drive the
    // bridge directly (the S05 fixture family over the memory disk);
    // the slow-LNK three-region chain drives the REAL read_link path
    // through the production payload assembly (`ktest_inode_from_desc`
    // above). Host = this module per subtasks S06(b).
    // ------------------------------------------------------------------

    /// A flat-geometry backend over a fresh memory disk (the S06-IF-1/2
    /// fixture form — the data.rs `ktest_bridge_backend` shape, re-spelled
    /// here because that helper is private to data.rs's own test module).
    fn ktest_data_backend_on(
        disk: Arc<ErofsMemoryDisk>,
        size: u64,
        raw: u32,
        tail_inline: bool,
        inline_data_start: u64,
    ) -> DataBackend {
        let fs = ktest_fs_on(disk, ktest_super_block(12, 0), ktest_single_device_table());
        let geom = ktest_flat_geometry(size, raw, tail_inline, inline_data_start);
        let npages = size.div_ceil(PAGE_SIZE as u64) as usize;
        DataBackend::new(
            fs.self_ref().clone(),
            fs.block_device().clone(),
            geom,
            npages,
        )
    }

    /// Reads a one-page segment back into bytes (the data.rs
    /// `ktest_segment_bytes` shape).
    fn ktest_page_bytes(segment: &BioSegment) -> [u8; PAGE_SIZE] {
        let mut buf = [0u8; PAGE_SIZE];
        segment.read_bytes(0, &mut buf).unwrap();
        buf
    }

    /// S06-IF-1 (anchor `docs/T-014/S06/index.md` §9): the META full-page
    /// corner — a FLAT_INLINE geometry with `size % bs == 0` (size = 2·bs
    /// exactly; the design sketch's "2.5bs" example is read through its
    /// leading constraints `size%bs==0` + `valid=PAGE`, which jointly
    /// require a whole-block tail): page 0 is MAPPED, page 1 is the tail
    /// block whose `m_plen = PAGE` — `fill_zeros(0)` rewrites nothing.
    /// `ids = 4096` gives blkoff(I) = 0, the boundary-exact-slot geometry
    /// (§6.2) where a full-block payload is legal.
    #[ktest]
    fn inline_meta_full_page_corner() {
        let disk = Arc::new(ErofsMemoryDisk::new(4 * PAGE_SIZE));
        let pattern = |off: usize| ((off % 251) + 1) as u8; // never zero
        let mut inline_page = vec![0u8; PAGE_SIZE];
        let mut data_page = vec![0u8; PAGE_SIZE];
        for (i, b) in inline_page.iter_mut().enumerate() {
            *b = pattern(i);
        }
        for (i, b) in data_page.iter_mut().enumerate() {
            *b = pattern(PAGE_SIZE + i);
        }
        disk.stage_bytes(PAGE_SIZE, &inline_page);
        disk.stage_bytes(2 * PAGE_SIZE, &data_page);
        // size = 2·bs; the flat data starts at device block 2; the inline
        // area sits block-aligned at 4096.
        let backend = ktest_data_backend_on(
            disk.clone(),
            (2 * PAGE_SIZE) as u64,
            2,
            true,
            PAGE_SIZE as u64,
        );

        // Page 0: the flat MAPPED segment — one whole-block BIO.
        let (segment, mut io_batch, completions) = ktest_bio_trio();
        backend
            .submit_read_bio(0, segment.clone(), completions.complete_fn(), &mut io_batch)
            .unwrap();
        io_batch.wait_all().unwrap();
        assert_eq!(completions.nr_completions(), 1);
        assert_eq!(completions.statuses(), vec![BioStatus::Complete]);
        assert_eq!(ktest_page_bytes(&segment)[..], data_page[..]);

        // Page 1: the tail block is the META arm with valid = PAGE — the
        // page holds EXACTLY the inline-area whole block (every byte
        // non-zero: `fill_zeros(0)` rewrote nothing), completing once.
        let (segment, mut io_batch, completions) = ktest_bio_trio();
        backend
            .submit_read_bio(1, segment.clone(), completions.complete_fn(), &mut io_batch)
            .unwrap();
        io_batch.wait_all().unwrap();
        assert_eq!(completions.nr_completions(), 1);
        assert_eq!(completions.statuses(), vec![BioStatus::Complete]);
        assert_eq!(ktest_page_bytes(&segment)[..], inline_page[..]);

        // Channel discrimination: the MAPPED page took one whole-block
        // BIO at device block 2; the META page took one byte-channel
        // bounce covering the full block at 4096 — same 8-sector
        // granularity, a different sector base (the origin pin).
        let sectors_per_block = (PAGE_SIZE / SECTOR_SIZE) as u64;
        assert_eq!(
            disk.requests(),
            vec![
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 2 * sectors_per_block,
                    nr_sectors: sectors_per_block,
                },
                BioRequest {
                    type_: BioType::Read,
                    start_sector: sectors_per_block,
                    nr_sectors: sectors_per_block,
                },
            ]
        );
    }

    /// S06-IF-2 (anchor S06 §9): the inline-area start-offset grid —
    /// blkoff(I) × plen over the legal cells {1, 100, bs−blkoff} (content
    /// fidelity + tail zeros; the S05-IF-4 single form gridded), plus the
    /// one-past-the-end cells → EUCLEAN with zero completions and zero
    /// device requests (the guard precedes any fetch). blkoff = 0 has no
    /// illegal cell in the non-wrapped domain: the whole block is legal
    /// (plen ≤ bs), and the only blkoff-0 EUCLEAN route is the
    /// u32-truncation wrap corner already pinned by S03-IF-7(a).
    #[ktest]
    fn inline_tail_start_offset_grid() {
        const BS: usize = 4096;
        let base = 2 * BS; // the inline area lives in device block 2
        let pattern = |off: usize| ((off % 251) + 1) as u8; // never zero
        let mut block = vec![0u8; BS];
        for (i, b) in block.iter_mut().enumerate() {
            *b = pattern(base + i);
        }

        for blkoff in [0usize, 1, 512, 3000] {
            for plen in [1usize, 100, BS - blkoff] {
                let disk = Arc::new(ErofsMemoryDisk::new(4 * PAGE_SIZE));
                let ids = base + blkoff;
                // The whole block is staged non-zero, so the [plen, PAGE)
                // tail zeros can only come from the fill — never off the
                // disk, where the residue sits on purpose.
                disk.stage_bytes(base, &block);
                let backend = ktest_data_backend_on(disk.clone(), plen as u64, 0, true, ids as u64);
                let (segment, mut io_batch, completions) = ktest_bio_trio();
                backend
                    .submit_read_bio(0, segment.clone(), completions.complete_fn(), &mut io_batch)
                    .unwrap();
                io_batch.wait_all().unwrap();
                assert_eq!(
                    completions.nr_completions(),
                    1,
                    "blkoff={blkoff} plen={plen}"
                );
                assert_eq!(
                    completions.statuses(),
                    vec![BioStatus::Complete],
                    "blkoff={blkoff} plen={plen}"
                );
                let page = ktest_page_bytes(&segment);
                assert_eq!(
                    page[..plen],
                    block[blkoff..blkoff + plen],
                    "prefix bytes, blkoff={blkoff} plen={plen}"
                );
                assert!(
                    page[plen..].iter().all(|&b| b == 0),
                    "zero tail, blkoff={blkoff} plen={plen}"
                );
                assert_eq!(
                    disk.requests().len(),
                    1,
                    "one byte-channel bounce, blkoff={blkoff} plen={plen}"
                );
            }
        }

        // The one-past-the-end cells: blkoff + plen = bs + 1 → EUCLEAN.
        for blkoff in [1usize, 512, 3000] {
            let plen = BS - blkoff + 1;
            let disk = Arc::new(ErofsMemoryDisk::new(4 * PAGE_SIZE));
            disk.stage_bytes(base, &block);
            let backend =
                ktest_data_backend_on(disk.clone(), plen as u64, 0, true, (base + blkoff) as u64);
            let (segment, mut io_batch, completions) = ktest_bio_trio();
            let err = backend
                .submit_read_bio(0, segment, completions.complete_fn(), &mut io_batch)
                .unwrap_err();
            assert_eq!(err.error(), Errno::EUCLEAN, "blkoff={blkoff} plen={plen}");
            assert_eq!(
                completions.nr_completions(),
                0,
                "blkoff={blkoff} plen={plen}"
            );
            assert!(
                disk.requests().is_empty(),
                "the guard precedes any fetch, blkoff={blkoff} plen={plen}"
            );
        }
    }

    /// S06-IF-3 (anchor S06 §9): the slow-LNK cross-block region — the
    /// §5.1(a) form. nid = 64 compact: iloc = 2048, inode_end = 2080;
    /// xattr_isize = 1952 → I = 4032; size = 100. The fast criterion ③
    /// fails (I + s = 4132 > round_up(inode_end) = 4096) → the production
    /// LNK arm assembles a DataBacked payload; and I + s > round_up(I) =
    /// 4096 → the payload would cross its start block → the map-layer
    /// EUCLEAN guard fires (blkoff 4032 + 100 > 4096) BEFORE any fetch.
    ///
    /// Exit errno: the guard produces EUCLEAN (single-sourced in
    /// map_blocks; pinned at the backend exit by S05-IF-5), but the
    /// page-cache VmIo boundary converts it lossily —
    /// `From<Error> for ostd::Error` maps EUCLEAN onto `InvalidArgs`
    /// (the `_` arm), and the return conversion reports EINVAL at the
    /// read_link exit. NOT EIO: erofs itself folds nothing (the opposite
    /// of the ext2 blanket-EIO negative example). The framework
    /// known-diff is registered in `docs/T-025/S06/index.md`.
    #[ktest]
    fn slow_lnk_inline_cross_block_euclean_exit() {
        let disk = Arc::new(ErofsMemoryDisk::new(2 * PAGE_SIZE));
        // The would-be payload, staged but never fetched.
        disk.stage_bytes(4032, &[0x41u8; 100]);
        let fs = ktest_fs_on(
            disk.clone(),
            ktest_super_block(12, 0),
            ktest_single_device_table(),
        );
        let desc = geometry_desc(
            InodeVersion::Compact,
            DataLayout::FlatInline,
            FileKind::Lnk,
            100,
            1952,
            AddrState::Flat,
            0,
        );
        assert!(
            !is_fast_symlink(&fs, 64, &desc),
            "the (a)-form geometry must route to the slow chain"
        );
        let inode = ktest_inode_from_desc(&fs, 64, desc);
        let err = inode.read_link().unwrap_err();
        assert_eq!(err.error(), Errno::EINVAL);
        assert!(
            disk.requests().is_empty(),
            "the cross-block guard precedes any fetch (construction included)"
        );
    }

    /// S06-IF-4 (anchor S06 §9): the slow-LNK xattr push-in region — the
    /// §5.1(b) form. nid = 64 extended: iloc = 2048, inode_end = 2112,
    /// round_up(inode_end) = 4096; xattr_isize = 2000 pushes I = 4112
    /// into the block AFTER the inode's; size = 100: ③ fails (4212 >
    /// 4096) → slow, but I + s = 4212 ≤ round_up(I) = 8192 → a LEGAL
    /// META tail starting in the next block. read_link must return the
    /// target staged at I byte-for-byte; the block-0 filler proves the
    /// bytes cannot have come from the (vacuous) flat arm.
    #[ktest]
    fn slow_lnk_inline_xattr_pushin_legal_meta() {
        let target: String = (0..100u8).map(|i| (b'a' + (i % 26)) as char).collect();
        let disk = Arc::new(ErofsMemoryDisk::new(2 * PAGE_SIZE));
        disk.stage_bytes(4112, target.as_bytes());
        // i_u = 0 → raw_blkaddr 0: filler at the flat-arm data area,
        // which a wrong fill would have read instead.
        disk.stage_bytes(0, &[0x46u8; 512]);
        let fs = ktest_fs_on(
            disk.clone(),
            ktest_super_block(12, 0),
            ktest_single_device_table(),
        );
        let desc = geometry_desc(
            InodeVersion::Extended,
            DataLayout::FlatInline,
            FileKind::Lnk,
            100,
            2000,
            AddrState::Flat,
            0,
        );
        assert!(
            !is_fast_symlink(&fs, 64, &desc),
            "the (b)-form geometry must route to the slow chain"
        );
        let inode = ktest_inode_from_desc(&fs, 64, desc);
        assert_eq!(inode.read_link().unwrap(), target);
        // One byte-channel bounce fetched [4112, 4212) — sector-rounded
        // to the single sector 8 (blkoff(I) = 16).
        assert_eq!(
            disk.requests(),
            vec![BioRequest {
                type_: BioType::Read,
                start_sector: (4112 / SECTOR_SIZE) as u64,
                nr_sectors: 1,
            }]
        );
    }

    /// S06-IF-5 (anchor S06 §9): the empty-inline corner — FLAT_INLINE
    /// with size = 0 in both forms. The slow-LNK form (xattr_isize = 2100
    /// → I = 4180 > round_up(inode_end) = 4096, criterion ③ fails on the
    /// empty sum) reads through the DataBacked page cache: an empty
    /// window is a trivial success (`Vmo::read` returns early on
    /// read_len == 0) — Ok("") with ZERO page commits. The REG form
    /// (capacity 0) reads an empty buffer at offset 0 the same way.
    /// Neither form touches the device.
    #[ktest]
    fn empty_inline_zero_page_touch() {
        let disk = Arc::new(ErofsMemoryDisk::new(2 * PAGE_SIZE));
        let fs = ktest_fs_on(
            disk.clone(),
            ktest_super_block(12, 0),
            ktest_single_device_table(),
        );
        let lnk_desc = geometry_desc(
            InodeVersion::Compact,
            DataLayout::FlatInline,
            FileKind::Lnk,
            0,
            2100,
            AddrState::Flat,
            0,
        );
        assert!(
            !is_fast_symlink(&fs, 64, &lnk_desc),
            "the empty slow-LNK corner must route to the slow chain"
        );
        let inode = ktest_inode_from_desc(&fs, 64, lnk_desc);
        assert_eq!(inode.read_link().unwrap(), "");

        let reg_desc = geometry_desc(
            InodeVersion::Compact,
            DataLayout::FlatInline,
            FileKind::Reg,
            0,
            0,
            AddrState::Flat,
            0,
        );
        let reg = ktest_inode_from_desc(&fs, 64, reg_desc);
        let mut empty = [0u8; 0];
        reg.page_cache()
            .expect("REG assembles a DataBacked payload")
            .read_bytes(0, &mut empty)
            .unwrap();

        assert!(
            disk.requests().is_empty(),
            "both empty-inline forms touch zero pages (zero device requests)"
        );
    }
}
