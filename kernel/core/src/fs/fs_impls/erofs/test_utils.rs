// SPDX-License-Identifier: MPL-2.0

//! Test-only fixtures and helpers for erofs kernel tests.
//!
//! Compiled only under `#[cfg(ktest)]` and never referenced by
//! production files.
//!
//! Fixture layers, landed by different tasks:
//!
//! * **Layer 0, devices**: the null block device (T-024/S04 — the
//!   pure-geometry suites that must never issue I/O) and the
//!   in-memory disk (T-025 S02 — the data-path suites). The memory
//!   disk serves staged bytes through both device channels, records
//!   every request for the channel-purity assertions, injects
//!   medium errors, and inherits the framework `EINVAL`
//!   end-of-device bound on the byte channel.
//! * **Layer 1, device-less literals**: the zero-baseline
//!   `SuperBlock`, the LNK-shaped `InodeDesc` (T-024/S04), and the
//!   direct-construction `DataGeometry` knobs (T-025 S02) —
//!   including the production-unreachable bypass forms the
//!   map-path defenses consume (compressed snapshot, cross-block
//!   inline tails).
//! * **Layer 2, BIO assembly parts**: the `submit_read_bio`
//!   direct-call trio — a one-page `FromDevice` segment, a
//!   single-slot `IoBatch`, and a counting completion log supplying
//!   the `complete_fn`.
//! * **Layer 3, fs wiring**: `Erofs` handles over the memory disk
//!   with crafted device tables. The private-field constructors
//!   live in `fs.rs` (`Erofs::ktest_new_with`,
//!   `DeviceTable::ktest_new`) and are re-faced here as thin
//!   helpers.
//! * **T-027 S02, builder foundations** (the sections between the
//!   fs wiring and the self-smoke suite): the `assert_errno!`
//!   macro and the little-endian byte patch/read helpers (the
//!   ext2 Layer-0 primitives minus the bitmap bit setter, which
//!   erofs has no use for), the five whitelisted byte templates
//!   extracted from the T-018 pipeline images
//!   (`docs/T-027/S01/index.md`), the layout writers that stage
//!   them (`write_super_block` with the checksummed finish,
//!   `write_super_block_raw` as the V5-only skip channel,
//!   `write_inode_at` on the production iloc formula,
//!   `write_dirents`, `write_meta_bytes`), and the memory-disk
//!   truncation channel (`nr_sectors_override`, the G-M10 form).
//!   The layer numbering above stays the T-024/T-025 four-layer
//!   form — the S02 sections slot in without renumbering
//!   (increment, not refactor).
//!
//! * **T-027 S03, chassis + fixture**: `ErofsFixture` — the staged
//!   memory disk plus the `Erofs::open` mount-attempt result — and
//!   `healthy_fixture()` over the S06 §3.2 healthy chassis: T-SB
//!   with the four geometry patches, the T-EXT64 root switched to
//!   FLAT_PLAIN at block 4, and the `.`/`..` directory block. The
//!   first ktest walking the full `Erofs::open` chain over staged
//!   bytes lives in `fs.rs` (`healthy_fixture_mounts`); the FX-*
//!   malformed builders (S04+) are local rewrites of this chassis.
//!
//! * **T-027 S04, the FX-SB builder family**: fourteen named
//!   constructors (`fx_sb_*`), each a local rewrite of the healthy
//!   chassis per S06 §5.1 — the V2–V8 superblock doors, the V5+V6
//!   order cross, and the G-M15 root/packed mount doors. The
//!   mount-assertion suite lives in `fs.rs` (the D1 host rule); the
//!   G-M10 truncated-disk form is S14's (its assertion value is a
//!   registered drift finalized there). Later slices append the
//!   FX-DIRENT/NAME/TIME/INODE/COMP/XATTR families the same way.
//!
//! * **T-027 S05, the FX-DIRENT builder family**: fifteen named
//!   constructors (`fx_dirent_*`), each a local rewrite of the
//!   chassis root directory block — the child forms also lay child
//!   directory inodes — per S06 §5.3: the nameoff high-bit /
//!   non-multiple / inverted chain, the out-of-order binary-search
//!   playground, the missing-`..` root/child pair, the wrong-nid /
//!   directory-cycle / d_type / zero-nid forms, the embedded-NUL
//!   half, and the R5/R10 corner builders. The lookup/readdir
//!   assertion suite lives in `inode/dir.rs` (the D1 host rule) —
//!   the two-strictness-domains pin there finally gets its executed
//!   R5 column over real malformed images.
//!
//! * **T-027 S06, the FX-NAME builder family**: three named
//!   constructors (`fx_name_*`), each a local rewrite of the chassis
//!   per S06 §5.4 — the non-UTF-8 dirent name (readdir EIO at the
//!   G-N04 precheck, lookup-side unreachability), the slash-bearing
//!   name (the G-N05 precheck), and the non-UTF-8 symlink target
//!   with both payload arms in one image (G-N02, the unified
//!   `read_link` conversion exit). The embedded-NUL name-family half
//!   reuses the S05 `fx_dirent_embedded_nul_names` image (same
//!   material, double consumption). Assertion suites live in
//!   `inode/dir.rs` and `inode/symlink.rs` (the D1 host rule).
//!
//! * **T-027 S07, the FX-TIME builder family**: three named
//!   constructors (`fx_time_*`), each a local rewrite of the chassis
//!   per S06 §5.5 — the giant mtime seconds word (le64 high bit, the
//!   F6 bit-pattern carrier), the giant mtime nsec (2e9, the F6n
//!   normalization registered drift), and the compact chassis with a
//!   giant superblock build_time (the compact ctime synthesis path,
//!   the compact half of the same bit-pattern assertion). All three
//!   are accept faces — no mount gate consumes a time field — so the
//!   assertion surface is the decoded time itself; the suite lives
//!   in `inode/mod.rs` (the D1 host rule). The compact chassis
//!   variant of S06 §3.2 lands with the third form
//!   (`lay_compact_root`).
//!
//! * **T-027 S08, the FX-INODE builder family**: eight named
//!   constructors (`fx_inode_*`) laying crafted CHILD inode records
//!   per S06 §5.2 (this slice = rows 1–6 and 9: the I3/I4/I7/I8/I10
//!   decode guards, the RD1 slot pair at nid 127/126 — cross-block
//!   splice vs exact-boundary corner, both over healthy records —
//!   and the DIR×CHUNK / FIFO×CHUNK acceptance crosses; the
//!   data-defense rows 7/8/11 are S09's, the compressed-special
//!   row 10 is S10/S11's). No mount gate reads a child slot, so
//!   every form mounts Ok and the guards fire at `iget`; the
//!   assertion suite lives in `inode/mod.rs` (the D1 host rule).
//!
//! * **T-027 S09, the FX-INODE data-defense family**: three named
//!   constructors finishing §5.2 (rows 7/8/11) — the giant
//!   FLAT_PLAIN i_size (2^32 + 100, the T-013 §11 truncation-angle
//!   value), the exact-boundary slot whose inline payload exactly
//!   fills a block (nid 126, i_size == bs — the cross-block guard's
//!   pass corner), and the cross-block slot's slow symlink (nid 127,
//!   one byte past the fast-criterion boundary: the map layer says
//!   EUCLEAN, the registered VmIo-boundary drift exits EINVAL).
//!   These forms mount Ok AND iget Ok — the defenses fire on the
//!   read path; the suites live in `inode/data.rs` and
//!   `inode/symlink.rs` (the D1 host rule), the first FX suites to
//!   drive the full mounted chain through the read API.
//!
//! * **T-027 S10, the FX-COMP mount-half family + the algs=0 comp
//!   chassis**: seven named constructors (`fx_comp_*`) per S06 §5.7 —
//!   the u1≠0 over-rejection and unknown-algs forms (the V9 door,
//!   rows 1/3), and the algs=0 `comp_chassis` single source with
//!   COMPR_CFGS and each of the four other known compression incompat
//!   bits set one at a time (rows 2/8, the G-Z03 parsed-but-ignored
//!   acceptance face; the 0x2 leg IS the row-2 chassis — dual
//!   consumption). Row 6 (fragments + packed compressed payload) has
//!   no builder here: it is the S04 G-M15 material, re-asserted by
//!   the `fs.rs` suite under the §5.1⑤ label (共同约束 10: 素材落
//!   S04, 断言 S10 复用). The iget half (rows 4/5/7) is S11's, over
//!   the same chassis.
//!
//! * **T-027 S11, the FX-COMP iget-half family**: three more named
//!   constructors over the S10 `comp_chassis` single source — the
//!   compressed REG/DIR/LNK rejection trio (row 4, the I12 errno
//!   source; suite in `inode/mod.rs`), the compressed special files
//!   with the G-Z02 dual-caliber st_blocks accounting and its
//!   nblks=0 fallback corner (row 5 + §5.2; suite in `inode/mod.rs`),
//!   and the dual-malformed mount-Ok form — FRAGMENTS plus a packed
//!   NON-compressed payload (row 7, G-Z05's counterpart direction,
//!   never tightened; suite in `fs.rs`). Three inode-mode constants
//!   widen their declaration visibility for the special-file legs
//!   (the S04/S06/S08 precedent, `inode/mod.rs`).
//!
//! * **T-027 S12, the FX-XATTR entry/layout family**: eight named
//!   constructors (`fx_xattr_*`) per S06 §5.6 rows 6–13 — the
//!   empty-name entry (W-X03's negative control), the glued acl
//!   names, the dead indexes, the X23 header-size overrun, the X24
//!   entry beyond remaining, the non-UTF-8 name (W-X06), the acl
//!   value-domain malformations, and the G-X09 symlink host (the
//!   S08-frozen case B). Each lays an ibody xattr area on a chassis
//!   child (`lay_xattr_child_at` — the xattr chassis-variant single
//!   source the S13 mechanism family reuses); every form mounts Ok
//!   and the assertion surface is the get/list/acl read chains — the
//!   suite lives in `xattr.rs` (that file's first ktests; the D1
//!   host rule). Four live namespace-index constants widen their
//!   visibility in `xattr.rs` for the builders (the S04 S_IF*
//!   precedent).
//!
//! The vector suite for `utils` lives inside `utils.rs` itself (pure
//! functions need no disk fixtures); the dirent/symlink vector suites
//! of T-024/S04 live in their implementation files the same way.
//! The fixture self-smoke suite lives at the tail of this file.
//!
//! Note for the S05-IF-10b grep (no erofs-owned completion
//! closures): the counting closure below is fixture-side by
//! construction — the memory disk completes synchronously in the
//! submitting context, never a real interrupt context — so the grep
//! must exclude this ktest-only file.

use core::{
    fmt,
    mem::offset_of,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use aster_block::{
    BlockDeviceMeta, SECTOR_SIZE,
    bio::{
        BioCompleteFn, BioDirection, BioEnqueueError, BioSegment, BioStatus, BioType, SubmittedBio,
    },
};
use device_id::{DeviceId, MajorId, MinorId};
use io_util::batch::IoBatch;
use ostd::mm::{FrameAllocOptions, HasSize, PAGE_SIZE, Segment, VmIo, io::util::HasVmReaderWriter};

use super::{
    Erofs,
    fs::DeviceTable,
    inode::{
        AddrState, CHUNK_FORMAT_ALL, CHUNK_FORMAT_INDEXES, ChunkGeometry, DataGeometry, DataLayout,
        FileKind, I_ALL, I_DATALAYOUT_BIT, I_VERSION_BIT, INODE_DATALAYOUT_MAX, ISLOT_BITS,
        InodeDesc, InodeVersion, RawDirent, RawInodeCompact, RawInodeExtended, S_IFBLK, S_IFCHR,
        S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, inode_location,
    },
    prelude::*,
    super_block::{
        BLKSZBITS_MIN, FeatureCompatSet, FeatureIncompatSet, NAME_LEN, RawSuperBlock,
        SUPER_MAGIC_V1, SUPER_OFFSET, SUPPORTED_BLKSZBITS, SuperBlock, verify_superblock_checksum,
    },
    utils::crc32c,
    xattr::{
        RawXattrEntry, RawXattrIbodyHeader, XATTR_INDEX_POSIX_ACL_ACCESS,
        XATTR_INDEX_POSIX_ACL_DEFAULT, XATTR_INDEX_TRUSTED, XATTR_INDEX_USER,
    },
};
use crate::fs::vfs::file_system::FsFlags;

// ===========================================================================
// Layer 0: devices — the null device, then the in-memory disk
// ===========================================================================

/// A `BlockDevice` that is never read or written: every bio completes
/// with `NotSupported`. It exists only to fill the `block_device`
/// field of a ktest handle — the pure-geometry suites never issue I/O
/// (and a fixture that accidentally did would fail loudly here rather
/// than fabricating zero bytes).
pub(super) struct ErofsNullDevice;

impl Debug for ErofsNullDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ErofsNullDevice")
    }
}

impl BlockDevice for ErofsNullDevice {
    fn enqueue(&self, bio: SubmittedBio) -> core::result::Result<(), BioEnqueueError> {
        bio.complete(BioStatus::NotSupported);
        Ok(())
    }

    fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: 0,
            nr_sectors: 0,
        }
    }

    fn name(&self) -> &str {
        "erofs-ktest-null"
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(MajorId::new(0), MinorId::new(0))
    }
}

/// One recorded device request: the bio type, the first sector (raw
/// `Sid` value), and the sector count. The whole-log length doubles
/// as the request counter of the S04-IF-4/S05-IF-10 purity
/// assertions — byte-vs-block channel discrimination reads the
/// recorded granularity and count (a byte-channel bounce bio carries
/// sub-block geometry; a direct `read_blocks_async` bio is
/// whole-block aligned). No `Eq` derive: the upstream `BioType`
/// does not implement it, and the log assertions compare through
/// `PartialEq` alone.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct BioRequest {
    pub type_: BioType,
    pub start_sector: u64,
    pub nr_sectors: u64,
}

/// An in-memory `BlockDevice` for the data-path ktest suites
/// (T-025 S02): zeroed pages staged with fixture bytes by the test,
/// served back through both device channels. Same shape as ext2's
/// `Ext2MemoryDisk` (`ext2/test_utils.rs:109-146`) — only the
/// channel mechanics are shared, no ext2 domain knowledge.
///
/// * **Read BIOs** are filled by the CPU straight into the bio
///   segments (`inner_dma_slice().writer()`) and completed
///   synchronously with `Complete` — the regular entry the ext2
///   suites also use. Write and flush bios complete
///   `NotSupported`: erofs is read-only, so any such request is a
///   fixture bug and fails loudly (the null-device posture).
/// * **The byte channel** (`VmIo for dyn BlockDevice`) comes for
///   free: its sector-bounce bios land in `enqueue` like any other
///   read, and its end-of-device bound (`EINVAL`, the RD2②
///   half, `impl_block_device.rs:93-97`) is enforced by the
///   framework before `enqueue` runs, against
///   `metadata().nr_sectors`.
/// * **Request recording**: every enqueue appends one
///   [`BioRequest`] to a spinlock-held log, before any completion
///   branch, so fault-injected requests stay observable too.
///   Framework-rejected out-of-bounds byte reads never reach the
///   device — their silence in the log is itself an assertion face.
/// * **Fault injection**: `set_fail_reads(true)` makes every Read
///   complete `IoError` (the S05-IF-7 medium-error face).
///
/// The disk performs no bounds check of its own inside `enqueue`
/// (the ext2 shape): a block-channel bio past the segment end
/// simply fills fewer bytes. Byte-channel callers get the real
/// `EINVAL` from the framework bound instead.
pub(super) struct ErofsMemoryDisk {
    segment: Segment<()>,
    requests: SpinLock<Vec<BioRequest>>,
    fail_reads: AtomicBool,
    /// The G-M10 truncation knob (T-027 S02): `None` — every disk so
    /// far — declares the physical segment size; `Some(sectors)`
    /// shrinks the *declared* device size (`metadata().nr_sectors`)
    /// below the physical allocation, which stays whole pages. The
    /// framework byte-channel bound consumes the declared value, so
    /// reads past it fail `EINVAL` before reaching `enqueue`; the
    /// mount-time assertion values of the truncated-image forms are
    /// S14's to finalize (registered drift: aster EINVAL / Linux
    /// EBADMSG).
    nr_sectors_override: Option<u64>,
}

impl ErofsMemoryDisk {
    /// Allocates a zeroed disk of `nbytes` bytes (the capacity knob
    /// of the S05-IF-8 truncation corner). The effective capacity
    /// floors to whole sectors — the sub-sector tail is
    /// unreachable, exactly like a real device; `size_bytes()`
    /// reports the enforceable bound.
    pub(super) fn new(nbytes: usize) -> Self {
        let npages = nbytes.div_ceil(PAGE_SIZE);
        let segment = FrameAllocOptions::new()
            .zeroed(true)
            .alloc_segment(npages)
            .unwrap();
        Self {
            segment,
            requests: SpinLock::new(Vec::new()),
            fail_reads: AtomicBool::new(false),
            nr_sectors_override: None,
        }
    }

    /// The G-M10 truncated disk: physical allocation of `nbytes`
    /// bytes (page-rounded — staging still reaches every physical
    /// page), but the device declares only `nr_sectors_override`
    /// sectors (e.g. 6 = 3072 bytes). Keeps everything else of the
    /// regular constructor: the request log, the read-only
    /// discipline, the `fail_reads` injection.
    pub(super) fn truncated(nbytes: usize, nr_sectors_override: u64) -> Self {
        let mut disk = Self::new(nbytes);
        disk.nr_sectors_override = Some(nr_sectors_override);
        disk
    }

    /// The declared device size in sectors — the override when
    /// present, the physical size otherwise.
    fn effective_nr_sectors(&self) -> u64 {
        self.nr_sectors_override
            .unwrap_or(self.segment.size() as u64 / SECTOR_SIZE as u64)
    }

    /// The staging surface: tests pre-load disk content through it
    /// (`write_bytes`/`write_val` of `VmIo`, e.g. chunk-index
    /// tables and tail-block residue).
    pub(super) fn segment(&self) -> &Segment<()> {
        &self.segment
    }

    /// Stages `bytes` at `offset` — the convenience spelling of
    /// `segment().write_bytes(offset, bytes)`.
    pub(super) fn stage_bytes(&self, offset: usize, bytes: &[u8]) {
        self.segment.write_bytes(offset, bytes).unwrap();
    }

    /// The byte bound the framework enforces on the byte channel:
    /// the *declared* `nr_sectors * SECTOR_SIZE` — the truncated
    /// disk declares less than it physically holds, and that smaller
    /// bound is what fires. Reads touching or crossing it fail
    /// `EINVAL` before reaching the device.
    pub(super) fn size_bytes(&self) -> usize {
        self.effective_nr_sectors() as usize * SECTOR_SIZE
    }

    /// A snapshot of the request log, in submission order.
    pub(super) fn requests(&self) -> Vec<BioRequest> {
        self.requests.lock().clone()
    }

    /// Injects (`true`) or clears (`false`) the medium-error face:
    /// every Read bio completes `IoError` after being recorded.
    pub(super) fn set_fail_reads(&self, fail: bool) {
        self.fail_reads.store(fail, Ordering::Relaxed);
    }
}

impl Debug for ErofsMemoryDisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErofsMemoryDisk")
            .field("bytes", &self.segment.size())
            .field("nr_requests", &self.requests.lock().len())
            .finish()
    }
}

impl BlockDevice for ErofsMemoryDisk {
    fn enqueue(&self, bio: SubmittedBio) -> core::result::Result<(), BioEnqueueError> {
        let type_ = bio.type_();
        let sid_range = bio.sid_range();
        let start_sector = sid_range.start.to_raw();
        let nr_sectors = sid_range.end.to_raw() - start_sector;
        self.requests.lock().push(BioRequest {
            type_,
            start_sector,
            nr_sectors,
        });

        if type_ == BioType::Read {
            if self.fail_reads.load(Ordering::Relaxed) {
                bio.complete(BioStatus::IoError);
                return Ok(());
            }
            let mut cur_device_ofs = start_sector as usize * SECTOR_SIZE;
            for seg in bio.segments() {
                let io_size = seg
                    .inner_dma_slice()
                    .writer()
                    .unwrap()
                    .write(self.segment.reader().skip(cur_device_ofs));
                cur_device_ofs += io_size;
            }
            bio.complete(BioStatus::Complete);
        } else {
            // Read-only discipline: writes and flushes are never
            // legitimately issued against an erofs device — fail
            // loudly instead of fabricating success.
            bio.complete(BioStatus::NotSupported);
        }
        Ok(())
    }

    fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: usize::MAX,
            nr_sectors: self.effective_nr_sectors() as usize,
        }
    }

    fn name(&self) -> &str {
        "erofs-ktest-memdisk"
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(MajorId::new(1), MinorId::new(0))
    }
}

// ===========================================================================
// Layer 1: device-less literals (zero baselines, explicit knobs)
// ===========================================================================

/// A zero-baseline `SuperBlock` with the two geometry knobs the
/// pure-geometry suites vary: `blkszbits` (the block size shift) and
/// `meta_blkaddr` (the metadata-area base, in blocks). Every other
/// field is the zero value — the consumers below (`block_size()`,
/// `inode_location` through `Erofs::ktest_new`) read geometry only,
/// never the feature bits, so a zeroed baseline cannot skew them.
///
/// The literal bypasses `SuperBlock::from(RawSuperBlock)` on purpose:
/// the conversion is the production single-`from_le` point and is
/// vector-tested on its own track (T-022); reusing it here would just
/// make the fixture depend on 21 raw fields being spelled out anyway.
pub(super) fn ktest_super_block(blkszbits: u8, meta_blkaddr: u32) -> SuperBlock {
    SuperBlock {
        magic: 0,
        feature_compat: 0,
        blkszbits,
        sb_extslots: 0,
        root_nid: 0,
        inos: 0,
        build_time: Duration::ZERO,
        blocks: 0,
        meta_blkaddr,
        xattr_blkaddr: 0,
        uuid: [0; 16],
        volume_name: [0; 16],
        feature_incompat: 0,
        u1: 0,
        extra_devices: 0,
        devt_slotoff: 0,
        dirblkbits: 0,
        xattr_prefix_count: 0,
        xattr_prefix_start: 0,
        packed_nid: 0,
        xattr_filter_reserved: 0,
    }
}

/// An LNK-shaped `InodeDesc` with the four knobs the fast/slow
/// criterion reads: the layout version (which fixes `inode_isize`
/// at 32/64), the datalayout, the inline-xattr size, and i_size.
/// Everything else is a zero baseline (`i_u` is unread on the LNK
/// arm; `addr_state` only feeds the T-025 map path).
pub(super) fn ktest_lnk_desc(
    version: InodeVersion,
    datalayout: DataLayout,
    xattr_isize: usize,
    size: u64,
) -> InodeDesc {
    InodeDesc {
        version,
        datalayout,
        kind: FileKind::Lnk,
        mode: InodeMode::from_bits_truncate(0o777),
        uid: 0,
        gid: 0,
        nlink: 1,
        size,
        xattr_isize,
        time: Duration::ZERO,
        i_u: 0,
        addr_state: AddrState::Flat,
        nr_sectors: 0,
    }
}

/// Direct `DataGeometry` construction with every knob exposed —
/// including the forms the I12 assembly gate makes unreachable in
/// production (`compressed = true`, cross-block inline tails): the
/// map-path defenses are tested by constructing exactly those inputs
/// (the S01 §1.5 defense-in-depth family). The knob order mirrors
/// the struct field order; `ktest_flat_geometry` spells the common
/// flat form.
pub(super) fn ktest_data_geometry(
    size: u64,
    block_bits: u32,
    raw_blkaddr: u32,
    tail_inline: bool,
    inline_data_start: u64,
    chunk: Option<ChunkGeometry>,
    compressed: bool,
) -> DataGeometry {
    DataGeometry {
        size,
        block_bits,
        raw_blkaddr,
        tail_inline,
        inline_data_start,
        chunk,
        compressed,
    }
}

/// The flat-form spelling: 4k block bits, no chunk area, not
/// compressed — `tail_inline` picks FLAT_INLINE vs FLAT_PLAIN, and
/// `inline_data_start` fixes the tail/extent base point.
pub(super) fn ktest_flat_geometry(
    size: u64,
    raw_blkaddr: u32,
    tail_inline: bool,
    inline_data_start: u64,
) -> DataGeometry {
    ktest_data_geometry(
        size,
        12,
        raw_blkaddr,
        tail_inline,
        inline_data_start,
        None,
        false,
    )
}

// ===========================================================================
// Layer 2: BIO assembly parts — the submit_read_bio direct-call trio
// ===========================================================================

/// Counts and records every invocation of a completion callback
/// built from it: how many times the callback ran, and the status
/// each call carried. The "complete exactly once" discipline of the
/// backend contract reads both.
///
/// The callback pushes into a spinlock-held `Vec` — the memory disk
/// completes synchronously in the submitting context, so the push
/// (which may allocate) never runs in a real interrupt context;
/// production completion paths stay allocation-free and closure-free
/// (see the module doc note for the S05-IF-10b grep).
pub(super) struct CompletionLog {
    nr_completions: AtomicUsize,
    statuses: SpinLock<Vec<BioStatus>>,
}

impl CompletionLog {
    pub(super) fn new() -> Self {
        Self {
            nr_completions: AtomicUsize::new(0),
            statuses: SpinLock::new(Vec::new()),
        }
    }

    /// Builds a `BioCompleteFn` that records into this log: each
    /// call bumps the counter and appends the status.
    pub(super) fn complete_fn(self: &Arc<Self>) -> BioCompleteFn {
        let log = self.clone();
        Box::new(move |status| {
            log.nr_completions.fetch_add(1, Ordering::Relaxed);
            log.statuses.lock().push(status);
        })
    }

    /// How many times the callback has run.
    pub(super) fn nr_completions(&self) -> usize {
        self.nr_completions.load(Ordering::Relaxed)
    }

    /// The statuses, in callback order.
    pub(super) fn statuses(&self) -> Vec<BioStatus> {
        self.statuses.lock().clone()
    }
}

impl Default for CompletionLog {
    fn default() -> Self {
        Self::new()
    }
}

/// The `submit_read_bio` direct-call trio (the S05 §10 fixture
/// form): a one-block `FromDevice` segment (exactly one page under
/// the 4k-only scope), a single-slot `IoBatch`, and a
/// [`CompletionLog`] whose `complete_fn()` supplies the callback.
/// Consumers destructure and pass the segment by value, the batch
/// mutably, and `completions.complete_fn()` for the callback.
pub(super) fn ktest_bio_trio() -> (BioSegment, IoBatch, Arc<CompletionLog>) {
    (
        BioSegment::alloc(1, BioDirection::FromDevice),
        IoBatch::with_capacity(1),
        Arc::new(CompletionLog::new()),
    )
}

// ===========================================================================
// Layer 3: fs wiring — handles over the memory disk, crafted tables
// ===========================================================================

/// A flatdev device table for the crafted-image vectors (S04-IF-2/3):
/// `slots` are `(blocks, mapped_blkaddr)` pairs addressed 1-based by
/// `slot(id)` — `slots[0]` is extra device 1. `device_id_mask` is
/// the chunk-id validity mask (extra=1 → 1, extra=2 → 3, mirroring
/// `roundup_pow_of_two(extra + 1) - 1`).
pub(super) fn ktest_flatdev_table(slots: &[(u32, u32)], device_id_mask: u32) -> DeviceTable {
    DeviceTable::ktest_new(true, slots, device_id_mask)
}

/// The single-device table (a flat image): no slots, mask 0 — every
/// chunk device id folds to the primary device (MD7).
pub(super) fn ktest_single_device_table() -> DeviceTable {
    DeviceTable::ktest_new(false, &[], 0)
}

/// Assembles an `Erofs` handle over the given memory disk and
/// device table (`Erofs::ktest_new_with` re-faced): the data-path
/// suites build `DataBackend`s against the returned handle exactly
/// like `new_data_backed` does (`fs.self_ref()` + `fs.block_device()`).
pub(super) fn ktest_fs_on(
    disk: Arc<ErofsMemoryDisk>,
    sb: SuperBlock,
    table: DeviceTable,
) -> Arc<Erofs> {
    Erofs::ktest_new_with(disk, sb, table)
}

// ===========================================================================
// T-027 S02: fixture-builder foundations — the assertion macro, the
// LE byte helpers, the whitelisted templates, the layout writers
// (design: docs/T-016/S06 §4.1–§4.2, decisions D3/D4)
// ===========================================================================

/// Asserts that `$expr` is `Err` carrying exactly `$errno` — the
/// ext2 `test_utils.rs` Layer-0 form, transcribed verbatim. The
/// mount/iget assertion suites of S03+ consume it through the
/// `pub(super) use` re-export below (host-file ktests import it as
/// `test_utils::assert_errno`); the `Ok` arm panics so a silently
/// succeeding form fails loudly instead of passing vacuously.
macro_rules! assert_errno {
    ($expr:expr, $errno:expr) => {
        match $expr {
            Err(e) => assert_eq!(e.error(), $errno),
            Ok(_) => panic!("expected Err({:?}), got Ok(_)", $errno),
        }
    };
    ($expr:expr, $errno:expr, $($msg:tt)+) => {
        match $expr {
            Err(e) => assert_eq!(e.error(), $errno, $($msg)+),
            Ok(_) => panic!("expected Err({:?}), got Ok(_): {}", $errno, format_args!($($msg)+)),
        }
    };
}
pub(super) use assert_errno;

// AUTO-DECISION: the LE byte family lands as width-split free
// functions (put_le_u16/u32/u64, get_le_u16/u32/u64) rather than the
// S06 §4.1 sketch's generic `put_le::<const N: usize>` spelling
// (context risk 7, implementation means only). The generic form has
// no clean read-side story — `get_le` would need to dispatch a
// return type from a const generic, which stable Rust cannot express
// without a macro anyway — and the per-width functions are the
// greppable, macro-free form. Patch offsets still come exclusively
// from `offset_of!` at every call site (the D3 discipline); these
// helpers carry no offsets of their own.

/// Patches `v` little-endian into `buf` at `off`. Panics when the
/// field range does not fit — a fixture bug that should fail loudly.
pub(super) fn put_le_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + size_of::<u16>()].copy_from_slice(&v.to_le_bytes());
}

/// The u32 arm of the patch family.
pub(super) fn put_le_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + size_of::<u32>()].copy_from_slice(&v.to_le_bytes());
}

/// The u64 arm of the patch family.
pub(super) fn put_le_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + size_of::<u64>()].copy_from_slice(&v.to_le_bytes());
}

/// Reads the little-endian u16 at `off` — the read side the
/// assertion suites use to check what a patch actually staged.
pub(super) fn get_le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + size_of::<u16>()].try_into().unwrap())
}

/// The u32 arm of the read family.
pub(super) fn get_le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + size_of::<u32>()].try_into().unwrap())
}

/// The u64 arm of the read family.
pub(super) fn get_le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + size_of::<u64>()].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Layer 2 increment: the whitelisted byte templates (S06 §3.1/§3.3,
// decision D3 — byte constants + typed patches). Pasted verbatim from
// the S01 extraction product `test/erofs_fixture_templates.rs`
// (script `test/erofs_fixture_templates.sh`; sources = the T-018
// pipeline images C1/C2/C10, sha256s recorded there and in
// `docs/T-027/S01/index.md` §2). Non-deterministic-field whitelist
// already applied at extraction, exactly three items:
// build_time/build_time_nsec zeroed, uuid = EROFS_UUID_BASE,
// checksum zeroed (always recomputed by `write_super_block` below).
// Field offsets named in comments mirror the const_assert anchors in
// super_block.rs / inode/mod.rs / inode/dir.rs — patch code takes
// them from `offset_of!`, never from these comments.
// ---------------------------------------------------------------------------

/// T-SB: 128-byte super block seed, C1 erofs_base.img [1024,1152),
/// whitelist applied (checksum/build_time/build_time_nsec zeroed,
/// uuid = base). Chassis landing (S06 §3.2) patches
/// root_nid/inos/blocks/meta_blkaddr to the chassis geometry
/// (0 / slot count / 32 / 1) and recomputes the checksum; the source
/// values in the comments are the C1 measurement, kept for review.
const SB_TEMPLATE: [u8; 128] = [
    0xe2, 0xe1, 0xf5, 0xe0, 0x00, 0x00, 0x00,
    0x00, // magic@0 = 0xE0F5E1E2; checksum@4 = 0 (recomputed by write_super_block; raw write = FX-SB V5 only)
    0x07, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x26,
    0x00, // feature_compat@8 = 0x7 (SB_CHKSUM | MTIME | XATTR_FILTER); blkszbits@12 = 12; sb_extslots@13 = 0; root_nid@14 = 38 (chassis patches to 0)
    0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // inos@16 = 262 (chassis patches to slot count)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // build_time@24 = 0 (WHITELISTED)
    0x00, 0x00, 0x00, 0x00, 0x75, 0x00, 0x00,
    0x00, // build_time_nsec@32 = 0 (WHITELISTED); blocks@36 = 117 (chassis: 32)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // meta_blkaddr@40 = 0 (chassis: 1); xattr_blkaddr@44 = 0
    0xe2, 0xe4, 0xf0, 0xc8, 0x1a, 0x2b, 0x4c, 0x3d, // uuid@48 = EROFS_UUID_BASE
    0x9e, 0x8f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // volume_name@64 = NUL x 16
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // feature_incompat@80 = 0; u1@84 = 0; extra_devices@86 = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // devt_slotoff@88 = 0; dirblkbits@90 = 0; xattr_prefix_count@91 = 0; xattr_prefix_start@92 = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // packed_nid@96 = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // xattr_filter_reserved@104 = 0; reserved2@105 = 0 x 23 (G5 verbatim)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// T-EXT64: 64-byte extended inode seed, C1 root inode @ iloc 1216.
/// FlatInline on disk; the chassis root switches datalayout to
/// FLAT_PLAIN with raw_blkaddr = block 4 (T-027 risk-1 resolution
/// direction). Inode time fields need no whitelisting: the T-018
/// stage anchors all source mtimes to @0 (asserted at extraction).
const INODE_EXT_TEMPLATE: [u8; 64] = [
    0x05, 0x00, 0x00, 0x00, 0xed, 0x41, 0x00,
    0x00, // i_format@0 = 0x0005 (version=1 extended, datalayout=2 FlatInline); i_xattr_icount@2 = 0; i_mode@4 = 0x41ED (S_IFDIR | 0755); i_reserved@6 = 0
    0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // i_size@8 = 122 (le64)
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
    0x00, // i_u@16 = 0xFFFFFFFF (FlatInline raw_blkaddr convention); i_ino@20 = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // i_uid@24 = 0; i_gid@28 = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // i_mtime@32 = 0 (stage anchors mtimes to @0)
    0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, // i_mtime_nsec@40 = 0; i_nlink@44 = 7
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // i_reserved2@48 = 0 x 16
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// T-CPT32: 32-byte compact inode seed, C2 (erofs_base_cpt.img)
/// root inode @ iloc 1216. No time fields: compact ctime is
/// synthesized from the superblock build_time (both zeroed on the
/// chassis).
// First consumer since T-027 S03: the `chassis_staging_shape`
// smoke cross-locks the seed's i_format word against the compose
// helper — the S02-era dead-code expectation came off with it. The
// compact chassis staging itself joined with the S07 FX-TIME family
// (`lay_compact_root`).
const INODE_CPT_TEMPLATE: [u8; 32] = [
    0x04, 0x00, 0x00, 0x00, 0xed, 0x41, 0x07,
    0x00, // i_format@0 = 0x0004 (version=0 compact, datalayout=2 FlatInline); i_xattr_icount@2 = 0; i_mode@4 = 0x41ED (S_IFDIR | 0755); i_nlink@6 = 7 (le16)
    0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // i_size@8 = 122 (le32); i_reserved@12 = 0
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, // i_u@16 = 0xFFFFFFFF; i_ino@20 = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // i_uid@24 = 0; i_gid@26 = 0; i_reserved2@28 = 0
];

/// T-DIRENT: 12-byte dirent seed, C1 root directory first entry
/// ".". Reference walk of the full 122-byte dir data (7 entries:
/// . .. dirs regular special symlink xattr_host; nids
/// 38,38,44,51,62,68,75; nameoff chain 84,85,87,91,98,105,112)
/// lives in `test/erofs_fixture_templates.dump.txt`.
const DIRENT_TEMPLATE: [u8; 12] = [
    0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // nid@0 = 38 (le64, '.')
    0x54, 0x00, 0x02,
    0x00, // nameoff@8 = 84 (le16, dirent array end of 7 entries); file_type@10 = 2 (DT_DIR); reserved@11 = 0
];

/// Prefix-record reference form, C10 erofs_prefix.img packed inode
/// payload (record at packed iloc + 64; pos0 = xattr_prefix_start
/// << 2 = 0). Packed form is mkfs-reachable only; the FX-XATTR
/// meta-form half (S13) lays this byte family into the meta area
/// itself (S06 §5.6). Reference only — the nid geometry is NOT
/// copied (risk 3: parity is not an on-disk invariant; the chassis
/// assigns its own even nids).
const XATTR_PREFIX_RECORD_REF: [u8; 18] = [
    0x10, 0x00, 0x01, 0x65, 0x72, 0x6f, 0x66,
    0x73, // len@0 = 16 (le16: 1 index byte + 15-byte infix); index@2 = 0x01 (user namespace base index); infix@3 = "erofs_test.lpx." (15 bytes)
    0x5f, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x6c, 0x70, 0x78, 0x2e,
];

// ---------------------------------------------------------------------------
// Layer 3 increment: the layout writers (S06 §4.2 — the
// `write_raw_inode_to_disk`/`write_simple_root_dir_block`
// counterparts; the group-descriptor and bitmap families are cut
// whole: erofs nids are direct-addressed, no indirection).
// ---------------------------------------------------------------------------

/// The chassis block geometry (S06 §3.2): the physical fixture block
/// is 4k and stays 4k regardless of any FX-SB V3 blkszbits *field*
/// rewrite — derived from the mount-gate constant, never a literal.
const CHASSIS_BLOCK_SIZE: usize = 1 << SUPPORTED_BLKSZBITS;

/// Stages `sb` at `SUPER_OFFSET` finished with the S06 §3.4
/// checksum sequence: set `SB_CHKSUM` (idempotent — the chassis
/// compat 0x7 already carries it), zero the `checksum` field, then
/// write back `crc32c(!0, region)` over `[SUPER_OFFSET,
/// SUPER_OFFSET + checksummed_len())`. The interval length comes
/// from the production formula (`SuperBlock::checksummed_len` over
/// the just-staged record) and the CRC from production
/// `utils::crc32c` — the fixture and the mount verifier share the
/// single source, so they cannot drift apart. Every healthy-landing
/// and FX superblock rewrite goes through here.
pub(super) fn write_super_block(disk: &ErofsMemoryDisk, sb: &[u8; 128]) {
    let mut buf = *sb;
    let compat_off = offset_of!(RawSuperBlock, feature_compat);
    let compat = get_le_u32(&buf, compat_off);
    put_le_u32(
        &mut buf,
        compat_off,
        compat | FeatureCompatSet::SB_CHKSUM.bits(),
    );
    put_le_u32(&mut buf, offset_of!(RawSuperBlock, checksum), 0);
    disk.stage_bytes(SUPER_OFFSET, &buf);

    let len = staged_super_block(disk).checksummed_len();
    let mut region = vec![0u8; len];
    disk.segment()
        .read_bytes(SUPER_OFFSET, &mut region)
        .unwrap();
    let checksum = crc32c(!0, &region);
    put_le_u32(&mut buf, offset_of!(RawSuperBlock, checksum), checksum);
    disk.stage_bytes(SUPER_OFFSET, &buf);
}

/// Stages `sb` verbatim — no SB_CHKSUM set, no checksum recompute.
/// The single explicit skip channel of S06 §3.4, reserved for the
/// FX-SB V5 bad-csum forms whose whole point is a broken checksum.
pub(super) fn write_super_block_raw(disk: &ErofsMemoryDisk, sb: &[u8; 128]) {
    disk.stage_bytes(SUPER_OFFSET, sb);
}

/// Decodes the currently staged superblock through the production
/// `From` conversion — the write family's addressing base and the
/// smoke suites' mirror, reading the same decode the mount path
/// reads.
fn staged_super_block(disk: &ErofsMemoryDisk) -> SuperBlock {
    let raw: RawSuperBlock = disk.segment().read_val(SUPER_OFFSET).unwrap();
    SuperBlock::from(raw)
}

/// Stages an inode record at the production slot offset — `iloc =
/// (meta_blkaddr << blkszbits) + (nid << ISLOT_BITS)` via
/// `inode::inode_location` (single source) over the *currently
/// staged* superblock. Contract: stage the chassis superblock
/// (meta_blkaddr = 1) before laying inodes; no FX form rewrites
/// meta_blkaddr, so the base stays stable through every later patch.
pub(super) fn write_inode_at(disk: &ErofsMemoryDisk, nid: u64, raw: &[u8]) {
    let iloc = inode_location(&staged_super_block(disk), nid) as usize;
    disk.stage_bytes(iloc, raw);
}

/// Stages a directory data block: the dirent array at the block
/// base, the name area immediately after it. The caller's first
/// dirent `nameoff` must therefore equal `entries.len()` — the
/// healthy mkfs form the T-DIRENT template mirrors (nameoff 84 =
/// 7 × 12). Block addressing uses the fixed chassis geometry, not
/// the staged sb: an FX-SB V3 blkszbits rewrite is a field patch,
/// not a geometry change (S06 §3.2).
pub(super) fn write_dirents(disk: &ErofsMemoryDisk, blk: u64, entries: &[u8], names: &[u8]) {
    let base = blk as usize * CHASSIS_BLOCK_SIZE;
    disk.stage_bytes(base, entries);
    disk.stage_bytes(base + entries.len(), names);
}

/// Stages arbitrary bytes into a metadata block — the shared-xattr
/// area, prefix records, chunk-index tables (S06 §4.2). Same fixed
/// chassis geometry as `write_dirents`.
pub(super) fn write_meta_bytes(disk: &ErofsMemoryDisk, blk: u64, off: usize, bytes: &[u8]) {
    disk.stage_bytes(blk as usize * CHASSIS_BLOCK_SIZE + off, bytes);
}

// ===========================================================================
// T-027 S03: ErofsFixture — the healthy chassis (S06 §3.2) and the
// mount-attempt fixture (S06 §4.3). Every FX-* builder (S04+) is a
// local rewrite of this chassis (the fixture口径: a healthy template,
// minimally patched — a healthy mkfs produces no malformed form).
// ===========================================================================

/// The chassis disk capacity in blocks (S06 §3.2): room for the
/// superblock, the meta area, the root directory data, the shared
/// xattr area (block 8+), and the out-of-device rewrite margins.
const CHASSIS_NR_BLOCKS: u32 = 32;

/// The inode-slot area base, in blocks (S06 §3.2): blocks [1, 4)
/// hold the chassis inode slots — nid 0..=383 at 32 bytes per slot,
/// so the RD1 corners (nid 127 cross-block, nid 126 exact-boundary)
/// land inside the area.
const CHASSIS_META_BLKADDR: u32 = 1;

/// The chassis `inos` value: the slot capacity of the meta area
/// (3 blocks x 128 slots). No mount gate consumes the field (only
/// the statfs ffree arithmetic reads it), so the capacity reading
/// is the self-consistent chassis spelling.
// AUTO-DECISION: inos = the meta-area slot capacity (384) rather
// than a file count — the field is gate-inert, and "slots the
// chassis geometry actually holds" is the value a healthy mkfs of
// this exact image could defend. A child count would change with
// every FX form's per-builder inode additions and drift per fixture.
const CHASSIS_INO_SLOTS: u64 = 384;

/// The root nid of the chassis (S06 §3.2): uniform-extended, so the
/// extended root record occupies slots 0 and 1; child inodes take
/// the even nids 2/4/6... from there (per-builder, S04+).
const CHASSIS_ROOT_NID: u64 = 0;

/// The root directory data block.
// AUTO-DECISION (T-027 risk 1): the chassis root is FLAT_PLAIN with
// raw_blkaddr = block 4, not the FlatInline form of the C1 seed
// (whose directory bytes sit inside the inode record). This matches
// the S06 §3.2 chassis table ("root 目录数据 块 4 起"), decouples the
// directory data from the inode record (the FX-INODE rewrite family
// patches slot bytes without dragging the directory along, and the
// RD1 corner rewrites stay pure inode-slot forms), and hands the
// FX-DIRENT/FX-NAME suites a whole-block playground. Rejected: the
// FlatInline chassis (couples record and data; multi-block dirent
// forms would need inline-tail arithmetic instead of plain blocks).
const CHASSIS_ROOT_DATA_BLK: u32 = 4;

/// The number of dirents in the chassis root directory: `.` and `..`
/// only.
// AUTO-DECISION: the base chassis carries a childless root even
// though the S06 §3.2 table spells the healthy dirent set as
// "./../child entries" — child inodes are per-builder (§5 "child
// inodes are laid per builder"), and a base-chassis child dirent
// would dangle (an un-laid slot igets as a bogus-mode inode,
// EUCLEAN), which a healthy mkfs never produces. The S04+ builders
// lay each child inode together with its dirent entry, so every
// fixture stays a self-consistent healthy image before its own
// patch.
const CHASSIS_ROOT_NDIRENTS: usize = 2;

/// The packed name area of the chassis root block: "." then ".."
/// (three 0x2E bytes — no separators; the nameoff chain carries the
/// lengths, the block tail beyond i_size stays zero).
const CHASSIS_ROOT_NAMES: &[u8] = b"...";

/// The root directory byte size: the dirent array plus the packed
/// names (write_dirents lays the names right behind the array).
const CHASSIS_ROOT_DIR_SIZE: u64 =
    (CHASSIS_ROOT_NDIRENTS * size_of::<RawDirent>() + CHASSIS_ROOT_NAMES.len()) as u64;

/// Composes an on-disk `i_format` word from the typed pair — the
/// inverse of the production decode (`parse_i_format`,
/// inode/mod.rs), assembled from the same bit-family constants
/// (`I_VERSION_BIT`/`I_DATALAYOUT_BIT`) and the same enum
/// discriminants the decode extracts, so no on-disk bit layout is
/// restated here. Cross-locked against both template seeds by the
/// `chassis_staging_shape` smoke below.
fn chassis_i_format(version: InodeVersion, datalayout: DataLayout) -> u16 {
    ((version as u16) << I_VERSION_BIT) | ((datalayout as u16) << I_DATALAYOUT_BIT)
}

/// One 12-byte dirent record: `nid`, `nameoff`, AND `file_type`
/// patched through `offset_of!` — the general form the S05 FX-DIRENT
/// builders lay child entries with (their file types include the
/// out-of-range bytes and non-DIR values the chassis never uses).
/// The raw-u8 spelling of `file_type` is the T-011 §2.2 discipline
/// (no enum-ization of the disk field).
fn dirent_record(nid: u64, nameoff: u16, file_type: u8) -> [u8; 12] {
    let mut entry = DIRENT_TEMPLATE;
    put_le_u64(&mut entry, offset_of!(RawDirent, nid), nid);
    put_le_u16(&mut entry, offset_of!(RawDirent, nameoff), nameoff);
    entry[offset_of!(RawDirent, file_type)] = file_type;
    entry
}

/// One 12-byte dirent record from the T-DIRENT seed: `nid` and
/// `nameoff` patched through `offset_of!`; the seed's file_type 2
/// (DT_DIR) and reserved 0 stay — every chassis entry is a
/// directory. Delegates to [`dirent_record`].
fn chassis_dirent(nid: u64, nameoff: u16) -> [u8; 12] {
    dirent_record(nid, nameoff, 2) // 2 = DT_DIR, the seed's value
}

/// Stages the healthy chassis onto `disk` (S06 §3.2) — the minimal
/// healthy image every FX form rewrites:
///
/// * superblock: T-SB with the four chassis geometry patches
///   (root_nid 0 / inos = slot capacity / blocks 32 / meta_blkaddr
///   1), staged through `write_super_block` so the §3.4 checksum
///   finish runs;
/// * root inode: T-EXT64 switched to Extended|FLAT_PLAIN with
///   raw_blkaddr = the root data block (the FlatInline seed values
///   — datalayout 2, i_u 0xFFFFFFFF — are chassis rewrites);
/// * root data block: the `.`/`..` dirent pair, both pointing at
///   the root nid (T-DIRENT x 2, nameoff chain 24/25).
///
/// Block 0 before `SUPER_OFFSET` stays zero — the disk allocates
/// zeroed pages, and the [0,1024) reservation is those staged
/// zeros themselves.
fn stage_healthy_chassis(disk: &ErofsMemoryDisk) {
    // Superblock first — `write_inode_at` addresses through the
    // staged record (meta_blkaddr = 1 lands here).
    let mut sb = SB_TEMPLATE;
    put_le_u16(
        &mut sb,
        offset_of!(RawSuperBlock, root_nid),
        CHASSIS_ROOT_NID as u16,
    );
    put_le_u64(&mut sb, offset_of!(RawSuperBlock, inos), CHASSIS_INO_SLOTS);
    put_le_u32(
        &mut sb,
        offset_of!(RawSuperBlock, blocks),
        CHASSIS_NR_BLOCKS,
    );
    put_le_u32(
        &mut sb,
        offset_of!(RawSuperBlock, meta_blkaddr),
        CHASSIS_META_BLKADDR,
    );
    write_super_block(disk, &sb);

    // Root inode at nid 0 -> iloc 4096: FLAT_PLAIN over the root
    // data block; size/nlink consistent with the `.`/`..`-only
    // directory below (nlink 2 = self + parent reference).
    let mut root = INODE_EXT_TEMPLATE;
    put_le_u16(
        &mut root,
        offset_of!(RawInodeExtended, i_format),
        chassis_i_format(InodeVersion::Extended, DataLayout::FlatPlain),
    );
    put_le_u64(
        &mut root,
        offset_of!(RawInodeExtended, i_size),
        CHASSIS_ROOT_DIR_SIZE,
    );
    put_le_u32(
        &mut root,
        offset_of!(RawInodeExtended, i_u),
        CHASSIS_ROOT_DATA_BLK,
    );
    put_le_u32(&mut root, offset_of!(RawInodeExtended, i_nlink), 2);
    write_inode_at(disk, CHASSIS_ROOT_NID, &root);

    // Root directory data: the dirent array at the block base, the
    // packed names right behind it (the `write_dirents` first-
    // nameoff contract: entries.len()); `..` starts one byte in,
    // right behind the one-byte `.`.
    let array_len = CHASSIS_ROOT_NDIRENTS * size_of::<RawDirent>();
    let dot = chassis_dirent(CHASSIS_ROOT_NID, array_len as u16);
    let dot_dot = chassis_dirent(CHASSIS_ROOT_NID, array_len as u16 + 1);
    let entries = [dot, dot_dot].concat();
    write_dirents(
        disk,
        CHASSIS_ROOT_DATA_BLK as u64,
        &entries,
        CHASSIS_ROOT_NAMES,
    );
}

/// A staged image plus its mount attempt (S06 §4.3): the FX-*
/// builder family (S04+) hands its host one value carrying both the
/// disk (for inspection and post-mount rewrites) and the
/// `Erofs::open` result — mount-Ok forms unwrap through
/// [`ErofsFixture::mounted`], rejection forms assert `open` with
/// `assert_errno!`.
/// A staged image plus its mount attempt (S06 §4.3): the FX-*
/// builder family (S04+) hands its host one value carrying both the
/// disk (for inspection and post-mount rewrites) and the
/// `Erofs::open` result — mount-Ok forms unwrap through
/// [`ErofsFixture::mounted`], rejection forms assert `open` with
/// `assert_errno!`.
///
/// The three rewrite-navigation fields (`disk`/`root_nid`/
/// `meta_blkaddr`) have no reader as of S03 — the mount test
/// consumes the image only through `open`. Their first consumers
/// join with the S04+ FX builders (post-mount inspection, pre-mount
/// rewrites, slot-offset navigation); once all three have readers
/// this expectation goes unfulfilled and the attribute must be
/// removed (the `fast_symlink_target` transitional-attribute
/// discipline, `inode/mod.rs`).
#[expect(dead_code)]
pub(super) struct ErofsFixture {
    /// The staged memory disk.
    pub(super) disk: Arc<ErofsMemoryDisk>,
    /// The mount attempt over the staged image — the S06 §4.3
    /// spelling `Erofs::open(disk, FsFlags::empty(), None)` (the
    /// `device=` semantics half belongs to initramfs; `open` itself
    /// forces RDONLY, so the empty flags are the fixture form).
    pub(super) open: Result<Arc<Erofs>>,
    /// Rewrite-navigation field (S06 §4.3): the chassis root nid.
    pub(super) root_nid: u64,
    /// Rewrite-navigation field (S06 §4.3): the chassis meta-area
    /// base, in blocks.
    pub(super) meta_blkaddr: u64,
}

impl ErofsFixture {
    /// The mounted handle — panics on an Err mount (the healthy and
    /// mount-Ok forms' consumer face; rejection forms never call
    /// here).
    pub(super) fn mounted(&self) -> Arc<Erofs> {
        self.open
            .as_ref()
            .expect("fixture must have mounted")
            .clone()
    }
}

/// The untouched healthy chassis, mounted (the S06 Layer-5
/// convenience entry): a fresh 32-block disk staged with
/// [`stage_healthy_chassis`] and opened through the production
/// `Erofs::open` — the full mount chain the `fs.rs` suite asserts
/// (`healthy_fixture_mounts`).
pub(super) fn healthy_fixture() -> ErofsFixture {
    let disk = Arc::new(ErofsMemoryDisk::new(
        CHASSIS_NR_BLOCKS as usize * CHASSIS_BLOCK_SIZE,
    ));
    stage_healthy_chassis(&disk);
    let open = Erofs::open(disk.clone() as Arc<dyn BlockDevice>, FsFlags::empty(), None);
    ErofsFixture {
        disk,
        open,
        root_nid: CHASSIS_ROOT_NID,
        meta_blkaddr: u64::from(CHASSIS_META_BLKADDR),
    }
}

// ===========================================================================
// T-027 S04: the FX-SB builder family (S06 §5.1; matrix §1.6 label row
// IMG-CRAFT-SB serving the §2.2 crafted rows). Fourteen named
// constructors, each a LOCAL rewrite of the healthy chassis — a healthy
// mkfs produces no malformed form, so the fixture口径 stays "minimal
// patches over staged bytes". Superblock field patches go through
// `write_super_block` (the §3.4 checksummed finish); the V5-family
// forms alone stage through `write_super_block_raw`, the single
// explicit skip channel, so the chassis checksum goes stale on
// purpose. The mount-assertion suite lives in `fs.rs` (the D1 host
// rule — the V1–V10 order authority is `Erofs::open`); the G-M10
// truncated-DISK form is S14's and is not built here.
//
// AUTO-DECISION: the V-door values are derived, not spelled — bad
// magic = SUPER_MAGIC_V1 ^ 0x0100_0000 (the §5.1 one-bit diff), the
// blkszbits pair = BLKSZBITS_MIN − 1 / SUPPORTED_BLKSZBITS + 1, the
// unknown incompat bit = next_power_of_two(known union). Only the
// extslots 184/185 pair is spelled (the forms' identity, per §5.1's
// own spelling), with the exactness of 184 cross-locked in the fs.rs
// suite against the production `sb_size()` == SUPER_REGION_MAX.
// Rejected: literals everywhere (a second truth per value; §5.1's
// "不抄字面" note names the incompat bit — the same discipline covers
// the rest of the family).
// ===========================================================================

/// Reads the currently staged 128-byte superblock record — the raw
/// byte view the `fx_sb_*` patches consume (the decoded mirror of
/// `staged_super_block` cannot carry the checksum field, and the
/// checksum is exactly what the V5 forms must preserve stale).
fn staged_super_block_record(disk: &ErofsMemoryDisk) -> [u8; 128] {
    let mut record = [0u8; 128];
    disk.segment()
        .read_bytes(SUPER_OFFSET, &mut record)
        .unwrap();
    record
}

/// Stages the healthy chassis, applies the local `rewrite`, then
/// attempts the production mount — the shared shape of every `fx_sb_*`
/// builder below (the S06 §4.3 fixture form: one value carrying both
/// the staged disk and the `Erofs::open` result).
fn rewritten_chassis(rewrite: impl FnOnce(&ErofsMemoryDisk)) -> ErofsFixture {
    let disk = Arc::new(ErofsMemoryDisk::new(
        CHASSIS_NR_BLOCKS as usize * CHASSIS_BLOCK_SIZE,
    ));
    stage_healthy_chassis(&disk);
    rewrite(&disk);
    let open = Erofs::open(disk.clone() as Arc<dyn BlockDevice>, FsFlags::empty(), None);
    ErofsFixture {
        disk,
        open,
        root_nid: CHASSIS_ROOT_NID,
        meta_blkaddr: u64::from(CHASSIS_META_BLKADDR),
    }
}

/// Reads the chassis root inode record, applies `patch`, and re-stages
/// it at the same slot. The G-M15 root-door rewrites touch exactly one
/// field each (i_format / i_mode); everything else stays the staged
/// chassis bytes.
// AUTO-DECISION: the G-M15 root forms patch the staged record in
// place (read → patch one field → re-stage) rather than re-laying it
// from the template — the minimal-rewrite口径 made literal: one field
// differs from the healthy chassis, the other 62 bytes are provably
// untouched. Rejected: template re-lay (re-stages 63 unchanged bytes
// and couples the form to seed values it does not consume).
fn patch_root_inode(disk: &ErofsMemoryDisk, patch: impl FnOnce(&mut [u8; 64])) {
    let iloc = inode_location(&staged_super_block(disk), CHASSIS_ROOT_NID) as usize;
    let mut record = [0u8; 64];
    disk.segment().read_bytes(iloc, &mut record).unwrap();
    patch(&mut record);
    write_inode_at(disk, CHASSIS_ROOT_NID, &record);
}

/// The lowest `feature_incompat` bit outside the known-bit union
/// (0x7F → 0x80), derived from the production flag set — S06 §5.1's
/// "位集引 T-010 §3.2 FeatureIncompatSet 常量,不抄字面" made code.
/// `next_power_of_two` of the union is strictly above it, hence
/// outside it, and tracks any future known-bit addition automatically.
fn unknown_incompat_bit() -> u32 {
    FeatureIncompatSet::all().bits().next_power_of_two()
}

// The V7 boundary forms (S06 §5.1): sb_size = 128 + 16 × extslots must
// stay within SUPER_REGION_MAX (= PAGE_SIZE − SUPER_OFFSET = 3072), so
// extslots = 184 is the exact page-boundary pass form (128 + 16 × 184
// = 3072) and 185 the first reject (3088 > 3072). The 16 is
// SB_EXTSLOT_SIZE, module-private in `super_block.rs` — the pair is
// spelled as the forms' identity (§5.1's own spelling), and the fs.rs
// suite cross-locks 184's exactness against the production `sb_size()`
// consuming SUPER_REGION_MAX (the PAGE-derived criterion the matrix
// §2.2 row forbids rewriting as a block-size bound).
const SB_EXTSLOTS_PAGE_BOUNDARY: u8 = 184;
const SB_EXTSLOTS_PAST_BOUNDARY: u8 = 185;

/// V2 — bad magic: the chassis magic with exactly one bit flipped
/// (0xE0F5E1E2 → 0xE1F5E1E2, the §5.1 one-bit diff, derived from the
/// production constant). Expected EINVAL at the V2 door (matrix §2.2
/// crafted row).
pub(super) fn fx_sb_bad_magic() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        put_le_u32(
            &mut sb,
            offset_of!(RawSuperBlock, magic),
            SUPER_MAGIC_V1 ^ 0x0100_0000,
        );
        write_super_block(disk, &sb);
    })
}

/// V3 lower arm — blkszbits one below `BLKSZBITS_MIN` (= 8). Expected
/// EINVAL (matrix §2.2 crafted row: the range rejection face of
/// G-M08, not the healthy sub-4k image face — that is the initramfs
/// BS-ALT family, never a fixture).
pub(super) fn fx_sb_blkszbits_below_min() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        sb[offset_of!(RawSuperBlock, blkszbits)] = BLKSZBITS_MIN - 1;
        write_super_block(disk, &sb);
    })
}

/// V3 upper arm — blkszbits one above the supported 4k (= 13, past
/// `BLKSZBITS_MAX`). Expected EINVAL. The disk geometry stays 4k: an
/// FX-SB V3 rewrite is a field patch, not a geometry change (S06 §3.2
/// "主列 fixture 物理块恒 4096B").
pub(super) fn fx_sb_blkszbits_above_supported() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        sb[offset_of!(RawSuperBlock, blkszbits)] = SUPPORTED_BLKSZBITS + 1;
        write_super_block(disk, &sb);
    })
}

/// V4 — non-zero dirblkbits (= 1). Expected EINVAL.
pub(super) fn fx_sb_dirblkbits_nonzero() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        sb[offset_of!(RawSuperBlock, dirblkbits)] = 1;
        write_super_block(disk, &sb);
    })
}

/// V5 — bad superblock checksum: one byte of the gate-inert `inos`
/// field flipped (inos feeds only the statfs ffree arithmetic, so the
/// stale checksum is the ONLY broken invariant), staged through
/// `write_super_block_raw` — the single explicit skip of the §3.4
/// recompute. Expected EBADMSG (matrix §2.2 / the G-M09 bad half).
pub(super) fn fx_sb_bad_checksum() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        let inos_off = offset_of!(RawSuperBlock, inos);
        let inos = get_le_u64(&sb, inos_off);
        put_le_u64(&mut sb, inos_off, inos ^ 0xFF);
        write_super_block_raw(disk, &sb);
    })
}

/// V6 — an unknown incompat bit (checksummed staging: V5 passes, the
/// unknown-bit door fires). Expected EINVAL; the known bits' mount-Ok
/// acceptance face is the FX-COMP per-bit family (S10), not here.
pub(super) fn fx_sb_unknown_incompat_bit() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        let off = offset_of!(RawSuperBlock, feature_incompat);
        let bits = get_le_u32(&sb, off);
        put_le_u32(&mut sb, off, bits | unknown_incompat_bit());
        write_super_block(disk, &sb);
    })
}

/// V7 pass form — sb_extslots = 184, the exact page boundary (sb_size
/// = SUPER_REGION_MAX = 3072). Expected mount Ok; the fs.rs suite
/// cross-locks `sb_size() == SUPER_REGION_MAX` on the mounted mirror.
pub(super) fn fx_sb_extslots_at_page_boundary() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        sb[offset_of!(RawSuperBlock, sb_extslots)] = SB_EXTSLOTS_PAGE_BOUNDARY;
        write_super_block(disk, &sb);
    })
}

/// V7 reject form — sb_extslots = 185, one slot past the page boundary
/// (sb_size = 3088 > 3072). Expected EINVAL.
pub(super) fn fx_sb_extslots_past_page_boundary() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        sb[offset_of!(RawSuperBlock, sb_extslots)] = SB_EXTSLOTS_PAST_BOUNDARY;
        write_super_block(disk, &sb);
    })
}

/// V8 — volume_name with no NUL byte in its 16 bytes (all 0x41).
/// Expected EUCLEAN (the EFSCORRUPTED mapping).
pub(super) fn fx_sb_volume_name_without_nul() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        let off = offset_of!(RawSuperBlock, volume_name);
        sb[off..off + size_of::<[u8; 16]>()].fill(0x41);
        write_super_block(disk, &sb);
    })
}

/// The V5+V6 order cross — both failures in one image: an unknown
/// incompat bit AND a stale checksum (raw staging, the V5 skip
/// channel). The mount must fail EBADMSG: the V5 door runs before the
/// V6 door, and a reorder of `read_superblock` would surface EINVAL
/// here instead (matrix §2.2: the errno priority chain IS the
/// assertion surface).
pub(super) fn fx_sb_bad_checksum_and_unknown_incompat() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        let off = offset_of!(RawSuperBlock, feature_incompat);
        let bits = get_le_u32(&sb, off);
        put_le_u32(&mut sb, off, bits | unknown_incompat_bit());
        write_super_block_raw(disk, &sb);
    })
}

/// G-M10 root door — root_nid = 0xFFFF (le16 max): the iloc formula
/// sends the Step-5 iget's inode read some 2 MB past the 128 KiB
/// device, and the framework byte-channel bound fails it before the
/// device is reached. Expected EINVAL — the registered drift value
/// (matrix §2.2 G-M10: Linux's metabuf read fails EIO; aster EINVAL
/// per the T-014 §4.4 byte-channel ledger). The truncated-DISK
/// sibling of this family is S14's (R1, value finalized there).
pub(super) fn fx_sb_root_nid_out_of_device() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        put_le_u16(&mut sb, offset_of!(RawSuperBlock, root_nid), u16::MAX);
        write_super_block(disk, &sb);
    })
}

/// G-M15 root door, compressed half — the chassis root's datalayout
/// switched to CompressedFull (i_format only; the DIR mode stays).
/// The Step-5 iget fails at the I12 arm-head gate, ahead of the F12
/// type judgement. Expected EOPNOTSUPP — the errno-distinguishable
/// negative control of the F12 EINVAL below (matrix §2.2 G-M15 row:
/// "root 压缩目录 → EOPNOTSUPP 非 F12 的 EINVAL").
pub(super) fn fx_sb_root_compressed() -> ErofsFixture {
    rewritten_chassis(|disk| {
        patch_root_inode(disk, |root| {
            put_le_u16(
                root,
                offset_of!(RawInodeExtended, i_format),
                chassis_i_format(InodeVersion::Extended, DataLayout::CompressedFull),
            );
        })
    })
}

/// G-M15 root door, type half — the chassis root's S_IFMT segment
/// switched DIR → REG (the 0755 permission bits stay). The iget
/// SUCCEEDS (a healthy REG decodes and assembles fine), then the F12
/// type gate rejects. Expected EINVAL (matrix §2.2 G-M15: "root 是
/// REG 读成功后类型判 → EINVAL,与 i_format 非法 EOPNOTSUPP 可区分"
/// — iget-before-type is the order face).
pub(super) fn fx_sb_root_not_dir() -> ErofsFixture {
    rewritten_chassis(|disk| {
        patch_root_inode(disk, |root| {
            let mode_off = offset_of!(RawInodeExtended, i_mode);
            let mode = get_le_u16(root, mode_off);
            put_le_u16(root, mode_off, (mode & !S_IFMT) | S_IFREG);
        })
    })
}

/// The nid the FX-SB G-M15 packed-payload form lays its compressed
/// inode at: the first free even slot behind the extended root
/// (uniform-extended — the root record holds slots 0/1, so nid 2 is
/// next; the chassis parity convention, not a C10-measured value).
const CHASSIS_PACKED_NID: u64 = 2;

/// G-M15 packed door — FRAGMENTS set plus packed_nid addressing a
/// freshly-laid compressed REG inode (the extended seed with the type
/// segment switched to REG and the datalayout to CompressedFull;
/// i_u/i_size stay seed bytes — the I12 gate fires before any payload
/// consumption). The Step-4 F10 iget fails at I12. Expected EOPNOTSUPP
/// (mount failure; matrix §2.2 G-M15 / T-004 §7.7 ⑤ — the same
/// material the FX-COMP family re-consumes, S06 §5.7's "同素材双消费"
/// note; the u1≠0 and per-bit acceptance comp forms are S10's).
pub(super) fn fx_sb_packed_compressed_payload() -> ErofsFixture {
    rewritten_chassis(|disk| {
        // The packed inode first — `write_inode_at` addresses through
        // the still-healthy staged superblock.
        let mut packed = INODE_EXT_TEMPLATE;
        put_le_u16(
            &mut packed,
            offset_of!(RawInodeExtended, i_format),
            chassis_i_format(InodeVersion::Extended, DataLayout::CompressedFull),
        );
        let mode_off = offset_of!(RawInodeExtended, i_mode);
        let mode = get_le_u16(&packed, mode_off);
        put_le_u16(&mut packed, mode_off, (mode & !S_IFMT) | S_IFREG);
        write_inode_at(disk, CHASSIS_PACKED_NID, &packed);

        let mut sb = staged_super_block_record(disk);
        let incompat_off = offset_of!(RawSuperBlock, feature_incompat);
        let incompat = get_le_u32(&sb, incompat_off);
        put_le_u32(
            &mut sb,
            incompat_off,
            incompat | FeatureIncompatSet::FRAGMENTS.bits(),
        );
        put_le_u64(
            &mut sb,
            offset_of!(RawSuperBlock, packed_nid),
            CHASSIS_PACKED_NID,
        );
        write_super_block(disk, &sb);
    })
}

// ===========================================================================
// T-027 S05: the FX-DIRENT builder family (S06 §5.3; matrix §1.6 label
// row IMG-CRAFT-DIRENT serving the §3.4 lookup rows — mask tolerance,
// out-of-order binary search, missing `..`/wrong nid, directory cycle,
// d_type ≥ 8, nid = 0 — and the §3.5 rows: the R5/R10 bound-check family
// and the W-N05/W-N06/W-N07 embedded-NUL half). Fifteen named
// constructors, each a LOCAL rewrite of the chassis root directory block
// (the child forms also lay healthy child directory inodes); field
// semantics and bound-check behavior are NOT re-derived here — the
// single sources are the T-013 dir册 and the matrix §3.4/§3.5 rows, and
// the assertion values live in the `inode/dir.rs` suite (the D1 host
// rule; the two-strictness-domains contract's executed R5 column).
//
// AUTO-DECISION: the S06 §5.3 table's 11 rows land as 15 constructors.
// The two splits are the rows' own text: 「缺 `..`(根与子目录各一
// 形态)」 becomes the root/child pair, and the R5/R10 family row becomes
// four corner builders (R5 nameoff==0; R10 empty name / name over
// NAME_LEN / name beyond maxsize) — the fourth R10 sub-form, the
// inverted-chain wrap-huge namelen, is already the inverted builder's
// readdir half. d_type 8/255 share one image (both entries patched) and
// the wrong-nid row keeps ONE form patching `..` — the matrix row's own
// 「`..` 指错 nid 照显」 example, the mechanism being shared. Rejected:
// strict one-constructor-per-row (leaves the R10 sub-forms
// unmaterialized); finer splits (two d_type images or a `.`-nid twin add
// no assertion surface).
// ===========================================================================

/// Reads the chassis root directory block's dirent slot `index`,
/// applies `patch`, and re-stages it in place — the G-M15
/// `patch_root_inode` discipline (read → patch one field → re-stage)
/// for the 12-byte records: the patched fields differ from the
/// healthy chassis, the neighboring bytes are provably untouched.
fn patch_root_dirent(disk: &ErofsMemoryDisk, index: usize, patch: impl FnOnce(&mut [u8; 12])) {
    let base = CHASSIS_ROOT_DATA_BLK as usize * CHASSIS_BLOCK_SIZE + index * size_of::<RawDirent>();
    let mut record = [0u8; 12];
    disk.segment().read_bytes(base, &mut record).unwrap();
    patch(&mut record);
    disk.stage_bytes(base, &record);
}

/// Re-lays the whole root directory block from typed records plus a
/// packed name area, aligning the root i_size to the laid bytes (the
/// multi-entry FX-DIRENT forms' staging face). The first record's
/// `nameoff` must equal `records.len() * 12` — the `write_dirents`
/// first-nameoff contract.
fn lay_root_dirents(disk: &ErofsMemoryDisk, records: &[[u8; 12]], names: &[u8]) {
    let entries = records.concat();
    write_dirents(disk, CHASSIS_ROOT_DATA_BLK as u64, &entries, names);
    let dir_size = (entries.len() + names.len()) as u64;
    patch_root_inode(disk, |root| {
        put_le_u64(root, offset_of!(RawInodeExtended, i_size), dir_size);
    });
}

/// Lays a healthy EMPTY child directory inode at `nid` — the extended
/// seed switched to FLAT_PLAIN with size 0 and raw_blkaddr 0 (a legal
/// empty directory; no data block, the N4 lookup gate answers ENOENT
/// before any read). The lookup-hit assertions of the FX-DIRENT forms
/// iget these targets. nlink is gate-inert; 1 is the self-consistent
/// spelling for a dotless empty directory.
fn lay_empty_dir_at(disk: &ErofsMemoryDisk, nid: u64) {
    let mut record = INODE_EXT_TEMPLATE;
    put_le_u16(
        &mut record,
        offset_of!(RawInodeExtended, i_format),
        chassis_i_format(InodeVersion::Extended, DataLayout::FlatPlain),
    );
    put_le_u64(&mut record, offset_of!(RawInodeExtended, i_size), 0);
    put_le_u32(&mut record, offset_of!(RawInodeExtended, i_u), 0);
    put_le_u32(&mut record, offset_of!(RawInodeExtended, i_nlink), 1);
    write_inode_at(disk, nid, &record);
}

/// Lays a healthy child directory at `nid` whose data lives at `blk`,
/// carrying `records`/`names` (i_size aligned; `..` points where the
/// records say) — the subdirectory level of the child forms. nlink 2 =
/// self + parent, the dot-bearing spelling.
fn lay_dir_with_block(
    disk: &ErofsMemoryDisk,
    nid: u64,
    blk: u32,
    records: &[[u8; 12]],
    names: &[u8],
) {
    let entries = records.concat();
    write_dirents(disk, blk as u64, &entries, names);
    let mut record = INODE_EXT_TEMPLATE;
    put_le_u16(
        &mut record,
        offset_of!(RawInodeExtended, i_format),
        chassis_i_format(InodeVersion::Extended, DataLayout::FlatPlain),
    );
    put_le_u64(
        &mut record,
        offset_of!(RawInodeExtended, i_size),
        (entries.len() + names.len()) as u64,
    );
    put_le_u32(&mut record, offset_of!(RawInodeExtended, i_u), blk);
    put_le_u32(&mut record, offset_of!(RawInodeExtended, i_nlink), 2);
    write_inode_at(disk, nid, &record);
}

/// The chassis root dirent-array end (= the first name's nameoff):
/// 2 × 12 = 24 — the base the nameoff corner rewrites derive from.
const CHASSIS_ROOT_ARRAY_END: usize = CHASSIS_ROOT_NDIRENTS * size_of::<RawDirent>();

/// Row 1, nameoff high bits — the first dirent's nameoff carries the
/// block-out-of-bounds value 4096 + 24: the lookup side masks it into
/// [0, bs) (silent fold, both dot names still resolve) while the
/// iteration side rejects the RAW value ≥ bs (R5 EUCLEAN) — the
/// visible-divergence row of the two-strictness-domains contract
/// (matrix §3.4 mask-tolerance row).
pub(super) fn fx_dirent_nameoff_high_bits() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let high = (CHASSIS_BLOCK_SIZE + CHASSIS_ROOT_ARRAY_END) as u16;
        patch_root_dirent(disk, 0, |de| {
            put_le_u16(de, offset_of!(RawDirent, nameoff), high);
        });
    })
}

/// Row 2, nameoff not a multiple of 12 — 13 (one byte into the
/// second record's nid field): the value lands inside the dirent
/// array area. Lookup consumes it silently (fold 13 → ndirents 1;
/// the NUL-led region compares Greater for every name — the
/// drift-preserving miss), readdir rejects (R5 non-multiple).
pub(super) fn fx_dirent_nameoff_not_multiple() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let not_multiple = (size_of::<RawDirent>() + 1) as u16;
        patch_root_dirent(disk, 0, |de| {
            put_le_u16(de, offset_of!(RawDirent, nameoff), not_multiple);
        });
    })
}

/// Row 3, inverted nameoff chain — the successor's nameoff (20) is
/// four bytes BELOW the predecessor's (24). Lookup reads an inverted
/// (empty) name region and drifts silently (namei.c:22-27); readdir
/// derives a wrap-huge namelen (20 − 24 as u32) and hits the R10
/// bogus-dirent door.
pub(super) fn fx_dirent_nameoff_inverted() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let inverted = (CHASSIS_ROOT_ARRAY_END - 4) as u16;
        patch_root_dirent(disk, 1, |de| {
            put_le_u16(de, offset_of!(RawDirent, nameoff), inverted);
        });
    })
}

// AUTO-DECISION: the out-of-order playground replaces the whole root
// directory data with FIVE single-entry blocks (4..=8) whose head names
// are deliberately unsorted — "aa", "bb", "abz", "cc", "dd" — with no
// `.`/`..` entries. The block-level probe trajectory that exposes the
// prefix-carry drift (probe b:6 "abz" Less, then b:4 "aa" Greater, then
// b:5 "bb" Equal-with-carry — the FALSE HIT) needs exactly this
// geometry: five blocks for the mid-point sequence, single-entry blocks
// so the in-block layer stays out of the trajectory, and the head slots
// free of dot names (dots would occupy the probed de0 positions). The
// form IS the crafted 乱序目录 (a healthy mkfs never emits unsorted
// names), so dropping the dots stays inside the fixture口径. Rejected:
// a subdirectory playground (an extra tree level for no added face);
// in-block-slot disorder (the in-block search resets the carry — no
// drift surface there).
//
// The head-name/probe-nid table (the form's identity, §5.3's 「乱序
// 二分」row; even nids per the chassis convention):
const UNSORTED_HEADS: [(&[u8], u64); 5] =
    [(b"aa", 2), (b"bb", 4), (b"abz", 6), (b"cc", 8), (b"dd", 10)];

/// Row 4, out-of-order binary search (matrix §3.4: lookup misses and
/// false hits are Linux-identical PRESERVED drift; the implementation
/// must stay a binary search — a linear scan would find "bb"). The
/// `inode/dir.rs` suite pins the trajectory pointwise: "ab" FALSE-HITS
/// the "bb" inode, "bb" itself MISSES, and readdir emits everything in
/// slot order with no alphabetical check.
pub(super) fn fx_dirent_unsorted_binary_search() -> ErofsFixture {
    rewritten_chassis(|disk| {
        for (i, &(name, nid)) in UNSORTED_HEADS.iter().enumerate() {
            let blk = CHASSIS_ROOT_DATA_BLK + i as u32;
            write_dirents(
                disk,
                blk as u64,
                &dirent_record(nid, size_of::<RawDirent>() as u16, 2),
                name,
            );
            lay_empty_dir_at(disk, nid);
        }
        // Root size: four full blocks plus the last block's array +
        // 2-byte name ("dd").
        let size = 4 * CHASSIS_BLOCK_SIZE + size_of::<RawDirent>() + UNSORTED_HEADS[4].0.len();
        patch_root_inode(disk, |root| {
            put_le_u64(root, offset_of!(RawInodeExtended, i_size), size as u64);
        });
    })
}

/// Row 5, root form — the root directory block carries `.` and one
/// child entry, no `..` (matrix §3.4: getdents emits the `..`-less
/// row set; the dcache-tree `..` walk is unaffected by on-disk
/// forms — that face is the initramfs layer's). The child at nid 2
/// is laid so the surviving entry resolves.
pub(super) fn fx_dirent_missing_dotdot_root() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_empty_dir_at(disk, 2);
        lay_root_dirents(
            disk,
            &[
                dirent_record(CHASSIS_ROOT_NID, CHASSIS_ROOT_ARRAY_END as u16, 2),
                dirent_record(2, (CHASSIS_ROOT_ARRAY_END + 1) as u16, 2),
            ],
            b".a",
        );
    })
}

/// Row 5, child form — the ROOT keeps its healthy `.`/`..` plus the
/// child entry "a" → nid 2; the CHILD's own block (block 5) carries
/// `.` and a grandchild entry, no `..`. Both levels' negative and
/// positive faces live in the dir.rs suite.
pub(super) fn fx_dirent_missing_dotdot_child() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_empty_dir_at(disk, 4);
        lay_dir_with_block(
            disk,
            2,
            CHASSIS_ROOT_DATA_BLK + 1,
            &[
                dirent_record(2, CHASSIS_ROOT_ARRAY_END as u16, 2),
                dirent_record(4, (CHASSIS_ROOT_ARRAY_END + 1) as u16, 2),
            ],
            b".g",
        );
        lay_root_dirents(
            disk,
            &[
                dirent_record(CHASSIS_ROOT_NID, 36, 2),
                dirent_record(CHASSIS_ROOT_NID, 37, 2),
                dirent_record(2, 39, 2),
            ],
            b"...a",
        );
    })
}

// AUTO-DECISION: the wrong-nid form patches `..` to nid 2 and LAYS a
// real (empty-directory) target inode at nid 2 — no dangling pointer.
// With a laid target, the assertions read "consumed as-is" end to end:
// getdents displays nid 2 and lookup("..") igets the child instead of
// the root. A dangling target (nid never laid) would conflate the
// namei hit with the iget failure (EUCLEAN), hiding the very
// no-cross-check face the row asserts. Rejected: patching `.` instead
// (same mechanism, and the matrix row names the `..` example); laying
// a REG target (the DIR/DIR mismatch adds nothing — d_type
// non-cross-check is the dtype form's face).
pub(super) fn fx_dirent_dotdot_wrong_nid() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_empty_dir_at(disk, 2);
        patch_root_dirent(disk, 1, |de| {
            put_le_u64(de, offset_of!(RawDirent, nid), 2);
        });
    })
}

/// Row 7, directory cycle — the root's "loop" entry and the child's
/// "loop" entry point at each other's directories (nid 2 ↔ nid 0):
/// two dirents forming a cycle, the W-N08 material. The dir.rs suite
/// pins the FS-level legs (each single-step lookup resolves; the
/// child's "loop" returns the ROOT identity — the walk can continue
/// forever). The PATH_MAX exhaustion face (registered drift
/// ELOOP vs ENAMETOOLONG) belongs to the VFS path resolver, which no
/// dir.rs ktest reaches; this image is the material it would loop on.
pub(super) fn fx_dirent_directory_cycle() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_dir_with_block(
            disk,
            2,
            CHASSIS_ROOT_DATA_BLK + 1,
            &[
                dirent_record(2, 36, 2),
                dirent_record(CHASSIS_ROOT_NID, 37, 2),
                dirent_record(CHASSIS_ROOT_NID, 39, 2),
            ],
            b"...loop",
        );
        lay_root_dirents(
            disk,
            &[
                dirent_record(CHASSIS_ROOT_NID, 36, 2),
                dirent_record(CHASSIS_ROOT_NID, 37, 2),
                dirent_record(2, 39, 2),
            ],
            b"...loop",
        );
    })
}

/// Row 8, d_type ≥ 8 — file_type 8 on `.` and 255 on `..`: readdir
/// degrades both to DT_UNKNOWN SILENTLY (R8: conversion from the
/// dirent byte only, no cross-check, no error). Lookup never reads
/// the field, so the walk is unaffected.
pub(super) fn fx_dirent_dtype_out_of_range() -> ErofsFixture {
    rewritten_chassis(|disk| {
        patch_root_dirent(disk, 0, |de| {
            de[offset_of!(RawDirent, file_type)] = 8;
        });
        patch_root_dirent(disk, 1, |de| {
            de[offset_of!(RawDirent, file_type)] = 255;
        });
    })
}

/// Row 9, zero nid — a third entry "zero" whose nid is 0 (the root's
/// own nid): readdir emits the row with ino 0 as-is (no validation,
/// R1) and d_type from the dirent byte (FT_REG 1) with no cross-check
/// against the DIR it resolves to; lookup("zero") follows the nid
/// just as uncritically — to the root itself.
pub(super) fn fx_dirent_zero_nid_entry() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_root_dirents(
            disk,
            &[
                dirent_record(CHASSIS_ROOT_NID, 36, 2),
                dirent_record(CHASSIS_ROOT_NID, 37, 2),
                dirent_record(0, 39, 1),
            ],
            b"...zero",
        );
    })
}

/// Row 10, embedded NUL names (the NUL half; the name-family half is
/// S06's) — two child entries: non-trailing "a\0b" and trailing
/// "t\0u". The iteration side emits the non-trailing name VERBATIM at
/// full nameoff-derived length (the NUL rides along; strnlen applies
/// only to the trailing entry) and truncates the trailing name at the
/// NUL; the getdents syscall faces (W-N05/W-N06/W-N07: buffer and
/// stickiness semantics) are the framework layer's. The lookup half
/// truncates on-disk names at the NUL inside dirnamecmp (namei.c).
pub(super) fn fx_dirent_embedded_nul_names() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_empty_dir_at(disk, 2);
        lay_empty_dir_at(disk, 4);
        lay_root_dirents(
            disk,
            &[
                dirent_record(CHASSIS_ROOT_NID, 48, 2),
                dirent_record(CHASSIS_ROOT_NID, 49, 2),
                dirent_record(2, 51, 1),
                dirent_record(4, 54, 1),
            ],
            b"...a\0bt\0u",
        );
    })
}

/// Row 11 (R5 corner), nameoff == 0 on the first dirent — BOTH
/// domains reject with EUCLEAN through different mechanisms: lookup
/// folds 0 → ndirents 0 → the N8 "corrupted dir block" door; readdir
/// fails the raw == 0 check. The matrix §3.4 same-errno-different-
/// mechanism family, executed on one image.
pub(super) fn fx_dirent_nameoff_zero() -> ErofsFixture {
    rewritten_chassis(|disk| {
        patch_root_dirent(disk, 0, |de| {
            put_le_u16(de, offset_of!(RawDirent, nameoff), 0);
        });
    })
}

/// Row 11 (R10 corner), empty name — the successor's nameoff EQUALS
/// the predecessor's (24 == 24): the non-trailing namelen derives as
/// zero, and the !(1..=NAME_LEN) door fires EUCLEAN. Lookup reads the
/// inverted-empty region and drifts silently (ENOENT — no error from
/// the lookup side).
pub(super) fn fx_dirent_empty_name() -> ErofsFixture {
    rewritten_chassis(|disk| {
        patch_root_dirent(disk, 1, |de| {
            put_le_u16(
                de,
                offset_of!(RawDirent, nameoff),
                CHASSIS_ROOT_ARRAY_END as u16,
            );
        });
    })
}

/// Row 11 (R10 corner), name over NAME_LEN — the successor's nameoff
/// (324 = 24 + 255 + 45) derives a 300-byte namelen for the first
/// entry: > NAME_LEN → EUCLEAN. Lookup stays silent (the NUL-truncated
/// region compares Less for "." — ENOENT via the drift path).
pub(super) fn fx_dirent_name_over_255() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let nameoff = (CHASSIS_ROOT_ARRAY_END + NAME_LEN + 45) as u16;
        patch_root_dirent(disk, 1, |de| {
            put_le_u16(de, offset_of!(RawDirent, nameoff), nameoff);
        });
    })
}

/// Row 11 (R10 corner), name beyond maxsize — the successor's
/// nameoff (40) derives a 16-byte name for the FIRST slot
/// ([24, 40)), whose END crosses the i_size-27 window:
/// nameoff + namelen = 40 > 27 → EUCLEAN at the first entry. The
/// trailing slot's OWN name can never craft this (strnlen caps the
/// scan at maxsize - nameoff, so its end stays ≤ maxsize) — the
/// beyond-window form is only reachable through a NON-trailing
/// nameoff chain. Lookup consumes the region as-is: NUL-truncated
/// [24, 40) reads "..." (bytes [24, 27) are the dot names), so both
/// dots miss while the coincidental "..." hit resolves to the root.
pub(super) fn fx_dirent_name_beyond_maxsize() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let nameoff = (CHASSIS_ROOT_ARRAY_END + 16) as u16;
        patch_root_dirent(disk, 1, |de| {
            put_le_u16(de, offset_of!(RawDirent, nameoff), nameoff);
        });
    })
}

// ===========================================================================
// T-027 S06: the FX-NAME builder family (S06 §5.4; matrix §1.6 label row
// IMG-CRAFT-NAME — the name/target CONTENT family: non-UTF-8 name, non-UTF-8
// symlink target, '/' name, embedded-NUL name — serving the §3.3 G-N02 /
// §3.4 W-N04 / §3.5 G-N04/G-N05/W-N05 rows per the matrix §8.3 service
// column, which is the authority over §5.4's service labels (the '/'-name
// row there cites G-N04 and the NUL row G-N05/W-N05; the matrix rows pin
// G-N04 = readdir non-UTF-8 → EIO and G-N05 = '/'-name → EIO — the
// builder SET is §1.6's four forms either way, only the row labels shift).
// Three new constructors; the embedded-NUL name-family half reuses the S05
// `fx_dirent_embedded_nul_names` image (below). The crafted names stay at
// their byte-sort position in the root block (the 0xFF-led name sorts
// above every ASCII name), so the lookup binary search keeps healthy
// trajectories for the sibling lookups the dir.rs suite asserts.
//
// AUTO-DECISION: the embedded-NUL name-family half lands as exact-byte
// lookup assertions over the S05 `fx_dirent_embedded_nul_names` image —
// same material, double consumption (the FX-SB G-M15 / FX-COMP §5.7
// precedent: one builder lives in exactly one family) — instead of a
// fourth builder re-staging the same `a\0b` shape. Rejected: a duplicate
// `fx_name_embedded_nul` image (two fixtures for one form, no added
// assertion surface).
//
// AUTO-DECISION: the G-N02 form covers BOTH payload arms plus two ASCII
// controls in ONE image — fast FLAT_INLINE and slow FLAT_PLAIN (i_u)
// share the single `read_link` conversion exit (S04-D5), so one image
// with a 2×2 arm/expectation grid pins the unified exit and proves the
// EIO comes from the UTF-8 judgement, not the staging. Rejected: one arm
// per builder (same mechanism, the d_type 8/255 one-image precedent).
// ===========================================================================

/// Lays a healthy FAST child symlink at `nid`: the extended seed with
/// the S_IFMT segment switched to LNK and datalayout FlatInline, the
/// `target` bytes staged right behind the record (the
/// `inline_data_start` position at the seed's zero xattr_icount).
///
/// Slot-geometry note: an extended record spans TWO 32-byte slots, so
/// the inline tail of a fast symlink at nid N collides with the record
/// of a child laid at nid N+2. The fixture therefore spaces its
/// inline-carrying children FOUR slots apart (target room = 64 bytes,
/// far above every target this family stages); the even-nid chassis
/// convention itself is untouched.
fn lay_fast_symlink_at(disk: &ErofsMemoryDisk, nid: u64, target: &[u8]) {
    let mut record = INODE_EXT_TEMPLATE;
    put_le_u16(
        &mut record,
        offset_of!(RawInodeExtended, i_format),
        chassis_i_format(InodeVersion::Extended, DataLayout::FlatInline),
    );
    let mode_off = offset_of!(RawInodeExtended, i_mode);
    let mode = get_le_u16(&record, mode_off);
    put_le_u16(&mut record, mode_off, (mode & !S_IFMT) | S_IFLNK);
    put_le_u64(
        &mut record,
        offset_of!(RawInodeExtended, i_size),
        target.len() as u64,
    );
    put_le_u32(&mut record, offset_of!(RawInodeExtended, i_nlink), 1);
    write_inode_at(disk, nid, &record);
    let iloc = inode_location(&staged_super_block(disk), nid) as usize;
    disk.stage_bytes(iloc + size_of::<RawInodeExtended>(), target);
}

/// Lays a healthy SLOW child symlink at `nid`: LNK × FLAT_PLAIN over a
/// whole target block (`i_u = blk`), the target bytes staged at the
/// block base — the DataBacked arm reads the very same bytes through
/// the page cache (the unified-exit premise of the G-N02 form).
fn lay_slow_symlink_at(disk: &ErofsMemoryDisk, nid: u64, blk: u32, target: &[u8]) {
    let mut record = INODE_EXT_TEMPLATE;
    put_le_u16(
        &mut record,
        offset_of!(RawInodeExtended, i_format),
        chassis_i_format(InodeVersion::Extended, DataLayout::FlatPlain),
    );
    let mode_off = offset_of!(RawInodeExtended, i_mode);
    let mode = get_le_u16(&record, mode_off);
    put_le_u16(&mut record, mode_off, (mode & !S_IFMT) | S_IFLNK);
    put_le_u64(
        &mut record,
        offset_of!(RawInodeExtended, i_size),
        target.len() as u64,
    );
    put_le_u32(&mut record, offset_of!(RawInodeExtended, i_u), blk);
    put_le_u32(&mut record, offset_of!(RawInodeExtended, i_nlink), 1);
    write_inode_at(disk, nid, &record);
    write_meta_bytes(disk, u64::from(blk), 0, target);
}

/// Row 1, non-UTF-8 dirent name — the crafted name is the two-byte
/// 0xFF/0x80 sequence (invalid UTF-8 in any position), sorted LAST in
/// the root block behind a healthy "tail" sibling. Readdir emits the
/// rows before it, then aborts EIO at the G-N04 precheck; lookup can
/// never match the bytes (no UTF-8 string contains 0xFF), the lossy
/// U+FFFD replacement included — the W-N04 registered drift's
/// fixture-side leg. Both targets are laid real (empty directories).
pub(super) fn fx_name_non_utf8_names() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_empty_dir_at(disk, 2); // "tail"
        lay_empty_dir_at(disk, 4); // the unreachable 0xFF-name target
        lay_root_dirents(
            disk,
            &[
                dirent_record(CHASSIS_ROOT_NID, 48, 2),
                dirent_record(CHASSIS_ROOT_NID, 49, 2),
                dirent_record(2, 51, 2), // "tail" @ [51, 55)
                dirent_record(4, 55, 2), // 0xFF 0x80 @ [55, 57), trailing
            ],
            b"...tail\xFF\x80",
        );
    })
}

/// Row 3, '/'-bearing name — "a/b" as a single dirent name (a healthy
/// mkfs never emits one: the separator is not a name byte). Readdir
/// aborts EIO at the G-N05 slash precheck (which runs BEFORE the
/// UTF-8 decode); the lookup half has no slash gate at all and
/// consumes the name byte-wise like any other.
pub(super) fn fx_name_slash_name() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_empty_dir_at(disk, 2);
        lay_root_dirents(
            disk,
            &[
                dirent_record(CHASSIS_ROOT_NID, 36, 2),
                dirent_record(CHASSIS_ROOT_NID, 37, 2),
                dirent_record(2, 39, 2), // "a/b" @ [39, 42), trailing
            ],
            b"...a/b",
        );
    })
}

/// Row 2, non-UTF-8 symlink target — four LNK children spaced four
/// slots apart (the inline-tail room, see `lay_fast_symlink_at`): the
/// fast arm with an ASCII target ("fastgood" @ nid 2, the control)
/// and with the raw 0xFF/0x80 bytes ("fastbad" @ nid 6), and the slow
/// FLAT_PLAIN arm likewise over whole target blocks ("slowbad" @ nid
/// 10 → block 5, "slowgood" @ nid 14 → block 6). The raw bytes reach
/// `read_link` unjudged (S02-D2) and fail EIO at the shared
/// conversion exit — matrix §3.3 G-N02, both arms, one image.
pub(super) fn fx_name_non_utf8_symlink_target() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_fast_symlink_at(disk, 2, b"ok-target");
        lay_fast_symlink_at(disk, 6, &[0xFF, 0x80]);
        lay_slow_symlink_at(disk, 10, 5, &[0xFE, 0xFF]);
        lay_slow_symlink_at(disk, 14, 6, b"page-target");
        lay_root_dirents(
            disk,
            &[
                dirent_record(CHASSIS_ROOT_NID, 72, 2),
                dirent_record(CHASSIS_ROOT_NID, 73, 2),
                dirent_record(6, 75, 7),  // "fastbad" @ [75, 82)
                dirent_record(2, 82, 7),  // "fastgood" @ [82, 90)
                dirent_record(10, 90, 7), // "slowbad" @ [90, 97)
                dirent_record(14, 97, 7), // "slowgood" @ [97, 105)
            ],
            b"...fastbadfastgoodslowbadslowgood",
        );
    })
}

// ===========================================================================
// T-027 S07: the FX-TIME builder family (S06 §5.5; matrix §1.6 label row
// IMG-CRAFT-TIME serving the §3.1 giant-timestamp bit-pattern row per the
// matrix §8.3 FX-TIME service row). Three named constructors, each a LOCAL
// rewrite of the chassis — and, unlike every family before it, all three
// are ACCEPT faces: no mount gate consumes a time field, so the mount
// stays Ok and the assertion surface is the DECODED TIME itself (the
// inode/mod.rs suite): the D10 three-times-one-source snapshot and the
// statx-exit bit pattern.
//
// AUTO-DECISION: the assertion venue is the module face, not the syscall
// face — `StatxTimestamp` is syscall-private, so the F6 exit is pinned by
// spelling the same conversion expression (`as_secs() as i64`,
// syscall/statx.rs) over the metadata Duration. The expression being
// identical, the "same bit pattern, never saturated, never an error"
// contract is locked at the carrier level. Rejected: reaching into the
// syscall item (not exported to the ktest domain); asserting only the
// Duration and trusting the exit (the exit conversion is exactly what
// the F6 row names as its constraint).
//
// AUTO-DECISION: the compact chassis variant (S06 §3.2 "compact 变体
// 底盘", continuous nids, T-CPT32 seed) lands as an in-place conversion
// of the staged extended chassis — `lay_compact_root` replaces the root
// record and clears the sibling slot — not as a parallel staging path:
// every other chassis byte (the superblock geometry patches, the
// `.`/`..` data block) is form-independent, so a second staging function
// would restate them for zero behavioral difference. Rejected:
// `stage_compact_chassis` as a full twin of `stage_healthy_chassis`
// (duplication with no assertion face).
//
// AUTO-DECISION: the giant values are derived, not hexadecimal-literal —
// the seconds word is `1u64 << 63` (§5.5's "le64 高位置 1" made code)
// and the nsec word is 2_000_000_000 (§5.5's own decimal spelling; the
// value is the form's identity). Rejected: 0x8000... literals (a second
// spelling of the same bits).
// ===========================================================================

/// Lays the chassis root in the COMPACT form — the S06 §3.2 compact
/// chassis variant (continuous nids; the T-CPT32 seed): the seed's root
/// record switched to FLAT_PLAIN over the chassis root data block, sized
/// and linked to the (form-independent) `.`/`..` block — the same
/// four-field treatment the extended chassis gives its root (the risk-1
/// FLAT_PLAIN resolution applies per chassis, not per record form). A
/// compact record spans ONE slot, so the extended seed's second-half
/// bytes behind it are cleared: no compact image carries that cross-form
/// leftover, and the cleared slot keeps the staging self-consistent.
fn lay_compact_root(disk: &ErofsMemoryDisk) {
    let mut root = INODE_CPT_TEMPLATE;
    put_le_u16(
        &mut root,
        offset_of!(RawInodeCompact, i_format),
        chassis_i_format(InodeVersion::Compact, DataLayout::FlatPlain),
    );
    put_le_u32(
        &mut root,
        offset_of!(RawInodeCompact, i_size),
        CHASSIS_ROOT_DIR_SIZE as u32,
    );
    put_le_u32(
        &mut root,
        offset_of!(RawInodeCompact, i_u),
        CHASSIS_ROOT_DATA_BLK,
    );
    put_le_u16(&mut root, offset_of!(RawInodeCompact, i_nlink), 2);
    write_inode_at(disk, CHASSIS_ROOT_NID, &root);
    let iloc = inode_location(&staged_super_block(disk), CHASSIS_ROOT_NID) as usize;
    let cleared = [0u8; size_of::<RawInodeExtended>() - size_of::<RawInodeCompact>()];
    disk.stage_bytes(iloc + size_of::<RawInodeCompact>(), &cleared);
}

/// Row 1, giant seconds — the extended root's `i_mtime` set to
/// 1 << 63 (§5.5 "le64 高位置 1"): the le64 domain carries through the
/// `Duration` decode unchanged (F6), and the statx exit's `as i64`
/// truncation emits the SAME BIT PATTERN as a negative tv_sec —
/// saturation or an error exit would drift the bit-pattern-level parity
/// (matrix §3.1 giant-timestamp row). Expected mount Ok; the
/// inode/mod.rs suite pins the decoded snapshot and the exit pattern.
pub(super) fn fx_time_giant_seconds() -> ErofsFixture {
    rewritten_chassis(|disk| {
        patch_root_inode(disk, |root| {
            put_le_u64(root, offset_of!(RawInodeExtended, i_mtime), 1u64 << 63);
        });
    })
}

/// Row 2, giant nsec — `i_mtime_nsec` = 2_000_000_000 (§5.5's spelling;
/// ≥ 1e9, the malformed-images-only domain). aster normalizes through
/// `duration_from_parts` into `Duration::new(2, 0)` — the same time
/// quantity spelled as the legal timespec — while Linux passes the raw
/// pair through (an illegal-but-verbatim tv_nsec of 2e9, inside
/// [1e9, 2^31)); the F6n REGISTERED DRIFT (T-011 §4 example
/// semantics), asserted at aster's normalized value. Expected mount Ok.
pub(super) fn fx_time_giant_nsec() -> ErofsFixture {
    rewritten_chassis(|disk| {
        patch_root_inode(disk, |root| {
            put_le_u32(
                root,
                offset_of!(RawInodeExtended, i_mtime_nsec),
                2_000_000_000,
            );
        });
    })
}

/// Row 3, the compact ctime synthesis path — the compact chassis
/// (`lay_compact_root`) plus the family's ONE superblock patch:
/// `build_time` = 1 << 63. A compact record carries no time field; all
/// three metadata times synthesize from `sb.build_time` (D10/G-M17),
/// which makes this image the compact half of the giant-seconds
/// bit-pattern assertion — its only reachable host on a compact image
/// (§5.5's "标签行未列,非虚构" note). Expected mount Ok (no gate
/// consumes build_time).
pub(super) fn fx_time_compact_ctime() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_compact_root(disk);
        let mut sb = staged_super_block_record(disk);
        put_le_u64(&mut sb, offset_of!(RawSuperBlock, build_time), 1u64 << 63);
        write_super_block(disk, &sb);
    })
}

// ===========================================================================
// T-027 S08: the FX-INODE builder family (S06 §5.2; matrix §1.6 label
// row IMG-CRAFT-INODE serving the §3.1 rows — the decode guard family,
// the extended cross-block splice D4a, and the kind × datalayout
// acceptance crosses). Eight named constructors laying crafted CHILD
// inode records: no mount gate reads a child slot, so every form
// mounts Ok and the guards fire at `iget` — the S06 §4.3 "mount-Ok
// forms ... do iget/lookup follow-up assertions" spelling; the suite
// lives in `inode/mod.rs` (the D1 host rule). This slice lands the
// §5.2 rows 1–6 and 9; the data-defense rows (exact-boundary
// full-block inline, cross-block slow LNK, the giant-i_size truncation
// angle — rows 7/8/11) are S09's and the compressed-special row 10 is
// S10/S11's.
//
// AUTO-DECISION: the RD1 slot pair lands as TWO fixtures — nid 127's
// 64-byte record spans slots 127+128 ([8160, 8224), its second half
// in block 2) while nid 126's spans slots 126+127 ([8128, 8192),
// ending exactly at the boundary), so the two records OVERLAP on
// slot 127 and structurally cannot share one image; §5.2's 「两槽都
// 造」 is thus one builder per slot. Rejected: one image carrying
// both records (slot collision); a nid-127-only family (the boundary
// corner is RD1's own correction — the §1.6 label row's "ofs=4032"
// misreading is exactly what the nid 126 form disproves).
//
// AUTO-DECISION: the RD1 records are REG × FLAT_PLAIN children with
// distinctive `i_size` (offset 8, inside the record's first 32-byte
// half) and `i_mtime` seconds (offset 32, inside the second half)
// values — a zero-content data block is legal regular-file content,
// so the carrier stays inside the healthy-mkfs-producible form, and a
// witness in EACH half pins the splice's byte fidelity (a misaligned
// or re-based read would decode the second-half mtime wrong).
// Rejected: the empty-directory child (the `lay_empty_dir_at` shape,
// size 0 — a zero-filled slot would decode identically, weakening
// the pin to a tautology).
//
// AUTO-DECISION: the I3 pattern is derived from the guard's own mask
// (`!I_ALL & 0x00FF` = bits 4–7), not §5.2's verbatim 0xF0F example —
// the example's low nibble corrupts the version/datalayout bits too,
// tripping I3 AND I4 with the same shared errno (both EOPNOTSUPP) and
// muddying which door the form pins; the derived pattern keeps the
// seed's low nibble so I3 is the only door that fires. Rejected:
// spelling 0x0F0F (a same-errno double trip adds no distinguishable
// face — unlike the FX-SB V5+V6 cross, whose two errnos differ).
// ===========================================================================

/// Lays the extended seed as a child record at `nid`, with `patch`
/// applied — the FX-INODE staging face: the seed carries every
/// healthy field, the patch rewrites exactly the fields its form
/// names (the `patch_root_inode` read-patch-restage discipline,
/// applied to a freshly-laid record instead of the staged root).
fn lay_extended_child_at(disk: &ErofsMemoryDisk, nid: u64, patch: impl FnOnce(&mut [u8; 64])) {
    let mut record = INODE_EXT_TEMPLATE;
    patch(&mut record);
    write_inode_at(disk, nid, &record);
}

/// The RD1 slot pair (S06 §5.2 / T-011 §5.1), derived from the
/// chassis geometry through the slot arithmetic — never spelled as
/// bare nids. A 4k block holds 128 slots; the unique cross-block
/// record starts at the block's LAST slot (nid ≡ 127 mod 128, offset
/// bs − 32 = 4064: the 64-byte read crosses into block 2), and the
/// exact-boundary corner one slot earlier (nid ≡ 126, offset 4032:
/// 4032 + 64 = 4096 ends AT the boundary, no crossing).
pub(super) const RD1_CROSS_BLOCK_NID: u64 = (CHASSIS_BLOCK_SIZE >> ISLOT_BITS) as u64 - 1;
/// The exact-boundary companion slot of [`RD1_CROSS_BLOCK_NID`] — the
/// corner the T-011 RD1 correction rescued from the §1.6 label row's
/// "ofs=4032" cross-block misreading.
pub(super) const RD1_EXACT_BOUNDARY_NID: u64 = (CHASSIS_BLOCK_SIZE >> ISLOT_BITS) as u64 - 2;

/// The lowest chunk-format bit outside `CHUNK_FORMAT_ALL` (0x3F →
/// 0x40), derived from the production mask — the same shape as
/// `unknown_incompat_bit` above, feeding the I10 forms.
fn unknown_chunk_format_bit() -> u16 {
    CHUNK_FORMAT_ALL.next_power_of_two()
}

/// Switches an extended seed record into a CHUNK_BASED child carrying
/// `chunkformat` in the low half of `i_u` (the D9 second reading),
/// optionally switching the S_IFMT type segment — the staging face
/// shared by the row 5 chunk-format family and the row 9 acceptance
/// crosses.
fn patch_chunk_child(record: &mut [u8; 64], chunkformat: u16, type_segment: Option<u16>) {
    put_le_u16(
        record,
        offset_of!(RawInodeExtended, i_format),
        chassis_i_format(InodeVersion::Extended, DataLayout::ChunkBased),
    );
    if let Some(segment) = type_segment {
        let mode_off = offset_of!(RawInodeExtended, i_mode);
        let mode = get_le_u16(record, mode_off);
        put_le_u16(record, mode_off, (mode & !S_IFMT) | segment);
    }
    put_le_u32(
        record,
        offset_of!(RawInodeExtended, i_u),
        u32::from(chunkformat),
    );
}

/// Switches an extended seed record into the healthy REG × FLAT_PLAIN
/// child the RD1 fixtures decode: datalayout FLAT_PLAIN over a free
/// data block (all-zero content — legal regular-file bytes), type REG
/// keeping the seed's permission bits, and the two splice witnesses —
/// `size` (offset 8, first 32-byte half) and `mtime` seconds
/// (offset 32, second half).
fn patch_rd1_reg_record(record: &mut [u8; 64], size: u64, mtime_secs: u64) {
    put_le_u16(
        record,
        offset_of!(RawInodeExtended, i_format),
        chassis_i_format(InodeVersion::Extended, DataLayout::FlatPlain),
    );
    let mode_off = offset_of!(RawInodeExtended, i_mode);
    let mode = get_le_u16(record, mode_off);
    put_le_u16(record, mode_off, (mode & !S_IFMT) | S_IFREG);
    put_le_u64(record, offset_of!(RawInodeExtended, i_size), size);
    // Block 9: behind the meta area and the root data block — a free
    // chassis block (never read at iget; the address just has to be
    // in-device legal).
    put_le_u32(record, offset_of!(RawInodeExtended, i_u), 9);
    put_le_u32(record, offset_of!(RawInodeExtended, i_nlink), 1);
    put_le_u64(record, offset_of!(RawInodeExtended, i_mtime), mtime_secs);
}

/// Row 1 (I3) — i_format high bits: bits 4–7 above `I_ALL`, the
/// version/datalayout nibble untouched (the section note: the derived
/// isolated pattern, not §5.2's 0xF0F). Expected EOPNOTSUPP at the
/// entry's one-shot validation (matrix §3.1 guard row) — the 2-byte
/// pre-read is the form's whole read set.
pub(super) fn fx_inode_ifmt_high_bits() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_extended_child_at(disk, 2, |record| {
            let off = offset_of!(RawInodeExtended, i_format);
            let ifmt = get_le_u16(record, off);
            put_le_u16(record, off, ifmt | (!I_ALL & 0x00FF));
        });
    })
}

/// Row 2 (I4) — a reserved datalayout: the discriminant set to
/// `INODE_DATALAYOUT_MAX` (5, the first reserved value, derived from
/// the production sentinel the guard compares against; the version
/// bit stays extended). Expected EOPNOTSUPP, strictly after I3's
/// mask check passed.
pub(super) fn fx_inode_datalayout_reserved() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_extended_child_at(disk, 2, |record| {
            put_le_u16(
                record,
                offset_of!(RawInodeExtended, i_format),
                ((INODE_DATALAYOUT_MAX as u16) << I_DATALAYOUT_BIT)
                    | ((InodeVersion::Extended as u16) << I_VERSION_BIT),
            );
        });
    })
}

/// Row 3 (I7) — a negative i_size: the le64 domain's high bit set
/// (`1 << 63`, the ≥ 2^63 domain), extended-only reachable — the
/// compact le32 domain is structurally non-negative, so no compact
/// twin is built (G7: the unreachable guard is not fabricated).
/// Expected EUCLEAN.
pub(super) fn fx_inode_negative_size() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_extended_child_at(disk, 2, |record| {
            put_le_u64(record, offset_of!(RawInodeExtended, i_size), 1u64 << 63);
        });
    })
}

/// Row 4 (I8) — bogus i_mode, both spelled corners in one image: nid 2
/// carries 0x0000 (the all-zero word — the matrix row's must-test
/// corner: a `0 → File` special-case misjudgement would swallow
/// exactly this form) and nid 4 carries 0x3000 (an S_IFMT segment
/// outside the seven kinds). Every other seed field stays healthy.
/// Both igets expected EUCLEAN — the guard fires before any payload
/// assembly (the one-image precedent: the d_type 8/255 form).
pub(super) fn fx_inode_bogus_mode() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_extended_child_at(disk, 2, |record| {
            put_le_u16(record, offset_of!(RawInodeExtended, i_mode), 0x0000);
        });
        lay_extended_child_at(disk, 4, |record| {
            put_le_u16(record, offset_of!(RawInodeExtended, i_mode), 0x3000);
        });
    })
}

/// Row 5 (I10 / G5) — the chunk-format family on DIR × CHUNK records,
/// both halves in one image: nid 2 carries an unknown chunk-format
/// bit (derived: strictly above `CHUNK_FORMAT_ALL`, hence outside it)
/// — expected EOPNOTSUPP at the I10 guard, before the `Chunked`
/// materialization; nid 4 carries the INDEXES variant (a known bit) —
/// expected iget Ok, the G5 acceptance face: the 5-bit blkbits domain
/// carries with no upper-bound check, and the INDEXES flag is a legal
/// chunk-unit switch.
pub(super) fn fx_inode_chunk_format() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_extended_child_at(disk, 2, |record| {
            patch_chunk_child(record, unknown_chunk_format_bit(), None);
        });
        lay_extended_child_at(disk, 4, |record| {
            patch_chunk_child(record, CHUNK_FORMAT_INDEXES, None);
        });
    })
}

/// Row 6, cross-block leg (D4a / RD1) — a healthy REG × FLAT_PLAIN
/// record at nid 127: the 64-byte read spans [8160, 8224), splicing
/// block 1's last slot with block 2's first (aster's single-point
/// read, RD0 — no boundary test, no two-segment splice). Expected
/// iget Ok with every staged field decoded byte-exact: the two
/// half-witnesses (i_size @8 / i_mtime @32) pin the splice fidelity
/// (matrix §3.1 D4a row: 拼接解码成功).
pub(super) fn fx_inode_cross_block_slot() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_extended_child_at(disk, RD1_CROSS_BLOCK_NID, |record| {
            patch_rd1_reg_record(record, 100, 1_700_000_000);
        });
    })
}

/// Row 6, exact-boundary leg — the same healthy record at nid 126:
/// [8128, 8192) ends exactly at the block boundary (4032 + 64 = 4096),
/// NOT a cross-block read (the §1.6 label row's "ofs=4032" reading,
/// corrected by T-011 RD1 — the corner this fixture disproves).
/// Expected iget Ok with identical treatment (the single-form read
/// knows no block boundaries); its own witness pair (size 200 /
/// mtime 1.6e9, distinct from the cross leg's) proves the read
/// fetched THIS record, not a neighbor's bytes.
pub(super) fn fx_inode_exact_boundary_slot() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_extended_child_at(disk, RD1_EXACT_BOUNDARY_NID, |record| {
            patch_rd1_reg_record(record, 200, 1_600_000_000);
        });
    })
}

/// Row 9 (组合照收) — the kind × datalayout acceptance crosses, three
/// children in one image: nid 2 DIR × CHUNK with a plain chunk format
/// (blkbits 0, the 4-byte block-map variant) and nid 4 FIFO × CHUNK
/// with the INDEXES variant — both ACCEPTED as-is (the D9 cross-cut
/// never sits inside a kind branch; the payloads land DataBacked over
/// the chunk geometry and Fifo respectively) — plus nid 6 FIFO ×
/// CHUNK with an unknown chunk bit: the I10 door stays reachable on
/// the cross cell too (matrix §3.1 组合照收行), expected EOPNOTSUPP.
pub(super) fn fx_inode_kind_layout_cross() -> ErofsFixture {
    rewritten_chassis(|disk| {
        lay_extended_child_at(disk, 2, |record| {
            patch_chunk_child(record, 0, None);
        });
        lay_extended_child_at(disk, 4, |record| {
            patch_chunk_child(record, CHUNK_FORMAT_INDEXES, Some(S_IFIFO));
        });
        lay_extended_child_at(disk, 6, |record| {
            patch_chunk_child(record, unknown_chunk_format_bit(), Some(S_IFIFO));
        });
    })
}

// ===========================================================================
// T-027 S09: the FX-INODE data-defense family (S06 §5.2 rows 7/8/11,
// matrix §1.6 label row IMG-CRAFT-INODE serving the §4.1/§4.2 read
// rows and the §4.3 INLINE row). Three named constructors whose
// crafted CHILD records pass every mount and iget gate — the
// defenses fire on the READ path (map_blocks through the page
// cache). The suites live in `inode/data.rs` and `inode/symlink.rs`
// (the D1 host rule): this slice is the first FX family whose
// assertion surface drives the full mounted chain (chassis →
// `Erofs::open` → iget → page cache → map_blocks) through the
// read API.
//
// AUTO-DECISION: the giant-size assertion surface = first/mid-page
// content fidelity (the le64 domain carried whole — a u32 collapse
// of size would shrink npages and the first page's valid window, so
// the full-page pattern read is the distinguishing face) plus the
// tail page's device-bound EINVAL (RD2②: the tail's data block 5 +
// 2^20 lies past the 32-block device; aster EINVAL vs Linux EIO,
// the registered drift value). The §4.2 zero-fill half is NOT
// reachable on a mounted crafted image — the tail page's data block
// is necessarily out of device — and stays with its real hosts (the
// initramfs mmap rows; the T-025 S05-IF-2 direct-construction
// vector). Rejected: shrinking the size to keep the tail in-device
// (breaks the T-013 §11 value 2^32+100); asserting the request log
// on the data.rs side (implementation detail, no matrix row).
//
// AUTO-DECISION: the expected payload bytes single-source through
// the exported `chassis_nonzero_pattern` formula — staged by the
// builders, re-derived by the suites. Rejected: a per-suite formula
// copy (a second truth); a read-back oracle over `disk.segment()`
// (would restate the iloc geometry these builders already own).
// ===========================================================================

/// The deterministic nonzero payload byte at inline offset `i` —
/// always in [1, 255], so any zero-fill mixing into an asserted
/// window fails loudly. Staged by the S09 builders below; re-derived
/// by the data.rs suites as the expectation (the single source).
pub(super) fn chassis_nonzero_pattern(i: usize) -> u8 {
    (i % 255) as u8 + 1
}

/// Stages one full block of the pattern at block `blk`.
fn stage_nonzero_pattern_block(disk: &ErofsMemoryDisk, blk: u32) {
    let payload: Vec<u8> = (0..CHASSIS_BLOCK_SIZE)
        .map(chassis_nonzero_pattern)
        .collect();
    disk.stage_bytes(blk as usize * CHASSIS_BLOCK_SIZE, &payload);
}

/// Row 11 — the giant FLAT_PLAIN i_size truncation angle: nid 2 is a
/// healthy REG × FLAT_PLAIN child with i_size = 2^32 + 100 (the
/// T-013 §11 fixture value; an le64-only domain — compact's le32
/// cannot express it, G7). Data blocks 5 and 10 (free chassis
/// blocks behind the root data block 4) carry the pattern: page 0
/// maps block 5, page la = 5·bs maps block 10 (the u64 full-domain
/// pa arithmetic), and the tail page (la = 2^32) would read block
/// 5 + 2^20 — past the 32-block device, the RD2② face. i_u keeps a
/// real data block: the crafted image stays a legal flat mapping of
/// a (device-oversized) regular file.
pub(super) fn fx_inode_giant_i_size() -> ErofsFixture {
    rewritten_chassis(|disk| {
        stage_nonzero_pattern_block(disk, 5);
        stage_nonzero_pattern_block(disk, 10);
        lay_extended_child_at(disk, 2, |record| {
            put_le_u16(
                record,
                offset_of!(RawInodeExtended, i_format),
                chassis_i_format(InodeVersion::Extended, DataLayout::FlatPlain),
            );
            let mode_off = offset_of!(RawInodeExtended, i_mode);
            let mode = get_le_u16(record, mode_off);
            put_le_u16(record, mode_off, (mode & !S_IFMT) | S_IFREG);
            put_le_u64(
                record,
                offset_of!(RawInodeExtended, i_size),
                (1u64 << 32) + 100,
            );
            put_le_u32(record, offset_of!(RawInodeExtended, i_u), 5);
            put_le_u32(record, offset_of!(RawInodeExtended, i_nlink), 1);
        });
    })
}

/// Row 7 — the exact-boundary slot with a full-block inline payload:
/// nid 126's record ends exactly at the block boundary (iloc 8128 +
/// 64 = 8192), so the FLAT_INLINE payload starts AT the block-2 base
/// with i_size == bs (4096): the cross-block guard's exact-boundary
/// PASS corner (blkoff(m_pa) + m_plen == bs, here 0 + 4096 — the
/// "i_size 恰占满 inode 尾至块界" reading of §5.2). The payload is
/// the whole pattern block 2 — the exact-boundary slot geometry puts
/// the record's last byte on the block edge and the payload start on
/// the next block's base (the record itself stays inside block 1);
/// i_u keeps the seed's 0xFFFFFFFF, the FlatInline convention of an
/// inline-only file (the C1 root's own bytes, consumed by no MAPPED
/// arm at this size).
pub(super) fn fx_inode_exact_boundary_full_inline() -> ErofsFixture {
    rewritten_chassis(|disk| {
        stage_nonzero_pattern_block(disk, 2);
        lay_extended_child_at(disk, RD1_EXACT_BOUNDARY_NID, |record| {
            put_le_u16(
                record,
                offset_of!(RawInodeExtended, i_format),
                chassis_i_format(InodeVersion::Extended, DataLayout::FlatInline),
            );
            let mode_off = offset_of!(RawInodeExtended, i_mode);
            let mode = get_le_u16(record, mode_off);
            put_le_u16(record, mode_off, (mode & !S_IFMT) | S_IFREG);
            put_le_u64(
                record,
                offset_of!(RawInodeExtended, i_size),
                CHASSIS_BLOCK_SIZE as u64,
            );
            put_le_u32(record, offset_of!(RawInodeExtended, i_nlink), 1);
        });
    })
}

/// Row 8 — the cross-block slot × slow LNK: nid 127's record spans
/// [8160, 8224) (the RD1 cross-block slot), and the child is an LNK ×
/// FLAT_INLINE whose size is exactly ONE PAST the fast-criterion
/// boundary — derived, not spelled: `round_up(inline_start, bs) −
/// inline_start + 1` with inline_start = 8224, i.e. 4065. Both
/// boundaries trip on the same byte: the criterion sends the payload
/// down the slow DataBacked arm (8224 + 4065 > 12288), and the
/// map-layer guard rejects the inline tail before any fetch (blkoff
/// 32 + 4065 > 4096) — production EUCLEAN (matrix §4.3 "跨块 →
/// EUCLEAN"), which the framework VmIo boundary folds to EINVAL (the
/// registered drift, T-025 S06 §3; the suites assert the aster
/// value). No payload is staged: the guard fires first.
pub(super) fn fx_inode_cross_block_slow_symlink() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let sb = staged_super_block(disk);
        let inline_start =
            inode_location(&sb, RD1_CROSS_BLOCK_NID) + size_of::<RawInodeExtended>() as u64;
        let bs = CHASSIS_BLOCK_SIZE as u64;
        let size = inline_start.div_ceil(bs) * bs - inline_start + 1;
        lay_extended_child_at(disk, RD1_CROSS_BLOCK_NID, |record| {
            put_le_u16(
                record,
                offset_of!(RawInodeExtended, i_format),
                chassis_i_format(InodeVersion::Extended, DataLayout::FlatInline),
            );
            let mode_off = offset_of!(RawInodeExtended, i_mode);
            let mode = get_le_u16(record, mode_off);
            put_le_u16(record, mode_off, (mode & !S_IFMT) | S_IFLNK);
            put_le_u64(record, offset_of!(RawInodeExtended, i_size), size);
            put_le_u32(record, offset_of!(RawInodeExtended, i_nlink), 1);
        });
    })
}

// ===========================================================================
// T-027 S10: the FX-COMP mount-half family and the algs=0 comp chassis
// (S06 §5.7; matrix §1.6 label row IMG-CRAFT-COMP serving the §5.1 rows
// ②③④⑤ and the §5.3 per-bit row). This slice = the MOUNT half: the u1
// door forms (rows 1/3, the V9 rejection), the algs=0 chassis with
// COMPR_CFGS / each known compression incompat bit set one at a time
// (rows 2/8, the G-Z03 parsed-but-ignored acceptance face), and row 6
// (fragments + packed compressed) consumed as the S04 G-M15 material's
// second assertion face — no builder of its own (共同约束 10: 素材落
// S04, 断言 S10 复用). The iget half (rows 4/5/7: compressed-datalayout
// inodes, the compressed-special accounting, the dual-malformed mount-Ok
// form) is S11's, over the same chassis. The suite lives in `fs.rs`
// (the D1 host rule — the V9 door and the Step-4/5 doors are
// `read_superblock`/`Erofs::open` business).
//
// AUTO-DECISION: the algs=0 comp chassis — the "comp 畸形底盘单源" of
// the S10/S11 split — lands as ONE parameterized private constructor,
// `comp_chassis(bits, rewrite)`: healthy chassis (u1 already 0), the
// per-form `rewrite`, then `bits` ORed into feature_incompat as the
// LAST staging step so the checksummed finish covers the final record
// (the fx_sb_packed_compressed_payload ordering: inodes first,
// superblock last). The cfg area COMPR_CFGS nominally announces is NOT
// staged — aster's layer 2 is shelved (tier A, G-Z01): no cfg reader
// exists, per §5.7②'s own "cfg 区不铺". Rejected: per-form open-coded
// superblock patches (the single source would dissolve into copy-paste
// across S10/S11); a chainable fixture (D5 already rejected chains).
//
// AUTO-DECISION: the §5.3 per-bit row lands as FOUR new constructors
// plus the row-2 chassis leg — the 0x2 form IS the algs=0+COMPR_CFGS
// chassis (u1=0 ∧ incompat=0x2, byte-identical), so one constructor
// carries both rows' assertion faces (the S06 FX-NAME dual-consumption
// precedent: a form's builder lives in exactly one family; the second
// consumption joins through the assertion face, in `fs.rs`). Rejected:
// a fifth near-identical 0x2 constructor (two names over the same
// bytes confuses the grep-able form list); collapsing the five legs
// into one parameterized call site (D5: named constructors ARE the
// form list). CHUNKED_FILE (0x4) has no leg — §5.3's own list is the
// five compression-half bits only.
//
// AUTO-DECISION: the u1 forms (rows 1/3) patch the PLAIN healthy
// chassis, not the comp chassis — their malformation is u1≠0 itself
// (the V9 door), and the comp constructor's contract keeps u1 at 0;
// routing them through it would fight the constructor's own invariant.
// The two u1 values are §5.7's own spellings (0x0003/0x0010): aster
// parses no algs bits — V9 is a plain u1≠0 test — so no production
// constant exists to derive them from (the S04 extslots 184/185
// precedent: values that ARE the form's identity get spelled).
// ===========================================================================

/// The algs=0 comp chassis — the single source of the FX-COMP forms
/// (S06 §5.7's "algs=0 畸形底盘", the S10/S11 cross-consumption base):
/// the healthy chassis (u1 already 0 = algs 0), the per-form
/// `rewrite`, then `bits` ORed into feature_incompat as the last
/// staging step through the checksummed writer. The COMPR_CFGS cfg
/// area is not staged (tier A has no layer-2 reader, §5.7②'s own
/// "cfg 区不铺"). S11's iget-half builders re-consume this
/// constructor with their child-inode rewrites in `rewrite`.
fn comp_chassis(bits: FeatureIncompatSet, rewrite: impl FnOnce(&ErofsMemoryDisk)) -> ErofsFixture {
    rewritten_chassis(|disk| {
        rewrite(disk);
        let mut sb = staged_super_block_record(disk);
        let off = offset_of!(RawSuperBlock, feature_incompat);
        let incompat = get_le_u32(&sb, off);
        put_le_u32(&mut sb, off, incompat | bits.bits());
        write_super_block(disk, &sb);
    })
}

/// Row 1 (§5.1③) — u1 ≠ 0 with NO COMPR_CFGS bit: the plain chassis
/// (incompat stays 0 — "不置 0x2" is the untouched chassis value) with
/// u1 = 0x0003 (the LZ4|LZMA algs pair, §5.7's own spelling). Expected
/// EOPNOTSUPP at the V9 door — the OVER-REJECTION face: the mainline
/// stub is deliberately a plain u1≠0 test that does not consult
/// COMPR_CFGS (G-Z03), and the matrix row pins it as-is ("过拒面断言,
/// 主列既有取舍勿「修正」") — no tightening, no cross-check.
pub(super) fn fx_comp_u1_without_cfgs() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        put_le_u16(&mut sb, offset_of!(RawSuperBlock, u1), 0x0003);
        write_super_block(disk, &sb);
    })
}

/// Row 3 (§5.1④) — algs carrying an unknown bit: u1 = 0x0010 (bit 4,
/// above the four known algorithm bits LZ4/LZMA/DEFLATE/ZSTD; §5.7's
/// own spelling). Expected EOPNOTSUPP — the same V9 door as row 1
/// (both are u1≠0; layer 1 is errno-blind to WHICH bits are set — the
/// algs domain is layer-2 business that tier A does not have). The
/// distinct value keeps the form separately grep-able, not separately
/// errno-ed.
pub(super) fn fx_comp_algs_unknown_bit() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut sb = staged_super_block_record(disk);
        put_le_u16(&mut sb, offset_of!(RawSuperBlock, u1), 0x0010);
        write_super_block(disk, &sb);
    })
}

/// Row 2 (§5.1②, mount half) — algs=0 with COMPR_CFGS set: the comp
/// chassis with the one bit (u1 stays the chassis 0; the cfg area is
/// not staged). Expected mount Ok: layer 1 passes (u1 == 0) and no cfg
/// consumption exists — the G-M11 "COMPR_CFGS ∧ u1=0" counterpart
/// synthesized on the crafted side (a healthy mkfs never produces it;
/// the EROFS-COMP initramfs image carries u1≠0 and fails layer 1).
/// The compressed-inode I12 rejection over this chassis is S11's.
/// Dual service: this same image is the §5.3 per-bit row's 0x2 leg.
pub(super) fn fx_comp_algs_zero_with_cfgs() -> ErofsFixture {
    comp_chassis(FeatureIncompatSet::COMPR_CFGS, |_| {})
}

/// Row 8 (§5.3), ZERO_PADDING leg (0x1) — the decompressor's
/// zero-padding variant, a compression-domain bit with no tier-A
/// consumer. Expected mount Ok: parsed into the feature set, never
/// acted on (G-Z03).
pub(super) fn fx_comp_incompat_zero_padding() -> ErofsFixture {
    comp_chassis(FeatureIncompatSet::ZERO_PADDING, |_| {})
}

/// Row 8 (§5.3), DEVICE_TABLE leg (0x8, alias COMPR_HEAD2) — the
/// dual-name bit's compression half. The bit's DEVICE_TABLE behavior
/// (the V10 scan reading `extra_devices`) is §2.2/G-M14 business; on
/// the chassis (extra_devices = 0) the scan takes the single-device
/// early return. This leg pins only the V6 acceptance: a known bit is
/// not rejected as unknown. Expected mount Ok.
pub(super) fn fx_comp_incompat_device_table() -> ErofsFixture {
    comp_chassis(FeatureIncompatSet::DEVICE_TABLE, |_| {})
}

/// Row 8 (§5.3), ZTAILPACKING leg (0x10) — a version gate with no
/// other v6.12 consumer. Expected mount Ok (parsed but ignored).
pub(super) fn fx_comp_incompat_ztailpacking() -> ErofsFixture {
    comp_chassis(FeatureIncompatSet::ZTAILPACKING, |_| {})
}

/// Row 8 (§5.3), FRAGMENTS leg (0x20, alias DEDUPE) — the dual-name
/// bit's compression half. The FRAGMENTS behavior (the Step-4 F10
/// packed door) is §2.2/G-M15 business; with the chassis packed_nid
/// = 0 the door's second conjunct fails open and no iget runs. This
/// leg pins only the V6 acceptance. Expected mount Ok.
pub(super) fn fx_comp_incompat_fragments() -> ErofsFixture {
    comp_chassis(FeatureIncompatSet::FRAGMENTS, |_| {})
}

// ===========================================================================
// T-027 S11: the FX-COMP iget-half family (S06 §5.7 rows 4/5/7; matrix
// §5.1 ⑦⑧⑥ + the §5.2 G-Z02 dual-caliber accounting + the S06 §5.2
// compressed-special row). Rows 4/5 lay compressed-datalayout children
// over the row-2 algs=0 chassis (`comp_chassis(COMPR_CFGS, …)` — the
// S10 single-source contract: "S11's iget-half builders re-consume
// this constructor"); the iget assertions live in `inode/mod.rs` (the
// D1 host rule — I12 fires at `InodePayload::new`, the st_blocks
// accounting at the decode). Row 7 (the dual-malformed mount-Ok form)
// lays its packed inode over the FRAGMENTS chassis; the mount-Ok
// assertion lives in `fs.rs` (the Step-4 F10 door is `Erofs::open`
// business).
//
// AUTO-DECISION: rows 4/5 ride the COMPR_CFGS leg of the algs=0
// chassis. Neither the I12 gate nor the nblks accounting consults any
// superblock bit, so any u1=0 chassis realizes the two rows;
// COMPR_CFGS is §5.7's own spelling of "algs=0 畸形底盘" and the S10
// §5 fact pinned the iget half to this exact constructor. Rejected:
// the plain incompat=0 chassis (u1=0 ∧ no bit is not the §5.7 chassis
// form, and it would fork the single source); the FRAGMENTS chassis
// (that bit is row 7's own identity).
//
// AUTO-DECISION: the compressed datalayout value spans {1, 3} across
// the legs — row 4's DIR leg and row 5's SOCK leg carry
// CompressedCompact, the rest CompressedFull. `is_data_compressed()`
// treats the pair identically, so spanning both keeps each row
// self-contained without extra children. Rejected: one value for all
// legs (leaves 3 unexercised inside the family); the full {1,3} ×
// kind matrix (8+ cells — beyond the rows' face, 加严).
//
// AUTO-DECISION: row 5's nblks/size pairs are picked so every leg's
// compressed caliber DIFFERS from its round_up(i_size) fallback, in
// both directions (5→40 vs 0, 9→72 vs 8, 1→8 vs 16, 3→24 vs 0) — the
// caliber distinction IS the §5.2 assertion ("非 round_up(i_size)
// 口径, 防沿用 ext2 样板口径漂移"); the nblks=0 corner rides the
// same image (the fx_inode_bogus_mode two-corners-in-one-image
// precedent). Rejected: a separate builder for the corner (the row's
// own 边角; the S06 form list stays 3).
// ===========================================================================

/// Switches an extended seed record into a COMPRESSED child — the
/// datalayout word rewritten, the S_IFMT segment optionally switched
/// (`None` keeps the seed's DIR segment, the `patch_chunk_child`
/// shape) — leaving i_size/i_u at the seed bytes: the row-4 rejection
/// forms need no more (the I12 arm-head gate fires before any payload
/// consumption, the S04 packed-material discipline).
fn patch_compressed_child(record: &mut [u8; 64], layout: DataLayout, type_segment: Option<u16>) {
    put_le_u16(
        record,
        offset_of!(RawInodeExtended, i_format),
        chassis_i_format(InodeVersion::Extended, layout),
    );
    if let Some(segment) = type_segment {
        let mode_off = offset_of!(RawInodeExtended, i_mode);
        let mode = get_le_u16(record, mode_off);
        put_le_u16(record, mode_off, (mode & !S_IFMT) | segment);
    }
}

/// The row-5 staging face: a compressed special-file child with
/// explicit accounting knobs — `nblks` lands in `i_u` (the D9 second
/// reading; the CHR/BLK rdev decode reads the SAME word — the i_u
/// double-read the acceptance row pins) and `size` in `i_size` (the
/// round_up fallback caliber's input).
fn patch_compressed_special(
    record: &mut [u8; 64],
    layout: DataLayout,
    type_segment: u16,
    size: u64,
    nblks: u32,
) {
    patch_compressed_child(record, layout, Some(type_segment));
    put_le_u64(record, offset_of!(RawInodeExtended, i_size), size);
    put_le_u32(record, offset_of!(RawInodeExtended, i_u), nblks);
    put_le_u32(record, offset_of!(RawInodeExtended, i_nlink), 1);
}

/// Row 4 (§5.1⑦) — the three iget-gated kinds over the algs=0
/// chassis: REG (nid 2, CompressedFull), DIR (nid 4, CompressedCompact,
/// the seed's own DIR segment kept), LNK (nid 6, CompressedFull),
/// i_size/i_u left at the seed bytes. Every iget fails at the I12
/// arm-head gate — the errno-SOURCE face (matrix ⑦: through the upper
/// layers the same failure surfaces as an ENOENT/EIO-class error; the
/// row pins the source itself). Suite: `inode/mod.rs`.
pub(super) fn fx_comp_compressed_reg_dir_lnk() -> ErofsFixture {
    comp_chassis(FeatureIncompatSet::COMPR_CFGS, |disk| {
        lay_extended_child_at(disk, 2, |record| {
            patch_compressed_child(record, DataLayout::CompressedFull, Some(S_IFREG));
        });
        lay_extended_child_at(disk, 4, |record| {
            patch_compressed_child(record, DataLayout::CompressedCompact, None);
        });
        lay_extended_child_at(disk, 6, |record| {
            patch_compressed_child(record, DataLayout::CompressedFull, Some(S_IFLNK));
        });
    })
}

/// Row 5 (§5.1⑧ + §5.2 G-Z02; the S06 §5.2 compressed-special row) —
/// four compressed special children plus the nblks=0 corner, one
/// image: CHR nid 2 (nblks 5, size 0), BLK nid 4 (9, 100), FIFO nid 6
/// (1, 5000 — the inverted corner: the compressed caliber lands BELOW
/// the fallback), SOCK nid 8 (CompressedCompact, 3, 0), and FIFO nid
/// 10 (nblks 0, size 5000 — the generic-caliber corner). iget
/// succeeds on every slot (the special arms never touch I12), and
/// st_blocks follows the compressed caliber. Suite: `inode/mod.rs`
/// (the W-N01 stx_attributes face is the initramfs-side registered
/// difference, not re-asserted there).
pub(super) fn fx_comp_compressed_special_files() -> ErofsFixture {
    comp_chassis(FeatureIncompatSet::COMPR_CFGS, |disk| {
        lay_extended_child_at(disk, 2, |record| {
            patch_compressed_special(record, DataLayout::CompressedFull, S_IFCHR, 0, 5);
        });
        lay_extended_child_at(disk, 4, |record| {
            patch_compressed_special(record, DataLayout::CompressedFull, S_IFBLK, 100, 9);
        });
        lay_extended_child_at(disk, 6, |record| {
            patch_compressed_special(record, DataLayout::CompressedFull, S_IFIFO, 5_000, 1);
        });
        lay_extended_child_at(disk, 8, |record| {
            patch_compressed_special(record, DataLayout::CompressedCompact, S_IFSOCK, 0, 3);
        });
        lay_extended_child_at(disk, 10, |record| {
            patch_compressed_special(record, DataLayout::CompressedFull, S_IFIFO, 5_000, 0);
        });
    })
}

/// Row 7 (§5.1⑥) — the dual-malformed mount-Ok form: algs=0 +
/// FRAGMENTS + packed_nid addressing a NON-compressed payload (a
/// fully healthy FLAT_PLAIN REG over block 9, the
/// `patch_rd1_reg_record` shape — unlike the S04 compressed material,
/// whose seed bytes hid behind the I12 gate, this record must iget Ok
/// at the Step-4 F10 door). Expected mount Ok: F10 checks only for a
/// compressed payload; a "packed must be compressed" cross-check does
/// not exist and must not be added (G-Z05, 不得顺手加严). Suite:
/// `fs.rs`.
pub(super) fn fx_comp_packed_uncompressed_payload() -> ErofsFixture {
    comp_chassis(FeatureIncompatSet::FRAGMENTS, |disk| {
        // The packed inode first — `write_inode_at` addresses through
        // the still-healthy staged superblock.
        lay_extended_child_at(disk, CHASSIS_PACKED_NID, |record| {
            patch_rd1_reg_record(record, 100, 0);
        });
        let mut sb = staged_super_block_record(disk);
        put_le_u64(
            &mut sb,
            offset_of!(RawSuperBlock, packed_nid),
            CHASSIS_PACKED_NID,
        );
        write_super_block(disk, &sb);
    })
}

// ===========================================================================
// T-027 S12: the FX-XATTR entry/layout family (S06 §5.6 rows 6–13; matrix
// §1.6 label row IMG-CRAFT-XATTR serving the §6.1 X24/W-X03/W-X06 rows,
// the §6.2 dead-index/glued-name rows, the §6.3 value-malformed rows, and
// the §6.1 G-X09 symlink-host half — the S08-frozen case B. The mechanism
// rows 1–5, bloom/shared/prefix, are S13's, over the same chassis
// variant). Eight named constructors, each a LOCAL rewrite of the chassis
// laying an ibody xattr area on a child inode (the S06 §5.6 chassis
// variant: i_xattr_icount patched, the ibody bytes staged at
// suffix_xattr_start = iloc + 64, the production base point). Every form
// mounts Ok — no mount gate reads a child's xattr area — and the
// assertion surface is the get/list/acl read chains; the suite lives in
// `xattr.rs` (that file's FIRST ktest suite; the D1 host rule).
//
// AUTO-DECISION: h_name_filter = 0 on every S12 ibody. The bloom gate is
// ACTIVE on the chassis (compat 0x7 carries XATTR_FILTER and the
// reserved byte is 0), and the all-clear bitmap is the one value that
// denies no query, keeping every walk here reachable. The crafted
// contradictory bitmap is S13's own form (G-X05); staging it on these
// images would couple every entry/layout row to the bloom mechanism row.
//
// AUTO-DECISION: the xattr chassis variant lands as the laying helpers
// below (`ibody_header`/`xattr_entry_bytes`/`icount_for_ibody`/
// `lay_xattr_child_at`) over `rewritten_chassis`, not a parallel
// staging path — every other chassis byte is form-independent (the
// `lay_compact_root` precedent), and S13's mechanism builders re-consume
// the same helpers (the subtask's single-source contract; their shared
// area rides `write_meta_bytes` at block 8+). Rejected: a `xattr_chassis`
// wrapper around `rewritten_chassis` (a pure alias); a second full
// staging function (the S07-rejected duplication).
// ===========================================================================

/// Composes the 12-byte ibody header (S06 §5.6): `h_name_filter` and
/// `h_shared_count` patched through `offset_of!`, `h_reserved2` left
/// zero (never read, G5).
fn ibody_header(name_filter: u32, shared_count: u8) -> [u8; size_of::<RawXattrIbodyHeader>()] {
    let mut header = [0u8; size_of::<RawXattrIbodyHeader>()];
    put_le_u32(
        &mut header,
        offset_of!(RawXattrIbodyHeader, h_name_filter),
        name_filter,
    );
    header[offset_of!(RawXattrIbodyHeader, h_shared_count)] = shared_count;
    header
}

/// Composes one on-disk xattr entry: the 4-byte header (`e_name_len` /
/// `e_name_index` / `e_value_size` patched through `offset_of!`) plus
/// the name and value bytes, zero-padded to the ALIGN4 total
/// (`erofs_xattr_entry_size`; the pad unit is
/// `size_of::<RawXattrEntry>()`, the C5 single source). The trailing
/// pad bytes are never read on disk. The name may be empty (a legal
/// on-disk value the acl storage and long-prefix matching consume)
/// and may be non-UTF-8 (raw bytes — the W-X06 form's identity).
fn xattr_entry_bytes(index: u8, name: &[u8], value: &[u8]) -> Vec<u8> {
    assert!(name.len() <= NAME_LEN, "on-disk names are NAME_LEN-capped");
    let entry_size = (size_of::<RawXattrEntry>() + name.len() + value.len())
        .next_multiple_of(size_of::<RawXattrEntry>());
    let mut entry = vec![0u8; entry_size];
    entry[offset_of!(RawXattrEntry, e_name_len)] = name.len() as u8;
    entry[offset_of!(RawXattrEntry, e_name_index)] = index;
    put_le_u16(
        &mut entry,
        offset_of!(RawXattrEntry, e_value_size),
        value.len() as u16,
    );
    let payload = size_of::<RawXattrEntry>();
    entry[payload..payload + name.len()].copy_from_slice(name);
    entry[payload + name.len()..payload + name.len() + value.len()].copy_from_slice(value);
    entry
}

/// The i_xattr_icount whose production decode yields an ibody of
/// exactly `ibody_len` bytes — the encode side of `xattr_ibody_size`
/// (isize = 12 + 4 × (icount − 1), `inode/mod.rs`), the
/// `chassis_i_format` inverse-of-decode discipline. Asserts the
/// well-formed domain (≥ 12, multiple of 4) — a fixture bug fails
/// loudly. The X23/X24 builders deliberately bypass this helper: their
/// geometry mismatch IS the form.
fn icount_for_ibody(ibody_len: usize) -> u16 {
    assert!(ibody_len >= size_of::<RawXattrIbodyHeader>());
    assert!(ibody_len.is_multiple_of(size_of::<RawXattrEntry>()));
    ((ibody_len - size_of::<RawXattrIbodyHeader>()) / size_of::<RawXattrEntry>() + 1) as u16
}

/// Switches an extended seed record's S_IFMT segment, keeping the
/// seed's permission bits — the one-line form the ibody children
/// repeat (the inline `mode_off` dance, extracted for this family).
fn switch_type_segment(record: &mut [u8; 64], segment: u16) {
    let mode_off = offset_of!(RawInodeExtended, i_mode);
    let mode = get_le_u16(record, mode_off);
    put_le_u16(record, mode_off, (mode & !S_IFMT) | segment);
}

/// Lays the extended seed as a child at `nid` carrying an inline
/// xattr ibody area — the S06 §5.6 xattr chassis variant, the S12/S13
/// single source: `patch` rewrites the kind/datalayout/size fields
/// (the `lay_extended_child_at` discipline), `i_xattr_icount` is set
/// to `icount` (the CALLER owns the geometry — the X23/X24 forms
/// deliberately mismatch it against the staged bytes), and `ibody`
/// stages at suffix_xattr_start = iloc + 64 (the production base
/// point, never recomputed here). The staged bytes must fit the
/// 4-slot child spacing (the `lay_fast_symlink_at` room rule).
fn lay_xattr_child_at(
    disk: &ErofsMemoryDisk,
    nid: u64,
    icount: u16,
    patch: impl FnOnce(&mut [u8; 64]),
    ibody: &[u8],
) {
    let mut record = INODE_EXT_TEMPLATE;
    patch(&mut record);
    put_le_u16(
        &mut record,
        offset_of!(RawInodeExtended, i_xattr_icount),
        icount,
    );
    write_inode_at(disk, nid, &record);
    let iloc = inode_location(&staged_super_block(disk), nid) as usize;
    let ibody_pos = iloc + size_of::<RawInodeExtended>();
    // The 4-slot child spacing (the `lay_fast_symlink_at` room rule)
    // leaves 64 bytes behind the record for the ibody.
    let room = (4 << ISLOT_BITS) - size_of::<RawInodeExtended>();
    assert!(ibody.len() <= room, "the ibody must fit the 4-slot child spacing");
    disk.stage_bytes(ibody_pos, ibody);
}

/// The standard ibody-child record patch (the `patch_rd1_reg_record`
/// shape minus the witnesses — the xattr chains never read the
/// payload): a healthy zero-length REG × FLAT_PLAIN over free block 9.
fn patch_reg_record(record: &mut [u8; 64]) {
    put_le_u16(
        record,
        offset_of!(RawInodeExtended, i_format),
        chassis_i_format(InodeVersion::Extended, DataLayout::FlatPlain),
    );
    switch_type_segment(record, S_IFREG);
    put_le_u64(record, offset_of!(RawInodeExtended, i_size), 0);
    put_le_u32(record, offset_of!(RawInodeExtended, i_u), 9);
    put_le_u32(record, offset_of!(RawInodeExtended, i_nlink), 1);
}

/// Lays the standard ibody child: [`patch_reg_record`] plus the ibody
/// area sized to the staged bytes (the well-formed geometry).
fn lay_xattr_reg_child_at(disk: &ErofsMemoryDisk, nid: u64, ibody: &[u8]) {
    lay_xattr_child_at(disk, nid, icount_for_ibody(ibody.len()), patch_reg_record, ibody);
}

/// Row 6 (§6.1 W-X03) — the empty-name entry: nid 2 carries a REAL
/// user entry with e_name_len = 0 and a one-byte value (the marker
/// ≠ 0: the entry demonstrably exists on disk), plus the healthy
/// "ctrl" control child at nid 4. get("user.") answers EINVAL at the
/// name-resolution gate (the per-FS W-X03 patch — the parse layer,
/// F38), the control hits (the walk is healthy), and the empty-name
/// entry matches no query (its suffix length 0 can never equal a
/// post-strip suffix ≥ 1) — the negative control proving the EINVAL
/// root is the parse gate, not absent entries. Suite: `xattr.rs`.
pub(super) fn fx_xattr_empty_name_entry() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut crafted = ibody_header(0, 0).to_vec();
        crafted.extend_from_slice(&xattr_entry_bytes(XATTR_INDEX_USER, b"", b"m"));
        lay_xattr_reg_child_at(disk, 2, &crafted);
        let mut control = ibody_header(0, 0).to_vec();
        control.extend_from_slice(&xattr_entry_bytes(XATTR_INDEX_USER, b"ctrl", b"ctrlval"));
        lay_xattr_reg_child_at(disk, 4, &control);
    })
}

/// Row 7 (§6.3 X44/F17 get dual + the W-X02 state-B list face) — the
/// glued acl names: index 2 and index 3 entries each carrying a
/// non-empty suffix ("foo"/"bar") and a 4-byte marker value. The acl
/// channel's INTERNAL query is empty-suffix — `e_name_len > 0` never
/// matches it → both exact acl names answer ENODATA (the F17 get-side
/// dual); the list side skips the acl rows unconditionally (aster's
/// single-namespace list channel — the registered state-B divergence
/// from Linux's glued full-name emission). Suite: `xattr.rs`.
pub(super) fn fx_xattr_glued_acl_name_entries() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut ibody = ibody_header(0, 0).to_vec();
        ibody.extend_from_slice(&xattr_entry_bytes(
            XATTR_INDEX_POSIX_ACL_ACCESS,
            b"foo",
            b"blob",
        ));
        ibody.extend_from_slice(&xattr_entry_bytes(
            XATTR_INDEX_POSIX_ACL_DEFAULT,
            b"bar",
            b"blob",
        ));
        lay_xattr_reg_child_at(disk, 2, &ibody);
    })
}

/// Row 8 (§6.2 X10) — the dead indexes: three entries carrying index
/// 0, 5 (the empty lustre slot), and 7 (the first value past the
/// 7-entry handler map) — the X10 domain, spelled as crafted bytes
/// (a malformation value, not a consumer face: the lustre constant
/// stays private-dead in `xattr.rs`). get never matches (the
/// full-value index equality against the query domain 1/4/6), list
/// skips every row without counting it. Suite: `xattr.rs`.
pub(super) fn fx_xattr_dead_index_entries() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut ibody = ibody_header(0, 0).to_vec();
        for (index, name) in [(0u8, b"a" as &[u8]), (5, b"b"), (7, b"c")] {
            ibody.extend_from_slice(&xattr_entry_bytes(index, name, b"v"));
        }
        lay_xattr_reg_child_at(disk, 2, &ibody);
    })
}

/// Row 9 (§6.2 X23) — header_sz ≥ isize: a 16-byte ibody (icount 2)
/// whose h_shared_count is raised to 2 (header_sz = 12 + 8 = 20 ≥ 16).
/// No explicit error anywhere: init overran the id reads (the second
/// id read four bytes PAST the area end — the F2 overrun-as-garbage
/// face; the bytes there are the disk's zeros), the inline walk is
/// empty, and the overrun ids (both 0) resolve through the chassis
/// xattr_blkaddr 0 to the block-0 zero bytes — dead entries,
/// exhaustion. The healthy "ok" control child at nid 4 separates the
/// X23 empty-walk ENODATA from a staging bug. Suite: `xattr.rs`.
pub(super) fn fx_xattr_header_size_overrun() -> ErofsFixture {
    rewritten_chassis(|disk| {
        // Only the 12-byte header is staged; the [12, 16) id slot and
        // the overrun read land on the disk's zeros.
        let ibody = ibody_header(0, 2);
        // icount 2 → isize 16 < header_sz 20 — the form's identity.
        lay_xattr_child_at(disk, 2, 2, patch_reg_record, &ibody);
        let mut control = ibody_header(0, 0).to_vec();
        control.extend_from_slice(&xattr_entry_bytes(XATTR_INDEX_USER, b"ok", b"v0"));
        lay_xattr_reg_child_at(disk, 4, &control);
    })
}

/// Row 10 (§6.1 X24) — the entry beyond remaining: a 32-byte ibody
/// (icount 6, entry area 20 bytes) whose single crafted entry claims
/// a 20-byte value — ALIGN4 size roundup(4 + 1 + 20) = 28 > 20 → the
/// X24 gate fires EUCLEAN at the walk, ahead of every consumer (the
/// get chain's only on-disk-corruption surfacing point; get and list
/// trip it identically). The staged entry bytes deliberately run past
/// the ibody end — never read, the gate fires first. Suite:
/// `xattr.rs`.
pub(super) fn fx_xattr_entry_beyond_remaining() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut ibody = ibody_header(0, 0).to_vec();
        ibody.extend_from_slice(&xattr_entry_bytes(
            XATTR_INDEX_USER,
            b"x",
            &[0xA5; 20], // the claimed size overruns; the bytes are never read
        ));
        // icount 6 → isize 32 < the entry's 28-byte need past the
        // header — the mismatch is the form.
        lay_xattr_child_at(disk, 2, 6, patch_reg_record, &ibody);
    })
}

/// Row 11 (§6.1 W-X06) — the non-UTF-8 name: a raw 0xFF/0x80 name
/// entry (invalid UTF-8 in any position) behind the healthy ASCII
/// "ok" control. Every aster query arrives lossy-replaced (U+FFFD,
/// six UTF-8 bytes) and never byte-matches the two raw bytes → ENODATA
/// — the REGISTERED DRIFT value (a raw-byte Linux query would hit).
/// The list OUTPUT half carries the raw bytes verbatim (a VmWriter
/// byte face, never narrowed through &str). Suite: `xattr.rs`.
pub(super) fn fx_xattr_non_utf8_names() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let mut ibody = ibody_header(0, 0).to_vec();
        ibody.extend_from_slice(&xattr_entry_bytes(XATTR_INDEX_USER, b"ok", b"v0"));
        ibody.extend_from_slice(&xattr_entry_bytes(
            XATTR_INDEX_USER,
            &[0xFF, 0x80],
            b"v1",
        ));
        lay_xattr_reg_child_at(disk, 2, &ibody);
    })
}

/// Row 12 (§6.3 X45/X46, 值域畸形/空值) — the acl value-domain legs,
/// one child each (an acl get parses the FIRST index-matching entry —
/// one outcome per inode), plus the generic-channel empty-value dual:
///
/// * nid 2: a_version 1 on a MISALIGNED 9-byte body → EOPNOTSUPP (the
///   version door BEFORE the alignment judgement; nid 8 is the same
///   shape with version 2 → EINVAL — the pair pins the order face);
/// * nid 4: a 2-byte body → EINVAL (shorter than the header);
/// * nid 6: the EMPTY value → EINVAL (the 0-length half — the acl
///   channel; the generic channel's Ok(0) dual is nid 16);
/// * nid 8: version 2 on the misaligned 9-byte body → EINVAL;
/// * nid 10: unknown tag 0x0003 → EINVAL (at its own entry);
/// * nid 12: ACL_USER (0x0002) carrying the −1 undefined id → EINVAL;
/// * nid 14: the pure version-2 header → "legal but empty" ENODATA;
/// * nid 16: a user entry "empty" with a 0-length value → Ok(0) (the
///   same on-disk empty value through the generic face — two
///   channels, two codes).
///
/// Suite: `xattr.rs`.
pub(super) fn fx_xattr_acl_value_malformed() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let acl_child = |disk: &ErofsMemoryDisk, nid: u64, value: &[u8]| {
            let mut ibody = ibody_header(0, 0).to_vec();
            ibody.extend_from_slice(&xattr_entry_bytes(
                XATTR_INDEX_POSIX_ACL_ACCESS,
                b"",
                value,
            ));
            lay_xattr_reg_child_at(disk, nid, &ibody);
        };
        // a_version = 1 (le32) + a misaligned 5-byte tail: the version
        // door fires before the alignment judgement.
        acl_child(disk, 2, &[0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00]);
        // Shorter than the 4-byte header.
        acl_child(disk, 4, &[0x02, 0x00]);
        // The empty value (the acl-channel half of the 0-length form).
        acl_child(disk, 6, &[]);
        // a_version = 2 + the same misaligned 5-byte tail.
        acl_child(disk, 8, &[0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00]);
        // Version 2 + one record with the unknown tag 0x0003.
        let unknown_tag = [0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00];
        acl_child(disk, 10, &unknown_tag);
        // Version 2 + ACL_USER (0x0002) with e_id = 0xFFFFFFFF.
        let undef_id = [0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x06, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        acl_child(disk, 12, &undef_id);
        // The pure version-2 header: count 0 → "legal but empty".
        acl_child(disk, 14, &[0x02, 0x00, 0x00, 0x00]);
        // The generic-channel empty-value dual: user "empty", value 0.
        let mut generic = ibody_header(0, 0).to_vec();
        generic.extend_from_slice(&xattr_entry_bytes(XATTR_INDEX_USER, b"empty", b""));
        lay_xattr_reg_child_at(disk, 16, &generic);
    })
}

/// Row 13 (§6.1 G-X09, the S08-frozen case B) — the symlink host: a
/// fast LNK at nid 2 carrying a user.* and a trusted.* entry, with
/// the ASCII inline target staged right behind the ibody area
/// (inline_data_start = iloc + 64 + isize — the payload/xattr
/// interplay the fast-symlink criterion consumes). get("user.x") →
/// ENODATA (X13: User ∧ non-reg/dir), get("trusted.x") hits (Trusted
/// carries zero type gate), list emits the user row (no type gate on
/// list — the asymmetry face), read_link returns the target (the
/// staging control), and a nouser_xattr re-mount of the same image
/// pins the X13-before-X3 order (ENODATA, not EOPNOTSUPP). Suite:
/// `xattr.rs`.
pub(super) fn fx_xattr_symlink_host_user() -> ErofsFixture {
    rewritten_chassis(|disk| {
        let target = b"ok-target";
        let mut ibody = ibody_header(0, 0).to_vec();
        ibody.extend_from_slice(&xattr_entry_bytes(XATTR_INDEX_USER, b"x", b"uv"));
        ibody.extend_from_slice(&xattr_entry_bytes(XATTR_INDEX_TRUSTED, b"x", b"tv"));
        lay_xattr_child_at(
            disk,
            2,
            icount_for_ibody(ibody.len()),
            |record| {
                put_le_u16(
                    record,
                    offset_of!(RawInodeExtended, i_format),
                    chassis_i_format(InodeVersion::Extended, DataLayout::FlatInline),
                );
                switch_type_segment(record, S_IFLNK);
                put_le_u64(
                    record,
                    offset_of!(RawInodeExtended, i_size),
                    target.len() as u64,
                );
                put_le_u32(record, offset_of!(RawInodeExtended, i_nlink), 1);
            },
            &ibody,
        );
        // The fast-symlink target behind the ibody area — the very
        // position the fast/slow criterion and `read_link` consume.
        let sb = staged_super_block(disk);
        let inline_start = inode_location(&sb, 2)
            + size_of::<RawInodeExtended>() as u64
            + ibody.len() as u64;
        disk.stage_bytes(inline_start as usize, target);
    })
}

// ===========================================================================
// Layer 4: fixture self-smoke (T-025 S02; the T-027 S02 builder
// foundations smokes and the T-027 S03 chassis shape smoke join at
// the tail)
// ===========================================================================

mod tests {
    use aster_block::{BLOCK_SIZE, id::Bid};
    use ostd::prelude::*;

    use super::*;
    use crate::fs::fs_impls::erofs::test_utils::assert_errno as assert_errno_reexport;

    /// Stages a position-dependent pattern and reads it back through
    /// the byte channel (`VmIo for dyn BlockDevice`), aligned and
    /// unaligned — byte-exact both ways, `read_val` included. Every
    /// bounce bio lands in the request log with the sector-rounded
    /// geometry of its range. The two stages spell both forms of the
    /// staging face: the `stage_bytes` convenience and the raw
    /// `segment()` accessor.
    #[ktest]
    fn memory_disk_byte_channel_roundtrip() {
        let disk = Arc::new(ErofsMemoryDisk::new(3 * PAGE_SIZE));
        let pattern = |off: usize| ((off * 7 + 13) & 0xff) as u8;
        let mut staged = vec![0u8; PAGE_SIZE];
        for (i, b) in staged.iter_mut().enumerate() {
            *b = pattern(i);
        }
        disk.stage_bytes(0, &staged);
        disk.segment()
            .write_bytes(PAGE_SIZE + 100, &staged[..300])
            .unwrap();

        let dev: Arc<dyn BlockDevice> = disk.clone();
        // An aligned whole page.
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_bytes(0, &mut buf).unwrap();
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, pattern(i), "byte {} of the aligned read", i);
        }
        // An unaligned range inside the second page.
        let mut unaligned = [0u8; 300];
        dev.read_bytes(PAGE_SIZE + 100, &mut unaligned).unwrap();
        for (i, b) in unaligned.iter().enumerate() {
            assert_eq!(*b, pattern(i), "byte {} of the unaligned read", i);
        }
        // `read_val`: the little-endian u32 at offset 16.
        let val: u32 = dev.read_val(16).unwrap();
        assert_eq!(
            val,
            u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            "read_val through the byte channel"
        );

        // Bounce geometry, in submission order: [0, PAGE) covers
        // sectors 0..8; [PAGE+100, PAGE+400) rounds to the single
        // sector starting at 8; [16, 20) rounds to sector 0.
        let sectors_per_block = (BLOCK_SIZE / SECTOR_SIZE) as u64;
        assert_eq!(
            disk.requests(),
            vec![
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 0,
                    nr_sectors: sectors_per_block,
                },
                BioRequest {
                    type_: BioType::Read,
                    start_sector: (PAGE_SIZE / SECTOR_SIZE) as u64,
                    nr_sectors: 1,
                },
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 0,
                    nr_sectors: 1,
                },
            ]
        );
    }

    /// Fills a one-block BIO through `read_blocks_async` and waits:
    /// the segment carries the disk bytes, the completion callback
    /// ran exactly once with `Complete`, and the request log shows
    /// the whole-block geometry of the block channel.
    #[ktest]
    fn memory_disk_block_channel_bio_fill() {
        let disk = Arc::new(ErofsMemoryDisk::new(6 * PAGE_SIZE));
        let pattern = |off: usize| ((off * 11 + 5) & 0xff) as u8;
        let mut staged = vec![0u8; PAGE_SIZE];
        for (i, b) in staged.iter_mut().enumerate() {
            *b = pattern(5 * PAGE_SIZE + i);
        }
        disk.stage_bytes(5 * PAGE_SIZE, &staged);

        let dev: Arc<dyn BlockDevice> = disk.clone();
        let (segment, mut io_batch, completions) = ktest_bio_trio();
        dev.read_blocks_async(
            Bid::new(5),
            segment.clone(),
            Some(completions.complete_fn()),
            &mut io_batch,
        )
        .unwrap();
        io_batch.wait_all().unwrap();

        assert_eq!(completions.nr_completions(), 1);
        assert_eq!(completions.statuses(), vec![BioStatus::Complete]);
        let mut buf = vec![0u8; PAGE_SIZE];
        segment.read_bytes(0, &mut buf).unwrap();
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, pattern(5 * PAGE_SIZE + i), "segment byte {}", i);
        }
        let sectors_per_block = (BLOCK_SIZE / SECTOR_SIZE) as u64;
        assert_eq!(
            disk.requests(),
            vec![BioRequest {
                type_: BioType::Read,
                start_sector: 5 * sectors_per_block,
                nr_sectors: sectors_per_block,
            }]
        );
    }

    /// The request log grows by exactly one entry per issued request
    /// and stays untouched by framework-rejected out-of-bounds byte
    /// reads (the `EINVAL` bound fires before enqueue — RD2②).
    #[ktest]
    fn memory_disk_request_log_bounds() {
        let disk = Arc::new(ErofsMemoryDisk::new(PAGE_SIZE));
        let dev: Arc<dyn BlockDevice> = disk.clone();
        let mut buf = [0u8; 8];

        dev.read_bytes(0, &mut buf).unwrap();
        assert_eq!(disk.requests().len(), 1);
        dev.read_bytes(SECTOR_SIZE, &mut buf).unwrap();
        assert_eq!(disk.requests().len(), 2);

        // At and past the end: rejected by the framework bound with
        // `InvalidArgs` (the ostd half of the EINVAL face), never
        // enqueued.
        let size = disk.size_bytes();
        assert_eq!(
            dev.read_bytes(size, &mut buf),
            Err(ostd::Error::InvalidArgs)
        );
        assert_eq!(
            dev.read_bytes(size - 4, &mut buf),
            Err(ostd::Error::InvalidArgs)
        );
        // Crossing the end from the last sector.
        let mut sector_buf = [0u8; SECTOR_SIZE];
        assert_eq!(
            dev.read_bytes(size - SECTOR_SIZE + 1, &mut sector_buf),
            Err(ostd::Error::InvalidArgs)
        );
        assert_eq!(
            disk.requests().len(),
            2,
            "rejected reads must not reach the device"
        );
    }

    /// `set_fail_reads(true)`: every Read completes `IoError` after
    /// being recorded. The byte channel surfaces it as
    /// `ostd::Error::IoError`; the block channel leaves the callback
    /// invoked exactly once with `IoError` and `wait_all` in error —
    /// the S05-IF-7 face. Clearing the flag restores normal reads.
    #[ktest]
    fn memory_disk_fail_reads_injection() {
        let disk = Arc::new(ErofsMemoryDisk::new(PAGE_SIZE));
        let dev: Arc<dyn BlockDevice> = disk.clone();
        let mut buf = [0u8; SECTOR_SIZE];

        disk.set_fail_reads(true);
        assert_eq!(dev.read_bytes(0, &mut buf), Err(ostd::Error::IoError));

        let (segment, mut io_batch, completions) = ktest_bio_trio();
        dev.read_blocks_async(
            Bid::new(0),
            segment,
            Some(completions.complete_fn()),
            &mut io_batch,
        )
        .unwrap();
        assert!(io_batch.wait_all().is_err());
        assert_eq!(completions.nr_completions(), 1);
        assert_eq!(completions.statuses(), vec![BioStatus::IoError]);
        // The injected request was recorded like any other.
        assert_eq!(disk.requests().len(), 2);
        assert_eq!(disk.requests()[0].type_, BioType::Read);

        disk.set_fail_reads(false);
        assert!(dev.read_bytes(0, &mut buf).is_ok());
    }

    /// `ktest_fs_on` wires the handle over the memory disk: the
    /// device `Arc` is the one handed in, the weak self-reference
    /// upgrades to the same handle, and the crafted flatdev table
    /// rides along (its accessors stay expect-gated until their
    /// production consumers land — S03/S04 remove the bridges, so
    /// this smoke only pins the wiring identity).
    #[ktest]
    fn ktest_fs_wiring_identity() {
        let disk = Arc::new(ErofsMemoryDisk::new(PAGE_SIZE));
        let dev: Arc<dyn BlockDevice> = disk.clone();
        let table = ktest_flatdev_table(&[(12, 12)], 1);
        let fs = ktest_fs_on(disk, ktest_super_block(12, 0), table);
        assert!(Arc::ptr_eq(fs.block_device(), &dev));
        let upgraded = fs.self_ref().upgrade().unwrap();
        assert!(Arc::ptr_eq(&upgraded, &fs));

        let flat = ktest_fs_on(
            Arc::new(ErofsMemoryDisk::new(PAGE_SIZE)),
            ktest_super_block(12, 0),
            ktest_single_device_table(),
        );
        assert!(flat.self_ref().upgrade().is_some());
    }

    /// The geometry constructors spell every knob — including the
    /// production-unreachable bypass forms (the compressed snapshot
    /// and a cross-block inline tail) the map-path defenses consume.
    #[ktest]
    fn ktest_geometry_knobs_roundtrip() {
        let flat = ktest_flat_geometry(3 * PAGE_SIZE as u64 + 100, 16, true, PAGE_SIZE as u64);
        assert_eq!(flat.size, 3 * PAGE_SIZE as u64 + 100);
        assert_eq!(flat.block_bits, 12);
        assert_eq!(flat.raw_blkaddr, 16);
        assert!(flat.tail_inline);
        assert_eq!(flat.inline_data_start, PAGE_SIZE as u64);
        assert_eq!(flat.chunk, None);
        assert!(!flat.compressed);

        let chunked = ktest_data_geometry(
            1 << 20,
            12,
            0,
            false,
            PAGE_SIZE as u64,
            Some(ChunkGeometry {
                unit: 8,
                chunkbits: 1,
            }),
            false,
        );
        assert_eq!(
            chunked.chunk,
            Some(ChunkGeometry {
                unit: 8,
                chunkbits: 1,
            })
        );

        // The bypass form no production constructor can build: the
        // compressed snapshot stays true past the I12 gate.
        let compressed = ktest_data_geometry(PAGE_SIZE as u64, 12, 16, false, 0, None, true);
        assert!(compressed.compressed);

        // The cross-block inline form (the EUCLEAN crafted edge):
        // the inline tail of a 100-byte remainder starting 4000
        // bytes into a block crosses the block end.
        let cross = ktest_flat_geometry(
            2 * PAGE_SIZE as u64 + 100,
            16,
            true,
            PAGE_SIZE as u64 + 4000,
        );
        assert!(cross.tail_inline);
        assert!(
            (cross.inline_data_start % PAGE_SIZE as u64) + 100 > PAGE_SIZE as u64,
            "the crafted inline tail must cross the block end"
        );
    }

    /// The assertion macro itself, exercised once in-file: the Err
    /// arm extracts `error()` and compares the errno. Pinned here so
    /// the macro's shape is proven before the S03+ mount/iget suites
    /// consume it (the Ok arm panics — a deliberately-failing form
    /// would abort the ktest run, so only the Err arm is spelled).
    ///
    /// `return_errno_with_message!` expands to a `return`, so each
    /// input is produced by calling a closure whose body is just the
    /// macro — the `return` then supplies the closure's value, the
    /// same `Err` a real failing call site produces. The `Result`
    /// type is spelled through `core::result`: both `ostd::prelude::*`
    /// and `super::*` glob-import a `Result`, and a bare one is
    /// ambiguous here (`Error` itself resolves unambiguously). The
    /// second invocation goes through the
    /// `pub(super)` re-export under its full crate path — the exact
    /// import shape the S03+ host suites use (the ext2 hosts'
    /// `use crate::fs::fs_impls::ext2::test_utils::{..,
    /// assert_errno, ..}` pattern) — which also keeps that
    /// re-export referenced until the hosts exist.
    #[ktest]
    fn assert_errno_macro_err_arm() {
        let e: core::result::Result<(), Error> =
            (|| return_errno_with_message!(Errno::EINVAL, "ktest macro shape smoke"))();
        assert_errno!(e, Errno::EINVAL);
        let e: core::result::Result<(), Error> =
            (|| return_errno_with_message!(Errno::EUCLEAN, "second arm"))();
        assert_errno_reexport!(e, Errno::EUCLEAN, "with message tail");
    }

    /// The LE helper family is little-endian by construction: known
    /// values land as explicitly spelled low-byte-first bytes, and
    /// the get side round-trips them back.
    #[ktest]
    fn le_helpers_little_endian_roundtrip() {
        let mut buf = [0u8; 14];
        put_le_u16(&mut buf, 0, 0x1234);
        assert_eq!(&buf[..2], &[0x34, 0x12]);
        put_le_u32(&mut buf, 2, 0xABCD_EF01);
        assert_eq!(&buf[2..6], &[0x01, 0xEF, 0xCD, 0xAB]);
        put_le_u64(&mut buf, 6, 0x0102_0304_0506_0708);
        assert_eq!(
            &buf[6..14],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(get_le_u16(&buf, 0), 0x1234);
        assert_eq!(get_le_u32(&buf, 2), 0xABCD_EF01);
        assert_eq!(get_le_u64(&buf, 6), 0x0102_0304_0506_0708);
    }

    /// `write_super_block` finishes with a checksum the production
    /// verifier accepts — including when the input carries the
    /// SB_CHKSUM bit clear (the §3.4 set step) — while
    /// `write_super_block_raw` stages the whitelisted template
    /// verbatim: zero checksum, verifier rejects. The V5-only skip
    /// semantics in miniature.
    #[ktest]
    fn write_super_block_recompute_vs_raw() {
        let disk = ErofsMemoryDisk::new(PAGE_SIZE);
        let verify_staged = |disk: &ErofsMemoryDisk| {
            let raw: RawSuperBlock = disk.segment().read_val(SUPER_OFFSET).unwrap();
            let len = SuperBlock::from(raw).checksummed_len();
            let mut region = vec![0u8; len];
            disk.segment()
                .read_bytes(SUPER_OFFSET, &mut region)
                .unwrap();
            (
                raw.checksum,
                verify_superblock_checksum(&mut region, raw.checksum),
            )
        };

        write_super_block(&disk, &SB_TEMPLATE);
        let (csum, ok) = verify_staged(&disk);
        assert!(ok, "production verify must accept the recomputed checksum");
        assert_ne!(
            csum, 0,
            "the recomputed value replaces the whitelisted zero"
        );

        // SB_CHKSUM clear on input: the writer sets the bit before
        // computing, so the staged record still verifies.
        let mut sb = SB_TEMPLATE;
        put_le_u32(&mut sb, offset_of!(RawSuperBlock, feature_compat), 0);
        write_super_block(&disk, &sb);
        let (_, ok) = verify_staged(&disk);
        assert!(
            ok,
            "the S06 3.4 SB_CHKSUM set step must make the record verify"
        );

        // The raw channel: the template's zero checksum goes to disk
        // untouched and fails the production verify.
        write_super_block_raw(&disk, &SB_TEMPLATE);
        let (csum, ok) = verify_staged(&disk);
        assert_eq!(csum, 0);
        assert!(!ok, "raw staging must NOT verify (the V5 skip channel)");
    }

    /// The layout writers stage at the formula offsets:
    /// `write_inode_at` lands the record at the production `iloc`
    /// (meta 1, blkszbits 12, so nid 2 → 4096 + 64);
    /// `write_dirents` lays the dirent array at the chassis block
    /// base with the name area right behind it; `write_meta_bytes`
    /// addresses block + byte offset.
    #[ktest]
    fn layout_writers_stage_at_formula_offsets() {
        // Nine pages: the meta-bytes stage writes into block 8
        // (bytes 32776..32794), so the disk must hold blocks 0..=8.
        let disk = ErofsMemoryDisk::new(9 * PAGE_SIZE);

        // Chassis-style superblock: the template patched to
        // meta_blkaddr = 1 (S06 3.2), staged through the recompute
        // writer so the record is mount-shaped.
        let mut sb = SB_TEMPLATE;
        put_le_u32(&mut sb, offset_of!(RawSuperBlock, meta_blkaddr), 1);
        write_super_block(&disk, &sb);
        let staged = staged_super_block(&disk);
        assert_eq!(staged.meta_blkaddr, 1);
        assert_eq!(staged.blkszbits, SUPPORTED_BLKSZBITS);

        // Inode: iloc via the production formula over the staged sb.
        write_inode_at(&disk, 2, &INODE_EXT_TEMPLATE);
        let iloc = inode_location(&staged, 2) as usize;
        assert_eq!(iloc, CHASSIS_BLOCK_SIZE + (2usize << ISLOT_BITS));
        let mut inode_back = [0u8; 64];
        disk.segment().read_bytes(iloc, &mut inode_back).unwrap();
        assert_eq!(inode_back, INODE_EXT_TEMPLATE);

        // Dirents: entries at the block base, names right after
        // (first-nameoff contract: entries.len()).
        let mut entries = DIRENT_TEMPLATE.to_vec();
        entries.extend_from_slice(&DIRENT_TEMPLATE);
        write_dirents(&disk, 4, &entries, b"names!");
        let base = 4 * CHASSIS_BLOCK_SIZE;
        let mut entries_back = [0u8; 24];
        disk.segment().read_bytes(base, &mut entries_back).unwrap();
        assert_eq!(&entries_back[..12], &DIRENT_TEMPLATE);
        let mut names_back = [0u8; 6];
        disk.segment()
            .read_bytes(base + 24, &mut names_back)
            .unwrap();
        assert_eq!(&names_back, b"names!");

        // Meta bytes: block + offset addressing (the prefix-record
        // reference family is the S13 consumer).
        write_meta_bytes(&disk, 8, 16, &XATTR_PREFIX_RECORD_REF);
        let mut prefix_back = [0u8; 18];
        disk.segment()
            .read_bytes(8 * CHASSIS_BLOCK_SIZE + 16, &mut prefix_back)
            .unwrap();
        assert_eq!(prefix_back, XATTR_PREFIX_RECORD_REF);
    }

    /// The G-M10 truncation channel: the declared size shrinks to
    /// the override while the physical allocation stays whole pages —
    /// `metadata().nr_sectors` and `size_bytes()` report 6 sectors
    /// (3072 bytes), staging still reaches the full page beyond the
    /// declared end. The mount-time assertion values of the
    /// truncated-image forms belong to S14 (registered drift); this
    /// smoke pins the mechanism only.
    #[ktest]
    fn memory_disk_truncated_declares_shrunk_sectors() {
        let disk = Arc::new(ErofsMemoryDisk::truncated(PAGE_SIZE, 6));
        let dev: Arc<dyn BlockDevice> = disk.clone();
        assert_eq!(dev.metadata().nr_sectors, 6);
        assert_eq!(disk.size_bytes(), 6 * SECTOR_SIZE);

        // The physical page beyond the declared end is still
        // stageable and readable through the segment.
        disk.stage_bytes(6 * SECTOR_SIZE, &[0xAA, 0xBB]);
        let mut back = [0u8; 2];
        disk.segment()
            .read_bytes(6 * SECTOR_SIZE, &mut back)
            .unwrap();
        assert_eq!(back, [0xAA, 0xBB]);
    }

    /// The chassis staging shape, pinned without mounting — the
    /// diagnostic complement of `healthy_fixture_mounts` (fs.rs):
    /// if the mount ever fails, this smoke separates a staging bug
    /// from a mount-path regression. Four faces: the i_format
    /// compose helper cross-locks against BOTH template seeds (it
    /// must reproduce the C1/C2-measured words 0x0005/0x0004
    /// bit-for-bit — its inverse is the production `parse_i_format`
    /// decode); the staged superblock decodes with exactly the four
    /// chassis patches and the untouched bloom-gate compat; the
    /// root record lands at the iloc formula position carrying the
    /// FLAT_PLAIN switch; the `.`/`..` block carries the nameoff
    /// chain at the `write_dirents` contract with both nids at the
    /// root.
    #[ktest]
    fn chassis_staging_shape() {
        // Compose-helper cross-lock against the measured seeds: the
        // inverse extraction of the production decode must
        // reproduce each seed's on-disk word exactly.
        assert_eq!(
            chassis_i_format(InodeVersion::Extended, DataLayout::FlatInline),
            get_le_u16(&INODE_EXT_TEMPLATE, offset_of!(RawInodeExtended, i_format)),
            "the helper must reproduce the C1 extended seed word"
        );
        assert_eq!(
            chassis_i_format(InodeVersion::Compact, DataLayout::FlatInline),
            get_le_u16(&INODE_CPT_TEMPLATE, offset_of!(RawInodeCompact, i_format)),
            "the helper must reproduce the C2 compact seed word"
        );

        let disk = ErofsMemoryDisk::new(CHASSIS_NR_BLOCKS as usize * CHASSIS_BLOCK_SIZE);
        stage_healthy_chassis(&disk);

        // The staged superblock through the production From decode:
        // the four patch fields plus untouched template facts (the
        // bloom-gate compat 0x7, the zero incompat).
        let sb = staged_super_block(&disk);
        assert_eq!(u64::from(sb.root_nid), CHASSIS_ROOT_NID);
        assert_eq!(sb.inos, CHASSIS_INO_SLOTS);
        assert_eq!(sb.blocks, CHASSIS_NR_BLOCKS);
        assert_eq!(sb.meta_blkaddr, CHASSIS_META_BLKADDR);
        assert_eq!(sb.feature_compat().bits(), 0x7);
        assert_eq!(sb.feature_incompat, 0);

        // The root record at the iloc formula position (meta 1,
        // nid 0 -> block boundary), carrying the FLAT_PLAIN switch.
        let iloc = inode_location(&sb, CHASSIS_ROOT_NID) as usize;
        assert_eq!(iloc, CHASSIS_BLOCK_SIZE);
        let mut root = [0u8; 64];
        disk.segment().read_bytes(iloc, &mut root).unwrap();
        assert_eq!(
            get_le_u16(&root, offset_of!(RawInodeExtended, i_format)),
            chassis_i_format(InodeVersion::Extended, DataLayout::FlatPlain)
        );
        assert_eq!(
            get_le_u64(&root, offset_of!(RawInodeExtended, i_size)),
            CHASSIS_ROOT_DIR_SIZE
        );
        assert_eq!(
            get_le_u32(&root, offset_of!(RawInodeExtended, i_u)),
            CHASSIS_ROOT_DATA_BLK
        );
        assert_eq!(get_le_u32(&root, offset_of!(RawInodeExtended, i_nlink)), 2);

        // The `.`/`..` block: both nids at the root, the nameoff
        // chain at the write_dirents contract (array end, array
        // end + 1), the packed names right behind the array.
        let base = CHASSIS_ROOT_DATA_BLK as usize * CHASSIS_BLOCK_SIZE;
        let array_end = CHASSIS_ROOT_NDIRENTS * size_of::<RawDirent>();
        let dot: RawDirent = disk.segment().read_val(base).unwrap();
        let dot_dot: RawDirent = disk
            .segment()
            .read_val(base + size_of::<RawDirent>())
            .unwrap();
        assert_eq!(u64::from_le(dot.nid), CHASSIS_ROOT_NID);
        assert_eq!(u64::from_le(dot_dot.nid), CHASSIS_ROOT_NID);
        assert_eq!(u16::from_le(dot.nameoff) as usize, array_end);
        assert_eq!(u16::from_le(dot_dot.nameoff) as usize, array_end + 1);
        let mut names = [0u8; CHASSIS_ROOT_NAMES.len()];
        disk.segment()
            .read_bytes(base + array_end, &mut names)
            .unwrap();
        assert_eq!(&names, CHASSIS_ROOT_NAMES);
    }
}
