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
        AddrState, ChunkGeometry, DataGeometry, DataLayout, FileKind, I_DATALAYOUT_BIT,
        I_VERSION_BIT, ISLOT_BITS, InodeDesc, InodeVersion, RawDirent, RawInodeCompact,
        RawInodeExtended, S_IFMT, S_IFREG, inode_location,
    },
    prelude::*,
    super_block::{
        BLKSZBITS_MIN, FeatureCompatSet, FeatureIncompatSet, RawSuperBlock, SUPER_MAGIC_V1,
        SUPER_OFFSET, SUPPORTED_BLKSZBITS, SuperBlock, verify_superblock_checksum,
    },
    utils::crc32c,
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
// helper — the S02-era dead-code expectation came off with it.
// Compact chassis staging itself arrives with the S07 FX-TIME
// suites.
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

/// One 12-byte dirent record from the T-DIRENT seed: `nid` and
/// `nameoff` patched through `offset_of!`; the seed's file_type 2
/// (DT_DIR) and reserved 0 stay — every chassis entry is a
/// directory.
fn chassis_dirent(nid: u64, nameoff: u16) -> [u8; 12] {
    let mut entry = DIRENT_TEMPLATE;
    put_le_u64(&mut entry, offset_of!(RawDirent, nid), nid);
    put_le_u16(&mut entry, offset_of!(RawDirent, nameoff), nameoff);
    entry
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
    disk.segment().read_bytes(SUPER_OFFSET, &mut record).unwrap();
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
        put_le_u64(&mut sb, inos_off, get_le_u64(&sb, inos_off) ^ 0xFF);
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
        put_le_u32(&mut sb, off, get_le_u32(&sb, off) | unknown_incompat_bit());
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
        put_le_u32(&mut sb, off, get_le_u32(&sb, off) | unknown_incompat_bit());
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
        put_le_u32(
            &mut sb,
            incompat_off,
            get_le_u32(&sb, incompat_off) | FeatureIncompatSet::FRAGMENTS.bits(),
        );
        put_le_u64(&mut sb, offset_of!(RawSuperBlock, packed_nid), CHASSIS_PACKED_NID);
        write_super_block(disk, &sb);
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
