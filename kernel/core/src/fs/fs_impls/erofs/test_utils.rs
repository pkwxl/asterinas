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
//!
//! The full erofs image builder (staged disk bytes walked by the
//! real `Erofs::open` chain) is still T-027's; until it lands,
//! ktests assemble handles directly (`ktest_new`/`ktest_fs_on`)
//! instead of mounting.
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
        AddrState, ChunkGeometry, DataGeometry, DataLayout, FileKind, InodeDesc, InodeVersion,
    },
    prelude::*,
    super_block::SuperBlock,
};

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
        }
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
    /// `nr_sectors * SECTOR_SIZE`. Reads touching or crossing this
    /// bound fail `EINVAL` before reaching the device.
    pub(super) fn size_bytes(&self) -> usize {
        self.segment.size() / SECTOR_SIZE * SECTOR_SIZE
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
            nr_sectors: self.segment.size() / SECTOR_SIZE,
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
// Layer 4: fixture self-smoke (T-025 S02)
// ===========================================================================

mod tests {
    use aster_block::{BLOCK_SIZE, id::Bid};
    use ostd::prelude::*;

    use super::*;

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
}
