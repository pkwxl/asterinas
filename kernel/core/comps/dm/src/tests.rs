// SPDX-License-Identifier: MPL-2.0

//! Kernel-mode unit tests (ktest) for the DM core.
//!
//! Contract under test: `TargetType::map` receives a sector that has already
//! been translated into target-relative form (`abs_sector - begin`) and
//! returns a `MappedIo` (underlying device + absolute sector on it).

use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use aster_block::{
    BLOCK_SIZE, BlockDevice, BlockDeviceMeta,
    bio::{Bio, BioDirection, BioEnqueueError, BioSegment, BioStatus, BioType, SubmittedBio},
    id::Sid,
};
use device_id::{DeviceId, MajorId, MinorId};
use io_util::batch::IoBatch;
use ostd::{
    mm::{FrameAllocOptions, Segment, VmIo, VmReader, VmWriter, io::util::HasVmReaderWriter},
    prelude::*,
};

use crate::{
    CtrOutcome, DmDevice, DmTable, ErrorTargetType, LinearTargetType, MappedIo, StripedTargetType,
    TargetType, TargetVersion,
    linear::{LinearPrivate, resolve_device},
    lookup_target, register_target, snapshot_targets,
    striped::StripedPrivate,
};

/// The global target registry is shared by all tests in one ktest run, so
/// every registration helper here must be idempotent.
fn ensure_builtin_targets() {
    // Ignore "already registered" errors.
    let _ = register_target(Arc::new(LinearTargetType::new()));
    let _ = register_target(Arc::new(ErrorTargetType::new()));
}

/// A minimal in-memory block device used to satisfy linear ctr's device
/// resolution. It never actually stores data.
#[derive(Debug)]
struct DummyDisk {
    name: String,
    id: DeviceId,
}

impl BlockDevice for DummyDisk {
    fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        bio.complete(BioStatus::Complete);
        Ok(())
    }

    fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: 1,
            nr_sectors: 4096,
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> DeviceId {
        self.id
    }
}

const DUMMY_DEV_NAME: &str = "dmtestdummy0";

/// Register a dummy block device with the given name (idempotent) and
/// return it.
fn ensure_dummy_device_named(name: &str, minor: u32) -> Arc<dyn BlockDevice> {
    if let Some(dev) = aster_block::collect_all()
        .into_iter()
        .find(|d| d.name() == name)
    {
        return dev;
    }
    let dev = Arc::new(DummyDisk {
        name: String::from(name),
        id: DeviceId::new(MajorId::new(250), MinorId::new(minor)),
    });
    aster_block::register(dev.clone()).unwrap();
    dev
}

/// Register the dummy block device (idempotent) and return it.
fn ensure_dummy_device() -> Arc<dyn BlockDevice> {
    ensure_dummy_device_named(DUMMY_DEV_NAME, 250)
}

const DUMMY_DEV_NAME1: &str = "dmtestdummy1";

/// Register a second dummy block device (idempotent) and return it.
fn ensure_dummy_device1() -> Arc<dyn BlockDevice> {
    ensure_dummy_device_named(DUMMY_DEV_NAME1, 251)
}

fn linear_type() -> Arc<dyn TargetType> {
    ensure_builtin_targets();
    lookup_target("linear").expect("linear target should be registered")
}

fn error_type() -> Arc<dyn TargetType> {
    ensure_builtin_targets();
    lookup_target("error").expect("error target should be registered")
}

struct DummyTargetType;

impl TargetType for DummyTargetType {
    fn name(&self) -> &str {
        "t010_dummy"
    }

    fn version(&self) -> TargetVersion {
        TargetVersion::new(9, 8, 7)
    }

    fn ctr(&self, _len: u64, _params: &[&str]) -> Result<CtrOutcome, &'static str> {
        Err("dummy: not constructible")
    }

    fn map(
        &self,
        _private: &dyn core::any::Any,
        _sector_in_target: u64,
    ) -> Result<MappedIo, &'static str> {
        Err("dummy: not mappable")
    }

    fn status(&self, _private: &dyn core::any::Any) -> String {
        String::new()
    }
}

#[ktest]
fn registry_register_lookup_snapshot() {
    // Registering a fresh target type succeeds.
    let first = register_target(Arc::new(DummyTargetType));
    assert!(
        first.is_ok() || first == Err("Target type already registered"),
        "unexpected register error"
    );

    // Duplicate registration is rejected.
    let dup = register_target(Arc::new(DummyTargetType));
    assert_eq!(dup, Err("Target type already registered"));

    // Lookup returns a usable Arc clone.
    let looked_up = lookup_target("t010_dummy").expect("dummy target should be registered");
    assert_eq!(looked_up.name(), "t010_dummy");
    assert_eq!(
        looked_up.version().to_dm_version(),
        (9 << 16) | (8 << 8) | 7
    );

    // Unknown names yield None instead of panicking.
    assert!(lookup_target("no_such_target_xyz").is_none());

    // The snapshot covers the registered target.
    let snapshot = snapshot_targets();
    assert!(
        snapshot
            .iter()
            .any(|(name, ver)| name == "t010_dummy"
                && ver.to_dm_version() == (9 << 16) | (8 << 8) | 7)
    );
}

#[ktest]
fn linear_ctr_rejects_bad_params() {
    let dev = ensure_dummy_device();
    let linear = linear_type();

    // Wrong parameter counts.
    assert!(linear.ctr(100, &[]).is_err());
    assert!(linear.ctr(100, &["onlyone"]).is_err());
    assert!(linear.ctr(100, &[DUMMY_DEV_NAME, "2048", "extra"]).is_err());

    // Non-decimal / negative offsets.
    assert!(linear.ctr(100, &[DUMMY_DEV_NAME, "12a3"]).is_err());
    assert!(linear.ctr(100, &[DUMMY_DEV_NAME, "-5"]).is_err());
    assert!(linear.ctr(100, &[DUMMY_DEV_NAME, ""]).is_err());

    // Unknown underlying device.
    assert!(linear.ctr(100, &["no_such_dev_xyz", "0"]).is_err());

    // Valid forms: bare name and "/dev/"-prefixed name.
    let outcome = linear.ctr(100, &[DUMMY_DEV_NAME, "2048"]).unwrap();
    assert_eq!(outcome.max_io_len, 0);
    let outcome_prefixed = linear.ctr(100, &["/dev/dmtestdummy0", "2048"]).unwrap();
    assert_eq!(outcome_prefixed.max_io_len, 0);

    // Sanity: the resolved device is the dummy disk.
    let mapped = linear.map(&*outcome.private, 0).unwrap();
    assert_eq!(mapped.device.name(), dev.name());
}

#[ktest]
fn linear_map_formula() {
    ensure_dummy_device();
    let linear = linear_type();
    let outcome = linear.ctr(100, &[DUMMY_DEV_NAME, "2048"]).unwrap();

    // map receives a target-relative sector: dev_sector = offset + sector_in_target.
    assert_eq!(linear.map(&*outcome.private, 0).unwrap().sector, 2048);
    assert_eq!(linear.map(&*outcome.private, 7).unwrap().sector, 2055);
    assert_eq!(linear.map(&*outcome.private, 99).unwrap().sector, 2147);
}

#[ktest]
fn error_target_behaves() {
    let error = error_type();

    // ctr takes no parameters and reports no max_io_len limit.
    assert!(error.ctr(64, &["unexpected"]).is_err());
    let outcome = error.ctr(64, &[]).unwrap();
    assert_eq!(outcome.max_io_len, 0);

    // map always fails.
    assert!(error.map(&*outcome.private, 0).is_err());
    assert!(error.map(&*outcome.private, 63).is_err());

    // status is an empty parameter string.
    assert_eq!(error.status(&*outcome.private), "");
}

#[ktest]
fn table_add_target_adjoin_rules() {
    ensure_builtin_targets();

    let mut table = DmTable::new();
    table.add_target(0, 100, "error", "").unwrap();
    table.add_target(100, 50, "error", "").unwrap();
    assert_eq!(table.nr_sectors(), 150);

    // Gap: begin must equal the current nr_sectors.
    assert!(table.add_target(200, 10, "error", "").is_err());
    // Zero length is rejected.
    assert!(table.add_target(150, 0, "error", "").is_err());
    // The table is unchanged by the rejected additions.
    assert_eq!(table.nr_sectors(), 150);
    assert_eq!(table.targets().len(), 2);
}

#[ktest]
fn table_add_target_unknown_type() {
    ensure_builtin_targets();

    let mut table = DmTable::new();
    assert!(table.add_target(0, 10, "nonexistent_xyz", "").is_err());
    assert_eq!(table.nr_sectors(), 0);
    assert!(table.targets().is_empty());
}

#[ktest]
fn table_find_target_bounds() {
    ensure_builtin_targets();

    let mut table = DmTable::new();
    table.add_target(0, 100, "error", "").unwrap();
    table.add_target(100, 50, "error", "").unwrap();

    assert_eq!(table.find_target(0).unwrap().begin, 0);
    assert_eq!(table.find_target(99).unwrap().begin, 0);
    assert_eq!(table.find_target(100).unwrap().begin, 100);
    assert_eq!(table.find_target(149).unwrap().begin, 100);
    assert!(table.find_target(150).is_none());

    // max_io_len is recorded on the target (error target: unlimited).
    assert_eq!(table.find_target(0).unwrap().max_io_len, 0);
}

#[ktest]
fn table_map_and_status_via_target() {
    ensure_builtin_targets();
    ensure_dummy_device();

    let mut table = DmTable::new();
    table
        .add_target(0, 100, "linear", "dmtestdummy0 2048")
        .unwrap();
    table.add_target(100, 50, "error", "").unwrap();

    // DmTarget::map takes an absolute sector, subtracts begin internally.
    let linear_target = table.find_target(5).unwrap();
    let mapped = linear_target.map(5).unwrap();
    assert_eq!(mapped.sector, 2048 + 5);
    assert_eq!(mapped.device.name(), DUMMY_DEV_NAME);

    // Second target: absolute sector 120 -> target-relative 20.
    let error_target = table.find_target(120).unwrap();
    assert!(error_target.map(120).is_err());

    // Out-of-range absolute sector is rejected by DmTarget::map.
    assert!(table.find_target(150).is_none());

    // status_params comes from TargetType::status.
    assert_eq!(linear_target.status_params(), "dmtestdummy0 2048");
    assert_eq!(error_target.status_params(), "");
    assert_eq!(linear_target.type_name(), "linear");
    assert_eq!(error_target.type_name(), "error");
}

// ==================================================================
// Split/enqueue tests (T-010 subtask 3)
// ==================================================================

/// An in-memory block device that honors `sid_offset` (in sectors, same as
/// `BioRequest::from(SubmittedBio)` computes the physical sid) and counts
/// the enqueued bios, so tests can observe the DM device's mapping and
/// splitting behavior.
#[derive(Debug)]
struct MemDisk {
    name: String,
    id: DeviceId,
    data: Segment<()>,
    nr_enqueues: AtomicUsize,
}

impl MemDisk {
    /// Creates and registers a `MemDisk` with the given (unique) name and
    /// minor id; `nsectors` is rounded up to whole blocks.
    fn new(name: &str, minor: u32, nsectors: usize) -> Arc<Self> {
        let nframes = (nsectors * aster_block::SECTOR_SIZE).div_ceil(BLOCK_SIZE);
        let disk = Arc::new(Self {
            name: String::from(name),
            id: DeviceId::new(MajorId::new(249), MinorId::new(minor)),
            data: FrameAllocOptions::new()
                .zeroed(true)
                .alloc_segment(nframes)
                .unwrap(),
            nr_enqueues: AtomicUsize::new(0),
        });
        aster_block::register(disk.clone()).unwrap();
        disk
    }

    fn read_bytes(&self, byte_off: usize, buf: &mut [u8]) {
        self.data.read_slice(byte_off, buf).unwrap();
    }

    fn enqueues(&self) -> usize {
        self.nr_enqueues.load(Ordering::Relaxed)
    }
}

impl BlockDevice for MemDisk {
    fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        self.nr_enqueues.fetch_add(1, Ordering::Relaxed);
        let bio_type = bio.type_();
        if bio_type == BioType::Flush {
            bio.complete(BioStatus::Complete);
            return Ok(());
        }

        let mut cur = (bio.sid_range().start + bio.sid_offset()).to_offset();
        for segment in bio.segments() {
            let n = match bio_type {
                BioType::Read => {
                    let slice = segment.inner_dma_slice();
                    let mut writer = slice.writer().unwrap();
                    writer.write(&mut self.data.reader().skip(cur))
                }
                BioType::Write => {
                    let slice = segment.inner_dma_slice();
                    let mut reader = slice.reader().unwrap();
                    self.data.writer().skip(cur).write(&mut reader)
                }
                BioType::Flush => 0,
            };
            cur += n;
        }
        bio.complete(BioStatus::Complete);
        Ok(())
    }

    fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: usize::MAX,
            nr_sectors: self.data.size() / aster_block::SECTOR_SIZE,
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> DeviceId {
        self.id
    }
}

/// A linear-like target type whose instances have a `max_io_len` limit of
/// `CHUNKED_MAX_IO_LEN` sectors, used to verify that bios are split on
/// `max_io_len` boundaries.
struct ChunkedTargetType;

const CHUNKED_MAX_IO_LEN: u64 = 8;
const CHUNKED_NAME: &str = "t010_chunked";

impl TargetType for ChunkedTargetType {
    fn name(&self) -> &str {
        CHUNKED_NAME
    }

    fn version(&self) -> TargetVersion {
        TargetVersion::new(0, 1, 0)
    }

    fn ctr(&self, _len: u64, params: &[&str]) -> Result<CtrOutcome, &'static str> {
        if params.len() != 2 {
            return Err("chunked: expected \"<dev> <offset>\"");
        }
        let dev = resolve_device(params[0])?;
        let offset = params[1]
            .parse::<u64>()
            .map_err(|_| "chunked: invalid offset")?;
        Ok(CtrOutcome {
            private: Box::new(LinearPrivate { dev, offset }),
            max_io_len: CHUNKED_MAX_IO_LEN,
        })
    }

    fn map(
        &self,
        private: &dyn core::any::Any,
        sector_in_target: u64,
    ) -> Result<MappedIo, &'static str> {
        let p = private
            .downcast_ref::<LinearPrivate>()
            .ok_or("chunked: invalid target private type")?;
        Ok(MappedIo {
            device: p.dev.clone(),
            sector: p.offset + sector_in_target,
        })
    }

    fn status(&self, _private: &dyn core::any::Any) -> String {
        String::new()
    }
}

fn ensure_chunked_target() {
    let _ = register_target(Arc::new(ChunkedTargetType));
}

/// Creates a `DmDevice` with `table` as the active table.
fn create_dm_with_table(table: DmTable) -> Arc<DmDevice> {
    let id = DeviceId::new(MajorId::new(253), MinorId::new(7));
    let dm = DmDevice::create("dmtest-split", id);
    dm.load_table(table);
    dm.swap_table();
    dm
}

/// Submits a write bio of `nblocks` blocks at `start`, filled with
/// `pattern`, and returns the final status.
fn dm_write(dm: &DmDevice, start: u64, nblocks: usize, pattern: &[u8]) -> BioStatus {
    assert_eq!(pattern.len(), nblocks * BLOCK_SIZE);
    let seg = BioSegment::alloc(nblocks, BioDirection::ToDevice);
    {
        let slice = seg.inner_dma_slice();
        let mut writer = slice.writer().unwrap();
        let n = writer.write(&mut VmReader::from(pattern));
        assert_eq!(n, pattern.len());
    }
    let bio = Bio::new(BioType::Write, Sid::new(start), vec![seg], None);
    bio.submit_and_wait(dm).unwrap()
}

/// Submits a read bio of `nblocks` blocks at `start` and returns the final
/// status plus the data read.
fn dm_read(dm: &DmDevice, start: u64, nblocks: usize) -> (BioStatus, Vec<u8>) {
    let seg = BioSegment::alloc(nblocks, BioDirection::FromDevice);
    let probe = seg.clone();
    let bio = Bio::new(BioType::Read, Sid::new(start), vec![seg], None);
    let status = bio.submit_and_wait(dm).unwrap();
    let mut buf = vec![0u8; nblocks * BLOCK_SIZE];
    let slice = probe.inner_dma_slice();
    let mut reader = slice.reader().unwrap();
    let n = reader.read(&mut VmWriter::from(&mut buf[..]));
    assert_eq!(n, buf.len());
    (status, buf)
}

/// Fast path: a single-piece bio is forwarded with a *sector* `sid_offset`
/// (regression test for the C1 bug, where the offset was multiplied by
/// `SECTOR_SIZE`).
#[ktest]
fn enqueue_fast_path_sector_offset() {
    ensure_builtin_targets();
    let md = MemDisk::new("dmt010md0", 0, 4096);

    let mut table = DmTable::new();
    table.add_target(0, 256, "linear", "dmt010md0 16").unwrap();
    let dm = create_dm_with_table(table);

    // Write one block (8 sectors) at DM sector 8 -> underlying sector 24.
    let pattern = vec![0x5au8; BLOCK_SIZE];
    let status = dm_write(&dm, 8, 1, &pattern);
    assert_eq!(status, BioStatus::Complete);

    // The data must land at sector 24 (= 8 + 16), i.e. byte offset 12288.
    let mut buf = vec![0u8; BLOCK_SIZE];
    md.read_bytes(24 * 512, &mut buf);
    assert_eq!(buf, pattern);
    // No splitting happened.
    assert_eq!(md.enqueues(), 1);

    // Read back through the DM device.
    let (status, data) = dm_read(&dm, 8, 1);
    assert_eq!(status, BioStatus::Complete);
    assert_eq!(data, pattern);
    assert_eq!(md.enqueues(), 2);
}

/// Slow path: a bio crossing a target boundary is split, and each piece
/// lands at the right place on the underlying device.
#[ktest]
fn enqueue_split_across_targets() {
    ensure_builtin_targets();
    let md = MemDisk::new("dmt010md1", 1, 4096);

    let mut table = DmTable::new();
    table.add_target(0, 16, "linear", "dmt010md1 0").unwrap();
    table
        .add_target(16, 16, "linear", "dmt010md1 1024")
        .unwrap();
    let dm = create_dm_with_table(table);

    // Write 16 sectors at DM sector 8: covers [8, 16) on target 0 (mapped
    // to underlying [8, 16)) and [16, 24) on target 1 (mapped to [1024,
    // 1032)).
    let mut pattern = vec![0xaau8; 2 * BLOCK_SIZE];
    pattern[BLOCK_SIZE..].fill(0xbb);
    let status = dm_write(&dm, 8, 2, &pattern);
    assert_eq!(status, BioStatus::Complete);

    let mut buf = vec![0u8; BLOCK_SIZE];
    md.read_bytes(8 * 512, &mut buf);
    assert_eq!(buf, vec![0xaau8; BLOCK_SIZE]);
    md.read_bytes(1024 * 512, &mut buf);
    assert_eq!(buf, vec![0xbbu8; BLOCK_SIZE]);
    assert_eq!(md.enqueues(), 2);

    // Read back across the boundary through the DM device.
    let (status, data) = dm_read(&dm, 8, 2);
    assert_eq!(status, BioStatus::Complete);
    assert_eq!(data, pattern);
    assert_eq!(md.enqueues(), 4);
}

/// Slow path: a bio is split on the per-target `max_io_len` boundaries even
/// within a single target.
#[ktest]
fn enqueue_split_on_max_io_len() {
    ensure_chunked_target();
    let md = MemDisk::new("dmt010md2", 2, 4096);

    let mut table = DmTable::new();
    table
        .add_target(0, 64, CHUNKED_NAME, "dmt010md2 100")
        .unwrap();
    let dm = create_dm_with_table(table);

    // 32 sectors with max_io_len = 8 -> four pieces [0,8) [8,16) [16,24)
    // [24,32), mapped contiguously to underlying sectors 100..132.
    let mut pattern = vec![0u8; 4 * BLOCK_SIZE];
    for (i, byte) in pattern.iter_mut().enumerate() {
        *byte = (i / BLOCK_SIZE) as u8 + 1;
    }
    let status = dm_write(&dm, 0, 4, &pattern);
    assert_eq!(status, BioStatus::Complete);
    assert_eq!(md.enqueues(), 4);

    let mut buf = vec![0u8; 4 * BLOCK_SIZE];
    md.read_bytes(100 * 512, &mut buf);
    assert_eq!(buf, pattern);

    let (status, data) = dm_read(&dm, 0, 4);
    assert_eq!(status, BioStatus::Complete);
    assert_eq!(data, pattern);
    assert_eq!(md.enqueues(), 8);
}

/// C2: a negative remapping (mapped sector < bio start sector) cannot be
/// expressed via `sid_offset`, so the bio must take the copy-based slow
/// path and still land correctly.
#[ktest]
fn enqueue_negative_remap_uses_slow_path() {
    ensure_builtin_targets();
    let md = MemDisk::new("dmt010md3", 3, 4096);

    let mut table = DmTable::new();
    // Filler target so that the second target can start at sector 1000
    // (tables must be adjoined); it maps far away and is never touched.
    table
        .add_target(0, 1000, "linear", "dmt010md3 2048")
        .unwrap();
    table.add_target(1000, 16, "linear", "dmt010md3 0").unwrap();
    let dm = create_dm_with_table(table);

    // DM sector [1000, 1008) maps to underlying sector 0, which is less
    // than the bio start sector: fast path cannot express this.
    let pattern = vec![0xc3u8; BLOCK_SIZE];
    let status = dm_write(&dm, 1000, 1, &pattern);
    assert_eq!(status, BioStatus::Complete);
    assert_eq!(md.enqueues(), 1);

    let mut buf = vec![0u8; BLOCK_SIZE];
    md.read_bytes(0, &mut buf);
    assert_eq!(buf, pattern);

    let (status, data) = dm_read(&dm, 1000, 1);
    assert_eq!(status, BioStatus::Complete);
    assert_eq!(data, pattern);
    assert_eq!(md.enqueues(), 2);
}

/// Slow path with a piece owned by an error target: the bio is completed
/// with an error status, and the successfully mapped piece is still
/// written.
#[ktest]
fn enqueue_split_with_error_piece() {
    ensure_builtin_targets();
    let md = MemDisk::new("dmt010md4", 4, 4096);

    let mut table = DmTable::new();
    table.add_target(0, 16, "linear", "dmt010md4 0").unwrap();
    table.add_target(16, 16, "error", "").unwrap();
    let dm = create_dm_with_table(table);

    let pattern = vec![0x7eu8; 2 * BLOCK_SIZE];
    let status = dm_write(&dm, 8, 2, &pattern);
    assert_eq!(status, BioStatus::IoError);

    // The first piece ([8, 16) on target 0) was still written.
    let mut buf = vec![0u8; BLOCK_SIZE];
    md.read_bytes(8 * 512, &mut buf);
    assert_eq!(buf, vec![0x7eu8; BLOCK_SIZE]);
    assert_eq!(md.enqueues(), 1);
}

/// Suspend defers the *whole* bio before splitting; resume replays it
/// against the current table.
#[ktest]
fn suspended_bio_replayed_on_resume() {
    ensure_builtin_targets();
    let md = MemDisk::new("dmt010md5", 5, 4096);

    let mut table = DmTable::new();
    table.add_target(0, 256, "linear", "dmt010md5 32").unwrap();
    let dm = create_dm_with_table(table);

    dm.suspend();
    assert!(dm.is_suspended());

    let pattern = vec![0x11u8; BLOCK_SIZE];
    let seg = BioSegment::alloc(1, BioDirection::ToDevice);
    {
        let slice = seg.inner_dma_slice();
        let mut writer = slice.writer().unwrap();
        writer.write(&mut VmReader::from(&pattern[..]));
    }
    let bio = Bio::new(BioType::Write, Sid::new(8), vec![seg], None);
    let mut batch = IoBatch::new();
    // The bio is accepted but deferred: nothing reaches the disk yet.
    bio.submit(dm.as_ref(), &mut batch).unwrap();
    assert_eq!(md.enqueues(), 0);

    dm.resume();
    batch.wait_all().unwrap();
    assert_eq!(md.enqueues(), 1);

    // Mapped to underlying sector 32 + 8 = 40.
    let mut buf = vec![0u8; BLOCK_SIZE];
    md.read_bytes(40 * 512, &mut buf);
    assert_eq!(buf, pattern);
}

// ==================================================================
// Striped target tests (T-011)
// ==================================================================

fn ensure_striped_target() {
    // Ignore "already registered" errors.
    let _ = register_target(Arc::new(StripedTargetType::new()));
}

fn striped_type() -> Arc<dyn TargetType> {
    ensure_striped_target();
    lookup_target("striped").expect("striped target should be registered")
}

#[ktest]
fn striped_ctr_rejects_bad_params() {
    let striped = striped_type();
    ensure_dummy_device();
    ensure_dummy_device1();

    // Too few arguments.
    assert!(striped.ctr(16, &[]).is_err());
    assert!(striped.ctr(16, &["2"]).is_err());

    // stripes == 0 (must be rejected before any division by `stripes`).
    assert!(striped.ctr(16, &["0", "8"]).is_err());
    // Non-decimal / negative stripe counts.
    assert!(striped.ctr(16, &["x2", "8"]).is_err());
    assert!(striped.ctr(16, &["-2", "8"]).is_err());
    // Stripe count overflowing u32.
    assert!(striped.ctr(16, &["4294967296", "8"]).is_err());

    // chunk_size == 0 (must be rejected before any division by it).
    assert!(striped.ctr(16, &["2", "0"]).is_err());
    // Non-decimal chunk size.
    assert!(striped.ctr(16, &["2", "8x"]).is_err());

    // Target length not divisible by the number of stripes.
    assert!(
        striped
            .ctr(
                10,
                &[
                    "3",
                    "1",
                    DUMMY_DEV_NAME,
                    "0",
                    DUMMY_DEV_NAME,
                    "0",
                    DUMMY_DEV_NAME,
                    "0"
                ]
            )
            .is_err()
    );

    // Stripe width not divisible by the chunk size (width = 16/2 = 8, 8 % 5 != 0).
    assert!(
        striped
            .ctr(16, &["2", "5", DUMMY_DEV_NAME, "0", DUMMY_DEV_NAME1, "0"])
            .is_err()
    );

    // argc != 2 + 2 * stripes: too few legs / too many legs.
    assert!(striped.ctr(16, &["2", "8", DUMMY_DEV_NAME, "0"]).is_err());
    assert!(
        striped
            .ctr(
                16,
                &[
                    "2",
                    "8",
                    DUMMY_DEV_NAME,
                    "0",
                    DUMMY_DEV_NAME1,
                    "0",
                    DUMMY_DEV_NAME,
                    "0"
                ]
            )
            .is_err()
    );

    // Non-decimal / negative / empty leg offsets.
    assert!(
        striped
            .ctr(
                16,
                &["2", "8", DUMMY_DEV_NAME, "12a3", DUMMY_DEV_NAME1, "0"]
            )
            .is_err()
    );
    assert!(
        striped
            .ctr(16, &["2", "8", DUMMY_DEV_NAME, "-1", DUMMY_DEV_NAME1, "0"])
            .is_err()
    );
    assert!(
        striped
            .ctr(16, &["2", "8", DUMMY_DEV_NAME, "", DUMMY_DEV_NAME1, "0"])
            .is_err()
    );

    // Unknown underlying device.
    assert!(
        striped
            .ctr(
                16,
                &["2", "8", "no_such_dev_xyz", "0", DUMMY_DEV_NAME1, "0"]
            )
            .is_err()
    );
}

#[ktest]
fn striped_ctr_success() {
    let striped = striped_type();
    ensure_dummy_device();
    ensure_dummy_device1();

    let outcome = striped
        .ctr(
            64,
            &["2", "8", DUMMY_DEV_NAME, "100", DUMMY_DEV_NAME1, "200"],
        )
        .unwrap();
    // The per-target max_io_len equals the chunk size (cf. Linux
    // `dm_set_target_max_io_len`).
    assert_eq!(outcome.max_io_len, 8);

    let p = outcome
        .private
        .downcast_ref::<StripedPrivate>()
        .expect("striped ctr should produce StripedPrivate");
    assert_eq!(p.stripes, 2);
    assert_eq!(p.chunk_size, 8);
    assert_eq!(p.legs.len(), 2);
    assert_eq!(p.legs[0].dev.name(), DUMMY_DEV_NAME);
    assert_eq!(p.legs[0].physical_start, 100);
    assert_eq!(p.legs[1].dev.name(), DUMMY_DEV_NAME1);
    assert_eq!(p.legs[1].physical_start, 200);

    // "/dev/"-prefixed device names are accepted too.
    assert!(
        striped
            .ctr(
                64,
                &["2", "8", "/dev/dmtestdummy0", "0", "/dev/dmtestdummy1", "0"]
            )
            .is_ok()
    );
}

/// Striped mapping with a power-of-2 geometry (stripes = 2, chunk = 8).
#[ktest]
fn striped_map_formula_pow2() {
    let striped = striped_type();
    ensure_dummy_device();
    ensure_dummy_device1();

    let outcome = striped
        .ctr(
            64,
            &["2", "8", DUMMY_DEV_NAME, "100", DUMMY_DEV_NAME1, "200"],
        )
        .unwrap();
    let p = &*outcome.private;

    // (sector_in_target, expected leg device, expected absolute sector)
    let cases: &[(u64, &str, u64)] = &[
        (0, DUMMY_DEV_NAME, 100),   // stripe 0, dev_sector 0
        (7, DUMMY_DEV_NAME, 107),   // last sector of chunk 0
        (8, DUMMY_DEV_NAME1, 200),  // stripe 1, dev_sector 0
        (15, DUMMY_DEV_NAME1, 207), // last sector of chunk 1
        (16, DUMMY_DEV_NAME, 108),  // stripe wraps to 0, dev_sector 8
        (24, DUMMY_DEV_NAME1, 208), // stripe 1, dev_sector 8
        (63, DUMMY_DEV_NAME1, 231), // stripe 1, dev_sector 31
    ];
    for &(sector, dev_name, expected) in cases {
        let mapped = striped.map(p, sector).unwrap();
        assert_eq!(mapped.device.name(), dev_name, "sector {}", sector);
        assert_eq!(mapped.sector, expected, "sector {}", sector);
    }
}

/// Striped mapping with a non-power-of-2 geometry (stripes = 3, chunk = 10),
/// exercising the div/mod path (Linux's `sector_div` fallback).
#[ktest]
fn striped_map_formula_non_pow2() {
    let striped = striped_type();
    ensure_dummy_device();
    ensure_dummy_device1();
    ensure_dummy_device_named("dmtestdummy2", 252);

    let outcome = striped
        .ctr(
            90,
            &[
                "3",
                "10",
                DUMMY_DEV_NAME,
                "0",
                DUMMY_DEV_NAME1,
                "1000",
                "dmtestdummy2",
                "2000",
            ],
        )
        .unwrap();
    let p = &*outcome.private;

    // (sector_in_target, expected leg device, expected absolute sector)
    let cases: &[(u64, &str, u64)] = &[
        (0, DUMMY_DEV_NAME, 0),      // stripe 0, dev_sector 0
        (9, DUMMY_DEV_NAME, 9),      // last sector of chunk 0
        (10, DUMMY_DEV_NAME1, 1000), // stripe 1, dev_sector 0
        (19, DUMMY_DEV_NAME1, 1009), // last sector of chunk 1
        (20, "dmtestdummy2", 2000),  // stripe 2, dev_sector 0
        (29, "dmtestdummy2", 2009),  // last sector of chunk 2
        (30, DUMMY_DEV_NAME, 10),    // stripe wraps to 0, dev_sector 10
        (40, DUMMY_DEV_NAME1, 1010), // stripe 1, dev_sector 10
        (89, "dmtestdummy2", 2029),  // stripe 2, dev_sector 29
    ];
    for &(sector, dev_name, expected) in cases {
        let mapped = striped.map(p, sector).unwrap();
        assert_eq!(mapped.device.name(), dev_name, "sector {}", sector);
        assert_eq!(mapped.sector, expected, "sector {}", sector);
    }
}

#[ktest]
fn striped_status_table() {
    let striped = striped_type();
    ensure_dummy_device();
    ensure_dummy_device1();

    let outcome = striped
        .ctr(64, &["2", "8", DUMMY_DEV_NAME, "0", DUMMY_DEV_NAME1, "300"])
        .unwrap();
    // STATUSTYPE_TABLE: "<stripes> <chunk_size> [<dev_name> <physical_start>]+"
    // with bare kernel device names (no "/dev/" prefix).
    assert_eq!(
        striped.status(&*outcome.private),
        "2 8 dmtestdummy0 0 dmtestdummy1 300"
    );
}

#[ktest]
fn striped_registered_in_registry() {
    ensure_striped_target();

    let looked_up = lookup_target("striped").expect("striped target should be registered");
    assert_eq!(looked_up.name(), "striped");
    assert_eq!(looked_up.version().to_dm_version(), (1 << 16) | (6 << 8));

    // The snapshot (backing DM_LIST_VERSIONS) covers striped 1.6.0.
    let snapshot = snapshot_targets();
    assert!(
        snapshot
            .iter()
            .any(|(name, ver)| name == "striped" && ver.to_dm_version() == (1 << 16) | (6 << 8))
    );
}
