// SPDX-License-Identifier: MPL-2.0

//! Kernel-mode unit tests (ktest) for the DM core.
//!
//! Contract under test: `TargetType::map` receives a sector that has already
//! been translated into target-relative form (`abs_sector - begin`) and
//! returns a `MappedIo` (underlying device + absolute sector on it).

use alloc::{string::String, sync::Arc};

use aster_block::{
    BlockDevice, BlockDeviceMeta,
    bio::{BioEnqueueError, BioStatus, SubmittedBio},
};
use device_id::{DeviceId, MajorId, MinorId};
use ostd::prelude::*;

use crate::{
    DmTable, ErrorTargetType, LinearTargetType, TargetType, TargetVersion, lookup_target,
    register_target, snapshot_targets,
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

/// Register the dummy block device (idempotent) and return it.
fn ensure_dummy_device() -> Arc<dyn BlockDevice> {
    if let Some(dev) = aster_block::collect_all()
        .into_iter()
        .find(|d| d.name() == DUMMY_DEV_NAME)
    {
        return dev;
    }
    let dev = Arc::new(DummyDisk {
        name: String::from(DUMMY_DEV_NAME),
        id: DeviceId::new(MajorId::new(250), MinorId::new(250)),
    });
    aster_block::register(dev.clone()).unwrap();
    dev
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

    fn ctr(
        &self,
        _len: u64,
        _params: &[&str],
    ) -> Result<crate::CtrOutcome, &'static str> {
        Err("dummy: not constructible")
    }

    fn map(
        &self,
        _private: &dyn core::any::Any,
        _sector_in_target: u64,
    ) -> Result<crate::MappedIo, &'static str> {
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
    assert_eq!(looked_up.version().to_dm_version(), (9 << 16) | (8 << 8) | 7);

    // Unknown names yield None instead of panicking.
    assert!(lookup_target("no_such_target_xyz").is_none());

    // The snapshot covers the registered target.
    let snapshot = snapshot_targets();
    assert!(
        snapshot
            .iter()
            .any(|(name, ver)| name == "t010_dummy" && ver.to_dm_version() == (9 << 16) | (8 << 8) | 7)
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
    table.add_target(0, 100, "linear", "dmtestdummy0 2048").unwrap();
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
