// SPDX-License-Identifier: MPL-2.0

//! Target type abstraction and registry for DM

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::any::Any;

use aster_block::BlockDevice;
use ostd::sync::SpinLock;

/// The name of a target type (e.g., "linear", "error")
pub type TargetTypeName = str;

/// Version number triple
#[derive(Clone, Copy)]
pub struct TargetVersion {
    /// Major version
    pub major: u32,
    /// Minor version
    pub minor: u32,
    /// Patch version
    pub patch: u32,
}

impl TargetVersion {
    /// Create a new version
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Convert to Linux DM version format: (major << 16) | (minor << 8) | patch
    pub fn to_dm_version(&self) -> u32 {
        (self.major << 16) | (self.minor << 8) | self.patch
    }
}

/// The outcome of a target constructor (`TargetType::ctr`):
/// the target's private data plus its per-target `max_io_len`
/// (in sectors; 0 means "no limit", cf. Linux `dm_set_target_max_io_len`).
pub struct CtrOutcome {
    /// Private data of the constructed target instance.
    pub private: Box<dyn Any + Send + Sync>,
    /// Maximum I/O length in sectors for this target instance (0 = unlimited).
    pub max_io_len: u64,
}

/// The result of mapping a sector through a target:
/// the underlying device to forward to and the absolute sector on it.
pub struct MappedIo {
    /// The underlying block device selected by the target.
    pub device: Arc<dyn BlockDevice>,
    /// The absolute sector on the underlying device.
    pub sector: u64,
}

/// Target type definition
pub trait TargetType: Send + Sync {
    /// Return the name of this target type
    fn name(&self) -> &TargetTypeName;

    /// Return the version of this target type
    fn version(&self) -> TargetVersion;

    /// Construct a new target instance.
    ///
    /// - `len`: the length (in sectors) of this target in the DM device
    ///   (needed by e.g. striped ctr validation, cf. Linux `ti->len`).
    /// - `params`: space-separated tokens from the ctr table line.
    ///
    /// Returns the private data and the per-target `max_io_len` on success.
    fn ctr(&self, len: u64, params: &[&str]) -> Result<CtrOutcome, &'static str>;

    /// Destruct a target instance. The default implementation simply drops
    /// the private data.
    fn dtr(&self, _private: Box<dyn Any + Send + Sync>) {}

    /// Map a sector through this target.
    ///
    /// `sector_in_target` is relative to the target's begin sector (the caller
    /// has already subtracted `begin` and verified the sector is in range),
    /// matching Linux's `map(sector - ti->begin)` semantics.
    ///
    /// Returns the underlying device and the absolute sector on it;
    /// error targets return `Err` here.
    fn map(&self, private: &dyn Any, sector_in_target: u64) -> Result<MappedIo, &'static str>;

    /// Get the STATUSTYPE_TABLE parameter string for this target instance
    /// (without the target type name itself), e.g. "vdd 2048" for linear.
    fn status(&self, private: &dyn Any) -> String;
}

/// Global registry of target types
struct Registry {
    targets: Vec<Arc<dyn TargetType>>,
}

impl Registry {
    fn register(&mut self, target_type: Arc<dyn TargetType>) -> Result<(), &'static str> {
        if self
            .targets
            .iter()
            .any(|t| t.name() == target_type.name())
        {
            return Err("Target type already registered");
        }
        self.targets.push(target_type);
        Ok(())
    }
}

static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry {
    targets: Vec::new(),
});

/// Register a target type globally
pub fn register_target(target_type: Arc<dyn TargetType>) -> Result<(), &'static str> {
    REGISTRY.lock().register(target_type)
}

/// Lookup a target type by name.
///
/// The `Arc` is cloned while holding the lock and returned to the caller,
/// so there is no lifetime tied to the registry lock.
pub fn lookup_target(name: &str) -> Option<Arc<dyn TargetType>> {
    REGISTRY
        .lock()
        .targets
        .iter()
        .find(|t| t.name() == name)
        .cloned()
}

/// Take a snapshot of the registry as (name, version) pairs.
///
/// Used by the control plane to implement DM_LIST_VERSIONS.
pub fn snapshot_targets() -> Vec<(String, TargetVersion)> {
    REGISTRY
        .lock()
        .targets
        .iter()
        .map(|t| (String::from(t.name()), t.version()))
        .collect()
}
