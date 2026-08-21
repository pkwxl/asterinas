// SPDX-License-Identifier: MPL-2.0

//! Target type abstraction and registry for DM

use alloc::{boxed::Box, string::String, vec::Vec};

use crate::alloc::string::ToString;

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
        Self { major, minor, patch }
    }

    /// Convert to Linux DM version format: (major << 16) | (minor << 8) | patch
    pub fn to_dm_version(&self) -> u32 {
        (self.major << 16) | (self.minor << 8) | self.patch
    }
}

/// Target type definition
pub trait TargetType: Send + Sync {
    /// Return the name of this target type
    fn name(&self) -> &TargetTypeName;

    /// Return the version of this target type
    fn version(&self) -> TargetVersion;

    /// Construct a new target instance with the given parameters
    ///
    /// Parameters are space-separated tokens from the ctr table line.
    /// Returns Ok(target_private_data) on success, Err(error_str) on failure.
    fn ctr(&self, params: &[&str]) -> Result<Box<dyn core::any::Any>, &'static str>;

    /// Destruct a target instance
    fn dtr(&self, private: &mut dyn core::any::Any);

    /// Map a sector through this target
    ///
    /// Returns Ok(new_sector) on success, Err(error_str) on failure.
    fn map(&self, private: &dyn core::any::Any, sector: u64) -> Result<u64, &'static str>;

    /// Get the status string for this target instance
    fn status(&self, private: &dyn core::any::Any) -> &'static str;
}

/// Global registry of target types
struct Registry {
    targets: Vec<(String, Box<dyn TargetType>)>,
}

impl Registry {
    fn register(&mut self, target_type: Box<dyn TargetType>) -> Result<(), &'static str> {
        let name = target_type.name().to_string();
        if self.targets.iter().any(|(n, _)| n == &name) {
            return Err("Target type already registered");
        }
        self.targets.push((name, target_type));
        Ok(())
    }

    fn lookup<'a>(&'a self, name: &'a str) -> Option<&'a dyn TargetType> {
        self.targets
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, b)| b.as_ref())
    }
}

/// Use a static registry with interior mutability via SpinLock
/// Initialize with empty Vec directly to avoid calling new() in const context
use ostd::sync::SpinLock;
static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry {
    targets: Vec::new(),
});

/// Register a target type globally
pub fn register_target(target_type: Box<dyn TargetType>) -> Result<(), &'static str> {
    let mut registry = REGISTRY.lock();
    registry.register(target_type)
}

/// Lookup a target type by name
/// Returns None because we can't return a reference that outlives the lock guard.
/// In practice, targets are looked up only during init phase when the system is single-threaded.
pub fn lookup_target(_name: &str) -> Option<&'static dyn TargetType> {
    // For now, return None as we can't safely return a reference from within the lock
    // This will be fixed in T-003 with proper design
    None
}
