// SPDX-License-Identifier: MPL-2.0

//! Error target implementation

use alloc::string::String;
use core::any::Any;

use crate::target::{CtrOutcome, MappedIo, TargetType, TargetVersion};

/// The error target type singleton (for registration).
///
/// Every I/O mapped through an error target fails. As in Linux
/// (`io_err_ctr`, dm-target.c), the target is reserved for internal use,
/// so its ctr always fails and user space can never load an error target.
pub struct ErrorTargetType;

impl ErrorTargetType {
    /// Get the singleton instance
    pub const fn new() -> Self {
        ErrorTargetType
    }
}

impl TargetType for ErrorTargetType {
    fn name(&self) -> &str {
        "error"
    }

    fn version(&self) -> TargetVersion {
        // Matches Linux's error target version (dm-target.c).
        TargetVersion::new(1, 7, 0)
    }

    fn ctr(&self, _len: u64, _params: &[&str]) -> Result<CtrOutcome, &'static str> {
        Err("error target is for internal use only")
    }

    fn map(
        &self,
        _private: &dyn Any,
        _sector_in_target: u64,
    ) -> Result<MappedIo, &'static str> {
        Err("error target: I/O error")
    }

    fn status(&self, _private: &dyn Any) -> String {
        String::new()
    }
}
