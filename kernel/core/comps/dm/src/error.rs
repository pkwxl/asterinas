// SPDX-License-Identifier: MPL-2.0

//! Error target implementation and DM error type

use alloc::{boxed::Box, string::String};
use core::any::Any;

use crate::target::{CtrOutcome, MappedIo, TargetType, TargetVersion};

/// The error target type singleton (for registration).
///
/// Every I/O mapped through an error target fails; it is used as a
/// placeholder table during device suspension transitions.
pub struct ErrorTargetType;

impl ErrorTargetType {
    /// Get the singleton instance
    pub const fn new() -> Self {
        ErrorTargetType
    }
}

/// Private data of an error target instance (stateless).
struct ErrorPrivate;

impl TargetType for ErrorTargetType {
    fn name(&self) -> &str {
        "error"
    }

    fn version(&self) -> TargetVersion {
        TargetVersion::new(1, 0, 0)
    }

    fn ctr(
        &self,
        _len: u64,
        params: &[&str],
    ) -> core::result::Result<CtrOutcome, &'static str> {
        if !params.is_empty() {
            return Err("error: expected no parameters");
        }
        Ok(CtrOutcome {
            private: Box::new(ErrorPrivate),
            max_io_len: 0,
        })
    }

    fn map(
        &self,
        _private: &dyn Any,
        _sector_in_target: u64,
    ) -> core::result::Result<MappedIo, &'static str> {
        Err("error target: I/O error")
    }

    fn status(&self, _private: &dyn Any) -> String {
        String::new()
    }
}

/// DM-specific error type
#[derive(Debug)]
pub struct DmError {
    errno: i32,
}

impl DmError {
    /// Create a new DM error with the given errno
    pub fn new(errno: i32) -> Self {
        Self { errno }
    }

    /// Get the errno value
    pub fn errno(&self) -> i32 {
        self.errno
    }
}

/// Result type for DM operations (currently unused but kept for future use)
#[expect(dead_code)]
pub type Result<T> = core::result::Result<T, DmError>;
