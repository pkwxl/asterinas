// SPDX-License-Identifier: MPL-2.0

//! Error handling for DM

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
