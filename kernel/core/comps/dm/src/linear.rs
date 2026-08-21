// SPDX-License-Identifier: MPL-2.0

//! Linear target implementation

use alloc::boxed::Box;

use crate::target::{TargetType, TargetVersion};

/// The linear target type singleton (for registration)
pub struct LinearTargetType;

impl LinearTargetType {
    /// Get the singleton instance
    pub const fn new() -> Self {
        LinearTargetType
    }

    /// Create a concrete linear target instance for use in DmDevice
    pub fn create_target(&self, offset: u64) -> crate::table::TargetPrivate {
        crate::table::TargetPrivate::new(offset)
    }
}

impl TargetType for LinearTargetType {
    fn name(&self) -> &str {
        "linear"
    }

    fn version(&self) -> TargetVersion {
        TargetVersion::new(1, 0, 0)
    }

    fn ctr(&self, params: &[&str]) -> Result<Box<dyn core::any::Any>, &'static str> {
        if params.len() != 1 {
            return Err("linear: expected exactly 1 parameter (offset)");
        }
        let offset_str = params[0];
        if offset_str.is_empty() {
            return Err("linear: offset parameter is empty");
        }
        // Strictly validate: must be decimal digits only
        for c in offset_str.chars() {
            if !c.is_ascii_digit() {
                return Err("linear: offset must be a non-negative decimal integer");
            }
        }
        match offset_str.parse::<u64>() {
            Ok(offset) => {
                // Create target private data (no underlying device yet)
                let priv_data = crate::table::TargetPrivate::new(offset);
                Ok(Box::new(priv_data))
            }
            Err(_) => Err("linear: invalid offset"),
        }
    }

    fn dtr(&self, _private: &mut dyn core::any::Any) {
        // Nothing to do
    }

    fn map(&self, private: &dyn core::any::Any, sector: u64) -> Result<u64, &'static str> {
        let priv_data = private
            .downcast_ref::<crate::table::TargetPrivate>()
            .ok_or("invalid target private type")?;
        Ok(priv_data.map_sector(sector))
    }

    fn status(&self, _private: &dyn core::any::Any) -> &'static str {
        "linear"
    }
}

/// Register the linear target type globally
pub fn register_linear_target() -> Result<(), &'static str> {
    super::register_target(Box::new(LinearTargetType::new()))
}
