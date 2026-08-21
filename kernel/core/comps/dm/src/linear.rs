// SPDX-License-Identifier: MPL-2.0

//! Linear target implementation

use alloc::boxed::Box;

use super::{target::{TargetPrivate, TargetType, TargetVersion}};

/// Linear target private data
pub struct LinearTarget {
    /// Offset to add to incoming sector
    offset: u64,
}

impl LinearTarget {
    /// Parse parameters for linear target
    ///
    /// Expected format: "<offset>" (single decimal parameter)
    pub fn parse_params(params: &[&str]) -> Result<u64, &'static str> {
        if params.len() != 1 {
            return Err("linear: expected exactly 1 parameter");
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
            Ok(offset) => Ok(offset),
            Err(_) => Err("linear: invalid offset"),
        }
    }

    /// Create a new linear target
    pub fn new(offset: u64) -> Self {
        Self { offset }
    }

    /// Map a sector through this linear target
    pub fn map_sector(&self, sector: u64) -> u64 {
        self.offset + sector
    }
}

impl TargetPrivate for LinearTarget {}

/// The linear target type singleton
pub struct LinearTargetType;

impl LinearTargetType {
    /// Get the singleton instance
    pub const fn new() -> Self {
        LinearTargetType
    }
}

impl TargetType for LinearTargetType {
    fn name(&self) -> &str {
        "linear"
    }

    fn version(&self) -> TargetVersion {
        TargetVersion::new(1, 0, 0)
    }

    fn ctr(&self, params: &[&str]) -> Result<Box<dyn TargetPrivate>, &'static str> {
        let offset = LinearTarget::parse_params(params)?;
        Ok(Box::new(LinearTarget::new(offset)))
    }

    fn dtr(&self, _private: &mut dyn TargetPrivate) {
        // Nothing to do
    }

    #[allow(unsafe_code)]
    fn map(&self, private: &dyn TargetPrivate, sector: u64) -> Result<u64, &'static str> {
        let linear = unsafe { &*(private as *const dyn TargetPrivate as *const LinearTarget) };
        Ok(linear.map_sector(sector))
    }

    fn status(&self, _private: &dyn TargetPrivate) -> &'static str {
        "linear"
    }
}

/// Register the linear target type globally
pub fn register_linear_target() -> Result<(), &'static str> {
    super::register_target(Box::new(LinearTargetType::new()))
}

#[cfg(ktest)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_params_valid() {
        assert_eq!(LinearTarget::parse_params(&["0"]).unwrap(), 0);
        assert_eq!(LinearTarget::parse_params(&["123"]).unwrap(), 123);
        assert_eq!(LinearTarget::parse_params(&["9999999999"]).unwrap(), 9999999999);
    }

    #[test]
    fn test_parse_params_invalid() {
        assert!(LinearTarget::parse_params(&[]).is_err());
        assert!(LinearTarget::parse_params(&["abc"]).is_err());
        assert!(LinearTarget::parse_params(&["123abc"]).is_err());
        assert!(LinearTarget::parse_params(&["-1"]).is_err());
    }

    #[test]
    fn test_map_sector() {
        let target_type = LinearTargetType::new();
        let private = target_type.ctr(&["100"]).unwrap();

        assert_eq!(target_type.map(private.as_ref(), 50).unwrap(), 150);
        assert_eq!(target_type.map(private.as_ref(), 0).unwrap(), 100);
        assert_eq!(target_type.map(private.as_ref(), 1000).unwrap(), 1100);
    }

    #[test]
    fn test_target_registration() {
        let target_type = LinearTargetType::new();
        assert_eq!(target_type.name(), "linear");
        assert_eq!(target_type.version().major, 1);
    }
}
