// SPDX-License-Identifier: MPL-2.0

//! DM table management

use alloc::{boxed::Box, vec::Vec};

use crate::target::{TargetType, TargetPrivate};

/// A single target in the table
pub struct DmTarget {
    /// Start sector (inclusive)
    pub begin: u64,
    /// Length in sectors
    pub len: u64,
    /// The target type
    pub target_type: &'static dyn TargetType,
    /// Private data for this target instance
    pub private: Option<Box<dyn TargetPrivate>>,
}

impl DmTarget {
    /// Create a new target
    pub fn new(
        begin: u64,
        len: u64,
        target_type: &'static dyn TargetType,
        private: Option<Box<dyn TargetPrivate>>,
    ) -> Self {
        Self { begin, len, target_type, private }
    }

    /// Get the end sector (exclusive)
    pub fn end(&self) -> u64 {
        self.begin + self.len
    }

    /// Check if a sector is within this target
    pub fn contains(&self, sector: u64) -> bool {
        self.begin <= sector && sector < self.end()
    }

    /// Map a sector through this target
    pub fn map(&self, sector: u64) -> Result<u64, &'static str> {
        if !self.contains(sector) {
            return Err("Sector out of range");
        }
        self.target_type.map(self.private.as_ref().unwrap().as_ref(), sector)
    }
}

/// DM table consisting of multiple targets
pub struct DmTable {
    /// Targets in the table
    targets: Vec<DmTarget>,
    /// Total length in sectors
    nr_sectors: u64,
}

impl DmTable {
    /// Create a new empty table
    pub fn new() -> Self {
        Self {
            targets: Vec::new(),
            nr_sectors: 0,
        }
    }

    /// Add a target to the table
    ///
    /// The target's begin must match the current table size (无缝adjoin).
    pub fn add_target(&mut self, target: DmTarget) -> Result<(), &'static str> {
        if target.begin != self.nr_sectors {
            return Err("Targets must be adjoin (begin must equal current nr_sectors)");
        }
        self.targets.push(target);
        self.nr_sectors += self.targets.last().unwrap().len;
        Ok(())
    }

    /// Find the target containing a sector
    pub fn find_target(&self, sector: u64) -> Option<&DmTarget> {
        self.targets.iter().find(|t| t.contains(sector))
    }

    /// Get total length in sectors
    pub fn nr_sectors(&self) -> u64 {
        self.nr_sectors
    }

    /// Map a sector through the table
    pub fn map_sector(&self, sector: u64) -> Result<u64, &'static str> {
        let target = self.find_target(sector).ok_or("Sector out of range")?;
        target.map(sector)
    }
}

