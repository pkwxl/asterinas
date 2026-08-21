// SPDX-License-Identifier: MPL-2.0

//! DM table management

use alloc::{sync::Arc, vec::Vec};
use core::fmt::Debug;

use aster_block::{BlockDevice, BlockDeviceMeta};

use crate::target::{TargetType, TargetVersion};

/// Private data for a target instance
#[derive(Clone)]
pub struct TargetPrivate {
    /// The offset to add to incoming sectors (for linear target)
    pub offset: u64,
    /// Underlying block device (placeholder, not used yet)
    #[allow(dead_code)]
    underlying: Option<Arc<dyn BlockDevice>>,
}

impl TargetPrivate {
    /// Create new private data with offset
    pub fn new(offset: u64) -> Self {
        Self { 
            offset, 
            underlying: None,
        }
    }

    /// Set the underlying device
    pub fn set_underlying(&mut self, dev: Arc<dyn BlockDevice>) {
        self.underlying = Some(dev);
    }

    /// Map a sector through this target (for linear target)
    pub fn map_sector(&self, sector: u64) -> u64 {
        self.offset + sector
    }

    /// Get the underlying device if set
    pub fn underlying(&self) -> Option<&Arc<dyn BlockDevice>> {
        self.underlying.as_ref()
    }
}

/// A single target in the table
#[derive(Clone)]
pub struct DmTarget {
    /// Start sector (inclusive)
    pub begin: u64,
    /// Length in sectors
    pub len: u64,
    /// The target type
    #[allow(dead_code)]
    pub target_type: &'static dyn TargetType,
    /// Private data for this target instance
    pub private: Option<TargetPrivate>,
}

impl DmTarget {
    /// Create a new target
    pub fn new(
        begin: u64,
        len: u64,
        target_type: &'static dyn TargetType,
        private: Option<TargetPrivate>,
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
    pub fn map_sector(&self, sector: u64) -> Result<u64, &'static str> {
        if !self.contains(sector) {
            return Err("Sector out of range");
        }
        match &self.private {
            Some(priv_data) => Ok(priv_data.map_sector(sector)),
            None => Err("Target has no private data"),
        }
    }
}

/// DM table consisting of multiple targets
#[derive(Clone)]
pub struct DmTable {
    /// Targets in the table
    #[allow(dead_code)]
    targets: Vec<DmTarget>,
    /// Total length in sectors
    nr_sectors: u64,
}

impl Debug for DmTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DmTable")
            .field("nr_sectors", &self.nr_sectors)
            .finish()
    }
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
        target.map_sector(sector)
    }

    /// Get metadata (nr_sectors only for now)
    pub fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: 1,
            nr_sectors: self.nr_sectors as usize,
        }
    }
}
