// SPDX-License-Identifier: MPL-2.0

//! DM table management

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::fmt::Debug;

use aster_block::{BlockDevice, BlockDeviceMeta};

use crate::target::{TargetType, TargetVersion};

/// Private data for a target instance
#[derive(Clone, Debug)]
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

    /// Create error target private data (no offset mapping)
    pub fn new_error() -> Self {
        Self {
            offset: 0,
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
        Self {
            begin,
            len,
            target_type,
            private,
        }
    }

    /// Create an empty target (for intermediate construction)
    pub fn new_empty(begin: u64, len: u64) -> Self {
        Self {
            begin,
            len,
            target_type: &EMPTY_TARGET_TYPE,
            private: None,
        }
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

    /// Get the target type name
    pub fn type_name(&self) -> &str {
        self.target_type.name()
    }
}

/// Empty target type for intermediate construction
struct EmptyTargetType;

impl TargetType for EmptyTargetType {
    fn name(&self) -> &str {
        ""
    }

    fn version(&self) -> TargetVersion {
        TargetVersion::new(0, 0, 0)
    }

    fn ctr(&self, _params: &[&str]) -> Result<Box<dyn core::any::Any>, &'static str> {
        Err("Empty target type cannot be constructed")
    }

    fn dtr(&self, _private: &mut dyn core::any::Any) {}

    fn map(&self, _private: &dyn core::any::Any, _sector: u64) -> Result<u64, &'static str> {
        Err("Empty target type cannot map")
    }

    fn status(&self, _private: &dyn core::any::Any) -> &'static str {
        ""
    }
}

static EMPTY_TARGET_TYPE: EmptyTargetType = EmptyTargetType;

/// DM table consisting of multiple targets
#[derive(Clone)]
pub struct DmTable {
    /// Targets in the table
    targets: Vec<DmTarget>,
    /// Total length in sectors
    nr_sectors: u64,
}

impl Default for DmTable {
    fn default() -> Self {
        Self::new()
    }
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
        let new_end = target.end();
        if new_end <= self.nr_sectors {
            return Err("Target length must be positive");
        }
        self.targets.push(target);
        self.nr_sectors = new_end;
        Ok(())
    }

    /// Add a target with explicit begin for multi-spec loading
    ///
    /// This allows loading targets from multiple dm_target_spec entries
    /// where each spec may have a non-zero sector_start.
    pub fn add_target_with_begin(&mut self, begin: u64, len: u64) -> Result<(), &'static str> {
        if begin != self.nr_sectors {
            return Err("Targets must be adjoin (begin must equal current nr_sectors)");
        }
        let new_end = begin + len;
        if len == 0 {
            return Err("Target length must be positive");
        }
        self.targets.push(DmTarget::new_empty(begin, len));
        self.nr_sectors = new_end;
        Ok(())
    }

    /// Load targets from dm_target_spec structures
    ///
    /// Parses multiple dm_target_spec entries linked by the `next` field.
    /// Returns the number of targets loaded and the remaining data offset.
    pub fn load_from_specs(
        &mut self,
        specs: &[u8],
        _target_data: &[u8],
    ) -> Result<usize, &'static str> {
        let mut count = 0;
        let mut spec_offset = 0;

        while spec_offset < specs.len() {
            if spec_offset + 48 > specs.len() {
                return Err("dm_target_spec incomplete");
            }

            // Parse dm_target_spec (48 bytes)
            let sector_start = u64::from_le_bytes([
                specs[spec_offset],
                specs[spec_offset + 1],
                specs[spec_offset + 2],
                specs[spec_offset + 3],
                specs[spec_offset + 4],
                specs[spec_offset + 5],
                specs[spec_offset + 6],
                specs[spec_offset + 7],
            ]);
            let length = u64::from_le_bytes([
                specs[spec_offset + 8],
                specs[spec_offset + 9],
                specs[spec_offset + 10],
                specs[spec_offset + 11],
                specs[spec_offset + 12],
                specs[spec_offset + 13],
                specs[spec_offset + 14],
                specs[spec_offset + 15],
            ]);
            let _status = i32::from_le_bytes([
                specs[spec_offset + 16],
                specs[spec_offset + 17],
                specs[spec_offset + 18],
                specs[spec_offset + 19],
            ]);
            let next_spec = u32::from_le_bytes([
                specs[spec_offset + 20],
                specs[spec_offset + 21],
                specs[spec_offset + 22],
                specs[spec_offset + 23],
            ]) as usize;

            // Extract target type
            let target_type_start = spec_offset + 24;
            if target_type_start + 16 > specs.len() {
                return Err("target_type incomplete");
            }
            let target_type_bytes = &specs[target_type_start..target_type_start + 16];
            let null_pos = target_type_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(16);
            let target_type_str = core::str::from_utf8(&target_type_bytes[..null_pos])
                .map_err(|_| "invalid target_type")?;

            // Parse params (8-byte aligned after target_type)
            let params_offset = (next_spec + 7) & !7;
            if params_offset >= next_spec {
                return Err("params offset invalid");
            }

            let params_start = spec_offset + params_offset;
            if params_start >= specs.len() {
                return Err("params out of bounds");
            }

            // Find NUL terminator
            let mut params_len = 0;
            while params_start + params_len < specs.len()
                && specs[params_start + params_len] != 0
            {
                params_len += 1;
            }

            if params_start + params_len > next_spec {
                return Err("params extend beyond spec");
            }

            let params_str = core::str::from_utf8(&specs[params_start..params_start + params_len])
                .map_err(|_| "invalid params")?;

            // Create target
            if target_type_str == "linear" {
                self.add_linear_target(sector_start, length, params_str)?;
            } else if target_type_str == "error" {
                self.add_error_target(sector_start, length)?;
            } else {
                return Err("unsupported target type");
            }

            count += 1;

            // Move to next spec
            if next_spec == 0 {
                break;
            }
            spec_offset = next_spec;
        }

        Ok(count)
    }

    /// Add a linear target from parameters
    pub fn add_linear_target(
        &mut self,
        sector_start: u64,
        length: u64,
        params: &str,
    ) -> Result<(), &'static str> {
        // Parse "dev_path offset" format
        let parts: Vec<&str> = params.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return Err("linear: expected \"dev_path offset\"");
        }

        let offset_str = parts[1];
        let offset: u64 = offset_str.parse().map_err(|_| "invalid offset")?;

        // Note: sector_start is the target's position in the DM device
        // We don't add to self.nr_sectors here because caller handles adjoin validation

        // For now, we just track the target; underlying device resolved later
        let priv_data = TargetPrivate::new(offset);
        let target_type = crate::target::lookup_target("linear")
            .unwrap_or_else(|| panic!("linear target not registered"));

        let target = DmTarget::new(
            sector_start,
            length,
            target_type,
            Some(priv_data),
        );
        
        self.add_target(target)?;
        Ok(())
    }

    /// Add an error target
    pub fn add_error_target(&mut self, sector_start: u64, length: u64) -> Result<(), &'static str> {
        let target_type = crate::target::lookup_target("error")
            .unwrap_or_else(|| panic!("error target not registered"));
        let priv_data = TargetPrivate::new_error();
        let target = DmTarget::new(sector_start, length, target_type, Some(priv_data));
        self.add_target(target)?;
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

    /// Get all targets as a slice
    pub fn targets(&self) -> &[DmTarget] {
        &self.targets
    }
}
