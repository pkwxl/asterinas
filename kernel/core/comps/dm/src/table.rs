// SPDX-License-Identifier: MPL-2.0

//! DM table management

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{any::Any, fmt::Debug};

use aster_block::BlockDeviceMeta;
use device_id::DeviceId;

use crate::target::{MappedIo, TargetType, lookup_target};

/// A single target in the table
#[derive(Clone)]
pub struct DmTarget {
    /// Start sector (inclusive)
    pub begin: u64,
    /// Length in sectors
    pub len: u64,
    /// The target type
    target_type: Arc<dyn TargetType>,
    /// Private data produced by the target's ctr (shared via `Arc` so that
    /// cloning a table stays cheap; the data itself is immutable after ctr).
    private: Arc<dyn Any + Send + Sync>,
    /// Maximum I/O length in sectors (0 = unlimited), cf. Linux
    /// `dm_set_target_max_io_len`.
    pub max_io_len: u64,
}

impl DmTarget {
    /// Get the end sector (exclusive)
    pub fn end(&self) -> u64 {
        self.begin + self.len
    }

    /// Check if a sector is within this target
    pub fn contains(&self, sector: u64) -> bool {
        self.begin <= sector && sector < self.end()
    }

    /// Map an absolute sector (in the DM device) through this target.
    ///
    /// Fails if the sector is out of this target's range or if the target
    /// itself rejects the mapping (e.g. the error target).
    pub fn map(&self, abs_sector: u64) -> Result<MappedIo, &'static str> {
        if !self.contains(abs_sector) {
            return Err("Sector out of range");
        }
        // Note: `&*self.private` (not `&self.private`) — passing the `Arc`
        // directly would make the `Arc` itself the concrete `Any` type and
        // break the target's downcast.
        self.target_type.map(&*self.private, abs_sector - self.begin)
    }

    /// Get the target type name
    pub fn type_name(&self) -> &str {
        self.target_type.name()
    }

    /// Get the STATUSTYPE_TABLE parameter string for this target
    pub fn status_params(&self) -> String {
        // See `map` for why `&*` is required here.
        self.target_type.status(&*self.private)
    }

    /// Return the device IDs of the underlying devices this target
    /// depends on (cf. `TargetType::deps`).
    pub fn deps(&self) -> Vec<DeviceId> {
        // See `map` for why `&*` is required here.
        self.target_type.deps(&*self.private)
    }

    /// Send a message to this target (cf. `TargetType::message`).
    pub fn message(&self, args: &[&str]) -> Result<Option<String>, &'static str> {
        // See `map` for why `&*` is required here.
        self.target_type.message(&*self.private, args)
    }
}

/// Maximum table/target length in sectors, cf. Linux `dm_table_add_target`'s
/// "too large device" check (`LLONG_MAX >> SECTOR_SHIFT`).
pub(crate) const MAX_SECTORS: u64 = (i64::MAX as u64) >> 9;

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

    /// The single entry point for adding a target to the table.
    ///
    /// Looks up the target type by name, tokenizes `params` on whitespace,
    /// runs the target's ctr, and appends the constructed target. The new
    /// target's `begin` must equal the current table size (adjoin) and its
    /// length must be positive.
    pub fn add_target(
        &mut self,
        begin: u64,
        len: u64,
        type_name: &str,
        params: &str,
    ) -> Result<(), &'static str> {
        if begin != self.nr_sectors {
            return Err("Targets must be adjoin (begin must equal current nr_sectors)");
        }
        if len == 0 {
            return Err("Target length must be positive");
        }
        if len > MAX_SECTORS {
            return Err("Target length too large");
        }
        if begin.checked_add(len).is_none() {
            return Err("Target end sector overflows");
        }
        let target_type = lookup_target(type_name).ok_or("Target type not registered")?;
        let tokens: Vec<&str> = params.split_whitespace().collect();
        let outcome = target_type.ctr(len, &tokens)?;
        self.targets.push(DmTarget {
            begin,
            len,
            target_type,
            private: outcome.private.into(),
            max_io_len: outcome.max_io_len,
        });
        self.nr_sectors = begin + len;
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

    /// Get metadata (nr_sectors only for now)
    pub fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            // The DM core accepts bios with any number of segments; see
            // `DmDevice::metadata` for the rationale.
            max_nr_segments_per_bio: usize::MAX,
            nr_sectors: self.nr_sectors as usize,
        }
    }

    /// Get all targets as a slice
    pub fn targets(&self) -> &[DmTarget] {
        &self.targets
    }

    /// Return the deduplicated list of underlying device IDs this table
    /// depends on (the data source of DM_TABLE_DEPS).
    pub fn deps(&self) -> Vec<DeviceId> {
        let mut deps = Vec::new();
        for target in &self.targets {
            for id in target.deps() {
                if !deps.contains(&id) {
                    deps.push(id);
                }
            }
        }
        deps
    }

    /// Send a message to the target that covers `sector` (the data-plane
    /// side of DM_TARGET_MSG). Fails if no target covers the sector or if
    /// the target does not support the message.
    pub fn message(&self, sector: u64, args: &[&str]) -> Result<Option<String>, &'static str> {
        let target = self
            .find_target(sector)
            .ok_or("no target covers the given sector")?;
        target.message(args)
    }
}
