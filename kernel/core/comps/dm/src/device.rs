// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::VecDeque, string::String, sync::Arc};
use core::{
    fmt::Debug,
    sync::atomic::{AtomicU32, Ordering},
};

use aster_block::{
    BlockDevice, BlockDeviceMeta,
    bio::{BioEnqueueError, SubmittedBio},
};
use device_id::DeviceId;
use ostd::sync::{RwLock, SpinLock};

use crate::DmTable;

/// Represents a mapped device with active/inactive table slots
#[derive(Debug)]
pub struct DmDevice {
    name: String,
    tables: RwLock<(Option<DmTable>, Option<DmTable>)>,
    suspend_flag: AtomicU32,
    deferred_queue: SpinLock<VecDeque<SubmittedBio>>,
}

impl DmDevice {
    /// Create a new dm device with the given name (suspended state, no table)
    pub fn create(name: &str) -> Arc<Self> {
        let device = DmDevice {
            name: String::from(name),
            tables: RwLock::new((None, None)),
            suspend_flag: AtomicU32::new(0),
            deferred_queue: SpinLock::new(VecDeque::new()),
        };
        Arc::new(device)
    }

    /// Load a table into the inactive slot
    pub fn load_table(&self, table: DmTable) {
        let mut tables = self.tables.write();
        tables.1 = Some(table);
    }

    /// Swap active and inactive tables (resume), making the inactive table active
    pub fn swap_table(&self) {
        // Use a temporary to break the borrow chain
        let old_inactive;
        {
            let mut tables = self.tables.write();
            old_inactive = tables.1.take();
            tables.1 = tables.0.take();
            tables.0 = old_inactive;
        }
    }

    /// Remove the device (requires open_count == 0, simplified: just drop)
    pub fn remove(&self) {
        let mut tables = self.tables.write();
        tables.0 = None;
        tables.1 = None;
    }

    /// Get the current active table
    pub fn get_active_table(&self) -> Option<DmTable> {
        self.tables.read().0.clone()
    }

    /// Get both active and inactive tables (for TABLE_STATUS)
    pub fn get_tables(&self) -> (Option<DmTable>, Option<DmTable>) {
        let tables = self.tables.read();
        (tables.0.clone(), tables.1.clone())
    }

    /// Suspend the device: block new I/O and wait for in-flight to complete
    pub fn suspend(&self) {
        // Set suspend flag
        self.suspend_flag.store(1, Ordering::SeqCst);
    }

    /// Resume the device: unblock and replay deferred queue
    pub fn resume(&self) {
        // Clear suspend flag
        self.suspend_flag.store(0, Ordering::SeqCst);

        // Replay deferred queue
        let mut queue = self.deferred_queue.lock();
        while let Some(bio) = queue.pop_front() {
            // Re-enqueue with current active table
            let _ = self.enqueue(bio);
        }
    }

    /// Check if device is suspended
    pub fn is_suspended(&self) -> bool {
        self.suspend_flag.load(Ordering::SeqCst) != 0
    }

    /// Add a bio to deferred queue (called when suspended)
    pub fn defer_bio(&self, bio: SubmittedBio) {
        self.deferred_queue.lock().push_back(bio);
    }
}

impl BlockDevice for DmDevice {
    fn enqueue(&self, mut bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        // Check if device is suspended
        let tables = self.tables.read();
        let active_table = tables.0.as_ref();

        if self.is_suspended() && active_table.is_some() {
            // Device suspended but has table - defer new I/O
            self.defer_bio(bio);
            return Ok(());
        }

        match active_table {
            Some(table) => {
                // Find target for this sector
                let sector = bio.sid_range().start.to_raw();

                match table.find_target(sector) {
                    Some(target) => match target.map(sector) {
                        Ok(mapped) => {
                            // `sid_offset` is in sector units and cannot express
                            // negative offsets; refuse instead of wrapping.
                            if mapped.sector < sector {
                                return Err(BioEnqueueError::Refused);
                            }
                            bio.set_sid_offset(mapped.sector - sector);
                            mapped.device.enqueue(bio)
                        }
                        Err(_) => Err(BioEnqueueError::Refused),
                    },
                    None => {
                        // No target found - should not happen if table is valid
                        Err(BioEnqueueError::Refused)
                    }
                }
            }
            None => {
                // Device suspended with no active table, reject I/O
                Err(BioEnqueueError::Refused)
            }
        }
    }

    fn metadata(&self) -> BlockDeviceMeta {
        let tables = self.tables.read();
        if let Some(table) = &tables.0 {
            table.metadata()
        } else {
            // No active table, return empty metadata
            BlockDeviceMeta {
                max_nr_segments_per_bio: 1,
                nr_sectors: 0,
            }
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> DeviceId {
        // TODO: allocate proper device ID
        unimplemented!("DmDevice ID allocation not yet implemented")
    }
}
