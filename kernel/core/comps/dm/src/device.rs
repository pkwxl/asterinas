// SPDX-License-Identifier: MPL-2.0

use alloc::{string::String, sync::Arc};
use core::fmt::Debug;
use core::ops::Range;

use aster_block::{
    BlockDevice, BlockDeviceMeta, SECTOR_SIZE,
    bio::{BioEnqueueError, SubmittedBio},
};
use device_id::DeviceId;
use ostd::sync::RwLock;

use crate::DmTable;

/// Represents a mapped device with active/inactive table slots
#[derive(Debug)]
pub struct DmDevice {
    name: String,
    #[allow(dead_code)]
    tables: RwLock<(Option<DmTable>, Option<DmTable>)>,
}

impl DmDevice {
    /// Create a new dm device with the given name (suspended state, no table)
    pub fn create(name: &str) -> Arc<Self> {
        let device = DmDevice {
            name: String::from(name),
            tables: RwLock::new((None, None)),
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
}

impl BlockDevice for DmDevice {
    fn enqueue(&self, mut bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        // Check if device is suspended (no active table)
        let tables = self.tables.read();
        let active_table = tables.0.as_ref();

        match active_table {
            Some(table) => {
                // Find target for this sector
                let sector = bio.sid_range().start.to_offset() as u64 / SECTOR_SIZE as u64;
                
                if let Some(target) = table.find_target(sector) {
                    // Calculate the offset on underlying device
                    let offset_on_underlying = 
                        target.begin + (sector - target.begin);
                    
                    // Set sid offset for sector remapping
                    bio.set_sid_offset(offset_on_underlying * SECTOR_SIZE as u64);
                    
                    // Forward to underlying device if available
                    match &target.private {
                        Some(priv_data) => {
                            let offset = priv_data.offset;
                            match priv_data.underlying() {
                                Some(underlying) => {
                                    bio.set_sid_offset((offset_on_underlying + offset) * SECTOR_SIZE as u64);
                                    return underlying.enqueue(bio);
                                }
                                None => {}
                            }
                        }
                        None => {}
                    }
                    
                    // No valid private data or underlying device found
                    Err(BioEnqueueError::Refused)
                } else {
                    // No target found - should not happen if table is valid
                    Err(BioEnqueueError::Refused)
                }
            }
            None => {
                // Device suspended, reject I/O
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
