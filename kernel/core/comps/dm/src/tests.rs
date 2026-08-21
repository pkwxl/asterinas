// SPDX-License-Identifier: MPL-2.0

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dm_table_adjoin() {
        let mut table = DmTable::new();

        // Add first target at sector 0
        let target1 = DmTarget::new_empty(0, 100);
        table.add_target(target1).unwrap();

        // Add second target adjacent to first
        let target2 = DmTarget::new_empty(100, 50);
        table.add_target(target2).unwrap();

        assert_eq!(table.nr_sectors(), 150);
    }

    #[test]
    fn test_dm_table_adjoin_violation() {
        let mut table = DmTable::new();

        // Add first target at sector 0
        let target1 = DmTarget::new_empty(0, 100);
        table.add_target(target1).unwrap();

        // Try to add target with gap (begin != current nr_sectors)
        let target2 = DmTarget::new_empty(150, 50);
        assert!(table.add_target(target2).is_err());
    }

    #[test]
    fn test_dm_table_find_target() {
        let mut table = DmTable::new();

        // Add targets
        let target1 = DmTarget::new_empty(0, 100);
        table.add_target(target1).unwrap();
        let target2 = DmTarget::new_empty(100, 50);
        table.add_target(target2).unwrap();

        assert!(table.find_target(50).is_some());
        assert!(table.find_target(99).is_some());
        assert!(table.find_target(100).is_some());
        assert!(table.find_target(149).is_some());
        assert!(table.find_target(150).is_none());
    }

    #[test]
    fn test_dm_table_sector_mapping() {
        let mut table = DmTable::new();

        // Add linear target at sector 100 with offset 200
        let target_type = crate::target::lookup_target("linear")
            .unwrap_or_else(|| panic!("linear not registered"));
        let priv_data = TargetPrivate::new(200);
        let target = DmTarget::new(100, 50, target_type, Some(priv_data));
        table.add_target(target).unwrap();

        // Sector 100 in DM device -> sector 300 on underlying (offset + (100 - 100) = 200 + 0)
        // But map_sector expects relative to begin
        let mapped = table.find_target(100).unwrap().map_sector(100);
        assert_eq!(mapped.unwrap(), 200);

        let mapped = table.find_target(120).unwrap().map_sector(120);
        assert_eq!(mapped.unwrap(), 220);
    }

    #[test]
    fn test_dm_table_error_target() {
        let mut table = DmTable::new();

        // Add error target
        let target_type = crate::target::lookup_target("error")
            .unwrap_or_else(|| panic!("error not registered"));
        let priv_data = TargetPrivate::new_error();
        let target = DmTarget::new(0, 100, target_type, Some(priv_data));
        table.add_target(target).unwrap();

        // Error target map should fail
        let result = table.find_target(50).unwrap().map_sector(50);
        assert!(result.is_err());
    }

    #[test]
    fn test_dm_device_create() {
        let device = DmDevice::create("test");
        assert_eq!(device.name(), "test");
        assert!(device.get_active_table().is_none());
        assert!(!device.is_suspended());
    }

    #[test]
    fn test_dm_device_suspend_resume() {
        let device = DmDevice::create("test");

        // Create a simple table
        let mut table = DmTable::new();
        let target_type = crate::target::lookup_target("linear")
            .unwrap_or_else(|| panic!("linear not registered"));
        let priv_data = TargetPrivate::new(0);
        let target = DmTarget::new(0, 100, target_type, Some(priv_data));
        table.add_target(target).unwrap();

        device.load_table(table);
        device.swap_table();

        // Suspend
        device.suspend();
        assert!(device.is_suspended());

        // Resume
        device.resume();
        assert!(!device.is_suspended());
    }

    #[test]
    fn test_dm_device_deferred_queue() {
        use aster_block::bio::{Bio, BioOp, SubmittedBio};
        use ostd::buff::PageBuff;

        let device = DmDevice::create("test");

        // Suspend first
        device.suspend();

        // Create a simple bio
        let buff = PageBuff::alloc_kernel_page(1).unwrap();
        let mut bio = Bio::new(vec![buff], 0, BioOp::Write).unwrap();
        bio.set_sid_offset(0);

        let submitted = SubmittedBio::new(bio).unwrap();

        // Enqueue should defer since suspended
        let result = device.enqueue(submitted.clone());
        assert!(result.is_ok(), "Enqueue should succeed for deferred bio");

        // Verify bio was added to queue (SpinLock.lock() instead of RefCell.borrow())
        let queue = device.deferred_queue.lock();
        assert_eq!(queue.len(), 1);
    }
}

    #[test]
    fn test_dm_target_contains() {
        let target = DmTarget::new_empty(100, 50);

        assert!(!target.contains(99));
        assert!(target.contains(100));
        assert!(target.contains(149));
        assert!(!target.contains(150));
    }

    #[test]
    fn test_dm_target_end() {
        let target = DmTarget::new_empty(100, 50);
        assert_eq!(target.end(), 150);
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DmIoctl {
    version: [u32; 3],
    data_size: u32,
    data_start: u32,
    target_count: u32,
    open_count: i32,
    flags: u32,
    event_nr: u32,
    padding: u32,
    dev: u64,
    name: [u8; 128],
    uuid: [u8; 129],
    data: [u8; 7],
}

#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
struct DmTargetSpec {
    sector_start: u64,
    length: u64,
    status: i32,
    next: u32,
    target_type: [u8; 16],
}
