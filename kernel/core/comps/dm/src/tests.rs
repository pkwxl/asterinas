// SPDX-License-Identifier: MPL-2.0

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dm_ioctl_version() {
        let version = [DM_VERSION_MAJOR, DM_VERSION_MINOR, DM_VERSION_PATCHLEVEL];
        assert_eq!(version[0], 4);
        assert_eq!(version[1], 48);
        assert_eq!(version[2], 0);
    }

    #[test]
    fn test_dm_commands() {
        const DM_VERSION_CMD: u32 = 0xC138FD00 | 0;
        const DM_DEV_CREATE_CMD: u32 = 0xC138FD00 | 3;
        const DM_DEV_REMOVE_CMD: u32 = 0xC138FD00 | 4;
        const DM_DEV_SUSPEND_CMD: u32 = 0xC138FD00 | 6;
        const DM_TABLE_LOAD_CMD: u32 = 0xC138FD00 | 9;
        const DM_DEV_STATUS_CMD: u32 = 0xC138FD00 | 5;
        const DM_LIST_VERSIONS_CMD: u32 = 0xC138FD00 | 13;

        assert_eq!(DM_VERSION_CMD, 0xC138FD00);
        assert_eq!(DM_DEV_CREATE_CMD, 0xC138FD03);
        assert_eq!(DM_DEV_REMOVE_CMD, 0xC138FD04);
        assert_eq!(DM_DEV_SUSPEND_CMD, 0xC138FD06);
        assert_eq!(DM_TABLE_LOAD_CMD, 0xC138FD09);
        assert_eq!(DM_DEV_STATUS_CMD, 0xC138FD05);
        assert_eq!(DM_LIST_VERSIONS_CMD, 0xC138FD0D);
    }

    #[test]
    fn test_dm_suspend_flag() {
        const DM_SUSPEND_FLAG: u32 = 1 << 1;
        assert_eq!(DM_SUSPEND_FLAG, 2);
    }

    #[test]
    fn test_dm_ioctl_size() {
        use core::mem::size_of;
        const SIZEOF_DM_IOCTL: usize = 312;
        assert_eq!(SIZEOF_DM_IOCTL, size_of::<DmIoctl>());
    }

    #[test]
    fn test_dm_target_spec_alignment() {
        use core::mem::{size_of, align_of};
        assert_eq!(align_of::<DmTargetSpec>(), 8);
        assert_eq!(size_of::<DmTargetSpec>(), 48);
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
