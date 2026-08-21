// SPDX-License-Identifier: MPL-2.0

//! Device Mapper (DM) control device (/dev/mapper/control)
//!
//! This module implements the DM ioctl interface:
//! - DM_VERSION: version query
//! - DM_DEV_CREATE: create mapped device
//! - DM_DEV_REMOVE: remove mapped device
//! - DM_TABLE_LOAD: load inactive table
//! - DM_DEV_SUSPEND: suspend/resume device

use alloc::{string::String, sync::Arc};
use core::str;

use device_id::{DeviceId, MajorId, MinorId};
use ostd::mm::VmIo;

use crate::{
    context::current_userspace,
    device::{Device, DeviceType, DevtmpfsInodeMeta, registry::char},
    fs::{file::PerOpenFileOps, vfs::inode::FileOps},
    prelude::*,
    process::signal::{PollHandle, Pollable},
};

use aster_dm::{DmDevice, DmTable};

const MISC_MAJOR: u32 = 10;
const DM_MINOR: u32 = 236;

const DM_VERSION_MAJOR: u32 = 4;
const DM_VERSION_MINOR: u32 = 48;
const DM_VERSION_PATCHLEVEL: u32 = 0;

const DM_NAME_LEN: usize = 128;
const DM_UUID_LEN: usize = 129;
const DM_TARGET_TYPE_LEN: usize = 16;

const DM_DEV_CREATE_CMD: u32 = 3;
const DM_DEV_REMOVE_CMD: u32 = 4;
const DM_DEV_SUSPEND_CMD: u32 = 6;
const DM_TABLE_LOAD_CMD: u32 = 9;
const DM_DEV_STATUS_CMD: u32 = 5;
const DM_LIST_VERSIONS_CMD: u32 = 13;
const DM_TABLE_STATUS_CMD: u32 = 12;

const DM_SUSPEND_FLAG: u32 = 1 << 1;
const DM_QUERY_INACTIVE_TABLE_FLAG: u32 = 1 << 12;

static DEVICE_REGISTRY: Mutex<BTreeMap<String, Arc<DmDevice>>> = Mutex::new(BTreeMap::new());

#[derive(Debug)]
struct DmControlDevice;

impl DmControlDevice {
    fn new() -> Arc<Self> {
        Arc::new(DmControlDevice)
    }

    fn lookup_device(name: &str) -> Option<Arc<DmDevice>> {
        DEVICE_REGISTRY.lock().get(name).cloned()
    }

    fn create_device(name: &str) -> Result<Arc<DmDevice>> {
        let mut registry = DEVICE_REGISTRY.lock();
        if registry.contains_key(name) {
            return_errno_with_message!(Errno::EEXIST, "device already exists");
        }
        let device = DmDevice::create(name);
        registry.insert(String::from(name), device.clone());
        Ok(device)
    }

    fn remove_device(name: &str) -> Result<()> {
        let mut registry = DEVICE_REGISTRY.lock();
        if !registry.contains_key(name) {
            return_errno_with_message!(Errno::ENODEV, "device not found");
        }
        registry.remove(name);
        Ok(())
    }
}

impl Device for DmControlDevice {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        let major = MajorId::new(MISC_MAJOR as u16);
        let minor = MinorId::new(DM_MINOR);
        DeviceId::new(major, minor)
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsInodeMeta<'_>> {
        Some(DevtmpfsInodeMeta::new("mapper/control"))
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(DmControlFile))
    }
}

struct DmControlFile;

impl Pollable for DmControlFile {
    fn poll(
        &self,
        mask: crate::events::IoEvents,
        _poller: Option<&mut PollHandle>,
    ) -> crate::events::IoEvents {
        mask & (crate::events::IoEvents::IN | crate::events::IoEvents::OUT)
    }
}

impl FileOps for DmControlFile {
    fn read_at(
        &self,
        _offset: usize,
        _writer: &mut VmWriter,
        _status_flags: crate::fs::file::StatusFlags,
    ) -> Result<usize> {
        Ok(0)
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _status_flags: crate::fs::file::StatusFlags,
    ) -> Result<usize> {
        Ok(0)
    }
}

impl PerOpenFileOps for DmControlFile {
    fn check_seekable(&self) -> Result<()> {
        Ok(())
    }

    fn is_offset_aware(&self) -> bool {
        false
    }

    fn ioctl(
        &self,
        _path: &crate::fs::vfs::path::Path,
        raw_ioctl: crate::util::ioctl::RawIoctl,
    ) -> Result<i32> {
        let nr = raw_ioctl.cmd() & 0xFF;

        match nr {
            0 => self.handle_version(raw_ioctl)?,
            DM_DEV_CREATE_CMD => self.handle_dev_create(raw_ioctl)?,
            DM_DEV_REMOVE_CMD => self.handle_dev_remove(raw_ioctl)?,
            DM_TABLE_LOAD_CMD => self.handle_table_load(raw_ioctl)?,
            DM_DEV_SUSPEND_CMD => self.handle_dev_suspend(raw_ioctl)?,
            DM_DEV_STATUS_CMD => self.handle_dev_status(raw_ioctl)?,
            DM_LIST_VERSIONS_CMD => self.handle_list_versions()?,
            DM_TABLE_STATUS_CMD => self.handle_table_status(raw_ioctl)?,
            _ => return_errno_with_message!(Errno::ENOTTY, "unknown DM ioctl command"),
        }
        Ok(0)
    }
}

impl DmControlFile {
    fn handle_version(&self, raw_ioctl: crate::util::ioctl::RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let version = [DM_VERSION_MAJOR, DM_VERSION_MINOR, DM_VERSION_PATCHLEVEL];
        let mut buf = [0u8; 12];
        buf[..4].copy_from_slice(&version[0].to_le_bytes());
        buf[4..8].copy_from_slice(&version[1].to_le_bytes());
        buf[8..12].copy_from_slice(&version[2].to_le_bytes());
        current_userspace!().write_bytes(arg, &buf)?;
        Ok(())
    }

    fn handle_dev_create(&self, raw_ioctl: crate::util::ioctl::RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let mut data = [0u8; 312];
        current_userspace!().read_bytes(arg, &mut data)?;

        let version = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let major = (version & 0xFFFFFFFF) as u32;
        if major != DM_VERSION_MAJOR {
            return_errno_with_message!(Errno::EINVAL, "DM version major mismatch");
        }

        let name_str = str::from_utf8(&data[48..48 + DM_NAME_LEN])
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid device name"))?;
        let name = name_str.split('\0').next().unwrap_or("");

        DmControlDevice::create_device(name)?;

        Ok(())
    }

    fn handle_dev_remove(&self, raw_ioctl: crate::util::ioctl::RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let mut data = [0u8; 312];
        current_userspace!().read_bytes(arg, &mut data)?;

        let name_str = str::from_utf8(&data[48..48 + DM_NAME_LEN])
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid device name"))?;
        let name = name_str.split('\0').next().unwrap_or("");

        DmControlDevice::remove_device(name)?;

        Ok(())
    }

    fn handle_table_load(&self, raw_ioctl: crate::util::ioctl::RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let mut data = [0u8; 312];
        current_userspace!().read_bytes(arg, &mut data)?;

        let name_str = str::from_utf8(&data[48..48 + DM_NAME_LEN])
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid device name"))?;
        let name = name_str.split('\0').next().unwrap_or("");

        let device = DmControlDevice::lookup_device(name)
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "device not found"))?;

        // Parse data_size and data_start
        let data_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let data_start = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

        if data_size < 312 || data_start > data_size {
            return_errno_with_message!(Errno::EINVAL, "invalid data_size or data_start");
        }

        // Get the table data buffer
        let table_data = if data_size > 312 {
            &data[312..data_size]
        } else {
            &[]
        };

        // Parse dm_target_spec chain
        let mut specs_data = [0u8; 4096];
        let specs_len = core::cmp::min(table_data.len(), specs_data.len());
        specs_data[..specs_len].copy_from_slice(&table_data[..specs_len]);

        // Parse target count
        let target_count =
            u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;

        if target_count == 0 {
            return_errno_with_message!(Errno::EINVAL, "target_count must be > 0");
        }

        // Parse dm_target_spec chain and build table
        let mut table = DmTable::new();
        self.parse_target_specs(&specs_data[..specs_len], target_count, &mut table)?;

        device.load_table(table);

        Ok(())
    }

    fn parse_target_specs(
        &self,
        specs: &[u8],
        target_count: usize,
        table: &mut DmTable,
    ) -> Result<()> {
        let mut offset = 0;

        for _ in 0..target_count {
            if offset + 48 > specs.len() {
                return_errno_with_message!(Errno::EINVAL, "dm_target_spec incomplete");
            }

            // Parse sector_start (u64 at offset 0)
            let sector_start = u64::from_le_bytes([
                specs[offset],
                specs[offset + 1],
                specs[offset + 2],
                specs[offset + 3],
                specs[offset + 4],
                specs[offset + 5],
                specs[offset + 6],
                specs[offset + 7],
            ]);

            // Parse length (u64 at offset 8)
            let length = u64::from_le_bytes([
                specs[offset + 8],
                specs[offset + 9],
                specs[offset + 10],
                specs[offset + 11],
                specs[offset + 12],
                specs[offset + 13],
                specs[offset + 14],
                specs[offset + 15],
            ]);

            // Parse status (s32 at offset 16)
            let _status = i32::from_le_bytes([
                specs[offset + 16],
                specs[offset + 17],
                specs[offset + 18],
                specs[offset + 19],
            ]);

            // Parse next (u32 at offset 20) - bytes to next spec
            let next = u32::from_le_bytes([
                specs[offset + 20],
                specs[offset + 21],
                specs[offset + 22],
                specs[offset + 23],
            ]) as usize;

            // Parse target_type (16 bytes at offset 24)
            let type_start = offset + 24;
            if type_start + DM_TARGET_TYPE_LEN > specs.len() {
                return_errno_with_message!(Errno::EINVAL, "target_type incomplete");
            }

            let null_pos = specs[type_start..type_start + DM_TARGET_TYPE_LEN]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(DM_TARGET_TYPE_LEN);
            let target_type_str = str::from_utf8(&specs[type_start..type_start + null_pos])
                .map_err(|_| Error::with_message(Errno::EINVAL, "invalid target_type"))?;

            // Parse params (8-byte aligned after spec)
            let params_offset = (next + 7) & !7;
            if params_offset > next || params_offset >= specs.len() {
                return_errno_with_message!(Errno::EINVAL, "params offset invalid");
            }

            let params_start = type_start + DM_TARGET_TYPE_LEN;
            if params_start >= next {
                return_errno_with_message!(Errno::EINVAL, "params out of bounds");
            }

            // Find NUL terminator for params
            let mut params_len = 0;
            while params_start + params_len < next && specs[params_start + params_len] != 0 {
                params_len += 1;
            }

            if params_start + params_len > next {
                return_errno_with_message!(Errno::EINVAL, "params extend beyond spec");
            }

            let params_str = str::from_utf8(&specs[params_start..params_start + params_len])
                .map_err(|_| Error::with_message(Errno::EINVAL, "invalid params"))?;

            // Add target to table
            self.add_target_to_table(table, sector_start, length, target_type_str, params_str)?;

            // Move to next spec
            if next == 0 {
                break;
            }
            offset = next;
        }

        Ok(())
    }

    fn add_target_to_table(
        &self,
        table: &mut DmTable,
        sector_start: u64,
        length: u64,
        target_type_str: &str,
        params_str: &str,
    ) -> Result<()> {
        match target_type_str {
            "linear" => table.add_linear_target(sector_start, length, params_str)
                .map_err(|e| Error::with_message(Errno::EINVAL, e)),
            "error" => table.add_error_target(sector_start, length)
                .map_err(|e| Error::with_message(Errno::EINVAL, e)),
            _ => {
                return_errno_with_message!(Errno::EINVAL, "unsupported target type")
            }
        }
    }

    fn handle_dev_suspend(&self, raw_ioctl: crate::util::ioctl::RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let mut data = [0u8; 312];
        current_userspace!().read_bytes(arg, &mut data)?;

        let flags =
            u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        let name_str = str::from_utf8(&data[48..48 + DM_NAME_LEN])
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid device name"))?;
        let name = name_str.split('\0').next().unwrap_or("");

        let device = DmControlDevice::lookup_device(name)
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "device not found"))?;

        if flags & DM_SUSPEND_FLAG != 0 {
            // Suspend
            device.suspend();
        } else {
            // Resume (swap tables and replay deferred I/O)
            device.swap_table();
            device.resume();
        }

        Ok(())
    }

    fn handle_dev_status(&self, raw_ioctl: crate::util::ioctl::RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let mut data = [0u8; 312];
        current_userspace!().read_bytes(arg, &mut data)?;

        let name_str = str::from_utf8(&data[48..48 + DM_NAME_LEN])
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid device name"))?;
        let name = name_str.split('\0').next().unwrap_or("");

        DmControlDevice::lookup_device(name)
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "device not found"))?;

        let dev_field_offset = 40;
        current_userspace!().write_bytes(arg + dev_field_offset, &0u64.to_le_bytes())?;

        Ok(())
    }

    fn handle_list_versions(&self) -> Result<()> {
        Ok(())
    }

    fn handle_table_status(&self, raw_ioctl: crate::util::ioctl::RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let mut data = [0u8; 312];
        current_userspace!().read_bytes(arg, &mut data)?;

        let flags =
            u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        // Check if querying inactive table
        let query_inactive = (flags & DM_QUERY_INACTIVE_TABLE_FLAG) != 0;

        let name_str = str::from_utf8(&data[48..48 + DM_NAME_LEN])
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid device name"))?;
        let name = name_str.split('\0').next().unwrap_or("");

        let device = DmControlDevice::lookup_device(name)
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "device not found"))?;

        // Get appropriate table
        let (active_table, inactive_table) = device.get_tables();
        let table = if query_inactive {
            inactive_table.as_ref()
        } else {
            active_table.as_ref()
        };

        // Build status output
        let mut status_str = String::new();

        if let Some(table) = table {
            for target in table.targets() {
                let begin = target.begin;
                let len = target.len;
                let type_name = target.type_name();
                
                // Build params
                let mut params_str = String::new();
                match &target.private {
                    Some(priv_data) => {
                        params_str.push_str("none ");
                        params_str.push_str(&priv_data.offset.to_string());
                        params_str.push(' ');
                    }
                    None => {
                        params_str.push_str("none");
                    }
                }

                // Build target string: "<begin> <len> <type_name> <params>"
                status_str.push_str(&begin.to_string());
                status_str.push(' ');
                status_str.push_str(&len.to_string());
                status_str.push(' ');
                status_str.push_str(type_name);
                status_str.push(' ');
                status_str.push_str(&params_str);
            }
        }

        // Write back to user buffer
        let data_start =
            u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
        let data_size =
            u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

        if data_start + status_str.len() <= data_size {
            current_userspace!().write_bytes(arg as usize + data_start, status_str.as_bytes())?;
        }

        Ok(())
    }
}

pub(super) fn init_in_first_kthread() {
    char::register(DmControlDevice::new()).unwrap();
}
