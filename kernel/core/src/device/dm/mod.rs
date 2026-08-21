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

const DM_DEV_CREATE_CMD: u32 = 3;
const DM_DEV_REMOVE_CMD: u32 = 4;
const DM_DEV_SUSPEND_CMD: u32 = 6;
const DM_TABLE_LOAD_CMD: u32 = 9;
const DM_DEV_STATUS_CMD: u32 = 5;
const DM_LIST_VERSIONS_CMD: u32 = 13;

const DM_SUSPEND_FLAG: u32 = 1 << 1;

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

        // TODO: Parse dm_target_spec from data section and load table
        let table = DmTable::new();
        device.load_table(table);

        Ok(())
    }

    fn handle_dev_suspend(&self, raw_ioctl: crate::util::ioctl::RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let mut data = [0u8; 312];
        current_userspace!().read_bytes(arg, &mut data)?;

        let flags = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        let name_str = str::from_utf8(&data[48..48 + DM_NAME_LEN])
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid device name"))?;
        let name = name_str.split('\0').next().unwrap_or("");

        let device = DmControlDevice::lookup_device(name)
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "device not found"))?;

        if flags & DM_SUSPEND_FLAG != 0 {
            // Suspend: mark as suspended
        } else {
            // Resume: swap tables
            device.swap_table();
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
}

pub(super) fn init_in_first_kthread() {
    char::register(DmControlDevice::new()).unwrap();
}
