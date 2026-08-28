// SPDX-License-Identifier: MPL-2.0

//! Device Mapper (DM) control device (/dev/mapper/control)
//!
//! This module implements the DM ioctl interface:
//! - DM_VERSION: version query
//! - DM_DEV_CREATE: create mapped device
//! - DM_DEV_REMOVE: remove mapped device
//! - DM_TABLE_LOAD: load inactive table
//! - DM_DEV_SUSPEND: suspend/resume device
//! - DM_DEV_STATUS: query device status
//! - DM_LIST_VERSIONS: list registered target types
//! - DM_TABLE_STATUS: dump the (in)active table in the DM ABI format

use core::str;

use device_id::{DeviceId, MajorId, MinorId};
use ostd::mm::VmIo;
use spin::Once;

use crate::{
    context::current_userspace,
    device::{Device, DeviceType, DevtmpfsInodeMeta, registry::char},
    fs::{file::PerOpenFileOps, vfs::inode::FileOps},
    prelude::*,
    process::{
        UserNamespace, credentials::capabilities::CapSet, posix_thread::AsPosixThread,
        signal::{PollHandle, Pollable},
    },
    security::lsm::hooks as lsm_hooks,
    util::ioctl::RawIoctl,
};

use aster_block::BlockDevice;
use aster_dm::{DmDevice, DmTable};

const MISC_MAJOR: u32 = 10;
const DM_MINOR: u32 = 236;

/// The block-device major number of Device Mapper devices (`/dev/dm-N`),
/// same as in Linux.
///
/// Note that in Asterinas the block majors 254 and downward are allocated
/// dynamically (e.g., 254 to virtio-blk, 253 to NVMe), so DM may fail to
/// acquire 253; in that case a dynamically allocated major is used instead.
/// User space learns the real major/minor from `dm_ioctl.dev`, so either
/// way works.
const DM_BLOCK_MAJOR: u16 = 253;
/// The maximum number of DM devices (minors) that can exist at once.
const MAX_DM_MINORS: u32 = 256;
/// The maximum `data_size` accepted for a TABLE_LOAD ioctl, as a
/// denial-of-service guard on the heap allocation (tables are tiny; the
/// Linux tools use a 16 KiB buffer by default).
const MAX_TABLE_LOAD_SIZE: usize = 1 << 20;

const DM_VERSION_MAJOR: u32 = 4;
const DM_VERSION_MINOR: u32 = 48;
const DM_VERSION_PATCHLEVEL: u32 = 0;

const DM_NAME_LEN: usize = 128;
const DM_TARGET_TYPE_LEN: usize = 16;

/// `sizeof(struct dm_ioctl)`: the fixed-size header every DM ioctl carries.
const DM_IOCTL_HEADER_LEN: usize = 312;
/// `sizeof(struct dm_target_spec)`: sector_start + length + status + next
/// + target_type[16]; the parameter string follows immediately after.
const DM_TARGET_SPEC_LEN: usize = 40;
/// `sizeof(struct dm_target_versions)` without the flexible `name[]`
/// member: next + version[3].
const DM_TARGET_VERSIONS_HEADER_LEN: usize = 16;

/// The full encoding of every DM ioctl command on x86_64:
/// `_IOWR(0xfd, nr, struct dm_ioctl)` == `0xC138FD00 | nr`.
const DM_IOCTL_CMD_BASE: u32 = 0xC138FD00;

// Field offsets in `struct dm_ioctl` (see linux/include/uapi/linux/dm-ioctl.h).
const OFF_VERSION: usize = 0;
const OFF_DATA_SIZE: usize = 12;
const OFF_DATA_START: usize = 16;
const OFF_TARGET_COUNT: usize = 20;
const OFF_OPEN_COUNT: usize = 24;
const OFF_FLAGS: usize = 28;
const OFF_DEV: usize = 40;
const OFF_NAME: usize = 48;

const DM_DEV_CREATE_CMD: u32 = 3;
const DM_DEV_REMOVE_CMD: u32 = 4;
// nr 5 is DM_DEV_RENAME in the Linux ABI; it is not implemented yet and
// deliberately falls through to the ENOTTY branch below.
const DM_DEV_SUSPEND_CMD: u32 = 6;
const DM_DEV_STATUS_CMD: u32 = 7;
const DM_TABLE_LOAD_CMD: u32 = 9;
const DM_TABLE_STATUS_CMD: u32 = 12;
const DM_LIST_VERSIONS_CMD: u32 = 13;

const DM_SUSPEND_FLAG: u32 = 1 << 1;
const DM_ACTIVE_PRESENT_FLAG: u32 = 1 << 5;
const DM_INACTIVE_PRESENT_FLAG: u32 = 1 << 6;
const DM_BUFFER_FULL_FLAG: u32 = 1 << 8;
const DM_QUERY_INACTIVE_TABLE_FLAG: u32 = 1 << 12;

/// Reads a little-endian `u32` field from a `dm_ioctl` header buffer.
fn get_u32(header: &[u8; DM_IOCTL_HEADER_LEN], offset: usize) -> u32 {
    u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap())
}

/// Reads the fixed-size `dm_ioctl` header from user space.
fn read_header(arg: usize) -> Result<[u8; DM_IOCTL_HEADER_LEN]> {
    let mut header = [0u8; DM_IOCTL_HEADER_LEN];
    current_userspace!().read_bytes(arg, &mut header)?;
    Ok(header)
}

/// Extracts the NUL-terminated device name from a `dm_ioctl` header.
fn parse_name(header: &[u8; DM_IOCTL_HEADER_LEN]) -> Result<&str> {
    let name_bytes = &header[OFF_NAME..OFF_NAME + DM_NAME_LEN];
    let name_str = str::from_utf8(name_bytes)
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid device name"))?;
    Ok(name_str.split('\0').next().unwrap_or(""))
}

/// Validates a DM device name, as Linux's `check_name` does
/// (dm-ioctl.c:767-782): the name must be non-empty and must not
/// contain '/', nor be "control", ".", or "..". Applied to every
/// command that takes a device name (Linux checks the name in
/// DEV_CREATE/DEV_RENAME; validating it elsewhere as well is
/// harmless and keeps the registry free of unusable keys).
fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.contains('/') || matches!(name, "control" | "." | "..") {
        return_errno_with_message!(Errno::EINVAL, "invalid DM device name");
    }
    Ok(())
}

/// Writes the kernel's interface version (4.48.0) back to user space,
/// as Linux's `check_version` does for every DM ioctl.
fn write_back_version(arg: usize) -> Result<()> {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&DM_VERSION_MAJOR.to_le_bytes());
    out[4..8].copy_from_slice(&DM_VERSION_MINOR.to_le_bytes());
    out[8..12].copy_from_slice(&DM_VERSION_PATCHLEVEL.to_le_bytes());
    current_userspace!().write_bytes(arg, &out)?;
    Ok(())
}

/// Writes the table-presence flags (`dm_ioctl.flags`) back to user space,
/// as `__dev_status` does in Linux: `DM_ACTIVE_PRESENT_FLAG` /
/// `DM_INACTIVE_PRESENT_FLAG` according to the tables, plus
/// `DM_SUSPEND_FLAG` while the device is suspended.
fn write_back_present_flags(arg: usize, device: &DmDevice, extra_flags: u32) -> Result<()> {
    let (active_table, inactive_table) = device.get_tables();
    let mut out_flags = extra_flags;
    if active_table.is_some() {
        out_flags |= DM_ACTIVE_PRESENT_FLAG;
    }
    if inactive_table.is_some() {
        out_flags |= DM_INACTIVE_PRESENT_FLAG;
    }
    if device.is_suspended() {
        out_flags |= DM_SUSPEND_FLAG;
    }
    current_userspace!().write_bytes(arg + OFF_FLAGS, &out_flags.to_le_bytes())?;
    Ok(())
}

/// Rounds `n` up to the next 8-byte boundary (the alignment of
/// `dm_target_spec`/`dm_target_versions` entries in the data area).
const fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// A DM device tracked by the control plane.
struct DmDevEntry {
    device: Arc<DmDevice>,
    /// The device ID allocated at DEV_CREATE time (see `dm_block_major`).
    id: DeviceId,
    /// Whether the device has been registered in the block-device
    /// registry (this happens on the first resume, when the device
    /// becomes live).
    registered: bool,
}

/// The ownership of the DM block-device major number (kept alive so that
/// the major is never reused by another driver).
static DM_BLOCK_MAJOR_OWNER: Once<aster_block::MajorIdOwner> = Once::new();

/// Returns the DM block-device major, acquiring it on first use.
///
/// The conventional DM major (253) is preferred; if another driver has
/// already taken it (block majors 254 and downward are dynamically
/// allocated in Asterinas), a fresh dynamic major is used instead.
fn dm_block_major() -> MajorId {
    DM_BLOCK_MAJOR_OWNER
        .call_once(|| {
            aster_block::acquire_major(MajorId::new(DM_BLOCK_MAJOR))
                .or_else(|_| aster_block::allocate_major())
                .expect("failed to allocate a block major for DM")
        })
        .get()
}

static DEVICE_REGISTRY: Mutex<BTreeMap<String, DmDevEntry>> = Mutex::new(BTreeMap::new());

/// A bitmap of allocated DM minor numbers (one bit per minor).
static MINOR_BITMAP: Mutex<[u64; (MAX_DM_MINORS / 64) as usize]> =
    Mutex::new([0; (MAX_DM_MINORS / 64) as usize]);

/// Allocates a free DM minor number, or `None` if all are in use.
fn alloc_minor() -> Option<u32> {
    let mut bitmap = MINOR_BITMAP.lock();
    for (word_idx, word) in bitmap.iter_mut().enumerate() {
        if *word != u64::MAX {
            let bit = (!*word).trailing_zeros();
            *word |= 1u64 << bit;
            return Some(word_idx as u32 * 64 + bit);
        }
    }
    None
}

/// Returns a DM minor number to the free pool.
fn free_minor(minor: u32) {
    debug_assert!(minor < MAX_DM_MINORS);
    let mut bitmap = MINOR_BITMAP.lock();
    bitmap[minor as usize / 64] &= !(1u64 << (minor % 64));
}

#[derive(Debug)]
struct DmControlDevice;

impl DmControlDevice {
    fn new() -> Arc<Self> {
        Arc::new(DmControlDevice)
    }

    fn lookup_device(name: &str) -> Option<Arc<DmDevice>> {
        DEVICE_REGISTRY
            .lock()
            .get(name)
            .map(|entry| entry.device.clone())
    }

    fn create_device(name: &str) -> Result<(Arc<DmDevice>, DeviceId)> {
        let mut registry = DEVICE_REGISTRY.lock();
        if registry.contains_key(name) {
            // Linux's `dm_hash_insert` reports -EBUSY for a duplicate
            // name (the v4 interface has no DM_EXISTS_FLAG semantics).
            return_errno_with_message!(Errno::EBUSY, "device already exists");
        }
        let minor = alloc_minor()
            .ok_or_else(|| Error::with_message(Errno::ENOSPC, "no free DM minor"))?;
        let id = DeviceId::new(dm_block_major(), MinorId::new(minor));
        let device = DmDevice::create(name, id);
        // A freshly created DM device starts out suspended (it has no
        // live table yet); the first DEV_SUSPEND(resume) brings it live.
        // Mark it suspended here so that `DmDevice::resume` — which
        // rejects resuming a non-suspended device — accepts that initial
        // resume. Suspending cannot fail on a fresh device.
        device
            .suspend()
            .expect("a freshly created device is not suspended");
        registry.insert(
            String::from(name),
            DmDevEntry {
                device: device.clone(),
                id,
                registered: false,
            },
        );
        Ok((device, id))
    }

    fn remove_device(name: &str) -> Result<()> {
        let mut registry = DEVICE_REGISTRY.lock();
        let Some(entry) = registry.remove(name) else {
            return_errno_with_message!(Errno::ENXIO, "device not found");
        };
        if entry.registered {
            let _ = aster_block::unregister(entry.id);
        }
        free_minor(entry.id.minor().get());
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

    fn ioctl(&self, _path: &crate::fs::vfs::path::Path, raw_ioctl: RawIoctl) -> Result<i32> {
        // Only a caller with CAP_SYS_ADMIN may use the DM control device
        // ("only root can play with this", dm-ioctl.c `ctl_ioctl`). An
        // ioctl always comes from a user thread, so `as_posix_thread()`
        // cannot return `None` here (same assumption as the VT driver's
        // ioctl permission check).
        let init_user_ns = UserNamespace::get_init_singleton();
        let capable_result = lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
            init_user_ns.as_ref(),
            current_thread!().as_posix_thread().unwrap(),
            CapSet::SYS_ADMIN,
        ));
        if let Err(err) = capable_result {
            // Linux reports -EACCES here while the capability LSM reports
            // -EPERM; translate to stay ABI-compatible.
            if err.error() == Errno::EPERM {
                return_errno_with_message!(Errno::EACCES, "DM ioctl requires CAP_SYS_ADMIN");
            }
            return Err(err);
        }

        let cmd = raw_ioctl.cmd();
        let nr = cmd & 0xFF;

        // The full command encoding must be `_IOWR(0xfd, nr, struct
        // dm_ioctl)` (`0xC138FD00 | nr` on x86_64); matching only the low
        // byte would interpret any unrelated ioctl whose low byte collides
        // with a DM command number as a DM command.
        let is_known_nr = matches!(
            nr,
            0 | DM_DEV_CREATE_CMD
                | DM_DEV_REMOVE_CMD
                | DM_DEV_STATUS_CMD
                | DM_DEV_SUSPEND_CMD
                | DM_TABLE_LOAD_CMD
                | DM_TABLE_STATUS_CMD
                | DM_LIST_VERSIONS_CMD
        );
        if !is_known_nr || cmd != DM_IOCTL_CMD_BASE | nr {
            return_errno_with_message!(Errno::ENOTTY, "unknown DM ioctl command");
        }

        // Every DM ioctl carries the fixed-size header with the interface
        // version; validate it (and write back the kernel version) before
        // dispatching, as `check_version`/`copy_params` do in Linux.
        self.check_version(&raw_ioctl)?;

        match nr {
            // The version query is fully handled by `check_version`.
            0 => {}
            DM_DEV_CREATE_CMD => self.handle_dev_create(raw_ioctl)?,
            DM_DEV_REMOVE_CMD => self.handle_dev_remove(raw_ioctl)?,
            DM_TABLE_LOAD_CMD => self.handle_table_load(raw_ioctl)?,
            DM_DEV_SUSPEND_CMD => self.handle_dev_suspend(raw_ioctl)?,
            DM_DEV_STATUS_CMD => self.handle_dev_status(raw_ioctl)?,
            DM_LIST_VERSIONS_CMD => self.handle_list_versions(raw_ioctl)?,
            DM_TABLE_STATUS_CMD => self.handle_table_status(raw_ioctl)?,
            _ => unreachable!(),
        }
        Ok(0)
    }
}

impl DmControlFile {
    /// Validates the header every DM ioctl carries (see Linux's
    /// `check_version` + `copy_params`): the interface major version must
    /// be 4, the minor version must not exceed 48, and the declared data
    /// area must at least cover the fixed header. The kernel's interface
    /// version is always written back.
    fn check_version(&self, raw_ioctl: &RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let major = get_u32(&header, OFF_VERSION);
        let minor = get_u32(&header, OFF_VERSION + 4);
        if major != DM_VERSION_MAJOR || minor > DM_VERSION_MINOR {
            return_errno_with_message!(Errno::EINVAL, "DM ioctl interface version mismatch");
        }

        let data_size = get_u32(&header, OFF_DATA_SIZE) as usize;
        let data_start = get_u32(&header, OFF_DATA_START) as usize;
        if data_size < DM_IOCTL_HEADER_LEN || data_start > data_size {
            return_errno_with_message!(Errno::EINVAL, "invalid data_size or data_start");
        }

        write_back_version(arg)
    }

    fn handle_dev_create(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;
        let name = parse_name(&header)?;
        check_name(name)?;

        let (_device, id) = DmControlDevice::create_device(name)?;

        // Write back the allocated device number (`dm_ioctl.dev`) so that
        // user space can `mknod /dev/dm-N` with it.
        current_userspace!().write_bytes(arg + OFF_DEV, &id.as_encoded_u64().to_le_bytes())?;

        Ok(())
    }

    fn handle_dev_remove(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;
        let name = parse_name(&header)?;
        check_name(name)?;

        let device = DmControlDevice::lookup_device(name)
            .ok_or_else(|| Error::with_message(Errno::ENXIO, "device not found"))?;

        // A device with open handles cannot be removed (Linux returns
        // -EBUSY from `__dev_destroy` in this case).
        let open_count = device.open_count();
        if open_count != 0 {
            return_errno_with_message!(Errno::EBUSY, "device still has open handles");
        }
        let dev = device.id().as_encoded_u64();

        DmControlDevice::remove_device(name)?;
        // Clear the tables so that any stale references to the device
        // (e.g. a cached device file for a since-recycled minor number)
        // fail with an I/O error instead of silently serving I/O through
        // the removed device's table (cf. Linux `dev_destroy`).
        device.remove();

        // Report the final device state (`dm_ioctl.open_count` and
        // `dm_ioctl.dev`), same as `dev_status`.
        current_userspace!().write_bytes(arg + OFF_OPEN_COUNT, &open_count.to_le_bytes())?;
        current_userspace!().write_bytes(arg + OFF_DEV, &dev.to_le_bytes())?;

        Ok(())
    }

    fn handle_table_load(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let data_size = get_u32(&header, OFF_DATA_SIZE) as usize;
        let data_start = get_u32(&header, OFF_DATA_START) as usize;

        if data_size > MAX_TABLE_LOAD_SIZE {
            return_errno_with_message!(Errno::EINVAL, "TABLE_LOAD data_size too large");
        }

        // Read the whole payload (header + spec chain) into a heap buffer;
        // a fixed-size stack buffer would either overflow or silently
        // truncate large tables.
        let mut data = alloc::vec![0u8; data_size];
        current_userspace!().read_bytes(arg, &mut data)?;

        let name_str = str::from_utf8(&data[OFF_NAME..OFF_NAME + DM_NAME_LEN])
            .map_err(|_| Error::with_message(Errno::EINVAL, "invalid device name"))?;
        let name = name_str.split('\0').next().unwrap_or("");
        check_name(name)?;

        let device = DmControlDevice::lookup_device(name)
            .ok_or_else(|| Error::with_message(Errno::ENXIO, "device not found"))?;

        // Parse target count
        let target_count =
            u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;

        if target_count == 0 {
            return_errno_with_message!(Errno::EINVAL, "target_count must be > 0");
        }

        // Parse dm_target_spec chain and build table
        let mut table = DmTable::new();
        self.parse_target_specs(&data[data_start..], target_count, &mut table)?;

        device.load_table(table);

        Ok(())
    }

    /// Parses the `dm_target_spec` chain in `specs` (which starts at
    /// `data_start`) and appends exactly `target_count` targets to `table`.
    ///
    /// On DM_TABLE_LOAD, each spec's `next` field is the offset from the
    /// *current* spec to the following one (see the comment in
    /// dm-ioctl.h), so the chain is walked with `offset += next`.
    fn parse_target_specs(
        &self,
        specs: &[u8],
        target_count: usize,
        table: &mut DmTable,
    ) -> Result<()> {
        let mut offset = 0usize;

        for i in 0..target_count {
            if offset + DM_TARGET_SPEC_LEN > specs.len() {
                return_errno_with_message!(Errno::EINVAL, "dm_target_spec out of bounds");
            }
            let spec = &specs[offset..offset + DM_TARGET_SPEC_LEN];

            let sector_start = u64::from_le_bytes(spec[0..8].try_into().unwrap());
            let length = u64::from_le_bytes(spec[8..16].try_into().unwrap());
            let next = u32::from_le_bytes(spec[20..24].try_into().unwrap()) as usize;

            // target_type: NUL-padded 16-byte field at offset 24.
            let type_field = &spec[24..24 + DM_TARGET_TYPE_LEN];
            let type_len = type_field
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(DM_TARGET_TYPE_LEN);
            let target_type_str = str::from_utf8(&type_field[..type_len])
                .map_err(|_| Error::with_message(Errno::EINVAL, "invalid target_type"))?;

            // The parameter string starts right after the spec and must be
            // NUL-terminated within the data area (as in Linux's
            // `populate_table`).
            let params_start = offset + DM_TARGET_SPEC_LEN;
            if params_start >= specs.len() {
                return_errno_with_message!(Errno::EINVAL, "target params out of bounds");
            }
            let Some(params_len) = specs[params_start..].iter().position(|&b| b == 0) else {
                return_errno_with_message!(Errno::EINVAL, "target params not NUL-terminated");
            };
            let params_str = str::from_utf8(&specs[params_start..params_start + params_len])
                .map_err(|_| Error::with_message(Errno::EINVAL, "invalid target params"))?;

            table
                .add_target(sector_start, length, target_type_str, params_str)
                .map_err(|e| Error::with_message(Errno::EINVAL, e))?;

            // Advance to the next spec. The last spec's `next` is unused,
            // same as in Linux. For a non-final spec, `next` must cover
            // the current spec plus its NUL-terminated params and keep the
            // next spec 8-byte aligned.
            if i + 1 < target_count {
                let min_next = DM_TARGET_SPEC_LEN + params_len + 1;
                if next < min_next || next % 8 != 0 {
                    return_errno_with_message!(
                        Errno::EINVAL,
                        "invalid dm_target_spec next offset"
                    );
                }
                offset = offset.checked_add(next).ok_or_else(|| {
                    Error::with_message(Errno::EINVAL, "dm_target_spec next overflow")
                })?;
            }
        }

        Ok(())
    }

    fn handle_dev_suspend(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let flags = get_u32(&header, OFF_FLAGS);
        let name = parse_name(&header)?;
        check_name(name)?;

        let device = DmControlDevice::lookup_device(name)
            .ok_or_else(|| Error::with_message(Errno::ENXIO, "device not found"))?;

        if flags & DM_SUSPEND_FLAG != 0 {
            // Suspend
            device
                .suspend()
                .map_err(|e| Error::with_message(Errno::EINVAL, e))?;
        } else {
            // Resume. A device with no table at all (freshly DEV_CREATE'd,
            // never TABLE_LOAD'd) cannot be resumed; Linux's `dm_resume`
            // reports -EINVAL in this case (dm.c:3111-3125).
            if matches!(device.get_tables(), (None, None)) {
                return_errno_with_message!(Errno::EINVAL, "device has no table to resume");
            }

            // Promote the inactive table only if one exists; an
            // unconditional swap would move the *active* table into the
            // inactive slot and leave the device without a live table
            // (e.g., on a repeated resume).
            if device.get_tables().1.is_some() {
                device.swap_table();
            }
            device
                .resume()
                .map_err(|e| Error::with_message(Errno::EINVAL, e))?;

            // Register the device in the block-device registry when it
            // becomes live (has an active table) for the first time.
            //
            // Note: block devices registered at runtime do not get a
            // /dev node automatically (the devtmpfs nodes are created in
            // the first-process stage, before any DM device exists), so
            // user space is expected to `mknod /dev/dm-N` with the
            // device number reported by DEV_CREATE/DEV_STATUS. This is an
            // intentional simplification.
            let mut registry = DEVICE_REGISTRY.lock();
            if let Some(entry) = registry.get_mut(name) {
                if !entry.registered && entry.device.get_active_table().is_some() {
                    aster_block::register(entry.device.clone()).map_err(|_| {
                        Error::with_message(Errno::EIO, "block register failed")
                    })?;
                    entry.registered = true;
                }
            }
        }

        // Report the table-presence flags (`dm_ioctl.flags`), as
        // `__dev_status` does in Linux.
        write_back_present_flags(arg, &device, 0)
    }

    fn handle_dev_status(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;
        let name = parse_name(&header)?;
        check_name(name)?;

        let device = DmControlDevice::lookup_device(name)
            .ok_or_else(|| Error::with_message(Errno::ENXIO, "device not found"))?;

        // Report the real open count (`dm_ioctl.open_count`).
        current_userspace!().write_bytes(arg + OFF_OPEN_COUNT, &device.open_count().to_le_bytes())?;

        // Report the table-presence flags (`dm_ioctl.flags`).
        write_back_present_flags(arg, &device, 0)?;

        // Report the real device number (`dm_ioctl.dev`).
        current_userspace!()
            .write_bytes(arg + OFF_DEV, &device.id().as_encoded_u64().to_le_bytes())?;

        Ok(())
    }

    fn handle_list_versions(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let data_size = get_u32(&header, OFF_DATA_SIZE) as usize;
        let data_start = get_u32(&header, OFF_DATA_START) as usize;

        let targets = aster_dm::snapshot_targets();

        // Build the `struct dm_target_versions` chain in the data area:
        // each entry is the 16-byte header (next + version[3]) followed by
        // the NUL-terminated name, padded to an 8-byte boundary; `next` is
        // the offset from the current entry to the following one (0 for
        // the last entry), as in Linux's `list_versions`.
        let mut out: Vec<u8> = Vec::new();
        let mut entry_offsets: Vec<usize> = Vec::new();
        for (name, version) in &targets {
            let entry_offset = out.len();
            entry_offsets.push(entry_offset);
            out.resize(entry_offset + DM_TARGET_VERSIONS_HEADER_LEN, 0);
            out[entry_offset + 4..entry_offset + 8]
                .copy_from_slice(&version.major.to_le_bytes());
            out[entry_offset + 8..entry_offset + 12]
                .copy_from_slice(&version.minor.to_le_bytes());
            out[entry_offset + 12..entry_offset + 16]
                .copy_from_slice(&version.patch.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            let aligned = align8(out.len());
            out.resize(aligned, 0);
        }
        for (i, &entry_offset) in entry_offsets.iter().enumerate() {
            let next = if i + 1 < entry_offsets.len() {
                (entry_offsets[i + 1] - entry_offset) as u32
            } else {
                0
            };
            out[entry_offset..entry_offset + 4].copy_from_slice(&next.to_le_bytes());
        }

        // `data_start <= data_size` was validated by `check_version`.
        let avail = data_size - data_start;
        if out.len() > avail {
            // Not enough room: report DM_BUFFER_FULL_FLAG, same as Linux.
            // Write the flag literally instead of OR-ing it into the input
            // flags: Linux's `validate_params` strips output-only flags
            // from the input, so they must never be echoed back.
            current_userspace!()
                .write_bytes(arg + OFF_FLAGS, &DM_BUFFER_FULL_FLAG.to_le_bytes())?;
            return Ok(());
        }

        if !out.is_empty() {
            current_userspace!().write_bytes(arg + data_start, &out)?;
        }
        // Report the size actually used, as Linux does.
        let used = (data_start + out.len()) as u32;
        current_userspace!().write_bytes(arg + OFF_DATA_SIZE, &used.to_le_bytes())?;

        Ok(())
    }

    fn handle_table_status(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let flags = get_u32(&header, OFF_FLAGS);
        let query_inactive = (flags & DM_QUERY_INACTIVE_TABLE_FLAG) != 0;
        let name = parse_name(&header)?;
        check_name(name)?;

        let device = DmControlDevice::lookup_device(name)
            .ok_or_else(|| Error::with_message(Errno::ENXIO, "device not found"))?;

        let (active_table, inactive_table) = device.get_tables();
        let table = if query_inactive {
            inactive_table.as_ref()
        } else {
            active_table.as_ref()
        };

        // Serialize the table as a `struct dm_target_spec` chain (the DM
        // ABI, cf. Linux's `retrieve_status`): each spec is followed by
        // its NUL-terminated parameter string, padded to an 8-byte
        // boundary. On TABLE_STATUS, a spec's `next` field is the offset
        // from the *first* spec (i.e., from `data_start`) to the following
        // spec; for the last spec it points one past the end of the chain.
        //
        // The parameter string always uses the STATUSTYPE_TABLE form
        // (the ctr parameters), regardless of whether the caller set
        // DM_STATUS_TABLE_FLAG; this matches what DM tables are usually
        // queried for and keeps the target interface simple.
        let mut out: Vec<u8> = Vec::new();
        let mut spec_offsets: Vec<usize> = Vec::new();
        let nr_targets = table.map_or(0, |table| table.targets().len());
        if let Some(table) = table {
            for target in table.targets() {
                let spec_offset = out.len();
                spec_offsets.push(spec_offset);
                out.resize(spec_offset + DM_TARGET_SPEC_LEN, 0);
                out[spec_offset..spec_offset + 8]
                    .copy_from_slice(&target.begin.to_le_bytes());
                out[spec_offset + 8..spec_offset + 16]
                    .copy_from_slice(&target.len.to_le_bytes());
                // status (offset 16): always 0; per-target error reporting
                // is not implemented yet.
                let type_name = target.type_name().as_bytes();
                let name_len = type_name.len().min(DM_TARGET_TYPE_LEN);
                out[spec_offset + 24..spec_offset + 24 + name_len]
                    .copy_from_slice(&type_name[..name_len]);
                out.extend_from_slice(target.status_params().as_bytes());
                out.push(0);
                let aligned = align8(out.len());
                out.resize(aligned, 0);
            }
        }
        for (i, &spec_offset) in spec_offsets.iter().enumerate() {
            let next = if i + 1 < spec_offsets.len() {
                spec_offsets[i + 1] as u32
            } else {
                out.len() as u32
            };
            out[spec_offset + 20..spec_offset + 24].copy_from_slice(&next.to_le_bytes());
        }

        // Write back `target_count`, as Linux does.
        current_userspace!()
            .write_bytes(arg + OFF_TARGET_COUNT, &(nr_targets as u32).to_le_bytes())?;

        let data_size = get_u32(&header, OFF_DATA_SIZE) as usize;
        let data_start = get_u32(&header, OFF_DATA_START) as usize;
        let avail = data_size - data_start;

        if out.len() > avail {
            // The buffer cannot hold the whole chain: report
            // DM_BUFFER_FULL_FLAG instead of writing a truncated chain
            // (a deliberate simplification; Linux emits the prefix that
            // fits).
            write_back_present_flags(arg, &device, DM_BUFFER_FULL_FLAG)?;
            return Ok(());
        }

        if !out.is_empty() {
            current_userspace!().write_bytes(arg + data_start, &out)?;
        }
        write_back_present_flags(arg, &device, 0)?;
        // Report the size actually used, as Linux does.
        let used = (data_start + out.len()) as u32;
        current_userspace!().write_bytes(arg + OFF_DATA_SIZE, &used.to_le_bytes())?;

        Ok(())
    }
}

pub(super) fn init_in_first_kthread() {
    aster_dm::init();
    char::register(DmControlDevice::new()).unwrap();
}
