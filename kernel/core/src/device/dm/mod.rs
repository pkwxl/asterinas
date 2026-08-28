// SPDX-License-Identifier: MPL-2.0

//! Device Mapper (DM) control device (/dev/mapper/control)
//!
//! This module implements the DM ioctl interface:
//! - DM_VERSION: version query
//! - DM_REMOVE_ALL: remove all mapped devices
//! - DM_LIST_DEVICES: list mapped devices (`dm_name_list` records)
//! - DM_DEV_CREATE: create mapped device (with optional uuid and
//!   DM_PERSISTENT_DEV_FLAG minor allocation)
//! - DM_DEV_REMOVE: remove mapped device
//! - DM_DEV_RENAME: rename a device or set its uuid
//! - DM_TABLE_LOAD: load inactive table
//! - DM_TABLE_CLEAR: discard the inactive table
//! - DM_TABLE_DEPS: list underlying devices of the (in)active table
//! - DM_DEV_SUSPEND: suspend/resume device
//! - DM_DEV_STATUS: query device status
//! - DM_DEV_WAIT: wait until the device's event number changes
//! - DM_LIST_VERSIONS: list registered target types
//! - DM_TABLE_STATUS: dump the (in)active table in the DM ABI format
//! - DM_TARGET_MSG: pass a message to a target (or the DM core)
//! - DM_DEV_SET_GEOMETRY: store a CHS geometry string
//! - DM_DEV_ARM_POLL: arm poll(2) notification for further events
//! - DM_GET_TARGET_VERSION: query the version of one target type

use core::{
    str,
    sync::atomic::{AtomicU32, Ordering},
};

use device_id::{DeviceId, MajorId, MinorId};
use ostd::{mm::VmIo, sync::WaitQueue};
use spin::Once;

use crate::{
    context::current_userspace,
    device::{Device, DeviceType, DevtmpfsInodeMeta, registry::char},
    events::IoEvents,
    fs::{file::PerOpenFileOps, vfs::inode::FileOps},
    prelude::*,
    process::{
        UserNamespace, credentials::capabilities::CapSet, posix_thread::AsPosixThread,
        signal::{PollHandle, Pollable, Pollee},
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
const DM_UUID_LEN: usize = 129;
const DM_TARGET_TYPE_LEN: usize = 16;

/// `sizeof(struct dm_ioctl)`: the fixed-size header every DM ioctl carries.
const DM_IOCTL_HEADER_LEN: usize = 312;
/// `sizeof(struct dm_target_spec)`: sector_start + length + status + next
/// + target_type[16]; the parameter string follows immediately after.
const DM_TARGET_SPEC_LEN: usize = 40;
/// `sizeof(struct dm_target_versions)` without the flexible `name[]`
/// member: next + version[3].
const DM_TARGET_VERSIONS_HEADER_LEN: usize = 16;
/// `sizeof(struct dm_target_deps)` without the flexible `dev[]` member:
/// count + padding.
const DM_TARGET_DEPS_HEADER_LEN: usize = 8;
/// The fixed part of a `struct dm_name_list` record: dev + next; the
/// NUL-terminated name follows immediately after.
const DM_NAME_LIST_HEADER_LEN: usize = 12;
/// The fixed part of a `struct dm_target_msg`: the sector; the
/// NUL-terminated message string follows immediately after.
const DM_TARGET_MSG_HEADER_LEN: usize = 8;

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
const OFF_EVENT_NR: usize = 32;
const OFF_DEV: usize = 40;
const OFF_NAME: usize = 48;
const OFF_UUID: usize = 176;

const DM_REMOVE_ALL_CMD: u32 = 1;
const DM_LIST_DEVICES_CMD: u32 = 2;
const DM_DEV_CREATE_CMD: u32 = 3;
const DM_DEV_REMOVE_CMD: u32 = 4;
const DM_DEV_RENAME_CMD: u32 = 5;
const DM_DEV_SUSPEND_CMD: u32 = 6;
const DM_DEV_STATUS_CMD: u32 = 7;
const DM_DEV_WAIT_CMD: u32 = 8;
const DM_TABLE_LOAD_CMD: u32 = 9;
const DM_TABLE_CLEAR_CMD: u32 = 10;
const DM_TABLE_DEPS_CMD: u32 = 11;
const DM_TABLE_STATUS_CMD: u32 = 12;
const DM_LIST_VERSIONS_CMD: u32 = 13;
const DM_TARGET_MSG_CMD: u32 = 14;
const DM_DEV_SET_GEOMETRY_CMD: u32 = 15;
const DM_DEV_ARM_POLL_CMD: u32 = 16;
const DM_GET_TARGET_VERSION_CMD: u32 = 17;

const DM_READONLY_FLAG: u32 = 1 << 0;
const DM_SUSPEND_FLAG: u32 = 1 << 1;
const DM_PERSISTENT_DEV_FLAG: u32 = 1 << 3;
const DM_STATUS_TABLE_FLAG: u32 = 1 << 4;
const DM_ACTIVE_PRESENT_FLAG: u32 = 1 << 5;
const DM_INACTIVE_PRESENT_FLAG: u32 = 1 << 6;
// DM_NOFLUSH_FLAG and DM_SKIP_LOCKFS_FLAG only steer the flush and
// lockfs steps of a Linux suspend; Asterinas has neither mechanism, so
// both flags are semantically no-ops here (see `handle_dev_suspend`).
const DM_NOFLUSH_FLAG: u32 = 1 << 7;
const DM_BUFFER_FULL_FLAG: u32 = 1 << 8;
const DM_SKIP_LOCKFS_FLAG: u32 = 1 << 10;
const DM_QUERY_INACTIVE_TABLE_FLAG: u32 = 1 << 12;
const DM_UUID_FLAG: u32 = 1 << 14;
const DM_DATA_OUT_FLAG: u32 = 1 << 16;
const DM_DEFERRED_REMOVE_FLAG: u32 = 1 << 17;

/// `dm_name_list` record flags (see dm-ioctl.h).
const DM_NAME_LIST_FLAG_HAS_UUID: u32 = 1;
const DM_NAME_LIST_FLAG_DOESNT_HAVE_UUID: u32 = 2;

/// Reads a little-endian `u32` field from a `dm_ioctl` header buffer.
fn get_u32(header: &[u8; DM_IOCTL_HEADER_LEN], offset: usize) -> u32 {
    u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap())
}

/// Reads a little-endian `u64` field from a `dm_ioctl` header buffer.
fn get_u64(header: &[u8; DM_IOCTL_HEADER_LEN], offset: usize) -> u64 {
    u64::from_le_bytes(header[offset..offset + 8].try_into().unwrap())
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

/// Extracts the NUL-terminated device uuid from a `dm_ioctl` header
/// ("" when none is set).
fn parse_uuid(header: &[u8; DM_IOCTL_HEADER_LEN]) -> Result<&str> {
    let uuid_bytes = &header[OFF_UUID..OFF_UUID + DM_UUID_LEN];
    let uuid_str = str::from_utf8(uuid_bytes)
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid device uuid"))?;
    Ok(uuid_str.split('\0').next().unwrap_or(""))
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
/// `DM_INACTIVE_PRESENT_FLAG` according to the tables, `DM_SUSPEND_FLAG`
/// while the device is suspended, `DM_READONLY_FLAG` while the device is
/// read-only and `DM_DEFERRED_REMOVE_FLAG` once deferred removal is
/// armed. The device's current event number (`dm_ioctl.event_nr`) is
/// written back as well, as `__dev_status` does.
///
/// The caller must not hold the `DEVICE_REGISTRY` lock.
fn write_back_present_flags(arg: usize, device: &DmDevice, extra_flags: u32) -> Result<()> {
    let (active_table, inactive_table) = device.get_tables();
    let mut out_flags = extra_flags;
    if device.is_readonly() {
        out_flags |= DM_READONLY_FLAG;
    }
    if device.is_deferred_remove() {
        out_flags |= DM_DEFERRED_REMOVE_FLAG;
    }
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
    current_userspace!().write_bytes(arg + OFF_EVENT_NR, &device_event_nr(device).to_le_bytes())?;
    Ok(())
}

/// Rounds `n` up to the next 8-byte boundary (the alignment of
/// `dm_target_spec`/`dm_target_versions` entries in the data area).
const fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Reads the NUL-terminated string at `arg + data_start` from user
/// space. The string must be NUL-terminated within `data_size` (cf.
/// Linux's `invalid_str`) and at most `max_len` bytes long (without the
/// NUL); otherwise EINVAL is returned.
fn read_data_string(
    arg: usize,
    data_start: usize,
    data_size: usize,
    max_len: usize,
) -> Result<String> {
    // `data_start <= data_size` was validated by `check_version`.
    let avail = data_size - data_start;
    let invalid = || Error::with_message(Errno::EINVAL, "data string missing or not NUL-terminated");
    if avail == 0 {
        return Err(invalid());
    }
    let mut buf = alloc::vec![0u8; avail.min(max_len.saturating_add(1))];
    current_userspace!().read_bytes(arg + data_start, &mut buf)?;
    // Reading `max_len + 1` bytes is enough: a longer string either has
    // no NUL in the window (EINVAL) or has its NUL at index `max_len` at
    // most, so a found NUL always satisfies the length limit.
    let Some(len) = buf.iter().position(|&b| b == 0) else {
        return Err(invalid());
    };
    String::from_utf8(buf[..len].to_vec())
        .map_err(|_| Error::with_message(Errno::EINVAL, "data string is not valid UTF-8"))
}

/// A DM device tracked by the control plane.
struct DmDevEntry {
    device: Arc<DmDevice>,
    /// The device ID allocated at DEV_CREATE time (see `dm_block_major`).
    id: DeviceId,
    /// The uuid assigned at DEV_CREATE or DEV_RENAME(DM_UUID_FLAG) time,
    /// if any.
    uuid: Option<String>,
    /// Whether the device has been registered in the block-device
    /// registry (this happens on the first resume, when the device
    /// becomes live).
    registered: bool,
    /// The value of the global event counter as of this device's last
    /// state change (cf. `md->event_nr` in Linux).
    event_nr: u32,
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

/// The global DM event counter (cf. `dm_global_event_nr` in Linux). It is
/// incremented on every device state change (create/remove/rename/
/// table_load/suspend/resume/clear); `dm_ioctl.event_nr` fields and the
/// DEV_WAIT/DEV_ARM_POLL machinery are based on it.
static GLOBAL_EVENT_NR: AtomicU32 = AtomicU32::new(0);

/// The wait queue behind DM_DEV_WAIT (cf. `md->eventq` in Linux). It is
/// woken on every event; waiters re-check their device's event number.
static EVENT_WAIT_QUEUE: WaitQueue = WaitQueue::new();

/// The per-open-file states of all currently open control-device files,
/// used to push event notifications to armed pollers.
static CONTROL_FILE_STATES: Mutex<Vec<Weak<DmControlFileState>>> = Mutex::new(Vec::new());

/// Reads the current global event counter.
fn global_event_nr() -> u32 {
    GLOBAL_EVENT_NR.load(Ordering::SeqCst)
}

/// Looks up the current event number of a device (0 if the device is not
/// in the registry, e.g. after removal).
///
/// The caller must not hold the `DEVICE_REGISTRY` lock.
fn device_event_nr(device: &DmDevice) -> u32 {
    let registry = DEVICE_REGISTRY.lock();
    registry
        .values()
        .find(|entry| entry.id == device.id())
        .map_or(0, |entry| entry.event_nr)
}

/// Records a device state change: bumps the global event counter, stores
/// it as the device's new event number (if `key` is given and the device
/// is still registered), and wakes up DEV_WAIT sleepers and armed
/// pollers (cf. `dm_table_event`/`dm_issue_global_event` in Linux).
///
/// The caller must not hold the `DEVICE_REGISTRY` lock.
fn trigger_event(key: Option<&str>) {
    let nr = GLOBAL_EVENT_NR.fetch_add(1, Ordering::SeqCst) + 1;
    if let Some(key) = key {
        let mut registry = DEVICE_REGISTRY.lock();
        if let Some(entry) = registry.get_mut(key) {
            entry.event_nr = nr;
        }
    }
    EVENT_WAIT_QUEUE.wake_all();
    let mut states = CONTROL_FILE_STATES.lock();
    // Prune dead entries while notifying the live ones.
    states.retain(|weak| {
        if let Some(state) = weak.upgrade() {
            state.pollee.notify(IoEvents::IN);
            true
        } else {
            false
        }
    });
}

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

/// Allocates a specific DM minor number (DM_PERSISTENT_DEV_FLAG);
/// returns `false` if it is already in use (cf. Linux `specific_minor`,
/// dm.c:2170-2187).
fn alloc_specific_minor(minor: u32) -> bool {
    debug_assert!(minor < MAX_DM_MINORS);
    let mut bitmap = MINOR_BITMAP.lock();
    let word = &mut bitmap[minor as usize / 64];
    let bit = 1u64 << (minor % 64);
    if *word & bit != 0 {
        return false;
    }
    *word |= bit;
    true
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

    /// Finds the device identified by a `dm_ioctl` header and returns its
    /// registry key (the current name) together with the device.
    ///
    /// The lookup follows Linux's priority (`__find_device_hash_cell`,
    /// dm-ioctl.c:909-953): a non-empty uuid wins over a non-empty name,
    /// which wins over a non-zero `dev` field. Specifying more than one
    /// identifier is invalid (EINVAL); a missing device is ENXIO.
    /// (LIST_DEVICES does not use this helper: there name and uuid act as
    /// prefix filters and may be combined.)
    ///
    /// On success the canonical name and uuid are written back into the
    /// user-space header, as Linux does in the same function.
    fn lookup_device(
        arg: usize,
        header: &[u8; DM_IOCTL_HEADER_LEN],
    ) -> Result<(String, Arc<DmDevice>)> {
        let name = parse_name(header)?;
        if !name.is_empty() {
            check_name(name)?;
        }
        let uuid = parse_uuid(header)?;
        let dev = get_u64(header, OFF_DEV);

        let not_found = || Error::with_message(Errno::ENXIO, "device not found");
        let registry = DEVICE_REGISTRY.lock();
        let (key, entry) = if !uuid.is_empty() {
            if !name.is_empty() || dev != 0 {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "uuid, name and dev are mutually exclusive"
                );
            }
            registry
                .iter()
                .find(|(_, entry)| entry.uuid.as_deref() == Some(uuid))
                .ok_or_else(not_found)?
        } else if !name.is_empty() {
            if dev != 0 {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "name and dev are mutually exclusive"
                );
            }
            registry.get_key_value(name).ok_or_else(not_found)?
        } else if dev != 0 {
            let id = DeviceId::from_encoded_u64(dev).ok_or_else(not_found)?;
            registry
                .iter()
                .find(|(_, entry)| entry.id == id)
                .ok_or_else(not_found)?
        } else {
            return Err(not_found());
        };
        let key = key.clone();
        let device = entry.device.clone();
        let entry_uuid = entry.uuid.clone();
        drop(registry);

        // Write back the canonical name and uuid (NUL-padded), so that a
        // lookup by uuid or dev also reports the name (and vice versa).
        let mut name_out = [0u8; DM_NAME_LEN];
        name_out[..key.len()].copy_from_slice(key.as_bytes());
        current_userspace!().write_bytes(arg + OFF_NAME, &name_out)?;
        let mut uuid_out = [0u8; DM_UUID_LEN];
        if let Some(uuid) = &entry_uuid {
            uuid_out[..uuid.len()].copy_from_slice(uuid.as_bytes());
        }
        current_userspace!().write_bytes(arg + OFF_UUID, &uuid_out)?;

        Ok((key, device))
    }

    fn create_device(
        name: &str,
        uuid: Option<String>,
        persistent_minor: Option<u32>,
    ) -> Result<(Arc<DmDevice>, DeviceId)> {
        let mut registry = DEVICE_REGISTRY.lock();
        if registry.contains_key(name) {
            // Linux's `dm_hash_insert` reports -EBUSY for a duplicate
            // name (the v4 interface has no DM_EXISTS_FLAG semantics).
            return_errno_with_message!(Errno::EBUSY, "device already exists");
        }
        if let Some(uuid) = &uuid {
            // A duplicate uuid is rejected with -EBUSY as well
            // (`dm_hash_insert`, dm-ioctl.c:283-294).
            if registry.values().any(|entry| entry.uuid.as_ref() == Some(uuid)) {
                return_errno_with_message!(Errno::EBUSY, "device uuid already exists");
            }
        }
        let minor = match persistent_minor {
            Some(minor) => {
                if !alloc_specific_minor(minor) {
                    return_errno_with_message!(Errno::EBUSY, "DM minor already in use");
                }
                minor
            }
            None => alloc_minor()
                .ok_or_else(|| Error::with_message(Errno::ENOSPC, "no free DM minor"))?,
        };
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
                uuid,
                registered: false,
                event_nr: 0,
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

/// Arms deferred removal on a device that still has open handles
/// (DM_DEFERRED_REMOVE_FLAG): the device is finalized once its last open
/// handle closes (cf. `dm_lock_for_deletion` + the last `dm_blk_close`
/// in Linux). `@cancel_deferred_remove` (DM_TARGET_MSG) disarms it.
fn arm_deferred_remove(device: &Arc<DmDevice>) {
    let device2 = device.clone();
    device.set_on_last_close(Box::new(move || deferred_remove_finalize(&device2)));
    device.mark_deferred_remove();
    // If every handle was already closed before the callback was armed
    // (racing with the open_count check of the caller), the callback
    // will never fire; finalize inline instead. The finalize is
    // idempotent, so a callback that did fire wins and this is a no-op.
    if device.open_count() == 0 {
        deferred_remove_finalize(device);
    }
}

/// Finalizes the (deferred) removal of a device: drops it from the
/// registry, unregisters the block device and frees its minor. The
/// device is located by identity rather than by name, so it works even
/// after a rename. Idempotent: only the first caller finds the registry
/// entry and performs the removal.
///
/// The caller must not hold the `DEVICE_REGISTRY` lock.
fn deferred_remove_finalize(device: &Arc<DmDevice>) {
    let entry = {
        let mut registry = DEVICE_REGISTRY.lock();
        let key = registry
            .iter()
            .find(|(_, entry)| Arc::ptr_eq(&entry.device, device))
            .map(|(key, _)| key.clone());
        key.and_then(|key| registry.remove(&key))
    };
    let Some(entry) = entry else {
        // Already finalized (e.g. by the inline path of
        // `arm_deferred_remove`, or a plain DEV_REMOVE after
        // `@cancel_deferred_remove`).
        return;
    };
    if entry.registered {
        let _ = aster_block::unregister(entry.id);
    }
    free_minor(entry.id.minor().get());
    // Clear the tables, same as a plain DEV_REMOVE.
    device.remove();
    trigger_event(None);
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
        // Like Linux's `dm_open`, remember the current global event
        // number: poll(2) on this file reports POLLIN once the counter
        // advances past it (see `dm_poll`).
        let state = Arc::new(DmControlFileState {
            pollee: Pollee::new(),
            last_event_nr: AtomicU32::new(global_event_nr()),
        });
        CONTROL_FILE_STATES.lock().push(Arc::downgrade(&state));
        Ok(Box::new(DmControlFile { state }))
    }
}

/// Per-open state of the control device (cf. `struct dm_file` in Linux).
struct DmControlFileState {
    /// The pollee notified (with `IoEvents::IN`) on every DM event.
    pollee: Pollee,
    /// The global event number as of the last open/DM_DEV_ARM_POLL.
    last_event_nr: AtomicU32,
}

struct DmControlFile {
    state: Arc<DmControlFileState>,
}

impl Drop for DmControlFile {
    fn drop(&mut self) {
        CONTROL_FILE_STATES
            .lock()
            .retain(|weak| match weak.upgrade() {
                Some(state) => !Arc::ptr_eq(&state, &self.state),
                None => false,
            });
    }
}

impl DmControlFile {
    /// The readiness of the control device (cf. `dm_poll` in Linux):
    /// readable iff the global event counter has advanced past this
    /// file's last armed event number.
    fn check_io_events(&self) -> IoEvents {
        let diff = global_event_nr().wrapping_sub(self.state.last_event_nr.load(Ordering::SeqCst));
        if (diff as i32) > 0 {
            IoEvents::IN
        } else {
            IoEvents::empty()
        }
    }
}

impl Pollable for DmControlFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.state
            .pollee
            .poll_with(mask, poller, || self.check_io_events())
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
            0 | DM_REMOVE_ALL_CMD
                | DM_LIST_DEVICES_CMD
                | DM_DEV_CREATE_CMD
                | DM_DEV_REMOVE_CMD
                | DM_DEV_RENAME_CMD
                | DM_DEV_STATUS_CMD
                | DM_DEV_SUSPEND_CMD
                | DM_DEV_WAIT_CMD
                | DM_TABLE_LOAD_CMD
                | DM_TABLE_CLEAR_CMD
                | DM_TABLE_DEPS_CMD
                | DM_TABLE_STATUS_CMD
                | DM_LIST_VERSIONS_CMD
                | DM_TARGET_MSG_CMD
                | DM_DEV_SET_GEOMETRY_CMD
                | DM_DEV_ARM_POLL_CMD
                | DM_GET_TARGET_VERSION_CMD
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
            DM_REMOVE_ALL_CMD => self.handle_remove_all(raw_ioctl)?,
            DM_LIST_DEVICES_CMD => self.handle_list_devices(raw_ioctl)?,
            DM_DEV_CREATE_CMD => self.handle_dev_create(raw_ioctl)?,
            DM_DEV_REMOVE_CMD => self.handle_dev_remove(raw_ioctl)?,
            DM_DEV_RENAME_CMD => self.handle_dev_rename(raw_ioctl)?,
            DM_TABLE_LOAD_CMD => self.handle_table_load(raw_ioctl)?,
            DM_DEV_SUSPEND_CMD => self.handle_dev_suspend(raw_ioctl)?,
            DM_DEV_STATUS_CMD => self.handle_dev_status(raw_ioctl)?,
            DM_DEV_WAIT_CMD => self.handle_dev_wait(raw_ioctl)?,
            DM_TABLE_CLEAR_CMD => self.handle_table_clear(raw_ioctl)?,
            DM_TABLE_DEPS_CMD => self.handle_table_deps(raw_ioctl)?,
            DM_LIST_VERSIONS_CMD => self.handle_list_versions(raw_ioctl)?,
            DM_TABLE_STATUS_CMD => self.handle_table_status(raw_ioctl)?,
            DM_TARGET_MSG_CMD => self.handle_target_msg(raw_ioctl)?,
            DM_DEV_SET_GEOMETRY_CMD => self.handle_dev_set_geometry(raw_ioctl)?,
            DM_DEV_ARM_POLL_CMD => self.handle_dev_arm_poll()?,
            DM_GET_TARGET_VERSION_CMD => self.handle_get_target_version(raw_ioctl)?,
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
        let uuid = parse_uuid(&header)?;
        let flags = get_u32(&header, OFF_FLAGS);

        // DM_PERSISTENT_DEV_FLAG: the caller requests a specific device
        // number, encoded in `dm_ioctl.dev` (cf. Linux `dev_create` +
        // `specific_minor`). The major must be the DM block-device major
        // and the minor must be in range; a minor that is already taken
        // is reported as EBUSY below.
        let persistent_minor = if flags & DM_PERSISTENT_DEV_FLAG != 0 {
            let id = DeviceId::from_encoded_u64(get_u64(&header, OFF_DEV)).ok_or_else(|| {
                Error::with_message(Errno::EINVAL, "invalid persistent device number")
            })?;
            if id.major() != dm_block_major() || id.minor().get() >= MAX_DM_MINORS {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "persistent device number out of DM range"
                );
            }
            Some(id.minor().get())
        } else {
            None
        };

        let uuid = (!uuid.is_empty()).then(|| String::from(uuid));
        let (_device, id) = DmControlDevice::create_device(name, uuid, persistent_minor)?;

        // Write back the allocated device number (`dm_ioctl.dev`) so that
        // user space can `mknod /dev/dm-N` with it.
        current_userspace!().write_bytes(arg + OFF_DEV, &id.as_encoded_u64().to_le_bytes())?;

        // Device creation is an event (it bumps the global event counter
        // and wakes up pollers).
        trigger_event(Some(name));

        Ok(())
    }

    fn handle_dev_remove(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let (key, device) = DmControlDevice::lookup_device(arg, &header)?;
        let flags = get_u32(&header, OFF_FLAGS);

        // A device with open handles cannot be removed right away. With
        // DM_DEFERRED_REMOVE_FLAG the removal is instead armed to happen
        // on the last close, and success is reported immediately (cf.
        // `dm_lock_for_deletion` in Linux's `dev_remove`).
        let open_count = device.open_count();
        if open_count != 0 {
            if flags & DM_DEFERRED_REMOVE_FLAG == 0 {
                return_errno_with_message!(Errno::EBUSY, "device still has open handles");
            }
            arm_deferred_remove(&device);
            return write_back_present_flags(arg, &device, DM_DEFERRED_REMOVE_FLAG);
        }

        let dev = device.id().as_encoded_u64();
        // Capture the final event number before the registry entry (which
        // stores it) goes away.
        let event_nr = device_event_nr(&device);

        DmControlDevice::remove_device(&key)?;
        // Clear the tables so that any stale references to the device
        // (e.g. a cached device file for a since-recycled minor number)
        // fail with an I/O error instead of silently serving I/O through
        // the removed device's table (cf. Linux `dev_destroy`).
        device.remove();
        trigger_event(None);

        // Report the final device state (`dm_ioctl.open_count` and
        // `dm_ioctl.dev`), same as `dev_status`.
        current_userspace!().write_bytes(arg + OFF_OPEN_COUNT, &open_count.to_le_bytes())?;
        current_userspace!().write_bytes(arg + OFF_DEV, &dev.to_le_bytes())?;
        current_userspace!().write_bytes(arg + OFF_EVENT_NR, &event_nr.to_le_bytes())?;

        Ok(())
    }

    /// DM_REMOVE_ALL: remove every mapped device. Devices with open
    /// handles are kept; if DM_DEFERRED_REMOVE is set they are armed for
    /// removal on last close instead. Never fails, like Linux's
    /// `remove_all` (dm-ioctl.c:530-535).
    fn handle_remove_all(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;
        let flags = get_u32(&header, OFF_FLAGS);
        let deferred = flags & DM_DEFERRED_REMOVE_FLAG != 0;

        // Collect the keys first: the registry is mutated while iterating.
        let keys: Vec<String> = DEVICE_REGISTRY.lock().keys().cloned().collect();
        for key in keys {
            let Some(device) = ({
                let registry = DEVICE_REGISTRY.lock();
                registry.get(&key).map(|entry| entry.device.clone())
            }) else {
                // Removed concurrently; nothing to do.
                continue;
            };
            if device.open_count() > 0 {
                if deferred {
                    arm_deferred_remove(&device);
                }
                continue;
            }
            if DmControlDevice::remove_device(&key).is_ok() {
                device.remove();
                trigger_event(None);
            }
        }

        // No output data, same as Linux (`param->data_size = 0`).
        current_userspace!().write_bytes(arg + OFF_DATA_SIZE, &0u32.to_le_bytes())?;
        Ok(())
    }

    /// DM_DEV_RENAME: rename a device, or (with DM_UUID_FLAG) set its
    /// uuid. The new name/uuid is the NUL-terminated string at
    /// `data_start` (Linux `dev_rename`, dm-ioctl.c:1044-1072).
    fn handle_dev_rename(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;
        let flags = get_u32(&header, OFF_FLAGS);
        let data_size = get_u32(&header, OFF_DATA_SIZE) as usize;
        let data_start = get_u32(&header, OFF_DATA_START) as usize;
        let change_uuid = flags & DM_UUID_FLAG != 0;

        let max_len = if change_uuid {
            DM_UUID_LEN - 1
        } else {
            DM_NAME_LEN - 1
        };
        let new = read_data_string(arg, data_start, data_size, max_len)?;
        if new.is_empty() {
            return_errno_with_message!(Errno::EINVAL, "empty new name or uuid");
        }
        if !change_uuid {
            check_name(&new)?;
        }

        let (old_key, device) = DmControlDevice::lookup_device(arg, &header)?;
        // The registry key under which the device is stored after the
        // rename (unchanged when only the uuid is set).
        let current_key = if change_uuid {
            old_key.clone()
        } else {
            new.clone()
        };

        let mut registry = DEVICE_REGISTRY.lock();
        if change_uuid {
            // The new uuid must be free (EBUSY) and a uuid can only be
            // set once (EINVAL), cf. Linux `dm_hash_rename`.
            if registry.values().any(|entry| entry.uuid.as_deref() == Some(new.as_str())) {
                return_errno_with_message!(Errno::EBUSY, "device uuid already exists");
            }
            let Some(entry) = registry.get_mut(&old_key) else {
                return_errno_with_message!(Errno::ENXIO, "device not found");
            };
            if entry.uuid.is_some() {
                return_errno_with_message!(Errno::EINVAL, "device uuid is already set");
            }
            entry.uuid = Some(new);
        } else {
            if registry.contains_key(&new) {
                return_errno_with_message!(Errno::EBUSY, "device already exists");
            }
            let Some(entry) = registry.remove(&old_key) else {
                return_errno_with_message!(Errno::ENXIO, "device not found");
            };
            registry.insert(new, entry);
        }
        drop(registry);

        // A rename/uuid change is an event (it bumps the global event
        // counter and wakes up pollers).
        trigger_event(Some(&current_key));

        // Note: the rename only affects this registry. The aster-block
        // device registry is indexed by `DeviceId`, and
        // `BlockDevice::name()` keeps returning the creation-time name
        // (a documented simplification, see `DmDevice`).

        // Report the table-presence flags, as `__dev_status` does after a
        // rename in Linux.
        write_back_present_flags(arg, &device, 0)
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

        let (key, device) = DmControlDevice::lookup_device(arg, &header)?;

        // Parse target count
        let target_count =
            u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;

        if target_count == 0 {
            return_errno_with_message!(Errno::EINVAL, "target_count must be > 0");
        }

        // Parse dm_target_spec chain and build table
        let mut table = DmTable::new();
        self.parse_target_specs(&data[data_start..], target_count, &mut table)?;

        // DM_READONLY_FLAG makes the loaded table read-only (in Linux it
        // becomes the table's open mode, cf. `get_mode`); writes to the
        // device are refused as long as it stays read-only.
        let flags = get_u32(&header, OFF_FLAGS);
        device.set_readonly(flags & DM_READONLY_FLAG != 0);

        device.load_table(table);
        trigger_event(Some(&key));

        // Report the device status, as `__dev_status` does at the end of
        // Linux's `table_load`.
        write_back_present_flags(arg, &device, 0)
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
        // DM_NOFLUSH_FLAG (skip the pre-suspend flush) and
        // DM_SKIP_LOCKFS_FLAG (skip the filesystem freeze/thaw) are
        // accepted but have no effect: this implementation has neither a
        // flush nor a lockfs step in its suspend path.
        let _ = flags & (DM_NOFLUSH_FLAG | DM_SKIP_LOCKFS_FLAG);
        let (key, device) = DmControlDevice::lookup_device(arg, &header)?;

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
            if let Some(entry) = registry.get_mut(&key) {
                if !entry.registered && entry.device.get_active_table().is_some() {
                    aster_block::register(entry.device.clone()).map_err(|_| {
                        Error::with_message(Errno::EIO, "block register failed")
                    })?;
                    entry.registered = true;
                }
            }
        }

        // Both suspend and resume are events (they bump the global event
        // counter and wake up pollers).
        trigger_event(Some(&key));

        // Report the table-presence flags (`dm_ioctl.flags`), as
        // `__dev_status` does in Linux.
        write_back_present_flags(arg, &device, 0)
    }

    fn handle_dev_status(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let (_key, device) = DmControlDevice::lookup_device(arg, &header)?;

        // Report the real open count (`dm_ioctl.open_count`).
        current_userspace!().write_bytes(arg + OFF_OPEN_COUNT, &device.open_count().to_le_bytes())?;

        // Report the table-presence flags (`dm_ioctl.flags`).
        write_back_present_flags(arg, &device, 0)?;

        // Report the real device number (`dm_ioctl.dev`).
        current_userspace!()
            .write_bytes(arg + OFF_DEV, &device.id().as_encoded_u64().to_le_bytes())?;

        Ok(())
    }

    /// DM_DEV_WAIT: sleep until the device's event number differs from
    /// the input `dm_ioctl.event_nr`, then report the device status
    /// (Linux `dev_wait` + `dm_wait_event`). Interrupted by signals
    /// (EINTR).
    fn handle_dev_wait(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;
        let waited_nr = get_u32(&header, OFF_EVENT_NR);

        let (key, device) = DmControlDevice::lookup_device(arg, &header)?;

        // Wait for a notification event. Divergence from Linux: if the
        // device is removed (or renamed) while waiting, Linux keeps
        // sleeping, while we wake up and report ENXIO below (the
        // registry key is the only handle we have on the device).
        EVENT_WAIT_QUEUE.pause_until(|| {
            let registry = DEVICE_REGISTRY.lock();
            match registry.get(&key) {
                Some(entry) => (entry.event_nr != waited_nr).then_some(()),
                None => Some(()),
            }
        })?;

        if !DEVICE_REGISTRY.lock().contains_key(&key) {
            return_errno_with_message!(Errno::ENXIO, "device not found");
        }

        // Report the device status, as `__dev_status` does in Linux.
        // Divergence: Linux additionally dumps the table status
        // (`retrieve_status`); we only report the header fields.
        current_userspace!().write_bytes(arg + OFF_OPEN_COUNT, &device.open_count().to_le_bytes())?;
        write_back_present_flags(arg, &device, 0)?;
        current_userspace!()
            .write_bytes(arg + OFF_DEV, &device.id().as_encoded_u64().to_le_bytes())?;

        Ok(())
    }

    /// DM_DEV_ARM_POLL: remember the current global event number for this
    /// open file; poll(2) on the file reports POLLIN once a further
    /// event arrives (Linux `dev_arm_poll`).
    fn handle_dev_arm_poll(&self) -> Result<()> {
        self.state
            .last_event_nr
            .store(global_event_nr(), Ordering::SeqCst);
        // Drop any readiness cached for the previous arming, so the next
        // poll re-evaluates against the new event number.
        self.state.pollee.invalidate();
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
        let (_key, device) = DmControlDevice::lookup_device(arg, &header)?;

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
        // With DM_STATUS_TABLE_FLAG the parameter string uses the
        // STATUSTYPE_TABLE form (the ctr parameters); without it the
        // STATUSTYPE_INFO form is used, which is the empty string for
        // the linear and error targets. Divergence: Linux's striped
        // target reports per-stripe health characters in the INFO form;
        // we report the empty string instead.
        let status_table = (flags & DM_STATUS_TABLE_FLAG) != 0;
        let mut out: Vec<u8> = Vec::new();
        let mut spec_offsets: Vec<usize> = Vec::new();
        // For each spec, the offset just past its NUL terminator (before
        // the 8-byte alignment padding); this is what Linux reports in
        // `data_size` for the last written spec.
        let mut spec_used_ends: Vec<usize> = Vec::new();
        // For each spec, the aligned offset just past it.
        let mut spec_ends: Vec<usize> = Vec::new();
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
                if status_table {
                    out.extend_from_slice(target.status_params().as_bytes());
                }
                out.push(0);
                spec_used_ends.push(out.len());
                let aligned = align8(out.len());
                out.resize(aligned, 0);
                spec_ends.push(out.len());
            }
        }

        let data_size = get_u32(&header, OFF_DATA_SIZE) as usize;
        let data_start = get_u32(&header, OFF_DATA_START) as usize;
        let avail = data_size - data_start;

        // Emit only the prefix of complete specs that fits into the
        // buffer, as Linux's `retrieve_status` does, and report
        // DM_BUFFER_FULL_FLAG when the chain was truncated.
        let nr_written = spec_ends.iter().take_while(|&&end| end <= avail).count();
        let written_len = if nr_written == 0 {
            0
        } else {
            spec_ends[nr_written - 1]
        };
        let truncated = nr_written < spec_offsets.len();
        for (i, &spec_offset) in spec_offsets.iter().take(nr_written).enumerate() {
            let next = if i + 1 < nr_written {
                spec_offsets[i + 1] as u32
            } else {
                written_len as u32
            };
            out[spec_offset + 20..spec_offset + 24].copy_from_slice(&next.to_le_bytes());
        }

        // Write back `target_count`, as Linux does (the total number of
        // targets, even when the chain was truncated).
        current_userspace!()
            .write_bytes(arg + OFF_TARGET_COUNT, &(nr_targets as u32).to_le_bytes())?;

        if written_len > 0 {
            current_userspace!().write_bytes(arg + data_start, &out[..written_len])?;
        }
        let extra_flags = if truncated { DM_BUFFER_FULL_FLAG } else { 0 };
        write_back_present_flags(arg, &device, extra_flags)?;
        if written_len > 0 {
            // Report the size actually used, as Linux does (up to the
            // end of the last written spec's parameter string).
            let used = (data_start + spec_used_ends[nr_written - 1]) as u32;
            current_userspace!().write_bytes(arg + OFF_DATA_SIZE, &used.to_le_bytes())?;
        }

        Ok(())
    }

    /// DM_LIST_DEVICES: dump the device list as a `struct dm_name_list`
    /// record chain (Linux `list_devices`, dm-ioctl.c:591-670). A
    /// non-empty input name (or uuid, with DM_UUID_FLAG) acts as a prefix
    /// filter.
    fn handle_list_devices(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let flags = get_u32(&header, OFF_FLAGS);
        let data_size = get_u32(&header, OFF_DATA_SIZE) as usize;
        let data_start = get_u32(&header, OFF_DATA_START) as usize;
        let name_pfx = parse_name(&header)?;
        let uuid_pfx = parse_uuid(&header)?;
        let want_uuid = flags & DM_UUID_FLAG != 0;

        // Snapshot the matching entries (sorted by name, since the
        // registry is a BTreeMap).
        let entries: Vec<(String, Option<String>, DeviceId, u32)> = DEVICE_REGISTRY
            .lock()
            .iter()
            .filter(|(name, entry)| {
                name.starts_with(name_pfx)
                    && entry
                        .uuid
                        .as_deref()
                        .unwrap_or("")
                        .starts_with(uuid_pfx)
            })
            .map(|(name, entry)| {
                (name.clone(), entry.uuid.clone(), entry.id, entry.event_nr)
            })
            .collect();

        // Each record is the fixed header (dev + next), the NUL-terminated
        // name padded to 8 bytes, then `event_nr` and the uuid-presence
        // flags, then (only with DM_UUID_FLAG) the NUL-terminated uuid,
        // padded to 8 bytes again.
        let mut out: Vec<u8> = Vec::new();
        let mut record_offsets: Vec<usize> = Vec::new();
        for (name, uuid, id, event_nr) in &entries {
            let record_offset = out.len();
            record_offsets.push(record_offset);
            out.resize(record_offset + DM_NAME_LIST_HEADER_LEN, 0);
            out[record_offset..record_offset + 8]
                .copy_from_slice(&id.as_encoded_u64().to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            out.resize(align8(out.len()), 0);
            out.extend_from_slice(&event_nr.to_le_bytes());
            let uuid_flag = if uuid.is_some() {
                DM_NAME_LIST_FLAG_HAS_UUID
            } else {
                DM_NAME_LIST_FLAG_DOESNT_HAVE_UUID
            };
            out.extend_from_slice(&uuid_flag.to_le_bytes());
            if want_uuid && let Some(uuid) = uuid {
                out.extend_from_slice(uuid.as_bytes());
                out.push(0);
                out.resize(align8(out.len()), 0);
            }
        }
        for (i, &record_offset) in record_offsets.iter().enumerate() {
            let next = if i + 1 < record_offsets.len() {
                (record_offsets[i + 1] - record_offset) as u32
            } else {
                0
            };
            out[record_offset + 8..record_offset + 12].copy_from_slice(&next.to_le_bytes());
        }

        // `data_start <= data_size` was validated by `check_version`.
        // Linux additionally requires room for the "no data" marker
        // (`nl->dev = 0`) even when the list is empty.
        let avail = data_size - data_start;
        if out.len() > avail || avail < 8 {
            // Not enough room: report DM_BUFFER_FULL_FLAG (written
            // literally, see `handle_list_versions`) and leave
            // `data_size` untouched, same as Linux.
            current_userspace!()
                .write_bytes(arg + OFF_FLAGS, &DM_BUFFER_FULL_FLAG.to_le_bytes())?;
            return Ok(());
        }

        if out.is_empty() {
            // Empty list: write the "no data" marker (dev == 0).
            current_userspace!().write_bytes(arg + data_start, &0u64.to_le_bytes())?;
        } else {
            current_userspace!().write_bytes(arg + data_start, &out)?;
        }
        // Report the size actually used (records only), as Linux does.
        let used = (data_start + out.len()) as u32;
        current_userspace!().write_bytes(arg + OFF_DATA_SIZE, &used.to_le_bytes())?;

        Ok(())
    }

    /// DM_TABLE_CLEAR: discard the inactive table (Linux `table_clear`,
    /// dm-ioctl.c:1605-1641). Idempotent, like in Linux.
    fn handle_table_clear(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let (key, device) = DmControlDevice::lookup_device(arg, &header)?;
        device.clear_inactive_table();
        trigger_event(Some(&key));

        write_back_present_flags(arg, &device, 0)
    }

    /// DM_TABLE_DEPS: list the underlying devices of the (in)active table
    /// as a `struct dm_target_deps` (Linux `retrieve_deps`,
    /// dm-ioctl.c:1646-1686).
    fn handle_table_deps(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let flags = get_u32(&header, OFF_FLAGS);
        let query_inactive = (flags & DM_QUERY_INACTIVE_TABLE_FLAG) != 0;
        let (_key, device) = DmControlDevice::lookup_device(arg, &header)?;

        let (active_table, inactive_table) = device.get_tables();
        let table = if query_inactive {
            inactive_table
        } else {
            active_table
        };
        let Some(table) = table else {
            // No table: report the device status but leave the data area
            // (and `data_size`) untouched, as Linux does.
            return write_back_present_flags(arg, &device, 0);
        };

        let deps = table.deps();
        let needed = DM_TARGET_DEPS_HEADER_LEN + 8 * deps.len();

        let data_size = get_u32(&header, OFF_DATA_SIZE) as usize;
        let data_start = get_u32(&header, OFF_DATA_START) as usize;
        let avail = data_size - data_start;
        if needed > avail {
            // Not enough room: report DM_BUFFER_FULL_FLAG without writing
            // `count` or `data_size`, same as Linux.
            return write_back_present_flags(arg, &device, DM_BUFFER_FULL_FLAG);
        }

        let mut out: Vec<u8> = Vec::with_capacity(needed);
        out.extend_from_slice(&(deps.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // padding
        for id in &deps {
            out.extend_from_slice(&id.as_encoded_u64().to_le_bytes());
        }
        current_userspace!().write_bytes(arg + data_start, &out)?;

        write_back_present_flags(arg, &device, 0)?;
        // Report the size actually used, as Linux does.
        let used = (data_start + needed) as u32;
        current_userspace!().write_bytes(arg + OFF_DATA_SIZE, &used.to_le_bytes())?;

        Ok(())
    }

    /// DM_GET_TARGET_VERSION: report the version of a single target type
    /// (named by `dm_ioctl.name`, not by the data area) as a one-entry
    /// `struct dm_target_versions` chain (the single-target path of
    /// Linux's `__list_versions`, dm-ioctl.c:704-765).
    fn handle_get_target_version(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let name = parse_name(&header)?;
        let target = aster_dm::lookup_target(name)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "target type not registered"))?;
        let version = target.version();

        let mut out: Vec<u8> = Vec::new();
        out.resize(DM_TARGET_VERSIONS_HEADER_LEN, 0);
        // next (offset 0): 0, the only entry.
        out[4..8].copy_from_slice(&version.major.to_le_bytes());
        out[8..12].copy_from_slice(&version.minor.to_le_bytes());
        out[12..16].copy_from_slice(&version.patch.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.resize(align8(out.len()), 0);

        let data_size = get_u32(&header, OFF_DATA_SIZE) as usize;
        let data_start = get_u32(&header, OFF_DATA_START) as usize;
        let avail = data_size - data_start;
        if out.len() > avail {
            // Not enough room: report DM_BUFFER_FULL_FLAG (written
            // literally, see `handle_list_versions`).
            current_userspace!()
                .write_bytes(arg + OFF_FLAGS, &DM_BUFFER_FULL_FLAG.to_le_bytes())?;
            return Ok(());
        }

        current_userspace!().write_bytes(arg + data_start, &out)?;
        // Report the size actually used, as Linux does.
        let used = (data_start + out.len()) as u32;
        current_userspace!().write_bytes(arg + OFF_DATA_SIZE, &used.to_le_bytes())?;

        Ok(())
    }

    /// DM_TARGET_MSG: pass a message to the target covering `sector`, or
    /// (with an '@' prefix) to the DM core (Linux `target_message` +
    /// `message_for_md`, dm-ioctl.c:1725-1846).
    fn handle_target_msg(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let data_size = get_u32(&header, OFF_DATA_SIZE) as usize;
        let data_start = get_u32(&header, OFF_DATA_START) as usize;
        if data_size > MAX_TABLE_LOAD_SIZE {
            return_errno_with_message!(Errno::EINVAL, "TARGET_MSG data_size too large");
        }

        let (_key, device) = DmControlDevice::lookup_device(arg, &header)?;

        // `struct dm_target_msg`: sector (u64) followed by the
        // NUL-terminated message string.
        if data_size - data_start < DM_TARGET_MSG_HEADER_LEN {
            return_errno_with_message!(Errno::EINVAL, "target message out of bounds");
        }
        let mut sector_buf = [0u8; DM_TARGET_MSG_HEADER_LEN];
        current_userspace!().read_bytes(arg + data_start, &mut sector_buf)?;
        let sector = u64::from_le_bytes(sector_buf);
        let message = read_data_string(
            arg,
            data_start + DM_TARGET_MSG_HEADER_LEN,
            data_size,
            usize::MAX,
        )?;
        let args: Vec<&str> = message.split_whitespace().collect();
        if args.is_empty() {
            return_errno_with_message!(Errno::EINVAL, "empty target message");
        }

        let mut extra_flags = 0;
        if args[0].starts_with('@') {
            // DM core messages (`message_for_md`); the only supported one
            // is `@cancel_deferred_remove`.
            if args[0] == "@cancel_deferred_remove" {
                if args.len() != 1 {
                    return_errno_with_message!(
                        Errno::EINVAL,
                        "invalid arguments for @cancel_deferred_remove"
                    );
                }
                device.cancel_deferred_remove();
            } else {
                return_errno_with_message!(Errno::EINVAL, "unsupported DM core message");
            }
        } else {
            let Some(table) = device.get_active_table() else {
                return_errno_with_message!(Errno::EINVAL, "device has no table");
            };
            match table.message(sector, &args) {
                Err(e) => return Err(Error::with_message(Errno::EINVAL, e)),
                Ok(None) => {}
                Ok(Some(out_str)) => {
                    // The message produced output: write it back at
                    // `data_start` and report DM_DATA_OUT_FLAG.
                    extra_flags = DM_DATA_OUT_FLAG;
                    let avail = data_size - data_start;
                    if out_str.len() + 1 > avail {
                        extra_flags |= DM_BUFFER_FULL_FLAG;
                    } else {
                        let mut out = out_str.into_bytes();
                        out.push(0);
                        current_userspace!().write_bytes(arg + data_start, &out)?;
                        let used = (data_start + out.len()) as u32;
                        current_userspace!().write_bytes(arg + OFF_DATA_SIZE, &used.to_le_bytes())?;
                    }
                }
            }
        }

        // Report the device status on success, as Linux does.
        write_back_present_flags(arg, &device, extra_flags)
    }

    /// DM_DEV_SET_GEOMETRY: store a CHS geometry string
    /// `"<cylinders> <heads> <sectors> <start>"` (Linux
    /// `dev_set_geometry`, dm-ioctl.c:1074-1123). The geometry is kept
    /// for reporting only and has no effect on I/O, same as in Linux.
    fn handle_dev_set_geometry(&self, raw_ioctl: RawIoctl) -> Result<()> {
        let arg = raw_ioctl.arg();
        let header = read_header(arg)?;

        let data_size = get_u32(&header, OFF_DATA_SIZE) as usize;
        let data_start = get_u32(&header, OFF_DATA_START) as usize;
        if data_size > MAX_TABLE_LOAD_SIZE {
            return_errno_with_message!(Errno::EINVAL, "SET_GEOMETRY data_size too large");
        }

        let (_key, device) = DmControlDevice::lookup_device(arg, &header)?;

        let geometry = read_data_string(arg, data_start, data_size, usize::MAX)?;
        let tokens: Vec<&str> = geometry.split_whitespace().collect();
        if tokens.len() != 4 {
            return_errno_with_message!(Errno::EINVAL, "geometry must have exactly 4 fields");
        }
        let mut fields = [0u64; 4];
        for (field, token) in fields.iter_mut().zip(tokens) {
            *field = token
                .parse::<u64>()
                .map_err(|_| Error::with_message(Errno::EINVAL, "invalid geometry field"))?;
        }
        let [cylinders, heads, sectors, start] = fields;
        // The range limits of `struct hd_geometry`.
        if cylinders > 65535 || heads > 255 || sectors > 255 {
            return_errno_with_message!(Errno::EINVAL, "geometry exceeds range limits");
        }
        // `cylinders * heads * sectors` is at most ~2^32, so it cannot
        // overflow a u64.
        if start > cylinders * heads * sectors {
            return_errno_with_message!(Errno::EINVAL, "geometry start beyond capacity");
        }

        device.set_geometry(geometry);

        // No output data, same as Linux (`param->data_size = 0`).
        current_userspace!().write_bytes(arg + OFF_DATA_SIZE, &0u32.to_le_bytes())?;
        Ok(())
    }
}

pub(super) fn init_in_first_kthread() {
    aster_dm::init();
    char::register(DmControlDevice::new()).unwrap();
}
