// SPDX-License-Identifier: MPL-2.0

//! VFS filesystem-type registration for erofs.
//!
//! `ErofsType` implements the `FsType` trait so the VFS layer can
//! discover and mount erofs volumes by name (`"erofs"`). Mount
//! deduplication follows the framework `FsCache`: one instance per
//! backing device, weak-upgrade based, with live RO/RW mismatches
//! surfacing as `EBUSY` from the framework.

use aster_systree::SysNode;
use device_id::DeviceId;

use super::{fs::Erofs, prelude::*};
use crate::fs::vfs::{
    file_system::FileSystem,
    registry::{FsCache, FsCreationCtx, FsProperties, FsType},
};

/// VFS-visible erofs filesystem type.
pub(super) struct ErofsType {
    cache: FsCache<DeviceId>,
}

pub(super) static EROFS_TYPE: ErofsType = ErofsType {
    cache: FsCache::new(),
};

impl FsType for ErofsType {
    type Key = DeviceId;

    fn name(&self) -> &'static str {
        "erofs"
    }

    fn properties(&self) -> FsProperties {
        FsProperties::NEED_DISK
    }

    fn create(&self, fs_creation_ctx: &mut FsCreationCtx) -> Result<Arc<dyn FileSystem>> {
        let disk = fs_creation_ctx.resolve_block_device()?.clone();
        let flags = fs_creation_ctx.flags();
        let args = fs_creation_ctx.args();
        Erofs::open(disk, flags, args).map(|fs| fs as Arc<dyn FileSystem>)
    }

    fn obtain_key_and_cache(
        &self,
        fs_creation_ctx: &mut FsCreationCtx,
    ) -> Option<(DeviceId, &FsCache<DeviceId>)> {
        let key = fs_creation_ctx
            .resolve_block_device()
            .ok()
            .map(|disk| disk.id())?;

        Some((key, &self.cache))
    }

    fn sysnode(&self) -> Option<Arc<dyn SysNode>> {
        // The static features subtree under /sys/fs/erofs is brought up
        // by the dedicated T-021 subtask S03; until then no sysfs
        // subtree is attached.
        None
    }
}
