// SPDX-License-Identifier: MPL-2.0

//! [`FileSystem`] trait implementation for [`Erofs`].
//!
//! Translates VFS-level root-inode, statfs, sync, and flag requests
//! into the erofs-internal surface. Erofs is read-only: `sync` is a
//! constant `Ok(())` (nothing is ever dirty), and flag
//! reconfiguration keeps the framework default until the remount
//! semantics land with T-023.

use aster_block::BLOCK_SIZE;

use super::super::Erofs;
use crate::{
    fs::{
        utils::NAME_MAX,
        vfs::{
            file_system::{FileSystem, FsEventSubscriberStats, FsFlags, SuperBlock},
            inode::Inode,
        },
    },
    prelude::*,
};

impl FileSystem for Erofs {
    fn name(&self) -> &'static str {
        "erofs"
    }

    fn sync(&self) -> Result<()> {
        // Read-only filesystem: nothing is ever dirty, nothing to flush.
        Ok(())
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root_inode()
    }

    fn sb(&self) -> SuperBlock {
        // Interim shape: the decoded geometry (magic included) lands
        // with the T-023 assembly sequence; until `open` succeeds this
        // method is unreachable.
        SuperBlock::new(0, BLOCK_SIZE, NAME_MAX, self.container_device_id())
    }

    fn flags(&self) -> FsFlags {
        self.fs_flags()
    }

    fn fs_event_subscriber_stats(&self) -> &FsEventSubscriberStats {
        self.fs_event_subscriber_stats()
    }
}
