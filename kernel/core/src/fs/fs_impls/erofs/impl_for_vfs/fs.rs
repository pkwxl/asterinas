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
        // Structurally unreachable failure (the ext2 precedent,
        // `ext2/impl_for_vfs/fs.rs:35-37`): the mount-time F11 read
        // validated the root and inserted it into the inode cache,
        // which only grows and holds strong references, so this
        // iget is always a cache hit for as long as the mount lives.
        self.root_inode().unwrap()
    }

    fn sb(&self) -> SuperBlock {
        // Interim shape: the decoded geometry (magic included) lands
        // with the statfs face of this task; `open` assembles fully
        // now, so this method is reachable and reports placeholder
        // values until then.
        SuperBlock::new(0, BLOCK_SIZE, NAME_MAX, self.container_device_id())
    }

    fn flags(&self) -> FsFlags {
        self.fs_flags()
    }

    fn fs_event_subscriber_stats(&self) -> &FsEventSubscriberStats {
        self.fs_event_subscriber_stats()
    }
}
