// SPDX-License-Identifier: MPL-2.0

//! [`FileSystem`] trait implementation for [`Erofs`].
//!
//! Translates VFS-level root-inode, statfs, sync, and flag requests
//! into the erofs-internal surface. Erofs is read-only: `sync` is a
//! constant `Ok(())` (nothing is ever dirty), and flag
//! reconfiguration is the remount face — thin delegation to
//! `Erofs::reconfigure`, which carries the linux
//! `erofs_fc_reconfigure` semantics (RM4/RM12/O3/RM13).

use super::super::Erofs;
use crate::{
    fs::vfs::{
        file_system::{FileSystem, FsEventSubscriberStats, FsFlags, SuperBlock},
        inode::Inode,
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
        // Dispatch-only layer (T-010 §1.4 rule 6): the statfs
        // translation assembly lives in the family method
        // (`Erofs::vfs_super_block`); this face never inlines it —
        // the ext2 sample that assembles here is the negative
        // example.
        self.vfs_super_block()
    }

    fn flags(&self) -> FsFlags {
        self.fs_flags()
    }

    /// Sets the filesystem flags — the remount face (the framework
    /// calls this from `Mount::remount`, mount.rs:659-661, under the
    /// mount-topology write lock). Thin delegation to the family
    /// method `Erofs::reconfigure`, the second orchestration point
    /// besides `open`. Unlike the ext2 sample — which ignores the
    /// data string (fact M19, the negative example) — erofs MUST
    /// forward it: the RM4 parse errno family and the RM12 whole
    /// reset both hang off the string. `_ctx` is unused: linux
    /// reconfigure has no context consumer, same as the ext2 sample.
    // AUTO-FIXME(W-M07): The flags arriving here were produced by
    // `FsFlags::from(MountFlags)` via from_bits_truncate in the syscall
    // layer, so sb_flags outside the FsFlags bit set are silently
    // dropped where Linux's reconfigure_super rejects them with EINVAL
    // (RM8). The truncation happens upstream of any filesystem code and
    // cannot be closed inside erofs; accepted drift per the scope
    // ledger. The initramfs assertion encodes the expected difference;
    // the fix (a pre-check at the syscall layer) is a separate
    // framework-track candidate.
    fn set_fs_flags(&self, flags: FsFlags, data: Option<&str>, _ctx: &Context) -> Result<()> {
        // Dispatch-only layer (T-010 §1.4 rule 6): the whole
        // reconfigure semantics live in the family method; this face
        // never inlines them (the ext2 override that stores flags and
        // warns in place is the negative example of the family shape).
        self.reconfigure(flags, data)
    }

    fn fs_event_subscriber_stats(&self) -> &FsEventSubscriberStats {
        self.fs_event_subscriber_stats()
    }
}
