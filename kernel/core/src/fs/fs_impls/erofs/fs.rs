// SPDX-License-Identifier: MPL-2.0

//! Core `Erofs` filesystem state for a mounted erofs volume.
//!
//! This module owns `Erofs`, the top-level handle for a mounted erofs
//! volume, together with the FS-level inode cache and the mount-option
//! carrier. The mount-time assembly sequence (read superblock ->
//! validate magic/features/checksum -> parse options -> read the root
//! inode -> construct the handle via `Arc::new_cyclic`) is owned by
//! `Erofs::open` and lands with T-023; the interim `open` below rejects
//! every mount with `EOPNOTSUPP` — a clear error, no panic, no
//! swallowing.
//!
//! Erofs is strictly read-only: there is no write path, no dirty
//! tracking, and no block allocation anywhere below this handle, so the
//! superblock, mount options, and geometry are decoded once during
//! `open` and stay immutable for the lifetime of the instance.
//!
//! # Locking
//!
//! All filesystem-wide state in `Erofs` is immutable after `open`
//! returns: the superblock, mount options, and geometry are decoded
//! once and never written back (erofs is read-only), so they carry no
//! locks. `flags` and `fs_event_subscriber_stats` use atomics. The only
//! lock is `inode_cache`, an nid-to-inode map guarded by an `RwMutex`
//! with double-checked locking: the fast path probes under a read lock;
//! on a miss, the slow path revalidates under the write lock,
//! constructs the inode (which may read metadata blocks), and inserts
//! it before releasing the guard. Nothing else may be locked while
//! `inode_cache` is held. Strong reference cycles are forbidden: the
//! handle keeps a weak self reference (`self_ref`) and hands out
//! `Weak<Erofs>` clones to inodes.

use core::sync::atomic::Ordering;

use device_id::DeviceId;

use super::{inode::Inode, prelude::*, super_block::SuperBlock};
use crate::fs::vfs::file_system::{AtomicFsFlags, FsEventSubscriberStats, FsFlags};

/// Top-level handle for a mounted erofs filesystem.
///
/// Owns the decoded superblock, the parsed mount options, and the
/// FS-level inode cache (keyed by nid: erofs has no block groups, so
/// the per-group cache host of allocation-based filesystems is lifted
/// to the filesystem handle).
pub struct Erofs {
    /// Backing block device.
    block_device: Arc<dyn BlockDevice>,
    /// Decoded and validated superblock (immutable after `open`).
    #[expect(dead_code)]
    super_block: SuperBlock,
    /// Parsed mount options (immutable after `open`).
    #[expect(dead_code)]
    mount_options: ErofsMountOptions,
    /// Recorded VFS filesystem flags.
    flags: AtomicFsFlags,
    /// FS event stats for VFS.
    fs_event_subscriber_stats: FsEventSubscriberStats,
    /// FS-level inode cache: nid -> inode identity anchor.
    #[expect(dead_code)]
    inode_cache: RwMutex<BTreeMap<ErofsNid, Arc<Inode>>>,
    /// Weak self reference handed out to inodes.
    self_ref: Weak<Erofs>,
}

/// Parsed mount options that affect reporting or geometry.
///
/// Interim placeholder: the real option set and its strict
/// unknown-option rejection (`EINVAL`, unlike the silently-ignoring
/// ext2 default) land with the T-023 assembly sequence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[expect(dead_code)]
pub(super) struct ErofsMountOptions;

impl Erofs {
    /// Opens and loads an erofs filesystem from a block device.
    ///
    /// Interim shape (T-021 skeleton): the assembly sequence — read the
    /// superblock, validate magic/blkszbits/features/checksum, parse
    /// the mount options, read the root inode, and construct the
    /// handle via `Arc::new_cyclic` — is owned by this function and
    /// lands with T-023. Until then every mount is rejected with a
    /// clear `EOPNOTSUPP` ("capability deferred"), deliberately
    /// distinct from the `EINVAL`/`EUCLEAN`/`EBADMSG` door that the
    /// final validation sequence will report, so no interim
    /// observation can be confused with the formal error surface.
    // AUTO-FIXME(G-M21): Several Linux mount-path allocation sites can
    // return -ENOMEM (superblock-private data, device slots, inode-cache
    // nodes, xattr scratch). Under Rust global-allocation semantics a failed
    // allocation aborts rather than yielding an error, and any intermediate
    // failure in `open` unwinds through Drop, so this implementation has no
    // reachable ENOMEM errno path. Do not add ENOMEM error arms here;
    // revisit only if fallible allocation APIs are introduced.
    pub(super) fn open(
        device: Arc<dyn BlockDevice>,
        flags: FsFlags,
        data: Option<&str>,
    ) -> Result<Arc<Self>> {
        // Consumed by the T-023 assembly sequence.
        let _ = (device, flags, data);
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "erofs mount assembly is not implemented yet"
        );
    }

    /// Returns the device ID of the underlying block device.
    pub(super) fn container_device_id(&self) -> DeviceId {
        self.block_device.id()
    }

    /// Returns the per file system flags.
    pub(super) fn fs_flags(&self) -> FsFlags {
        self.flags.load(Ordering::Relaxed)
    }

    /// Returns the fs event subscriber stats.
    pub(super) fn fs_event_subscriber_stats(&self) -> &FsEventSubscriberStats {
        &self.fs_event_subscriber_stats
    }

    /// Returns the root inode.
    ///
    /// Interim shape (T-021 skeleton): the real lookup — decode the
    /// root nid from the superblock and resolve it through
    /// `inode_cache` so a single nid always maps to a single inode
    /// identity — lands with the T-023 assembly sequence. Since `open`
    /// rejects every mount for now, this path is unreachable; it
    /// returns a placeholder directory inode so the `FileSystem`
    /// trait surface stays total.
    pub(super) fn root_inode(&self) -> Arc<Inode> {
        Arc::new(Inode::placeholder_dir(self.self_ref.clone()))
    }
}
