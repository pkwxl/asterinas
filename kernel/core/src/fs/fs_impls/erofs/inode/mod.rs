// SPDX-License-Identifier: MPL-2.0

//! Erofs inode family.
//!
//! The central type, `Inode`, represents one in-memory erofs inode and
//! is the concrete inode object exposed to the VFS adapter. Inodes are
//! identified by nid — erofs has no block groups, so inode numbers are
//! linear and the FS-level cache in `fs.rs` is keyed by nid directly.
//!
//! Interim placeholder (T-021 skeleton): the on-disk decoding — the
//! 64-byte regular and 32-byte compact/packed dual formats, the typed
//! payload enumeration, and the format-based type dispatch — lands with
//! T-022 (structures) and T-024 (metadata/namei). Only the minimal
//! handle shell required by the `FileSystem` trait surface is present;
//! payload shapes are deliberately not pre-declared here.
//!
//! # Submodules
//!
//! | Submodule | Responsibility                                     |
//! |-----------|----------------------------------------------------|
//! | `mod`     | The inode handle and dual-format decoding (T-022)  |
//! | `data`    | Block mapping and physical read primitives (T-025) |
//! | `file`    | Regular-file reads through the page cache (T-025)  |
//! | `dir`     | Dirent decoding and name lookup (T-024)            |
//! | `symlink` | Inline symlink target reads (T-024)                |
//!
//! # Locking
//!
//! An `Inode` is immutable after construction (nid, type, descriptor,
//! and payload are decoded once — the filesystem is read-only and never
//! updates atime); regular-file payloads hold a framework `PageCache`
//! that synchronizes itself and the VFS `Extension` slot synchronizes
//! itself, so there are no per-inode locks and no cross-inode lock
//! ordering. The `inode_cache` lock in `fs.rs` is released before any
//! inode operation runs (lookup hands out an `Arc<Inode>` clone and
//! operations execute outside the guard).

#![short_vis_path::add(erofs)]

mod data;
mod dir;
mod file;
mod symlink;

use super::{fs::Erofs, prelude::*};
use crate::fs::vfs::inode::Extension;

/// An erofs inode number (`nid`): the linear on-disk inode identifier.
pub(super) type ErofsNid = u64;

/// An in-memory erofs inode.
///
/// Interim placeholder (T-021 skeleton): the real handle additionally
/// carries the nid, the decoded descriptor, and the type-specific
/// payload; those shapes land with T-022/T-024. What is already final
/// here is the weak back-pointer discipline: `self_ref` is the only
/// link back to the filesystem handle (strong reference cycles are
/// forbidden family-wide) and the upgrade path carries an `EIO` guard.
pub struct Inode {
    type_: InodeType,
    self_ref: Weak<Erofs>,
    extension: Extension,
}

impl Inode {
    /// Constructs the placeholder root-directory inode handed out by
    /// the interim `Erofs::root_inode`.
    pub(super) fn placeholder_dir(self_ref: Weak<Erofs>) -> Self {
        Self {
            type_: InodeType::Dir,
            self_ref,
            extension: Extension::new(),
        }
    }

    /// Returns the inode number (nid).
    ///
    /// Placeholder: always 0 until the nid field lands with the T-022
    /// decoding body.
    pub(super) fn ino(&self) -> ErofsNid {
        0
    }

    /// Returns the inode type.
    pub(super) fn type_(&self) -> InodeType {
        self.type_
    }

    /// Returns a reference to the owning `Erofs` filesystem.
    ///
    /// The weak-upgrade failure guard is defensive by design: with the
    /// strong inode cache the mount always outlives the inodes it
    /// handed out, so the `EIO` below is structurally unreachable.
    pub(super) fn fs(&self) -> Result<Arc<Erofs>> {
        self.self_ref
            .upgrade()
            .ok_or_else(|| Error::with_message(Errno::EIO, "filesystem already dropped"))
    }

    /// Returns a reference to the VFS extension slot.
    pub(super) fn extension(&self) -> &Extension {
        &self.extension
    }
}
