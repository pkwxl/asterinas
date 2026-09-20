// SPDX-License-Identifier: MPL-2.0

//! VFS trait implementations for the erofs filesystem.
//!
//! This module bridges the erofs-specific types (`Erofs`, `Inode`) to
//! the generic VFS layer. The two child modules each contain `impl`
//! blocks for the corresponding VFS traits:
//!
//! * `fs` — `FileSystem` for `Erofs` (root, statfs, sync).
//! * `inode` — `FileOps` and `Inode` for `Inode` (I/O, metadata,
//!   lookup, extension slot, xattr glue).
//!
//! The adapter only dispatches; it holds no logic of its own. The
//! mutating members it implements answer `EROFS` (the filesystem is
//! read-only by construction); the directory-entry family needs no
//! member at all — the VFS mount-writable front gate refuses those
//! with `EROFS` before any filesystem code runs (erofs keeps
//! `FsFlags::RDONLY` permanently set; the shape landed with
//! T-024 S05).

mod fs;
mod inode;

// AUTO-TODO(G-M20): Generic VFS facilities gated at the mount/umount
// layer in Linux — frozen superblock transitions, user namespaces,
// idmap/exclusive mounts, emergency remount (SB_FORCE), and the
// MNT_FORCE/MNT_DETACH/MNT_EXPIRE umount flags — have no aster VFS
// counterpart, so no branch is implemented for any of them. The umount
// flag bits are accepted-and-ignored by the framework syscall layer
// (framework behavior, not erofs); negative-contrast coverage lives in
// the regression matrix (G-M20 rows), not in code assertions here.
