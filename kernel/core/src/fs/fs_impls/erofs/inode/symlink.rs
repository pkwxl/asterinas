// SPDX-License-Identifier: MPL-2.0

//! Inline symlink targets for erofs inodes.
//!
//! This module will own the inline-target read (the `i_size` bytes
//! that follow the inode body). Slow symlinks are cut: erofs never
//! stores them out-of-line, so there is no external-target path.
//!
//! Interim placeholder (T-021 skeleton): the symlink body lands with
//! T-024. Nothing is pre-declared here.

#![short_vis_path::add(erofs)]
