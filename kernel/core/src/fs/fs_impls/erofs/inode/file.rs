// SPDX-License-Identifier: MPL-2.0

//! Regular-file reads for erofs inodes.
//!
//! This module will own the buffered read path (through the page
//! cache) with the tail-of-last-page zero-fill obligation, and the
//! direct-I/O alignment gates. Write, resize, and preallocation paths
//! do not exist: the filesystem is read-only and every mutating entry
//! point is rejected with `EROFS` at the VFS adapter.
//!
//! Interim placeholder (T-021 skeleton): the read body lands with
//! T-025. Nothing is pre-declared here.

#![short_vis_path::add(erofs)]
