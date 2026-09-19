// SPDX-License-Identifier: MPL-2.0

//! Extended attributes for erofs inodes.
//!
//! This module will own the dual-storage iteration mechanism (inline
//! entries in the inode body plus shared xattr blocks), the `get`/
//! `list` public interfaces, the bloom-filter gate (`h_name_filter`,
//! consuming `utils::xxh32` with the seed `0x25BBE08F + index`), and
//! the ACL read channel. Set/remove operations do not exist: they are
//! rejected with `EROFS` at the VFS adapter. The mount-time
//! xattr-prefix assembly face is cut (G-M17) — namespace dispatch
//! lives in the get/list entry points themselves.
//!
//! Interim placeholder (T-021 skeleton): the iteration body lands with
//! T-026. Nothing is pre-declared here.
