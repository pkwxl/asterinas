// SPDX-License-Identifier: MPL-2.0

//! Directory entries for erofs inodes.
//!
//! This module will own the dirent decoding (the `erofs_dirent`
//! header plus the nameoff array), the by-name lookup
//! (`erofs_namei` semantics), and the getdents iteration. It
//! deliberately does not consume `xxh32` — the bloom gate lives in
//! the xattr get chain — and it never updates atime on lookups or
//! reads.
//!
//! Interim placeholder (T-021 skeleton): the dirent body lands with
//! T-024. Nothing is pre-declared here.

#![short_vis_path::add(erofs)]
