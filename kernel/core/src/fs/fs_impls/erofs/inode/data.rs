// SPDX-License-Identifier: MPL-2.0

//! Block mapping and physical read primitives for erofs inodes.
//!
//! This module will own the flat-mode block mapping (`map_blocks`,
//! including the datalayout rejection arm), the single-device identity
//! mapping (`map_dev`), and the metadata/data physical read primitives
//! that the inode family consumes. Public functions take decoded
//! layout parameters, geometry, and the device handle — never
//! `&Inode` — so the L2/L3 dependency edge stays acyclic.
//!
//! Interim placeholder (T-021 skeleton): the mapping body lands with
//! T-025 (data path). Nothing is pre-declared here.
//!
//! # Interrupt context
//!
//! Completion callbacks of the page-cache backend run in interrupt
//! context: they must not take blocking locks (including
//! `inode_cache`), must not allocate memory, and must not call into
//! the VFS.

#![short_vis_path::add(erofs)]
