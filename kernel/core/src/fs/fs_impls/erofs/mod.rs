// SPDX-License-Identifier: MPL-2.0

//! EROFS: the Enhanced Read-Optimized File System, a read-only Linux
//! filesystem designed for read-heavy workloads on fixed media.
//!
//! This module is currently being brought up (task T-021). The present,
//! interim state contains only the L0 utility layer; the ten-file layout
//! of `docs/T-010/analysis.md` §1 — `fs.rs`, `fs_type.rs`,
//! `super_block.rs`, `inode/{mod,data,file,dir,symlink}.rs`, `xattr.rs`,
//! `prelude.rs`, `impl_for_vfs/{mod,fs,inode}.rs`, `test_utils.rs` —
//! together with the `__log_prefix!` binding and the `init()` VFS
//! registration entry is filled in by the subsequent T-021 subtasks.
//! Until then the module is compiled but inert: nothing registers it,
//! and no erofs code runs on any boot path.
//!
//! # Current module structure
//!
//! | File    | Layer | Responsibility |
//! |---------|-------|----------------|
//! | `utils` | L0 | Checksum/hash primitives (`crc32c`, `xxh32`) with the embedded ktest vector suite; zero family dependencies |
//!
//! # References
//!
//! - `linux/fs/erofs/` (Linux v6.12.103, the behavioral parity baseline)

mod utils;
