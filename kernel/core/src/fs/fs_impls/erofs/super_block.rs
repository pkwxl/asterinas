// SPDX-License-Identifier: MPL-2.0

//! On-disk erofs superblock: decoding, validation, and geometry.
//!
//! This module will own the raw on-disk layout (`#[repr(C)]`, anchored
//! to `linux/fs/erofs/erofs_fs.h`), the validated in-memory
//! representation, the feature-bit predicates, the superblock checksum
//! verification (consuming `utils::crc32c` over the checksum interval —
//! the interval formula lives here, not in `utils`), and the cross-file
//! on-disk constants (`SUPER_OFFSET`, `SUPER_MAGIC_V1`, and the
//! compat/incompat bitflag sets).
//!
//! Interim placeholder (T-021 skeleton): the decoding body lands with
//! T-022 and the mount-time validation sequence with T-023. Only the
//! minimal type shell required by the `Erofs` handle is present;
//! field-level shapes are deliberately not pre-declared here.
//!
//! Boundary: field-level decoding and predicates only — the assembly
//! and validation *order* decisions belong solely to
//! `fs.rs::Erofs::open`.

/// Validated in-memory mirror of the on-disk superblock.
///
/// Placeholder form: the real decoded geometry (block size, root nid,
/// feature sets, uuid, volume name) lands with T-022.
#[derive(Debug)]
pub(super) struct SuperBlock;
