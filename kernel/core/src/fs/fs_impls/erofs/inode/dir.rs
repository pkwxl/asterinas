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
//! Bring-up state (T-022 S04): the on-disk record `RawDirent` is in
//! place with its 6 layout assertions. The decoding walk (the dirent
//! index array plus the trailing name area), the by-name lookup, and
//! the getdents iteration land with T-024; nothing reads the record
//! until then — the `const_assert!` anchors keep the type and all
//! its fields live in every cfg (same rationale as `RawDeviceSlot`
//! in `super_block.rs`).

#![short_vis_path::add(erofs)]

use core::mem::offset_of;

use ostd::const_assert;

use super::super::prelude::*;

/// The erofs on-disk dirent (`erofs_dirent`,
/// linux/fs/erofs/erofs_fs.h:276-281; field semantics single-sourced
/// in `docs/T-001/analysis.md` §6.3).
///
/// A directory block is the index array (12 × N records) followed by
/// the name area: entry starts are always multiples of 12,
/// N = nameoff[0] / 12, names sort in strict alphabetical order, and
/// the format itself validates none of this — the two walks and
/// their bound checks belong to T-024. Consumers read the record by
/// value only; taking a reference to a field of a packed structure
/// is forbidden (A3).
// No deadness attribute: the permanent `const_assert!` layout
// anchors below reference the type and each of its fields, so both
// stay live in every cfg and an `#[expect(dead_code)]` would only be
// reported unfulfilled (same rationale as `RawDeviceSlot` in
// `super_block.rs`).
//
// `#[repr(C, packed)]` is load-bearing (A3): under the natural
// layout the le64 `nid` member would tail-pad the record to 16
// bytes, while the C side is `__packed` down to 12 (BUILD_BUG_ON at
// erofs_fs.h:451) — a plain `#[repr(C)]` would fail the size
// assertion below. This is the only packed structure on the erofs
// main column.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct RawDirent {
    /// The target inode number; no bound or existence check of any
    /// kind — iget is the backstop.
    pub nid: u64, // @0  __le64
    /// The in-block start offset of this entry's name. The two walk
    /// paths keep different strictnesses — readdir bounds-checks
    /// strictly while lookup masks with `blocksize - 1` (G8; each
    /// path preserves its own form, T-024).
    pub nameoff: u16, // @8  __le16
    /// Generic FT_* value domain, unchecked: readdir converts to
    /// DT_* (values ≥ 8 silently degrade to DT_UNKNOWN) while lookup
    /// passes the byte through. The field stays a raw u8 — the
    /// conversion helper lands with the walk (T-024).
    pub file_type: u8, // @10 __u8
    /// Reserved; never read (G5).
    pub reserved: u8, // @11 __u8
}

// Layout triple and per-field offsets (A1), each anchored to
// linux/fs/erofs/erofs_fs.h; the source-side counterpart of the size
// assertion is BUILD_BUG_ON at erofs_fs.h:451.
const_assert!(size_of::<RawDirent>() == 12); // erofs_fs.h:451
const_assert!(align_of::<RawDirent>() == 1); // __packed pins the alignment to 1
const_assert!(offset_of!(RawDirent, nid) == 0); // erofs_fs.h:277
const_assert!(offset_of!(RawDirent, nameoff) == 8); // erofs_fs.h:278
const_assert!(offset_of!(RawDirent, file_type) == 10); // erofs_fs.h:279
const_assert!(offset_of!(RawDirent, reserved) == 11); // erofs_fs.h:280
