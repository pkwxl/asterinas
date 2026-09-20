// SPDX-License-Identifier: MPL-2.0

//! Extended attributes for erofs inodes.
//!
//! This module will own the dual-storage iteration mechanism (inline
//! entries in the inode body plus shared xattr blocks), the `get`/
//! `list` public interfaces, the bloom-filter gate (`h_name_filter`,
//! consuming `utils::xxh32` with the seed `0x25BBE08F + index`), and
//! the ACL read channel. Set/remove operations do not exist: they are
//! rejected with `EROFS` at the VFS adapter. The sb-level xattr
//! handler-table face is cut (G-M17) — namespace dispatch lives in
//! the get/list entry points themselves — while the mount-time
//! long-prefix table load keeps a reserved call slot in
//! `Erofs::open` (`load_xattr_prefixes` below, F15): the slot is
//! final, the body lands with the xattr domain design (T-015).
//!
//! Bring-up state (T-022 S04): the two on-disk record headers are in
//! place — `RawXattrIbodyHeader` (the fixed 12-byte head that every
//! inline xattr area starts with) and `RawXattrEntry` (the 4-byte
//! entry header shared by the inline suffix and the shared xattr
//! space) — with their 5 + 5 layout assertions. No decode mirror
//! exists for either header (XA0): all validation and derivation
//! happen at the runtime walk, where each little-endian field gets
//! its single `from_le` in place (E1); the flexible members — the
//! `h_shared_xattrs[]` id array, `e_name[]`, and the trailing
//! name/value bytes — are deliberately not modeled (U3), their
//! elements read one at a time by the walk. The domain constants
//! (name indexes, long-prefix bits, bloom filter family, entry
//! alignment) and every consumer land with T-026; nothing reads
//! these headers until then — the `const_assert!` anchors keep both
//! types and all their fields live in every cfg (same rationale as
//! `RawDeviceSlot` in `super_block.rs`).

use core::mem::offset_of;

use ostd::const_assert;

use super::{fs::Erofs, prelude::*};

/// The erofs on-disk xattr ibody header (`erofs_xattr_ibody_header`,
/// linux/fs/erofs/erofs_fs.h:204-209; field semantics single-sourced
/// in `docs/T-001/analysis.md` §5.3).
///
/// Every inline xattr area starts with this header
/// (erofs_fs.h:201-202); a read-only filesystem carries no
/// `h_refcount` field. The trailing `h_shared_xattrs[]` shared-id
/// array is a flexible member and is not modeled (U3.1) — the walk
/// reads its elements as bare `u32`s, one `read_val` per id.
// No deadness attribute: the permanent `const_assert!` layout
// anchors below reference the type and each of its fields, so both
// stay live in every cfg and an `#[expect(dead_code)]` would only be
// reported unfulfilled (same rationale as `RawDeviceSlot` in
// `super_block.rs`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct RawXattrIbodyHeader {
    /// The name bloom-filter bitmap; bit value 1 means the name is
    /// not present (consumed by the get chain, T-026).
    pub h_name_filter: u32, // @0  __le32
    /// The number of shared-xattr references (the length of the
    /// trailing id array); no upper-bound check (≤ 255).
    pub h_shared_count: u8, // @4  __u8
    /// Reserved; never read (G5).
    pub h_reserved2: [u8; 7], // @5  __u8[7]
}

// Layout triple and per-field offsets (A1), each anchored to
// linux/fs/erofs/erofs_fs.h; the source-side counterpart of the size
// assertion is BUILD_BUG_ON at erofs_fs.h:445.
const_assert!(size_of::<RawXattrIbodyHeader>() == 12); // erofs_fs.h:445
const_assert!(align_of::<RawXattrIbodyHeader>() == 4); // the le32 member pins the alignment
const_assert!(offset_of!(RawXattrIbodyHeader, h_name_filter) == 0); // erofs_fs.h:205
const_assert!(offset_of!(RawXattrIbodyHeader, h_shared_count) == 4); // erofs_fs.h:206
const_assert!(offset_of!(RawXattrIbodyHeader, h_reserved2) == 5); // erofs_fs.h:207

/// The erofs on-disk xattr entry header (`erofs_xattr_entry`,
/// linux/fs/erofs/erofs_fs.h:231-237; field semantics single-sourced
/// in `docs/T-001/analysis.md` §5.4).
///
/// The single 4-byte record form for both storage sites — the inline
/// suffix that follows the ibody header and the shared xattr space.
/// The trailing variable-length region — `[e_name: e_name_len bytes]
/// [e_value: e_value_size bytes][padding up to a 4-byte multiple]`
/// with name and value contiguous, no intermediate alignment, and
/// padding bytes never read — is not modeled (U3.2); the name bytes
/// carry no NUL terminator (the length is `e_name_len` itself). Name
/// and value are read by byte offset at the walk (T-026).
// No deadness attribute — same const_assert liveness rationale as
// `RawXattrIbodyHeader` above.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct RawXattrEntry {
    /// The name length, excluding the prefix part; 0 is allowed
    /// (long-prefix exact full-name matching, POSIX ACL empty-name
    /// storage).
    pub e_name_len: u8, // @0  __u8
    /// The name index: bit 7 (`0x80`) is the long-prefix flag, the
    /// low 7 bits (`0x7f`) the prefix-table or short-prefix index.
    /// No independent check — bounds are checked at use (T-026).
    pub e_name_index: u8, // @1  __u8
    /// The value length; 0 is allowed. An undersized getxattr output
    /// buffer reports ERANGE at the consumption face (T-026).
    pub e_value_size: u16, // @2  __le16
}

// Layout triple and per-field offsets (A1), each anchored to
// linux/fs/erofs/erofs_fs.h; the source-side counterpart of the size
// assertion is BUILD_BUG_ON at erofs_fs.h:446.
const_assert!(size_of::<RawXattrEntry>() == 4); // erofs_fs.h:446
const_assert!(align_of::<RawXattrEntry>() == 2); // the le16 member pins the alignment
const_assert!(offset_of!(RawXattrEntry, e_name_len) == 0); // erofs_fs.h:232
const_assert!(offset_of!(RawXattrEntry, e_name_index) == 1); // erofs_fs.h:233
const_assert!(offset_of!(RawXattrEntry, e_value_size) == 2); // erofs_fs.h:234

/// F15 — the mount-time long-xattr name-prefix table load
/// (`erofs_xattr_prefixes_init`, `super.c:746-748`), called from
/// step 6 of `Erofs::open` (`fs.rs`).
///
/// Slot-only transitional shape: the call site and its position in
/// the assembly order are final (`open` is the single ordering
/// authority — F12 before this call, success after it), while the
/// body — gated by the on-disk prefix count, reading the prefix
/// area through the mirror fields, with its EFSCORRUPTED → EUCLEAN
/// error family — lands with the xattr domain design (T-015;
/// markers G-X02/G-X03, anchored here and in `fs.rs`). Until then
/// this accepts unconditionally: an image with a positive prefix
/// count mounts without the table (no interim rejection the real
/// body would have to walk back).
// Transitional compatibility layer — remove when the xattr domain
// implementation lands (T-026 executes the T-015 design); the call
// site itself is final.
pub(super) fn load_xattr_prefixes(_fs: &Erofs) -> Result<()> {
    Ok(())
}
