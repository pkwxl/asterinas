// SPDX-License-Identifier: MPL-2.0

//! Extended attributes for erofs (read-only).
//!
//! Responsibilities:
//! - dual-storage iteration over inline ibody entries and shared-block
//!   entries (identical on-disk entry format);
//! - the `get`/`list` entry points, hosted as inherent methods on
//!   `Inode` and forwarded one-line from `impl_for_vfs`;
//! - the bloom-filter gate (`h_name_filter`) on the get path;
//! - the ACL value read channel ("system.posix_acl_access/default").
//!
//! All metadata reads in this module (ibody header, shared ids, entries,
//! shared-area bases) are point-of-use, uncached, byte-precise reads on
//! the device byte stream, governed by the "# Metadata reads" contract
//! in `mod.rs`; read-site position formulas come single-source from the
//! base-point family in `inode/mod.rs` (never recomputed here).
//! Set/remove are not hosted here: the trait overrides reject with
//! EROFS directly (read-only filesystem).
//!
//! # Locking
//!
//! This module owns no OS-level locks. Its synchronized state is two
//! once-cells: the per-inode `xattrs` cell on `Inode` and the
//! mount-time prefix-table cell on `Erofs`, published once during
//! `Erofs::open` before the handle is published and read-only ever
//! after. Both are leaves — neither is held while acquiring any other
//! lock, and mount-time loading never touches `mount_options`.
//!
//! The per-inode cell is initialized lazily on the first xattr access
//! through `try_call_once`: the fast path is a single atomic load;
//! concurrent first accessors serialize on the cell, and a failed
//! initialization restores the vacant state so the next access re-runs
//! it — mirroring the C bit-lock + EA_INITED pair (failures are never
//! cached; a success is cached for the inode lifetime). Initialization
//! reads only the inode description and the device byte stream: it
//! never touches `mount_options` or `inode_cache`, so the cell is a
//! leaf with no lock ordering, and it is only accessed in task
//! context — never from interrupt handlers or page-cache completion
//! callbacks. Mount-option gates read `mount_options` under its short
//! read guard after the cell access returns, so no lock is ever
//! nested here.

// AUTO-TODO(G-M17): Linux installs an sb->s_xattr handler list at mount
// and may load on-disk xattr name prefixes (erofs_xattr_prefixes_init).
// aster has no sb assembly surface: namespace dispatch is carried by the
// get/list entry points in this file; the prefix table itself is fully
// assembled at mount step 6 (`load_xattr_prefixes`, F15 — the state-A
// full load of the xattr-domain design), so long-prefix decoding
// consults a resident table; the sample text's "cut" wording predates
// that state-A decision (T-026 S01 decision 3, docs/T-026/S01/index.md).

use core::mem::offset_of;

use ostd::const_assert;

use super::{
    fs::Erofs,
    inode::{Inode, InodeDesc, InodeXattrState},
    prelude::*,
};

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

// ---------------------------------------------------------------------------
// The xattr-domain constants (T-026 S01; the S01 §3.3 master table plus
// the S05/S08 increment rows): on-disk facts transcribed from
// linux/fs/erofs/erofs_fs.h and include/uapi/linux/posix_acl(_xattr).h,
// referenced by path at their consumption sites, never forwarded
// through the prelude. Private to this module; not enum-ized (XA1
// value transcription). Unconsumed members carry transitional expects
// with their first-consumer slice (the expect-wave discipline; removed
// as the consumers land — the S09 slice reconciles the residue).
// ---------------------------------------------------------------------------

/// Name index of `user.*` attributes (`EROFS_XATTR_INDEX_USER`,
/// erofs_fs.h:212).
// First consumer: `resolve_query_name` (T-026 S06). Transitional
// expect — remove when that consumer lands.
#[expect(dead_code)]
const XATTR_INDEX_USER: u8 = 1; // erofs_fs.h:212

/// Name index of the access-ACL pseudo-name
/// (`EROFS_XATTR_INDEX_POSIX_ACL_ACCESS`, erofs_fs.h:213).
// First consumer: the list base-prefix row 2 (T-026 S07); the ACL
// exact-name match (S08) joins later. Transitional expect — remove
// when the first consumer lands.
#[expect(dead_code)]
const XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2; // erofs_fs.h:213

/// Name index of the default-ACL pseudo-name
/// (`EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT`, erofs_fs.h:214).
// First consumer: the list base-prefix row 3 (T-026 S07); the ACL
// exact-name match (S08) joins later. Transitional expect — remove
// when the first consumer lands.
#[expect(dead_code)]
const XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3; // erofs_fs.h:214

/// Name index of `trusted.*` attributes (`EROFS_XATTR_INDEX_TRUSTED`,
/// erofs_fs.h:215).
// First consumer: `resolve_query_name` (T-026 S06). Transitional
// expect — remove when that consumer lands.
#[expect(dead_code)]
const XATTR_INDEX_TRUSTED: u8 = 4; // erofs_fs.h:215

/// Name index of the (unmapped) Lustre attributes
/// (`EROFS_XATTR_INDEX_LUSTRE`, erofs_fs.h:216).
// No consumer by design: index 5 is the dead-index family (X10) — no
// namespace resolves to it (the query domain is 1/4/6 plus the ACL
// pair 2/3) and no list row exists, so on-disk entries carrying it
// simply never match and list skips them. Kept for the XA1 faithful
// transcription; the expect stays until the S09
// consumed-or-deleted reconciliation.
#[expect(dead_code)]
const XATTR_INDEX_LUSTRE: u8 = 5; // erofs_fs.h:216

/// Name index of `security.*` attributes (`EROFS_XATTR_INDEX_SECURITY`,
/// erofs_fs.h:217).
// First consumer: `resolve_query_name` (T-026 S06). Transitional
// expect — remove when that consumer lands.
#[expect(dead_code)]
const XATTR_INDEX_SECURITY: u8 = 6; // erofs_fs.h:217

/// Bit 7 of `e_name_index`: set when the entry refers to a long xattr
/// name prefix (`EROFS_XATTR_LONG_PREFIX`, erofs_fs.h:223).
// First consumer: the long-prefix hit test of the entry matching
// (T-026 S06). Transitional expect — remove when that consumer
// lands.
#[expect(dead_code)]
const XATTR_LONG_PREFIX: u8 = 0x80; // erofs_fs.h:223

/// The low 7 bits of `e_name_index`: the prefix-table index when the
/// long-prefix bit is set (`EROFS_XATTR_LONG_PREFIX_MASK`,
/// erofs_fs.h:224).
// First consumer: `Erofs::long_prefix` (T-026 S05). Transitional
// expect — remove when that consumer lands.
#[expect(dead_code)]
const XATTR_LONG_PREFIX_MASK: u8 = 0x7f; // erofs_fs.h:224

/// The bloom-filter bit width (`EROFS_XATTR_FILTER_BITS`,
/// erofs_fs.h:226): hashbits are `xxh32(...) & (XATTR_FILTER_BITS - 1)`.
// First consumer: the bloom denial predicate (T-026 S04).
// Transitional expect — remove when that consumer lands.
#[expect(dead_code)]
const XATTR_FILTER_BITS: u32 = 32; // erofs_fs.h:226

/// The mkfs-convention default of `h_name_filter`
/// (`EROFS_XATTR_FILTER_DEFAULT` = UINT32_MAX, erofs_fs.h:227).
// Dead constant by design (F51): EROFS_XATTR_FILTER_DEFAULT has zero
// kernel-side references — registered for transcription fidelity
// only. Never consumed (do not wire it into the gate), never
// deleted; the expect is permanent.
#[expect(dead_code)]
const FILTER_DEFAULT: u32 = u32::MAX; // erofs_fs.h:227

/// The bloom-filter seed (`EROFS_XATTR_FILTER_SEED`, erofs_fs.h:228):
/// the per-name hash input is `xxh32(suffix, FILTER_SEED + index)`.
// First consumer: the bloom denial predicate (T-026 S04).
// Transitional expect — remove when that consumer lands.
#[expect(dead_code)]
const FILTER_SEED: u32 = 0x25BBE08F; // erofs_fs.h:228

/// The xattr entry alignment unit (`EROFS_XATTR_ALIGN`: every entry —
/// header + name + value — is rounded up to `sizeof(erofs_xattr_entry)`,
/// erofs_fs.h:253). Same-sourced with the `RawXattrEntry` layout
/// assertion above (C5): the constant IS the structure size, never
/// the literal 4.
// First consumer: the entry-size walk helper (T-026 S02).
// Transitional expect — remove when that consumer lands.
#[expect(dead_code)]
const XATTR_ENTRY_ALIGN: usize = size_of::<RawXattrEntry>();

/// The fixed part of an on-disk long-prefix record (`base_index` +
/// the 4-byte rounded `infix_len` header precedes the infix bytes):
/// the lower bound of the record domain is 1 byte of infix
/// (`docs/T-015/S05/index.md` §2.2; the C shape is the
/// `erofs_xattr_long_prefix` flexible member — no struct is modeled,
/// U3).
// First consumer: `read_prefix_record` bounds (T-026 S05).
// Transitional expect — remove when that consumer lands.
#[expect(dead_code)]
const LONG_PREFIX_FIXED_LEN: usize = 1;

/// ACL tag: the file-owner entry (`ACL_USER_OBJ`,
/// include/uapi/linux/posix_acl.h:28).
// First consumer: `parse_posix_acl` (T-026 S08). Transitional
// expect — remove when that consumer lands.
#[expect(dead_code)]
const ACL_USER_OBJ: u16 = 0x01; // posix_acl.h:28

/// ACL tag: a named-user entry (`ACL_USER`, posix_acl.h:29).
// First consumer: `parse_posix_acl` (T-026 S08). Transitional
// expect — remove when that consumer lands.
#[expect(dead_code)]
const ACL_USER: u16 = 0x02; // posix_acl.h:29

/// ACL tag: the group-owner entry (`ACL_GROUP_OBJ`, posix_acl.h:30).
// First consumer: `parse_posix_acl` (T-026 S08). Transitional
// expect — remove when that consumer lands.
#[expect(dead_code)]
const ACL_GROUP_OBJ: u16 = 0x04; // posix_acl.h:30

/// ACL tag: a named-group entry (`ACL_GROUP`, posix_acl.h:31).
// First consumer: `parse_posix_acl` (T-026 S08). Transitional
// expect — remove when that consumer lands.
#[expect(dead_code)]
const ACL_GROUP: u16 = 0x08; // posix_acl.h:31

/// ACL tag: the mask entry (`ACL_MASK`, posix_acl.h:32).
// First consumer: `parse_posix_acl` (T-026 S08). Transitional
// expect — remove when that consumer lands.
#[expect(dead_code)]
const ACL_MASK: u16 = 0x10; // posix_acl.h:32

/// ACL tag: the others entry (`ACL_OTHER`, posix_acl.h:33).
// First consumer: `parse_posix_acl` (T-026 S08). Transitional
// expect — remove when that consumer lands.
#[expect(dead_code)]
const ACL_OTHER: u16 = 0x20; // posix_acl.h:33

/// The on-disk ACL value version word (`POSIX_ACL_XATTR_VERSION`,
/// include/uapi/linux/posix_acl_xattr.h: the `a_version` header
/// field of `posix_acl_xattr_header`).
// First consumer: `parse_posix_acl` (T-026 S08). Transitional
// expect — remove when that consumer lands.
#[expect(dead_code)]
const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;

/// The undefined-ACL-id sentinel (`ACL_UNDEFINED_ID` = (uid_t)-1,
/// posix_acl.h:21) — the sole invalid `e_id` for ACL_USER/ACL_GROUP
/// entries under the `init_user_ns` identity domain.
// First consumer: `parse_posix_acl` (T-026 S08). Transitional
// expect — remove when that consumer lands.
#[expect(dead_code)]
const ACL_UNDEFINED_ID: u32 = u32::MAX; // (-1), posix_acl.h:21

// ---------------------------------------------------------------------------
// The per-inode lazy init entry and state accessor (T-026 S01 §1.4).
// Hosted as an inherent `impl Inode` block here — the cross-module
// inherent-impl precedent of `inode/symlink.rs`/`inode/dir.rs`: the
// state lives on the handle (inode/mod.rs), the xattr logic lives
// here. One-line trait forwards join at `impl_for_vfs` (T-026 S09).
// ---------------------------------------------------------------------------

impl Inode {
    /// Lazily initializes and returns the per-inode xattr state.
    ///
    /// F3: failures are NOT cached — each call re-runs the init until
    /// success; on success the state is cached for the inode
    /// lifetime (the `spin::Once` mirror of the C bit-lock +
    /// EA_INITED pair; see the `# Locking` section of the module
    /// doc).
    ///
    /// The weak-upgrade guard runs BEFORE the cell call, outside the
    /// init closure: a guard error is not an init error and must not
    /// flow through the cell's failure semantics (it is structurally
    /// unreachable under the strong inode cache — the same guard as
    /// `Inode::fs`).
    // Transitional — first consumed by the get/list/acl entry chains
    // (T-026 S06–S08), themselves wired to the trait forwards at
    // S09; remove this expect then (as a dead-code-analysis root it
    // is what keeps the cell field read and the init function live
    // until then).
    #[expect(dead_code)]
    pub(in crate::fs::fs_impls::erofs) fn xattr_state(&self) -> Result<&InodeXattrState> {
        let fs = self.fs()?;
        let (nid, desc) = (self.ino(), self.desc());
        self.xattrs.try_call_once(|| init_inode_xattrs(&fs, nid, desc))
    }
}

/// The lazy-init body — the X1 three-state gate and the ibody read
/// points #10/#11 (`docs/T-015/S02/index.md` §2.1) — lands with the
/// ibody walk slice (T-026 S02). Slot-only shape until then:
/// unreachable, because `xattr_state` above has no caller until the
/// entry chains land. `fs` enters as a named parameter (the L4-edge
/// boundary note of `docs/T-015/S01/index.md` §3.2).
// Transitional compatibility layer — replace with the S02 body; the
// signature is final.
fn init_inode_xattrs(
    _fs: &Erofs,
    _nid: ErofsNid,
    _desc: &InodeDesc,
) -> Result<InodeXattrState> {
    return_errno_with_message!(Errno::EOPNOTSUPP, "xattr init walk not landed yet")
}

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
