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

use ostd::{const_assert, mm::VmIo};

use super::{
    fs::Erofs,
    inode::{Inode, InodeDesc, InodeXattrState, suffix_xattr_start},
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
// Live since T-026 S02: consumed by `XattrEntryAt::entry_size`
// (the walk's ALIGN4 size helper).
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
        self.xattrs
            .try_call_once(|| init_inode_xattrs(&fs, nid, desc))
    }
}

/// The lazy-init body — the X1 three-state gate plus the ibody read
/// points #10/#11 (`docs/T-015/S02/index.md` §2.1; the walk half of
/// `erofs_init_inode_xattrs`, xattr.c:28-124). Runs only inside the
/// `try_call_once` closure of `xattr_state` above: never at
/// iget/mount time (the lazy-host decision — an X1-shaped inode
/// still igets Ok and serves stat/open; only the xattr syscalls
/// replay the init error, XAT-01/02). A failure publishes nothing
/// (the cell stays vacant, F3); a success freezes the state for the
/// inode lifetime.
fn init_inode_xattrs(fs: &Erofs, nid: ErofsNid, desc: &InodeDesc) -> Result<InodeXattrState> {
    // X1 three-state gate (xattr.c:54-77): pure arithmetic, zero
    // I/O, ahead of every device read; the judgement order mirrors
    // C (== 12 before < 12 — structural fidelity, three disjoint
    // domains).
    let isize_ = desc.xattr_isize; // the unvalidated decoded value (seam ①)
    let hdr = size_of::<RawXattrIbodyHeader>(); // = 12 (const_assert cross-check)
    if isize_ == hdr {
        // Exactly one bare 12-byte header: legal on disk but
        // undefined ("maybe use later with some new sb feature",
        // erofs_fs.h:199-203) → EOPNOTSUPP (X1a). get/list/acl all
        // pass it through.
        return_errno_with_message!(Errno::EOPNOTSUPP, "xattr ibody is a bare header");
    }
    if isize_ < hdr {
        if isize_ != 0 {
            // The (0, 12) defensive dead branch (F1: the value
            // domain is {0} ∪ {12, 16, 20, …} — icount's unconditional
            // 12 + 4×(icount−1) conversion cannot land inside the
            // open interval) → EUCLEAN. Transcribed as-is, with no
            // assertion and no debug_assert (dead-code family
            // discipline: a debug-build panic would not match the C
            // production baseline).
            return_errno_with_message!(Errno::EUCLEAN, "bogus xattr ibody size");
        }
        // No inline xattr area: C -ENOATTR == ENODATA (X1c). The
        // get/acl chains pass it through; the list chain converts it
        // to a 0-length listing (X35, honored by the list chain, S07).
        return_errno_with_message!(Errno::ENODATA, "no inline xattrs");
    }

    // Read point #10 (docs/T-011 S07 §3.2): the 12-byte ibody header,
    // a single read at `suffix_xattr_start` (= iloc + inode_isize;
    // the base-point family in `inode/mod.rs` is the single source —
    // never recomputed here). The usize cast is loss-free on 64-bit
    // targets (the read-site precedent).
    let pos = suffix_xattr_start(fs.super_block(), nid, desc);
    let raw = fs
        .block_device()
        .read_val::<RawXattrIbodyHeader>(pos as usize)?; // passthrough

    // XA0: in-place from_le at the walk point; `h_reserved2` is
    // dropped unread (F6). `h_name_filter` is extracted
    // unconditionally — regardless of the compat bit or the reserved
    // fields: the bloom *effectivity* gate (compat 0x4 ∧ reserved
    // == 0) and the xxh32 bit consumption belong to S04, evaluated
    // at each get entry (xattr.c:401-407), never here.
    let name_filter = u32::from_le(raw.h_name_filter);
    let shared_count = raw.h_shared_count as usize; // u8 direct read (E1)

    // Read point #11: one bare le32 per shared id, no isize upper
    // bound (F2: a crafted count overrunning the ibody reads the
    // ids anyway — the geometry imbalance surfaces later at the X23
    // walk gate, never as an init rejection). No ENOMEM arm exists:
    // allocation failure aborts in this tree (X2/G-M21);
    // shared_count == 0 is an empty Vec, zero allocation (F4 — the
    // C kmalloc(0)/ZERO_SIZE_PTR corner). The header above is read
    // even when shared_count == 0 and never short-circuited: the
    // full-support invariant (G-X06) — the id-array bytes decide the
    // inline entry-area start at the X23 gate, so even a
    // hypothetical shared-trimmed build would still have to skip
    // them; this build has no cfg trim face at all.
    let mut shared_ids = Vec::with_capacity(shared_count); // ≤ 255 × 4 B
    for i in 0..shared_count as u64 {
        let id_pos = pos + size_of::<RawXattrIbodyHeader>() as u64 + 4 * i;
        let id = u32::from_le(fs.block_device().read_val::<u32>(id_pos as usize)?); // host order
        shared_ids.push(id); // C :112 le32_to_cpu in place
    }
    // Publication freezes the state (S01-D1).
    Ok(InodeXattrState {
        name_filter,
        shared_ids,
    })
}

// ---------------------------------------------------------------------------
// The ibody entry walk (T-026 S02; `docs/T-015/S02/index.md` §2.2 — the
// walk half of `erofs_xattr_iter_inline`, xattr.c:314-356: the X23/X24
// gates and the advance; the consumption half — the foreach bodies with
// their three split points — belongs to the get/list chains, S06/S07).
// The shared-area walk (S03) reuses `XattrEntryAt` and
// `read_xattr_entry_at`: both storage sites share the on-disk entry
// format, so read point #12 has exactly one implementation.
// ---------------------------------------------------------------------------

/// A decoded single-entry view: the 4-byte record plus the geometry
/// of its variable-length region (read point #12's single form for
/// both the inline suffix and the shared xattr space). Decode mirror
/// of the XA0 discipline: `e_value_size` is from_le'd here, the two
/// u8 fields are direct reads; `e_name_index` keeps the long-prefix
/// bit as on disk, consumed by the entry matching (S06/S07) — never
/// rewritten here.
///
/// A view, not a copy: consumers read the name/value bytes through
/// `name_pos`/`value_pos` on the device byte stream (`read_bytes`,
/// one whole-name/whole-value read — the RD2① registered
/// read-granularity drift against C's per-block early-abort compare;
/// observable only under device fault injection).
pub(super) struct XattrEntryAt {
    /// The device-absolute offset of the 4-byte entry header — the
    /// base point of the name/value formulas.
    pos: u64,
    /// `e_name_len`, excluding the prefix part; 0 is allowed.
    e_name_len: u8,
    /// `e_name_index`: bit 7 (`0x80`) is the long-prefix flag, the
    /// low 7 bits the prefix-table/short-prefix index.
    // First reader: the get/list entry matching (T-026 S06/S07).
    // Transitional expect — remove when the first reader lands.
    #[expect(dead_code)]
    e_name_index: u8,
    /// `e_value_size`, already from_le'd (XA0 walk-point decode).
    e_value_size: u16,
}

// Transitional — `name_pos`/`value_pos` are first called by the
// get/list chain bodies (T-026 S06/S07), themselves wired to the
// trait forwards at S09; remove this expect when those consumers
// land.
#[expect(dead_code)]
impl XattrEntryAt {
    /// The entry's on-disk total size — `erofs_xattr_entry_size`
    /// (erofs_fs.h:254-260): header + name + value, rounded up to
    /// `XATTR_ENTRY_ALIGN` (the T-011 S04 §3 helper terminal shape,
    /// hosted here). The value-region ALIGN4 skip of the list path
    /// (which never reads values) rides on this helper — no separate
    /// skip site exists or is needed.
    fn entry_size(&self) -> usize {
        (size_of::<RawXattrEntry>() + self.e_name_len as usize + self.e_value_size as usize)
            .next_multiple_of(XATTR_ENTRY_ALIGN)
    }

    /// Device offset of the name bytes (`e_name_len` of them, no NUL
    /// terminator on disk).
    fn name_pos(&self) -> u64 {
        self.pos + size_of::<RawXattrEntry>() as u64
    }

    /// Device offset of the value bytes (`e_value_size` of them).
    fn value_pos(&self) -> u64 {
        self.name_pos() + self.e_name_len as u64
    }
}

/// Read point #12, the single implementation: decode the 4-byte entry
/// header at `pos` (channel error codes pass through uncollapsed —
/// EUCLEAN for on-disk malformation is produced by the X24 gate
/// below, never by this read).
fn read_xattr_entry_at(dev: &dyn BlockDevice, pos: u64) -> Result<XattrEntryAt> {
    // The usize cast is loss-free on 64-bit targets (the read-site
    // precedent).
    let raw = dev.read_val::<RawXattrEntry>(pos as usize)?;
    Ok(XattrEntryAt {
        pos,
        e_name_len: raw.e_name_len,
        e_name_index: raw.e_name_index,
        e_value_size: u16::from_le(raw.e_value_size),
    })
}

/// The inline ibody entry-area cursor — the walk half of
/// `erofs_xattr_iter_inline` (xattr.c:314-356). Holds geometry only:
/// no user-buffer state enters the walk (the get value protocol and
/// the list name accumulator belong to the consumers, S06/S07 — the
/// deliberate split against C's mixed iter struct, S02-D1).
struct IbodyEntryWalk<'a> {
    dev: &'a dyn BlockDevice,
    /// The device offset of the next entry header.
    pos: u64,
    /// The bytes remaining in the entry area (the current entry
    /// included); an X23-empty walk carries 0 and never reads.
    remaining: usize,
}

// Transitional — constructed by the get/list chain bodies
// (T-026 S06/S07), themselves wired to the trait forwards at S09;
// remove this expect when those consumers land.
#[expect(dead_code)]
impl<'a> IbodyEntryWalk<'a> {
    /// Construction IS the X23 gate (xattr.c:322-327):
    /// `header_sz = size_of::<RawXattrIbodyHeader>() + 4 ×
    /// shared_count`, with `shared_count` taken from the init-cached
    /// memory state (`state.shared_ids.len()` — no header re-read).
    /// `header_sz >= isize` collapses the two states — `==` (the
    /// header and id array exactly fill the area: a legal
    /// zero-inline-entry inode) and `>` (a crafted geometry, the F2
    /// chain's tail end: init already read the overrunning ids as
    /// garbage, and the walk's only reaction to the unbalanced
    /// geometry is "no inline entries") — into an empty walk: zero
    /// I/O, zero error face. The ENOATTR semantics of C's X23
    /// surface through the consumer orchestration instead (only
    /// walk-exhaustion falls through to the shared area, S03/S06/
    /// S07). The gate also decides the inline entry-area start:
    /// `suffix_xattr_start + header_sz` (read point #12's inline
    /// start, via the base-point family — no recomputation here).
    fn new(fs: &'a Erofs, nid: ErofsNid, desc: &InodeDesc, state: &InodeXattrState) -> Self {
        let header_sz = size_of::<RawXattrIbodyHeader>() + 4 * state.shared_ids.len();
        let suffix = suffix_xattr_start(fs.super_block(), nid, desc);
        if header_sz >= desc.xattr_isize {
            return Self {
                dev: &**fs.block_device(),
                // Unused while remaining == 0; the area base is the
                // natural neutral value.
                pos: suffix,
                remaining: 0,
            };
        }
        Self {
            dev: &**fs.block_device(),
            pos: suffix + header_sz as u64,
            remaining: desc.xattr_isize - header_sz,
        }
    }

    /// The next entry: read the 4-byte header (read point #12) → X24
    /// bound check → advance. Site order mirrors C :333-344 — the
    /// read failure precedes X24, and X24 precedes any consumer
    /// (including list: list never reads values, but `entry_size`
    /// carries `e_value_size`, so a malformed value size triggers
    /// the gate all the same).
    fn next_entry(&mut self) -> Result<Option<XattrEntryAt>> {
        if self.remaining == 0 {
            return Ok(None); // walk exhausted
        }
        let entry = read_xattr_entry_at(self.dev, self.pos)?; // EIO/EINVAL passthrough
        let sz = entry.entry_size();
        if self.remaining < sz {
            // X24 (xattr.c:339-342): the entry overruns the
            // remaining area — C -EFSCORRUPTED → EUCLEAN (an on-disk
            // malformation, never EIO; the ext2 EIO gate is the F45
            // hard prohibition). DBG_BUGON(1) is a no-op in
            // production C and is not migrated. This is the get
            // chain's only on-disk-corruption surfacing point:
            // once it fires, inline corruption masks a same-named
            // shared entry (the order assertion belongs to S03).
            return_errno_with_message!(Errno::EUCLEAN, "xattr entry beyond ibody");
        }
        self.pos += sz as u64; // the authoritative advance (:344/:353 —
        self.remaining -= sz; // consumers cannot touch walk geometry)
        Ok(Some(entry))
    }
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
