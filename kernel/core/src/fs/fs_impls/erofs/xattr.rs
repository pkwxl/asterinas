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
use spin::Once;

use super::{
    fs::Erofs,
    inode::{Inode, InodeDesc, InodeXattrState, suffix_xattr_start},
    prelude::*,
    super_block::{FeatureCompatSet, FeatureIncompatSet, NAME_LEN, SuperBlock},
    utils::xxh32,
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
// Live since T-026 S05: consumed by `Erofs::long_prefix` below — the
// single mask point of the table-resolve face. The bridging `expect`
// was removed when the first consumer landed.
const XATTR_LONG_PREFIX_MASK: u8 = 0x7f; // erofs_fs.h:224

/// The bloom-filter bit width (`EROFS_XATTR_FILTER_BITS`,
/// erofs_fs.h:226): hashbits are `xxh32(...) & (XATTR_FILTER_BITS - 1)`.
// Live since T-026 S04: consumed by the bloom denial predicate
// (`xattr_filter_denies` below) as the hashbit mask. The bridging
// `expect` was removed when the first consumer landed.
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
// Live since T-026 S04: consumed by the bloom denial predicate
// (`xattr_filter_denies` below) as the xxh32 seed base. The bridging
// `expect` was removed when the first consumer landed.
const FILTER_SEED: u32 = 0x25BBE08F; // erofs_fs.h:228

/// The xattr entry alignment unit (`EROFS_XATTR_ALIGN`: every entry —
/// header + name + value — is rounded up to `sizeof(erofs_xattr_entry)`,
/// erofs_fs.h:253). Same-sourced with the `RawXattrEntry` layout
/// assertion above (C5): the constant IS the structure size, never
/// the literal 4.
// Live since T-026 S02: consumed by `XattrEntryAt::entry_size`
// (the walk's ALIGN4 size helper).
const XATTR_ENTRY_ALIGN: usize = size_of::<RawXattrEntry>();

/// The fixed part of an on-disk long-prefix record:
/// `sizeof(struct erofs_xattr_long_prefix)` = the single `base_index`
/// byte (erofs_fs.h:240-243; the flexible infix member is not
/// modeled, U3) — the lower bound of the record-length domain; the
/// upper bound is `NAME_LEN` + this constant (the P4 check of the
/// prefix load below).
// Live since T-026 S05: consumed by the record-domain bounds check of
// the prefix load below. The bridging `expect` was removed when the
// first consumer landed.
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

// ---------------------------------------------------------------------------
// The shared-area entry cursor (T-026 S03; `docs/T-015/S03/index.md` §2 —
// the walk half of `erofs_xattr_iter_shared`, xattr.c:358-382). The
// get/list orchestration that falls through to this walk — "get only on
// inline-walk exhaustion, success stops", "list continues on any inline
// Ok" (X37), and the X24 masking order — belongs to the consumer chains
// (S06/S07); the orchestration contract table lives in
// `docs/T-015/S03/index.md` §4.
// ---------------------------------------------------------------------------

/// The shared-block entry cursor — the walk half of
/// `erofs_xattr_iter_shared` (xattr.c:358-382).
///
/// G-X01/X25 negative fact: NO bound check of any kind on the shared
/// ids — the read position is computed and read unconditionally. The
/// shared area has no on-disk length field (the superblock carries
/// only its start, `xattr_blkaddr`), and a shared entry has no X24
/// counterpart (no remaining-size gate): an out-of-range id surfaces
/// only through the device channel or as coincidentally parseable
/// bytes, never as a walk rejection (the three-shape parity table is
/// `docs/T-015/S03/index.md` §3.1).
///
/// Structural differences from `IbodyEntryWalk`: no X23/X24 gates and
/// no entry-size advance — every id is an independent base point. C
/// recomputes `it->pos` at each loop head (xattr.c:368); the partial
/// advances the foreach consumers make are overwritten by the next
/// round, which the cursor form carries structurally (consumers never
/// move this walk). Shared-entry bytes are uncached: every get/list
/// call re-reads them through the device channel (point-of-use
/// contract); the once-cell caches only the decoded id array — the
/// memory state this walk iterates.
struct SharedEntryWalk<'a> {
    dev: &'a dyn BlockDevice,
    /// Read point #15's base half, precomputed once as the loop
    /// invariant: `xattr_blkaddr × block_size` (the
    /// `erofs_pos(sb, xattr_blkaddr)` counterpart; an RO invariant
    /// hoisted out of the loop with zero behavioral difference,
    /// S03-D1). This base computation is the mirror field's only
    /// runtime consumer (F50: superblock definition → mirror read →
    /// this point closes the consumption set).
    base: u64,
    /// The init-cached shared-id array (`InodeXattrState::
    /// shared_ids`, read at point #11 by S02 §2.1): an empty slice
    /// is shared_count == 0 and iterates zero times — the natural
    /// empty-`Iter` form, no explicit branch (S03-D3; contrast X27's
    /// mandatory count == 0 branch, a lookup on a zero-length table
    /// — a different mechanism, owned by S05).
    ids: core::slice::Iter<'a, u32>,
}

// Transitional — constructed by the get/list chain bodies
// (T-026 S06/S07), themselves wired to the trait forwards at S09;
// remove this expect when those consumers land.
#[expect(dead_code)]
impl<'a> SharedEntryWalk<'a> {
    /// Pure-arithmetic construction: zero I/O, zero error face, zero
    /// validation — no `xattr_blkaddr` value-domain check either
    /// (the T-012 zero-validation mirror read carries over to this
    /// first runtime consumer).
    fn new(fs: &'a Erofs, state: &'a InodeXattrState) -> Self {
        // Both factors widen to u64 before multiplying (S03-D2): the
        // C counterparts are the u64-shifting `erofs_pos` macro and
        // the size_t-promoted `id × sizeof` product (internal.h:221,
        // xattr.c:368-369); a u32-domain `4 * id` would wrap on
        // crafted ids > 0x3FFFFFFF — behavioral drift.
        let base = fs.super_block().xattr_blkaddr as u64 * fs.super_block().block_size() as u64;
        Self {
            dev: &**fs.block_device(),
            base,
            ids: state.shared_ids.iter(),
        }
    }

    /// The next entry: read point #15's start = `base + 4 × id` (a
    /// 4-byte-granularity byte-stream offset, decoupled from the
    /// block size; the id passes in unbound-checked). The 4-byte
    /// header read reuses the single `read_xattr_entry_at`
    /// implementation — read point #12 has no second copy for the
    /// shared site — and the consumers read the name/value bytes
    /// through `name_pos`/`value_pos` the same way (the #12
    /// variable region, same shape). `entry_size()` is deliberately
    /// not consumed on this path: every id is an independent base
    /// point, so there is no advance and no ALIGN4 skip site (C's
    /// sole `erofs_xattr_entry_size` call sits in iter_inline, :337).
    ///
    /// X25: no bound check is added here — not the device end, not
    /// the shared-area edge, not the id value domain, and no
    /// remaining-style entry gate either (`docs/T-015/S03/index.md`
    /// §3.3 items 1–4). The only failure path is the channel read
    /// itself, whose error codes pass through uncollapsed (§3.3
    /// item 7: EINVAL/EIO stay distinct — no errno folding, and
    /// this walk produces no EUCLEAN; on-disk malformation has no
    /// surfacing point on the shared path). An ext2-style EIO gate
    /// on on-disk content is the F45 hard prohibition (§3.3 item
    /// 5): this walk neither interprets nor validates what it
    /// reads.
    fn next_entry(&mut self) -> Result<Option<XattrEntryAt>> {
        let Some(&id) = self.ids.next() else {
            return Ok(None); // walk exhausted (shared_count == 0 is the same shape)
        };
        // The id widens before multiplying (S03-D2); the addition
        // carries no overflow check (§3.3 item 6) — the u64
        // magnitude bound (base ≤ (2^32−1)×2^12 plus 4×(2^32−1) ≈
        // 2^44+2^34) is far below 2^64, C has no check in the same
        // position, and adding one would be a new defense face.
        let pos = self.base + 4 * id as u64;
        read_xattr_entry_at(self.dev, pos).map(Some) // channel codes passthrough
    }
}

// ---------------------------------------------------------------------------
// The bloom-filter gate (T-026 S04; `docs/T-015/S04/index.md` §2.1–§2.3 —
// the `vi->xattr_name_filter` consumption of `erofs_getxattr`,
// xattr.c:401-407). Get-path only by construction: the caller set of
// `xattr_filter_denies` is exactly one site, the get entry chain
// (T-026 S06); the ACL internal query reaches the same gate through
// that chain (empty suffix, index 2/3, T-026 S08), and the list chain
// is structurally free of any bloom reference — the get/list
// asymmetry negative fact (S04 §2.5: same image, same name, get
// denied while list still emits it).
// ---------------------------------------------------------------------------

/// The bloom-filter effectivity gate — the single-source Rust
/// counterpart of the `xattr.c:401` predicate half: the static bit
/// predicate generated by `EROFS_FEATURE_FUNCS(xattr_filter, ...)`
/// (internal.h:241) combined with the `!sbi->xattr_filter_reserved`
/// mirror read (super.c:334).
///
/// Per-call evaluation (S04-D1): the superblock is immutable after
/// mount, so this is two memory reads — semantically identical to a
/// mount-time snapshot, and it mirrors the C form (evaluated at
/// every getxattr entry; no mount-time materialization, no per-inode
/// caching of the effectivity). The two halves stay separately
/// observable — a crafted image may clear the compat bit or set the
/// reserved byte alone (XAT-16 (a)/(b)) — and `xattr_filter_reserved`
/// is consumed as a pure gate input with zero value-domain judgement
/// (the T-012 zero-validation mirror: a non-zero value was accepted
/// at mount and only switches this gate off, never a rejection).
fn xattr_filter_active(sb: &SuperBlock) -> bool {
    sb.feature_compat().contains(FeatureCompatSet::XATTR_FILTER) && sb.xattr_filter_reserved == 0
}

/// Bloom gate = `xattr.c:401-407`.
///
/// Returns `true` when the on-disk bitmap asserts that the queried
/// name is **definitely absent** — the caller (the get entry chain,
/// T-026 S06) short-circuits to ENODATA without touching any on-disk
/// entry. Pure predicate (S04-D2): the ENODATA production point is
/// the caller, never here. Bit semantics are complementary
/// (`h_name_filter`: bit SET = not-present); a cleared bit only
/// means "may exist" — a false pass-through into the dual-storage
/// walk is by design, the filter can only push get toward ENODATA
/// and never the other way (X20, one-way). The bitmap is trusted:
/// a crafted contradictory bitmap (bit set while the entry exists)
/// denies all the same — no bitmap-vs-entry consistency check
/// exists or may be added (that would be a drift, not a defense).
///
/// The bitmap interpretation freezes the hash algorithm (mkfs lays
/// out the bits per XXH32): any non-XXH32 substitute — jhash
/// included — would misread *present* names as absent on every
/// filter-enabled image (T-005 F52). Substitution is prohibited;
/// the reference-vector unit tests in `utils.rs` are the
/// correctness lock.
///
/// `index` is always query-side — the namespace indexes 1/4/6 plus
/// the ACL internal pair 2/3 (S04 §2.3); the on-disk entry
/// `e_name_index` value domain, including the `0x80 | k`
/// long-prefix form, never enters this gate (two disjoint domains,
/// never mixed). `suffix` is the prefix-stripped suffix as raw
/// bytes; the ACL channel passes the empty slice — a legal xxh32
/// input, not an exempt channel (F13) — and non-UTF-8 suffixes are
/// structurally absent at the framework layer (W-X06, a registered
/// difference; the pointer lives at the S06 name resolution).
// Transitional — consumed by the get entry chain (T-026 S06; the
// ACL internal query rides the same chain at T-026 S08); remove
// this expect when that consumer lands. As a dead-code-analysis
// root it also keeps `xattr_filter_active`, `xxh32`, the
// XATTR_FILTER_BITS/FILTER_SEED constants, and the
// `xattr_filter_reserved` mirror field live until then.
#[expect(dead_code)]
fn xattr_filter_denies(sb: &SuperBlock, name_filter: u32, index: u8, suffix: &[u8]) -> bool {
    if !xattr_filter_active(sb) {
        return false; // gate off: never deny; xxh32 uncalled, bitmap unread
    }
    // hashbit = xxh32(suffix, FILTER_SEED + index) & 31  (xattr.c:402-404)
    let hashbit = xxh32(suffix, FILTER_SEED.wrapping_add(index as u32)) & (XATTR_FILTER_BITS - 1);
    name_filter & (1u32 << hashbit) != 0
}

// ---------------------------------------------------------------------------
// The long xattr name-prefix table (T-026 S05; `docs/T-015/S05/index.md`
// §2.1–§2.6 — `erofs_xattr_prefixes_init`/`erofs_read_metadata`,
// xattr.c:457-511 + super.c:113-145): the state-A full load behind the
// F15 slot of mount step 6, the decoded-table once-cell on `Erofs`, and
// the `0x80 | k` resolve face consumed by the get/list entry matching
// (T-026 S06/S07). Domain split of the record reads (G-X02): the meta
// half is a plain device-byte-stream read (read point #3's long-prefix
// half, revived); the packed half rides the #13 page-cache exception
// family — "file-content reads go through the inode's own page cache"
// — with the backend still sourced from `fs.block_device`.
// ---------------------------------------------------------------------------

/// One decoded long-prefix record (the `erofs_xattr_prefix_item`
/// counterpart, xattr.c:502-503): `infix.len()` IS the C `infix_len`
/// (= record length − 1; the S01-D3 no-redundant-length rule).
pub(in crate::fs::fs_impls::erofs) struct XattrPrefixItem {
    /// The short-prefix index byte, kept exactly as on disk — no
    /// value-domain check: a malformed base_index simply never matches
    /// on the get side and is skipped on the list side (S05 §1.4).
    // First consumer: the get/list entry matching (T-026 S06/S07).
    // Transitional expect — remove when that consumer lands.
    #[expect(dead_code)]
    pub(in crate::fs::fs_impls::erofs) base_index: u8,
    /// The infix bytes following the base index (record length − 1),
    /// kept verbatim — may be non-UTF-8 and may contain NUL; the list
    /// path concatenates them as raw bytes (S05 §1.4; the W-X06 output
    /// half never narrows through &str).
    // First consumer: the get/list entry matching (T-026 S06/S07).
    // Transitional expect — remove when that consumer lands.
    #[expect(dead_code)]
    pub(in crate::fs::fs_impls::erofs) infix: Vec<u8>,
}

/// The FS-level long-prefix table host — the C `sbi->xattr_prefixes`
/// array plus `xattr_prefix_count` collapsed into one value (the
/// table length == `Vec::len` == the mount-time superblock count; the
/// superblock is never re-read at runtime). Interior: a once-cell
/// published exactly once at mount step 6 and frozen for the mount
/// lifetime (S05-D4: `call_once`, not `try_call_once` — a failed load
/// fails the whole mount, so there is no retry path to model, and the
/// re-entrancy panic face of `call_once` is structurally unreachable:
/// mounting is single-threaded and the handle is not yet reachable
/// through the FsCache).
pub(in crate::fs::fs_impls::erofs) struct XattrPrefixes(Once<Vec<XattrPrefixItem>>);

impl XattrPrefixes {
    /// The vacant cell every handle starts from (the fs.rs constructor
    /// line); publication happens only in `load`, only at mount step 6.
    pub(in crate::fs::fs_impls::erofs) fn new() -> Self {
        Self(Once::new())
    }

    /// The F15 body — the P1–P6 branches of `docs/T-015/S05/index.md`
    /// §1.1 (`xattr.c:470-511`).
    fn load(&self, fs: &Erofs) -> Result<()> {
        // P1 (xattr.c:478-479): count == 0 → zero reads, zero
        // allocation (`Vec::new()` never allocates — the C "no
        // kzalloc" parity) — and the EMPTY table is still published:
        // "the cell is complete after a successful mount" holds
        // unconditionally, so the resolve face below has no unloaded
        // state to handle. This loop gate is the sole consumption
        // face of the `xattr_prefix_count` mirror.
        let count = fs.super_block().xattr_prefix_count as usize;
        if count == 0 {
            self.0.call_once(Vec::new);
            return Ok(());
        }
        // pos0 (xattr.c:474): `xattr_prefix_start << 2` — a hard-coded
        // 4-BYTE unit shift, NOT the erofs_pos block unit (deliberately
        // unlike read point #15's `xattr_blkaddr × block_size`); the
        // u32 mirror widens to u64 BEFORE the shift (S03-D2 arithmetic
        // discipline). No value-domain pre-check on the start: an
        // out-of-range area surfaces as the channel error of the first
        // record read (XAT-22; a pre-check would be a new defense face
        // — the image is trusted, S05 §2.6 item 4).
        let pos = u64::from(fs.super_block().xattr_prefix_start) << 2;
        // G-X02 dual mapping (xattr.c:485-488): the C test is
        // `sbi->packed_inode != NULL`, whose assignment predicate is
        // re-derived here (FRAGMENTS bit ∧ packed_nid ≠ 0 — the very
        // predicate mount step 4/F10 already ran); no resident packed
        // handle exists on purpose (identity single-sources through
        // the inode cache), so this is a guaranteed cache-hit iget.
        // The two forms share ONE textual record implementation,
        // instantiated per source type (the compile-minimal form of
        // the `&dyn VmIo` sample — see the AUTO-DECISION note at
        // `read_prefix_record`).
        let items = if fs
            .super_block()
            .feature_incompat()
            .contains(FeatureIncompatSet::FRAGMENTS)
            && fs.super_block().packed_nid != 0
        {
            // Packed form: the prefix bytes are regular file content
            // of the packed inode — read through its DataBacked page
            // cache (C `buf.mapping = packed_inode->i_mapping`; pos is
            // a packed-file-relative offset). The iget Err face is
            // structurally unreachable (step 4 iget'd the same nid and
            // the cache never evicts) — `?` is defensive passthrough;
            // the hit path takes only a read guard, never the
            // inode-cache write side (R1).
            let packed = fs.iget(fs.super_block().packed_nid)?;
            // Keepalive borrow form (context risk 5): the local
            // `Arc<Inode>` pins the page cache (and its backend) for
            // the whole record loop — the borrow checker enforces the
            // lifetime the two-tuple sample carried, in the minimal
            // shape that compiles.
            let Some(pc) = packed.page_cache() else {
                // A crafted non-DataBacked packed payload (special
                // file / fast symlink): C hits an aops-less undefined
                // face here; this tree rejects cleanly — on-disk
                // malformation → EUCLEAN (registered known-diff, no
                // assertion family).
                return_errno_with_message!(Errno::EUCLEAN, "packed inode has no data payload");
            };
            read_prefix_table(pc, pos, count)
        } else {
            // Meta form: the prefix area is read straight off the
            // device byte stream at the absolute offset pos0 — read
            // point #3's long-prefix half, revived (the
            // algorithm-config half of erofs_read_metadata stays cut
            // with compression, shelf A).
            read_prefix_table(&**fs.block_device(), pos, count)
        }?;
        // Compute-then-publish (S05-D4): only a fully-built table is
        // published. On failure the cell stays vacant and the whole
        // handle dies with the mount error — the half-built local Vec
        // drops with it (the C cleanup counterpart is plain Rust
        // ownership: no explicit free call, no leak face, and the
        // put_super cleanup collapses into the Erofs Drop).
        self.0.call_once(|| items);
        Ok(())
    }
}

/// The record loop (xattr.c:496-507): `count` records, first failure
/// stops (P3 passthrough / P4 EUCLEAN), the half-built items die with
/// the error. Generic over the record source so that the G-X02 dual
/// mapping shares ONE implementation (instantiated once for the packed
/// page cache, once for the device byte stream).
fn read_prefix_table<S: VmIo + ?Sized>(
    src: &S,
    mut pos: u64,
    count: usize,
) -> Result<Vec<XattrPrefixItem>> {
    let mut items = Vec::with_capacity(count); // ≤ 255; X2: no ENOMEM arm (G-M21)
    for _ in 0..count {
        let rec = read_prefix_record(src, &mut pos)?; // P3: the read happens FIRST
        // P4 (xattr.c:496-501), AFTER the read: the record domain is
        // [LONG_PREFIX_FIXED_LEN, NAME_LEN + LONG_PREFIX_FIXED_LEN] =
        // [1, 256]. A zero header length was already mapped to 65536
        // inside the reader, so it always lands on this upper bound —
        // the oversized READ must happen before any domain judgement
        // (P5: the rejection force is entirely the upper bound;
        // short-circuiting an empty length into a rejection here would
        // reorder observable I/O against the C flow).
        if rec.len() < LONG_PREFIX_FIXED_LEN || rec.len() > NAME_LEN + LONG_PREFIX_FIXED_LEN {
            return_errno_with_message!(Errno::EUCLEAN, "bogus xattr prefix length");
        }
        // P6 (xattr.c:502-503): base_index verbatim + infix = the
        // remaining len − 1 bytes; no content validation of either
        // (malformed base_index / non-UTF-8 / NUL-carrying infixes are
        // stored as-is — S05 §2.6 items 2 and 3).
        let (base_index, infix) = match rec.split_first() {
            Some((&b, rest)) => (b, rest.to_vec()),
            // P4 guarantees len >= 1 here (the 0-arm of the domain
            // check above); the From<FileKind> unreachable precedent.
            None => unreachable!("P4 guarantees len >= 1"),
        };
        items.push(XattrPrefixItem { base_index, infix });
    }
    Ok(items)
}

/// `erofs_read_metadata` equivalent (super.c:113-145; the T-001 §3.6
/// length-prefixed record convention) — the single reader of the
/// long-prefix record stream. Record form: `le16 len` header, then
/// `len` body bytes; the next record starts at the next 4-byte
/// boundary. `len == 0` means 65536 (the U16_MAX + 1 encoding,
/// super.c:125-126 — P5's root: the oversized read is issued BEFORE
/// the caller's domain check can reject it).
// AUTO-DECISION: generic `<S: VmIo + ?Sized>` instead of the design
// sample's `src: &dyn VmIo` — `&dyn BlockDevice` does not coerce to
// `&dyn VmIo` (VmIo is not a supertrait of BlockDevice; the existing
// `impl VmIo for dyn BlockDevice` enables method calls but not the
// trait-object coercion), so the meta-form arm cannot produce a
// `&dyn VmIo` without a hand-written adapter type. The generic keeps
// ONE textual implementation (the design's "single code path, dual
// form") with two monomorphizations — semantically identical.
// Rejected: a manual adapter struct forwarding VmIo over
// `&dyn BlockDevice` (a new type and a second implementation surface
// for zero benefit); duplicating the reader per mapping arm (violates
// the single-implementation contract).
fn read_prefix_record<S: VmIo + ?Sized>(src: &S, pos: &mut u64) -> Result<Vec<u8>> {
    *pos = (*pos).next_multiple_of(4); // round_up 4: inter-record padding skipped (super.c:119)
    // The single le16 length read (C1); the offset cast is loss-free
    // on 64-bit targets (the read-site precedent). P3: channel error
    // codes pass through uncollapsed.
    let raw = src.read_val::<u16>(*pos as usize)?;
    *pos += size_of::<u16>() as u64; // super.c:130
    let len = match u16::from_le(raw) as usize {
        0 => u16::MAX as usize + 1, // len == 0 → 65536 (super.c:125-126)
        n => n,
    };
    let mut buf = vec![0u8; len]; // the kmalloc half; X2: no ENOMEM arm (G-M21)
    // C's per-block slice loop (`cnt = min(block tail, remaining)`,
    // one bread + memcpy per slice) is a block-granular-mapping
    // artifact: both target forms are byte-precise unbounded readers,
    // so the whole body is one read — the RD2① registered
    // read-granularity family, observable only under fault injection,
    // no assertion (S05 §2.2 argument 1). No short read.
    src.read_bytes(*pos as usize, &mut buf)?;
    *pos += len as u64; // the record body is consumed
    Ok(buf) // the CALLER judges the domain (P4 is post-read by design)
}

/// F15 — the mount-time long-xattr name-prefix table load
/// (`erofs_xattr_prefixes_init`, xattr.c:470-511), called from step 6
/// of `Erofs::open` (`fs.rs`). The state-A full load: a positive
/// prefix count gets its table assembled and published before the
/// mount succeeds. Failure family: EUCLEAN (the P4 record domain; the
/// non-DataBacked packed corner) and the channel codes (EIO/EINVAL,
/// P3) pass through and fail the whole mount — first failure stops,
/// no errno folding.
// G-X04: this path consults `xattr_prefix_count` alone — ZERO
// incompat-bit references. The XATTR_PREFIXES bit's only face is V6
// known-bit membership: bit set + count 0 mounts as the P1 no-op, bit
// clear + count > 0 loads the table all the same — no cross-check
// exists, and adding one would reject images C accepts.
// Live since T-026 S05: the real body replaced the slot-only
// placeholder (the open-step-6 call site was final all along).
pub(super) fn load_xattr_prefixes(fs: &Erofs) -> Result<()> {
    fs.xattr_prefixes.load(fs)
}

/// The runtime table-resolve face — the single X27 entry, consumed by
/// the entry matching of get/list (T-026 S06/S07).
impl Erofs {
    /// Resolves a `0x80 | k` on-disk name index against the mounted
    /// table. Call ONLY when the long-prefix bit is set — the mask is
    /// applied here, at this one point (`k = 0..=127`). Out-of-table k
    /// — including every k when the table is empty — returns `None`
    /// through the explicit `Vec::get` bounds check: the structural
    /// replacement of C's pointer comparison `pf >= prefixes + count`
    /// (xattr.c:266-268, :213-214), whose count == 0 truth relies on
    /// `NULL + k >= NULL + 0` — C-practice pointer arithmetic that
    /// Rust must not and does not borrow. After a successful mount the
    /// cell is always complete (P1 publishes the empty Vec), so
    /// `None` is decided solely by the bounds. The get side treats
    /// `None` as a non-match and iterates on; the list side skips the
    /// entry — the two consumer faces (S05 §2.5).
    // Transitional — first consumed by the get/list entry matching
    // (T-026 S06/S07), wired to the trait forwards at S09; remove
    // this expect when that consumer lands. As a dead-code-analysis
    // root it keeps the `XATTR_LONG_PREFIX_MASK` consumption and the
    // item construction face live until then.
    #[expect(dead_code)]
    pub(in crate::fs::fs_impls::erofs) fn long_prefix(
        &self,
        e_name_index: u8,
    ) -> Option<&XattrPrefixItem> {
        let k = (e_name_index & XATTR_LONG_PREFIX_MASK) as usize; // 0..=127
        self.xattr_prefixes.0.get().and_then(|table| table.get(k))
    }
}
