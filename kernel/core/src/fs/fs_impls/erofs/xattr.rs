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
//! callbacks. Mount-option gates read `mount_options` under a short
//! read guard at their chain position (ahead of the cell access on
//! the get and acl chains; per-entry inside the list foreach, after
//! the cell access) and release it immediately — the guards are
//! leaves, so no lock is ever held across `try_call_once` and no
//! lock is ever nested here.

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
// The vfs `Inode` trait enters anonymously (`as _`): it is needed in
// scope purely for method resolution on the erofs `Inode` (`type_`,
// `check_permission` — the G-X09/G-X08 gate pair), and a named alias
// would only shadow-conflict with the erofs `Inode` import above.
use crate::fs::{
    file::Permission,
    vfs::{
        inode::Inode as _,
        xattr::{XattrName, XattrNamespace},
    },
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
    /// not present (consumed by the get and acl chains since
    /// T-026 S06/S08).
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
/// and value are read by byte offset at the walk (since T-026 S02).
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
    /// No independent check — bounds are checked at use (since
    /// T-026: the X24 entry gate, the X27 table resolve).
    pub e_name_index: u8, // @1  __u8
    /// The value length; 0 is allowed. An undersized getxattr output
    /// buffer reports ERANGE at the consumption face (T-026 S06).
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
// value transcription). Liveness closed at S09: every consumable
// member is live through the entry chains (see the per-member
// "Live since" notes); the two structurally-unconsumable
// transcriptions (`FILTER_DEFAULT`, `XATTR_INDEX_LUSTRE`) keep
// PERMANENT expects by design — never consumed, never deleted (the
// expect-wave terminal state).
// ---------------------------------------------------------------------------

/// Name index of `user.*` attributes (`EROFS_XATTR_INDEX_USER`,
/// erofs_fs.h:212).
// Live since T-026 S06: consumed by `resolve_query_name` below. The
// bridging `expect` was removed when that consumer landed.
const XATTR_INDEX_USER: u8 = 1; // erofs_fs.h:212

/// Name index of the access-ACL pseudo-name
/// (`EROFS_XATTR_INDEX_POSIX_ACL_ACCESS`, erofs_fs.h:213).
// Live since T-026 S07: consumed by the list base-prefix row 2
// below and, since S08, the acl exact-name dispatch
// (`get_system_xattr`). The bridging `expect` was removed when the
// first consumer landed.
const XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2; // erofs_fs.h:213

/// Name index of the default-ACL pseudo-name
/// (`EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT`, erofs_fs.h:214).
// Live since T-026 S07: consumed by the list base-prefix row 3
// below and, since S08, the acl exact-name dispatch
// (`get_system_xattr`). The bridging `expect` was removed when the
// first consumer landed.
const XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3; // erofs_fs.h:214

/// Name index of `trusted.*` attributes (`EROFS_XATTR_INDEX_TRUSTED`,
/// erofs_fs.h:215).
// Live since T-026 S06: consumed by `resolve_query_name` below. The
// bridging `expect` was removed when that consumer landed.
const XATTR_INDEX_TRUSTED: u8 = 4; // erofs_fs.h:215

/// Name index of the (unmapped) Lustre attributes
/// (`EROFS_XATTR_INDEX_LUSTRE`, erofs_fs.h:216).
// No consumer by design: index 5 is the dead-index family (X10) — no
// namespace resolves to it (the query domain is 1/4/6 plus the ACL
// pair 2/3) and no list row exists, so on-disk entries carrying it
// simply never match and list skips them. Kept for the XA1 faithful
// transcription; the S09 consumed-or-deleted reconciliation closed
// on "kept" — the same permanent-expect form as FILTER_DEFAULT above
// (never consumed, never deleted; wiring it anywhere would fabricate
// a handler row Linux does not have).
#[expect(dead_code)]
const XATTR_INDEX_LUSTRE: u8 = 5; // erofs_fs.h:216

/// Name index of `security.*` attributes (`EROFS_XATTR_INDEX_SECURITY`,
/// erofs_fs.h:217).
// Live since T-026 S06: consumed by `resolve_query_name` below. The
// bridging `expect` was removed when that consumer landed.
const XATTR_INDEX_SECURITY: u8 = 6; // erofs_fs.h:217

/// Bit 7 of `e_name_index`: set when the entry refers to a long xattr
/// name prefix (`EROFS_XATTR_LONG_PREFIX`, erofs_fs.h:223).
// Live since T-026 S06: consumed by the long-prefix hit test of
// `entry_matches` below. The bridging `expect` was removed when that
// consumer landed.
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
// Live since T-026 S08: consumed by the tag dispatch of
// `parse_posix_acl` below. The bridging `expect` was removed when
// that consumer landed.
const ACL_USER_OBJ: u16 = 0x01; // posix_acl.h:28

/// ACL tag: a named-user entry (`ACL_USER`, posix_acl.h:29).
// Live since T-026 S08: consumed by the tag dispatch of
// `parse_posix_acl` and the identity write-back of
// `serialize_posix_acl` below. The bridging `expect` was removed
// when those consumers landed.
const ACL_USER: u16 = 0x02; // posix_acl.h:29

/// ACL tag: the group-owner entry (`ACL_GROUP_OBJ`, posix_acl.h:30).
// Live since T-026 S08: consumed by the tag dispatch of
// `parse_posix_acl` below. The bridging `expect` was removed when
// that consumer landed.
const ACL_GROUP_OBJ: u16 = 0x04; // posix_acl.h:30

/// ACL tag: a named-group entry (`ACL_GROUP`, posix_acl.h:31).
// Live since T-026 S08: consumed by the tag dispatch of
// `parse_posix_acl` and the identity write-back of
// `serialize_posix_acl` below. The bridging `expect` was removed
// when those consumers landed.
const ACL_GROUP: u16 = 0x08; // posix_acl.h:31

/// ACL tag: the mask entry (`ACL_MASK`, posix_acl.h:32).
// Live since T-026 S08: consumed by the tag dispatch of
// `parse_posix_acl` below. The bridging `expect` was removed when
// that consumer landed.
const ACL_MASK: u16 = 0x10; // posix_acl.h:32

/// ACL tag: the others entry (`ACL_OTHER`, posix_acl.h:33).
// Live since T-026 S08: consumed by the tag dispatch of
// `parse_posix_acl` below. The bridging `expect` was removed when
// that consumer landed.
const ACL_OTHER: u16 = 0x20; // posix_acl.h:33

/// The on-disk ACL value version word (`POSIX_ACL_XATTR_VERSION`,
/// include/uapi/linux/posix_acl_xattr.h: the `a_version` header
/// field of `posix_acl_xattr_header`).
// Live since T-026 S08: consumed by the header check of
// `parse_posix_acl` and the header emit of `serialize_posix_acl`
// below. The bridging `expect` was removed when those consumers
// landed.
const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;

/// The undefined-ACL-id sentinel (`ACL_UNDEFINED_ID` = (uid_t)-1,
/// posix_acl.h:21) — the sole invalid `e_id` for ACL_USER/ACL_GROUP
/// entries under the `init_user_ns` identity domain.
// Live since T-026 S08: consumed by the named-entry id gate of
// `parse_posix_acl` and the default-class rewrite of
// `serialize_posix_acl` below. The bridging `expect` was removed
// when those consumers landed.
const ACL_UNDEFINED_ID: u32 = u32::MAX; // (-1), posix_acl.h:21

// ---------------------------------------------------------------------------
// The per-inode lazy init entry and state accessor (T-026 S01 §1.4).
// Hosted as an inherent `impl Inode` block here — the cross-module
// inherent-impl precedent of `inode/symlink.rs`/`inode/dir.rs`: the
// state lives on the handle (inode/mod.rs), the xattr logic lives
// here. The one-line trait forwards live at `impl_for_vfs`
// (since T-026 S09).
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
    // Live since T-026 S06: consumed by the get entry chain below,
    // the list entry chain since S07, and the acl channel
    // (`get_system_xattr` below) since S08. The dead-code-analysis
    // roots are the get and list entries themselves (trait forwards
    // in `impl_for_vfs` since T-026 S09); the cell field read and
    // the init function stay live through those roots. The bridging
    // `expect` was removed when the first consumer landed.
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
    // Live since T-026 S06: read by `entry_matches` below and, since
    // S07, the list long-prefix test. The bridging `expect` was
    // removed when the first reader landed.
    e_name_index: u8,
    /// `e_value_size`, already from_le'd (XA0 walk-point decode).
    e_value_size: u16,
}

// Live since T-026 S06: the accessors and `entry_size` are consumed
// by the get chain bodies below and, since S07, the list foreach
// body. The bridging `expect` was removed when those consumers
// landed.
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

// Live since T-026 S06: constructed and driven by the get entry
// chain below, the list entry chain since S07, and the acl channel's
// `acl_find_value` since S08. The bridging `expect` was removed when
// those consumers landed.
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

// Live since T-026 S06: constructed and driven by the get entry
// chain below, the list entry chain since S07, and the acl channel's
// `acl_find_value` since S08. The bridging `expect` was removed when
// those consumers landed.
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
// `xattr_filter_denies` is exactly two sites — the get entry chain
// (T-026 S06) and, since S08, the acl channel's own gate (same door,
// same order — the empty-suffix internal query, index 2/3) — while
// the list chain is structurally free of any bloom reference — the
// get/list asymmetry negative fact (S04 §2.5: same image, same name,
// get denied while list still emits it).
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
// Live since T-026 S06: consumed by the get entry chain below and,
// since S08, the acl channel's gate (`get_system_xattr` — same door,
// same order; the empty suffix is a legal xxh32 input, not an exempt
// channel). The dead-code-analysis root is now the get entry itself;
// through it,
// `xattr_filter_active`, `xxh32`, the XATTR_FILTER_BITS/FILTER_SEED
// constants, and the `xattr_filter_reserved` mirror field stay
// live. The bridging `expect` was removed when the first consumer
// landed.
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
    // Live since T-026 S06: read by `entry_matches` below and, since
    // S07, the list base-row gate. The bridging `expect` was removed
    // when the first consumer landed.
    pub(in crate::fs::fs_impls::erofs) base_index: u8,
    /// The infix bytes following the base index (record length − 1),
    /// kept verbatim — may be non-UTF-8 and may contain NUL; the list
    /// path concatenates them as raw bytes (S05 §1.4; the W-X06 output
    /// half never narrows through &str).
    // Live since T-026 S06: read by `entry_matches` below and, since
    // S07, the list name assembly — both raw-byte faces, never
    // narrowed through &str. The bridging `expect` was removed when
    // the first consumer landed.
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
    // Live since T-026 S06: consumed by `entry_matches` below and,
    // since S07, the list foreach body. Through the get/list chains'
    // dead-code roots, the `XATTR_LONG_PREFIX_MASK` consumption and
    // the item construction face stay live. The bridging `expect`
    // was removed when the first consumer landed.
    pub(in crate::fs::fs_impls::erofs) fn long_prefix(
        &self,
        e_name_index: u8,
    ) -> Option<&XattrPrefixItem> {
        let k = (e_name_index & XATTR_LONG_PREFIX_MASK) as usize; // 0..=127
        self.xattr_prefixes.0.get().and_then(|table| table.get(k))
    }
}

// ---------------------------------------------------------------------------
// The get entry chain (T-026 S06; `docs/T-015/S06/index.md` §2.1/§2.2/§2.4/
// §2.5 — the `erofs_getxattr` counterpart, xattr.c:384-426, plus the
// foreach consumer of both storage walks, xattr.c:251-312). The entry is
// an inherent method on `Inode`; the trait override in `impl_for_vfs`
// is the S06-D1 one-line forward (since T-026 S09; gate position:
// every gate lives in this body — `impl_for_vfs` stays dispatch-only).
// The entry-matching half is the S08-D1 shared extraction
// `entry_matches`, landed here directly in its final form (analysis
// §12.4 ①: the extracted shape is terminal, the booklet's inlined S06
// draft superseded — the acl channel reuses the same helper at S08, so
// the match logic stays single-source exactly as C's one foreach served
// both call faces, xattr.c:534 → :251-312).
// ---------------------------------------------------------------------------

/// The get-face query-name resolution product (non-System namespaces
/// only; System is dispatched to the acl channel before this type is
/// ever built).
struct XattrQuery<'a> {
    /// The on-disk name index (1/4/6). F37: this is NOT the
    /// `XattrNamespace` discriminant value (User=1/Trusted=2/System=3/
    /// Security=4) — two distinct value domains, and the conversion
    /// lives in `resolve_query_name` alone.
    index: u8,
    /// The prefix-stripped suffix as raw bytes (via `str::as_bytes`;
    /// the W-X06 note at `resolve_query_name`).
    suffix: &'a [u8],
}

/// Full name → (on-disk index, suffix) — S06-D2. Call position in the
/// gate chain: AFTER the G-X09/G-X08 gates, BEFORE the X3 gate (the C
/// order xattr_permission → resolve → handler get, §1.1 ⑥→⑧→⑨ of the
/// booklet: X13/X15 surface before X7/X3).
fn resolve_query_name<'a>(name: &XattrName<'a>) -> Result<XattrQuery<'a>> {
    // The prefix is determined FORWARD from the namespace — a private
    // three-arm match with System structurally excluded. Excluding
    // System here is the structural half of NOT copying ext2's
    // `From<XattrNamespace>` single-value System mapping (the B4
    // prohibition): no reverse-strip EINVAL face, no trailing-dot
    // prefix strip, no second name-layer EINVAL source.
    let (index, prefix): (u8, &str) = match name.namespace() {
        XattrNamespace::User => (XATTR_INDEX_USER, "user."), // 1
        XattrNamespace::Trusted => (XATTR_INDEX_TRUSTED, "trusted."), // 4
        XattrNamespace::Security => (XATTR_INDEX_SECURITY, "security."), // 6
        // Unreachable: the entry dispatched System names to the acl
        // channel (⑥) before this function runs.
        XattrNamespace::System => unreachable!("dispatched to acl channel"),
    };
    // Structurally infallible (S06-D2): the parse layer's namespace
    // detection is a starts_with guarantee, so the strip cannot fail.
    let suffix = name
        .full_name()
        .strip_prefix(prefix)
        .expect("parse layer guarantees the namespace prefix");
    // W-X03 (per-FS patch parity with X7; no landing marker, the
    // degradation condition declared inline): a bare namespace prefix
    // ("user." etc.) has an empty suffix; the VFS-level X7 rejects it
    // with EINVAL. A framework-side candidate (parse-layer
    // empty-suffix rejection, the W-X03 framework row) would make
    // this gate a redundant no-op — it may then be removed with no
    // behavior change. Until then this is the ONLY EINVAL source in
    // the erofs name layer (XAT-23/24).
    if suffix.is_empty() {
        return_errno_with_message!(Errno::EINVAL, "bare xattr namespace prefix");
    }
    // W-X06 (registered difference, XAT-30): `XattrName` holds a
    // `&str` (framework `fs_apis/xattr.rs`), and non-UTF-8 names were
    // lossy-replaced (U+FFFD) at the syscall layer — the suffix bytes
    // below carry the replacement and NEVER match the on-disk raw
    // bytes, so such queries answer ENODATA (Linux can hit). No
    // remedy exists inside erofs (the &str narrowing is structural
    // framework face, AR-S01-6); the list OUTPUT half is a separate
    // VmWriter byte face that this note does not touch (S05 §2.5).
    Ok(XattrQuery {
        index,
        suffix: suffix.as_bytes(),
    })
}

/// Query-side match of one entry against `query` — the shared first
/// half of the foreach consumers (C: xattr.c:263-300 served both the
/// generic query and the acl channel's empty-suffix query through the
/// same foreach; the S08-D1 extraction, landed here directly per
/// analysis §12.4 ① — the acl consumer `acl_foreach_body` has shared
/// it since T-026 S08, so the match logic stays single-source exactly
/// as C's one foreach served both call faces).
/// Short-circuit order mirrors C: index/total-length arithmetic
/// first, infix compare next, e_name read+compare last (read errors
/// surface at the same logical point as C's per-block name copy
/// :288-291; the one whole-name read is the RD2① registered
/// granularity family).
fn entry_matches(fs: &Erofs, entry: &XattrEntryAt, query: &XattrQuery<'_>) -> Result<bool> {
    let infix_len: usize = if entry.e_name_index & XATTR_LONG_PREFIX != 0 {
        let Some(pf) = fs.long_prefix(entry.e_name_index) else {
            return Ok(false); // X27: out-of-table k / empty table → no match, iterate on
        };
        if query.index != pf.base_index
            || query.suffix.len() != entry.e_name_len as usize + pf.infix.len()
        {
            return Ok(false);
        }
        if !query.suffix.starts_with(&pf.infix) {
            // = memcmp(query, infix, infix_len)
            return Ok(false);
        }
        pf.infix.len()
    } else {
        if query.index != entry.e_name_index || query.suffix.len() != entry.e_name_len as usize {
            // X10/X11, get-side expression: FULL-VALUE index equality
            // — an on-disk 0/2/3/5/≥7 can never match a query index
            // in {1,4,6} (the acl pair 2/3 reaches this same test
            // through the S08 channel); no separate gate exists or
            // is needed.
            return Ok(false);
        }
        0
    };
    // The e_name segment: one whole read then compare (≤255 bytes;
    // X2: no ENOMEM arm — G-M21). Slice-safe: the total-length
    // equality already passed above, so infix_len ≤ suffix.len().
    let mut name_buf = vec![0u8; entry.e_name_len as usize];
    fs.block_device()
        .read_bytes(entry.name_pos() as usize, &mut name_buf)?;
    Ok(*name_buf.as_slice() == query.suffix[infix_len..])
}

/// The explicit counterpart of C's -ENOATTR mismatch (S02 §2.3: an
/// errno is never a control-flow sentinel).
enum GetOutcome {
    Matched(usize),
    Mismatch,
}

/// `erofs_getxattr_foreach` (xattr.c:251-312), the value-protocol
/// half: after the shared `entry_matches` screen, both
/// short-circuits (the size query and ERANGE) precede any value-byte
/// device read (S06-D4 — "value area unreadable ∧ buffer too small"
/// answers ERANGE, not a device error; XAT-28③).
fn get_foreach_body(
    fs: &Erofs,
    entry: &XattrEntryAt,
    query: &XattrQuery<'_>,
    writer: &mut VmWriter<'_>,
) -> Result<GetOutcome> {
    if !entry_matches(fs, entry, query)? {
        return Ok(GetOutcome::Mismatch); // X28: a mismatch iterates on (orchestration)
    }
    let value_sz = entry.e_value_size as usize; // u16 ≤ 65535 (F14: E2BIG unreachable)
    if writer.avail() == 0 {
        // Two-phase (F46): answer the length — zero value reads,
        // zero copies, the user buffer untouched.
        return Ok(GetOutcome::Matched(value_sz));
    }
    if value_sz > writer.avail() {
        // Judge BEFORE copying: no partial copy (X26); the value
        // bytes below are not read on this path either.
        return_errno_with_message!(Errno::ERANGE, "xattr value buffer too small");
    }
    // ≤65535 bytes; X2: no ENOMEM arm (G-M21). The value read is
    // deliberately LAST (S06-D4).
    let mut value_buf = vec![0u8; value_sz];
    fs.block_device()
        .read_bytes(entry.value_pos() as usize, &mut value_buf)?;
    // The single user-write point; an EFAULT passes through with the
    // framework's own code (the W-X05 registered timing drift).
    writer.write_fallible(&mut VmReader::from(value_buf.as_slice()))?;
    Ok(GetOutcome::Matched(value_sz))
}

impl Inode {
    /// The get-face entry — the `erofs_getxattr` counterpart (xattr.c:
    /// 384-426), matrix-one rows 6–31. The gate order below IS the
    /// priority order (⑥–⑮, the C call chain ⑤–⑩ mirrored; a swapped
    /// pair is an assertion face, never a refactor).
    // Live since T-026 S09: the trait forward in `impl_for_vfs`
    // calls it; through it the whole chain below stays live
    // (xattr_state, both walks, the bloom gate, the prefix resolve
    // face, and the constants/fields they consume). The bridging
    // `expect` of S06–S08 was removed when the forward landed.
    pub(in crate::fs::fs_impls::erofs) fn get_xattr(
        &self,
        name: XattrName<'_>,
        writer: &mut VmWriter<'_>,
    ) -> Result<usize> {
        // The strong-cache unreachable-EIO guard (the `Inode::fs`
        // discipline, T-013 §1.2).
        let fs = self.fs()?;
        // ⑥ System dispatch → the acl channel (X42 exact names / X43
        //    noacl+symlink gates / X44 empty-suffix query / X45/X46
        //    parse+serialize — the body landed with T-026 S08). The
        //    order mirrors C ⑤: the dispatch precedes permission —
        //    an acl name never passes G-X08/G-X09 (xattr.c:736
        //    ahead of :434-436).
        if matches!(name.namespace(), XattrNamespace::System) {
            return self.get_system_xattr(&fs, name, writer);
        }
        // ⑦ G-X09, the type gate (state A, X13 parity; get only —
        //    list has no type gate [S07], set/remove are unreachable
        //    [S09]): User ∧ non-reg/dir → ENODATA.
        // ⑧ G-X08, the permission gate (state A, X15 parity): only
        //    User∧(reg|dir) reaches MAY_READ; Trusted/Security carry
        //    ZERO fs-side gates (the F12 exemption face — the cap
        //    check for trusted. lives in the framework syscall layer
        //    as the X14 code equivalent). X13 before X15
        //    (xattr.c:141-153): the two gates share the single user
        //    branch, a type failure never reaches the permission
        //    check. Deliberately NOT copied: ext2's all-namespace
        //    MAY_READ gate (B6) and ramfs's all-namespace type gate
        //    + list masking (F43/D15) — either would give
        //    trusted./security. an EACCES face Linux never produces.
        if matches!(name.namespace(), XattrNamespace::User) {
            if !matches!(self.type_(), InodeType::File | InodeType::Dir) {
                return_errno_with_message!(Errno::ENODATA, "user.* on special file");
            }
            self.check_permission(Permission::MAY_READ)?; // failure → EACCES
        }
        // ⑨ Name resolution (the W-X03 empty-suffix EINVAL; the F37
        //    conversion — its only site).
        let query = resolve_query_name(&name)?;
        // ⑩ The X3 nouser_xattr gate (position = C ⑨: after resolve,
        //    before init). Reads User only — the gate does not
        //    narrow Trusted/Security (the gates do not read each
        //    other, T-005 §2.4); the option is read live under the
        //    short guard (O4 — a remount swap takes effect on the
        //    next syscall).
        if matches!(name.namespace(), XattrNamespace::User) && !fs.mount_options.read().user_xattr()
        {
            return_errno_with_message!(Errno::EOPNOTSUPP, "user xattrs disabled");
        }
        // ⑪ The lazy init (S02: the X1 three states / X2 no arm /
        //    channel codes pass through — the get face transmits
        //    them; the list-side X35 conversion belongs to S07).
        let state = self.xattr_state()?;
        // ⑫ The bloom gate (S04: X20). F13: deliberately BEFORE ⑬ —
        //    a trusted-bitmap denial answers ENODATA with zero walk
        //    construction and zero I/O.
        if xattr_filter_denies(
            fs.super_block(),
            state.name_filter,
            query.index,
            query.suffix,
        ) {
            return_errno_with_message!(Errno::ENODATA, "bloom filter: absent");
        }
        // ⑬ The X21 suffix-length gate — dead code kept as a
        //    structural mirror (S06-D3: X12 caps the full name at
        //    255 ⇒ the suffix at 250, so both sides are
        //    unreachable; transcribed with no assertion). Kept so
        //    the F13 order has a code-bearing surface.
        if query.suffix.len() > NAME_LEN {
            return_errno_with_message!(Errno::ERANGE, "xattr name too long");
        }
        // ⑭ The dual walk (the S03 §4.2 orchestration, verbatim):
        //      inline first; ONLY inline-walk EXHAUSTION falls
        //      through to the shared walk — a match returns (success
        //      stops), an error terminates (an inline X24 EUCLEAN
        //      masks a same-named shared entry: the negative
        //      corollary of "get only lands on shared via -ENOATTR").
        let mut ibody = IbodyEntryWalk::new(&fs, self.ino(), self.desc(), state);
        while let Some(entry) = ibody.next_entry()? {
            if let GetOutcome::Matched(len) = get_foreach_body(&fs, &entry, &query, writer)? {
                return Ok(len);
            }
        }
        let mut shared = SharedEntryWalk::new(&fs, state);
        while let Some(entry) = shared.next_entry()? {
            if let GetOutcome::Matched(len) = get_foreach_body(&fs, &entry, &query, writer)? {
                return Ok(len);
            }
        }
        // ⑮ The terminal: dual-walk exhaustion IS the C -ENOATTR
        //    (the initial-sentinel resolution, S03 §4.3).
        return_errno_with_message!(Errno::ENODATA, "no matching xattr")
    }

    /// The System-namespace entry — the S06 §2.5 ⑥ dispatch slot,
    /// with the real channel landed by S08 (the C chain:
    /// do_getxattr's is_posix_acl_xattr dispatch, linux/fs/xattr.c:
    /// 725-745, + vfs_get_acl's gate pair, posix_acl.c:1173-1205, +
    /// erofs_get_acl, xattr.c:513-551, + posix_acl_from_xattr /
    /// vfs_posix_acl_to_xattr, posix_acl.c:736-835/894-939).
    ///
    /// ACL names bypass G-X08/G-X09 entirely — an acl name never
    /// passes xattr_permission (posix_acl.c:1184-1187; the aster
    /// System namespace carries no cap gate either — shape-aligned,
    /// no assertion). The channel is zero-conversion on the init
    /// codes: ENODATA stays ENODATA (C's NULL-acl → ENODATA is the
    /// same code, xattr.c:542-543), EOPNOTSUPP/EUCLEAN and the
    /// channel codes pass through exactly like the generic get face.
    pub(in crate::fs::fs_impls::erofs) fn get_system_xattr(
        &self,
        fs: &Erofs,
        name: XattrName<'_>,
        writer: &mut VmWriter<'_>,
    ) -> Result<usize> {
        // X42, the exact-name dispatch (linux/fs/xattr.c:736 +
        // include/linux/xattr.h:25-29): full-string compare against
        // the two exact names — NOT prefix matching. The else arm IS
        // the X6-equivalent: every non-exact system.* name (bare
        // "system.", "system.foo", the glued
        // "system.posix_acl_accessfoo") reaches no handler in
        // Linux's resolve (the erofs s_xattr table has no
        // system-prefix handler), so both sides answer EOPNOTSUPP —
        // the name layer's only errno for this namespace, with ZERO
        // strip and ZERO name-layer EINVAL (the ext2 B4 trio — the
        // From<System> single-value mapping, the trailing-dot
        // prefix, the strip-failure EINVAL — is the prohibited copy
        // face; see also S08 §2.3 note 1). A bare "system." is NOT
        // the X7 EINVAL case: X7 requires a handler prefix to match
        // first (as "user." does). X42 precedes X43 (C's dispatch
        // precedes vfs_get_acl): a non-exact name on a noacl mount
        // is answered here, never by the noacl gate (same code,
        // order preserved — XAT-39).
        let index = match name.full_name() {
            "system.posix_acl_access" => XATTR_INDEX_POSIX_ACL_ACCESS, // 2
            "system.posix_acl_default" => XATTR_INDEX_POSIX_ACL_DEFAULT, // 3
            _ => return_errno_with_message!(Errno::EOPNOTSUPP, "unknown system xattr name"),
        };
        // X43 ②, the noacl gate (vfs_get_acl:1192-1193): the standing
        // EOPNOTSUPP equivalent — it is NOT ENODATA, and the two
        // codes must never be swapped (the gate fires even on an
        // inode whose acl entry exists on disk — the distinguishing
        // shape of XAT-41①). Read live under the short guard (O4: a
        // remount swap takes effect on the next syscall).
        if !fs.mount_options.read().posix_acl() {
            return_errno_with_message!(Errno::EOPNOTSUPP, "posix acl disabled");
        }
        // X43 ③, the symlink gate (vfs_get_acl:1194-1195):
        // EOPNOTSUPP, not ENODATA, and ONLY the SymLink kind is
        // rejected — devices, fifos and sockets query normally (a
        // different source from the G-X09 four-kind rejection; do
        // not conflate the two shapes). ②③ precede init (the §6.3
        // judgement order): "noacl ∧ isize == 0" answers EOPNOTSUPP
        // where init alone would answer ENODATA — the order
        // assertion face XAT-41②. The noacl-vs-symlink relative
        // order is same-code (indistinguishable, no assertion).
        if matches!(self.type_(), InodeType::SymLink) {
            return_errno_with_message!(Errno::EOPNOTSUPP, "acl on symlink");
        }
        // ④ The lazy init (S02: the X1 states / X2 no arm / channel
        //    codes — all transmitted; the acl channel converts
        //    nothing, unlike the list-side X35).
        let state = self.xattr_state()?;
        // ⑤ The X44 internal query (erofs_get_acl:534's "" literal):
        //    an INTERNAL construction — it bypasses
        //    `resolve_query_name` entirely, so the W-X03
        //    empty-suffix EINVAL gate never applies to it (that gate
        //    only sees user-provided full names; the acl channel's
        //    name is kernel-constructed).
        let query = XattrQuery { index, suffix: &[] };
        // ⑥ The bloom gate (S04's interface 1/2: same door, same
        //    order — after init, before the walk; C :534 → :401-407):
        //    the empty suffix goes into xxh32 verbatim (seed
        //    FILTER_SEED + 2/3), and a trusted contradictory bitmap
        //    denies the acl query all the same — the empty suffix is
        //    NOT an exempt input (XAT-45). A denial answers ENODATA
        //    with zero walk construction and zero walk I/O.
        if xattr_filter_denies(
            fs.super_block(),
            state.name_filter,
            query.index,
            query.suffix,
        ) {
            return_errno_with_message!(Errno::ENODATA, "bloom filter: absent");
        }
        // (X21's suffix-length gate: an empty suffix is ≤ NAME_LEN
        //  unconditionally — the same judgement C makes at :410-412 —
        //  so this chain carries no separate site; the ⑬ gate of the
        //  generic face only ever sees user-provided names.)
        // ⑦ The dual walk (the S03 §4.2 orchestration, acl shape):
        //    a mismatch iterates on, ONLY inline-walk exhaustion
        //    falls through to the shared walk, a match stops, and an
        //    inline X24 EUCLEAN masks a same-indexed shared entry —
        //    identical to the generic get face (the acl consumer is
        //    the fourth consumer of the same pair of walks).
        let Some(value) = acl_find_value(fs, self, &query, state)? else {
            // X44's tail: dual-walk exhaustion. An on-disk acl-index
            // entry with e_name_len > 0 never matches the
            // empty-suffix query (the F17 get-side dual — the list
            // half emits the glued name all the same, XAT-35) →
            // ENODATA (XAT-42①).
            return_errno_with_message!(Errno::ENODATA, "no acl entry");
        };
        // ⑧ X45, the value parse (`parse_posix_acl` below — the
        //    three-code split with the C order preserved: version
        //    before alignment, parse errors before any buffer
        //    judgement). The parse runs UNCONDITIONALLY: even a
        //    size=0 user buffer parses first, so a malformed value
        //    reports its own code instead of the length (S08 §1.2
        //    corollary 1; the generic get face answers the length
        //    with zero value reads — the read-timing dual,
        //    XAT-44③).
        let Some(entries) = parse_posix_acl(&value)? else {
            // A pure header: "legal but empty" answers as absent
            // (posix_acl.c:751-752; XAT-43⑦).
            return_errno_with_message!(Errno::ENODATA, "empty acl");
        };
        // ⑨ X46, the buffer protocol (vfs_posix_acl_to_xattr:907-911):
        //    real_size = 4 + 8n (== e_value_size — alignment is a
        //    parse hard gate, so the identity holds; XAT-40③); the
        //    two-phase length answer / judge-before-write order; the
        //    emitted bytes are the ROUND-TRIP product (default-class
        //    e_id rewritten to 0xFFFFFFFF), never an on-disk
        //    passthrough (XAT-47 is the anti-passthrough lock). E2BIG
        //    is unreachable (F14: real_size == e_value_size ≤ 65535
        //    < 65536).
        let real_size = size_of::<u32>() + entries.len() * size_of::<PosixAclEntry>();
        if writer.avail() == 0 {
            return Ok(real_size); // two-phase: the parse has already run
        }
        if real_size > writer.avail() {
            return_errno_with_message!(Errno::ERANGE, "acl value buffer too small");
        }
        let bytes = serialize_posix_acl(&entries);
        // The single user-write point; an EFAULT carries the
        // framework's own code (the W-X05 registered family —
        // code-equivalent to X18, layer/timing drift registered).
        writer.write_fallible(&mut VmReader::from(bytes.as_slice()))?;
        Ok(real_size)
    }
}

// ---------------------------------------------------------------------------
// The list entry chain (T-026 S07; `docs/T-015/S07/index.md` §2.1–§2.6 —
// the `erofs_listxattr` counterpart, xattr.c:428-455, plus the list
// foreach consumer of both storage walks, xattr.c:200-249). The entry is
// an inherent method on `Inode`; the trait override in `impl_for_vfs`
// is the one-line forward (since T-026 S09; gate position: every gate
// lives in this body — `impl_for_vfs` stays dispatch-only). Structurally
// free of any bloom reference (the get/list asymmetry, S04 §2.5): the
// caller set of `xattr_filter_denies` — the get chain above and,
// since S08, the acl channel — never includes any list-side site;
// same image, same name, get may be denied while list still
// emits it.
// ---------------------------------------------------------------------------

/// Base-row visibility gate + output prefix — the single-source Rust
/// counterpart of `erofs_xattr_prefix` (xattr.h:21-45) combined with
/// `xattr_handler_can_list` (include/linux/xattr.h:60-64:
/// `handler && (!handler->list || handler->list(dentry))`).
///
/// Evaluated per entry (the C `.list` callbacks are per-entry too);
/// mount options are read under a short guard each call — a live
/// remount change takes effect on the next syscall (O4). The
/// concurrent-remount torn-list corner (early entries visible, late
/// ones skipped) exists in C in the same position (`test_opt` is an
/// unlocked per-entry read); both sides are isomorphic, no assertion.
///
/// Returns `None` → skip silently: no error, and the entry is NOT
/// counted in the total (C `prefix == NULL → return 0`, xattr.c:226).
///
/// The full visibility matrix factorizes over three independent
/// inputs — the caller's cap state (carried by `namespace`, W-X02
/// state B), `user_xattr`, and `posix_acl` (S07 §2.1's 8-combination
/// exhaustive table): user rows read `user_xattr` only, the acl rows
/// read `posix_acl` only, the trusted row reads the cap signal only,
/// security is always visible, dead indexes never — disjoint
/// predicates, so the factorization IS the exhaustion. Consequence
/// (X34): the size=0 total varies with the visible set — root and
/// non-root answer different totals on the same inode (the trusted
/// row modulates it).
fn list_base_prefix(
    fs: &Erofs,
    namespace: XattrNamespace,
    base_index: u8,
) -> Option<&'static [u8]> {
    match base_index {
        XATTR_INDEX_USER => {
            // X4 (xattr.c:126-129): nouser_xattr → skip. NOTE: the get
            // side rejects the same option with EOPNOTSUPP (X3, the
            // get chain ⑩) — one option, two manifestations on the
            // two halves; the two must not be conflated (XAT-33④).
            fs.mount_options.read().user_xattr().then_some(b"user.")
        }
        XATTR_INDEX_POSIX_ACL_ACCESS => {
            // X43's list half: noacl → SKIP (the get half answers
            // EOPNOTSUPP — again one option, two codes, XAT-33②).
            // The row's output segment is the FULL access-acl name —
            // F17: no trailing dot (the nop acl handlers carry
            // `.name`, not `.prefix`; the ext2 trailing-dot form is
            // the B4 drift cell #3).
            fs.mount_options
                .read()
                .posix_acl()
                .then_some(b"system.posix_acl_access")
        }
        XATTR_INDEX_POSIX_ACL_DEFAULT => {
            // Rows 2/3 share the gate predicate (IS_POSIXACL ←
            // SB_POSIXACL ← the parsed `acl`/`noacl` option) and
            // differ only in the emitted full name.
            fs.mount_options
                .read()
                .posix_acl()
                .then_some(b"system.posix_acl_default")
        }
        XATTR_INDEX_TRUSTED => {
            // X5 (xattr.c:131-134): per-entry capable(CAP_SYS_ADMIN) —
            // carried by the `namespace` parameter here (W-X02 state
            // B: a capability signal, NOT a filter; see the entry doc
            // below). C evaluates the creds per entry; they cannot
            // change inside one syscall call, so the signal-carrying
            // form is equivalent.
            (namespace == XattrNamespace::Trusted).then_some(b"trusted.")
        }
        XATTR_INDEX_SECURITY => {
            // F7: the security handler has no `.list` callback, so
            // `xattr_handler_can_list` short-circuits true — always
            // listable, parameter- and option-independent.
            Some(b"security.")
        }
        // X10: 0 / 5 (the empty lustre slot) / >=7 (outside the
        // 7-entry handler map) — never listable, regardless of caller
        // or options; C's `idx && idx < ARRAY_SIZE(handlers)` gate
        // dissolves structurally in the match skeleton. A dead index
        // is a SKIP, never an error (the ext2 all-branch lustre
        // revival is drift cell #2).
        _ => None,
    }
}

/// Per-call list state (call-scoped; never cached across calls).
///
/// S07-D2 (G-X10/X36 shape): the staged `buf` is the kernel-side
/// counterpart of C's klist buffer — the user buffer is touched only
/// at the terminal single-point `write_fallible` of the entry below,
/// so ERANGE and walk errors leave it pristine (an X36 failure
/// discards the staged bytes wholesale). The per-entry X36 increment
/// check precedes each staging, which bounds `buf.len()` by `avail`
/// (≤ 65536) plus the last name_total (≈ 535 B worst case) — the
/// same bound C's klist carries; the rejected total-first staging of
/// the whole visible set (a ~35 MB crafted upper bound) is exactly
/// what this shape exists to avoid.
struct ListCtx {
    /// `writer.avail() == 0` at entry — the X34 two-phase size query:
    /// names are never read, only summed (C `!it->buffer`).
    zero_pass: bool,
    /// The user buffer size — C `it.buffer_size`.
    avail: usize,
    /// The accumulated total — C `it.buffer_ofs` (skipped entries are
    /// never counted; X34: this is what a size=0 query returns).
    total: usize,
    /// Staged output bytes: prefix + infix + name + NUL per visible
    /// entry; only grows while `total <= avail`.
    buf: Vec<u8>,
}

/// The list foreach body — the list half of the shared foreach
/// (xattr.c:200-249). `Ok(())` is dual-purpose — output or skip both
/// continue (X37: the entry below runs both walks unconditionally in
/// order; only an `Err` terminates, discarding the staged bytes).
fn list_foreach_body(
    fs: &Erofs,
    namespace: XattrNamespace,
    entry: &XattrEntryAt,
    ctx: &mut ListCtx,
) -> Result<()> {
    // 1. Long-prefix segment (xattr.c:209-222): a `0x80 | k` index
    //    resolves through the mounted table; out-of-table k —
    //    including every k when the table is empty — skips, not
    //    counted (the X27 list shape: the same resolve face as get,
    //    whose reaction is a non-match instead). The infix bytes are
    //    concatenated verbatim below — non-UTF-8 and NUL-carrying
    //    infixes included (the W-X06 OUTPUT half is a VmWriter byte
    //    face, never narrowed through &str).
    let (base_index, infix): (u8, &[u8]) = if entry.e_name_index & XATTR_LONG_PREFIX != 0 {
        let Some(pf) = fs.long_prefix(entry.e_name_index) else {
            return Ok(()); // skip: not counted
        };
        (pf.base_index, pf.infix.as_slice())
    } else {
        (entry.e_name_index, &[][..])
    };
    // 2. Base-row visibility gate (xattr.c:224-226; the table above):
    //    X4/X5/X10/the acl rows → skip, not counted.
    let Some(prefix) = list_base_prefix(fs, namespace, base_index) else {
        return Ok(()); // skip: X4/X5/X10/acl gate closed
    };
    // 3. name_total = prefix_len + infix_len + e_name_len + 1
    //    (xattr.c:227-228; the 1 is the NUL). F17 corollary: rows 2/3
    //    carry the full acl name as the prefix segment with no
    //    trailing dot, so a mkfs-normal entry (e_name_len == 0) lists
    //    the exact name while a crafted non-empty suffix concatenates
    //    verbatim, unvalidated ("system.posix_acl_accessfoo\0" —
    //    XAT-35; its get side is unreachable through X44's
    //    empty-suffix exact match, S08).
    let name_total = prefix.len() + infix.len() + entry.e_name_len as usize + 1;
    // 4. Two-phase / accumulating judgement (xattr.c:230-236; the
    //    G-X10 eager form: judge first, stage after).
    if ctx.zero_pass {
        // X34: the name bytes are NOT read on this path (C `!buffer`
        // — a size=0 query over a name area beyond the device end
        // still answers the total; the read is unreachable).
        ctx.total += name_total;
        return Ok(());
    }
    if ctx.total + name_total > ctx.avail {
        // X36 (xattr.c:235-236): per-entry, BEFORE this entry's name
        // read — the C position verbatim, so the "visible set
        // overflows the buffer ∧ a later walk error" combination
        // answers ERANGE on both sides (a crafted out-of-device
        // shared id is preempted exactly as in C). The staged bytes
        // die with the error; the user buffer is never touched.
        return_errno_with_message!(Errno::ERANGE, "xattr list buffer too small");
    }
    // 5. Assembly staging (xattr.c:238-248): prefix memcpy + infix
    //    memcpy + e_name copy + one hand-written NUL per name
    //    (exactly one — names carry no terminator on disk,
    //    e_name_len is the length). e_value is never read on the
    //    list path: the value region is skipped by `entry_size`'s
    //    ALIGN4 advance inside the inline walk, the shared walk has
    //    no advance at all, and `value_pos()` has zero list-side
    //    references.
    ctx.buf.extend_from_slice(prefix);
    ctx.buf.extend_from_slice(infix);
    // e_name_len ≤ 255: a fixed stack scratch, zero per-entry
    // allocation (X2: no ENOMEM arm).
    let mut name = [0u8; NAME_LEN];
    fs.block_device().read_bytes(
        entry.name_pos() as usize,
        &mut name[..entry.e_name_len as usize],
    )?;
    ctx.buf
        .extend_from_slice(&name[..entry.e_name_len as usize]);
    ctx.buf.push(0); // the hand-written '\0' (xattr.c:248)
    ctx.total += name_total;
    Ok(())
}

impl Inode {
    /// The list-face entry — the `erofs_listxattr` counterpart
    /// (xattr.c:428-455), matrix-two rows 5–13; the gate order below
    /// IS the priority order.
    ///
    /// The chain has NO acl dispatch, NO name copying, NO
    /// xattr_permission, and NO prefix parsing (T-005 §4.1): all
    /// visibility filtering sinks into the foreach body above. The
    /// list-face negative discipline: no permission gate (the Linux
    /// list chain checks none — the ramfs F43 masking form is
    /// prohibited), no type gate (X13 is get-only: symlinks and
    /// special files list normally), nouser_xattr is a SKIP not
    /// EOPNOTSUPP (X4 vs X3), a dead index is a SKIP not an error
    /// (X10), concatenated acl names are not validated (F17), and
    /// there is no partial write (G-X10).
    ///
    /// W-X02 (registered workaround, state B): the trait passes a
    /// single namespace chosen by the syscall layer
    /// (`get_current_xattr_namespace`, `crate::syscall`'s
    /// `listxattr.rs`): `Trusted` iff the caller holds CAP_SYS_ADMIN
    /// (permitted + LSM-checked), `User` otherwise. We consume that
    /// parameter **as a capability signal, not as a filter**: the
    /// output is the caller-visible set of the Linux visibility
    /// matrix — the only consumption point is the trusted-row gate
    /// (X5) above; every other row is parameter-independent. Do NOT
    /// copy the ext2 "namespace == User ⇒ drop non-user entries"
    /// form (B5) — it silently loses security.* for non-root callers
    /// (three drift cells; the targeted parity assertions are
    /// XAT-32②/33③/34).
    ///
    /// Implicit contract (registered risk, W-X02): "parameter value
    /// == caller cap state" is a framework-side invariant we rely
    /// on. If the syscall layer ever enumerates namespaces per call
    /// (a state-A signature extension) or changes the selector
    /// semantics, the trusted gate here must be re-derived from the
    /// caller's credentials; the rest of this method is unaffected.
    // Live since T-026 S09: the trait forward in `impl_for_vfs`
    // calls it; through it the list chain above stays live
    // (list_base_prefix, ListCtx, list_foreach_body, the ACL index
    // constants, and the posix_acl accessor they consume). The
    // bridging `expect` of S07–S08 was removed when the forward
    // landed.
    pub(in crate::fs::fs_impls::erofs) fn list_xattr(
        &self,
        namespace: XattrNamespace,
        writer: &mut VmWriter<'_>,
    ) -> Result<usize> {
        // The strong-cache unreachable-EIO guard (the `Inode::fs`
        // discipline, T-013 §1.2).
        let fs = self.fs()?;
        // ① init with the X35 conversion (xattr.c:434-436): ENODATA
        //    is the ONLY code the list side swallows — isize == 0
        //    becomes a 0-length listing (an empty name list is not
        //    an error; the get side transparently propagates ENODATA
        //    instead — the two-half split, XAT-36's same-inode dual
        //    call). X1a EOPNOTSUPP / X1b EUCLEAN / the channel codes
        //    pass through unconverted.
        let state = match self.xattr_state() {
            Ok(state) => state,
            Err(e) if e.error() == Errno::ENODATA => return Ok(0),
            Err(e) => return Err(e),
        };
        // ② The per-call context; a zero-pass (avail == 0) call
        //    allocates nothing and reads no name bytes (X34).
        let avail = writer.avail();
        let mut ctx = ListCtx {
            zero_pass: avail == 0,
            avail,
            total: 0,
            buf: Vec::new(),
        };
        // ③ The dual walk (S03 §4.2's list skeleton, verbatim: the
        //    two loops run unconditionally in order — X37's "any
        //    inline Ok → shared" has no continue condition left to
        //    get wrong in the cursor form; only an `Err` terminates,
        //    an inline X24 EUCLEAN masking the shared names and
        //    discarding the staged bytes with it).
        let mut ibody = IbodyEntryWalk::new(&fs, self.ino(), self.desc(), state);
        while let Some(entry) = ibody.next_entry()? {
            list_foreach_body(&fs, namespace, &entry, &mut ctx)?;
        }
        let mut shared = SharedEntryWalk::new(&fs, state);
        while let Some(entry) = shared.next_entry()? {
            list_foreach_body(&fs, namespace, &entry, &mut ctx)?;
        }
        // ④ The terminal: one single-point user write (G-X10 zero
        //    touch — an EFAULT carries the framework's own code,
        //    code-equivalent to X32; the layer and timing difference
        //    is the W-X05 registered family, no assertion), then the
        //    total (X34: size=0 and size≥total answer the same
        //    number; skipped entries are never counted).
        if !ctx.zero_pass {
            writer.write_fallible(&mut VmReader::from(ctx.buf.as_slice()))?;
        }
        Ok(ctx.total)
    }
}

// ---------------------------------------------------------------------------
// The ACL read channel (T-026 S08; `docs/T-015/S08/index.md` §2.1–§2.4 —
// erofs_get_acl's consumers: the X44 acl foreach body over the same dual
// walk as the generic get face, plus the X45/X46 value parser and
// serializer). The entry — `get_system_xattr` above, the ⑥ dispatch slot
// — owns the gate chain; the pieces here are the walk consumer, the
// on-disk record view, and the two value-protocol halves. State two of
// the acl design: exact-name reads only. The permission-evaluation half
// of ACLs stays registered as cut (G-M07: no ACL enforcement layer
// consumes the value — this channel's output is user-visible bytes only;
// erofs does not repair the framework, AR-S01-6). Zero new locks (S08
// §2.5): the Once cell caches the xattr state, never the acl value —
// every query re-runs the walk and the parse, the no-acl-cache mirror
// of C's uncached `.get_inode_acl` face (xattr.c:513-551 has no cached
// acl get on this kernel; the get_cached_acl snapshot above it misses
// by construction).
// ---------------------------------------------------------------------------

/// The acl consumer's per-entry outcome — the value-protocol
/// counterpart of `GetOutcome`: a mismatch iterates on, a match
/// carries the whole value bytes (read unconditionally — the acl
/// value protocol has no entry-level two-phase short-circuit).
enum AclOutcome {
    Matched(Vec<u8>),
    Mismatch,
}

/// The acl channel's foreach body — the X44 value protocol in its acl
/// special case (C: xattr.c:251-312's foreach served the acl channel's
/// empty-suffix query through the same body, xattr.c:534/:539). The
/// single-pass form: a match reads the value UNCONDITIONALLY — the
/// behavior-equivalent single-pass fusion of C's two-call shape (S08
/// §1.2 corollary 3: the init Once fast path, the bloom
/// re-evaluation, and both walks are idempotent, so one pass and two
/// passes answer the same code in the same order — the I/O halving is
/// device-read count, not user-visible behavior). A mismatched
/// entry's value is never read (same shape on both sides); a read
/// failure surfaces at the matched entry with the channel's own code
/// (an oversized crafted e_value_size surfaces here even for a
/// size=0 user buffer — the read-timing dual XAT-44④).
fn acl_foreach_body(
    fs: &Erofs,
    entry: &XattrEntryAt,
    query: &XattrQuery<'_>,
) -> Result<AclOutcome> {
    if !entry_matches(fs, entry, query)? {
        return Ok(AclOutcome::Mismatch); // X28: a mismatch iterates on (orchestration)
    }
    // e_value_size ≤ 65535; X2: no ENOMEM arm (G-M21). An empty value
    // (C's rc == 0 guard keeps the buffer NULL, xattr.c:542) is the
    // empty Vec here — it flows into the parse's short-value EINVAL
    // arm (S08 §1.2 corollary 2), unlike the generic get face where
    // an empty value is a legal Ok(0): the same on-disk entry, two
    // channels, two codes.
    let mut value = vec![0u8; entry.e_value_size as usize];
    fs.block_device()
        .read_bytes(entry.value_pos() as usize, &mut value)?;
    Ok(AclOutcome::Matched(value))
}

/// The acl channel's dual-walk orchestration — the S03 §4.2 get
/// skeleton verbatim with `acl_foreach_body` as the consumer: the
/// inline walk first, ONLY inline-walk exhaustion falls through to
/// the shared walk (a match returns, an error terminates — an inline
/// X24 EUCLEAN masks a same-indexed shared entry), and exhaustion
/// answers `None` → the entry's terminal ENODATA. The fourth consumer
/// of the same orchestration contract (get / list / acl), reading the
/// same init-cached state the entry chain already acquired.
fn acl_find_value(
    fs: &Erofs,
    inode: &Inode,
    query: &XattrQuery<'_>,
    state: &InodeXattrState,
) -> Result<Option<Vec<u8>>> {
    let mut ibody = IbodyEntryWalk::new(fs, inode.ino(), inode.desc(), state);
    while let Some(entry) = ibody.next_entry()? {
        if let AclOutcome::Matched(value) = acl_foreach_body(fs, &entry, query)? {
            return Ok(Some(value)); // success stops
        }
    }
    let mut shared = SharedEntryWalk::new(fs, state);
    while let Some(entry) = shared.next_entry()? {
        if let AclOutcome::Matched(value) = acl_foreach_body(fs, &entry, query)? {
            return Ok(Some(value)); // success stops
        }
    }
    Ok(None) // dual-walk exhaustion → the entry's terminal ENODATA
}

/// One decoded acl record — the host-order mirror of the on-disk
/// `posix_acl_xattr_entry` (include/uapi/linux/posix_acl_xattr.h:
/// e_tag/e_perm le16 + e_id le32, exactly 8 bytes). `repr(C)` so the
/// layout anchors below double as the record-domain anchor: the
/// parse/serialize stride and the entry's `real_size = 4 + 8n`
/// arithmetic both consume `size_of::<PosixAclEntry>()` — the same
/// discipline as `XATTR_ENTRY_ALIGN` = `size_of::<RawXattrEntry()>`
/// (the constant IS the structure size, C5).
// AUTO-DECISION: one repr(C) struct instead of the booklet's separate
// `PosixAclEntryOnDisk` layout-anchor + a host-order copy (S08 §2.3
// sample). The parse reads fields per-`from_le_bytes` off the in-
// memory value slice — no Pod face exists (or is wanted: the slice is
// 1-aligned, so a transmute read would be wrong anyway) — so a second
// constructed-nowhere anchor struct would only restate these very
// offsets while risking the never-constructed dead-code face. The
// anchors below carry the same on-disk facts; semantic zero-
// difference (the `read_prefix_record` compile-minimal adaptation of
// S05 is the same precedent).
#[repr(C)]
struct PosixAclEntry {
    e_tag: u16,  // @0  __le16
    e_perm: u16, // @2  __le16
    e_id: u32,   // @4  __le32
}

// Layout triple and per-field offsets (A1), anchored to
// include/uapi/linux/posix_acl_xattr.h (the source-side counterpart
// is the size/count helper family of linux/include/linux/
// posix_acl_xattr.h:18-35: real_size = 4 + 8n over exactly these
// fields).
const_assert!(size_of::<PosixAclEntry>() == 8); // posix_acl_xattr.h
const_assert!(align_of::<PosixAclEntry>() == 4); // the le32 member pins the alignment
const_assert!(offset_of!(PosixAclEntry, e_tag) == 0); // posix_acl_xattr.h
const_assert!(offset_of!(PosixAclEntry, e_perm) == 2); // posix_acl_xattr.h
const_assert!(offset_of!(PosixAclEntry, e_id) == 4); // posix_acl_xattr.h

/// `posix_acl_from_xattr`'s validation half (fix_xattr_common,
/// posix_acl.c:736-755, + the from_xattr entry loop, :781-835) — the
/// three-code split with the C order preserved line by line: EINVAL
/// (short value), EOPNOTSUPP (version), EINVAL (misalignment),
/// `Ok(None)` = a pure header ("legal but empty" treated as absent →
/// the caller's ENODATA), then the per-entry checks in entry order
/// (an unknown tag or an undefined named id fails at its own entry,
/// like C's fail path). `e_perm` is never validated (any 16 bits
/// pass; serialize re-emits them verbatim); the four default-class
/// tags leave `e_id` semantically unread (serialize rewrites it
/// unconditionally). No alloc-failure arm exists (X2/G-M21: the C
/// kmalloc points :796-798 both map to this tree's abort family).
fn parse_posix_acl(value: &[u8]) -> Result<Option<Vec<PosixAclEntry>>> {
    // :741-744 — the two short arms of C (a NULL value and a value
    // smaller than the 4-byte header) answer the same EINVAL; the
    // empty Vec of the acl consumer and a real short value are one
    // shape at the slice face (the value length is single-source
    // here — no merge loss; the rc==0 NULL distinction C makes at
    // :542 has already collapsed into the empty Vec upstream).
    if value.len() < size_of::<u32>() {
        return_errno_with_message!(Errno::EINVAL, "bogus acl value");
    }
    let a_version = u32::from_le_bytes(value[..size_of::<u32>()].try_into().unwrap());
    // :745-746 — the version check PRECEDES the alignment check: a
    // "version ≠ 2 ∧ misaligned" value answers EOPNOTSUPP, not
    // EINVAL — the order IS the assertion face (XAT-43②).
    if a_version != POSIX_ACL_XATTR_VERSION {
        return_errno_with_message!(Errno::EOPNOTSUPP, "acl version");
    }
    // :748-750 — posix_acl_xattr_count's negative case: the remainder
    // must be a whole number of 8-byte records.
    let rest = value.len() - size_of::<u32>();
    if !rest.is_multiple_of(size_of::<PosixAclEntry>()) {
        return_errno_with_message!(Errno::EINVAL, "acl size misaligned");
    }
    let count = rest / size_of::<PosixAclEntry>();
    if count == 0 {
        // :751-752 — a pure header carries zero entries: "legal but
        // empty" answers as absent (Ok(None) → the caller's ENODATA).
        return Ok(None);
    }
    // count ≤ (65535 − 4) / 8 = 8188 records ≤ 64 KiB; X2: no ENOMEM
    // arm (G-M21).
    let mut entries = Vec::with_capacity(count);
    // The alignment check above already pins the remainder to zero, so
    // `as_chunks().0` walks exactly the records `chunks_exact` would
    // (the erofs utils.rs xxh32 stripe ladder is the same precedent).
    for rec in value[size_of::<u32>()..]
        .as_chunks::<{ size_of::<PosixAclEntry>() }>()
        .0
    {
        // Field offsets 0/2/4 are the const_assert anchors above.
        let e_tag = u16::from_le_bytes(rec[..2].try_into().unwrap());
        let e_perm = u16::from_le_bytes(rec[2..4].try_into().unwrap()); // unvalidated
        let e_id = u32::from_le_bytes(rec[4..8].try_into().unwrap());
        match e_tag {
            ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_MASK | ACL_OTHER => {
                // The default classes: e_id is semantically unread —
                // C's from_xattr leaves it undefined (:801-811) and
                // serialize rewrites it unconditionally below.
            }
            ACL_USER | ACL_GROUP => {
                // The init_user_ns identity domain (S08-D3): the sole
                // invalid id is the -1 sentinel — the make_kuid/kgid
                // INVALID_UID/GID judgement (`uid_t -1`) transcribed
                // verbatim (erofs has no idmap/user_namespace face);
                // every other u32 passes, and existence is NOT
                // queried on either side (a lookup would be drift).
                if e_id == ACL_UNDEFINED_ID {
                    return_errno_with_message!(Errno::EINVAL, "acl id undefined");
                }
            }
            // :825-826/:831-833 — an unknown tag fails at its own
            // entry (e_tag outside {0x01,0x02,0x04,0x08,0x10,0x20}).
            _ => return_errno_with_message!(Errno::EINVAL, "acl unknown tag"),
        }
        entries.push(PosixAclEntry {
            e_tag,
            e_perm,
            e_id,
        });
    }
    Ok(Some(entries))
}

/// `vfs_posix_acl_to_xattr`'s emit half (posix_acl.c:913-937). The
/// round trip is NOT a byte passthrough (S08 §1.4): the named
/// entries (ACL_USER/ACL_GROUP) write e_id back identically (the
/// init_user_ns identity domain), while the four default classes
/// carry an UNCONDITIONAL 0xFFFFFFFF rewrite (:933-934) — parse never
/// read their e_id, serialize never preserves it. The difference
/// face is exactly that single field: normal mkfs/setfacl images are
/// byte-equal through the round trip (their default-class e_id is
/// already -1 on disk), while crafted values surface the rewrite —
/// XAT-47 is the anti-passthrough lock (a verbatim-copy
/// implementation passes XAT-40 and fails exactly there).
fn serialize_posix_acl(entries: &[PosixAclEntry]) -> Vec<u8> {
    let cap = size_of::<u32>() + size_of_val(entries);
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
    for e in entries {
        out.extend_from_slice(&e.e_tag.to_le_bytes()); // verbatim
        out.extend_from_slice(&e.e_perm.to_le_bytes()); // verbatim
        let e_id = match e.e_tag {
            ACL_USER | ACL_GROUP => e.e_id, // identity write-back
            _ => ACL_UNDEFINED_ID,          // default-class rewrite
        };
        out.extend_from_slice(&e_id.to_le_bytes());
    }
    out
}
