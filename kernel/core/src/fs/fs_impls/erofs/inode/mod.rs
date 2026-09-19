// SPDX-License-Identifier: MPL-2.0

//! Erofs inode family.
//!
//! The central type, `Inode`, represents one in-memory erofs inode and
//! is the concrete inode object exposed to the VFS adapter. Inodes are
//! identified by nid — erofs has no block groups, so inode numbers are
//! linear and the FS-level cache in `fs.rs` is keyed by nid directly.
//!
//! Bring-up state (T-022 S05): the on-disk half of the dual-format
//! decoding is in place — the two raw inode records (`RawInodeCompact`
//! 32B / `RawInodeExtended` 64B, sharing the discriminating prefix at
//! offsets 0/2/4/16), the chunk-domain records (`RawInodeChunkInfo`, a
//! registration-only host for its layout assertions, and
//! `RawInodeChunkIndex` for element-wise reads), the `i_format` bit
//! family with the two extraction helpers, and the inode-domain
//! constants — 13 + 15 + 4 + 5 layout assertions in total. The typed
//! vocabulary (four enums and `InodeDesc`), the dual `TryFrom` decode
//! with the I7/I8/I10 guards, and the entry read land with the
//! remaining T-022 subtasks (S06-S08). The `Inode` handle shell below
//! — still the minimal shell required by the `FileSystem` trait
//! surface — stays interim until T-024 (the nid, descriptor, and
//! payload fields land then; payload shapes remain deliberately not
//! pre-declared).
//!
//! # Submodules
//!
//! | Submodule | Responsibility                                     |
//! |-----------|----------------------------------------------------|
//! | `mod`     | The inode handle and dual-format decoding (T-022)  |
//! | `data`    | Block mapping and physical read primitives (T-025) |
//! | `file`    | Regular-file reads through the page cache (T-025)  |
//! | `dir`     | Dirent decoding and name lookup (T-024)            |
//! | `symlink` | Inline symlink target reads (T-024)                |
//!
//! # Locking
//!
//! An `Inode` is immutable after construction (nid, type, descriptor,
//! and payload are decoded once — the filesystem is read-only and never
//! updates atime); regular-file payloads hold a framework `PageCache`
//! that synchronizes itself and the VFS `Extension` slot synchronizes
//! itself, so there are no per-inode locks and no cross-inode lock
//! ordering. The `inode_cache` lock in `fs.rs` is released before any
//! inode operation runs (lookup hands out an `Arc<Inode>` clone and
//! operations execute outside the guard).

#![short_vis_path::add(erofs)]

mod data;
mod dir;
mod file;
mod symlink;

use core::mem::offset_of;

use ostd::const_assert;

use super::{fs::Erofs, prelude::*};
use crate::fs::vfs::inode::Extension;

/// An erofs inode number (`nid`): the linear on-disk inode identifier.
pub(super) type ErofsNid = u64;

/// An in-memory erofs inode.
///
/// Interim placeholder (T-021 skeleton): the real handle additionally
/// carries the nid, the decoded descriptor, and the type-specific
/// payload; those shapes land with T-022/T-024. What is already final
/// here is the weak back-pointer discipline: `self_ref` is the only
/// link back to the filesystem handle (strong reference cycles are
/// forbidden family-wide) and the upgrade path carries an `EIO` guard.
pub struct Inode {
    type_: InodeType,
    self_ref: Weak<Erofs>,
    extension: Extension,
}

impl Inode {
    /// Constructs the placeholder root-directory inode handed out by
    /// the interim `Erofs::root_inode`.
    pub(super) fn placeholder_dir(self_ref: Weak<Erofs>) -> Self {
        Self {
            type_: InodeType::Dir,
            self_ref,
            extension: Extension::new(),
        }
    }

    /// Returns the inode number (nid).
    ///
    /// Placeholder: always 0 until the nid field lands with the T-022
    /// decoding body.
    pub(super) fn ino(&self) -> ErofsNid {
        0
    }

    /// Returns the inode type.
    pub(super) fn type_(&self) -> InodeType {
        self.type_
    }

    /// Returns a reference to the owning `Erofs` filesystem.
    ///
    /// The weak-upgrade failure guard is defensive by design: with the
    /// strong inode cache the mount always outlives the inodes it
    /// handed out, so the `EIO` below is structurally unreachable.
    pub(super) fn fs(&self) -> Result<Arc<Erofs>> {
        self.self_ref
            .upgrade()
            .ok_or_else(|| Error::with_message(Errno::EIO, "filesystem already dropped"))
    }

    /// Returns a reference to the VFS extension slot.
    pub(super) fn extension(&self) -> &Extension {
        &self.extension
    }
}

// ---------------------------------------------------------------------------
// On-disk raw records: the dual-format inode family (T-022 S05;
// `docs/T-011/S03/index.md` §3/§4/§6, `docs/T-011/analysis.md` §2.1).
// ---------------------------------------------------------------------------

/// The erofs on-disk compact inode (`erofs_inode_compact`,
/// linux/fs/erofs/erofs_fs.h:156-171; field semantics single-sourced
/// in `docs/T-001/analysis.md` §4.3).
///
/// The 32-byte reduced form of the dual on-disk inode formats. The
/// layout invariant shared with the extended form (asserted on both
/// sides below): `i_format`/`i_xattr_icount`/`i_mode`/`i_u` sit at
/// the same offsets @0/@2/@4/@16 — the structural premise that lets
/// the decode entry pre-read the 2-byte `i_format`, run the I3/I4
/// guards, and pick the layout before reading the full record (the
/// source side sequences the same way: inode.c:53-67 ahead of :69;
/// the entry read itself lands with T-022 S08).
///
/// Being a le32, `i_size` can never exceed `i64::MAX`, so the
/// negative-size guard I7 is structurally unreachable on this form
/// and no fake guard is fabricated (G7) — the guard lives on the
/// extended form only.
// No deadness attribute: the permanent `const_assert!` layout anchors
// below reference the type and each of its 11 fields, so both stay
// live in every cfg and an `#[expect(dead_code)]` would only be
// reported unfulfilled (same rationale as `RawDeviceSlot` in
// `super_block.rs`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct RawInodeCompact {
    /// The inode format hints: bit 0 = version, bits 1-3 = datalayout,
    /// bits 4-15 reserved — a 1 + 3 bit split, not half-nibbles (the
    /// bit family constants live below). Its single E1 conversion is
    /// the entry's 2-byte pre-read; no conversion point re-reads it.
    pub i_format: u16, // @0  __le16
    /// The inline-xattr size in 4-byte units (0 = none); converted
    /// through the `xattr_ibody_size` helper at the decode (T-022
    /// S06/S07).
    pub i_xattr_icount: u16, // @2  __le16
    /// The raw mode word (S_IFMT nibble + permission bits), carried
    /// as-is; the `FileKind::from_raw_i_mode` discrimination lands
    /// with T-022 S06.
    pub i_mode: u16, // @4  __le16
    /// The hard-link count, carried as-is including 0 (the ext2
    /// link-count ESTALE door is an ext2-specific defense and is
    /// deliberately not transcribed).
    pub i_nlink: u16, // @6  __le16
    /// The file size; the le32 domain caps it at 4GiB - 1.
    pub i_size: u32, // @8  __le32
    /// Reserved; never read (G5).
    pub i_reserved: u32, // @12 __le32
    /// The C union `i_u` (erofs_fs.h:141-153), carried as the minimal
    /// common width integer (U1: Rust unions are structurally excluded
    /// in the safe-Rust kernel tree). Four readings of one 32-bit
    /// value, discriminated by the consumer — never by this record:
    ///
    /// - `compressed_blocks` __le32 (:143): the total compressed
    ///   block count of a compressed inode;
    /// - `raw_blkaddr` __le32 (:146): the data start block of an
    ///   uncompressed flat inode;
    /// - `rdev` __le32 (:149): the device number of a CHR/BLK inode
    ///   (decoded through the new_decode_dev bit pattern);
    /// - `c` `erofs_inode_chunk_info` (:152): the chunk summary of a
    ///   chunk-based inode.
    ///
    /// Fidelity is the two-independent-passes discipline (T-003 §1.4):
    /// the single `u32::from_le` at the decode yields the one
    /// host-order `iu` every reading is a view of — pathological
    /// kind x datalayout combinations (CHR x compressed, FIFO x
    /// chunk, ...) are accepted parity behavior. The chunk-info
    /// reading decomposes as `chunkformat = iu as u16` (format@0 in
    /// LE means the low half, and the 4-byte size of
    /// `RawInodeChunkInfo` means the bit widths coincide — both
    /// mechanically proven by its layout assertions), while the
    /// reserved half (`iu >> 16`) is never read or checked (G5).
    pub i_u: u32, // @16
    /// 32-bit stat compatibility field; deliberately not consumed —
    /// st_ino derives from the nid (X2).
    pub i_ino: u32, // @20 __le32
    /// The 16-bit uid (zero-extended at the decode).
    pub i_uid: u16, // @24 __le16
    /// The 16-bit gid (zero-extended at the decode).
    pub i_gid: u16, // @26 __le16
    /// Reserved; never read (G5).
    pub i_reserved2: u32, // @28 __le32
}

// Layout triple and per-field offsets (A1), each anchored to
// linux/fs/erofs/erofs_fs.h; the source-side counterpart of the size
// assertion is BUILD_BUG_ON at erofs_fs.h:443.
const_assert!(size_of::<RawInodeCompact>() == 32); // erofs_fs.h:443
const_assert!(align_of::<RawInodeCompact>() == 4); // the le32 members pin the alignment
const_assert!(offset_of!(RawInodeCompact, i_format) == 0); // erofs_fs.h:157
const_assert!(offset_of!(RawInodeCompact, i_xattr_icount) == 2); // erofs_fs.h:160
const_assert!(offset_of!(RawInodeCompact, i_mode) == 4); // erofs_fs.h:161
const_assert!(offset_of!(RawInodeCompact, i_nlink) == 6); // erofs_fs.h:162
const_assert!(offset_of!(RawInodeCompact, i_size) == 8); // erofs_fs.h:163
const_assert!(offset_of!(RawInodeCompact, i_reserved) == 12); // erofs_fs.h:164
const_assert!(offset_of!(RawInodeCompact, i_u) == 16); // erofs_fs.h:165
const_assert!(offset_of!(RawInodeCompact, i_ino) == 20); // erofs_fs.h:167
const_assert!(offset_of!(RawInodeCompact, i_uid) == 24); // erofs_fs.h:168
const_assert!(offset_of!(RawInodeCompact, i_gid) == 26); // erofs_fs.h:169
const_assert!(offset_of!(RawInodeCompact, i_reserved2) == 28); // erofs_fs.h:170

/// The erofs on-disk extended inode (`erofs_inode_extended`,
/// linux/fs/erofs/erofs_fs.h:174-191; field semantics single-sourced
/// in `docs/T-001/analysis.md` §4.4).
///
/// The 64-byte complete form of the dual on-disk inode formats,
/// sharing the discriminating prefix with the compact form
/// (`i_format`/`i_xattr_icount`/`i_mode`/`i_u` at @0/@2/@4/@16 — see
/// the compact form's doc). Two form-specific facts: the negative-
/// size guard I7 is reachable only here (the le64 domain; the guard
/// itself lands with the TryFrom decode, T-022 S07), and this record
/// is the only inode structure whose read may cross a block boundary
/// — the single 64-byte device-stream read handles that internally
/// (RD0; the entry read lands with T-022 S08).
// No deadness attribute — same const_assert liveness rationale as
// `RawInodeCompact` above.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct RawInodeExtended {
    /// The inode format hints — the shared discriminating prefix (see
    /// the compact form's `i_format` doc for the bit layout).
    pub i_format: u16, // @0  __le16
    /// The inline-xattr size in 4-byte units (0 = none).
    pub i_xattr_icount: u16, // @2  __le16
    /// The raw mode word (S_IFMT nibble + permission bits), carried
    /// as-is.
    pub i_mode: u16, // @4  __le16
    /// Reserved; never read (G5). Beware the cross-form name trap:
    /// this field is @6 __le16 here, while the compact form packs
    /// `i_nlink` into that slot and puts its own `i_reserved` at @12
    /// __le32 — same name, different slot and width (T-001 §4.4).
    pub i_reserved: u16, // @6  __le16
    /// The file size, le64 domain; the negative-size guard I7
    /// (`> i64::MAX` -> EUCLEAN) is reachable on this form only and
    /// lands with the TryFrom decode (T-022 S07). The giant-second
    /// domain is carried unchanged through the `Duration` decode
    /// (F6; the `as i64` truncation happens at the statx exit).
    pub i_size: u64, // @8  __le64
    /// The C union `i_u` — the same U1 carrier, four-reading table,
    /// two-passes discipline, and chunk-info decomposition as on the
    /// compact form's field (erofs_fs.h:141-153).
    pub i_u: u32, // @16
    /// 32-bit stat compatibility field; deliberately not consumed —
    /// st_ino derives from the nid (X2).
    pub i_ino: u32, // @20 __le32
    /// The 32-bit uid.
    pub i_uid: u32, // @24 __le32
    /// The 32-bit gid.
    pub i_gid: u32, // @28 __le32
    /// The modification time, seconds part; decoded with the nsec
    /// field through `utils::duration_from_parts` — F6 full-domain
    /// seconds plus the F6n giant-nsec normalization known-diff
    /// (reachable only from malformed images).
    pub i_mtime: u64, // @32 __le64
    /// The modification time, nanoseconds part.
    pub i_mtime_nsec: u32, // @40 __le32
    /// The hard-link count, carried as-is including 0 (no ESTALE
    /// door, same as the compact form).
    pub i_nlink: u32, // @44 __le32
    /// Reserved; never read (G5). A fixed byte array carried as-is
    /// (U2).
    pub i_reserved2: [u8; 16], // @48 __u8[16]
}

// Layout triple and per-field offsets (A1), each anchored to
// linux/fs/erofs/erofs_fs.h; the source-side counterpart of the size
// assertion is BUILD_BUG_ON at erofs_fs.h:444.
const_assert!(size_of::<RawInodeExtended>() == 64); // erofs_fs.h:444
const_assert!(align_of::<RawInodeExtended>() == 8); // the le64 members pin the alignment
const_assert!(offset_of!(RawInodeExtended, i_format) == 0); // erofs_fs.h:175
const_assert!(offset_of!(RawInodeExtended, i_xattr_icount) == 2); // erofs_fs.h:178
const_assert!(offset_of!(RawInodeExtended, i_mode) == 4); // erofs_fs.h:179
const_assert!(offset_of!(RawInodeExtended, i_reserved) == 6); // erofs_fs.h:180
const_assert!(offset_of!(RawInodeExtended, i_size) == 8); // erofs_fs.h:181
const_assert!(offset_of!(RawInodeExtended, i_u) == 16); // erofs_fs.h:182
const_assert!(offset_of!(RawInodeExtended, i_ino) == 20); // erofs_fs.h:184
const_assert!(offset_of!(RawInodeExtended, i_uid) == 24); // erofs_fs.h:185
const_assert!(offset_of!(RawInodeExtended, i_gid) == 28); // erofs_fs.h:186
const_assert!(offset_of!(RawInodeExtended, i_mtime) == 32); // erofs_fs.h:187
const_assert!(offset_of!(RawInodeExtended, i_mtime_nsec) == 40); // erofs_fs.h:188
const_assert!(offset_of!(RawInodeExtended, i_nlink) == 44); // erofs_fs.h:189
const_assert!(offset_of!(RawInodeExtended, i_reserved2) == 48); // erofs_fs.h:190

/// The erofs on-disk chunk info (`erofs_inode_chunk_info`,
/// linux/fs/erofs/erofs_fs.h:136-139; field semantics single-sourced
/// in `docs/T-001/analysis.md` §4.5.1).
///
/// A registration-only record (IN2): on disk these 4 bytes live
/// inside the `i_u` union slot and always arrive through the
/// decomposition documented on the `i_u` fields above (`iu as u16`),
/// so this structure never enters a read path, is never constructed,
/// and derives no `Pod`. The layout assertions below are the
/// mechanical proof of that decomposition — `format` at offset 0
/// means the low 16 bits in LE, and the 4-byte size means the bit
/// widths coincide with `i_u`; the runtime consumer is the
/// decomposition itself, not a constructor. The reserved half is
/// never read or checked (G5), and no helper exists for it (no
/// consumer-less functions).
// No deadness attribute — same const_assert liveness rationale as
// `RawInodeCompact` above.
#[repr(C)]
pub(super) struct RawInodeChunkInfo {
    /// The chunk format: bits 0-4 = the chunk-blkbits shift, bit 5 =
    /// INDEXES (the `CHUNK_FORMAT_*` constants below). The I10
    /// unknown-bit guard consumes `CHUNK_FORMAT_ALL` at the decode
    /// (T-022 S07).
    pub format: u16, // @0 __le16
    /// Reserved; never read (G5).
    pub reserved: u16, // @2 __le16
}

// Layout triple and per-field offsets (A1), each anchored to
// linux/fs/erofs/erofs_fs.h; the source-side counterpart of the size
// assertion is BUILD_BUG_ON at erofs_fs.h:447.
const_assert!(size_of::<RawInodeChunkInfo>() == 4); // erofs_fs.h:447
const_assert!(align_of::<RawInodeChunkInfo>() == 2); // the le16 members pin the alignment
const_assert!(offset_of!(RawInodeChunkInfo, format) == 0); // erofs_fs.h:137
const_assert!(offset_of!(RawInodeChunkInfo, reserved) == 2); // erofs_fs.h:138

/// The erofs on-disk chunk index (`erofs_inode_chunk_index`,
/// linux/fs/erofs/erofs_fs.h:269-273; field semantics single-sourced
/// in `docs/T-001/analysis.md` §6.7).
///
/// The INDEXES=1 extent-area element, read element-wise through
/// `read_val` (the extent array itself is deliberately not wrapped
/// in a structure, U3). The INDEXES=0 sibling form is the bare
/// `__le32[]` block map, registered only through
/// `BLOCK_MAP_ENTRY_SIZE` below — no structure is fabricated for it
/// either.
///
/// The source-side keep-in-sync assertion against
/// `z_erofs_lcluster_index` (erofs_fs.h:452-454) is deferred together
/// with the whole compression family (both sides of the comparison):
/// landing it now would dangle on an undefined type (the archive-C
/// compression domain, G-Z01).
// No deadness attribute — same const_assert liveness rationale as
// `RawInodeCompact` above.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct RawInodeChunkIndex {
    /// "always 0, don't care for now" (source comment): carried
    /// without validation — a non-zero value is silently accepted.
    pub advise: u16, // @0 __le16
    /// The back-end storage id, masked at consumption:
    /// `roundup_pow_of_two(extra_devices + 1) - 1` — on a
    /// single-device volume the mask folds to 0 with no
    /// out-of-range error (consumption: T-025).
    pub device_id: u16, // @2 __le16
    /// The start block address of this chunk. `== NULL_ADDR` means a
    /// hole (a zero read); otherwise the physical address is
    /// `blkaddr * blocksize`. No bounds check — a corrupted address
    /// only moves the read position or surfaces the device error
    /// (consumption: T-025).
    pub blkaddr: u32, // @4 __le32
}

// Layout triple and per-field offsets (A1), each anchored to
// linux/fs/erofs/erofs_fs.h; the source-side counterpart of the size
// assertion is BUILD_BUG_ON at erofs_fs.h:448.
const_assert!(size_of::<RawInodeChunkIndex>() == 8); // erofs_fs.h:448
const_assert!(align_of::<RawInodeChunkIndex>() == 4); // the le32 member pins the alignment
const_assert!(offset_of!(RawInodeChunkIndex, advise) == 0); // erofs_fs.h:270
const_assert!(offset_of!(RawInodeChunkIndex, device_id) == 2); // erofs_fs.h:271
const_assert!(offset_of!(RawInodeChunkIndex, blkaddr) == 4); // erofs_fs.h:272

// ---------------------------------------------------------------------------
// The i_format bit family and the inode-domain constants (T-011 §2.2;
// on-disk facts transcribed from linux/fs/erofs/erofs_fs.h, referenced
// by path at their consumption sites, never forwarded through the
// prelude).
// ---------------------------------------------------------------------------

/// The version bit position within `i_format`
/// (`EROFS_I_VERSION_BIT`, erofs_fs.h:117).
// Live through the extraction helpers at the bottom of this file: an
// item carrying `#[expect(dead_code)]` is a dead-code-analysis root,
// and its references count (same rationale as `SUPER_OFFSET` in
// `super_block.rs`).
pub(super) const I_VERSION_BIT: u16 = 0;

/// The version bit mask (`EROFS_I_VERSION_MASK`, erofs_fs.h:114).
// Live through `inode_version` — same rationale as `I_VERSION_BIT`.
pub(super) const I_VERSION_MASK: u16 = 0x01;

/// The datalayout bit position within `i_format`
/// (`EROFS_I_DATALAYOUT_BIT`, erofs_fs.h:118).
// Live through `inode_datalayout` — same rationale as
// `I_VERSION_BIT`.
pub(super) const I_DATALAYOUT_BIT: u16 = 1;

/// The datalayout bit mask (`EROFS_I_DATALAYOUT_MASK`,
/// erofs_fs.h:115).
// Live through `inode_datalayout` — same rationale as
// `I_VERSION_BIT`.
pub(super) const I_DATALAYOUT_MASK: u16 = 0x07;

/// The full low-bit domain of `i_format` (`EROFS_I_ALL` =
/// `(1 << EROFS_I_ALL_BIT) - 1`, erofs_fs.h:121): version +
/// datalayout, bits 0-3. The I3 guard mask — any bit above it (the
/// 0xFFF0 remainder of the le16 domain) is "unsupported i_format"
/// (EOPNOTSUPP, inode.c:53-59).
// First consumer: the I3 guard of `parse_i_format` (T-022 S06).
#[expect(dead_code)]
pub(super) const I_ALL: u16 = 0x0F;

/// The compact-layout discriminant (`EROFS_INODE_LAYOUT_COMPACT`,
/// erofs_fs.h:132): the version-bit value selecting the 32-byte
/// on-disk form.
// First consumer: the `InodeVersion` construction from the extracted
// version bit (`parse_i_format`, T-022 S06).
#[expect(dead_code)]
pub(super) const INODE_LAYOUT_COMPACT: u8 = 0;

/// The extended-layout discriminant (`EROFS_INODE_LAYOUT_EXTENDED`,
/// erofs_fs.h:134): the version-bit value selecting the 64-byte
/// on-disk form.
// First consumer: same as `INODE_LAYOUT_COMPACT` (T-022 S06).
#[expect(dead_code)]
pub(super) const INODE_LAYOUT_EXTENDED: u8 = 1;

/// The datalayout sentinel (`EROFS_INODE_DATALAYOUT_MAX`,
/// erofs_fs.h:104) — the I4 criterion: an extracted datalayout >= 5
/// (the reserved values 5-7) is "unsupported datalayout" (EOPNOTSUPP,
/// inode.c:61-67). The five legitimate discriminants 0-4 land as the
/// `DataLayout` enum variants (T-022 S06), not as constants here —
/// the enum carries the disk values itself.
// First consumer: the I4 guard of `parse_i_format` (T-022 S06).
#[expect(dead_code)]
pub(super) const INODE_DATALAYOUT_MAX: u8 = 5;

/// The chunk-blkbits field mask within the chunk-info format
/// (`EROFS_CHUNK_FORMAT_BLKBITS_MASK`, erofs_fs.h:124): chunksize =
/// blocksize << chunk-blkbits. The 5-bit domain is carried in full,
/// with no upper-bound check (T-001 §6.6).
// First consumer: the chunkbits formula of the D9 decode —
// `blkszbits + (format & CHUNK_FORMAT_BLKBITS_MASK)` (T-022 S07).
#[expect(dead_code)]
pub(super) const CHUNK_FORMAT_BLKBITS_MASK: u16 = 0x001F;

/// The chunk-index flag (`EROFS_CHUNK_FORMAT_INDEXES`,
/// erofs_fs.h:126): extent area made of 8-byte chunk indexes versus a
/// bare 4-byte blkaddr array.
// First consumers: `AddrState::chunk_unit()` (T-022 S06) and the
// extent-unit selection of the chunked map path (T-025).
#[expect(dead_code)]
pub(super) const CHUNK_FORMAT_INDEXES: u16 = 0x0020;

/// The union of the known chunk-format bits
/// (`EROFS_CHUNK_FORMAT_ALL`, erofs_fs.h:128-129) — the I10 guard
/// mask: any bit outside it is "unsupported chunk format"
/// (EOPNOTSUPP, inode.c:170-175).
// First consumer: the I10 guard of the TryFrom decode (T-022 S07).
#[expect(dead_code)]
pub(super) const CHUNK_FORMAT_ALL: u16 = 0x003F;

/// `EROFS_NULL_ADDR = -1` (erofs_fs.h:263): the chunk-index/block-map
/// value representing a zeroed chunk — a hole.
// First consumer: the hole semantics of the chunked map path
// (`inode/data.rs`, T-025).
#[expect(dead_code)]
pub(super) const NULL_ADDR: u32 = u32::MAX;

/// `EROFS_BLOCK_MAP_ENTRY_SIZE = sizeof(__le32)` (erofs_fs.h:266):
/// the element width of the INDEXES=0 bare block-address array. The
/// bare `__le32[]` stream has no structure to host a layout
/// assertion (U3 — no fabricated structures), so this constant is
/// its only registered form.
// First consumer: the INDEXES=0 extent unit of the chunked map path
// (`inode/data.rs`, T-025).
#[expect(dead_code)]
pub(super) const BLOCK_MAP_ENTRY_SIZE: usize = 4;

/// islotbits = ilog2(sizeof(erofs_inode_compact)) = 5 (super.c:336):
/// the inode-slot width is the fixed 32-byte stride, independent of
/// whether the inode actually stored in a slot is compact or extended
/// (T-001 §4.1). Derived from the structure size — same-sourced with
/// the layout assertions above (C5) — and never written as the
/// literal 5.
// First consumer: the inode metadata-space location formula
// `meta_blkaddr << blkszbits + nid << ISLOT_BITS` (T-024 — the iloc
// computation is the assembly side's step 1).
#[expect(dead_code)]
pub(super) const ISLOT_BITS: u32 = size_of::<RawInodeCompact>().ilog2();

// ---------------------------------------------------------------------------
// i_format extraction (parity with internal.h:296-304). The input is
// the host-order value after the entry pre-read's single `from_le` —
// bit-domain decomposition always happens after the endianness
// conversion (E1).
// ---------------------------------------------------------------------------

/// Extracts the version bit from `i_format` (the parity of
/// `erofs_inode_version`, internal.h:296-299).
// First consumer: `parse_i_format` (T-022 S06); the entry read
// (T-022 S08) joins through it.
#[expect(dead_code)]
fn inode_version(ifmt: u16) -> u8 {
    ((ifmt >> I_VERSION_BIT) & I_VERSION_MASK) as u8
}

/// Extracts the datalayout bits from `i_format` (the parity of
/// `erofs_inode_datalayout`, internal.h:301-304).
// First consumer: the I4 guard and the `DataLayout` construction of
// `parse_i_format` (T-022 S06).
#[expect(dead_code)]
fn inode_datalayout(ifmt: u16) -> u8 {
    ((ifmt >> I_DATALAYOUT_BIT) & I_DATALAYOUT_MASK) as u8
}
