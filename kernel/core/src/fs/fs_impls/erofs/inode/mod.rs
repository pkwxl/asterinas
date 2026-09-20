// SPDX-License-Identifier: MPL-2.0

//! Erofs inode family.
//!
//! The central type, `Inode`, represents one in-memory erofs inode and
//! is the concrete inode object exposed to the VFS adapter. Inodes are
//! identified by nid — erofs has no block groups, so inode numbers are
//! linear and the FS-level cache in `fs.rs` is keyed by nid directly.
//!
//! Bring-up state (T-022 S05–S08 + T-023 S04): the decode half is
//! complete —
//! the two raw inode records (`RawInodeCompact` 32B /
//! `RawInodeExtended` 64B, sharing the discriminating prefix at
//! offsets 0/2/4/16), the chunk-domain records (`RawInodeChunkInfo`,
//! a registration-only host for its layout assertions, and
//! `RawInodeChunkIndex` for element-wise reads), the `i_format` bit
//! family with the two extraction helpers and the entry's
//! `parse_i_format` validation, the inode-domain constants — 13 + 15
//! + 4 + 5 layout assertions in total — plus the four vocabulary
//! enums (`InodeVersion`, `DataLayout`, `FileKind`, `AddrState`),
//! the decoded `InodeDesc` mirror with its 13-field set, the
//! `xattr_ibody_size` helper, the dual `TryFrom` decode with the
//! I7/I8/I10 guards and the G-Z02 dual-caliber `nr_sectors`
//! accounting, the two ID4 `i_u` accessors, and the decode entry
//! `read_inode_desc` — the five-step sequence from the 2-byte
//! pre-read through the `TryFrom`; its step 1 (the iloc formula) and
//! the nid-keyed iget cache live in `Erofs::iget` (`fs.rs`, landed
//! with T-023 S04). The `Inode` handle below carries the nid and the
//! decoded descriptor since T-023 (transitional form: honest type
//! face through `desc.kind`; the metadata assembly stays interim);
//! the payload faces (PageCache/Pipe/device numbers) land with
//! T-024 and remain deliberately not pre-declared here.
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

use align_ext::AlignExt;
use device_id::{DeviceId, MajorId, MinorId};
use ostd::{const_assert, mm::VmIo};

use super::{fs::Erofs, prelude::*, super_block::SuperBlock};
use crate::fs::vfs::inode::Extension;

/// An erofs inode number (`nid`): the linear on-disk inode identifier.
pub(super) type ErofsNid = u64;

/// An in-memory erofs inode.
///
/// Transitional form (T-023): carries the nid and the decoded
/// descriptor — the single data source of the type face and of the
/// compressed-data judgement — plus the weak back-pointer and the
/// VFS extension slot. The payload field (per-kind PageCache/Pipe/
/// device faces) lands with T-024. What is already final here is the
/// weak back-pointer discipline: `self_ref` is the only link back to
/// the filesystem handle (strong reference cycles are forbidden
/// family-wide) and the upgrade path carries an `EIO` guard.
pub struct Inode {
    nid: ErofsNid,
    desc: InodeDesc,
    self_ref: Weak<Erofs>,
    extension: Extension,
}

impl Inode {
    /// Constructs the inode handle (transitional T-023 form): the
    /// nid, the decoded descriptor, and the weak filesystem
    /// back-pointer. The sole constructor — every `Inode` comes from
    /// the slow path of `Erofs::iget` (`fs.rs`). T-024 extends the
    /// same construction point with the payload assembly (per-kind
    /// PageCache/Pipe/device faces) and the I12 arm-first gate.
    pub(super) fn new(nid: ErofsNid, desc: InodeDesc, self_ref: Weak<Erofs>) -> Self {
        Self {
            nid,
            desc,
            self_ref,
            extension: Extension::new(),
        }
    }

    /// Returns the inode number (nid) — the linear on-disk inode
    /// identifier as resolved by `Erofs::iget` (st_ino derives from
    /// it, X2; the on-disk `i_ino` compat field is never consumed).
    pub(super) fn ino(&self) -> ErofsNid {
        self.nid
    }

    /// Returns the inode type, derived from the decoded descriptor
    /// (`desc.kind` is the single data source — the handle keeps no
    /// separate type field and one judgement path).
    ///
    /// Honest minimal face (T-023): the seven-kind mapping below is
    /// the full bijection onto the framework `InodeType`. The
    /// `Other` arm is structurally unreachable — the I8 guard
    /// rejects it with `EUCLEAN` before a descriptor escapes the
    /// decode — and exists only to keep the match exhaustive. The
    /// formal `From<FileKind> for InodeType` face and the metadata
    /// payload land with T-024.
    pub(super) fn type_(&self) -> InodeType {
        match self.desc.kind {
            FileKind::Reg => InodeType::File,
            FileKind::Dir => InodeType::Dir,
            FileKind::Lnk => InodeType::SymLink,
            FileKind::Chr => InodeType::CharDevice,
            FileKind::Blk => InodeType::BlockDevice,
            FileKind::Fifo => InodeType::NamedPipe,
            FileKind::Sock => InodeType::Socket,
            // Unreachable: the I8 guard ("bogus i_mode", EUCLEAN)
            // rejects the Other kind at the decode, so a runtime
            // descriptor never carries it.
            FileKind::Other(_) => unreachable!("I8 rejects the Other kind at decode"),
        }
    }

    /// Whether this inode carries compressed data — the handle-side
    /// forwarder of the rejection-chain layer-3 predicate (G-M15).
    ///
    /// Pure forwarding, no criteria here: the judgement lives on the
    /// descriptor (`InodeDesc::is_data_compressed`, the single
    /// source) and must not be rewritten at any forwarding face —
    /// the mount-time site gates of `Erofs::open` (F10/F11) and the
    /// runtime map_blocks half share it.
    pub(super) fn is_data_compressed(&self) -> bool {
        self.desc.is_data_compressed()
    }

    /// Whether this inode is a directory — the `desc.kind`
    /// judgement (same data source as `type_`), consumed by the
    /// F12 mount door.
    pub(super) fn is_dir(&self) -> bool {
        matches!(self.desc.kind, FileKind::Dir)
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
// Live since T-022 S06: consumed by the I3 guard of `parse_i_format`
// below — an `#[expect(dead_code)]` function is a dead-code-analysis
// root, and its references count. The bridging `expect` was removed
// when that consumer landed.
pub(super) const I_ALL: u16 = 0x0F;

/// The compact-layout discriminant (`EROFS_INODE_LAYOUT_COMPACT`,
/// erofs_fs.h:132): the version-bit value selecting the 32-byte
/// on-disk form.
// Live since T-022 S06: referenced by the compile-time discriminant
// lock beside `InodeVersion` (and spelled on the else arm of the
// version construction in `parse_i_format` — the 1-bit extraction
// domain makes that arm exactly this value).
pub(super) const INODE_LAYOUT_COMPACT: u8 = 0;

/// The extended-layout discriminant (`EROFS_INODE_LAYOUT_EXTENDED`,
/// erofs_fs.h:134): the version-bit value selecting the 64-byte
/// on-disk form.
// Live since T-022 S06: referenced by the compile-time discriminant
// lock beside `InodeVersion` and compared directly by the version
// construction in `parse_i_format`.
pub(super) const INODE_LAYOUT_EXTENDED: u8 = 1;

/// The datalayout sentinel (`EROFS_INODE_DATALAYOUT_MAX`,
/// erofs_fs.h:104) — the I4 criterion: an extracted datalayout >= 5
/// (the reserved values 5-7) is "unsupported datalayout" (EOPNOTSUPP,
/// inode.c:61-67). The five legitimate discriminants 0-4 land as the
/// `DataLayout` enum variants below, not as constants here —
/// the enum carries the disk values itself.
// Live since T-022 S06: consumed by the I4 guard of `parse_i_format`
// below — same root-reference rationale as `I_ALL`.
pub(super) const INODE_DATALAYOUT_MAX: u8 = 5;

/// The chunk-blkbits field mask within the chunk-info format
/// (`EROFS_CHUNK_FORMAT_BLKBITS_MASK`, erofs_fs.h:124): chunksize =
/// blocksize << chunk-blkbits. The 5-bit domain is carried in full,
/// with no upper-bound check (T-001 §6.6).
// Live since T-022 S07: consumed by the chunkbits formula of the D9
// decode — `blkszbits + (format & CHUNK_FORMAT_BLKBITS_MASK)`. The
// bridging `expect` was removed when the first consumer landed.
pub(super) const CHUNK_FORMAT_BLKBITS_MASK: u16 = 0x001F;

/// The chunk-index flag (`EROFS_CHUNK_FORMAT_INDEXES`,
/// erofs_fs.h:126): extent area made of 8-byte chunk indexes versus a
/// bare 4-byte blkaddr array.
// Live since T-022 S06: consumed by `AddrState::chunk_unit` below
// (itself an `#[expect(dead_code)]` root whose references count); the
// chunked map path (`inode/data.rs`, T-025) joins through that
// accessor. The bridging `expect` was removed when the first
// consumer landed.
pub(super) const CHUNK_FORMAT_INDEXES: u16 = 0x0020;

/// The union of the known chunk-format bits
/// (`EROFS_CHUNK_FORMAT_ALL`, erofs_fs.h:128-129) — the I10 guard
/// mask: any bit outside it is "unsupported chunk format"
/// (EOPNOTSUPP, inode.c:170-175).
// Live since T-022 S07: consumed by the I10 guard of the TryFrom
// decode. The bridging `expect` was removed when the first consumer
// landed.
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
// Live since T-022 S06: consumed by `AddrState::chunk_unit` below
// (the INDEXES=0 unit of that accessor); the chunked extent walk
// (`inode/data.rs`, T-025) joins through it. The bridging `expect`
// was removed when the first consumer landed.
pub(super) const BLOCK_MAP_ENTRY_SIZE: usize = 4;

/// islotbits = ilog2(sizeof(erofs_inode_compact)) = 5 (super.c:336):
/// the inode-slot width is the fixed 32-byte stride, independent of
/// whether the inode actually stored in a slot is compact or extended
/// (T-001 §4.1). Derived from the structure size — same-sourced with
/// the layout assertions above (C5) — and never written as the
/// literal 5.
// Live since T-023 S04: consumed by the iloc formula of `Erofs::iget`
// (`fs.rs`) — the assembly-side step 1 of the five-step decode. The
// bridging `expect` was removed when the first consumer landed.
pub(super) const ISLOT_BITS: u32 = size_of::<RawInodeCompact>().ilog2();

// ---------------------------------------------------------------------------
// i_format extraction (parity with internal.h:296-304). The input is
// the host-order value after the entry pre-read's single `from_le` —
// bit-domain decomposition always happens after the endianness
// conversion (E1).
// ---------------------------------------------------------------------------

/// Extracts the version bit from `i_format` (the parity of
/// `erofs_inode_version`, internal.h:296-299).
// Live since T-022 S06: called by `parse_i_format` below; the entry
// read (T-022 S08) joins through it.
fn inode_version(ifmt: u16) -> u8 {
    ((ifmt >> I_VERSION_BIT) & I_VERSION_MASK) as u8
}

/// Extracts the datalayout bits from `i_format` (the parity of
/// `erofs_inode_datalayout`, internal.h:301-304).
// Live since T-022 S06: called twice by `parse_i_format` below (the
// I4 guard and the `DataLayout` construction).
fn inode_datalayout(ifmt: u16) -> u8 {
    ((ifmt >> I_DATALAYOUT_BIT) & I_DATALAYOUT_MASK) as u8
}

// ---------------------------------------------------------------------------
// The typed vocabulary: four enums, the InodeDesc mirror, the
// xattr-size helper, and the entry's one-shot i_format validation
// (T-022 S06; `docs/T-011/S05/index.md` §2/§3, `docs/T-011/S03/
// index.md` §2.2, `docs/T-011/S06/index.md` §1.1, `docs/T-011/
// analysis.md` §3.2).
// ---------------------------------------------------------------------------

/// The inode layout version (i_format bit 0; the discriminants are
/// the on-disk `EROFS_INODE_LAYOUT_*` values).
///
/// No `Invalid` variant: the 1-bit domain has exactly two values, and
/// the sole construction entrance is `parse_i_format` below — the
/// source-side version switch default (inode.c:126-130,
/// -EOPNOTSUPP) is structurally unreachable and is not fabricated as
/// an error arm (G7, T-001 §9.7.1). The TryFrom conversions
/// additionally carry the version statically in their input types,
/// so no dispatch on it can miss a case.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InodeVersion {
    /// The 32-byte on-disk form (`EROFS_INODE_LAYOUT_COMPACT`).
    Compact = 0, // erofs_fs.h:132
    /// The 64-byte on-disk form (`EROFS_INODE_LAYOUT_EXTENDED`).
    Extended = 1, // erofs_fs.h:134
}

// The on-disk layout discriminants and the enum's own discriminants
// are the same values — locked here at compile time so the version
// construction of `parse_i_format` and the disk layout stay
// same-sourced (C5). Underscore-named consts are dead-code-exempt
// themselves yet count as uses of the referenced items.
const _: () = {
    assert!(INODE_LAYOUT_COMPACT == InodeVersion::Compact as u8);
    assert!(INODE_LAYOUT_EXTENDED == InodeVersion::Extended as u8);
};

/// The data layout (i_format bits 1-3; the discriminants are the
/// on-disk values, erofs_fs.h:98-104).
///
/// The reserved values 5-7 never become variants: the I4 guard of
/// the entry validation rejects them before construction
/// (EOPNOTSUPP, inode.c:61-67), so the type carries no
/// reserved-value or `Invalid` variants and no unreachable match arm
/// exists anywhere (T-001 §9.7.1). The exhaustive classification of
/// the low nibble — 16 combinations, 0x0-0x9 passing (ten) and
/// 0xA-0xF rejected by I4 (six) — is the design/verification ledger
/// (`docs/T-011/S06/index.md` §3.2), not a runtime surface.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DataLayout {
    /// Data sits at the `i_u` flat block address.
    FlatPlain = 0, // erofs_fs.h:99
    /// Compressed data, full form (`EROFS_INODE_FLAT_COMPRESSED`).
    CompressedFull = 1, // erofs_fs.h:100
    /// The file tail is inline after the inode record.
    FlatInline = 2, // erofs_fs.h:101
    /// Compressed data, compact form
    /// (`EROFS_INODE_COMPACT_COMPRESSED`).
    CompressedCompact = 3, // erofs_fs.h:102
    /// The extent area is a chunk-index or block-map array.
    ChunkBased = 4, // erofs_fs.h:103
}

impl DataLayout {
    /// The parity of `erofs_is_data_compressed` (erofs_fs.h:107-111):
    /// datalayout ∈ {1, 3}. The single source of this predicate —
    /// the TryFrom D9/D12 accounting consumes it first, and the
    /// layer-3 rejection site `inode/data.rs::map_blocks`
    /// (datalayout ≠ flat → EOPNOTSUPP, T-025) forwards through it,
    /// never rewrites it.
    // Live since T-022 S07: consumed by the D9/D12 segments of the
    // TryFrom bodies. The bridging `expect` was removed when the
    // first consumer landed.
    pub(super) fn is_compressed(&self) -> bool {
        matches!(self, Self::CompressedFull | Self::CompressedCompact)
    }
}

// The `i_mode` type-bit constants (include/uapi/linux/stat.h facts,
// transcribed as the module-private host — no framework-wide host
// exists: `InodeType` carries its own local `TYPE_MASK`, and its
// `from_raw_mode` is the rejected precedent documented on `FileKind`).
const S_IFMT: u16 = 0o170000;
const S_IFIFO: u16 = 0o010000;
const S_IFCHR: u16 = 0o020000;
const S_IFDIR: u16 = 0o040000;
const S_IFBLK: u16 = 0o060000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;
const S_IFSOCK: u16 = 0o140000;

/// The S_IFMT type segment of `i_mode`, typed (T-001 §9.7.4 full
/// form; the parity of the source switch, inode.c:138-155).
///
/// The sole construction entrance is `from_raw_i_mode`. The
/// framework's `InodeType::from_raw_mode`
/// (`file/inode_attr/type.rs:38-48`) is deliberately not used: it
/// special-cases mode==0 to `File` (linux reports -EFSCORRUPTED
/// there) and reports unknown types as EINVAL — a double drift from
/// the linux behavior this decode mirrors (the ext2 negative
/// precedent, G-N01 candidate 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FileKind {
    /// S_IFREG.
    Reg,
    /// S_IFDIR.
    Dir,
    /// S_IFLNK.
    Lnk,
    /// S_IFCHR.
    Chr,
    /// S_IFBLK.
    Blk,
    /// S_IFIFO.
    Fifo,
    /// S_IFSOCK.
    Sock,
    /// Any S_IFMT value outside the seven kinds — nine of the
    /// sixteen nibble values. The I8 guard rejects this variant with
    /// EUCLEAN at construction, so a runtime `InodeDesc` never
    /// carries it; the variant itself is the guard-carrying face and
    /// keeps every kind match default-free (T-001 §9.7.4). The
    /// payload is the nibble value, kept for diagnostics.
    // AUTO-DECISION: no dead-code suppression on the payload — the
    // in-crate clippy -Dwarnings run (T-022 S06 test round) proved
    // the field-never-read finding does not fire at this position
    // (the standalone-probe prediction diverged: the sole
    // construction site lives inside the not-yet-called
    // `from_raw_i_mode`), so an expect here stays unfulfilled.
    Other(u8),
}

impl FileKind {
    /// Types the S_IFMT segment of `i_mode`. Exhaustive over the 16
    /// nibble values: the seven kinds {1, 2, 4, 6, 8, A, C} pass and
    /// the other nine land in `Other` (the low 12 permission bits
    /// are irrelevant here — they are carried losslessly by the
    /// `mode` field, X3).
    // Live since T-022 S07: consumed by the kind decode and the I8
    // guard of the TryFrom bodies. The bridging `expect` was removed
    // when the first consumer landed.
    fn from_raw_i_mode(i_mode: u16) -> Self {
        match i_mode & S_IFMT {
            S_IFIFO => Self::Fifo,
            S_IFCHR => Self::Chr,
            S_IFDIR => Self::Dir,
            S_IFBLK => Self::Blk,
            S_IFREG => Self::Reg,
            S_IFLNK => Self::Lnk,
            S_IFSOCK => Self::Sock,
            other => Self::Other((other >> 12) as u8),
        }
    }
}

/// The D9 cross-cutting discrimination product — the decoded form of
/// the second, datalayout-driven reading of `i_u` (T-001 §9.7.3,
/// archive-A form).
///
/// The source-side `vi` union "one storage overwritten per stage"
/// cannot exist under decode-once plus mutually-exclusive-layer
/// trimming: the enum makes the alias-overwrite unrepresentable, and
/// the D9 discrimination is driven by `datalayout` alone — it is
/// structurally never placed inside a kind branch (the pathological
/// kind x datalayout combinations are accepted parity behavior,
/// T-003 §1.4).
// The variants are constructed by the TryFrom D9 segments below. The
// enum-level bridging `expect` was removed in the T-022 S07 test
// round: trait impls are live roots of the in-crate dead-code
// analysis, so the conversions' constructions are already visible
// and the expectation came out unfulfilled (the standalone probe had
// predicted the bodies stay invisible — it diverged). The `bits`
// payload is first read by the T-025 map path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AddrState {
    /// FLAT_PLAIN / FLAT_INLINE: the data start is the `raw_blkaddr`
    /// reading of `i_u` (accessor landing with T-022 S07). Carries
    /// no copy of the u32 — the value is always `i_u`, and a
    /// duplicate would violate the single-data-source discipline.
    Flat,
    /// CHUNK_BASED: the chunk metadata materialized once at the
    /// decode. `format` keeps the raw chunk-format word (the INDEXES
    /// bit is consumed by `chunk_unit()`); `bits` = sb.blkszbits +
    /// (format & CHUNK_FORMAT_BLKBITS_MASK) (inode.c:176-177; the
    /// 5-bit domain is carried in full, no upper-bound check). The
    /// I10 guard runs before the materialization, so a format with
    /// unknown bits never enters this variant.
    Chunked { format: u16, bits: u32 },
    /// Compressed (archive A): decoded and accepted (T-003 §1.4),
    /// with the `compressed_blocks` reading of `i_u` consumed inside
    /// the conversion body by the nr_sectors accounting (D12) — no
    /// post-decode consumer copy remains, and the layer-3 rejection
    /// (I12) belongs to `inode/data.rs::map_blocks` (T-025).
    /// Revival note: this variant gains its z_* payload with the
    /// G-Z01 archive-C takeover.
    Compressed,
}

impl AddrState {
    /// The extent element unit of the chunked map path (the derived
    /// supply of `docs/T-011/S03/index.md` §6.3): INDEXES (format
    /// bit 5) set → `size_of::<RawInodeChunkIndex>()`, otherwise
    /// `BLOCK_MAP_ENTRY_SIZE`; `None` outside the chunked state.
    /// `data.rs` takes the unit through this accessor and does not
    /// reference the mod.rs domain constants directly (the
    /// cross-file discipline, T-010 §3.2).
    // First consumer: the chunked extent walk (`inode/data.rs`,
    // T-025).
    #[expect(dead_code)]
    pub(super) fn chunk_unit(&self) -> Option<usize> {
        match self {
            Self::Flat | Self::Compressed => None,
            Self::Chunked { format, .. } => Some(if format & CHUNK_FORMAT_INDEXES != 0 {
                size_of::<RawInodeChunkIndex>()
            } else {
                BLOCK_MAP_ENTRY_SIZE
            }),
        }
    }
}

/// The erofs in-memory inode descriptor — the decoded mirror of the
/// dual-format on-disk records (the ext2 counterpart is
/// `ext2/inode/mod.rs:233-254`).
///
/// Decoded once, wholly immutable after construction (the
/// mutually-exclusive-layer-trim model, T-010 §5.3 D2); the resident
/// `Inode` handle (T-024) carries one. The sole construction
/// entrances are the two TryFrom conversions (T-022 S07) — the
/// filesystem is read-only, so there is no ext2-style `new()`
/// creator and no write-direction `From<&InodeDesc>` either.
///
/// # Field liveness (dead-code ledger)
///
/// The same discipline as the `SuperBlock` mirror. Trait impls are
/// live roots of the in-crate dead-code analysis, so the two
/// conversion bodies (S07) are already visible — every helper they
/// reference stays live through them (the S07 test round removed the
/// eight first-consumer expects that came out unfulfilled). Writes
/// are not reads, though: a field is only live once live code reads
/// it. `version` is read by `inode_isize()` below and `kind` and
/// `i_u` by the ID4 accessors below — an `#[expect(dead_code)]`
/// method is a dead-code-analysis root, and its reads count — while
/// the other ten fields carry their own `#[expect(dead_code)]` with
/// the first consumer annotated, firing `unfulfilled` as the removal
/// prompt when that consumer lands.
///
/// # Not-mirrored ledger (explicit, `docs/T-011/analysis.md` §3.2)
///
/// `nid` (st_ino derives from it on the handle, X2), `i_ino` (never
/// read, X2), `i_reserved`/`i_reserved2` (G5), `nblks` (the
/// compressed-blocks reading is consumed inside the conversion body
/// by the D12 accounting — no post-decode consumer exists in
/// archive A), the `rdev` bit pattern (an accessor face, not a
/// field), separate ctime/atime copies (D10: the three times are
/// one field), and btime (no on-disk source, X9 — the assembler
/// fills `None`).
#[derive(Clone, Copy, Debug)]
pub(super) struct InodeDesc {
    /// The on-disk layout version (carried statically by the TryFrom
    /// input type; read by `inode_isize()` below).
    pub(super) version: InodeVersion,
    /// The data layout — the entry's one-shot discrimination product,
    /// flowing in as a conversion parameter (I3/I4 are never
    /// re-judged here).
    // Live since T-023 S04: read by the layer-3 predicate
    // `is_data_compressed` below (an expect-carrying item is a
    // dead-code-analysis root, so its reads count); the path dispatch
    // of the handle joins with T-024.
    pub(super) datalayout: DataLayout,
    /// Runtime invariant: never `Other` — the I8 guard rejects at
    /// construction, so `Other` exists only on the guard-carrying
    /// face.
    // Live since T-022 S07: read by the accessor premises below (the
    // InodeType mapping joins in T-024).
    pub(super) kind: FileKind,
    /// The 12 permission bits, carried losslessly (X3: no permission
    /// canonicalization at the decode).
    // First reader: Metadata.mode (T-024).
    #[expect(dead_code)]
    pub(super) mode: InodeMode,
    /// The owner id (zero-extended from le16 on the compact form).
    // First reader: the Uid wrapper (T-024).
    #[expect(dead_code)]
    pub(super) uid: u32,
    /// The group id (zero-extended from le16 on the compact form).
    // First reader: the Gid wrapper (T-024).
    #[expect(dead_code)]
    pub(super) gid: u32,
    /// The hard-link count, carried as-is including 0 — the ext2
    /// link-count ESTALE door is an ext2-specific defense and is
    /// deliberately not transcribed.
    // First reader: Metadata.nr_hard_links (T-024, as usize).
    #[expect(dead_code)]
    pub(super) nlink: u32,
    /// The file size. Construction invariant: <= i64::MAX (the
    /// extended form via the I7 guard, the compact form by the le32
    /// width).
    // First readers: Metadata.size (T-024, as usize) and the data
    // path (T-025).
    #[expect(dead_code)]
    pub(super) size: u64,
    /// The inline-xattr area size, as converted by
    /// `xattr_ibody_size` — an unvalidated value carried in the
    /// mirror; the boundary guard belongs to the consumer (T-026).
    // First readers: the extent-start location (T-025) and the
    // three-state gate / ibody location (T-026).
    #[expect(dead_code)]
    pub(super) xattr_isize: usize,
    /// The modification time (the F6/F6n carrier discipline: the
    /// le64 seconds domain is carried unchanged — the `as i64`
    /// truncation happens at the statx exit — and a malformed nsec
    /// >= 1e9 normalizes through `duration_from_parts`, the F6n
    /// known-diff, reachable only from malformed images). D10: the
    /// three Metadata times are filled from this one field; the
    /// compact form copies `sb.build_time` (the same-source
    /// derivation).
    // First reader: the three Metadata times (T-024).
    #[expect(dead_code)]
    pub(super) time: Duration,
    /// The C union `i_u` as the single host-order source (the
    /// conversion body's one `from_le`); every reading — the
    /// first-pass kind views and the second-pass datalayout views —
    /// is a view of this one value, never a re-interpretation in
    /// place (the two-independent-passes fidelity, T-003 §1.3).
    // Live since T-022 S07: read by the ID4 accessors below.
    pub(super) i_u: u32,
    /// The D9 discrimination product (see `AddrState`).
    // First readers: the chunk-unit/bits consumption (T-024/T-025).
    #[expect(dead_code)]
    pub(super) addr_state: AddrState,
    /// The 512-byte-sector accounting — the D12 dual-caliber product
    /// (the formula's single source is the G-Z02 note inside the
    /// conversion bodies, T-022 S07).
    // First reader: Metadata.nr_sectors_allocated (T-024).
    #[expect(dead_code)]
    pub(super) nr_sectors: usize,
}

impl InodeDesc {
    /// The per-version on-disk inode size (the source-side
    /// `vi->inode_isize`, inode.c:70/:76): consumes `size_of`
    /// directly — the layout assertions above already prove 32/64,
    /// so no literal is written (C5). The suffix location (inline
    /// xattr / inline data start = inode_isize + xattr_isize) is the
    /// consumer.
    // First consumers: the extent-start location of the chunked map
    // path (T-025) and the ibody location (T-026).
    #[expect(dead_code)]
    pub(super) fn inode_isize(&self) -> usize {
        match self.version {
            InodeVersion::Compact => size_of::<RawInodeCompact>(),
            InodeVersion::Extended => size_of::<RawInodeExtended>(),
        }
    }

    /// The first-pass `i_u` reading for REG/DIR/LNK: the data start
    /// block (D8, inode.c:142). No range check — out-of-volume and
    /// zero values are carried as-is; the rejection belongs to the
    /// data-path consumer (`inode/data.rs`, T-025).
    ///
    /// The `debug_assert` below pins the discrimination premise, not
    /// a disk value: its target is API misuse (a review-surface
    /// programming error), which is not an error path and never a
    /// parity surface (the DBG_BUGON discipline, G6, bans the
    /// opposite promotion of debug asserts into runtime checks).
    // First consumer: the flat direct mapping of the map path
    // (`inode/data.rs::map_blocks`, T-025).
    #[expect(dead_code)]
    pub(super) fn raw_blkaddr(&self) -> u32 {
        debug_assert!(matches!(
            self.kind,
            FileKind::Reg | FileKind::Dir | FileKind::Lnk
        ));
        self.i_u
    }

    /// The first-pass `i_u` reading for CHR/BLK: the device number
    /// (D8, inode.c:151), through the `new_decode_dev` bit pattern
    /// (kdev_t.h:46-51): major = (v & 0xfff00) >> 8 (12 bits) and
    /// minor = (v & 0xff) | ((v >> 12) & 0xfff00) (20 bits) — exactly
    /// the full domains of `MajorId`/`MinorId`, so the ranged
    /// constructors have no reachable failure (linux decodes any
    /// le32 into a defined device number). The ext2 extended-branch
    /// precedent (`block_ptr_tree.rs:898-906`) is taken here without
    /// the encode/decode round trip, which is the identity on these
    /// widths. FIFO/SOCK have no reading path at all — the assembly
    /// fills `self_dev_id = None` for them (T-003 X6, T-024). Same
    /// premise-assert discipline as `raw_blkaddr` above.
    // First consumer: the special-file assembly (`self_dev_id`,
    // T-024).
    #[expect(dead_code)]
    pub(super) fn rdev(&self) -> DeviceId {
        debug_assert!(matches!(self.kind, FileKind::Chr | FileKind::Blk));
        let v = self.i_u;
        let major = (v & 0xfff00) >> 8;
        let minor = (v & 0xff) | ((v >> 12) & 0xfff00);
        DeviceId::new(MajorId::new(major as u16), MinorId::new(minor))
    }

    /// I12 predicate — rejection-chain layer 3 (G-M15): whether this
    /// inode carries compressed data whose consumers are shelved under
    /// scope decision AR-S01-5. Mirrors `erofs_fill_inode`: REG/DIR/LNK
    /// flow into the a_ops assignment and a compressed datalayout fails
    /// iget with EOPNOTSUPP under the non-ZIP build, while special
    /// files (CHR/BLK/FIFO/SOCK) return early and stay exempt. The
    /// runtime half of this rejection is lazy (map_blocks, T-014);
    /// this predicate is the single judgement source for both.
    // Live since T-023 S05: the F10/F11 mount-time site gates of
    // `Erofs::open` reach it through the `Inode` forwarder above
    // (which must not rewrite the criteria, single-source
    // contract); later joiners: the I12 assembly arm-first gate
    // (T-024) and the map_blocks defensive half (T-014). The
    // bridging `expect` was removed when the first consumer landed.
    pub(super) fn is_data_compressed(&self) -> bool {
        self.datalayout.is_compressed() // T-011 ID2: ⟺ ∈ {1, 3}
            && matches!(self.kind, FileKind::Reg | FileKind::Dir | FileKind::Lnk)
    }
}

/// The parity of `erofs_xattr_ibody_size` (erofs_fs.h:245-252):
/// icount == 0 → 0, otherwise 12 + 4 × (icount − 1).
///
/// An unconditional conversion with no boundary check: the le16
/// input domain caps the result at 262148 bytes and the mirror
/// deliberately carries the unvalidated value — the boundary guard
/// belongs to the consumption point (T-026). The literal 12 is the
/// `RawXattrIbodyHeader` size, same-valued with its layout
/// assertion in `xattr.rs` (a mutual proof — this file does not
/// reference the xattr.rs type, the L4 direction forbids it). The
/// two branches are exhaustive over the le16 domain, so the
/// (icount == 0, result == 12) corner is structurally unreachable
/// and no third arm exists (G7).
// Live since T-022 S07: consumed by the `xattr_isize` field decode
// of the TryFrom bodies. The bridging `expect` was removed when the
// first consumer landed.
fn xattr_ibody_size(icount: u16) -> usize {
    if icount == 0 {
        0
    } else {
        12 + 4 * (icount as usize - 1)
    }
}

/// The entry's one-shot `i_format` validation (step 3 of the
/// five-step decode, `docs/T-011/S05/index.md` §1.1): the I3/I4
/// guards, then the typed pair.
///
/// Guard order = the source execution order
/// (`docs/T-001/analysis.md` §9.2): I3 first — any bit above `I_ALL`
/// (the 0xFFF0 remainder of the le16 domain) is "unsupported
/// i_format" (EOPNOTSUPP, inode.c:53-59); I4 strictly after — an
/// extracted datalayout of 5..=7 (the reserved discriminants) is
/// "unsupported datalayout" (EOPNOTSUPP, inode.c:61-67). With both
/// malformed values present the first error is I3's (the same-errno
/// ordering, the observable face of the sequence).
///
/// The one-shot-validation defense: the discrimination read set is
/// exactly the 2 pre-read bytes, so a malformed value never triggers
/// the full-record read, any suffix read, or the cross-block stream
/// (`docs/T-011/S06/index.md` §4).
// Live since T-022 S08: called by `read_inode_desc` below; the T-024
// assembly (iloc computation + iget) joins through it.
fn parse_i_format(ifmt: u16) -> Result<(InodeVersion, DataLayout)> {
    if ifmt & !I_ALL != 0 {
        return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported i_format");
    }
    if inode_datalayout(ifmt) >= INODE_DATALAYOUT_MAX {
        return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported datalayout");
    }

    // The two guards above are the whole rejection face, so the
    // catch-all arms below fold only onto values already rejected
    // there: the version extraction masks to its 1-bit domain, and a
    // datalayout of 5..=7 has returned at I4 — no unreachable error
    // arm is fabricated (G7).
    let version = if inode_version(ifmt) == INODE_LAYOUT_EXTENDED {
        InodeVersion::Extended
    } else {
        InodeVersion::Compact // == INODE_LAYOUT_COMPACT (erofs_fs.h:132)
    };
    let datalayout = match inode_datalayout(ifmt) {
        0 => DataLayout::FlatPlain,         // erofs_fs.h:99
        1 => DataLayout::CompressedFull,    // erofs_fs.h:100
        2 => DataLayout::FlatInline,        // erofs_fs.h:101
        3 => DataLayout::CompressedCompact, // erofs_fs.h:102
        _ => DataLayout::ChunkBased,        // == 4 (erofs_fs.h:103); 5..=7 rejected at I4
    };
    Ok((version, datalayout))
}

// ---------------------------------------------------------------------------
// The dual TryFrom decode (T-022 S07; signatures `docs/T-011/S05/
// index.md` §1.2, field table §3.1, accessor shrink §5; guard and
// order spec `docs/T-011/S06/index.md` §1.1/§2.1; G-Z02 note
// `docs/T-011/analysis.md` §4.5). The compressed-blocks and chunk
// readings of `i_u` stay inline in these bodies (ID4: no
// consumer-less functions) — `nblks` is exhausted by the D12
// accounting below, the chunk metadata by the `AddrState::Chunked`
// materialization.
// ---------------------------------------------------------------------------

/// The compact-form decode: the D5 field accounting plus the I8/I10
/// guards.
///
/// The parameter-form triple (ID0): the version is carried statically
/// by the input type, `datalayout` is the entry's one-shot
/// discrimination product flowing in as a parameter (I3/I4 are never
/// re-judged here), and the superblock enters as one whole reference
/// — the three exogenous consumption points are the compact time
/// derivation, the chunkbits shift, and the D12 dual-caliber
/// accounting. The error face is {I8, I10}: the negative-size guard
/// I7 is structurally unreachable on this form — the le32 domain
/// caps `i_size` at 4GiB - 1 — and no fake guard is fabricated (G7;
/// the ext2 precedent `ext2/inode/mod.rs:316-318` is the
/// extended-form counterpart only, and the ext2 ESTALE and
/// symlink-size doors are deliberately not transcribed).
///
/// No I/O arm (the input is already an in-memory image; read errors
/// belong to the entry read, S08), no ENOMEM arm (all-Copy fields,
/// zero allocation, F4/G-M21), and no assembly-face guard (I12 and
/// the blkszbits door belong to the data path and the mount
/// sequence). Half-state invisibility (C1): every guard returns
/// before the `Ok` literal is assembled, so no partially-built
/// descriptor can escape the conversion.
impl TryFrom<(&RawInodeCompact, DataLayout, &SuperBlock)> for InodeDesc {
    type Error = Error;

    fn try_from(
        (raw, datalayout, sb): (&RawInodeCompact, DataLayout, &SuperBlock),
    ) -> Result<Self> {
        // D5 field decode: pure memory, no error exit — the source
        // copies the fields (inode.c:97-124) ahead of every content
        // guard. E1: every little-endian field converts exactly once,
        // here (the 7-field ledger, S05 §6; the `mode` local serves
        // both the kind discrimination and the permission bits).
        let mode = u16::from_le(raw.i_mode);
        let kind = FileKind::from_raw_i_mode(mode);
        let size = u32::from_le(raw.i_size) as u64;
        let xattr_isize = xattr_ibody_size(u16::from_le(raw.i_xattr_icount));
        let iu = u32::from_le(raw.i_u);

        // D8 (I8): the bogus-i_mode guard, strictly before the D9
        // cross-cut (inode.c:157-161 ahead of :164-178).
        if matches!(kind, FileKind::Other(_)) {
            return_errno_with_message!(Errno::EUCLEAN, "bogus i_mode");
        }

        // D9: the second, datalayout-driven reading of `iu` — never
        // inside a kind branch (the pathological kind x datalayout
        // combinations are accepted parity behavior, T-003 §1.4).
        let addr_state = match datalayout {
            DataLayout::FlatPlain | DataLayout::FlatInline => AddrState::Flat,
            DataLayout::CompressedFull | DataLayout::CompressedCompact => AddrState::Compressed,
            DataLayout::ChunkBased => {
                // The chunk-info decomposition (S03 §5): `iu as u16`,
                // mechanically proven by the `RawInodeChunkInfo`
                // layout assertions; the reserved half is never read
                // (G5).
                let chunkformat = iu as u16;
                // I10: unknown chunk-format bits, rejected before the
                // `Chunked` materialization (inode.c:170-175).
                if chunkformat & !CHUNK_FORMAT_ALL != 0 {
                    return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported chunk format");
                }
                // inode.c:176-177: the 5-bit chunk-blkbits domain is
                // carried in full, with no upper-bound check.
                let bits = sb.blkszbits as u32 + (chunkformat & CHUNK_FORMAT_BLKBITS_MASK) as u32;
                AddrState::Chunked {
                    format: chunkformat,
                    bits,
                }
            }
        };

        // AUTO-TODO(G-Z02): The compressed data path is deferred as a whole
        // under archive A, yet this parsing remains a parity bookkeeping
        // duty — a compressed inode reports st_blocks from the on-disk
        // compressed_blocks count (the round_up(i_size) fallback covers
        // every non-compressed layout). Merge it back into the data path
        // when the G-Z01 deferral note is lifted.
        let nblks: u32 = if datalayout.is_compressed() { iu } else { 0 };
        let nr_sectors: usize = if nblks != 0 {
            // The compressed-block count in 512-byte sectors (4k
            // example: << 3). The blkszbits - 9 underflow is
            // structurally prevented by the mount-time door (G-M08),
            // not re-checked here.
            (nblks as usize) << (sb.blkszbits as usize - 9)
        } else {
            // The generic caliber: round_up(size, block_size) >> 9
            // (4k example: round_up(size, 4096) >> 9); size = 0
            // yields 0. usize carries it without overflow (the
            // extreme i64::MAX size lands at ~2^54 sectors).
            (size as usize).align_up(sb.block_size()) >> 9
        };

        Ok(Self {
            version: InodeVersion::Compact,
            datalayout,
            kind,
            mode: InodeMode::from_bits_truncate(mode & 0o7777),
            uid: u16::from_le(raw.i_uid) as u32,
            gid: u16::from_le(raw.i_gid) as u32,
            nlink: u16::from_le(raw.i_nlink) as u32,
            size,
            xattr_isize,
            // D10: the compact form carries no own timestamp; the
            // three Metadata times derive from the superblock build
            // time (the same-source derivation, S02 §5.3).
            time: sb.build_time,
            i_u: iu,
            addr_state,
            nr_sectors,
        })
    }
}

/// The extended-form decode: the full I7 → I8 → I10 guard chain over
/// the D6 field accounting.
///
/// Same parameter-form triple and same boundaries as the compact
/// decode above; the form-specific difference is the error face
/// {I7, I8, I10}: the le64 `i_size` domain makes the negative-size
/// guard reachable here only (inode.c:133-137; the ext2 structural
/// precedent is `ext2/inode/mod.rs:316-318`). The guard order is the
/// source execution order (T-001 §9.2): I7 strictly before I8 and
/// the D9 cross-cut — with I7 and I10 both tripping, the first error
/// is I7's, and swapping that order would drift the errno from
/// EUCLEAN to EOPNOTSUPP (the errno-level ordering pin, S06 §2.2).
impl TryFrom<(&RawInodeExtended, DataLayout, &SuperBlock)> for InodeDesc {
    type Error = Error;

    fn try_from(
        (raw, datalayout, sb): (&RawInodeExtended, DataLayout, &SuperBlock),
    ) -> Result<Self> {
        // D6 field decode: pure memory, no error exit; the 9-field
        // E1 ledger (S05 §6) converts each little-endian field
        // exactly once, here.
        let size = u64::from_le(raw.i_size);
        let mode = u16::from_le(raw.i_mode);
        let kind = FileKind::from_raw_i_mode(mode);
        let xattr_isize = xattr_ibody_size(u16::from_le(raw.i_xattr_icount));
        let iu = u32::from_le(raw.i_u);
        let time = super::utils::duration_from_parts(
            u64::from_le(raw.i_mtime),
            u32::from_le(raw.i_mtime_nsec),
        );

        // D7 (I7): negative i_size, extended-only (inode.c:133-137).
        if size > i64::MAX as u64 {
            return_errno_with_message!(Errno::EUCLEAN, "negative i_size");
        }

        // D8 (I8): the bogus-i_mode guard, strictly before the D9
        // cross-cut (inode.c:157-161 ahead of :164-178).
        if matches!(kind, FileKind::Other(_)) {
            return_errno_with_message!(Errno::EUCLEAN, "bogus i_mode");
        }

        // D9: the second, datalayout-driven reading of `iu` — never
        // inside a kind branch (the pathological kind x datalayout
        // combinations are accepted parity behavior, T-003 §1.4).
        let addr_state = match datalayout {
            DataLayout::FlatPlain | DataLayout::FlatInline => AddrState::Flat,
            DataLayout::CompressedFull | DataLayout::CompressedCompact => AddrState::Compressed,
            DataLayout::ChunkBased => {
                // The chunk-info decomposition (S03 §5): `iu as u16`,
                // mechanically proven by the `RawInodeChunkInfo`
                // layout assertions; the reserved half is never read
                // (G5).
                let chunkformat = iu as u16;
                // I10: unknown chunk-format bits, rejected before the
                // `Chunked` materialization (inode.c:170-175).
                if chunkformat & !CHUNK_FORMAT_ALL != 0 {
                    return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported chunk format");
                }
                // inode.c:176-177: the 5-bit chunk-blkbits domain is
                // carried in full, with no upper-bound check.
                let bits = sb.blkszbits as u32 + (chunkformat & CHUNK_FORMAT_BLKBITS_MASK) as u32;
                AddrState::Chunked {
                    format: chunkformat,
                    bits,
                }
            }
        };

        // The G-Z02 deferral note quoted verbatim in the compact body
        // above covers this caliber as well — one marker per tree, the
        // formula itself is per-form.
        let nblks: u32 = if datalayout.is_compressed() { iu } else { 0 };
        let nr_sectors: usize = if nblks != 0 {
            // The compressed-block count in 512-byte sectors (4k
            // example: << 3). The blkszbits - 9 underflow is
            // structurally prevented by the mount-time door (G-M08),
            // not re-checked here.
            (nblks as usize) << (sb.blkszbits as usize - 9)
        } else {
            // The generic caliber: round_up(size, block_size) >> 9
            // (4k example: round_up(size, 4096) >> 9); size = 0
            // yields 0. usize carries it without overflow (the
            // extreme i64::MAX size lands at ~2^54 sectors).
            (size as usize).align_up(sb.block_size()) >> 9
        };

        Ok(Self {
            version: InodeVersion::Extended,
            datalayout,
            kind,
            mode: InodeMode::from_bits_truncate(mode & 0o7777),
            uid: u32::from_le(raw.i_uid),
            gid: u32::from_le(raw.i_gid),
            nlink: u32::from_le(raw.i_nlink),
            size,
            xattr_isize,
            time,
            i_u: iu,
            addr_state,
            nr_sectors,
        })
    }
}

// ---------------------------------------------------------------------------
// The decode entry (T-022 S08; sequence `docs/T-011/S05/index.md` §1.1,
// read contract `docs/T-011/S07/index.md` §3–§4, D-domain table
// `docs/T-011/analysis.md` §5.2).
// ---------------------------------------------------------------------------

/// Decodes the on-disk inode at byte offset `iloc` into an
/// `InodeDesc` — steps 2–5 of the five-step decode sequence, in the
/// source execution order (`docs/T-001/analysis.md` §9.2; behavioral
/// baseline inode.c:27-197):
///
/// - Step 2, the 2-byte pre-read `read_val::<u16>(iloc)`: the single
///   point where `i_format` enters the decode surface, and its
///   single `u16::from_le` (E1 — the `TryFrom` conversions re-derive
///   nothing from it). Read errors propagate unchanged (C2): `?`
///   passthrough with no FS-layer message, no errno folding — a read
///   past the device end surfaces the aster boundary errno EINVAL,
///   a registered I/O-model known-diff against linux's EIO (RD2),
///   deliberately not simulated here.
/// - Step 3, `parse_i_format`: the I3 → I4 guards plus the typed
///   pair. The discrimination read set is exactly the 2 pre-read
///   bytes — a malformed value returns before any full-record read,
///   any suffix read, or the cross-block region is touched.
/// - Step 4, the version dispatch: one single-point read of the
///   selected record straight at `iloc`. The extended record is
///   *always* fetched by the one 64-byte `read_val` (RD0):
///   cross-block fetch is built into the byte-stream primitive (the
///   device address space knows no block boundaries), so the
///   source-side boundary test and two-segment splice (inode.c:72-96)
///   exist as no code here; the compact record never crosses a block
///   (32 always divides the block size). Fixture note for the
///   regression family (T-027, RD1): on a 4k volume the unique
///   cross-block slot is ofs = 4064 (nid ≡ 127 mod 128), while
///   ofs = 4032 (nid ≡ 126) is the exact-block-boundary corner and
///   does *not* cross — the landed single-form read treats both
///   slots identically.
/// - Step 5, `InodeDesc::try_from((&raw, datalayout, sb))`: the pure
///   in-memory conversion carrying the I7/I8/I10 guards (T-022 S07).
///
/// Step 1 — the iloc location
/// `(meta_blkaddr << blkszbits) + (nid << ISLOT_BITS)` — and the
/// iget cache live in `Erofs::iget` (`fs.rs`, landed with T-023
/// S04); this entry starts from the already-computed byte offset.
/// No decoder-side caching (RD3): every call reads the device
/// directly, so repeat reads of one nid are the iget caller's
/// business.
// I6 (kmalloc ENOMEM) unreachable: no heap allocation on this path (F4/G-M21)
//
// Live since T-023 S04: called by `Erofs::iget` (`fs.rs`), which
// computes the `iloc` argument (step 1 of the five-step sequence).
// The bridging `expect` was removed when the first consumer landed.
pub(super) fn read_inode_desc(
    device: &dyn BlockDevice,
    sb: &SuperBlock,
    iloc: usize,
) -> Result<InodeDesc> {
    // Step 2: the 2-byte pre-read of `i_format` — an I2 read error
    // propagates before any guard runs (the source's first metabuf
    // read, inode.c:45-50, holds the same position).
    let ifmt = u16::from_le(device.read_val::<u16>(iloc)?);
    // Step 3: the one-shot I3 -> I4 validation plus the typed pair;
    // on a malformed value the read set stays at the 2 pre-read
    // bytes.
    let (version, datalayout) = parse_i_format(ifmt)?;
    // Step 4: the version dispatch — one single-point read per form,
    // straight at `iloc` (RD0: no boundary test, no two-segment
    // splice, either form).
    match version {
        InodeVersion::Compact => {
            let raw = device.read_val::<RawInodeCompact>(iloc)?;
            InodeDesc::try_from((&raw, datalayout, sb))
        }
        InodeVersion::Extended => {
            let raw = device.read_val::<RawInodeExtended>(iloc)?;
            InodeDesc::try_from((&raw, datalayout, sb))
        }
    }
}
