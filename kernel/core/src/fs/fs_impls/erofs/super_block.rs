// SPDX-License-Identifier: MPL-2.0

//! On-disk erofs superblock: decoding, validation, and geometry.
//!
//! This module owns the raw on-disk layout (`#[repr(C)]`, anchored to
//! `linux/fs/erofs/erofs_fs.h`), the validated in-memory mirror, the
//! feature-bit predicates, the superblock checksum verification
//! (consuming `utils::crc32c` over the checksum interval — the
//! interval formula lives here, not in `utils`), and the cross-file
//! on-disk constants (`SUPER_OFFSET`, `SUPER_MAGIC_V1`, `NAME_LEN`,
//! and the compat/incompat bitflag sets).
//!
//! Bring-up state: the disk side has landed — `RawSuperBlock`,
//! `RawDeviceSlot`, the compression config record headers (archive-A
//! registration), the feature bitflag sets, the cross-file constants,
//! and the 26 + 6 layout assertions. The mirror side — the decoded
//! `SuperBlock`, the pure `From<RawSuperBlock>` conversion, the
//! checksum verification, and the predicate/accessor surface — lands
//! with the same task; the mount-time validation sequence with T-023.
//! Until then the `SuperBlock` at the bottom remains the minimal type
//! shell required by the `Erofs` handle.
//!
//! Boundary: field-level decoding and predicates only — the assembly
//! and validation *order* decisions belong solely to
//! `fs.rs::Erofs::open`.

use core::mem::offset_of;

use ostd::const_assert;

use super::prelude::*;

// ---------------------------------------------------------------------------
// Cross-file on-disk constants (T-010 §3.2; referenced by path at their
// consumption sites, never forwarded through the prelude).
// ---------------------------------------------------------------------------

/// The erofs superblock is located at byte 1024 from the beginning of
/// the device (`EROFS_SUPER_OFFSET`, erofs_fs.h:12; consumed at
/// super.c:290,323).
// First consumers: the mount-time superblock read (`fs.rs`, T-023) and
// the mirror-side `sb_size()` upper-bound door. Until then there is no
// live caller — the `expect` below fires the moment one lands, which
// is the prompt to remove it.
#[expect(dead_code)]
pub(super) const SUPER_OFFSET: usize = 1024;

/// The erofs V1 magic number
/// (`linux/include/uapi/linux/magic.h:23`; consumed at super.c:292).
// First consumers: the mount-time magic door (`fs.rs`, T-023) and the
// statfs `f_type` field (`impl_for_vfs/fs.rs`, T-023).
#[expect(dead_code)]
pub(super) const SUPER_MAGIC_V1: u32 = 0xE0F5E1E2;

/// The maximum length of an erofs name (`EROFS_NAME_LEN`,
/// erofs_fs.h:289) — the shared upper bound of dirent names and xattr
/// names.
// Hosted here (XA2) because the two consumers, `inode/dir.rs` and
// `xattr.rs`, are mutually independent in the module DAG; the first
// consumers land with the namei/xattr domains (T-024/T-026).
#[expect(dead_code)]
pub(super) const NAME_LEN: usize = 255;

/// The size of one superblock extension slot in bytes
/// (`EROFS_SB_EXTSLOT_SIZE`, erofs_fs.h:44).
// Consumed by the mirror-side `sb_size()` (= 128 + extslots × 16),
// which lands with the SuperBlock mirror later in this task.
#[expect(dead_code)]
const SB_EXTSLOT_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// Feature bitflag sets (erofs_fs.h:14-42; bit tables single-sourced in
// `docs/T-010/S03/index.md` §2.3).
// ---------------------------------------------------------------------------

bitflags! {
    /// Compatible feature set (`feature_compat`, erofs_fs.h:14-16).
    ///
    /// Unknown compat bits are silently accepted — linux has no
    /// unknown-compat-bit check (super.c:307) — so the mirror-side
    /// accessor decodes with `from_bits_truncate` and never rejects.
    // First consumers: the mirror-side accessors and the SB_CHKSUM
    // verification door (this task's mirror side; mount-time
    // consumption in T-023).
    //
    // No deadness attribute on the set: the bitflags 1.3 expansion
    // writes hand-rolled fmt/bitops trait impls for the type, which
    // the dead-code analysis counts as uses — the set is live by
    // construction in every cfg, so an `expect(dead_code)` here is
    // reported unfulfilled (`unfulfilled_lint_expectations`).
    pub(super) struct FeatureCompatSet: u32 {
        /// The superblock checksum is present and verified at mount
        /// (super.c:308 triggers the crc32c verification).
        const SB_CHKSUM = 1 << 0;
        /// No v6.12 consumer; accepted and ignored (parity by
        /// transcription).
        const MTIME = 1 << 1;
        /// Xattr name filter (bloom); effective only when
        /// `xattr_filter_reserved == 0` (xattr.c:401).
        const XATTR_FILTER = 1 << 2;
    }
}

bitflags! {
    /// Incompatible feature set (`feature_incompat`, erofs_fs.h:22-42).
    ///
    /// Ten linux names over seven distinct on-disk values: the three
    /// same-value pairs are carried as doc aliases on the single
    /// constant — the kernel consumes both meanings simultaneously and
    /// has no mutual-exclusion check, and one constant per bit
    /// excludes the "independent bits" misuse by construction.
    // First consumers: the mirror-side accessors and the unknown-bit
    // door (this task's mirror side; mount-time consumption in T-023).
    //
    // No deadness attribute on the set — same liveness-by-construction
    // rationale as on `FeatureCompatSet` above.
    pub(super) struct FeatureIncompatSet: u32 {
        /// Zero padding (compression domain, decompressor.c:217).
        const ZERO_PADDING = 1 << 0;
        /// Volume-level compression algorithm config records are
        /// present (decompressor.c:473, zmap.c:571). Alias, same value
        /// 0x2: `EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER`.
        const COMPR_CFGS = 1 << 1;
        /// Chunk-based files exist; behavior is decided per inode by
        /// the datalayout, this bit is only a version gate.
        const CHUNKED_FILE = 1 << 2;
        /// The device table is present (scanned at super.c:225).
        /// Alias, same value 0x8:
        /// `EROFS_FEATURE_INCOMPAT_COMPR_HEAD2`.
        const DEVICE_TABLE = 1 << 3;
        /// Ztailpacking; a version gate with no other v6.12 consumer.
        const ZTAILPACKING = 1 << 4;
        /// Fragments (packed inode, initialized at super.c:724).
        /// Alias, same value 0x20: `EROFS_FEATURE_INCOMPAT_DEDUPE`.
        const FRAGMENTS = 1 << 5;
        /// Long xattr name prefixes; behavior follows
        /// `xattr_prefix_count` (T-026).
        const XATTR_PREFIXES = 1 << 6;
    }
}

// ---------------------------------------------------------------------------
// Raw on-disk structures: super block and device slot.
// ---------------------------------------------------------------------------

/// The erofs on-disk superblock (`erofs_super_block`,
/// linux/fs/erofs/erofs_fs.h:55-87; field semantics single-sourced in
/// `docs/T-001/analysis.md` §3.2).
///
/// A single fixed 128-byte layout — the superblock has no
/// compact/extended duality (that is an inode-layout concern) —
/// followed on disk by `sb_extslots × 16` bytes of extension slots.
/// The slot area is a byte range whose content has no v6.12 consumer
/// and is deliberately not modeled as a structure (U3).
///
/// Endianness (E1): every little-endian field is converted exactly
/// once via `uN::from_le` at the mirror-side `From` conversion, except
/// `checksum`, whose single conversion lives in the checksum
/// verification helper; `u8` fields and byte arrays are read directly.
// No deadness attribute: the permanent `const_assert!` layout
// anchors below reference the type — underscore-named const items
// are dead-code-exempt themselves yet still count as uses of the
// referenced types — so the type is live in every cfg and an
// `expect(dead_code)` would only be reported unfulfilled.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct RawSuperBlock {
    /// The file system magic number.
    pub magic: u32, // @0 __le32
    /// crc32c over the superblock region; read by the checksum
    /// verification helper (the other E1 conversion point).
    pub checksum: u32, // @4 __le32
    /// Compatible feature bits (`FeatureCompatSet`); unknown bits are
    /// silently accepted.
    pub feature_compat: u32, // @8 __le32
    /// The filesystem block size as a bit shift (`1 << blkszbits`);
    /// no endianness (u8).
    pub blkszbits: u8, // @12 __u8
    /// The superblock size = 128 + sb_extslots × `SB_EXTSLOT_SIZE`.
    pub sb_extslots: u8, // @13 __u8
    /// The nid of the root directory inode.
    pub root_nid: u16, // @14 __le16
    /// The total number of valid inodes (== f_files - f_favail).
    pub inos: u64, // @16 __le64
    /// The compact-inode time derivation source (seconds part).
    pub build_time: u64, // @24 __le64
    /// The compact-inode time derivation source (nanoseconds part).
    pub build_time_nsec: u32, // @32 __le32
    /// The total number of blocks, used for statfs.
    pub blocks: u32, // @36 __le32
    /// The start block address of the metadata area.
    pub meta_blkaddr: u32, // @40 __le32
    /// The start block address of the shared xattr area.
    pub xattr_blkaddr: u32, // @44 __le32
    /// The 128-bit volume UUID (byte array, read as-is).
    pub uuid: [u8; 16], // @48 __u8[16]
    /// The volume name (NUL-terminated within 16 bytes; the NIL door
    /// is mount-time business).
    pub volume_name: [u8; 16], // @64 __u8[16]
    /// Incompatible feature bits (`FeatureIncompatSet`); unknown bits
    /// are a mount-time error.
    pub feature_incompat: u32, // @80 __le32
    /// The C union `u1` (erofs_fs.h:73-78), carried as the minimal
    /// common width integer (U1: Rust unions are structurally excluded
    /// in the safe-Rust kernel tree). Two readings, discriminated by
    /// the consumer:
    ///
    /// - `EROFS_FEATURE_INCOMPAT_COMPR_CFGS` set:
    ///   `available_compr_algs`, the algorithm bitmap (LZ4=0, LZMA=1,
    ///   DEFLATE=2, ZSTD=3; erofs_fs.h:298-305);
    /// - clear: `lz4_max_distance`, the legacy LZ4 sliding window.
    ///
    /// This structure only stores the bits; reading discrimination is
    /// mount-time and compression-domain business (T-023+).
    pub u1: u16, // @84 __le16
    /// The number of devices besides the primary device.
    pub extra_devices: u16, // @86 __le16
    /// The device table start offset, in `DEVT_SLOT_SIZE` units.
    pub devt_slotoff: u16, // @88 __le16
    /// The directory block size in bit shift (non-zero is a
    /// mount-time error).
    pub dirblkbits: u8, // @90 __u8
    /// The number of long xattr name prefixes.
    pub xattr_prefix_count: u8, // @91 __u8
    /// The start of the long xattr name prefix area.
    pub xattr_prefix_start: u32, // @92 __le32
    /// The nid of the special packed inode (fragments).
    pub packed_nid: u64, // @96 __le64
    /// Reserved for the xattr name filter (the bloom filter is
    /// effective only when this is zero).
    pub xattr_filter_reserved: u8, // @104 __u8
    /// Read-but-not-checked (G5): kept for layout; the mirror does
    /// not carry it.
    pub reserved2: [u8; 23], // @105 __u8[23]
}

// Layout triple and per-field offsets (A1), each anchored to its
// linux/fs/erofs/erofs_fs.h source line; the source-side counterpart
// of the size assertion is BUILD_BUG_ON at erofs_fs.h:442.
const_assert!(size_of::<RawSuperBlock>() == 128); // erofs_fs.h:442
const_assert!(align_of::<RawSuperBlock>() == 8); // le64 members pin the alignment
const_assert!(offset_of!(RawSuperBlock, magic) == 0); // erofs_fs.h:56
const_assert!(offset_of!(RawSuperBlock, checksum) == 4); // erofs_fs.h:57
const_assert!(offset_of!(RawSuperBlock, feature_compat) == 8); // erofs_fs.h:58
const_assert!(offset_of!(RawSuperBlock, blkszbits) == 12); // erofs_fs.h:59
const_assert!(offset_of!(RawSuperBlock, sb_extslots) == 13); // erofs_fs.h:60
const_assert!(offset_of!(RawSuperBlock, root_nid) == 14); // erofs_fs.h:62
const_assert!(offset_of!(RawSuperBlock, inos) == 16); // erofs_fs.h:63
const_assert!(offset_of!(RawSuperBlock, build_time) == 24); // erofs_fs.h:65
const_assert!(offset_of!(RawSuperBlock, build_time_nsec) == 32); // erofs_fs.h:66
const_assert!(offset_of!(RawSuperBlock, blocks) == 36); // erofs_fs.h:67
const_assert!(offset_of!(RawSuperBlock, meta_blkaddr) == 40); // erofs_fs.h:68
const_assert!(offset_of!(RawSuperBlock, xattr_blkaddr) == 44); // erofs_fs.h:69
const_assert!(offset_of!(RawSuperBlock, uuid) == 48); // erofs_fs.h:70
const_assert!(offset_of!(RawSuperBlock, volume_name) == 64); // erofs_fs.h:71
const_assert!(offset_of!(RawSuperBlock, feature_incompat) == 80); // erofs_fs.h:72
const_assert!(offset_of!(RawSuperBlock, u1) == 84); // erofs_fs.h:73-78
const_assert!(offset_of!(RawSuperBlock, extra_devices) == 86); // erofs_fs.h:79
const_assert!(offset_of!(RawSuperBlock, devt_slotoff) == 88); // erofs_fs.h:80
const_assert!(offset_of!(RawSuperBlock, dirblkbits) == 90); // erofs_fs.h:81
const_assert!(offset_of!(RawSuperBlock, xattr_prefix_count) == 91); // erofs_fs.h:82
const_assert!(offset_of!(RawSuperBlock, xattr_prefix_start) == 92); // erofs_fs.h:83
const_assert!(offset_of!(RawSuperBlock, packed_nid) == 96); // erofs_fs.h:84
const_assert!(offset_of!(RawSuperBlock, xattr_filter_reserved) == 104); // erofs_fs.h:85
const_assert!(offset_of!(RawSuperBlock, reserved2) == 105); // erofs_fs.h:86

/// The erofs device table slot (`erofs_deviceslot`,
/// linux/fs/erofs/erofs_fs.h:46-52; field semantics single-sourced in
/// `docs/T-001/analysis.md` §3.4).
///
/// Archive-A registration: the multi-device scan is pruned (G-M14), so
/// this structure never enters a read path yet and derives no `Pod`.
/// Revival comes with the multi-device domain, which takes over the
/// device-table locating formula (`devt_slotoff × DEVT_SLOT_SIZE`), the
/// empty-tag door (super.c:171-175, "empty device tag" → EINVAL), the
/// per-device block accounting, and the `mapped_blkaddr` consumption
/// (T-025 data path); deriving `Pod` and wiring `read_val` happen then.
/// No mirror structure is built now — nothing consumes one.
// No deadness attribute (and never an `#[allow]`: the workspace bans
// allow attributes, clippy::allow_attributes, T-010 §3.3): like
// `RawSuperBlock` above, the type is kept live in every cfg by the
// permanent `const_assert!` anchors below, so an `expect(dead_code)`
// would only be reported unfulfilled.
#[repr(C)]
pub(super) struct RawDeviceSlot {
    /// The device tag (sha256 digest / backend id / doubling as a
    /// path).
    pub tag: [u8; 64], // @0 u8[64]
    /// The total number of blocks of this device.
    pub blocks: u32, // @64 __le32
    /// Blocks of this device are mapped starting at this address.
    pub mapped_blkaddr: u32, // @68 __le32
    /// Reserved; never read (G5).
    pub reserved: [u8; 56], // @72 u8[56]
}

/// The size of one device table slot (`EROFS_DEVT_SLOT_SIZE` =
/// `sizeof(struct erofs_deviceslot)`, erofs_fs.h:52).
// Registered constant: consumed by the device-table locating formula
// when the multi-device domain revives (G-M14); `size_of` keeps it
// same-sourced with the layout assertions below (C5). `#[expect]`
// rather than the sketch's `#[allow]` for the same reason as on
// `RawDeviceSlot`.
#[expect(dead_code)]
pub(super) const DEVT_SLOT_SIZE: usize = size_of::<RawDeviceSlot>(); // = 128

// Layout triple and per-field offsets (A1), anchored to
// linux/fs/erofs/erofs_fs.h:46-52; the source-side counterpart of the
// size assertion is BUILD_BUG_ON at erofs_fs.h:455.
const_assert!(size_of::<RawDeviceSlot>() == 128); // erofs_fs.h:455
const_assert!(align_of::<RawDeviceSlot>() == 4); // le32 members pin the alignment
const_assert!(offset_of!(RawDeviceSlot, tag) == 0); // erofs_fs.h:47
const_assert!(offset_of!(RawDeviceSlot, blocks) == 64); // erofs_fs.h:48
const_assert!(offset_of!(RawDeviceSlot, mapped_blkaddr) == 68); // erofs_fs.h:49
const_assert!(offset_of!(RawDeviceSlot, reserved) == 72); // erofs_fs.h:50

// ---------------------------------------------------------------------------
// Compression config record headers (archive-A registration, SB2).
//
// Payload shapes of the volume-level algorithm-config records carried
// in `erofs_read_metadata` containers (`docs/T-001/analysis.md` §3.6,
// §7.8). They never enter a read path in the archive-A mainline — the
// compressed data path is deferred as a whole — so they derive no
// `Pod`, carry no layout assertions (the source side asserts none
// either, R-c), and are consumed by nothing. Packed: when the revival
// task reads them, it reads by value only, no field references (A3).
// Field validation semantics (size < 14 → EINVAL, the
// max_pclusterblks zero fixup, format checks, windowbits range →
// EOPNOTSUPP, ...) are single-sourced in `docs/T-001/analysis.md`
// §7.8 and belong to the revival task. Revival lands with the G-Z01
// archive-C compression domain, together with its error paths;
// relocating these structures then is the revival task's call.
// (`#[expect(dead_code)]` rather than the sketch's `#[allow]` — the
// workspace bans allow attributes, clippy::allow_attributes,
// T-010 §3.3; unlike the structures above, these headers are
// referenced by no `const_assert!`, so the expectation stays
// fulfilled until the revival.)
// ---------------------------------------------------------------------------

/// The LZ4 config record payload (`z_erofs_lz4_cfgs`,
/// erofs_fs.h:308-312; 14 bytes + a 2-byte length field).
#[expect(dead_code)]
#[repr(C, packed)]
struct RawLz4Cfgs {
    /// The customized sliding window distance.
    max_distance: u16, // @0 __le16
    /// The maximum physical cluster size, in blocks.
    max_pclusterblks: u16, // @2 __le16
    reserved: [u8; 10], // @4 u8[10]
}

/// The LZMA config record payload (`z_erofs_lzma_cfgs`,
/// erofs_fs.h:314-319; 14 bytes + a 2-byte length field).
#[expect(dead_code)]
#[repr(C, packed)]
struct RawLzmaCfgs {
    /// The dictionary size, in bytes.
    dict_size: u32, // @0 __le32
    /// The record format version; zero on disk.
    format: u16, // @4 __le16
    reserved: [u8; 8], // @6 u8[8]
}

/// The DEFLATE config record payload (`z_erofs_deflate_cfgs`,
/// erofs_fs.h:323-327; 6 bytes + a 2-byte length field).
#[expect(dead_code)]
#[repr(C, packed)]
struct RawDeflateCfgs {
    /// The window size exponent, 8..15 for DEFLATE.
    windowbits: u8, // @0 __u8
    reserved: [u8; 5], // @1 u8[5]
}

/// The ZSTD config record payload (`z_erofs_zstd_cfgs`,
/// erofs_fs.h:329-334; 6 bytes + a 2-byte length field).
#[expect(dead_code)]
#[repr(C, packed)]
struct RawZstdCfgs {
    /// The record format version; zero on disk.
    format: u8, // @0 __u8
    /// windowLog minus ZSTD_WINDOWLOG_ABSOLUTEMIN (10).
    windowlog: u8, // @1 __u8
    reserved: [u8; 4], // @2 u8[4]
}

/// Validated in-memory mirror of the on-disk superblock.
///
/// Placeholder form: the real decoded geometry (block size, root nid,
/// feature sets, uuid, volume name) lands with the mirror side later
/// in this task, replacing this shell wholesale.
#[derive(Debug)]
pub(super) struct SuperBlock;
