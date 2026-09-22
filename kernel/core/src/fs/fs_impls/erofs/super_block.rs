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
//! Bring-up state: both halves have landed — the disk side
//! (`RawSuperBlock`, `RawDeviceSlot`, the compression config record
//! headers, the feature bitflag sets, the cross-file constants, the
//! 26 + 6 layout assertions) and the mirror side (the decoded
//! `SuperBlock`, the pure `From<RawSuperBlock>` conversion, the
//! checksum verification, and the predicate/accessor surface). The
//! mount-time validation order (`read_superblock` in `fs.rs`,
//! T-023 S03) consumes the mirror: every V-door predicate, the
//! checksum helper, and the magic/dirblkbits/u1 fields are live
//! through it. Every later consumer family has since landed too —
//! the root-inode/geometry fields with T-023, the xattr family
//! (the bloom bit + reservation byte since T-026 S04, the prefix
//! count/start since S05, `xattr_blkaddr` since S03) — so the only
//! `#[expect(dead_code)]` residue is the two permanent cut-domain
//! groups: the compression config record headers (G-Z01 revival)
//! and the `volume_name()` view accessor (no consumer yet).
//!
//! Boundary: field-level decoding and predicates only — the assembly
//! and validation *order* decisions belong solely to
//! `fs.rs::Erofs::open`.

use core::mem::offset_of;

use aster_util::fixed_str::FixedCStr;
use ostd::const_assert;

use super::prelude::*;

// ---------------------------------------------------------------------------
// Cross-file on-disk constants (T-010 §3.2; referenced by path at their
// consumption sites, never forwarded through the prelude).
// ---------------------------------------------------------------------------

/// The erofs superblock is located at byte 1024 from the beginning of
/// the device (`EROFS_SUPER_OFFSET`, erofs_fs.h:12; consumed at
/// super.c:290,323).
// Live since T-022 S03: the mirror-side `checksummed_len()` consumes
// it — an `#[expect(dead_code)]` method is a dead-code-analysis root,
// and its references count. The mount-time superblock read (`fs.rs`,
// T-023) joins later; the bridging `expect` was removed when the
// first consumer landed.
pub(super) const SUPER_OFFSET: usize = 1024;

/// The erofs V1 magic number
/// (`linux/include/uapi/linux/magic.h:23`; consumed at super.c:292).
// Live since T-023 S03: the V2 magic door of `read_superblock`
// (`fs.rs`) compares against it; the statfs f_type face joined with
// T-023 S06 (`Erofs::vfs_super_block`, SF1). The bridging `expect`
// was removed when the first consumer landed.
pub(super) const SUPER_MAGIC_V1: u32 = 0xE0F5E1E2;

/// The maximum length of an erofs name (`EROFS_NAME_LEN`,
/// erofs_fs.h:289) — the shared upper bound of dirent names and xattr
/// names.
// Hosted here (XA2) because the consumers, `inode/dir.rs` and
// `xattr.rs`, are mutually independent in the module DAG.
// Live since T-023 S06: the statfs namelen face of
// `Erofs::vfs_super_block` (`fs.rs`) reads it (SF7); the namei
// consumer (T-024) and the xattr consumers — the P4 record-domain
// bound and the list name scratch (T-026 S05/S07) — read it
// through the same constant. The bridging `expect` was removed
// when the first consumer landed.
pub(super) const NAME_LEN: usize = 255;

/// The size of one superblock extension slot in bytes
/// (`EROFS_SB_EXTSLOT_SIZE`, erofs_fs.h:44).
// Live since T-022 S03: consumed by the mirror-side `sb_size()` — an
// `#[expect(dead_code)]` method is a dead-code-analysis root, and its
// references count. The bridging `expect` was removed when that
// consumer landed.
const SB_EXTSLOT_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// Mount-validation geometry constants: the V3 blkszbits bounds, the
// 4k-only scope gate, and the PAGE-derived superblock-region bound
// (design: `docs/T-012/S02/index.md` §8, folded into
// `docs/T-012/analysis.md` §2.6). Consumers: `read_superblock` in
// `fs.rs` — the validation order belongs solely there (T-010 §1.4
// rule 4); this file supplies the judgement inputs only. Liveness:
// born consumed by `read_superblock` (live since T-023 S03), an
// `#[expect(dead_code)]` dead-code-analysis root whose references
// count — no bridging `expect` needed.
// ---------------------------------------------------------------------------

/// The minimum blkszbits the mount validation accepts
/// (`super.c:297-301`, the literal 9 lower arm). V3a lower bound.
pub(super) const BLKSZBITS_MIN: u8 = 9;

/// The maximum blkszbits the mount validation accepts — PAGE-derived
/// single source: the `super.c:298` upper arm is
/// `blkszbits > PAGE_SHIFT`. Exported from the framework page size so
/// a page-size change re-derives the bound instead of silently
/// diverging (design decision D4). V3a upper bound.
pub(super) const BLKSZBITS_MAX: u8 = PAGE_SIZE.trailing_zeros() as u8;

/// The only blkszbits this tree mounts: 4k. A literal on purpose —
/// 4k-only is a scope property (AR-S01-1), not a page property: on a
/// 64K-page arch the scope still means 12, so a PAGE-derived form
/// would drift with the architecture (design decision D4). V3b gate.
pub(super) const SUPPORTED_BLKSZBITS: u8 = 12;

/// The superblock region upper bound, `PAGE_SIZE - SUPER_OFFSET`
/// (= 3072). Dual duty (design decisions D4/D5): the V7 `sb_size`
/// upper bound — PAGE-derived on purpose; under the 4k-only gate it
/// coincides with a block-derived bound, which is exactly why the
/// block form must not be substituted (the 512B/1k/2k rows stay
/// dormant, not deleted) — and the V5 stack-buffer capacity, which is
/// also the checksummed-region upper bound for blkszbits <= PAGE_SHIFT.
pub(super) const SUPER_REGION_MAX: usize = PAGE_SIZE - SUPER_OFFSET;

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
        // Live since T-026 S04: tested through `feature_compat()` by
        // the bloom effectivity gate (`xattr.rs`) at every get entry.
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
        /// Long xattr name prefixes. G-X04: deliberately NOT consumed
        /// anywhere — the prefix-table load gates on
        /// `xattr_prefix_count` alone (bit set + count 0 = a P1
        /// no-op mount; bit clear + count > 0 loads the table all the
        /// same); the bit's only face is V6 known-bit membership
        /// (accepted, never rejected, never acted on).
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
/// Pod revival (T-023, archive A / AR-S01-4 F): the flatdev half of
/// the device scan landed and reads slots one by one with `read_val`
/// at `devt_slotoff × DEVT_SLOT_SIZE + i × 128` (the locating formula
/// this structure was registered for), so it enters a read path and
/// derives `Pod` per the A3 rule — repr(C) size 128 / align 4, four
/// fields explicitly filling the layout with no padding. The flatdev
/// guards skip tag handling and device opening (super.c:171-205 are
/// guarded by `!flatdev`): the tag is neither read nor validated
/// (MD4), and blocks/mapped_blkaddr are taken as-is (MD13). Still no
/// mirror structure: the flatdev projection (`DeviceSlot` in `fs.rs`)
/// copies the two consumed fields out at the read site, where the
/// single `from_le` of each also lives (E1 read-site conversion, new
/// with T-023).
// No deadness attribute (and never an `#[allow]`: the workspace bans
// allow attributes, clippy::allow_attributes, T-010 §3.3): like
// `RawSuperBlock` above, the type is kept live in every cfg by the
// permanent `const_assert!` anchors below, so an `expect(dead_code)`
// would only be reported unfulfilled.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
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
// Live since T-023 S02: the flatdev slot loop of `scan_devices`
// (`fs.rs`) steps through the slot area in units of this constant —
// the device-table locating formula it was registered for; `size_of`
// keeps it same-sourced with the layout assertions below (C5). The
// bridging `expect` was removed when the first consumer landed.
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

// ---------------------------------------------------------------------------
// In-memory mirror: SuperBlock, the pure decode, and the predicate
// surface (SB3/SB4/SB5, `docs/T-011/S02/index.md` §5; conversion table
// §5.2, predicate surface §5.5, from_le ledger §5.6).
// ---------------------------------------------------------------------------

/// Validated in-memory mirror of the on-disk superblock (SB4/SB5).
///
/// The conversion point is the pure `From<RawSuperBlock>` below: no
/// validation, no error arm, no ordering — every mount-time gate
/// (magic, blkszbits bounds, dirblkbits, checksum trigger and value,
/// unknown incompat bits, sb_size bound, volume-name NIL, the
/// V-series doors) is *supplied* here as a predicate or accessor and
/// *sequenced* solely by `fs.rs::Erofs::open` (T-023). Fields are
/// `pub(super)` for direct family reads; derived values and
/// judgements are methods.
///
/// Carries all 22 semantic fields of the 24 on-disk fields —
/// `checksum` lives only at the byte layer, inside the checksum
/// verification helper, and `reserved2` is read-but-not-checked
/// (G5) — with the two build timestamp fields collapsed into the
/// single `build_time: Duration`: 21 fields in total.
///
/// # Field liveness (dead-code ledger)
///
/// The `From` conversion *writes* every field but reads none, and the
/// derived `Clone`/`Copy`/`Debug` impls are intentionally ignored by
/// dead-code analysis, so a mirror field is only live once live code
/// reads it. Fields consumed through accessors (`blkszbits`,
/// `sb_extslots`, `feature_compat`, `feature_incompat`,
/// `volume_name`) follow their accessors' liveness — an item
/// carrying an `expect` is a dead-code-analysis root, so its reads
/// count, and an accessor consumed by the mount validation order
/// (`read_superblock` in `fs.rs`, live since T-023 S03) keeps its
/// field live without any attribute. Every other field carried
/// its own `#[expect(dead_code)]` with its first consumer
/// annotated: the `expect` fired `unfulfilled` the moment that
/// consumer landed, which was the removal prompt (the cut-domain
/// pair additionally carried its SB5 revival note). The ledger is
/// closed — the xattr family completed the last field wave
/// (T-026 S03–S05), every mirror field is live, and the module's
/// residual expects (the compression config record headers, the
/// `volume_name()` accessor) are not mirror fields. The design
/// sketch marked only the cut-domain pair with a deadness
/// attribute; the landed form generalized it to every
/// not-yet-read field, for the same reason S01 replaced
/// `#[allow]` with `#[expect]` — the workspace bans allow
/// attributes, and the `expect` doubles as the revival alarm.
#[derive(Clone, Copy, Debug)]
pub(super) struct SuperBlock {
    /// The file system magic number (host order; the `From` body is
    /// its single `from_le`).
    // Live since T-023 S03: the V2 magic door of `read_superblock`
    // (`fs.rs`) reads it (EINVAL on mismatch). The bridging `expect`
    // was removed when the first consumer landed.
    pub(super) magic: u32,
    /// Compatible feature bits, host order; decoded by the
    /// `feature_compat()` accessor. Unknown compat bits are silently
    /// accepted (G4) — no unknown-compat door exists anywhere.
    pub(super) feature_compat: u32,
    /// The filesystem block size as a bit shift (`1 << blkszbits`);
    /// read directly (u8, no endianness). The bounds door (G-M08:
    /// outside 9..=PAGE_SHIFT → EINVAL) is mount-time (T-023).
    pub(super) blkszbits: u8,
    /// The number of 16-byte superblock extension slots; consumed by
    /// `sb_size()`. The V7 upper-bound door is mount-time (T-023).
    pub(super) sb_extslots: u8,
    /// The nid of the root directory inode (host order).
    // Live since T-023 S04: `Erofs::root_inode` (`fs.rs`) reads it —
    // `iget(ErofsNid::from(sb.root_nid))`, the le16 zero-extended
    // with no range check (Linux has none). The bridging `expect`
    // was removed when the first consumer landed.
    pub(super) root_nid: u16,
    /// The total number of valid inodes (host order).
    // Live since T-023 S06: the statfs ffree face of
    // `Erofs::vfs_super_block` (`fs.rs`) consumes it
    // (`u64::MAX - inos`, super.c:994). (The T-011/S02 field table
    // named `f_files` — loose wording corrected by the S06 design:
    // f_files is the constant ULLONG_MAX, inos feeds ffree.) The
    // bridging `expect` was removed when the first consumer landed.
    pub(super) inos: u64,
    /// The compact-inode time derivation source, as a single
    /// `Duration` decoded through `utils::duration_from_parts` (ID1):
    /// the seconds field carries the full le64 domain unchanged (F6;
    /// the `as i64` truncation happens at the statx exit), and a
    /// malformed nsec >= 1e9 normalizes through the carrier — the
    /// F6n known-diff, reached only from malformed images.
    // Live since T-022 S07: read by the compact-inode D10 decode of
    // the inode TryFrom (`time: sb.build_time`; the T-024 handle
    // ctime derives through the same mirror field — D10
    // three-times-one-field). The bridging `expect` was removed when
    // the first consumer landed.
    pub(super) build_time: Duration,
    /// The total number of blocks (host order), the statfs basis.
    // Live since T-023 S02: `scan_devices` (`fs.rs`) seeds its u64
    // `total_blocks` accumulator from this mirror field
    // (`u64::from(sb.blocks)`, the primary-device block count); the
    // statfs face consumes that sum through `DeviceTable::
    // total_blocks()` (single source). The bridging `expect` was
    // removed when the first consumer landed.
    pub(super) blocks: u32,
    /// The start block address of the metadata area (host order).
    // Live since T-023 S04: the iloc formula of `Erofs::iget`
    // (`fs.rs`) consumes the mirror field
    // (`(meta_blkaddr << blkszbits) + (nid << ISLOT_BITS)`). The
    // bridging `expect` was removed when the first consumer landed.
    pub(super) meta_blkaddr: u32,
    /// The start block address of the shared xattr area (host order).
    // Live since T-026 S03: the shared-xattr walk base —
    // `SharedEntryWalk::new` (`xattr.rs`) computes `xattr_blkaddr ×
    // block_size`, the base half of read point #15; this is the
    // field's only runtime consumer (F50), and by the X25 negative
    // fact no value-domain check runs on it. The bridging `expect`
    // was removed when the first consumer landed.
    pub(super) xattr_blkaddr: u32,
    /// The 128-bit volume UUID (byte array, read as-is).
    // Live since T-023 S06: the fsid branch discriminator of
    // `Erofs::vfs_super_block` (`fs.rs`) reads it — the all-zero
    // test picks the device-encoded branch (SF9), any other value
    // the XOR fold (SF8). The bridging `expect` was removed when
    // the first consumer landed.
    pub(super) uuid: [u8; 16],
    /// The volume name, as read off disk (byte array; not yet
    /// NUL-checked). The NIL door and the decoded view are the two
    /// accessors below — the door must run first (T-023).
    pub(super) volume_name: [u8; 16],
    /// Incompatible feature bits, host order; decoded by the
    /// `feature_incompat()` accessor, gated by
    /// `has_unknown_incompat()`.
    pub(super) feature_incompat: u32,
    /// The C union `u1` (erofs_fs.h:73-78), carried as the minimal
    /// common width integer (U1) with its two readings discriminated
    /// by the consumer: `available_compr_algs` (the algorithm bitmap,
    /// LZ4=0/LZMA=1/DEFLATE=2/ZSTD=3) when `COMPR_CFGS` is set,
    /// otherwise `lz4_max_distance` (the legacy LZ4 sliding window).
    /// The mirror stores the host-order bits only; reading
    /// discrimination is mount-time and compression-domain business.
    // Live since T-023 S03: the V9 compression-cfg guard of
    // `read_superblock` (`fs.rs`) tests the zero condition (u1 != 0
    // -> EOPNOTSUPP, layer 1 of the compression rejection chain); the
    // COMPR_CFGS algorithm-config records join with the G-Z01
    // revival. The bridging `expect` was removed when the first
    // consumer landed.
    pub(super) u1: u16,
    /// The number of devices besides the primary device (host order).
    // Live since T-023 S02: the V10 device scan (`scan_devices`,
    // `fs.rs`) reads this mirror field as the on-disk count (`ondisk`,
    // gated by DEVICE_TABLE) for the count check and the flatdev slot
    // loop. The bridging `expect` was removed when the first consumer
    // landed.
    pub(super) extra_devices: u16,
    /// The device table start offset, in `DEVT_SLOT_SIZE` units (host
    /// order). Cut-domain registration (SB5) superseded: the flatdev
    /// half of the device scan landed with T-023 (archive A,
    /// AR-S01-4 F) and consumes this offset through the device-table
    /// locating formula (`devt_slotoff × DEVT_SLOT_SIZE`); the
    /// empty-tag door (super.c:171-175) stays unreachable — flatdev
    /// never validates tags (MD4).
    // Live since T-023 S02: `scan_devices` (`fs.rs`) computes the slot
    // area base from this mirror field. The bridging `expect` was
    // removed when the first consumer landed.
    pub(super) devt_slotoff: u16,
    /// The directory block size in bit shift; non-zero is a
    /// mount-time error (T-023).
    // Live since T-023 S03: the V4 dirblkbits door of
    // `read_superblock` (`fs.rs`) rejects non-zero with EINVAL. The
    // bridging `expect` was removed when the first consumer landed.
    pub(super) dirblkbits: u8,
    /// The number of long xattr name prefixes; read directly (u8).
    // Live since T-026 S05: the prefix-table load
    // (`load_xattr_prefixes`, `xattr.rs`) consumes it as the record
    // count — the load's ONLY gate (P1: count == 0 exits before any
    // I/O; no incompat-bit cross-check exists, G-X04). The bridging
    // `expect` was removed when the first consumer landed.
    pub(super) xattr_prefix_count: u8,
    /// The start of the long xattr name prefix area (host order).
    // Live since T-026 S05: the prefix-table load (`xattr.rs`)
    // computes the record-stream base as this value << 2 — a 4-byte
    // unit shift, deliberately NOT the erofs_pos block unit (unlike
    // the #15 base of the shared-xattr walk); no value-domain check
    // (an out-of-range start surfaces as the first record's channel
    // error). The bridging `expect` was removed when the first
    // consumer landed.
    pub(super) xattr_prefix_start: u32,
    /// The nid of the special packed inode (fragments; host order).
    // Live since T-023 S05: the F10 door of `Erofs::open` (`fs.rs`)
    // pairs it with the FRAGMENTS bit and igets it; the resident
    // counterpart linux keeps (sbi->packed_inode) deliberately does
    // not exist — identity lives in the inode cache. The bridging
    // `expect` was removed when the first consumer landed.
    pub(super) packed_nid: u64,
    /// The xattr name filter reservation byte; the bloom filter is
    /// effective only when this is zero (read directly, u8).
    // Live since T-026 S04: the bloom effectivity gate
    // (`xattr_filter_active`, `xattr.rs`) reads it as the second half
    // of the per-get-entry predicate (xattr.c:401) — a pure gate
    // input with zero value-domain judgement (a non-zero value was
    // accepted at mount and only switches the gate off, never a
    // rejection). The bridging `expect` was removed when the first
    // consumer landed.
    pub(super) xattr_filter_reserved: u8,
}

/// Pure field decode: no validation, no error arm, no ordering (SB3).
///
/// The single E1 conversion point for the 15 little-endian superblock
/// fields (each `from_le` exactly once, S02 §5.6); `u8` fields and
/// byte arrays are read directly; `checksum` is deliberately not
/// converted here — its single `from_le` lives in
/// `verify_superblock_checksum`, the other conversion point. The two
/// build
/// timestamp fields collapse through `utils::duration_from_parts`,
/// the ID1 single source shared with the inode `time` decode.
impl From<RawSuperBlock> for SuperBlock {
    fn from(raw: RawSuperBlock) -> Self {
        Self {
            magic: u32::from_le(raw.magic),
            feature_compat: u32::from_le(raw.feature_compat),
            blkszbits: raw.blkszbits,
            sb_extslots: raw.sb_extslots,
            root_nid: u16::from_le(raw.root_nid),
            inos: u64::from_le(raw.inos),
            build_time: super::utils::duration_from_parts(
                u64::from_le(raw.build_time),
                u32::from_le(raw.build_time_nsec),
            ),
            blocks: u32::from_le(raw.blocks),
            meta_blkaddr: u32::from_le(raw.meta_blkaddr),
            xattr_blkaddr: u32::from_le(raw.xattr_blkaddr),
            uuid: raw.uuid,
            volume_name: raw.volume_name,
            feature_incompat: u32::from_le(raw.feature_incompat),
            u1: u16::from_le(raw.u1),
            extra_devices: u16::from_le(raw.extra_devices),
            devt_slotoff: u16::from_le(raw.devt_slotoff),
            dirblkbits: raw.dirblkbits,
            xattr_prefix_count: raw.xattr_prefix_count,
            xattr_prefix_start: u32::from_le(raw.xattr_prefix_start),
            packed_nid: u64::from_le(raw.packed_nid),
            xattr_filter_reserved: raw.xattr_filter_reserved,
        }
    }
}

impl SuperBlock {
    /// Returns the file system block size, in the general form
    /// `1 << blkszbits` (never a 4096 literal). The blkszbits bounds
    /// door (G-M08) is mount-time (T-023) and is not re-checked here:
    /// the decode layer supplies the formula, the mount layer
    /// guarantees the domain it is evaluated over.
    // Live since T-022 S07: consumed by the D12 nr_sectors decode of
    // the inode TryFrom (`align_up(sb.block_size())`); the
    // mount-time geometry and every later read site below the handle
    // (T-023+) join through the same accessor — all read positions
    // are mirror-driven per RD3. The bridging `expect` was removed
    // when the first consumer landed.
    pub(super) fn block_size(&self) -> usize {
        1 << self.blkszbits
    }

    /// Returns the on-disk superblock size: the fixed 128-byte record
    /// plus `sb_extslots` 16-byte extension slots. The base is
    /// `size_of::<RawSuperBlock>()`, same-sourced with the layout
    /// assertions (C5); the slot unit is `SB_EXTSLOT_SIZE`. The V7
    /// upper-bound door (sb_size > PAGE_SIZE − SUPER_OFFSET → EINVAL)
    /// is mount-time (T-023).
    // Live since T-023 S03: the V7 door of `read_superblock` (`fs.rs`)
    // bounds `sb_size()` by `SUPER_REGION_MAX`; the volume-level
    // metadata record area start joins with the assembly face of this
    // task. The bridging `expect` was removed when the first consumer
    // landed.
    pub(super) fn sb_size(&self) -> usize {
        size_of::<RawSuperBlock>() + SB_EXTSLOT_SIZE * self.sb_extslots as usize
    }

    /// Returns the compatible feature set, decoded with
    /// `from_bits_truncate`: linux has no unknown-compat-bit check
    /// (super.c:307), so unknown bits are silently accepted —
    /// dropped by the truncation without any rejection (G4).
    // Live since T-023 S03: the V5 checksum trigger of
    // `read_superblock` (`fs.rs`) tests SB_CHKSUM through this
    // accessor; the XATTR_FILTER bloom gate half joined with T-026
    // S04 (`xattr_filter_active`, `xattr.rs`, reads it at every get
    // entry). The bridging `expect` was removed when the first
    // consumer landed.
    pub(super) fn feature_compat(&self) -> FeatureCompatSet {
        FeatureCompatSet::from_bits_truncate(self.feature_compat)
    }

    /// Returns the incompatible feature set, decoded with
    /// `from_bits_truncate` — meaningful only behind the unknown-bit
    /// door, which the mount-time sequence must run first (T-023):
    /// after that door, truncation loses nothing.
    // Live since T-023 S02: `scan_devices` (`fs.rs`) gates the on-disk
    // extra-device count on `DEVICE_TABLE` through this accessor; the
    // remaining mount-time bit judgements (the unknown-bit door,
    // COMPR_CFGS, ZTAILPACKING) join with the read_superblock step.
    // The bridging `expect` was removed when the first consumer
    // landed.
    pub(super) fn feature_incompat(&self) -> FeatureIncompatSet {
        FeatureIncompatSet::from_bits_truncate(self.feature_incompat)
    }

    /// Returns whether any unknown incompatible feature bit is set.
    /// The mask is the union of the known bits and cannot shrink
    /// (G3); `ext2/super_block.rs:245-248` is the structural
    /// precedent. The EINVAL door itself is mount-time (T-023,
    /// super.c:315-320).
    // Live since T-023 S03: the V6 unknown-incompat door of
    // `read_superblock` (`fs.rs`) consumes it. The bridging `expect`
    // was removed when the first consumer landed.
    pub(super) fn has_unknown_incompat(&self) -> bool {
        self.feature_incompat & !FeatureIncompatSet::all().bits() != 0
    }

    /// Returns whether `volume_name` contains a NUL byte within its
    /// 16 bytes. The NIL door (no NUL → EUCLEAN, the mapping of the
    /// linux EFSCORRUPTED, super.c:346-352) is mount-time (T-023).
    // Live since T-023 S03: the V8 NIL door of `read_superblock`
    // (`fs.rs`) consumes it. The bridging `expect` was removed when
    // the first consumer landed.
    pub(super) fn volume_name_is_nul_terminated(&self) -> bool {
        self.volume_name.contains(&0)
    }

    /// Returns the volume name as a NUL-terminated fixed string.
    ///
    /// Silently truncates when no NUL is present
    /// (`FixedCStr::from_bytes_until_nul` clamps at the first NUL or
    /// the end of the 16 bytes), so the NIL door must run *before*
    /// this accessor is consulted — an ordering constraint owned by
    /// the mount-time sequence (T-023).
    // No consumer inside T-023: the V8 door reads the *predicate*
    // above, not this accessor. Expectation corrected by the
    // T-023/S08 expects audit (the sketch note named a mount-time
    // consumer that the final design never landed); the first real
    // consumer is post-T-023 (mount logging / a future domain) —
    // remove the `expect` when it lands.
    #[expect(dead_code)]
    pub(super) fn volume_name(&self) -> FixedCStr<16> {
        FixedCStr::from_bytes_until_nul(&self.volume_name)
    }

    /// Returns the length of the checksummed superblock region, in
    /// the general blkszbits form of super.c:57-62: `len = 1 <<
    /// blkszbits`, then `len -= 1024` only when the block size
    /// exceeds `SUPER_OFFSET` (T-001 §3.5 single source). The covered
    /// device interval is `[SUPER_OFFSET, SUPER_OFFSET + len)`; for
    /// blkszbits < 10 the region deliberately extends past the end of
    /// block 0 — a parity fact of the conditional, not a defect.
    // Live since T-023 S03: the V5 arm of `read_superblock` (`fs.rs`)
    // reads exactly this many bytes at SUPER_OFFSET into its stack
    // buffer before handing them to `verify_superblock_checksum`.
    // The bridging `expect` was removed when the first consumer
    // landed.
    pub(super) fn checksummed_len(&self) -> usize {
        let block_size = 1 << self.blkszbits;
        if block_size > SUPER_OFFSET {
            block_size - SUPER_OFFSET
        } else {
            block_size
        }
    }
}

/// Verifies the superblock checksum over `region` — the bytes the
/// caller read over `[SUPER_OFFSET, SUPER_OFFSET +
/// SuperBlock::checksummed_len())`; the helper CRCs over exactly
/// what it is given, so the region length is a caller contract
/// pinned by `checksummed_len`'s documentation — against
/// `raw_checksum`, the raw on-disk `checksum` field value.
///
/// Zeroes the checksum field within the caller's buffer copy (the
/// offsets are the same-sourced layout anchors, C5 — the zeroing
/// touches only the in-memory copy, never the device; this is the
/// kmemdup-and-clear of super.c:64-71 without a heap allocation),
/// then compares `crc32c(!0, region)` with the disk value. The single
/// E1 conversion of `checksum` happens here. The trigger bit
/// (`FeatureCompatSet::SB_CHKSUM`), the failure errno (EBADMSG,
/// "invalid checksum"), and the call position in the door sequence
/// belong to the mount-time sequence (T-023).
// Live since T-023 S03: the V5 arm of `read_superblock` (`fs.rs`)
// feeds it the freshly read coverage interval and `raw.checksum`.
// The bridging `expect` was removed when the first consumer landed.
pub(super) fn verify_superblock_checksum(region: &mut [u8], raw_checksum: u32) -> bool {
    region[offset_of!(RawSuperBlock, checksum)..offset_of!(RawSuperBlock, feature_compat)].fill(0);
    super::utils::crc32c(!0, region) == u32::from_le(raw_checksum)
}
