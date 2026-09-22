// SPDX-License-Identifier: MPL-2.0

//! EROFS checksum and hash primitives (L0 of the erofs dependency DAG).
//!
//! This file is the dependency-free bottom layer of the erofs family
//! (`docs/T-010/analysis.md` §1.4): nothing from the family may leak in
//! here, and nothing here may grow knowledge of erofs on-disk structures —
//! e.g. the superblock checksum *interval* formula belongs to the consumer
//! side (`super_block.rs`), not to these primitives.
//!
//! Two hash primitives and one timestamp helper are provided:
//!
//! - `crc32c`: table-driven CRC32C (Castagnoli polynomial, reflected form)
//!   in pure update form — no final XOR; the seed is the running register.
//! - `xxh32`: one-shot XXH32, a direct transcription of `linux/lib/xxhash.c`
//!   (little-endian 4-byte lanes, wrapping arithmetic throughout, no
//!   streaming interface — the erofs input domain is short suffixes plus
//!   a `u32` seed).
//! - `duration_from_parts`: decode-direction `(secs, nsecs) -> Duration`
//!   conversion with a saturating carry — pure integer arithmetic with
//!   no on-disk knowledge, the single source (ID1) for every erofs
//!   timestamp decode.
//!
//! Upgrade path (S04 D1, `docs/T-010/analysis.md` §4.1): the moment a
//! second consumer outside `fs_impls/erofs` appears, promote the two
//! hash primitives into a dedicated `kernel/libs/` crate following the
//! jhash precedent — a pure move with zero behavior drift.
//!
//! The `#[cfg(ktest)]` suite at the tail of this file locks both
//! primitives against the reference vector tables of
//! `docs/T-010/analysis.md` §4.3 (transcribed verbatim; inputs are
//! regenerated with the LCG rule defined there and cross-checked against
//! fixed head bytes).

// Dead-code ledger (closed at T-026 S04): this module previously
// carried a module-level dead-code expectation (applied to non-ktest
// builds only) whose sole regular-build subject was `xxh32` — no
// caller before the xattr bloom domain. The first regular-build
// caller, the bloom denial predicate in `xattr.rs` (itself a
// dead-code-analysis root under a transitional expect until the get
// entry chain consumed it, T-026 S06), landed with T-026 S04: every
// item here is live in every cfg now, and the module-level
// expectation was removed (keeping it would be reported unfulfilled).
// Earlier liveness: `crc32c` since T-022 S03 (called by the checksum
// verification in `super_block.rs`, a dead-code-analysis root whose
// call counts), and `duration_from_parts` since the live
// `From<RawSuperBlock>` mirror decode.

use core::time::Duration;

/// Reflected CRC32C (Castagnoli) polynomial: 0x1EDC6F41 normal form,
/// 0x82F63B78 reflected form.
const CRC32C_POLYNOMIAL: u32 = 0x82F63B78;

/// Compile-time construction of the 256-entry CRC32C byte table:
/// `table[i]` is the reflected-polynomial remainder of the byte `i` —
/// the standard byte-at-a-time lookup table.
const fn build_crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ CRC32C_POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC32C_TABLE: [u32; 256] = build_crc32c_table();

/// CRC32C (Castagnoli 0x1EDC6F41, reflected 0x82F63B78),
/// table-driven, update-only semantics identical to the kernel's
/// `crc32c(crc, buf, len)` (`linux/lib/libcrc32c.c:38`): `seed` is
/// the running register; the result is NOT xored with `!0`. Erofs
/// callers pass `!0` and compare directly against the on-disk
/// superblock checksum (`linux/fs/erofs/super.c:55-80`).
pub(super) fn crc32c(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for &byte in data {
        crc = CRC32C_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

/// XXH32 primes (`linux/lib/xxhash.c:64-68`).
const PRIME32_1: u32 = 0x9E3779B1;
const PRIME32_2: u32 = 0x85EBCA77;
const PRIME32_3: u32 = 0xC2B2AE3D;
const PRIME32_4: u32 = 0x27D4EB2F;
const PRIME32_5: u32 = 0x165667B1;

/// Reads the little-endian `u32` lane at byte offset `i` (xxHash is a
/// little-endian hash by definition).
fn read_le32(data: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
}

/// `xxh32_round` (`linux/lib/xxhash.c:94-101`):
/// `acc = rotl(acc + lane * P2, 13) * P1`, wrapping throughout.
fn xxh32_round(acc: u32, lane: u32) -> u32 {
    acc.wrapping_add(lane.wrapping_mul(PRIME32_2))
        .rotate_left(13)
        .wrapping_mul(PRIME32_1)
}

/// `XXH32_avalanche` final mixing step (`linux/lib/xxhash.c:143-150`).
fn xxh32_avalanche(hash: u32) -> u32 {
    let mut hash = hash;
    hash ^= hash >> 15;
    hash = hash.wrapping_mul(PRIME32_2);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(PRIME32_3);
    hash ^= hash >> 16;
    hash
}

/// One-shot XXH32, a faithful transcription of `linux/lib/xxhash.c:102-153`.
/// Four-byte lanes are read little-endian; wrapping arithmetic
/// throughout; no streaming interface (erofs input domain is
/// 0..=255-byte suffixes plus a `u32` seed, T-005 §8.1).
pub(super) fn xxh32(data: &[u8], seed: u32) -> u32 {
    let mut h32;

    if data.len() >= 16 {
        let mut v1 = seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2);
        let mut v2 = seed.wrapping_add(PRIME32_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME32_1);

        // The C `do { ... } while (p <= limit)` over 16-byte stripes is
        // exactly the `as_chunks::<16>()` ladder; the leftover is the
        // tail below. (`&[u8; 16]` coerces to the `&[u8]` lane reader.)
        for stripe in data.as_chunks::<16>().0 {
            v1 = xxh32_round(v1, read_le32(stripe, 0));
            v2 = xxh32_round(v2, read_le32(stripe, 4));
            v3 = xxh32_round(v3, read_le32(stripe, 8));
            v4 = xxh32_round(v4, read_le32(stripe, 12));
        }

        h32 = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
    } else {
        h32 = seed.wrapping_add(PRIME32_5);
    }

    h32 = h32.wrapping_add(data.len() as u32);

    // Tail lanes: 4-byte lanes while at least four bytes remain, then
    // single bytes (`linux/lib/xxhash.c:136-142`).
    let mut pos = data.len() / 16 * 16;
    while pos + 4 <= data.len() {
        h32 = h32.wrapping_add(read_le32(data, pos).wrapping_mul(PRIME32_3));
        h32 = h32.rotate_left(17).wrapping_mul(PRIME32_4);
        pos += 4;
    }
    while pos < data.len() {
        h32 = h32.wrapping_add(u32::from(data[pos]).wrapping_mul(PRIME32_5));
        h32 = h32.rotate_left(11).wrapping_mul(PRIME32_1);
        pos += 1;
    }

    xxh32_avalanche(h32)
}

// ---------------------------------------------------------------------------
// Timestamp conversion (ID1, `docs/T-011/analysis.md` §5.3).
// ---------------------------------------------------------------------------

/// Decode-direction `(secs, nsecs) -> Duration` conversion — the single
/// source for every erofs timestamp decode. Hosted in `utils.rs` and
/// `pub(super)` because both consumers live in sibling files: the
/// `build_time` mirror field (`super_block.rs`, T-022 S03) and the inode
/// `time` field (`inode/mod.rs`, T-022 S07).
///
/// Normalizes exactly like `Duration::new` (an `nsecs` of 1e9 or more
/// carries into `secs`); the only difference is the carry being a
/// `saturating_add`: in the malformed corner where `secs` lies within
/// `[u64::MAX - 3, u64::MAX]` and `nsecs >= 1e9`, std must panic while
/// this function saturates to a value of the same family — that corner
/// already sits in the F6n known-diff domain (reachable only from
/// malformed images; normal images keep nsec < 1e9), so saturation
/// merely turns the panic into a known-diff value: no new guard, no
/// error, no clamping (F6n, `docs/T-011/S01/index.md` §4.2).
// Live since T-022 S03: the `SuperBlock` mirror decode
// (`super_block.rs`, `From<RawSuperBlock>`) is the first reachable
// caller, and the inode `time` decode (T-022 S07) joins it later. No
// deadness attribute belongs here — the bridging item-level
// `expect(dead_code)` was removed the moment this first caller
// landed (its firing `unfulfilled` was the pre-annotated removal
// prompt).
pub(super) fn duration_from_parts(secs: u64, nsecs: u32) -> Duration {
    Duration::new(
        secs.saturating_add((nsecs / 1_000_000_000) as u64),
        nsecs % 1_000_000_000,
    )
}

#[cfg(ktest)]
mod tests {
    use alloc::vec::Vec;

    use ostd::prelude::*;

    use super::*;

    /// LCG input stream of `docs/T-010/analysis.md` §4.3:
    /// `x_{i+1} = (x_i * 2654435761 + 1) mod 2^32`, `byte_i = x_{i+1} & 0xff`.
    fn lcg(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            x = x.wrapping_mul(2654435761).wrapping_add(1);
            buf.push((x & 0xff) as u8);
        }
        buf
    }

    /// Fixed head bytes of `lcg(_, 0x25BBE08F)` — §4.3 cross-check point.
    const LCG_HEAD_16: [u8; 16] = [
        0xe0, 0xe1, 0x92, 0xf3, 0x04, 0xc5, 0x36, 0x57, 0x28, 0xa9, 0xda, 0xbb, 0x4c, 0x8d, 0x7e,
        0x1f,
    ];

    /// Fixed head bytes of the superblock-shape block
    /// (`lcg(3072, 0x5A17C0DE)` with bytes 4..8 zeroed) — §4.3.
    const SUPERBLOCK_SHAPE_HEAD_16: [u8; 16] = [
        0x7f, 0xd0, 0xd1, 0x82, 0x00, 0x00, 0x00, 0x00, 0x47, 0x18, 0x99, 0xca, 0xab, 0x3c, 0x7d,
        0x6e,
    ];

    /// TABLE A — systematic XXH32 coverage over `lcg(len, 0x25BBE08F)`
    /// (length ladder crossing every <16 tail residue, 16, 17..31,
    /// 32..64 multi-stripe, and long inputs):
    /// `(len, [seed = 0, 1, 0x25BBE08F, 0x25BBE090])`.
    const TABLE_A: &[(usize, [u32; 4])] = &[
        (0, [0x02CC5D05, 0x0B2CB792, 0x59FF5D54, 0xEA92CA90]),
        (1, [0x119B983B, 0xBB0A4D80, 0xB12E2651, 0x3C95A0BB]),
        (3, [0x708B1831, 0xC0153C93, 0x5C3A203F, 0x44B97274]),
        (4, [0x1CC94E3B, 0x6A21E9CD, 0x02D8339B, 0xA141759D]),
        (5, [0xCA95523D, 0xCB5A2BE0, 0x8A3E08F2, 0x0F05C28A]),
        (8, [0x1FE4C84C, 0x7E0125EA, 0x69BF5433, 0x4AB7DB1E]),
        (15, [0x41FDE6BD, 0xFDFB025A, 0xF5074653, 0xFE74005E]),
        (16, [0x8FB14CA7, 0x2DA80CB2, 0x735E30FE, 0x10E3919B]),
        (17, [0x5D975EFD, 0x6274A386, 0x0E45910C, 0xFCBA8138]),
        (20, [0x98EE7253, 0xF101F5DC, 0x029A271C, 0x822EACDD]),
        (31, [0x92B86A8F, 0x423F0170, 0x274F6521, 0x692D8900]),
        (32, [0xB68EAE8B, 0x6D857377, 0x55C85436, 0x5889E8A9]),
        (33, [0xE29C933A, 0xA06D12D1, 0xE41D1BF3, 0xC9EA4DD6]),
        (63, [0x619303C0, 0x839F3752, 0x3A6C863F, 0xE6099C52]),
        (64, [0xEBA7B4A3, 0xE1C381AC, 0xC9DADE1D, 0xB3657B8B]),
        (100, [0x15F817A9, 0x1682538F, 0xCC1D5A82, 0xBDD81A17]),
        (222, [0x70A609B1, 0x89F56671, 0xC591C141, 0x9339236E]),
    ];

    /// TABLE C — CRC32C vectors (kernel update semantics, no final XOR).
    /// Row 3 is the RFC 3720 "123456789" anchor; the superblock-shape
    /// row and the chaining property are asserted separately below.
    const TABLE_C: &[(u32, &[u8], u32)] = &[
        (0x00000000, b"", 0x00000000),
        (0xFFFFFFFF, b"", 0xFFFFFFFF),
        (0xFFFFFFFF, b"123456789", 0x1CF96D7C),
        (0xFFFFFFFF, b"a", 0x3E2FBCCF),
        (0x00000000, b"a", 0x93AD1061),
        (0xFFFFFFFF, &[0x00; 32], 0x756EC955),
        (0xFFFFFFFF, &[0xFF; 32], 0x9D5754BC),
    ];

    /// TABLE D — bloom-domain XXH32 vectors (T-005 F52 gate):
    /// `(name suffix, seed, hash, bitmap slot = hash & 31)`. The slot
    /// column feeds the T-016 crafted-bitmap cases; the `FILTER_SEED`
    /// constant itself is private to `xattr.rs`.
    const TABLE_D: &[(&[u8], u32, u32, u32)] = &[
        (b"com.example.foo", 0x25BBE08F, 0x33A1AC8E, 14),
        (b"security.selinux", 0x25BBE090, 0x0FD23D83, 3),
        (b"trusted.overlay.origin", 0x25BBE091, 0x143ABFD2, 18),
        (b"posix_acl_access", 0x25BBE093, 0x9EC3CCBF, 31),
    ];

    /// The superblock-shape block of TABLE C row 8: `lcg(3072, 0x5A17C0DE)`
    /// with bytes 4..8 zeroed (the 4k-only checksum interval shape, §4.3).
    fn superblock_shape_block() -> Vec<u8> {
        let mut block = lcg(3072, 0x5A17C0DE);
        block[4..8].fill(0);
        block
    }

    #[ktest]
    fn xxh32_reference_vectors() {
        // Lock the LCG rule itself against the fixed head bytes first.
        assert_eq!(lcg(16, 0x25BBE08F), LCG_HEAD_16);

        for (len, expecteds) in TABLE_A {
            let input = lcg(*len, 0x25BBE08F);
            for (i, seed) in [0u32, 1, 0x25BBE08F, 0x25BBE090].into_iter().enumerate() {
                assert_eq!(
                    xxh32(&input, seed),
                    expecteds[i],
                    "xxh32 TABLE A mismatch: len = {}, seed = {:#x}",
                    len,
                    seed
                );
            }
        }

        // TABLE B — literal vectors, in table order (rows 7-8 are the
        // byte-range inputs `00 01 .. 1f` and `00 01 .. 2f`).
        let range32: Vec<u8> = (0u8..32).collect();
        let range48: Vec<u8> = (0u8..48).collect();
        let table_b: &[(&[u8], u32, u32)] = &[
            (b"a", 0x00000000, 0x550D7456),
            (b"abc", 0x00000000, 0x32D153FF),
            (b"abcd", 0x00000000, 0xA3643705),
            (b"abcde", 0x00000000, 0x9738F19B),
            (b"abcdefghijklmnop", 0x00000000, 0x9D2D8B62),
            (b"abcdefghijklmnopq", 0x00000000, 0xB3B873E1),
            (&range32[..], 0x25BBE08F, 0x99348BE3),
            (&range48[..], 0x00000007, 0xFDE7E97F),
            (b"123456789", 0x00000000, 0x937BAD67),
        ];
        for &(input, seed, expected) in table_b {
            assert_eq!(xxh32(input, seed), expected, "xxh32 TABLE B row");
        }

        for (suffix, seed, expected_hash, expected_slot) in TABLE_D {
            let hash = xxh32(suffix, *seed);
            assert_eq!(hash, *expected_hash, "xxh32 TABLE D hash");
            assert_eq!(hash & 31, *expected_slot, "bloom slot = hash & 31");
        }
    }

    #[ktest]
    fn crc32c_reference_vectors() {
        for (seed, input, expected) in TABLE_C {
            assert_eq!(
                crc32c(*seed, input),
                *expected,
                "crc32c TABLE C mismatch: seed = {:#x}",
                seed
            );
        }

        // TABLE C row 8: the superblock-shape block, whose fixed head
        // doubles as the second LCG cross-check point.
        let block = superblock_shape_block();
        assert_eq!(&block[..16], &SUPERBLOCK_SHAPE_HEAD_16[..]);
        assert_eq!(crc32c(0xFFFFFFFF, &block), 0xBA29EE63, "table C row 8");

        // Chaining property (§4.3): the update form composes over
        // concatenation — `crc32c(crc32c(!0, a), b) == crc32c(!0, a || b)`
        // with `a` the first 1024 bytes and `b` the remaining 2048.
        let (a, b) = block.split_at(1024);
        assert_eq!(crc32c(crc32c(0xFFFFFFFF, a), b), crc32c(0xFFFFFFFF, &block));
    }
}
