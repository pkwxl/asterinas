#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0
"""
erofs_sb_csum_fix.py -- recompute and write back the erofs superblock
checksum after out-of-mkfs image patches.

Landed with T-023/S09: the flatdev_badtag generation rule (Makefile)
patches the device-slot tag *after* mkfs.erofs has finalized the
superblock checksum, leaving the image with a stale checksum field —
any checksum-verifying mount (Linux super.c:55-80 parity, and the
mount-side verification landed in T-023/S03) then rejects it with
EBADMSG before the tag-blind gate is ever reached. This helper
restores self-consistency, so the image tests what it claims to test:
a bad tag, not a broken checksum.

Coverage formula mirrors the mount-side single source
(kernel/core/src/fs/fs_impls/erofs/super_block.rs
`SuperBlock::checksummed_len()`, blueprint docs/T-012/analysis.md
§2.3): len = block_size - 1024 when block_size > 1024, else
block_size; the region starts at byte 1024; the checksum field itself
(offset +4 within the superblock) is zeroed for the computation.
Algorithm: reflected CRC32C (poly 0x82F63B78), seed 0xFFFFFFFF, no
final xor -- identical to the kernel-side `utils.rs::crc32c` and the
erofs on-disk convention.

Usage: erofs_sb_csum_fix.py <image>   (rewrites the field in place;
idempotent: the computation never reads the stored value)
"""

import struct
import sys

SUPER_OFFSET = 1024
SB_CHECKSUM_OFF = 4  # within the superblock (erofs_fs.h:57)

_CRC32C_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0x82F63B78 if _c & 1 else 0)
    _CRC32C_TABLE.append(_c)


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    path = sys.argv[1]
    with open(path, "r+b") as f:
        f.seek(0)
        img = f.read()
        if len(img) < SUPER_OFFSET + 128:
            print(f"error: {path}: shorter than superblock region", file=sys.stderr)
            return 1
        sb = img[SUPER_OFFSET:SUPER_OFFSET + 128]
        if struct.unpack_from("<I", sb, 0)[0] != 0xE0F5E1E2:
            print(f"error: {path}: bad erofs magic at {SUPER_OFFSET}", file=sys.stderr)
            return 1
        blkszbits = sb[12]
        block_size = 1 << blkszbits
        region_len = block_size - SUPER_OFFSET if block_size > SUPER_OFFSET else block_size
        if SUPER_OFFSET + region_len > len(img):
            print(
                f"error: {path}: checksum region [{SUPER_OFFSET},"
                f"{SUPER_OFFSET + region_len}) exceeds image size {len(img)}",
                file=sys.stderr,
            )
            return 1
        region = bytearray(img[SUPER_OFFSET:SUPER_OFFSET + region_len])
        old = struct.unpack_from("<I", region, SB_CHECKSUM_OFF)[0]
        region[SB_CHECKSUM_OFF:SB_CHECKSUM_OFF + 4] = b"\x00" * 4
        new = crc32c(bytes(region))
        f.seek(SUPER_OFFSET + SB_CHECKSUM_OFF)
        f.write(struct.pack("<I", new))
    print(
        f"{path}: sb checksum {old:#010x} -> {new:#010x} "
        f"(region [{SUPER_OFFSET}, {SUPER_OFFSET + region_len}), "
        f"blkszbits={blkszbits})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
