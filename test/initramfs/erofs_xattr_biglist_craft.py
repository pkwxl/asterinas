#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0
"""
erofs_xattr_biglist_craft.py -- build the crafted erofs image that
hosts a single inode whose xattr name list totals 70000 bytes
(W-X07 / XAT-38 segments 2+3 carrier, T-032).

Why a crafted image at all: a healthy mkfs.erofs pipeline *cannot*
produce a single-inode name list longer than XATTR_LIST_MAX (65536):
mkfs ingests source-tree xattrs through llistxattr, and the host
kernel (matching mainline Linux) refuses to enumerate a list that
large regardless of tolerance flags (adjudication + probe evidence:
docs/T-032/S02/index.md §2.4/§7.4). The XAT-38 recipe therefore
allows the crafted-image branch, and this script implements it as a
template-transform: mkfs a clean 374-name base (65450B, ingestible),
then re-emit only the file unit with the full 400-name ibody, patch
the superblock (blocks/build_time/build_time_nsec zeroed for byte
determinism), and recompute the SB checksum.

Name formula (single source: docs/T-032/S02/index.md §4 -- the host
stage, this script, and the erofs_common.h C helper are three
same-formula implementations):
    name(i) = "user." + "%04d"(i) + "-" + pad(i)*164,
    pad(i) = 'a' + (i % 26), i in [0, 400)
    full name length 174B (list contribution 175B incl. NUL);
    sum = 400 * 175 = 70000 exactly; value = "V"; file body = 'b'.

On-disk facts consumed here (probe-verified, docs/T-032/S02 §4.1):
    xattr_isize = (i_xattr_icount + 2) * 4 (NOT (icount+1)*4);
    crafted ibody = 12 + 400*ALIGN4(4+169+1) = 70412 -> icount 17603;
    shared xattrs are NOT used (nf=0, sc=0): RawXattrIbodyHeader's
    h_shared_count is u8 (shared id <= 255), 400 unique names must
    stay inline;
    SB checksum region = [1024, 1024 + blksz - 1024), checksum field
    zeroed for the computation, reflected CRC32C (poly 0x82F63B78),
    seed 0xFFFFFFFF, no final xor (same spelling as
    erofs_sb_csum_fix.py, the in-tree single source).

Determinism: build_time/nsec and inode mtime fields are zeroed and
the UUID is fixed by the caller, so the output is a pure function of
(--uuid, formula) -- byte-identical across clean rebuilds. The
digest gate for this image is therefore *literal equality*, stronger
than the SB-whitelist gate of the mkfs-family images
(docs/T-032/S02 §3).

Version gate: mkfs spelling is bound to erofs-utils 1.7.1 (same
self-check shape as erofs_stage.sh self-check #1: the no-arg call
prints usage and exits non-zero; --version is not recognized). A
different version halts the build.

Usage:
    erofs_xattr_biglist_craft.py --uuid <uuid> <output-image>

The UUID is passed in (single source: the Makefile variable
EROFS_UUID_XATTR_BIGLIST). The output image must live outside the
scratch source tree (mkfs would ingest an output image placed inside
the tree it scans -- guarded below).
"""

import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

EROFS_UTILS_EXPECTED = "1.7.1"
N_BASE = 374   # base names: 374*175 = 65450 <= 65536 (mkfs-ingestible)
N_FINAL = 400  # final names: 400*175 = 70000 (the registered fixture)
SUPER_OFFSET = 1024
MAGIC = 0xE0F5E1E2
XATTR_INDEX_USER = 1
ENTRY_ALIGN = 176  # ALIGN4(4 + 169 + 1) per name entry

_CRC32C_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0x82F63B78 if _c & 1 else 0)
    _CRC32C_TABLE.append(_c)


def die(msg: str) -> "None":
    print(f"CRAFT-FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


def version_gate() -> None:
    """mkfs.erofs version gate, bound to 1.7.1 (erofs_stage.sh #1 shape)."""
    try:
        r = subprocess.run(["mkfs.erofs"], capture_output=True, text=True)
    except FileNotFoundError:
        die("mkfs.erofs ABSENT (erofs-utils not installed)")
    if r.returncode == 0:
        die("mkfs.erofs no-arg call exited 0 (expected usage, rc != 0)")
    lines = [ln for ln in (r.stdout + r.stderr).splitlines() if ln.strip()]
    tail = lines[-1] if lines else ""
    versions = re.findall(r"[0-9]+(?:\.[0-9]+)+", tail)
    found = versions[-1] if versions else ""
    if not found.startswith(EROFS_UTILS_EXPECTED):
        shown = found if found else "<unparsed>"
        die(
            f"mkfs.erofs version '{shown}' != "
            f"{EROFS_UTILS_EXPECTED} -- mkfs spelling is version-bound; "
            "re-verify the parameter face before allowing this build "
            "(docs/T-016/S03 §6.1 divergent-version procedure)"
        )


def suffix(i: int) -> bytes:
    return ("%04d-" % i).encode() + bytes([97 + (i % 26)]) * 164


def mkfs_base(uuid: str, tree: str, img: str) -> None:
    """Build the N_BASE clean base image from a scratch tree."""
    os.makedirs(tree, exist_ok=True)
    host = f"{tree}/xattr_biglist.bin"
    with open(host, "wb") as fh:
        fh.write(b"b")
    for i in range(N_BASE):
        os.setxattr(host, "user." + suffix(i).decode(), b"V")
    r = subprocess.run(
        ["mkfs.erofs", "-U", uuid, "-T", "0", img, tree],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        die(f"mkfs base failed: {r.stderr}")


def parse(img_path: str):
    """Parse the base image: SB + root inode + the biglist file inode."""
    img = bytearray(open(img_path, "rb").read())
    sb0 = SUPER_OFFSET
    if struct.unpack_from("<I", img, sb0)[0] != MAGIC:
        die(f"base image has no erofs magic at {sb0}")
    blkszbits = img[sb0 + 12]
    blksz = 1 << blkszbits
    root_nid = struct.unpack_from("<H", img, sb0 + 14)[0]
    meta = struct.unpack_from("<I", img, sb0 + 40)[0]

    def iloc(nid):
        return (meta << blkszbits) + (nid << 5)

    def inode(nid):
        o = iloc(nid)
        ifmt = struct.unpack_from("<H", img, o)[0]
        ver, dl = ifmt & 1, (ifmt >> 1) & 7
        ic = struct.unpack_from("<H", img, o + 2)[0]
        isz = 64 if ver else 32
        xis = (ic + 2) * 4 if ic else 0  # xattr_isize = (icount+2)*4
        size = struct.unpack_from("<Q", img, o + 8)[0]
        iu = struct.unpack_from("<Q", img, o + 16)[0]
        return dict(off=o, ifmt=ifmt, ver=ver, dl=dl, ic=ic, isz=isz,
                    xis=xis, size=size, iu=iu)

    root = inode(root_nid)
    dd = root["off"] + root["isz"] + root["xis"] if root["dl"] == 2 \
        else (root["iu"] & 0xFFFFFFFF) * blksz
    first_no = struct.unpack_from("<H", img, dd + 8)[0]
    nd = first_no // 12
    fnid = None
    for k in range(nd):
        nid, no, ft = struct.unpack_from("<QHB", img, dd + 12 * k)
        nx = struct.unpack_from("<H", img, dd + 12 * (k + 1))[0] \
            if k + 1 < nd else root["size"]
        if img[dd + no:dd + nx].decode() == "xattr_biglist.bin":
            fnid = nid
    if fnid is None:
        die("base image has no xattr_biglist.bin dirent")
    return img, blkszbits, blksz, root, inode(fnid)


def build(base_path: str) -> bytes:
    """Template-transform: re-emit the file unit with the 400-name ibody."""
    img, blkszbits, blksz, root, file = parse(base_path)
    sb0 = SUPER_OFFSET
    if file["dl"] != 2:
        die("base file inode is not FlatInline")
    ibody = 12 + N_FINAL * ENTRY_ALIGN
    icount = ibody // 4 - 2                  # xattr_isize = (icount+2)*4
    unit = file["isz"] + ibody + file["size"]
    unit_pad = (unit + 31) // 32 * 32
    end = file["off"] + unit_pad
    total_blks = (end + blksz - 1) // blksz
    out = bytearray(total_blks * blksz)
    out[:file["off"]] = img[:file["off"]]    # SB region + root unit verbatim
    fraw = bytearray(img[file["off"]:file["off"] + file["isz"]])
    struct.pack_into("<H", fraw, 2, icount)
    if file["ver"] == 1:                     # extended: zero mtime
        struct.pack_into("<Q", fraw, 32, 0)
        struct.pack_into("<I", fraw, 40, 0)
    out[file["off"]:file["off"] + file["isz"]] = fraw
    p = file["off"] + file["isz"]
    struct.pack_into("<IB", out, p, 0, 0)     # 12B header: nf=0, sc=0
    p += 12
    for i in range(N_FINAL):
        sfx = suffix(i)
        out[p] = len(sfx)                     # e_name_len = 169 (<= 255)
        out[p + 1] = XATTR_INDEX_USER
        struct.pack_into("<H", out, p + 2, 1)  # e_value_size = 1
        out[p + 4:p + 4 + len(sfx)] = sfx
        out[p + 4 + len(sfx)] = ord("V")
        p += ENTRY_ALIGN
    out[p] = ord("b")                         # FlatInline file body
    struct.pack_into("<I", out, sb0 + 36, total_blks)   # SB.blocks
    struct.pack_into("<Q", out, sb0 + 24, 0)            # SB.build_time
    struct.pack_into("<I", out, sb0 + 32, 0)            # SB.build_time_nsec
    if root["ver"] == 1:
        rr = bytearray(out[root["off"]:root["off"] + 64])
        struct.pack_into("<Q", rr, 32, 0)
        struct.pack_into("<I", rr, 40, 0)
        out[root["off"]:root["off"] + 64] = rr
    # SB checksum (single-source spelling = erofs_sb_csum_fix.py:
    # region [1024, 1024 + blksz - 1024), checksum field zeroed,
    # crc32c with no final xor).
    rlen = blksz - SUPER_OFFSET if blksz > SUPER_OFFSET else blksz
    region = bytearray(out[sb0:sb0 + rlen])
    struct.pack_into("<I", region, 4, 0)
    struct.pack_into("<I", out, sb0 + 4, crc32c(bytes(region)))
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Craft erofs_xattr_biglist.img (T-032 W-X07 carrier)")
    ap.add_argument("--uuid", required=True,
                    help="fixed volume UUID (single source: Makefile)")
    ap.add_argument("output", help="output image path")
    args = ap.parse_args()

    version_gate()

    out_real = os.path.realpath(args.output)
    out_dir = os.path.dirname(out_real) or "."
    os.makedirs(out_dir, exist_ok=True)

    scratch = tempfile.mkdtemp(prefix="erofs_xattr_biglist.")
    try:
        tree = f"{scratch}/tree"
        base = f"{scratch}/base.img"
        # Guard: the output image must stay outside the scratch source
        # tree (mkfs scans the tree AFTER creating the output file and
        # would ingest an image placed inside it).
        if out_real.startswith(os.path.realpath(tree) + os.sep):
            die(f"output image {out_real} is inside the source tree {tree}")
        mkfs_base(args.uuid, tree, base)
        crafted = build(base)
        with open(args.output, "wb") as fh:
            fh.write(crafted)
        digest = hashlib.sha256(crafted).hexdigest()
        print(f"CRAFT-SIZE {len(crafted)}")
        print(f"CRAFT-SHA {digest}")
        return 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
