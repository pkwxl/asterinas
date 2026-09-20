// SPDX-License-Identifier: MPL-2.0

//! The erofs symlink faces: the fast/slow split judgement and the
//! inline-target read, both consumed by the LNK arm of the payload
//! assembly (`InodePayload::new`, `inode/mod.rs`).
//!
//! What "slow symlinks are cut" means (C-6g, `docs/T-013/analysis.md`
//! §3.2 — the correct reading of the early skeleton note): the cut
//! is the ext2-style *dedicated slow-symlink mechanism* — the
//! fixed-size inline target array (`FastSymlinkTarget`), the
//! `MAX_FAST_SYMLINK_LEN` gate, and the write-side split. It is NOT
//! a behavior cut: slow symlinks (LNK × FLAT_PLAIN / CHUNK_BASED,
//! and FLAT_INLINE failing the criterion) are fully preserved
//! through the DataBacked payload and the page cache — `read_link`
//! reads the very same bytes through that path. The fast/slow split
//! is purely an internal payload choice; both arms produce the same
//! readlink output.
//!
//! The precise inline start is `inline_data_start` — inode end plus
//! the inline-xattr area — never a bare "just past the inode body":
//! a read anchored at the inode body would fetch the wrong bytes on
//! any image whose inodes carry inline xattrs.

#![short_vis_path::add(erofs)]

use ostd::mm::VmIo;

use super::super::{fs::Erofs, prelude::*};
use super::{DataLayout, InodeDesc};

/// L3 three-element fast/slow criterion in absolute byte-offset form
/// (the terminal rewrite of the T-011 S07 §5.1 sketch anchor, S04-D1;
/// `docs/T-013/analysis.md` §3.1, `docs/T-013/S04/index.md` §1.2–1.3):
/// the aster homologue of `erofs_fill_symlink`'s decision
/// (linux inode.c:15-21), evaluated in absolute device coordinates.
///
/// Pure in-memory geometry: no device I/O, no locks (R1-safe inside
/// the iget critical section). The call site is the LNK arm of
/// `InodePayload::new`, strictly AFTER the I12 arm-head gate, so the
/// datalayout here is one of {0, 2, 4}:
///
/// 1. `datalayout == FLAT_INLINE`, otherwise slow ({0, 4} → slow;
///    {1, 3} were already rejected by the gate);
/// 2. `inline_start.checked_add(size)` — `None` → slow (the
///    `check_add_overflow` homologue; the u64-vs-i64 algebraic
///    difference is registered, S04 §1.4: the i64 sign-bit overflow
///    Linux can take is unreachable at u64 width after a successful
///    decode, and every value the i64 path rejects also fails
///    element ③, so the two forms agree pointwise);
/// 3. `end ≤ round_up(inode_end, bs)` — the boundary anchor is the
///    block containing the inode's LAST byte (F-1′: NOT
///    `round_up(inline_data_start)` — that sketch anchor diverges on
///    the giant-xattr corner), boundary-exact end allowed (the
///    `off > i_blocksize` mirror, `≤` passes).
pub(super) fn is_fast_symlink(fs: &Erofs, nid: ErofsNid, desc: &InodeDesc) -> bool {
    // Element ① — datalayout == FLAT_INLINE (inode.c:18).
    if desc.datalayout != DataLayout::FlatInline {
        return false;
    }
    let bs = fs.super_block().block_size() as u64;
    let inode_end = super::suffix_xattr_start(fs.super_block(), nid, desc);
    // Geometry adds are structurally wrap-free at this point: the
    // decode already read [iloc, iloc + inode_isize) off the device,
    // so inode_end is device-bounded; xattr_isize ≤ 262148 (the le16
    // icount bound) cannot push past u64 on any real device (see
    // S04 §1.4 for the reachability accounting).
    let inline_start = inode_end + desc.xattr_isize as u64;
    // Elements ② (no overflow) and ③ (end within the block holding
    // the inode's last byte, boundary-exact allowed).
    match inline_start.checked_add(desc.size) {
        // Element ③: end within the block holding the inode's last
        // byte, boundary-exact allowed — `div_ceil(bs) * bs` is
        // round_up(inode_end, bs).
        Some(end) => end <= inode_end.div_ceil(bs) * bs,
        // Element ② failed: overflow → slow.
        None => false,
    }
}

/// Reads the FLAT_INLINE symlink target bytes (read site #14,
/// `docs/T-011/S07/index.md` §3.2): `desc.size` bytes at
/// `inline_data_start` — the aster homologue of the `kmemdup_nul`
/// copy (linux inode.c:23-24).
///
/// Byte-stream read, naturally cross-block (RD3): covers the
/// cross-block slot whose target lives in the second metadata
/// block. Err face = the I2 device read, passed through as-is (C2 —
/// no message added, no errno folding). `i_size == 0` → empty vec,
/// zero allocations (the F4/I9 abort-family note: a non-empty
/// allocation failure is an abort, never an Err arm, G-M21).
///
/// Only ever called on the fast arm (the criterion proved
/// `size < block_size`), so the buffer is bounded by the fast-path
/// upper limit.
pub(super) fn read_inline_target(fs: &Erofs, nid: ErofsNid, desc: &InodeDesc) -> Result<Vec<u8>> {
    let start = super::inline_data_start(fs.super_block(), nid, desc);
    // size ≤ i64::MAX (the decode invariant), so the usize cast is
    // loss-free on 64-bit targets.
    let mut buf = vec![0u8; desc.size as usize];
    fs.block_device().read_bytes(start as usize, &mut buf)?; // I2 passthrough
    Ok(buf)
}
