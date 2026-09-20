// SPDX-License-Identifier: MPL-2.0

//! Block mapping and physical read primitives for erofs inodes.
//!
//! Current face: the **minimal read-only flat page-cache backend**
//! (`DataBackend`) assembled into every DataBacked payload by
//! `inode/mod.rs::new_data_backed` — the decision-1 scope of
//! `docs/T-024/subtasks.md` S01. It covers datalayout FLAT_PLAIN
//! (file block `idx` → device block `raw_blkaddr + idx`, the
//! identity mapping of `erofs_map_blocks_flatmode`,
//! linux data.c:82-96) and FLAT_INLINE (the inline tail bytes that
//! follow the inode record, data.c:98-110); CHUNK_BASED answers
//! EOPNOTSUPP on every read — the deferred arm, empty on the
//! main-column image family. **Minimal flat face — final shape
//! lands with T-025 (§1.1 seam)**: the final map_blocks/map_dev
//! walk, the chunk mapping (M4–M7), and the crafted-edge validation
//! (e.g. the "inline data across blocks" EFSCORRUPTED arm of
//! data.c:103-108) replace the arms below in place, evolving this
//! type without churning the payload construction.
//!
//! Seam contract carried from T-024 into T-025 (§1.1):
//! - the constructor parameter set is final (`Weak<Erofs>` +
//!   `Arc<dyn BlockDevice>` + collapsed geometry + npages) so the
//!   evolution stays in place;
//! - the backend serves reads at ARBITRARY file offsets — page
//!   granularity naturally satisfies that, and no block-alignment
//!   assumption is built in here;
//! - device errors travel unfolded: every arm returns the device
//!   stack's errno as-is to the page-cache exit (the G-M10 family's
//!   known-diff posture — no EIO folding in either direction);
//! - the page-cache capacity stays `desc.size.align_up(PAGE_SIZE)`
//!   (ext2 precedent `ext2/inode/mod.rs:614-627`), kept in sync by
//!   the constructor caller.
//!
//! Public functions take decoded layout parameters, geometry, and
//! the device handle — never `&Inode` and never `&InodeDesc` — so
//! the L2/L3 dependency edge stays acyclic (the geometry collapse
//! happens once in `inode/mod.rs`, L3).
//!
//! # Interrupt context
//!
//! Completion callbacks of the page-cache backend run in interrupt
//! context: they must not take blocking locks (including
//! `inode_cache`), must not allocate memory, and must not call into
//! the VFS. The inline-tail fill below runs synchronously in the
//! caller's (page-cache read path's) context instead — it touches
//! none of the three prohibited surfaces.

#![short_vis_path::add(erofs)]

use aster_block::{
    bio::{BioCompleteFn, BioSegment, BioStatus},
    id::Bid,
};
use io_util::batch::IoBatch;
use ostd::mm::{PAGE_SIZE, VmIo, io::util::HasVmReaderWriter};

use super::super::{fs::Erofs, prelude::*};
use crate::vm::page_cache::BlockAsPageCacheBackend;

/// Minimal read-only page-cache backend for erofs DataBacked
/// payloads (decision 1, `docs/T-024/subtasks.md` S01; final shape
/// lands with T-025 — see the module doc for the seam contract).
///
/// One instance per inode, constructed inside the iget write-guard
/// critical section and immutable afterwards: the geometry is
/// collapsed once (L3) and never re-derived. The page cache it
/// serves holds only a `Weak<dyn PageCacheBackend>` here; the
/// strong owner is the `InodePayload::DataBacked` variant.
pub(super) struct DataBackend {
    /// Weak back-reference to the owning filesystem — the
    /// constructor-seam parameter for the T-025 map_blocks face
    /// (mount geometry and device-table walks); the minimal face
    /// reads the device it already holds instead.
    // First consumer: the final data-path face (T-025, §1.1 seam).
    #[expect(dead_code)]
    fs: Weak<Erofs>,
    /// The backing device: flat-region BIOs and inline-tail byte
    /// reads both go through it.
    device: Arc<dyn BlockDevice>,
    /// The per-inode geometry, collapsed from the decoded descriptor
    /// by `new_data_backed` (L3) into plain values.
    layout: FlatLayout,
    /// Page bound = ceil(size / PAGE_SIZE): the EINVAL bound of the
    /// backend contract (`page_cache/mod.rs` read_page_async). The
    /// filesystem is read-only, so the bound never moves.
    npages: usize,
}

/// The collapsed flat geometry of one DataBacked inode, in plain
/// decoded values (built by `inode/mod.rs::new_data_backed`; this
/// module never sees the descriptor itself).
pub(super) enum FlatLayout {
    /// datalayout ∈ {FLAT_PLAIN, FLAT_INLINE}
    /// (`erofs_map_blocks_flatmode`, data.c:82-110): file block
    /// `idx < flat_blocks` maps to device block `raw_blkaddr + idx`;
    /// the single block beyond them, when present, is the inline
    /// tail stored in the metadata area at `tail.start`.
    Flat {
        /// Device-block base of the flat region (the `i_u`
        /// `raw_blkaddr` reading).
        raw_blkaddr: u64,
        /// Number of device-backed flat blocks = erofs_iblks(i_size)
        /// − tailendpacking (data.c:84). Under the 4k-only scope
        /// (AR-S01-1) one erofs block == one BIO block == one page.
        flat_blocks: u64,
        /// The FLAT_INLINE tail (the EROFS_MAP_META region);
        /// `None` for FLAT_PLAIN.
        tail: Option<InlineTail>,
    },
    /// datalayout == CHUNK_BASED: every read fails EOPNOTSUPP — the
    /// deferred arm of decision 1 (T-024); the chunk mapping
    /// (M4–M7) lands with T-025 and replaces this arm in place.
    Chunked,
    /// datalayout ∈ {COMPRESSED_FULL, COMPRESSED_COMPACT}:
    /// structurally unreachable after the I12 arm-head assembly gate
    /// (S02-R1) — kept as the defensive half of the layer-3
    /// rejection chain (C-4), the same unreachable-but-defensive
    /// posture as the F10/F11 mount-site gates, with the same
    /// message string.
    Compressed,
}

/// The inline-tail geometry of a FLAT_INLINE inode (the
/// EROFS_MAP_META region).
pub(super) struct InlineTail {
    /// Device byte offset of the inline region = `inline_data_start`
    /// (the base-point formula family, inode/mod.rs — the single
    /// source every inline consumer derives from).
    pub(super) start: u64,
    /// Tail length in bytes = `i_size − flat_blocks · block_size`
    /// (1..=block_size). The page is zero beyond it.
    pub(super) len: usize,
}

impl DataBackend {
    /// Wraps the collapsed geometry. Constructor-seam parameter set
    /// (decision 1): final for T-025's in-place evolution.
    pub(super) fn new(
        fs: Weak<Erofs>,
        device: Arc<dyn BlockDevice>,
        layout: FlatLayout,
        npages: usize,
    ) -> Self {
        Self {
            fs,
            device,
            layout,
            npages,
        }
    }
}

impl BlockAsPageCacheBackend for DataBackend {
    fn submit_read_bio(
        &self,
        idx: usize,
        bio_segment: BioSegment,
        complete_fn: BioCompleteFn,
        io_batch: &mut IoBatch,
    ) -> Result<()> {
        // The backend bounds contract (fail with EINVAL past the
        // end, page_cache/mod.rs read_page_async). Static bound: the
        // filesystem is read-only, npages never moves.
        if idx >= self.npages {
            return_errno_with_message!(Errno::EINVAL, "invalid read size");
        }
        match &self.layout {
            FlatLayout::Flat {
                raw_blkaddr,
                flat_blocks,
                tail,
            } => {
                if (idx as u64) < *flat_blocks {
                    // Identity mapping: file block idx → device
                    // block raw_blkaddr + idx (data.c:87-90). One BIO
                    // block per file block — the 4k-only scope makes
                    // the erofs block size, BLOCK_SIZE, and PAGE_SIZE
                    // coincide. The enqueue error converts through
                    // the crate error type; completion (including
                    // the page up-to-date transition and the page
                    // lock release) runs in the device completion.
                    self.device.read_blocks_async(
                        Bid::new(raw_blkaddr + idx as u64),
                        bio_segment,
                        Some(complete_fn),
                        io_batch,
                    )?;
                    Ok(())
                } else {
                    // The inline-tail page: `idx == flat_blocks` —
                    // the npages bound leaves exactly this one page
                    // beyond the flat region (a FLAT_PLAIN layout
                    // has npages == flat_blocks and never gets
                    // here).
                    let tail = tail
                        .as_ref()
                        .expect("the npages bound leaves only the tail page here");
                    // Synchronous fill in the caller's context (the
                    // page-cache read path), NOT an interrupt
                    // callback — the three interrupt-context
                    // prohibitions above stay untouched. The bytes
                    // land in the page through the segment's DMA
                    // writer: the DmaStream mapped from the page is
                    // bidirectional at the DMA layer, and the
                    // FromDevice gate on `BioSegment::writer` models
                    // device-filled data only — this arm is the
                    // filesystem itself producing the bytes (same
                    // posture as the framework's own
                    // `BioStatus::Zeros` arm, which also fills the
                    // page without any device I/O). The zeroed
                    // bounce buffer keeps the beyond-tail bytes of
                    // the page reading as zeros.
                    let mut page_bytes = [0u8; PAGE_SIZE];
                    self.device
                        .read_bytes(tail.start as usize, &mut page_bytes[..tail.len])?; // I2, unfolded
                    bio_segment
                        .inner_dma_slice()
                        .writer()?
                        .write(&mut VmReader::from(&page_bytes[..]));
                    // Marks the page up-to-date and releases the page
                    // lock (the closure owns the LockedCachePage).
                    complete_fn(BioStatus::Complete);
                    Ok(())
                }
            }
            // The deferred arm (decision 1): the main-column image
            // family carries no chunk-based inode; the chunk mapping
            // (M4–M7) lands with T-025 and replaces this arm.
            FlatLayout::Chunked => {
                return_errno_with_message!(
                    Errno::EOPNOTSUPP,
                    "chunk-based mapping lands with the data-path task"
                );
            }
            // Unreachable after the I12 arm-head gate (S02-R1);
            // defensive half of the layer-3 rejection chain (C-4),
            // same message string as the F10/F11 site gates.
            FlatLayout::Compressed => {
                return_errno_with_message!(
                    Errno::EOPNOTSUPP,
                    "compressed inode data is not supported"
                );
            }
        }
    }

    fn submit_write_bio(
        &self,
        _idx: usize,
        _bio_segment: BioSegment,
        _complete_fn: BioCompleteFn,
        _io_batch: &mut IoBatch,
    ) -> Result<()> {
        // Structurally unreachable: a read-only filesystem has no
        // write path, so no page is ever dirtied and writeback never
        // starts. The explicit EROFS rejection (not EINVAL) keeps
        // the answer meaningful should a future caller appear.
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }
}
