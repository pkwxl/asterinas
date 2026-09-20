// SPDX-License-Identifier: MPL-2.0

//! Block mapping and physical read primitives for erofs inodes.
//!
//! Current face: the minimal read-only flat page-cache backend
//! (`DataBackend`) assembled into every DataBacked payload by
//! `inode/mod.rs::new_data_backed` — the decision-1 scope of
//! `docs/T-024/subtasks.md` S01. Since T-025 S01 the backend reads
//! the FINAL geometry: the desc-derived plain-value bundle
//! `DataGeometry` below (collapsed once by the pure function
//! `inode/mod.rs::data_geometry`) replaced the transitional
//! `FlatLayout`/`InlineTail` pair in place, per the §1.1 seam — the
//! constructor parameter set never churned. The remaining T-025
//! slices evolve this file in place: the map_blocks/map_dev walk
//! lands with S03, the chunk mapping (M4–M7) with S04, and the
//! four-arm submit_read_bio rewrite — including the crafted-edge
//! validation (e.g. the "inline data across blocks" EFSCORRUPTED
//! arm of data.c:103-108) — with S05.
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
//! happens once in `inode/mod.rs`, L3: `data_geometry`).
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

use core::mem::offset_of;

use aster_block::{
    bio::{BioCompleteFn, BioSegment, BioStatus},
    id::Bid,
};
use io_util::batch::IoBatch;
use ostd::{
    const_assert,
    mm::{PAGE_SIZE, VmIo, io::util::HasVmReaderWriter},
};

use super::super::{fs::Erofs, prelude::*};
use crate::vm::page_cache::BlockAsPageCacheBackend;

/// Desc-derived geometry for one DataBacked payload, precomputed
/// by the caller in `inode/mod.rs` at payload-construction time
/// (`data_geometry`; T-010 §1.4 rule 5: data.rs takes decoded plain
/// values, never `&Inode`/`&InodeDesc`).
///
/// Field-validity discipline (contract-level, no nested Options):
/// `raw_blkaddr`/`tail_inline` are valid iff the layout is Flat,
/// `chunk` iff CHUNK_BASED; `size`/`block_bits`/
/// `inline_data_start` are always well-defined; `compressed` is
/// always the predicate snapshot. The three mutually exclusive
/// datalayouts {FLAT_PLAIN, FLAT_INLINE, CHUNK_BASED} are encoded
/// jointly by the `(chunk.is_none(), tail_inline)` pair plus the
/// `compressed` boolean; the map_blocks dispatcher (S03) keys on
/// exactly that pair and debug-asserts the validity domain (an
/// API-misuse face, not an on-disk check).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DataGeometry {
    /// i_size (I7: <= 2^63-1; compact <= 2^32-1).
    pub size: u64,
    /// sb.blkszbits (== 12 under the G-M08 mount gate; kept
    /// general-form — every mapping formula goes through this
    /// shift, never through a PAGE_SIZE assumption).
    pub block_bits: u32,
    /// desc.raw_blkaddr() — the data start block (the `i_u`
    /// reading). Valid iff the layout is Flat.
    pub raw_blkaddr: u32,
    /// datalayout == FLAT_INLINE — the flat-mode tail-end packing
    /// BIT only, never a judgement about whether an inline tail
    /// EXISTS: the size=0 and exact-block-size corners keep the bit
    /// set with an empty (absent) tail region; tail positioning is
    /// arithmetic in the consumer (M2), not a stored fact.
    pub tail_inline: bool,
    /// inode_location(nid) + inode_isize + xattr_isize (the T-013
    /// §3.1 base-point family). Always well-defined; consumed by
    /// the inline tail (Flat + tail_inline) and as the extent-base
    /// input of the chunked walk (S04).
    pub inline_data_start: u64,
    /// Some iff datalayout == CHUNK_BASED.
    pub chunk: Option<ChunkGeometry>,
    /// Snapshot of `InodeDesc::is_data_compressed()` evaluated once
    /// at construction (the single-source predicate, S01-D3).
    /// Always false after the I12 assembly gate — the stored value
    /// is the consumption form of the layer-3 defensive half.
    pub compressed: bool,
}

/// The CHUNK_BASED geometry (the decoded chunk summary, T-011 §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ChunkGeometry {
    /// The extent-area element width: 8 (chunk indexes, the INDEXES
    /// bit) or 4 (the bare block-map entry) — the
    /// `AddrState::chunk_unit()` value evaluated in mod.rs.
    pub unit: usize,
    /// The chunk size shift in blocks: chunk size = `1 <<
    /// chunkbits` blocks (= sb.blkszbits + (format & 0x1F) at the
    /// decode).
    pub chunkbits: u32,
}

/// Read-only page-cache backend for erofs DataBacked payloads
/// (decision 1, `docs/T-024/subtasks.md` S01; the geometry is final
/// since T-025 S01 — see the module doc for the seam contract).
///
/// Declared at erofs scope (`pub(in crate::fs::fs_impls::erofs)`)
/// because erofs-visible signatures — `Inode::data_backend` and the
/// `DataBacked` payload field — name the type (the
/// `private_interfaces` contract; the `data` module itself stays
/// private, and `inode/mod.rs` re-exports the short path).
///
/// One instance per inode, constructed inside the iget write-guard
/// critical section and immutable afterwards: the geometry is
/// collapsed once (L3) and never re-derived. The page cache it
/// serves holds only a `Weak<dyn PageCacheBackend>` here; the
/// strong owner is the `InodePayload::DataBacked` variant.
pub(in crate::fs::fs_impls::erofs) struct DataBackend {
    /// Weak back-reference to the owning filesystem — the
    /// constructor-seam parameter for the map_blocks/map_dev faces
    /// (mount geometry and device-table walks, T-025 S03/S04); the
    /// minimal face reads the device it already holds instead.
    // First consumer: map_dev / upgrade_fs (T-025 S03).
    #[expect(dead_code)]
    fs: Weak<Erofs>,
    /// The backing device: flat-region BIOs and inline-tail byte
    /// reads both go through it.
    device: Arc<dyn BlockDevice>,
    /// The per-inode geometry bundle, collapsed from the decoded
    /// descriptor by `data_geometry` (L3) into plain values.
    geom: DataGeometry,
    /// Page bound = ceil(size / PAGE_SIZE): the EINVAL bound of the
    /// backend contract (`page_cache/mod.rs` read_page_async). The
    /// filesystem is read-only, so the bound never moves.
    npages: usize,
}

impl DataBackend {
    /// Wraps the collapsed geometry. Constructor-seam parameter set
    /// (decision 1): final for T-025's in-place evolution.
    pub(super) fn new(
        fs: Weak<Erofs>,
        device: Arc<dyn BlockDevice>,
        geom: DataGeometry,
        npages: usize,
    ) -> Self {
        // 4k-only scope (AR-S01-1/G-M08): the erofs block size, the
        // BIO `BLOCK_SIZE`, and `PAGE_SIZE` coincide — pinned
        // structurally by the mount gate (blkszbits == 12). The
        // assert documents the premise at its only reliance site:
        // the page-granular identity mapping and the tail sizing of
        // the arms below.
        debug_assert_eq!(1u64 << geom.block_bits, PAGE_SIZE as u64);
        // S01-D7 canonical derivation: npages == size.div_ceil(
        // PAGE_SIZE) == capacity / PAGE_SIZE — the two caller-side
        // expressions are the same canonical relation (S01-IF-1).
        debug_assert_eq!(npages, geom.size.div_ceil(PAGE_SIZE as u64) as usize);
        Self {
            fs,
            device,
            geom,
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
        // Layer-3 defensive half, FINAL shape (S01-D3): the stored
        // predicate snapshot, consumed here instead of re-derived.
        // Structurally unreachable after the I12 arm-head assembly
        // gate (S02-R1) — kept as defense in depth against future
        // bypasses of that gate, the same unreachable-but-defensive
        // posture as the F10/F11 mount-site gates, with the same
        // message string.
        if self.geom.compressed {
            return_errno_with_message!(Errno::EOPNOTSUPP, "compressed inode data is not supported");
        }
        match self.geom.chunk {
            None => {
                // Flat-mode geometry (erofs_map_blocks_flatmode,
                // data.c:82-96): erofs_iblks(i_size) = ceil(size/bs),
                // tailendpacking subtracts the inline last block
                // (data.c:84). Saturating: a zero-size FLAT_INLINE
                // inode has iblks == 0 and no readable page at all,
                // so the 0−1 wrap of the C unsigned arithmetic is
                // clamped instead (no read can reach either
                // geometry). The exact u32-truncation mirror of the
                // linux lastblk arithmetic lands with the flat
                // map_blocks face (S03, S03-D5).
                let bs = 1u64 << self.geom.block_bits;
                let lastblk = self
                    .geom
                    .size
                    .div_ceil(bs)
                    .saturating_sub(u64::from(self.geom.tail_inline));
                if (idx as u64) < lastblk {
                    // Identity mapping: file block idx → device
                    // block raw_blkaddr + idx (data.c:87-90). One BIO
                    // block per file block — the 4k-only scope makes
                    // the erofs block size, BLOCK_SIZE, and PAGE_SIZE
                    // coincide (pinned by the constructor assert).
                    // The enqueue error converts through the crate
                    // error type; completion (including the page
                    // up-to-date transition and the page lock
                    // release) runs in the device completion.
                    self.device.read_blocks_async(
                        Bid::new(u64::from(self.geom.raw_blkaddr) + idx as u64),
                        bio_segment,
                        Some(complete_fn),
                        io_batch,
                    )?;
                    Ok(())
                } else {
                    // The inline-tail page: idx == lastblk — the
                    // npages bound leaves exactly this one page
                    // beyond the flat region (a FLAT_PLAIN layout
                    // has npages == lastblk and never gets here; the
                    // tail length below is [1, bs] whenever the page
                    // is reachable, the size == 0 corner having
                    // npages == 0 and no page at all).
                    let tail_len = (self.geom.size - lastblk * bs) as usize;
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
                    // I2 passthrough: the device errno travels
                    // unfolded to the page-cache exit.
                    self.device.read_bytes(
                        self.geom.inline_data_start as usize,
                        &mut page_bytes[..tail_len],
                    )?;
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
            // TRANSITIONAL ARM (T-025 decomposition decision 4):
            // purpose — keep every chunk-based read failing
            // EOPNOTSUPP until the chunk mapping (M4–M7) lands;
            // removal — S04 replaces the mapping through the
            // map_blocks face and S05's four-arm rewrite of
            // submit_read_bio removes the last transitional
            // annotation. The main-column image family carries no
            // chunk-based inode, so behavior is unchanged meanwhile.
            Some(_) => {
                return_errno_with_message!(
                    Errno::EOPNOTSUPP,
                    "chunk-based mapping lands with the data-path task"
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

// ---------------------------------------------------------------------------
// The chunk-index record and the hole sentinel, migrated from
// inode/mod.rs (S01-D6, the T-011 IN0 pre-authorization): their only
// runtime consumers are the chunk-index/block-map reads of the map
// path (T-011 read points #8/#9, S04) — hosting them here keeps
// data.rs free of the forbidden L2→L3 edge (mod.rs would otherwise
// be re-imported for the read_val element type). The decode side
// keeps zero residual consumption (the chunk-layout decode goes
// through the i_u decomposition in mod.rs, and
// `AddrState::chunk_unit` reaches the record size through this
// module's path). The CHUNK_FORMAT constants and
// `RawInodeChunkInfo` stay in mod.rs (I10/D9/iloc consumers).
// ---------------------------------------------------------------------------

/// The erofs on-disk chunk index (`erofs_inode_chunk_index`,
/// linux/fs/erofs/erofs_fs.h:269-273; field semantics single-sourced
/// in `docs/T-001/analysis.md` §6.7).
///
/// The INDEXES=1 extent-area element, read element-wise through
/// `read_val` (the extent array itself is deliberately not wrapped
/// in a structure, U3). The INDEXES=0 sibling form is the bare
/// `__le32[]` block map, registered only through the
/// `BLOCK_MAP_ENTRY_SIZE` constant left in mod.rs — no structure is
/// fabricated for it either.
///
/// The source-side keep-in-sync assertion against
/// `z_erofs_lcluster_index` (erofs_fs.h:452-454) is deferred together
/// with the whole compression family (both sides of the comparison):
/// landing it now would dangle on an undefined type (the archive-C
/// compression domain, G-Z01).
// No deadness attribute: the permanent `const_assert!` layout anchors
// below reference the type and each of its 3 fields, so both stay
// live in every cfg and an `#[expect(dead_code)]` would only be
// reported unfulfilled (same rationale as the raw inode records in
// mod.rs).
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(super) struct RawInodeChunkIndex {
    /// "always 0, don't care for now" (source comment): carried
    /// without validation — a non-zero value is silently accepted.
    pub advise: u16, // @0 __le16
    /// The back-end storage id, masked at consumption:
    /// `roundup_pow_of_two(extra_devices + 1) - 1` — on a
    /// single-device volume the mask folds to 0 with no
    /// out-of-range error (consumption: T-025 S04).
    pub device_id: u16, // @2 __le16
    /// The start block address of this chunk. `== NULL_ADDR` means a
    /// hole (a zero read); otherwise the physical address is
    /// `blkaddr * blocksize`. No bounds check — a corrupted address
    /// only moves the read position or surfaces the device error
    /// (consumption: T-025 S04).
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

/// `EROFS_NULL_ADDR = -1` (erofs_fs.h:263): the chunk-index/block-map
/// value representing a zeroed chunk — a hole.
// First consumer: the hole semantics of the chunked map path
// (T-025 S04).
#[expect(dead_code)]
pub(super) const NULL_ADDR: u32 = u32::MAX;

#[cfg(ktest)]
mod tests {
    use align_ext::AlignExt;
    use ostd::prelude::*;

    use super::*;
    use crate::fs::fs_impls::erofs::{Erofs, test_utils::ktest_super_block};

    /// S01-IF-1 (anchor `docs/T-014/S01/index.md` §9): the capacity
    /// relation — the mod.rs capacity formula (`align_up(PAGE_SIZE)`)
    /// and the backend's canonical npages derivation
    /// (`div_ceil(PAGE_SIZE)`) are two pure expressions of the same
    /// canonical relation `capacity == npages * PAGE_SIZE`. The
    /// 2^63−1 corner also proves the align_up panic-freedom premise
    /// (S01 §3.2: overflow only past 2^64 − 4096).
    #[ktest]
    fn backend_npages_capacity_relation() {
        const SIZES: &[u64] = &[0, 1, 4095, 4096, (1u64 << 32) + 100, u64::MAX >> 1];
        for &size in SIZES {
            let capacity = (size as usize).align_up(PAGE_SIZE);
            let npages = size.div_ceil(PAGE_SIZE as u64);
            assert_eq!(
                capacity as u64,
                npages * PAGE_SIZE as u64,
                "size = {}",
                size
            );
        }
    }

    /// S01-IF-5 (anchor S01 §9): backend construction performs ZERO
    /// device I/O — the handle below carries the null device, so an
    /// accidental read on the construction path fails loudly here
    /// (the null device never fabricates bytes) instead of passing
    /// silently. The npages check pins the constructor-side bound
    /// against the canonical derivation.
    #[ktest]
    fn data_backend_constructs_without_io() {
        let fs = Erofs::ktest_new(ktest_super_block(12, 0));
        let geom = DataGeometry {
            // Three flat pages plus a 100-byte inline tail.
            size: 3 * PAGE_SIZE as u64 + 100,
            block_bits: 12,
            raw_blkaddr: 16,
            tail_inline: true,
            inline_data_start: 4096,
            chunk: None,
            compressed: false,
        };
        let backend = DataBackend::new(fs.self_ref().clone(), fs.block_device().clone(), geom, 4);
        assert_eq!(backend.npages, 4);
    }
}
