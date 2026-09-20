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
//! slices evolve this file in place: the map layer landed with S03
//! (`map_blocks` flat branches M1/M2 + the three-arm `map_dev` walk)
//! and grew its chunk branches with S04 (M4–M7) — neither consumed
//! by the minimal backend yet — and the four-arm submit_read_bio
//! rewrite — including the crafted-edge validation (e.g. the
//! "inline data across blocks" EFSCORRUPTED arm of data.c:103-108) —
//! lands with S05.
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

use align_ext::AlignExt;
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
///
/// Declared at erofs scope (`pub(in crate::fs::fs_impls::erofs)`,
/// the `DataBackend` form below): the ktest fixture face of these
/// names goes through the `inode/mod.rs` re-export, and a re-export
/// may not raise the item's own visibility (E0365).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::fs::fs_impls::erofs) struct DataGeometry {
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
/// Erofs-scoped like `DataGeometry` above (the same re-export seam).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::fs::fs_impls::erofs) struct ChunkGeometry {
    /// The extent-area element width: 8 (chunk indexes, the INDEXES
    /// bit) or 4 (the bare block-map entry) — the
    /// `AddrState::chunk_unit()` value evaluated in mod.rs.
    pub unit: usize,
    /// The chunk size shift in blocks: chunk size = `1 <<
    /// chunkbits` blocks (= sb.blkszbits + (format & 0x1F) at the
    /// decode).
    pub chunkbits: u32,
}

bitflags! {
    /// Outcome flags — the aster analog of `EROFS_MAP_*`
    /// (linux/fs/erofs/internal.h:315-328). The value bits mirror
    /// linux exactly for parity review. Only the two non-compressed
    /// bits exist under archive A; the compressed family (ENCODED
    /// 0x4 / FULL_MAPPED 0x8 / __FRAGMENT 0x10 / PARTIAL_REF 0x20)
    /// is revived together with the G-Z01 compressed branch.
    pub(super) struct MapFlags: u32 {
        /// Has a disk mapping (EROFS_MAP_MAPPED = 0x0001).
        const MAPPED = 0x0001;
        /// The payload lives in the inode metadata area
        /// (EROFS_MAP_META = 0x0002).
        const META = 0x0002;
    }
}

/// One non-compressed extent mapping — the aster analog of linux
/// `struct erofs_map_blocks` (internal.h:330-339). Not carried:
/// `buf`/`mpage` (no cross-call metabuf, S02-D1/D2) and
/// `m_algorithmformat` (set only by zmap, archive A).
// Dead-code ledger (staged landing): the S03 map layer constructs
// this record but only writes it — the field readers land with the
// S05 submit_read_bio dispatch (m_flags/m_pa/m_plen) and the S07
// DIO copy; until then the ktest assertions are the only readers
// and they are compiled out of regular builds. Struct-level rather
// than the per-field super_block.rs form because all six fields
// flip live at the same S05 milestone; the `cfg_attr` form keeps
// the ktest cfg clean of an unfulfilled `expect` (utils.rs
// precedent). The expect half fires `unfulfilled` once the first
// regular-build reader lands — the removal prompt.
#[cfg_attr(not(ktest), expect(dead_code))]
#[derive(Clone, Copy, Debug)]
pub(super) struct MapBlocks {
    /// Logical start. Input echo, except the CHUNK_BASED branch
    /// which aligns it down to the chunk boundary (data.c:150).
    pub m_la: u64,
    /// Extent logical length; on success always == m_plen (M8, the
    /// dual-role contract of `map_blocks`).
    pub m_llen: u64,
    /// Physical byte offset on the (pre-map_dev) device byte stream:
    /// MAPPED — data start; META — inline payload start; meaningless
    /// (deterministic 0) while MAPPED is unset.
    pub m_pa: u64,
    /// Mapped length (MAPPED/META) or hole length (post-EOF only).
    pub m_plen: u64,
    /// Device id (CHUNK 8B-index branch only; 0 elsewhere). Resolve
    /// via `map_dev` — never a raw device handle.
    pub m_deviceid: u16,
    /// Outcome trichotomy: MAPPED|META / MAPPED / empty.
    pub m_flags: MapFlags,
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
    // Live since T-025 S03: `upgrade_fs` reads it on every nonzero-id
    // map_dev walk, and since S04 on every chunk-8B mask fetch too.
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

    // -------------------------------------------------------------------
    // The map layer (T-025 S03/S04): the map_blocks flat + chunk
    // branches and the map_dev walk. Pure submit-context code — no
    // completion-context entry, no blocking locks (`&self` is
    // immutable post-construction).
    // -------------------------------------------------------------------

    /// Map one non-compressed extent covering logical offset `m_la`.
    ///
    /// # The `m_llen` dual-role contract (M8/I1)
    ///
    /// `m_llen` is both an input and part of the output:
    ///
    /// 1. *Input*: the caller's remaining window length. Only the
    ///    post-EOF branch consumes it (`m_plen = m_llen`,
    ///    data.c:124-129), so a query past EOF still reports how far
    ///    the unmapped hole extends.
    /// 2. *Output*: on success the returned `m_llen` is always set to
    ///    `m_plen` (data.c:182-183) — the extent covers
    ///    `[m_la, m_la + m_llen)`.
    /// 3. *No rollback on error*: an `Err` carries no partial mapping
    ///    (the linux "partial update, no rollback" note is satisfied
    ///    by value semantics; data.c error paths).
    /// 4. `m_la` is also an output: the CHUNK_BASED branch aligns it
    ///    down to the chunk boundary (data.c:150); the flat branches
    ///    echo the input.
    ///
    /// Passing `m_llen == 0` is legal but degenerate: the post-EOF
    /// branch then reports `m_plen == 0` (linux iomap patches this up
    /// at its own layer, data.c:318-319 — aster callers never pass
    /// 0).
    // Dead-code ledger (staged landing): the S03-IF suite below is
    // the only caller until the production consumers land (the S05
    // submit_read_bio rewrite, then S07 DIO / S08 read_at) — the
    // suite is compiled out of regular builds, so the map face needs
    // this root to stay lint-clean there. The `cfg_attr` form, not a
    // bare `expect`, because the ktest cfg keeps this item live and
    // a bare `expect` would only be reported unfulfilled there (the
    // utils.rs precedent). Root semantics: `MapBlocks` and
    // `map_blocks_flatmode` follow this item's liveness. The expect
    // half fires `unfulfilled` the moment the S05 consumer lands —
    // the removal prompt.
    #[cfg_attr(not(ktest), expect(dead_code))]
    pub(super) fn map_blocks(&self, m_la: u64, m_llen: u64) -> Result<MapBlocks> {
        // (a) Layer-3 defensive half (I12; S01-D3 bool snapshot) —
        //     the SINGLE carrying point of the compressed rejection:
        //     submit_read_bio does not repeat this gate (S03 §2.3).
        //     Structurally unreachable behind the assembly gate; kept
        //     as defense-in-depth (the F10/F11 family posture).
        if self.geom.compressed {
            // AUTO-TODO(G-Z01): The compressed mapping path (z_erofs_map_blocks_iter,
            // zmap.c) is deferred as a whole under archive A. Reviving it means
            // replacing this defensive rejection with the real compressed branch
            // here; until then the F10/F11 mount gates and the I12 assembly gate
            // keep this arm structurally unreachable.
            return_errno_with_message!(Errno::EOPNOTSUPP, "compressed inode data is not supported");
        }
        // (b) post-EOF: leave out-of-bound access unmapped
        //     (data.c:124-129). Structurally unreachable behind both
        //     current callers (they clamp below size) but kept for
        //     function-level parity and the fiemap/zmap revival
        //     consumers. m_plen consumes the dual-role input; m_pa
        //     and m_deviceid take the deterministic zeros (linux
        //     leaves stack residue there — unobservable, consumers
        //     never read m_pa while !MAPPED).
        if m_la >= self.geom.size {
            return Ok(MapBlocks {
                m_la,
                m_llen, // the echo equals m_plen (dual-role output)
                m_pa: 0,
                m_plen: m_llen,
                m_deviceid: 0, // the data.c:123 entry clear
                m_flags: MapFlags::empty(),
            });
        }
        // (c) layout dispatch (data.c:131-134): chunk.is_none()
        //     doubles as the flat discriminator. The debug assert is
        //     the DataGeometry field-validity domain (S01 §1.3): a
        //     CHUNK_BASED geometry never carries the flat tail bit —
        //     an API-misuse face, not an on-disk check.
        debug_assert!(self.geom.chunk.is_none() || !self.geom.tail_inline);
        match self.geom.chunk {
            None => self.map_blocks_flatmode(m_la),
            Some(cg) => self.map_blocks_chunked(m_la, cg),
        }
    }

    /// data.c:81-108 (`erofs_map_blocks_flatmode`) — the two flat
    /// states: FLAT_PLAIN (all-MAPPED) and FLAT_INLINE (the tail
    /// segment carries MAP_META). Pure geometry: no I/O and no
    /// chunk-table reads (S03-D4 — the helper split mirrors the
    /// linux function so the parity table anchors line up).
    fn map_blocks_flatmode(&self, m_la: u64) -> Result<MapBlocks> {
        // lastblk (data.c:87) with the erofs_blk_t = u32 domain
        // mirrored (S03-D5): erofs_iblks = ceil(size / bs) truncated
        // to u32, then the wrapping subtraction of the tail block —
        // crafted giant i_size (extended ≥ 2^44) traces linux
        // point-for-point (errno and branch both).
        let bs = 1u64 << self.geom.block_bits;
        let nblks = self.geom.size.div_ceil(bs);
        let lastblk = (nblks as u32).wrapping_sub(u64::from(self.geom.tail_inline) as u32);
        let lastblk_pos = (lastblk as u64) << self.geom.block_bits; // erofs_pos
        if m_la < lastblk_pos {
            // MAPPED segment (data.c:90-92): identity over
            // raw_blkaddr; plen reaches the block-rounded end and is
            // NOT clamped to i_size (the last-page tail zerofill duty
            // belongs to the backend consumers, G-P02). No hole
            // check either — flat inodes have none ("no hole in flat
            // inodes", data.c:89), and a crafted NULL_ADDR
            // raw_blkaddr reads through to the device error exactly
            // as in linux (no tightening, G-Z05 family discipline).
            let plen = lastblk_pos - m_la;
            Ok(MapBlocks {
                m_la,
                m_llen: plen,
                m_pa: (u64::from(self.geom.raw_blkaddr) << self.geom.block_bits) + m_la,
                m_plen: plen,
                m_deviceid: 0,
                m_flags: MapFlags::MAPPED,
            })
        } else {
            // Inline tail (data.c:93-105): the payload lives in the
            // inode's metadata area at inline_data_start +
            // blkoff(m_la) (the iloc + inode_isize + xattr_isize
            // prefix is collapsed into inline_data_start, T-013 §3.1
            // single source); the copy length clamps to i_size
            // naturally.
            debug_assert!(self.geom.tail_inline); // DBG_BUGON, data.c:94
            let m_pa = self.geom.inline_data_start + (m_la & (bs - 1));
            let m_plen = self.geom.size - m_la;
            // "inline data should be located in the same meta block"
            // (data.c:99-104): the cross-block defense — judgement,
            // errno, and timing (before any INLINE fetch) are
            // single-sourced HERE; the consumers (the S05 fill arm
            // and the S07 DIO copy) do not re-check.
            if (m_pa & (bs - 1)) + m_plen > bs {
                return_errno_with_message!(Errno::EUCLEAN, "inline data across blocks");
            }
            Ok(MapBlocks {
                m_la,
                m_llen: m_plen,
                m_pa,
                m_plen,
                m_deviceid: 0,
                // META always accompanies MAPPED (the data.c:105 |=).
                m_flags: MapFlags::MAPPED | MapFlags::META,
            })
        }
    }

    /// data.c:136-178 (`erofs_map_blocks`, CHUNK_BASED branch) — the
    /// chunk walk M4–M7. Unlike the flat helper this is not pure
    /// geometry: every call reads exactly one extent-area element
    /// through the metadata byte channel (the S03-D7 `read_val`
    /// single read point; linux reads one metabuf per call,
    /// data.c:145-149 — never a cached array, S02-D2).
    fn map_blocks_chunked(&self, m_la: u64, cg: ChunkGeometry) -> Result<MapBlocks> {
        // M4 (data.c:136-139): the INDEXES bit selects the
        // extent-area element width; aster carries it as
        // `ChunkGeometry.unit`, collapsed once by
        // `AddrState::chunk_unit` at the decode (the single INDEXES
        // knowledge point). The discrimination goes through
        // `size_of` (the C5 same-source form); the debug assert is
        // the unit validity domain — an API-misuse face, not an
        // on-disk check.
        debug_assert!(cg.unit == size_of::<RawInodeChunkIndex>() || cg.unit == size_of::<u32>());
        // M5 (data.c:141-143): the chunk number and the table
        // position — extent_base aligns the inline prefix up to the
        // element width, `unit * chunknr` walks the array.
        let chunknr = m_la >> cg.chunkbits;
        let pos = self.extent_base(cg.unit) + (cg.unit as u64) * chunknr;
        // The one table-element read of the whole walk, typed by the
        // unit: 4-byte block-map entries (#9) vs 8-byte chunk
        // indexes (#8, the S01-D6 record). The 8B form reads the
        // `advise` field (all 8 bytes land) but consumes it nowhere
        // — the RD2① read-granularity known-diff family. Errors
        // travel unfolded (C2): the framework byte-channel bound
        // answers EINVAL past the device end (RD2②). Linux reads
        // the element BEFORE the m_la write-back (data.c:145-149
        // before :150) — by-value output makes the order
        // unobservable, the placement keeps the trace.
        let (blkaddr, device_id) = if cg.unit == size_of::<u32>() {
            (
                u32::from_le(self.device.read_val::<u32>(pos as usize)?),
                0u16,
            )
        } else {
            let idx = self.device.read_val::<RawInodeChunkIndex>(pos as usize)?;
            (u32::from_le(idx.blkaddr), u16::from_le(idx.device_id))
        };
        // M5 (data.c:150-152): the chunk-aligned m_la write-back —
        // the output m_la may sit BELOW the query la; consumers
        // recover the in-extent offset as `query_la − m_la`. Then
        // the last-chunk clamp: `size − chunk_la` cannot underflow
        // (chunk_la ≤ m_la < size — the post-EOF guard ran first),
        // and align_up is linux round_up (the same formula). The
        // extent is always a whole-block multiple — a chunk extent
        // never has a sub-block tail (§4.6), so last-page zerofill
        // stays a backend duty (G-P02).
        let chunk_la = chunknr << cg.chunkbits;
        let m_plen = (1u64 << cg.chunkbits)
            .min((self.geom.size - chunk_la).align_up(1u64 << self.geom.block_bits));
        // M6/M7 (data.c:155-178): the shared NULL_ADDR predicate —
        // linux's `default:` arm means "non-NULL maps", there is no
        // third state.
        if blkaddr == NULL_ADDR {
            // Hole: flags empty, m_pa/m_deviceid the deterministic
            // zeros (linux leaves residue — unobservable, consumers
            // never read m_pa while !MAPPED).
            return Ok(MapBlocks {
                m_la: chunk_la,
                m_llen: m_plen,
                m_pa: 0,
                m_plen,
                m_deviceid: 0,
                m_flags: MapFlags::empty(),
            });
        }
        // M6 (4B block map): no device_id field exists — the C5
        // single-volume fold keeps m_deviceid structurally 0. M7
        // (8B chunk index): `device_id & mask` (data.c:173-174),
        // the mask fetched through the fs upgrade so the
        // DeviceTable stays the single source (S03-D8; mask == 0
        // folds every id to the primary device — the MD7
        // silent-drop mechanism itself, pure arithmetic, no branch).
        // The `as u16` mirrors the C assignment truncation
        // (m_deviceid is u16); production masks never exceed
        // 0xFFFF (extra_devices is 16-bit on disk).
        let m_deviceid = if cg.unit == size_of::<u32>() {
            0
        } else {
            (u32::from(device_id) & self.device_id_mask()?) as u16
        };
        Ok(MapBlocks {
            m_la: chunk_la,
            m_llen: m_plen,
            m_pa: u64::from(blkaddr) << self.geom.block_bits,
            m_plen,
            m_deviceid,
            m_flags: MapFlags::MAPPED,
        })
    }

    /// The extent-area base point of a CHUNK_BASED inode (T-011
    /// §5.2): `ALIGN(iloc + inode_isize + xattr_isize, unit)`
    /// (data.c:142-143) — the inline prefix already collapsed into
    /// `geom.inline_data_start`, rounded up to the element width.
    ///
    /// Computed on every mapping (S03-D6): one align_up is
    /// noise-level next to the channel read each chunk mapping
    /// already performs, so the geometry field face stays at the
    /// §1.1 bound (no cached field).
    fn extent_base(&self, unit: usize) -> u64 {
        self.geom.inline_data_start.align_up(unit as u64)
    }

    /// The chunk-id validity mask (super.c:242), fetched through the
    /// fs upgrade so the DeviceTable stays its single source
    /// (S03-D8 — a geometry snapshot would be sb-level state posing
    /// as desc-derived, a double source). One `Weak::upgrade` per
    /// chunk-8B mapping is noise next to the channel read (W-P02
    /// family note, no acceptance).
    fn device_id_mask(&self) -> Result<u32> {
        Ok(self.upgrade_fs()?.device_table().device_id_mask())
    }

    /// Resolve a mapped extent onto the primary device byte stream.
    ///
    /// Takes the `(m_pa, m_deviceid)` pair produced by `map_blocks`
    /// and returns the physical byte offset to read on the primary
    /// device (`self.device`) — the aster analog of linux
    /// `erofs_map_dev` (data.c:188-237), projected onto the two
    /// reachable device-table forms:
    ///
    /// - `m_deviceid == 0`: primary device — identity (linux sets
    ///   `m_bdev = sb->s_bdev` at entry and skips the table).
    /// - `m_deviceid != 0` (flatdev images only: a nonzero id
    ///   requires `device_id_mask != 0`): 1-based slot lookup;
    ///   `None` → `ENODEV` (the linux idr_find miss, data.c:209-213).
    ///   A hit translates `m_pa += mapped_blkaddr << block_bits` and
    ///   STILL reads the primary device — the flatdev deployment
    ///   contract assumes the slot content physically follows the
    ///   primary image (MD13 trust semantics: no capacity
    ///   cross-check, no per-slot bounds check).
    ///
    /// The returned offset may lie past the primary device end on
    /// crafted images; the error then comes from the device stack of
    /// whichever channel the consumer uses and passes through
    /// unchanged (never re-mapped here).
    ///
    /// # Composition contract (I2)
    ///
    /// Every consumer of `MapBlocks.m_pa` calls this exactly once
    /// after `map_blocks` and before dispatching on `m_flags` — the
    /// linux `erofs_iomap_begin` shape (data.c:298-302). This
    /// includes the META state (linux reads its metabuf at the
    /// resolved pa, data.c:328) and, vacuously, the empty state
    /// (holes keep `m_deviceid == 0`, so the call is the identity
    /// and the pa is unused).
    // Dead-code ledger (staged landing, same form as `map_blocks`
    // above): ktest-suite-only caller until S05/S07/S08; the
    // `cfg_attr` form keeps the ktest cfg clean of an unfulfilled
    // `expect`. Root semantics: `upgrade_fs` below, the `fs` field it
    // reads, and the `Erofs::device_table` / `DeviceTable::flatdev`
    // / `slot` accessors (fs.rs) all follow this item's liveness in
    // regular builds. The expect half fires `unfulfilled` when the
    // first production consumer lands — the removal prompt.
    #[cfg_attr(not(ktest), expect(dead_code))]
    pub(super) fn map_dev(&self, m_pa: u64, m_deviceid: u16) -> Result<u64> {
        // AUTO-TODO(G-M16): Linux sets the backing device's logical block size
        // at mount and switches to a larger one when the superblock demands it
        // (F3/F5). The aster block layer has no logical-block-size concept
        // (`BlockDeviceMeta` carries no such field), so both steps are statically
        // cut and this mapping is the identity onto the single backing device.
        // If a framework logical block size is ever added (candidate W-P05,
        // gated on a G-P01 upgrade), re-evaluate this row in the same batch —
        // including the 4k-only gate (AR-S01-1), under which no switch step has
        // semantics.
        // Multi-device revival note (U3; W-O02 / G-M13 mount half): the
        // non-flatdev arms of linux erofs_map_dev — selecting a per-device
        // bdev for a nonzero device id, and the mapped_blkaddr interval
        // fallback for id-less mappings — are structurally unreachable here:
        // any mounted device table with extra devices is flatdev (a
        // count-matching `device=` mount is rejected at scan time, G-M13).
        // Reviving true multi-device means returning a per-slot device handle
        // from this function and adding the interval arm; re-evaluate in the
        // same batch as the mount-side rejection.
        //
        // (a) Primary device: identity. data.c:206-207 — m_bdev is
        //     s_bdev (primary) at entry and `if (map->m_deviceid)` is
        //     the only dispatch key; id 0 never consults the table
        //     and never upgrades the fs handle (data.c:207 before
        //     :208) — the single-volume hot path touches neither the
        //     Weak nor the DeviceTable.
        if m_deviceid == 0 {
            return Ok(m_pa);
        }
        // (b) Nonzero id — flatdev images only (data.c:208-213): the
        //     1-based slot lookup (idr_find(tree, id − 1)); a miss is
        //     ENODEV, reachable only through the crafted over-supply
        //     mask corner (extra=2, mask=3, id=3) — parity, not drift
        //     (linux idr_find returns NULL on the same input).
        let fs = self.upgrade_fs()?;
        let Some((_blocks, mapped_blkaddr)) = fs.device_table().slot(u32::from(m_deviceid)) else {
            return_errno_with_message!(Errno::ENODEV, "device id not found in the device table");
        };
        // (c) flatdev translation (data.c:214-218): still reads the
        //     PRIMARY device — the linux branch returns before any
        //     per-device fill, and aster returns the pure offset
        //     while consumers structurally read `self.device`. The
        //     slot `blocks` value is not consumed here (its only
        //     consumers are the statfs accumulation and the
        //     unreachable MD12 interval scan).
        debug_assert!(fs.device_table().flatdev()); // slots hit ⇒ flatdev
        // erofs_pos(sb, blk) = blk << blkszbits (internal.h:221).
        Ok(m_pa + (u64::from(mapped_blkaddr) << self.geom.block_bits))
    }

    /// Upgrade the weak fs handle to the live `Erofs` instance.
    ///
    /// Defensive-only: inode-cache strong references outlive every
    /// DataBackend consumer (S01 §1.5), so failure is unreachable;
    /// the EIO guard follows the family form (the ext2 block-manager
    /// and Inode::fs precedents). Shared by `map_dev` and the
    /// chunk-8B mask fetch (S04-D5).
    fn upgrade_fs(&self) -> Result<Arc<Erofs>> {
        self.fs
            .upgrade()
            .ok_or_else(|| Error::with_message(Errno::EIO, "filesystem already dropped"))
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
        //
        // TRANSITIONAL DUPLICATION (T-025 S03): the single carrying
        // point of this rejection is `map_blocks` (a) since S03;
        // this minimal face does not call the map layer yet, so the
        // gate stays duplicated here until the S05 four-arm rewrite
        // routes submit_read_bio through map_blocks and removes this
        // copy (S03 §2.3's single-point declaration).
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
            // purpose — the map layer has carried the real chunk
            // walk since S04, but this minimal face still bypasses
            // it, so every chunk-based read keeps failing
            // EOPNOTSUPP here; removal — S05's four-arm rewrite of
            // submit_read_bio routes this face through map_blocks.
            // The main-column image family carries no chunk-based
            // inode, so behavior is unchanged meanwhile.
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
// Live since T-025 S04: the hole predicate of the chunked walk —
// both the 4B block-map and the 8B chunk-index arms (data.c:157/168).
pub(super) const NULL_ADDR: u32 = u32::MAX;

#[cfg(ktest)]
mod tests {
    use align_ext::AlignExt;
    use ostd::prelude::*;

    use super::*;
    use crate::fs::fs_impls::erofs::{
        Erofs,
        fs::DeviceTable,
        test_utils::{
            ErofsMemoryDisk, ktest_data_geometry, ktest_flat_geometry, ktest_flatdev_table,
            ktest_fs_on, ktest_single_device_table, ktest_super_block,
        },
    };

    /// A flat-geometry backend over a device-less handle (S03-D4: the
    /// flat arm is pure geometry, so the null device makes any
    /// accidental I/O fail loudly here).
    fn ktest_null_backend(geom: DataGeometry) -> DataBackend {
        let fs = Erofs::ktest_new(ktest_super_block(12, 0));
        let npages = geom.size.div_ceil(PAGE_SIZE as u64) as usize;
        DataBackend::new(
            fs.self_ref().clone(),
            fs.block_device().clone(),
            geom,
            npages,
        )
    }

    /// A chunked-geometry backend over a fresh memory disk and the
    /// given device table (the S03-IF-5/6/9 fixture form): the disk
    /// comes back for table staging (two pages — the extent areas
    /// sit past the 4 KiB mark to exercise the align_up), the fs
    /// handle must outlive the queries (the 8B mask fetch upgrades
    /// the Weak).
    fn ktest_chunk_backend(
        table: DeviceTable,
        size: u64,
        unit: usize,
        chunkbits: u32,
        inline_data_start: u64,
    ) -> (Arc<ErofsMemoryDisk>, Arc<Erofs>, DataBackend) {
        let disk = Arc::new(ErofsMemoryDisk::new(2 * PAGE_SIZE));
        let fs = ktest_fs_on(disk.clone(), ktest_super_block(12, 0), table);
        let geom = ktest_data_geometry(
            size,
            12,
            0,
            false,
            inline_data_start,
            Some(ChunkGeometry { unit, chunkbits }),
            false,
        );
        let npages = size.div_ceil(PAGE_SIZE as u64) as usize;
        let backend = DataBackend::new(
            fs.self_ref().clone(),
            fs.block_device().clone(),
            geom,
            npages,
        );
        (disk, fs, backend)
    }

    /// Stages one 8-byte chunk-index record at `pos` in the little-
    /// endian on-disk form (`advise`, `device_id`, `blkaddr`) — the
    /// bytes `read_val::<RawInodeChunkIndex>` parses back.
    fn stage_chunk_index(
        disk: &ErofsMemoryDisk,
        pos: usize,
        advise: u16,
        device_id: u16,
        blkaddr: u32,
    ) {
        let mut bytes = [0u8; 8];
        bytes[..2].copy_from_slice(&advise.to_le_bytes());
        bytes[2..4].copy_from_slice(&device_id.to_le_bytes());
        bytes[4..].copy_from_slice(&blkaddr.to_le_bytes());
        disk.stage_bytes(pos, &bytes);
    }

    /// S03-IF-1/S03-IF-10 (anchor `docs/T-014/S03/index.md` §10): the
    /// MAPPED-formula grid over size × la — non-block-aligned sizes,
    /// sub-block sizes, the exact block, multi-block, and the
    /// FLAT_INLINE flat region — plus the M8 exit invariant
    /// (`m_llen == m_plen` on every success) and the no-i_size-clamp
    /// pin (plen reaches the block-rounded end).
    #[ktest]
    fn map_blocks_flat_mapped_grid() {
        const BS: u64 = 4096;
        // (size, tail_inline, raw_blkaddr)
        let cases: &[(u64, bool, u32)] = &[
            (1, false, 16), // size < bs
            (100, false, 16),
            (4095, false, 7),         // one byte short of the block
            (4096, false, 7),         // the exact block
            (4097, false, 7),         // one byte past → two blocks
            (3 * BS + 100, true, 16), // FLAT_INLINE: 3 flat blocks + tail
            (16 * BS, false, 32),     // multi-block exact
        ];
        let las = |size: u64, lastblk_pos: u64| {
            vec![0, 1, BS - 1, BS, lastblk_pos - 1]
                .into_iter()
                .filter(move |&la| la < lastblk_pos && la < size)
                .chain(
                    [lastblk_pos / 2]
                        .into_iter()
                        .filter(move |&la| la < lastblk_pos && la < size),
                )
        };
        for &(size, tail_inline, raw) in cases {
            let geom = ktest_data_geometry(size, 12, raw, tail_inline, 0, None, false);
            let backend = ktest_null_backend(geom);
            let lastblk_pos = size.div_ceil(BS).wrapping_sub(u64::from(tail_inline)) << 12;
            for la in las(size, lastblk_pos) {
                let m = backend.map_blocks(la, PAGE_SIZE as u64).unwrap();
                assert_eq!(m.m_flags, MapFlags::MAPPED, "size={size} la={la}");
                assert_eq!(m.m_la, la, "la echo, size={size} la={la}");
                assert_eq!(
                    m.m_pa,
                    ((raw as u64) << 12) + la,
                    "pa formula, size={size} la={la}"
                );
                assert_eq!(
                    m.m_plen,
                    lastblk_pos - la,
                    "plen formula, size={size} la={la}"
                );
                assert_eq!(m.m_llen, m.m_plen, "M8, size={size} la={la}");
                assert_eq!(m.m_deviceid, 0, "size={size} la={la}");
            }
            // The no-clamp pin: the last MAPPED extent of a partial
            // final block reaches past i_size to the block end.
            // FLAT_PLAIN only — the inline family is excluded: its
            // flat MAPPED segment ends at lastblk_pos < i_size by
            // construction (the tail block is the META extent, not
            // part of the flat run), so the pin is vacuous there.
            if size % BS != 0 && !tail_inline {
                let m = backend.map_blocks(0, PAGE_SIZE as u64).unwrap();
                assert!(
                    m.m_plen > size,
                    "plen must not clamp to i_size (size={size})"
                );
            }
        }
    }

    /// S03-IF-2 (anchor S03 §10): the FLAT_INLINE tail in its normal
    /// state — `blkoff(m_pa) + m_plen ≤ bs` — pointwise over the tail
    /// region: flags MAPPED|META, pa = inline_data_start +
    /// blkoff(la), plen = llen = size − la (the i_size clamp).
    #[ktest]
    fn map_blocks_flat_inline_tail() {
        const BS: u64 = 4096;
        // 3 flat blocks + a 100-byte tail; the inline area starts
        // 2000 bytes into its metadata block.
        let geom = ktest_data_geometry(3 * BS + 100, 12, 16, true, BS + 2000, None, false);
        let backend = ktest_null_backend(geom);
        for la in [3 * BS, 3 * BS + 1, 3 * BS + 37, 3 * BS + 99] {
            let m = backend.map_blocks(la, PAGE_SIZE as u64).unwrap();
            assert_eq!(m.m_flags, MapFlags::MAPPED | MapFlags::META, "la={la}");
            assert_eq!(m.m_pa, (BS + 2000) + (la - 3 * BS), "pa formula, la={la}");
            assert_eq!(
                m.m_plen,
                3 * BS + 100 - la,
                "plen clamps to i_size, la={la}"
            );
            assert_eq!(m.m_llen, m.m_plen, "M8, la={la}");
            assert_eq!(m.m_deviceid, 0, "la={la}");
        }
    }

    /// S03-IF-3: the cross-block EUCLEAN defense — crafted
    /// geometries whose inline tail would straddle a block boundary
    /// are rejected before any fetch; the exact boundary
    /// (`blkoff(m_pa) + m_plen == bs`) still maps.
    #[ktest]
    fn map_blocks_inline_cross_block_euclean() {
        const BS: u64 = 4096;
        // Tail spans [8192, 8292); inline area at blkoff 4000.
        let geom = ktest_data_geometry(2 * BS + 100, 12, 16, true, BS + 4000, None, false);
        let backend = ktest_null_backend(geom);
        // la=8192: pa blkoff 4000 + plen 100 > 4096.
        let err = backend.map_blocks(2 * BS, PAGE_SIZE as u64).unwrap_err();
        assert_eq!(err.error(), Errno::EUCLEAN);
        // la=8282 (blkoff 90): plen 10; 4000 + 90 + 10 > 4096.
        let err = backend
            .map_blocks(2 * BS + 90, PAGE_SIZE as u64)
            .unwrap_err();
        assert_eq!(err.error(), Errno::EUCLEAN);

        // The exact boundary maps: inline area at blkoff 3996 —
        // la=8192 gives 3996 + 100 == 4096.
        let geom = ktest_data_geometry(2 * BS + 100, 12, 16, true, BS + 3996, None, false);
        let backend = ktest_null_backend(geom);
        let m = backend.map_blocks(2 * BS, PAGE_SIZE as u64).unwrap();
        assert_eq!(m.m_flags, MapFlags::MAPPED | MapFlags::META);
        assert_eq!(m.m_plen, 100);
        // And the deepest legal query still fits: la=8288 (blkoff 96),
        // plen 4 → 3996 + 96 + 4 == 4096.
        let m = backend.map_blocks(2 * BS + 96, PAGE_SIZE as u64).unwrap();
        assert_eq!(m.m_plen, 4);
    }

    /// S03-IF-4: post-EOF queries stay unmapped — flags empty,
    /// `m_plen` consumes the dual-role input, la/llen echo, and
    /// m_pa/m_deviceid take the deterministic zeros — over three
    /// llen magnitudes.
    #[ktest]
    fn map_blocks_post_eof_unmapped() {
        let geom = ktest_flat_geometry(4096, 16, false, 0);
        let backend = ktest_null_backend(geom);
        for la in [4096u64, 5000, 1 << 40] {
            for llen in [1u64, 4096, 1 << 40] {
                let m = backend.map_blocks(la, llen).unwrap();
                assert_eq!(m.m_flags, MapFlags::empty(), "la={la} llen={llen}");
                assert_eq!(m.m_la, la, "la echo, la={la} llen={llen}");
                assert_eq!(m.m_llen, llen, "llen echo, la={la} llen={llen}");
                assert_eq!(
                    m.m_plen, llen,
                    "plen consumes the input, la={la} llen={llen}"
                );
                assert_eq!(m.m_pa, 0, "la={la} llen={llen}");
                assert_eq!(m.m_deviceid, 0, "la={la} llen={llen}");
            }
        }
    }

    /// S03-IF-7: the lastblk u32-truncation mirror (erofs_blk_t =
    /// u32; the S03-D5 family of T-013 S05-D4). Live pins:
    /// (a) FLAT_INLINE size = 2^44 + 100, la = 100 — the truncated
    ///     lastblk_pos collapses to 0, so the query falls into the
    ///     inline-tail else branch and the giant m_plen (2^44)
    ///     trips the cross-block guard: EUCLEAN, exactly the linux
    ///     production trace (a u64 general form would instead
    ///     return MAPPED here — this is the distinguishing case);
    /// (b) the design's second corner: la = size − 10 maps META with
    ///     plen = 10 through the same truncated walk;
    /// (c) the FLAT_PLAIN size = 2^44 corner: the arithmetic
    ///     precondition (lastblk truncates to 0, so la = 0 selects
    ///     the else branch). Driving it live would hit the B3
    ///     `debug_assert!(tail_inline)` mirror first — the same
    ///     trace as a CONFIG_EROFS_FS_DEBUG Linux (DBG_BUGON,
    ///     internal.h:35-36); the production (release) route to
    ///     EUCLEAN through the same guard is live-pinned by (a).
    #[ktest]
    fn map_blocks_lastblk_u32_truncation_mirror() {
        const BS: u64 = 4096;
        let size = (1u64 << 44) + 100;
        let geom = ktest_data_geometry(size, 12, 16, true, BS, None, false);
        let backend = ktest_null_backend(geom);
        // (a) nblks = 2^32 + 1 → (u32) = 1 → lastblk = 1 − 1 = 0 →
        // else branch with m_plen = 2^44 → EUCLEAN.
        let err = backend.map_blocks(100, PAGE_SIZE as u64).unwrap_err();
        assert_eq!(err.error(), Errno::EUCLEAN);
        // (b) la = size − 10: blkoff(la) = 90, plen = 10 → META.
        let m = backend.map_blocks(size - 10, PAGE_SIZE as u64).unwrap();
        assert_eq!(m.m_flags, MapFlags::MAPPED | MapFlags::META);
        assert_eq!(m.m_pa, BS + 90);
        assert_eq!(m.m_plen, 10);
        assert_eq!(m.m_llen, m.m_plen);
        // (c) FLAT_PLAIN size = 2^44: nblks = 2^32 → (u32) = 0 →
        // lastblk_pos = 0, so la = 0 would select the else branch
        // (the branch-selection precondition, asserted arithmetically
        // here since the debug-build B3 mirror fires first in that
        // corner).
        let nblks = (1u64 << 44).div_ceil(BS);
        let lastblk = (nblks as u32).wrapping_sub(0);
        assert_eq!(lastblk, 0);
        assert!(!(0u64 < (lastblk as u64) << 12));
    }

    /// S03-IF-8: the compressed defense on the bypass form — a
    /// geometry with the snapshot still true (past the I12 assembly
    /// gate) is rejected EOPNOTSUPP, and the guard precedes the
    /// post-EOF branch (a compressed query at la ≥ size still gets
    /// EOPNOTSUPP — aster's own guard order).
    #[ktest]
    fn map_blocks_compressed_defense() {
        let geom = ktest_data_geometry(4096, 12, 16, false, 0, None, true);
        let backend = ktest_null_backend(geom);
        let err = backend.map_blocks(0, PAGE_SIZE as u64).unwrap_err();
        assert_eq!(err.error(), Errno::EOPNOTSUPP);
        // Guard order: even a post-EOF la sees the compressed arm.
        let err = backend.map_blocks(1 << 40, PAGE_SIZE as u64).unwrap_err();
        assert_eq!(err.error(), Errno::EOPNOTSUPP);
    }

    /// S03-IF-5 (anchor `docs/T-014/S03/index.md` §10): the chunk 4B
    /// block-map arm — NULL_ADDR → hole (flags empty, deterministic
    /// zeros), blkaddr → MAPPED (pa = blkaddr << bsb), the
    /// chunk-aligned m_la write-back (a mid-chunk query la maps from
    /// the chunk start), and the last-chunk clamp of m_plen; the 8B
    /// layout run over the SAME chunk slots must produce the
    /// identical mapping (the same-slot comparison half; only the
    /// extent-area encoding differs).
    #[ktest]
    fn map_blocks_chunk_4b_block_map() {
        const BS: u64 = 4096;
        const CHUNK: u64 = 2 * BS; // chunkbits = 13
        // inline_data_start = 4000 is 4-misaligned: extent_base(4) =
        // 4004 (the IF-9 unaligned corner rides along).
        let (disk, _fs, backend) =
            ktest_chunk_backend(ktest_single_device_table(), 5 * BS + 100, 4, 13, 4000);
        // Table: chunk 0 → block 100, chunk 1 → hole, chunk 2 →
        // block 200.
        disk.stage_bytes(4004, &100u32.to_le_bytes());
        disk.stage_bytes(4008, &NULL_ADDR.to_le_bytes());
        disk.stage_bytes(4012, &200u32.to_le_bytes());

        // TEMP S04 DIAGNOSTIC — remove once the fixture defect is
        // located: the staged bytes, the channel read-back, and the
        // request log, all in one panic message.
        {
            let mut raw = [0u8; 24];
            disk.segment().read_bytes(3992, &mut raw).unwrap();
            let dev: Arc<dyn BlockDevice> = disk.clone();
            let mut ch = [0u8; 4];
            dev.read_bytes(4004, &mut ch).unwrap();
            let val = dev.read_val::<u32>(4004).unwrap();
            panic!(
                "DIAG raw[3992..4016]={raw:02x?} ch[4004..]={ch:02x?} val={val} reqs={:?}",
                disk.requests()
            );
        }

        // MAPPED over chunk 0: la 0, a mid-chunk la, and the last
        // byte of the chunk all share chunknr 0 — the write-back
        // moves m_la below every query la but 0.
        for la in [0u64, 100, CHUNK - 1] {
            let m = backend.map_blocks(la, PAGE_SIZE as u64).unwrap();
            assert_eq!(m.m_flags, MapFlags::MAPPED, "la={la}");
            assert_eq!(m.m_la, 0, "chunk-aligned write-back, la={la}");
            assert_eq!(m.m_pa, 100 << 12, "pa formula, la={la}");
            assert_eq!(m.m_plen, CHUNK, "plen = the chunk length, la={la}");
            assert_eq!(m.m_llen, m.m_plen, "M8, la={la}");
            assert_eq!(m.m_deviceid, 0, "no device_id field (C5), la={la}");
        }
        // Hole over chunk 1: flags empty, the zeros, and the SAME
        // chunk-long plen (the hole still spans the whole chunk).
        for la in [CHUNK, CHUNK + 37] {
            let m = backend.map_blocks(la, PAGE_SIZE as u64).unwrap();
            assert_eq!(m.m_flags, MapFlags::empty(), "la={la}");
            assert_eq!(m.m_la, CHUNK, "write-back, la={la}");
            assert_eq!(m.m_plen, CHUNK, "hole spans the chunk, la={la}");
            assert_eq!(m.m_llen, m.m_plen, "M8, la={la}");
            assert_eq!(m.m_pa, 0, "la={la}");
            assert_eq!(m.m_deviceid, 0, "la={la}");
        }
        // The last chunk: the remainder 4106 rounds up to exactly
        // one chunk — no clamp here.
        let m = backend
            .map_blocks(2 * CHUNK + 37, PAGE_SIZE as u64)
            .unwrap();
        assert_eq!(m.m_flags, MapFlags::MAPPED);
        assert_eq!(m.m_la, 2 * CHUNK);
        assert_eq!(m.m_pa, 200 << 12);
        assert_eq!(m.m_plen, CHUNK);
        assert_eq!(m.m_llen, m.m_plen);

        // The last-chunk clamp (chunkbits = 14 → 4-block chunks,
        // extent_base at an aligned 4100): the final chunk of the
        // same size carries only 4106 bytes → m_plen clamps to the
        // block-rounded remainder 8192 < 16384, while chunk 0 keeps
        // the full chunk length.
        let (disk, _fs, big) =
            ktest_chunk_backend(ktest_single_device_table(), 5 * BS + 100, 4, 14, 4100);
        disk.stage_bytes(4100, &100u32.to_le_bytes());
        disk.stage_bytes(4104, &200u32.to_le_bytes());
        let m = big.map_blocks(0, PAGE_SIZE as u64).unwrap();
        assert_eq!(m.m_plen, 4 * BS, "an interior chunk keeps the full length");
        let m = big.map_blocks(4 * BS, PAGE_SIZE as u64).unwrap();
        assert_eq!(m.m_flags, MapFlags::MAPPED);
        assert_eq!(m.m_la, 4 * BS);
        assert_eq!(m.m_pa, 200 << 12);
        assert_eq!(m.m_plen, 2 * BS, "the last chunk clamps to round_up(4106)");
        assert_eq!(m.m_llen, m.m_plen);

        // The same-slot 8B comparison: identical chunk slots through
        // the 8-byte index encoding (ids 4000 is 8-aligned — a
        // different extent base than the 4B run, the mapping must
        // not care).
        let (disk, _fs, indexed) =
            ktest_chunk_backend(ktest_single_device_table(), 5 * BS + 100, 8, 13, 4000);
        stage_chunk_index(&disk, 4000, 0, 0, 100);
        stage_chunk_index(&disk, 4008, 0, 0, NULL_ADDR);
        stage_chunk_index(&disk, 4016, 0, 0, 200);
        for la in [0u64, 100, CHUNK - 1, CHUNK, CHUNK + 37, 2 * CHUNK + 37] {
            let four = backend.map_blocks(la, PAGE_SIZE as u64).unwrap();
            let eight = indexed.map_blocks(la, PAGE_SIZE as u64).unwrap();
            assert_eq!(eight.m_flags, four.m_flags, "same-slot parity, la={la}");
            assert_eq!(eight.m_la, four.m_la, "la={la}");
            assert_eq!(eight.m_pa, four.m_pa, "la={la}");
            assert_eq!(eight.m_plen, four.m_plen, "la={la}");
            assert_eq!(eight.m_llen, four.m_llen, "la={la}");
            assert_eq!(eight.m_deviceid, four.m_deviceid, "la={la}");
        }
    }

    /// S03-IF-6 (anchor S03 §10): the chunk 8B index arm — NULL →
    /// hole regardless of the device id; a value → MAPPED with
    /// `m_deviceid = device_id & mask`: mask = 0 silently folds
    /// every id onto the primary device (MD7 — the mechanism is the
    /// arithmetic itself, no branch), mask ≠ 0 keeps the masked
    /// value (the flatdev extra=1 → mask=1 form). The `advise`
    /// field is staged non-zero in one entry and must not disturb
    /// anything (read, never consumed — RD2①).
    #[ktest]
    fn map_blocks_chunk_8b_device_mask() {
        const CHUNK: u64 = 2 * 4096;
        // mask = 0 (single-device table): ids 7 and 5 both fold to 0.
        let (disk, _fs, backend) =
            ktest_chunk_backend(ktest_single_device_table(), 3 * CHUNK, 8, 13, 4000);
        stage_chunk_index(&disk, 4000, 0, 7, 10);
        stage_chunk_index(&disk, 4008, 0, 7, NULL_ADDR);
        stage_chunk_index(&disk, 4016, 0, 5, 20);
        let m = backend.map_blocks(0, PAGE_SIZE as u64).unwrap();
        assert_eq!(m.m_flags, MapFlags::MAPPED);
        assert_eq!(m.m_deviceid, 0, "mask=0 folds id 7 onto the primary device");
        assert_eq!(m.m_pa, 10 << 12);
        // NULL wins over any device id: the hole arm.
        let m = backend.map_blocks(CHUNK, PAGE_SIZE as u64).unwrap();
        assert_eq!(m.m_flags, MapFlags::empty());
        assert_eq!(m.m_deviceid, 0);
        assert_eq!(m.m_plen, CHUNK);
        let m = backend.map_blocks(2 * CHUNK, PAGE_SIZE as u64).unwrap();
        assert_eq!(m.m_deviceid, 0, "mask=0 folds id 5");
        assert_eq!(m.m_pa, 20 << 12);
        assert_eq!(m.m_llen, m.m_plen);

        // mask = 1 (flatdev extra=1): the masked values ride along
        // for map_dev to resolve later.
        let table = ktest_flatdev_table(&[(10, 100)], 1);
        let (disk, _fs, backend) = ktest_chunk_backend(table, 4 * CHUNK, 8, 13, 4000);
        stage_chunk_index(&disk, 4000, 0, 1, 10); // 1 & 1 = 1
        stage_chunk_index(&disk, 4008, 0, 5, 20); // 5 & 1 = 1
        stage_chunk_index(&disk, 4016, 0, 2, 30); // 2 & 1 = 0
        stage_chunk_index(&disk, 4024, 3, 3, 40); // 3 & 1 = 1, advise ignored
        for (la, want_id, want_pa) in [
            (0u64, 1u16, 10u64 << 12),
            (CHUNK, 1, 20 << 12),
            (2 * CHUNK, 0, 30 << 12),
            (3 * CHUNK, 1, 40 << 12),
        ] {
            let m = backend.map_blocks(la, PAGE_SIZE as u64).unwrap();
            assert_eq!(m.m_flags, MapFlags::MAPPED, "la={la}");
            assert_eq!(m.m_deviceid, want_id, "la={la}");
            assert_eq!(m.m_pa, want_pa, "la={la}");
            assert_eq!(m.m_llen, m.m_plen, "M8, la={la}");
        }
    }

    /// S03-IF-9 (anchor S03 §10): the extent-area base point —
    /// `align_up(inline_data_start, unit)` over the {misaligned,
    /// aligned} × {unit 4, 8} grid, both as the pure helper formula
    /// and wired through the chunk branch: the candidate area is
    /// 0xFF-filled (any base drift reads 0xFF… = NULL_ADDR and maps
    /// a hole), sentinels land only at `base + unit × chunknr`, so
    /// a MAPPED hit proves the exact entry position — chunknr
    /// scaling included.
    #[ktest]
    fn map_blocks_chunk_extent_base_grid() {
        // The pure formula: 4002 is misaligned for both widths,
        // 4008 is aligned for both.
        for (ids, unit, want) in [
            (4002u64, 4usize, 4004u64),
            (4002, 8, 4008),
            (4008, 4, 4008),
            (4008, 8, 4008),
        ] {
            let geom = ktest_data_geometry(
                3 * 2 * 4096,
                12,
                0,
                false,
                ids,
                Some(ChunkGeometry {
                    unit,
                    chunkbits: 13,
                }),
                false,
            );
            let backend = ktest_null_backend(geom);
            assert_eq!(backend.extent_base(unit), want, "ids={ids} unit={unit}");
        }

        // Wired through the branch, both widths over one disk: the
        // 4B sentinels (base 4004) and the 8B sentinels (base 4008)
        // occupy disjoint byte ranges of the 0xFF-filled area.
        let disk = Arc::new(ErofsMemoryDisk::new(PAGE_SIZE));
        let fs = ktest_fs_on(
            disk.clone(),
            ktest_super_block(12, 0),
            ktest_single_device_table(),
        );
        let mk_backend = |unit: usize| {
            let geom = ktest_data_geometry(
                3 * 2 * 4096,
                12,
                0,
                false,
                4002,
                Some(ChunkGeometry {
                    unit,
                    chunkbits: 13,
                }),
                false,
            );
            DataBackend::new(fs.self_ref().clone(), fs.block_device().clone(), geom, 6)
        };
        let backend4 = mk_backend(4);
        let backend8 = mk_backend(8);
        disk.stage_bytes(4000, &[0xffu8; 32]);
        disk.stage_bytes(4008, &500u32.to_le_bytes()); // 4B chunknr 1
        disk.stage_bytes(4012, &600u32.to_le_bytes()); // 4B chunknr 2
        stage_chunk_index(&disk, 4016, 0, 0, 500); // 8B chunknr 1
        stage_chunk_index(&disk, 4024, 0, 0, 600); // 8B chunknr 2
        for (la, blk) in [(2 * 4096u64, 500u64), (4 * 4096, 600)] {
            let m4 = backend4.map_blocks(la + 5, PAGE_SIZE as u64).unwrap();
            assert_eq!(m4.m_flags, MapFlags::MAPPED, "unit=4 la={la}");
            assert_eq!(
                m4.m_pa,
                blk << 12,
                "entry read at base+unit*chunknr, unit=4 la={la}"
            );
            assert_eq!(m4.m_la, la, "write-back, unit=4 la={la}");
            let m8 = backend8.map_blocks(la + 5, PAGE_SIZE as u64).unwrap();
            assert_eq!(m8.m_flags, MapFlags::MAPPED, "unit=8 la={la}");
            assert_eq!(
                m8.m_pa,
                blk << 12,
                "entry read at base+unit*chunknr, unit=8 la={la}"
            );
            assert_eq!(m8.m_la, la, "write-back, unit=8 la={la}");
        }
    }

    /// S04-IF-1 (anchor `docs/T-014/S04/index.md` §9): the identity
    /// arm — id 0 over both table forms (single-device and flatdev
    /// extra=1) and the pa grid returns pa unchanged with zero
    /// device I/O (the S04-IF-4 half: the log stays empty).
    #[ktest]
    fn map_dev_identity_arm() {
        let disk = Arc::new(ErofsMemoryDisk::new(PAGE_SIZE));
        let single = ktest_fs_on(
            disk.clone(),
            ktest_super_block(12, 0),
            ktest_single_device_table(),
        );
        let flat = ktest_fs_on(
            disk.clone(),
            ktest_super_block(12, 0),
            ktest_flatdev_table(&[(12, 12)], 1),
        );
        for fs in [&single, &flat] {
            let backend = DataBackend::new(
                fs.self_ref().clone(),
                fs.block_device().clone(),
                ktest_flat_geometry(4096, 0, false, 0),
                1,
            );
            for pa in [0u64, 512, 1 << 40] {
                assert_eq!(backend.map_dev(pa, 0).unwrap(), pa);
            }
        }
        assert!(
            disk.requests().is_empty(),
            "map_dev must not touch the device"
        );
    }

    /// S04-IF-2: the translation arm in its general form — the
    /// slot's mapped_blkaddr over {0, 1, 2^32−1} × block_bits over
    /// {9..12} (the sub-12 corners use a directly-constructed
    /// backend: the constructor pins the 4k-only premise): always
    /// `pa + (mapped << bits)` (internal.h:221, erofs_pos).
    #[ktest]
    fn map_dev_translation_general_form() {
        let disk = Arc::new(ErofsMemoryDisk::new(PAGE_SIZE));
        for bits in [9u32, 10, 11, 12] {
            for mapped in [0u32, 1, u32::MAX] {
                let fs = ktest_fs_on(
                    disk.clone(),
                    ktest_super_block(12, 0),
                    ktest_flatdev_table(&[(10, mapped)], 1),
                );
                let backend = DataBackend {
                    fs: fs.self_ref().clone(),
                    device: fs.block_device().clone(),
                    geom: ktest_data_geometry(4096, bits, 0, false, 0, None, false),
                    npages: 1,
                };
                for pa in [0u64, 511, 4095, 1 << 40] {
                    assert_eq!(
                        backend.map_dev(pa, 1).unwrap(),
                        pa + ((mapped as u64) << bits),
                        "bits={bits} mapped={mapped} pa={pa}"
                    );
                }
            }
        }
        assert!(disk.requests().is_empty());
    }

    /// S04-IF-3 + S04-IF-4: the MD10 example mirror over the
    /// over-supply mask corner — extra=2, mask=3, two slots: id 0
    /// identity, ids 1..2 translate, id 3 (masked-valid but past the
    /// array, linux idr_find miss) is ENODEV; and the whole walk is
    /// pure — the request log stays empty through every arm (no
    /// channel I/O, no nr_sectors consultation).
    #[ktest]
    fn map_dev_enodev_over_supply_mask() {
        let disk = Arc::new(ErofsMemoryDisk::new(PAGE_SIZE));
        let fs = ktest_fs_on(
            disk.clone(),
            ktest_super_block(12, 0),
            ktest_flatdev_table(&[(10, 100), (20, 200)], 3),
        );
        let backend = DataBackend::new(
            fs.self_ref().clone(),
            fs.block_device().clone(),
            ktest_flat_geometry(4096, 0, false, 0),
            1,
        );
        assert_eq!(backend.map_dev(4096, 0).unwrap(), 4096);
        assert_eq!(backend.map_dev(4096, 1).unwrap(), 4096 + (100u64 << 12));
        assert_eq!(backend.map_dev(4096, 2).unwrap(), 4096 + (200u64 << 12));
        let err = backend.map_dev(4096, 3).unwrap_err();
        assert_eq!(err.error(), Errno::ENODEV);
        assert!(
            disk.requests().is_empty(),
            "map_dev must stay pure across all arms"
        );
    }

    /// S04-IF-5: the upgrade guard — a dead Weak plus a nonzero id
    /// fails EIO (the defensive family form; unreachable behind the
    /// strong inode cache in production).
    #[ktest]
    fn map_dev_dead_weak_eio() {
        let disk = Arc::new(ErofsMemoryDisk::new(PAGE_SIZE));
        let fs = ktest_fs_on(
            disk,
            ktest_super_block(12, 0),
            ktest_flatdev_table(&[(10, 100)], 1),
        );
        let backend = DataBackend::new(
            fs.self_ref().clone(),
            fs.block_device().clone(),
            ktest_flat_geometry(4096, 0, false, 0),
            1,
        );
        drop(fs);
        let err = backend.map_dev(4096, 1).unwrap_err();
        assert_eq!(err.error(), Errno::EIO);
    }

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
