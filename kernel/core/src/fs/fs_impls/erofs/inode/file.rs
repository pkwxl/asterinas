// SPDX-License-Identifier: MPL-2.0

//! Regular-file reads for erofs inodes.
//!
//! Terminal responsibility (`docs/T-013/analysis.md` §7.3, refined by
//! `docs/T-014/analysis.md` §0.3 C-7): this module hosts the two
//! inherent read entries — the buffered `read_at` (the EISDIR guard
//! first, the zero-length early exit, then the DataBacked page-cache
//! read) and the direct-I/O entry `read_direct_at` (the G-P01
//! alignment gate plus the Y3 no-fallback extent walk). The
//! direct-I/O flag dispatch is exactly one conditional and lives in
//! the VFS adapter's `FileOps::read_at` (`impl_for_vfs/inode.rs`):
//! the per-open flag is visible only at that layer, and keeping the
//! dispatch beside it means one grep of the flag name hits the
//! single dispatch point (F7 — the silent-degradation trap's
//! mechanical defense). statx DIOALIGN stays unadvertised (W-P03 /
//! W-N02: the mask bit is never set; were it ever advertised, the
//! value should be `SECTOR_SIZE`).
//!
//! Deliberately no `set_atime` after reads on either arm (G-N07:
//! X8's three-times-identity baseline; the ext2 post-read
//! `set_atime` is the negative sample). Write, resize, and
//! preallocation paths do not exist: the filesystem is read-only and
//! every mutating entry point is rejected with `EROFS` at the VFS
//! adapter.

#![short_vis_path::add(erofs)]

use aster_block::SECTOR_SIZE;
use ostd::mm::VmIo;

use super::{super::prelude::*, FileKind, Inode, data::MapFlags};

impl Inode {
    /// Reads file data at `offset` through the page cache — the
    /// buffered arm the VFS adapter forwards to when the direct-I/O
    /// flag is absent.
    ///
    /// Guard order is the assertion surface (analysis.md §6.2): a
    /// directory fd gets EISDIR before anything else — including the
    /// zero-length buffer (R2; sample `ext2/inode/file.rs:22-25`) —
    /// then a zero-length read is `Ok(0)` (ext2 same-order early
    /// exit). Past the guards, the three-segment collection (the C-7
    /// position pin; ext2 `inode/file.rs:229-243` the form
    /// reference): a post-EOF offset reads `Ok(0)`, a cross-EOF read
    /// is pre-truncated to `size − offset` with the writer limited
    /// to that bound (M3 — EOF truncation is the FS side's duty; the
    /// page-cache layer's own clipping is never relied on), and the
    /// page-cache read's fill errors propagate unfolded through `?`
    /// (no blanket-EIO; the EUCLEAN-through-VmIo folding is the
    /// registered S06 §3 known-diff).
    // Deliberately NO set_atime after reads — G-N07; the ext2
    // body's post-read `set_atime(utils::now())`
    // (`ext2/inode/file.rs:32`) is the negative sample, same family
    // as `ext2/inode/dir/mod.rs:61`.
    //
    // Live since T-024 S05: the VFS adapter's `FileOps::read_at`
    // forwards to this body (the else arm of the dispatch); the data
    // body since T-025 S08 — the buffered flip, the activation point
    // of the DATA-guarded boot regressions (decision 1 of
    // `docs/T-025/subtasks.md`).
    pub(in crate::fs::fs_impls::erofs) fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
    ) -> Result<usize> {
        // read(2) on a directory fd → EISDIR. Guard precedes
        // everything (R2; sample ext2/inode/file.rs:22-25).
        if self.kind() == FileKind::Dir {
            return_errno!(Errno::EISDIR);
        }
        if writer.avail() == 0 {
            return Ok(0);
        }
        // The three segments (C-7). `size` is the immutable decode
        // snapshot (X7) — the i_size_read race of a writable
        // filesystem does not exist here. The cache handle is
        // structurally Some past the EISDIR guard (REG is always
        // DataBacked; the FastSymlink corner is unreachable through
        // open) — the EINVAL else arm is the same defensive errno as
        // the direct arm's backend fetch below, never a panic.
        let size = self.desc().size;
        let Some(page_cache) = self.page_cache() else {
            return_errno_with_message!(Errno::EINVAL, "inode has no data page cache");
        };
        if offset as u64 >= size {
            return Ok(0);
        }
        let read_len = writer.avail().min((size - offset as u64) as usize);
        writer.limit(read_len);
        page_cache.read(offset, writer)?;
        Ok(read_len)
    }

    /// Direct-I/O read path (T-025 S07; `docs/T-014/S07/index.md`
    /// §3.2). The guard order below IS the behavioral face:
    ///
    /// 1. EISDIR first — the same guard as the buffered arm, so a
    ///    directory fd reads EISDIR with or without the direct-I/O
    ///    flag (R2; linux rejects in `vfs_read` before `read_iter`).
    /// 2. Zero-length early out (Y1; linux data.c:410-411) — BEFORE
    ///    the alignment gate, so `count == 0` at a misaligned offset
    ///    still reads `Ok(0)`, not EINVAL (the ext2 order — gate
    ///    before the zero-length check — is the #6 negative sample
    ///    and is deliberately not copied).
    /// 3. The G-P01 three-factor gate (data.c:426-428 mirrored):
    ///    `(offset | count | buf_addr) & (SECTOR_SIZE - 1)` over the
    ///    ORIGINAL count (before any truncation) and the user
    ///    buffer's cursor address. The boundary is 512 — the device
    ///    granularity constant — never a 4096 block predicate (the
    ///    other #6 negative: a 4K gate would reject the 512-aligned
    ///    reads linux serves; X3 — the DIO boundary does not follow
    ///    the fs block size). Parity work carries no AUTO-TODO
    ///    marker (AR-S01-2).
    /// 4. post-EOF: `offset >= size → Ok(0)`; a cross-EOF read is
    ///    pre-truncated to `size − offset` (linux trims after the
    ///    fact and reverts the iterator — same observable result,
    ///    mechanism difference registered).
    ///
    /// The extent walk (Y3 — no buffered fallback; every error
    /// propagates unfolded through `?`): `map_blocks` then `map_dev`
    /// per extent; holes zero-fill the writer on the CPU (I3); MAPPED
    /// and META (inline) extents share the one-hop device
    /// byte-channel read (S07-D2 — the S06 inline contract's single
    /// data outlet). The walk touches the page cache exactly zero
    /// times. Reads into the user buffer are fallible: an EFAULT
    /// wins over any progress (linux `dio_flags = 0` semantics —
    /// error first, partial counts dropped).
    // Deliberately NO flush_range/evict before the walk (S07-D3):
    // the medium is read-only, so the page cache holds no coherence
    // object for a DIO read; ext2's pre-DIO flush
    // (`ext2/inode/file.rs:285`) serves its writable pages and is
    // NOT copied — on a dirty-MAP_SHARED corner it would even hurt
    // (EROFS injected into the read path, S05 §6.4). And no ext2-
    // style fallback TODO note either: Y3 (no buffered fallback) is
    // the decided behavior here, and a comment wishing for one
    // would contradict it.
    pub(in crate::fs::fs_impls::erofs) fn read_direct_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
    ) -> Result<usize> {
        // (a) EISDIR first — same guard, same position as the
        //     buffered arm (R2).
        if self.kind() == FileKind::Dir {
            return_errno!(Errno::EISDIR);
        }
        // (b) Zero-length early out (Y1) — precedes the gate, so a
        //     misaligned offset with an empty buffer still reads
        //     Ok(0) (linux data.c:410-411 ahead of the :417-428 DIO
        //     branch; the ext2 inverted order is the #6 negative).
        let count = writer.avail();
        if count == 0 {
            return Ok(0);
        }
        // (c) G-P01 three-factor gate on the ORIGINAL count and the
        //     buffer's cursor address — the bitwise
        //     single-expression mirror of linux data.c:426-428.
        //     SECTOR_SIZE (= 512, block/src/lib.rs:62) is the only
        //     spelling of the boundary (X3: the gate is independent
        //     of the fs block size in both the 4k-only present and
        //     any future sub-4k form).
        let buf_addr = writer.cursor().addr();
        if (offset | count | buf_addr) & (SECTOR_SIZE - 1) != 0 {
            return_errno_with_message!(Errno::EINVAL, "O_DIRECT read is not 512-byte aligned");
        }
        // (d) post-EOF / cross-EOF truncation (F5). `size` is the
        //     immutable decode snapshot (X7) — linux's i_size_read
        //     race window does not exist on a read-only filesystem.
        //     The backend handle is structurally Some once past the
        //     EISDIR guard (REG is always DataBacked); the EINVAL
        //     else arm is the family's defensive errno (ext2's
        //     `block_manager()?` same code, never a panic).
        let size = self.desc().size;
        let Some(backend) = self.data_backend() else {
            return_errno_with_message!(Errno::EINVAL, "inode has no data mapping");
        };
        if offset as u64 >= size {
            return Ok(0);
        }
        let read_len = count.min((size - offset as u64) as usize);
        writer.limit(read_len);
        // (e) The extent walk — Y3: no buffered fallback, errors
        //     propagate unfolded. `writer.limit(read_len)` above is
        //     the one legitimate whole-window shrink (the target
        //     bound); every per-segment bound below rides a copy.
        let mut pos = offset as u64;
        let mut total = 0usize;
        while writer.has_avail() {
            let map = backend.map_blocks(pos, writer.avail() as u64)?;
            let base = backend.map_dev(map.m_pa, map.m_deviceid)?;
            let in_ext = (pos - map.m_la) as usize;
            debug_assert!(in_ext < map.m_plen as usize); // the map covers pos
            let n = (map.m_plen as usize - in_ext).min(writer.avail());
            if map.m_flags == MapFlags::empty() {
                // Whole-extent hole — CPU zero-fill at extent
                // granularity (I3; linux iov_iter_zero,
                // direct-io.c:480). fill_zeros advances the writer
                // itself; its partial count is dropped — an EFAULT
                // wins over progress (§5 of the S07 design).
                writer.fill_zeros(n).map_err(|(err, _filled)| err)?;
            } else {
                // MAPPED and META (inline) share this single data
                // outlet (S07-D2, the S06 contract's common exit):
                // one one-hop device byte-channel read over
                // [base + in_ext, +n). Segment-length control goes
                // through a clone_exclusive copy — `limit` is a
                // destructive shrink (end = cursor + max_avail), so
                // limiting the original writer here would end the
                // whole loop after this segment; the copy's writes
                // never advance the original cursor (io/mod.rs),
                // which `skip(n)` does instead (S07-D5).
                let pa = (base + in_ext as u64) as usize;
                let mut seg = writer.clone_exclusive();
                seg.limit(n);
                backend.device.read(pa, &mut seg)?;
                writer.skip(n);
            }
            total += n;
            pos += n as u64;
        }
        Ok(total)
    }
}

#[cfg(ktest)]
mod tests {
    use aster_block::bio::BioType;
    use ostd::{mm::io::Fallible, prelude::*};

    use super::{
        super::{
            AddrState, DataLayout, InodeDesc, InodeVersion, data::NULL_ADDR, ktest_inode_from_desc,
        },
        *,
    };
    use crate::fs::fs_impls::erofs::{
        Erofs,
        fs::DeviceTable,
        test_utils::{
            BioRequest, ErofsMemoryDisk, ktest_flatdev_table, ktest_fs_on,
            ktest_single_device_table, ktest_super_block,
        },
    };

    /// The inline-area/extent-base oracle of the compact nid-64
    /// fixture over `ktest_super_block(12, meta)`:
    /// `iloc = meta<<12 + 64<<5`, plus `inode_isize` 32, plus the
    /// xattr suffix — pinned by hand, not by calling the formula
    /// family (a circular oracle would pin nothing).
    const fn ktest_ids(meta_blkaddr: u32, xattr_isize: usize) -> u64 {
        ((meta_blkaddr as u64) << 12) + (64 << 5) + 32 + xattr_isize as u64
    }

    /// The REG-fixture knobs of [`ktest_reg_inode`], bundled to stay
    /// under the clippy argument threshold (field order matching the
    /// `InodeDesc` literal below).
    struct RegKnobs {
        meta_blkaddr: u32,
        datalayout: DataLayout,
        size: u64,
        xattr_isize: usize,
        addr_state: AddrState,
        i_u: u32,
    }

    /// A REG inode directly constructed over a literal descriptor
    /// (the S06 fixture face): the payload assembly is the production
    /// `InodePayload::new`, so the backend and page-cache wiring is
    /// the real chain `read_direct_at` walks. Construction itself
    /// performs zero device I/O (the geometry collapse is pure).
    /// The caller-owned-fs form: the backend keeps only a weak fs
    /// handle, so flatdev/chunk-index walks (map_dev with a nonzero
    /// device id, index-table re-reads) need the `Erofs` alive for
    /// as long as the inode reads — hold this `fs` binding in the
    /// test scope (the S04 suite's posture).
    fn ktest_reg_inode_on(fs: &Erofs, knobs: RegKnobs) -> Arc<Inode> {
        let desc = InodeDesc {
            version: InodeVersion::Compact,
            datalayout: knobs.datalayout,
            kind: FileKind::Reg,
            mode: InodeMode::from_bits_truncate(0o644),
            uid: 0,
            gid: 0,
            nlink: 1,
            size: knobs.size,
            xattr_isize: knobs.xattr_isize,
            time: Duration::ZERO,
            i_u: knobs.i_u,
            addr_state: knobs.addr_state,
            nr_sectors: 0,
        };
        ktest_inode_from_desc(fs, 64, desc)
    }

    /// The self-contained form for layouts whose walk never upgrades
    /// the weak fs handle (flat single-device: map_dev's id-0 arm);
    /// the short-lived `fs` inside is sound for those.
    fn ktest_reg_inode(
        disk: Arc<ErofsMemoryDisk>,
        table: DeviceTable,
        knobs: RegKnobs,
    ) -> Arc<Inode> {
        let fs = ktest_fs_on(disk, ktest_super_block(12, knobs.meta_blkaddr), table);
        ktest_reg_inode_on(&fs, knobs)
    }

    /// A flat REG fixture with the common knobs pre-filled
    /// (`i_u` = the raw data block).
    fn ktest_flat_reg(
        disk: Arc<ErofsMemoryDisk>,
        datalayout: DataLayout,
        size: u64,
        xattr_isize: usize,
        i_u: u32,
    ) -> Arc<Inode> {
        ktest_reg_inode(
            disk,
            ktest_single_device_table(),
            RegKnobs {
                meta_blkaddr: 3,
                datalayout,
                size,
                xattr_isize,
                addr_state: AddrState::Flat,
                i_u,
            },
        )
    }

    /// Position-dependent staging pattern (the S05 suite's form).
    fn pattern(off: usize) -> u8 {
        ((off * 13 + 7) & 0xff) as u8
    }

    fn stage_pattern(disk: &ErofsMemoryDisk, start: usize, len: usize) {
        let mut staged = vec![0u8; len];
        for (i, b) in staged.iter_mut().enumerate() {
            *b = pattern(start + i);
        }
        disk.stage_bytes(start, &staged);
    }

    /// Stages one 8-byte chunk-index record at `pos` in the little-
    /// endian on-disk form (`advise` kept zero; the S03/S04 suite's
    /// staging face).
    fn stage_index(disk: &ErofsMemoryDisk, pos: usize, device_id: u16, blkaddr: u32) {
        let mut bytes = [0u8; 8];
        bytes[2..4].copy_from_slice(&device_id.to_le_bytes());
        bytes[4..].copy_from_slice(&blkaddr.to_le_bytes());
        disk.stage_bytes(pos, &bytes);
    }

    /// A fallible user-buffer stand-in over `buf`: the cursor lands
    /// exactly `misalign` bytes past the next 512-boundary at or
    /// after the buffer start — and, when `misalign == 0`, off the
    /// 4096 grid as well (the S07-IF-2 form: 512-aligned yet not
    /// 4K-aligned). Kernel pages never fault, so the fallible
    /// writer's EFAULT arm stays out of the picture here (the
    /// runtime EFAULT fixture belongs to the boot regression task).
    /// Returns the writer and the buffer offset its cursor landed on.
    fn ktest_dio_writer(
        buf: &mut [u8],
        misalign: usize,
        len: usize,
    ) -> (VmWriter<'_, Fallible>, usize) {
        assert!(misalign < SECTOR_SIZE);
        let mut writer = VmWriter::from(&mut buf[..]).to_fallible();
        let mut pad = (SECTOR_SIZE - (writer.cursor().addr() % SECTOR_SIZE)) % SECTOR_SIZE;
        if misalign == 0 && (writer.cursor().addr() + pad).is_multiple_of(PAGE_SIZE) {
            pad += SECTOR_SIZE;
        }
        pad += misalign;
        writer.skip(pad);
        writer.limit(len);
        (writer, pad)
    }

    /// S07-IF-1 (anchor `docs/T-014/S07/index.md` §11): the G-P01
    /// gate's three factors separate — each case misaligns exactly
    /// one of {offset, count, buf} and fails EINVAL, the all-aligned
    /// control reads through, and every rejection happens before any
    /// device I/O.
    #[ktest]
    fn dio_alignment_three_factor_gate() {
        let disk = Arc::new(ErofsMemoryDisk::new(4 * PAGE_SIZE));
        stage_pattern(&disk, PAGE_SIZE, 2 * PAGE_SIZE); // data [4096, 12288)
        let inode = ktest_flat_reg(
            disk.clone(),
            DataLayout::FlatPlain,
            2 * PAGE_SIZE as u64,
            0,
            1, // raw_blkaddr: data starts at block 1
        );
        // Control: all three factors 512-aligned → the read passes.
        let mut buf = vec![0u8; 2 * PAGE_SIZE];
        let (mut writer, pad) = ktest_dio_writer(&mut buf, 0, 1024);
        assert_eq!(
            writer.cursor().addr() % SECTOR_SIZE,
            0,
            "fixture: the control buffer is 512-aligned"
        );
        assert_eq!(inode.read_direct_at(512, &mut writer).unwrap(), 1024);

        for i in 0..1024 {
            assert_eq!(buf[pad + i], pattern(PAGE_SIZE + 512 + i), "byte {i}");
        }
        // Exactly the control's byte-channel bounce so far — no
        // page-cache fill (a fill of page 0 would read 8 whole
        // sectors at sector 8, not 2 at sector 9).
        assert_eq!(
            disk.requests(),
            vec![BioRequest {
                type_: BioType::Read,
                start_sector: 9,
                nr_sectors: 2,
            }]
        );
        // pos-only: count and buffer stay aligned.
        let (mut writer, _) = ktest_dio_writer(&mut buf, 0, 1024);
        assert_eq!(
            inode
                .read_direct_at(512 + 128, &mut writer)
                .unwrap_err()
                .error(),
            Errno::EINVAL
        );
        // count-only: the ORIGINAL count is checked — 1000 is not a
        // 512 multiple (the truncation never gets a chance to
        // legitimize it).
        let (mut writer, _) = ktest_dio_writer(&mut buf, 0, 1000);
        assert_eq!(
            inode.read_direct_at(1024, &mut writer).unwrap_err().error(),
            Errno::EINVAL
        );
        // buf-only: the cursor address is the third factor.
        let (mut writer, _) = ktest_dio_writer(&mut buf, 1, 1024);
        assert_eq!(
            writer.cursor().addr() % SECTOR_SIZE,
            1,
            "fixture: the buffer is misaligned by exactly one byte"
        );
        assert_eq!(
            inode.read_direct_at(1024, &mut writer).unwrap_err().error(),
            Errno::EINVAL
        );
        // Still exactly one request — all three rejections preceded
        // any device I/O.
        assert_eq!(disk.requests().len(), 1);
    }

    /// S07-IF-2: the 512 boundary — offset 512, count 512, and a
    /// 512-aligned buffer that is NOT 4096-aligned all pass (a 4096
    /// gate — the ext2 #6 boundary negative — would reject exactly
    /// this form); the content is byte-exact and the request log
    /// shows the lone sub-page byte-channel bounce.
    #[ktest]
    fn dio_512_boundary_success() {
        let disk = Arc::new(ErofsMemoryDisk::new(4 * PAGE_SIZE));
        stage_pattern(&disk, PAGE_SIZE, 2 * PAGE_SIZE);
        let inode = ktest_flat_reg(
            disk.clone(),
            DataLayout::FlatPlain,
            2 * PAGE_SIZE as u64,
            0,
            1,
        );
        let mut buf = vec![0u8; PAGE_SIZE];
        let (mut writer, pad) = ktest_dio_writer(&mut buf, 0, SECTOR_SIZE);
        let addr = writer.cursor().addr();
        assert_eq!(addr % SECTOR_SIZE, 0, "512-aligned");
        assert_ne!(addr % PAGE_SIZE, 0, "yet off the 4K grid (the #6 form)");
        assert_eq!(inode.read_direct_at(512, &mut writer).unwrap(), SECTOR_SIZE);

        for i in 0..SECTOR_SIZE {
            assert_eq!(buf[pad + i], pattern(PAGE_SIZE + 512 + i), "byte {i}");
        }
        assert_eq!(
            disk.requests(),
            vec![BioRequest {
                type_: BioType::Read,
                start_sector: 9,
                nr_sectors: 1,
            }]
        );
    }

    /// S07-IF-3: the guard ORDER — a zero-length read at a
    /// misaligned offset is `Ok(0)`, not EINVAL (the zero-length
    /// guard precedes the gate; linux data.c:410-411 before :426 —
    /// the ext2 inverted order is the #6 negative); a post-EOF read
    /// with everything aligned is `Ok(0)` too. Zero device requests
    /// across the board.
    #[ktest]
    fn dio_zero_length_and_post_eof_order() {
        let disk = Arc::new(ErofsMemoryDisk::new(4 * PAGE_SIZE));
        stage_pattern(&disk, PAGE_SIZE, 2 * PAGE_SIZE);
        let inode = ktest_flat_reg(
            disk.clone(),
            DataLayout::FlatPlain,
            2 * PAGE_SIZE as u64,
            0,
            1,
        );
        let mut buf = vec![0u8; PAGE_SIZE];
        // Zero length first: the misaligned offset never reaches the
        // gate.
        let (mut writer, _) = ktest_dio_writer(&mut buf, 0, 0);
        assert_eq!(inode.read_direct_at(100, &mut writer).unwrap(), 0);
        // post-EOF (aligned factors): Ok(0) at the boundary and far
        // beyond.
        let (mut writer, _) = ktest_dio_writer(&mut buf, 0, SECTOR_SIZE);
        assert_eq!(inode.read_direct_at(2 * PAGE_SIZE, &mut writer).unwrap(), 0);
        assert_eq!(inode.read_direct_at(1 << 20, &mut writer).unwrap(), 0);
        assert!(disk.requests().is_empty());
    }

    /// S07-IF-4: the cross-EOF truncation — offset 512-aligned,
    /// count a 512 multiple, `size − offset` NOT a 512 multiple: the
    /// gate checked the ORIGINAL count, the walk pre-truncates to
    /// `size − offset` (300), the content stops at i_size, and the
    /// staged device residue past i_size never reaches the buffer.
    #[ktest]
    fn dio_cross_eof_truncation() {
        let size = PAGE_SIZE as u64 + 300;
        let disk = Arc::new(ErofsMemoryDisk::new(3 * PAGE_SIZE));
        // The block-rounded extent [4096, 12288) carries patterned
        // residue past i_size (device bytes [8492, 12288)) — the
        // truncation must leave it on the device.
        stage_pattern(&disk, PAGE_SIZE, 2 * PAGE_SIZE);
        let inode = ktest_flat_reg(disk.clone(), DataLayout::FlatPlain, size, 0, 1);
        let mut buf = vec![0u8; PAGE_SIZE];
        let (mut writer, pad) = ktest_dio_writer(&mut buf, 0, 512);
        assert_eq!(
            inode.read_direct_at(PAGE_SIZE, &mut writer).unwrap(),
            300,
            "truncated to size − offset"
        );

        for i in 0..300 {
            assert_eq!(buf[pad + i], pattern(2 * PAGE_SIZE + i), "byte {i}");
        }
        assert!(
            buf[pad + 300..pad + 512].iter().all(|&b| b == 0),
            "no residue past i_size"
        );
        // The lone bounce served [8192, 8492) — sector-rounded to
        // [8192, 8704), one sector.
        assert_eq!(
            disk.requests(),
            vec![BioRequest {
                type_: BioType::Read,
                start_sector: 16,
                nr_sectors: 1,
            }]
        );
    }

    /// S07-IF-5: the DIO walk never touches the page cache — every
    /// device request is a byte-channel bounce carrying the exact
    /// sub-block geometry of its window (a page-cache fill of page 0
    /// would instead issue one whole-block 8-sector read at sector
    /// 8); the INLINE tail reads its payload straight out of the
    /// metadata area through the same data outlet. (The comparative
    /// buffered half of the invariant — a fill observed > 0 — is
    /// pinned by the S08 suite below,
    /// `buffered_read_at_collects_through_page_cache`.)
    #[ktest]
    fn dio_no_page_cache_touch() {
        // A sub-page MAPPED window [512, 1024): one sector at 9.
        let disk = Arc::new(ErofsMemoryDisk::new(4 * PAGE_SIZE));
        stage_pattern(&disk, PAGE_SIZE, 2 * PAGE_SIZE);
        let inode = ktest_flat_reg(
            disk.clone(),
            DataLayout::FlatPlain,
            2 * PAGE_SIZE as u64,
            0,
            1,
        );
        let mut buf = vec![0u8; PAGE_SIZE];
        let (mut writer, _) = ktest_dio_writer(&mut buf, 0, SECTOR_SIZE);
        assert_eq!(inode.read_direct_at(512, &mut writer).unwrap(), SECTOR_SIZE);
        assert_eq!(
            disk.requests(),
            vec![BioRequest {
                type_: BioType::Read,
                start_sector: 9,
                nr_sectors: 1,
            }]
        );

        // The INLINE tail: 100 payload bytes staged in the metadata
        // area (ids = 14368, blkoff 2080 — a legal same-block
        // geometry), read directly by the flagged pread. The buffer
        // is reused from the control read — re-zeroed so the bytes
        // past the 100-byte window can only come from this read.
        let payload: Vec<u8> = (0..100u8)
            .map(|i| i.wrapping_mul(5).wrapping_add(3))
            .collect();
        disk.stage_bytes(ktest_ids(3, 0) as usize, &payload);
        let inode = ktest_flat_reg(
            disk.clone(),
            DataLayout::FlatInline,
            PAGE_SIZE as u64 + 100,
            0,
            1,
        );
        buf.fill(0);
        let (mut writer, pad) = ktest_dio_writer(&mut buf, 0, SECTOR_SIZE);
        assert_eq!(inode.read_direct_at(PAGE_SIZE, &mut writer).unwrap(), 100);

        assert_eq!(&buf[pad..pad + 100], &payload[..], "the inline payload");
        assert!(buf[pad + 100..pad + SECTOR_SIZE].iter().all(|&b| b == 0));
        // Second request: the tail bounce over [14368, 14468) —
        // sector-rounded into one sector at 28. No whole-block fill
        // anywhere.
        assert_eq!(
            disk.requests(),
            vec![
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 9,
                    nr_sectors: 1,
                },
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 28,
                    nr_sectors: 1,
                },
            ]
        );
    }

    /// S08-IF (the flip): the buffered body collects through the
    /// page cache — the comparative half of `dio_no_page_cache_touch`
    /// above. Same flat fixture, same window [512, 1024): the
    /// unflagged read FILLS page 0 (one whole-block 8-sector read at
    /// sector 8 — the block channel), where the flagged walk bounced
    /// 1 sector at 9 without filling anything. The three segments'
    /// EOF faces are the second half: post-EOF offsets read `Ok(0)`
    /// with the writer untouched, and a cross-EOF read pre-truncates
    /// to `size − offset` — the tail page riding the byte channel
    /// inside the fill, with the staged device residue past i_size
    /// never reaching the buffer (G-P02's buffered face).
    #[ktest]
    fn buffered_read_at_collects_through_page_cache() {
        let disk = Arc::new(ErofsMemoryDisk::new(4 * PAGE_SIZE));
        stage_pattern(&disk, PAGE_SIZE, 2 * PAGE_SIZE);
        let inode = ktest_flat_reg(
            disk.clone(),
            DataLayout::FlatPlain,
            2 * PAGE_SIZE as u64,
            0,
            1,
        );
        // post-EOF: Ok(0) at the boundary and far beyond; the writer
        // keeps its full window (no limit shrink) and the device log
        // stays empty (no speculative fill).
        let mut buf = vec![0u8; PAGE_SIZE];
        let mut writer = VmWriter::from(&mut buf[..]).to_fallible();
        assert_eq!(inode.read_at(2 * PAGE_SIZE, &mut writer).unwrap(), 0);
        assert_eq!(inode.read_at(1 << 20, &mut writer).unwrap(), 0);
        assert_eq!(writer.avail(), PAGE_SIZE, "the writer is untouched");
        assert!(disk.requests().is_empty());
        // The window [512, 1024): content byte-exact, and the sole
        // device touch is the whole-block page-cache fill — the
        // channel discriminator against the DIO 1-sector bounce.
        let mut writer = VmWriter::from(&mut buf[..]).to_fallible();
        assert_eq!(inode.read_at(512, &mut writer).unwrap(), 512);
        for (i, &byte) in buf.iter().enumerate().take(512) {
            assert_eq!(byte, pattern(PAGE_SIZE + 512 + i), "byte {i}");
        }
        assert!(
            buf[512..].iter().all(|&b| b == 0),
            "only the requested window advanced"
        );
        assert_eq!(
            disk.requests(),
            vec![BioRequest {
                type_: BioType::Read,
                start_sector: 8,
                nr_sectors: 8,
            }]
        );

        // Cross-EOF truncation on a fresh disk: size = PAGE + 300,
        // window [512, 512 + PAGE) → truncated to 3884. Page 0 fills
        // whole (block channel, 8 sectors at 8); the tail page's
        // [0, 300) prefix rides the byte channel (one sector at 16)
        // — the two channels inside one buffered read, and the
        // patterned residue past i_size stays on the device.
        let disk = Arc::new(ErofsMemoryDisk::new(3 * PAGE_SIZE));
        stage_pattern(&disk, PAGE_SIZE, 2 * PAGE_SIZE);
        let inode = ktest_flat_reg(
            disk.clone(),
            DataLayout::FlatPlain,
            PAGE_SIZE as u64 + 300,
            0,
            1,
        );
        let mut buf = vec![0u8; 2 * PAGE_SIZE];
        let mut writer = VmWriter::from(&mut buf[..]).to_fallible();
        assert_eq!(
            inode.read_at(512, &mut writer).unwrap(),
            3884,
            "truncated to size − offset"
        );
        for (i, &byte) in buf.iter().enumerate().take(3884) {
            assert_eq!(byte, pattern(PAGE_SIZE + 512 + i), "byte {i}");
        }
        assert!(
            buf[3884..].iter().all(|&b| b == 0),
            "no residue past i_size"
        );
        assert_eq!(
            disk.requests(),
            vec![
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 8,
                    nr_sectors: 8,
                }, // page 0 fill: whole block (block channel)
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 16,
                    nr_sectors: 1,
                }, // tail page [0, 300): byte-channel bounce
            ]
        );
    }

    /// S07-IF-6: the three states through the flagged pread, whole
    /// file each — FLAT_PLAIN multi-block, FLAT_INLINE (flat prefix
    /// + inline tail), and CHUNK_BASED with a NULL hole chunk —
    /// content byte-exact, the hole segment reading zeros.
    #[ktest]
    fn dio_three_states_content() {
        // FLAT_PLAIN: one 3-block MAPPED extent, read whole.
        let disk = Arc::new(ErofsMemoryDisk::new(4 * PAGE_SIZE));
        stage_pattern(&disk, PAGE_SIZE, 3 * PAGE_SIZE);
        let inode = ktest_flat_reg(
            disk.clone(),
            DataLayout::FlatPlain,
            3 * PAGE_SIZE as u64,
            0,
            1,
        );
        let mut buf = vec![0u8; 4 * PAGE_SIZE];
        let (mut writer, pad) = ktest_dio_writer(&mut buf, 0, 3 * PAGE_SIZE);
        assert_eq!(inode.read_direct_at(0, &mut writer).unwrap(), 3 * PAGE_SIZE);

        for i in 0..3 * PAGE_SIZE {
            assert_eq!(buf[pad + i], pattern(PAGE_SIZE + i), "FLAT_PLAIN byte {i}");
        }
        assert_eq!(
            disk.requests(),
            vec![BioRequest {
                type_: BioType::Read,
                start_sector: 8,
                nr_sectors: 24,
            }]
        );

        // FLAT_INLINE: 2 flat blocks + a 512-byte inline tail (ids =
        // 14368, blkoff 2080; 2080 + 512 <= 4096 — legal). A fresh
        // disk, so the request log below carries this state's
        // traffic alone (the CHUNK_BASED state re-stages likewise).
        let disk = Arc::new(ErofsMemoryDisk::new(4 * PAGE_SIZE));
        stage_pattern(&disk, PAGE_SIZE, 2 * PAGE_SIZE);
        let payload: Vec<u8> = (0..512)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(1))
            .collect();
        disk.stage_bytes(ktest_ids(3, 0) as usize, &payload);
        let inode = ktest_flat_reg(
            disk.clone(),
            DataLayout::FlatInline,
            2 * PAGE_SIZE as u64 + 512,
            0,
            1,
        );
        let (mut writer, pad) = ktest_dio_writer(&mut buf, 0, 2 * PAGE_SIZE + 512);
        assert_eq!(
            inode.read_direct_at(0, &mut writer).unwrap(),
            2 * PAGE_SIZE + 512
        );

        for i in 0..2 * PAGE_SIZE {
            assert_eq!(
                buf[pad + i],
                pattern(PAGE_SIZE + i),
                "FLAT_INLINE flat byte {i}"
            );
        }
        assert_eq!(
            &buf[pad + 2 * PAGE_SIZE..pad + 2 * PAGE_SIZE + 512],
            &payload[..],
            "the inline tail"
        );
        // The flat bounce plus the tail bounce ([14368, 14880) →
        // sectors 28..30).
        assert_eq!(
            disk.requests(),
            vec![
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 8,
                    nr_sectors: 16,
                },
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 28,
                    nr_sectors: 2,
                },
            ]
        );

        // CHUNK_BASED (8-byte indexes, chunkbits 13 → 8 KiB chunks):
        // chunk 0 mapped (blk 1), chunk 1 a NULL hole, chunk 2
        // mapped (blk 4) — the data placement skirts the metadata
        // block hosting the extent table at align_up(14368, 8).
        let disk = Arc::new(ErofsMemoryDisk::new(6 * PAGE_SIZE));
        stage_pattern(&disk, PAGE_SIZE, 2 * PAGE_SIZE); // chunk 0: [4096, 12288)
        stage_pattern(&disk, 4 * PAGE_SIZE, 2 * PAGE_SIZE); // chunk 2: [16384, 24576)
        let table = ktest_ids(3, 0) as usize; // 14368, 8-aligned
        stage_index(&disk, table, 0, 1);
        stage_index(&disk, table + 8, 0, NULL_ADDR);
        stage_index(&disk, table + 16, 0, 4);
        let fs = ktest_fs_on(
            disk.clone(),
            ktest_super_block(12, 3),
            ktest_single_device_table(),
        );
        let inode = ktest_reg_inode_on(
            &fs,
            RegKnobs {
                meta_blkaddr: 3,
                datalayout: DataLayout::ChunkBased,
                size: 3 * 8192,
                xattr_isize: 0,
                addr_state: AddrState::Chunked {
                    format: 0x21, // INDEXES | blkbits 1 → chunkbits 13
                    bits: 13,
                },
                i_u: 0,
            },
        );
        let mut buf = vec![0u8; 7 * PAGE_SIZE];
        let (mut writer, pad) = ktest_dio_writer(&mut buf, 0, 3 * 8192);
        assert_eq!(inode.read_direct_at(0, &mut writer).unwrap(), 3 * 8192);

        for i in 0..8192 {
            assert_eq!(buf[pad + i], pattern(PAGE_SIZE + i), "chunk 0 byte {i}");
        }
        assert!(
            buf[pad + 8192..pad + 16384].iter().all(|&b| b == 0),
            "the hole reads zeros"
        );
        for i in 0..8192 {
            assert_eq!(
                buf[pad + 16384 + i],
                pattern(4 * PAGE_SIZE + i),
                "chunk 2 byte {i}"
            );
        }
        // Per extent: one table-element read; data only for the
        // mapped chunks; nothing for the hole.
        assert_eq!(
            disk.requests(),
            vec![
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 28,
                    nr_sectors: 1,
                }, // table 0
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 8,
                    nr_sectors: 16,
                }, // chunk 0
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 28,
                    nr_sectors: 1,
                }, // table 1
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 28,
                    nr_sectors: 1,
                }, // table 2
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 32,
                    nr_sectors: 16,
                }, // chunk 2
            ]
        );
    }

    /// S07-IF-7: the EUCLEAN passthrough — a crafted cross-block
    /// inline geometry fails the flagged pread with the mapping
    /// layer's own errno (the crate-Result chain preserves it,
    /// unlike the buffered VmIo boundary — the S06 §3 known-diff);
    /// the guard fires before any fetch, so the device log stays
    /// empty.
    #[ktest]
    fn dio_inline_cross_block_euclean() {
        // Tail [8192, 8292); ids = 16288 (blkoff 4000): 4000 + 100
        // > 4096 → the single-sourced cross-block defense.
        let xattr_isize = (16288 - 14_368) as usize; // ktest_ids(3, x) = 16288
        let disk = Arc::new(ErofsMemoryDisk::new(4 * PAGE_SIZE));
        let inode = ktest_flat_reg(
            disk.clone(),
            DataLayout::FlatInline,
            2 * PAGE_SIZE as u64 + 100,
            xattr_isize,
            1,
        );
        let mut buf = vec![0u8; PAGE_SIZE];
        let (mut writer, _) = ktest_dio_writer(&mut buf, 0, SECTOR_SIZE);
        let err = inode
            .read_direct_at(2 * PAGE_SIZE, &mut writer)
            .unwrap_err();
        assert_eq!(err.error(), Errno::EUCLEAN);
        assert!(disk.requests().is_empty(), "the guard precedes any fetch");
    }

    /// S07-IF-8 (Y3): no buffered fallback — a mid-walk byte-channel
    /// failure (the framework's end-of-device bound, the RD2②
    /// EINVAL half) returns the error with the first chunk's
    /// progress discarded, and nothing lands in the page cache (the
    /// only device touches are the walk's own table reads and data
    /// bounce).
    #[ktest]
    fn dio_byte_channel_end_einval_no_fallback() {
        // meta 0: the extent table sits at align_up(2080, 4) = 2080
        // in block 0; chunk 0's data (blk 1, [4096, 12288)) fits
        // inside the three-page disk, chunk 1's (blk 2,
        // [12288, 20480)) runs past the end.
        let disk = Arc::new(ErofsMemoryDisk::new(3 * PAGE_SIZE));
        stage_pattern(&disk, PAGE_SIZE, 2 * PAGE_SIZE);
        let table = ktest_ids(0, 0) as usize;
        disk.stage_bytes(table, &1u32.to_le_bytes());
        disk.stage_bytes(table + 4, &2u32.to_le_bytes());
        let inode = ktest_reg_inode(
            disk.clone(),
            ktest_single_device_table(),
            RegKnobs {
                meta_blkaddr: 0,
                datalayout: DataLayout::ChunkBased,
                size: 2 * 8192,
                xattr_isize: 0,
                addr_state: AddrState::Chunked {
                    format: 0x01, // 4-byte block map, blkbits 1 → chunkbits 13
                    bits: 13,
                },
                i_u: 0,
            },
        );
        let mut buf = vec![0u8; 5 * PAGE_SIZE];
        let (mut writer, _) = ktest_dio_writer(&mut buf, 0, 2 * 8192);
        let err = inode.read_direct_at(0, &mut writer).unwrap_err();
        assert_eq!(err.error(), Errno::EINVAL, "RD2② aster semantics, unfolded");
        // Exactly the walk's own touches: chunk 0's table read + data
        // bounce, then chunk 1's table read — the past-end data read
        // was rejected by the framework bound BEFORE enqueue.
        assert_eq!(
            disk.requests(),
            vec![
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 4,
                    nr_sectors: 1,
                }, // table 0: [2080, 2084)
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 8,
                    nr_sectors: 16,
                }, // chunk 0: [4096, 12288)
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 4,
                    nr_sectors: 1,
                }, // table 1: [2084, 2088)
            ]
        );
    }

    /// S07-IF-9: the map_dev composition through the flagged pread —
    /// chunk-8B extents on a flatdev image (extra=1, slot
    /// mapped_blkaddr = 2) translate `pa += 2 << 12` and STILL read
    /// the primary device (G-O06), content byte-exact; the crafted
    /// over-supply id (extra=2, mask=3, id 3 — past the two slots)
    /// fails ENODEV mid-walk before any data read.
    #[ktest]
    fn dio_flatdev_translation_and_enodev() {
        // Translation: chunks at blk 2/3 translate to 16384/20480
        // (the two reads overlap on the device — the position-
        // dependent pattern keeps that self-consistent).
        let disk = Arc::new(ErofsMemoryDisk::new(7 * PAGE_SIZE));
        stage_pattern(&disk, 4 * PAGE_SIZE, 3 * PAGE_SIZE);
        let table = ktest_ids(3, 0) as usize; // 14368, 8-aligned
        stage_index(&disk, table, 1, 2);
        stage_index(&disk, table + 8, 1, 3);
        let fs = ktest_fs_on(
            disk.clone(),
            ktest_super_block(12, 3),
            ktest_flatdev_table(&[(10, 2)], 1),
        );
        let inode = ktest_reg_inode_on(
            &fs,
            RegKnobs {
                meta_blkaddr: 3,
                datalayout: DataLayout::ChunkBased,
                size: 2 * 8192,
                xattr_isize: 0,
                addr_state: AddrState::Chunked {
                    format: 0x21,
                    bits: 13,
                },
                i_u: 0,
            },
        );
        let mut buf = vec![0u8; 6 * PAGE_SIZE];
        let (mut writer, pad) = ktest_dio_writer(&mut buf, 0, 2 * 8192);
        assert_eq!(inode.read_direct_at(0, &mut writer).unwrap(), 2 * 8192);

        for i in 0..8192 {
            assert_eq!(
                buf[pad + i],
                pattern(4 * PAGE_SIZE + i),
                "chunk 0 byte {i} (translated)"
            );
            assert_eq!(
                buf[pad + 8192 + i],
                pattern(5 * PAGE_SIZE + i),
                "chunk 1 byte {i} (translated)"
            );
        }
        assert_eq!(
            disk.requests(),
            vec![
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 28,
                    nr_sectors: 1,
                }, // table 0
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 32,
                    nr_sectors: 16,
                }, // chunk 0: [16384, 24576)
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 28,
                    nr_sectors: 1,
                }, // table 1
                BioRequest {
                    type_: BioType::Read,
                    start_sector: 40,
                    nr_sectors: 16,
                }, // chunk 1: [20480, 28672)
            ]
        );

        // ENODEV: extra=2/mask=3 with two slots; id 3 is masked-valid
        // but past the array (the linux idr_find miss). meta 0 keeps
        // the table inside the one-page disk.
        let disk = Arc::new(ErofsMemoryDisk::new(PAGE_SIZE));
        stage_index(&disk, ktest_ids(0, 0) as usize, 3, 5);
        let fs = ktest_fs_on(
            disk.clone(),
            ktest_super_block(12, 0),
            ktest_flatdev_table(&[(10, 100), (20, 200)], 3),
        );
        let inode = ktest_reg_inode_on(
            &fs,
            RegKnobs {
                meta_blkaddr: 0,
                datalayout: DataLayout::ChunkBased,
                size: 8192,
                xattr_isize: 0,
                addr_state: AddrState::Chunked {
                    format: 0x21,
                    bits: 13,
                },
                i_u: 0,
            },
        );
        let (mut writer, _) = ktest_dio_writer(&mut buf, 0, SECTOR_SIZE);
        let err = inode.read_direct_at(0, &mut writer).unwrap_err();
        assert_eq!(err.error(), Errno::ENODEV);
        // The table read ran; the data read never did.
        assert_eq!(
            disk.requests(),
            vec![BioRequest {
                type_: BioType::Read,
                start_sector: 4,
                nr_sectors: 1,
            }]
        );
    }
}
