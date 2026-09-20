// SPDX-License-Identifier: MPL-2.0

//! Test-only fixtures and helpers for erofs kernel tests.
//!
//! Compiled only under `#[cfg(ktest)]` and never referenced by
//! production files.
//!
//! Two fixture layers, landed by different tasks:
//!
//! * **Device-less handle fixtures (T-024/S04, this file)**: the null
//!   block device, the zero-baseline `SuperBlock` literal, and the
//!   LNK-shaped `InodeDesc` literal. These serve the PURE-GEOMETRY
//!   ktest suites (`is_fast_symlink` in `inode/symlink.rs`): the
//!   criterion consumes only the superblock geometry and the
//!   descriptor fields, never device bytes, so the handle is assembled
//!   directly (`Erofs::ktest_new` in `fs.rs`) instead of walking the
//!   real `Erofs::open` chain.
//! * **The in-memory disk and the erofs image builder**: still
//!   T-027's, mirroring the ext2 `test_utils` shape (staged disk bytes
//!   + `Erofs::open`). Until it lands, no ktest may assume readable
//!   device content.
//!
//! The vector suite for `utils` lives inside `utils.rs` itself (pure
//! functions need no disk fixtures); the dirent/symlink vector suites
//! of T-024/S04 live in their implementation files the same way.

use core::fmt;

use aster_block::{
    BlockDevice, BlockDeviceMeta,
    bio::{BioEnqueueError, BioStatus, SubmittedBio},
};
use device_id::{DeviceId, MajorId, MinorId};

use super::{
    inode::{AddrState, DataLayout, FileKind, InodeDesc, InodeVersion},
    prelude::*,
    super_block::SuperBlock,
};

// ===========================================================================
// Layer 0: the null block device
// ===========================================================================

/// A `BlockDevice` that is never read or written: every bio completes
/// with `NotSupported`. It exists only to fill the `block_device`
/// field of a ktest handle — the pure-geometry suites never issue I/O
/// (and a fixture that accidentally did would fail loudly here rather
/// than fabricating zero bytes).
pub(super) struct ErofsNullDevice;

impl fmt::Debug for ErofsNullDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ErofsNullDevice")
    }
}

impl BlockDevice for ErofsNullDevice {
    fn enqueue(&self, bio: SubmittedBio) -> core::result::Result<(), BioEnqueueError> {
        bio.complete(BioStatus::NotSupported);
        Ok(())
    }

    fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: 0,
            nr_sectors: 0,
        }
    }

    fn name(&self) -> &str {
        "erofs-ktest-null"
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(MajorId::new(0), MinorId::new(0))
    }
}

// ===========================================================================
// Layer 1: device-less literals (zero baselines, two knobs each)
// ===========================================================================

/// A zero-baseline `SuperBlock` with the two geometry knobs the
/// pure-geometry suites vary: `blkszbits` (the block size shift) and
/// `meta_blkaddr` (the metadata-area base, in blocks). Every other
/// field is the zero value — the consumers below (`block_size()`,
/// `inode_location` through `Erofs::ktest_new`) read geometry only,
/// never the feature bits, so a zeroed baseline cannot skew them.
///
/// The literal bypasses `SuperBlock::from(RawSuperBlock)` on purpose:
/// the conversion is the production single-`from_le` point and is
/// vector-tested on its own track (T-022); reusing it here would just
/// make the fixture depend on 21 raw fields being spelled out anyway.
pub(super) fn ktest_super_block(blkszbits: u8, meta_blkaddr: u32) -> SuperBlock {
    SuperBlock {
        magic: 0,
        feature_compat: 0,
        blkszbits,
        sb_extslots: 0,
        root_nid: 0,
        inos: 0,
        build_time: Duration::ZERO,
        blocks: 0,
        meta_blkaddr,
        xattr_blkaddr: 0,
        uuid: [0; 16],
        volume_name: [0; 16],
        feature_incompat: 0,
        u1: 0,
        extra_devices: 0,
        devt_slotoff: 0,
        dirblkbits: 0,
        xattr_prefix_count: 0,
        xattr_prefix_start: 0,
        packed_nid: 0,
        xattr_filter_reserved: 0,
    }
}

/// An LNK-shaped `InodeDesc` with the four knobs the fast/slow
/// criterion reads: the layout version (which fixes `inode_isize`
/// at 32/64), the datalayout, the inline-xattr size, and i_size.
/// Everything else is a zero baseline (`i_u` is unread on the LNK
/// arm; `addr_state` only feeds the T-025 map path).
pub(super) fn ktest_lnk_desc(
    version: InodeVersion,
    datalayout: DataLayout,
    xattr_isize: usize,
    size: u64,
) -> InodeDesc {
    InodeDesc {
        version,
        datalayout,
        kind: FileKind::Lnk,
        mode: InodeMode::from_bits_truncate(0o777),
        uid: 0,
        gid: 0,
        nlink: 1,
        size,
        xattr_isize,
        time: Duration::ZERO,
        i_u: 0,
        addr_state: AddrState::Flat,
        nr_sectors: 0,
    }
}
