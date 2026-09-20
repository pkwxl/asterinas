// SPDX-License-Identifier: MPL-2.0

//! EROFS: the Enhanced Read-Optimized File System, a read-only Linux
//! filesystem designed for read-heavy workloads on fixed media.
//!
//! This module is the entry point for erofs support in Asterinas. A caller
//! registers the `Erofs` filesystem type via `init`, after which the VFS
//! can recognize `"erofs"` as a filesystem type and attempt to mount erofs
//! volumes through the standard filesystem trait interfaces.
//!
//! The Enhanced Read-Optimized File System (erofs) is a Linux read-only
//! filesystem targeting memory efficiency and compact on-disk layouts:
//! fixed-size inodes with a 32-byte compact form, inline data and
//! symlinks, cluster-aligned data placement, and optional compression.
//! This implementation is read-only by construction: there is no write
//! path, no dirty tracking, and no allocator anywhere in the family;
//! every mutating VFS entry point is explicitly rejected with `EROFS`.
//!
//! # On-disk layout
//!
//! An erofs volume starts with a 1024-byte reserved region followed by
//! the superblock; inode numbers (`nid`s) index inodes linearly, and
//! file data is placed in units of the block size chosen at mkfs time.
//! There are no block groups, bitmaps, or group descriptor tables.
//! The `super_block` module owns the on-disk superblock decoding and
//! validation (the checksum interval formula lives there, not in
//! `utils`), while `fs` owns the mount-time assembly sequence.
//!
//! # Module structure
//!
//! | Module         | Responsibility                                        |
//! |----------------|-------------------------------------------------------|
//! | `fs`           | Filesystem handle: mount state, inode cache           |
//! | `inode`        | Inode family: decoding, data, files, dirs, symlinks   |
//! | `xattr`        | Extended attribute iteration and reads                |
//! | `super_block`  | On-disk superblock decoding and validation            |
//! | `impl_for_vfs` | Wires erofs types into the VFS trait interfaces       |
//! | `fs_type`      | `FsType` registration glue and sysnode                 |
//! | `utils`        | Checksum/hash primitives (`crc32c`, `xxh32`)          |
//! | `prelude`      | Common imports shared across submodules               |
//!
//! The inode family splits into `mod`, `data`, `file`, `dir`, and
//! `symlink` submodules; the ktest-only fixtures live in `test_utils`
//! (compiled under `#[cfg(ktest)]`, never referenced by production
//! files).
//!
//! # Metadata reads
//!
//! EROFS keeps no shared block-device cache. All raw metadata reads
//! (superblock, device table, inode records, chunk indexes / block
//! maps, inline payloads, xattr structures) are synchronous, uncached,
//! byte-precise reads over the main device byte stream (`VmIo`
//! primitives on `Arc<dyn BlockDevice>`), issued at the point of use
//! in task context. Errors pass through unchanged (no folding, no
//! re-mapping). Directory entry walks do NOT use this channel — they
//! read through the directory inode's own page cache. Page-cache
//! fills are hosted by the backend in `inode/data.rs`: full mapped
//! pages go through block BIOs, while sub-page tails and inline
//! payloads are fetched with the same byte-stream primitives as part
//! of the fill (submit context) — the uncached point-of-use contract
//! above governs the metadata consumers only.
//!
//! # Bring-up state
//!
//! The skeleton, the superblock/inode decoding, the mount assembly,
//! and the namei family have landed (T-021..T-024). T-025 lands the
//! non-compressed data path: the mapping layer and the page-cache
//! bridge in `inode/data.rs` are final since its S05 slice — every
//! DataBacked page fill (buffered reads, mmap faults, readdir, slow
//! symlinks) goes through the four-arm backend — and the direct-I/O
//! read path (the flag dispatch in `impl_for_vfs` plus
//! `read_direct_at` in `inode/file.rs`) since S07: DIO reads walk
//! the extents straight through the device byte channel and never
//! touch the page cache. The buffered `read_at` collection is the
//! remaining slice.
//!
//! # References
//!
//! - `linux/fs/erofs/` (Linux v6.12.103, the behavioral parity baseline)

// Set this module's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "erofs: "
    };
}

pub use fs::Erofs;
pub use inode::Inode;

use self::fs_type::EROFS_TYPE;
use crate::fs::vfs::registry;

mod fs;
mod fs_type;
mod impl_for_vfs;
mod inode;
mod prelude;
mod super_block;
mod utils;
mod xattr;

#[cfg(ktest)]
mod test_utils;

/// Registers the erofs filesystem type with the VFS registry.
///
/// Registration can only fail on a duplicate filesystem-type name or a
/// sysnode collision, both of which would be programming bugs (`"erofs"`
/// is unique in the whole tree), hence the `unwrap`.
pub(super) fn init() {
    registry::register(&EROFS_TYPE).unwrap();
}
