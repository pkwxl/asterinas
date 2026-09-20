// SPDX-License-Identifier: MPL-2.0

//! Regular-file reads for erofs inodes.
//!
//! Terminal responsibility (`docs/T-013/analysis.md` §7.3): the
//! `read_at` face — the EISDIR guard first, the zero-length early
//! exit, then the DataBacked page-cache read (the data body itself
//! lands with T-025). Deliberately no `set_atime` after reads
//! (G-N07: X8's three-times-identity baseline) and no O_DIRECT
//! special-casing (the aster framework has no erofs DIO channel —
//! statx DIOALIGN staying 0 is the W-N02 registered form; the
//! `_status_flags` parameter is ignored, ramfs same shape). Write,
//! resize, and preallocation paths do not exist: the filesystem is
//! read-only and every mutating entry point is rejected with
//! `EROFS` at the VFS adapter.
//!
//! Bring-up state (T-024 S02): the guard positions are live; past
//! them the deferred-capability answer (`EOPNOTSUPP`) holds until
//! the T-025 data body lands (decision 1 of `docs/T-024/
//! subtasks.md`).

#![short_vis_path::add(erofs)]

use super::{super::prelude::*, FileKind, Inode};
use crate::fs::file::StatusFlags;

impl Inode {
    /// Reads file data at `offset` through the page cache — the body
    /// the VFS adapter's `FileOps::read_at` forwards to (S05).
    ///
    /// Guard order is the assertion surface (analysis.md §6.2): a
    /// directory fd gets EISDIR before anything else — including the
    /// zero-length buffer (R2; sample `ext2/inode/file.rs:22-25`) —
    /// then a zero-length read is `Ok(0)` (ext2 same-order early
    /// exit). The data body beyond the guards lands with T-025.
    // Deliberately NO set_atime after reads — G-N07; the ext2
    // body's post-read `set_atime(utils::now())`
    // (`ext2/inode/file.rs:32`) is the negative sample, same family
    // as `ext2/inode/dir/mod.rs:61`.
    //
    // Bridging expect: the trait face still answers EOPNOTSUPP
    // itself until the S05 rewrite forwards here — first consumer:
    // S05.
    #[expect(dead_code)]
    pub(in crate::fs::fs_impls::erofs) fn read_at(
        &self,
        _offset: usize,
        writer: &mut VmWriter,
        _status_flags: StatusFlags, // no O_DIRECT special-casing
    ) -> Result<usize> {
        // read(2) on a directory fd → EISDIR. Guard precedes
        // everything (R2; sample ext2/inode/file.rs:22-25).
        if self.kind() == FileKind::Dir {
            return_errno!(Errno::EISDIR);
        }
        if writer.avail() == 0 {
            return Ok(0);
        }
        // Data body: DataBacked page-cache read — lands with T-025
        // (decision 1); the message keeps the transitional form.
        return_errno_with_message!(Errno::EOPNOTSUPP, "erofs data path is not implemented yet");
    }
}
