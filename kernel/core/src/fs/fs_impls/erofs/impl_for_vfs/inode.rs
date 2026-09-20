// SPDX-License-Identifier: MPL-2.0

//! VFS inode trait implementations for the erofs
//! [`Inode`](super::super::Inode).
//!
//! Wires the erofs `Inode` into the VFS layer by implementing the
//! `FileOps` and `Inode` traits. Read-side surfaces whose domains are
//! still pending (data path, namei, xattr) answer with `EOPNOTSUPP`
//! ("capability deferred") until their tasks land; every mutating
//! surface is explicitly rejected with `EROFS` — that rejection is
//! the final, structural behavior of a read-only filesystem, not a
//! placeholder.
//!
//! The no-error-returning time setters (`set_atime`/`set_mtime`/
//! `set_ctime`) are no-ops by design: erofs never records atime
//! writes anywhere (zero atime writes, including directory reads), so
//! there is no state they could mutate. The xattr read surfaces keep
//! the trait defaults (`EOPNOTSUPP`), which is exactly the
//! deferred-capability answer until the xattr domain lands.

use aster_block::BLOCK_SIZE;

use super::super::{Inode as ErofsInode, prelude::*};
use crate::{
    fs::{
        file::StatusFlags,
        vfs::{
            file_system::FileSystem,
            inode::{
                Extension, FallocMode, FileOps, HardLinkability, Inode, Metadata, MknodType,
                RenameMode,
            },
            xattr::{XattrName, XattrSetFlags},
        },
    },
    process::{Gid, Uid},
    vm::page_cache::Vmo,
};

impl FileOps for ErofsInode {
    fn read_at(
        &self,
        _offset: usize,
        _writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        // The data path lands with T-025; until then reads report the
        // deferred capability rather than fabricated data.
        return_errno_with_message!(Errno::EOPNOTSUPP, "erofs data path is not implemented yet");
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn readdir_at(&self, _offset: usize, _visitor: &mut dyn DirentVisitor) -> Result<usize> {
        // Namei and dirent iteration land with T-024.
        return_errno_with_message!(Errno::EOPNOTSUPP, "erofs readdir is not implemented yet");
    }
}

impl Inode for ErofsInode {
    fn size(&self) -> usize {
        // Interim shape: sizes stay zero until the metadata assembly
        // lands (T-024); the transitional handle already carries the
        // decoded descriptor, but this trait face does not read it
        // yet.
        0
    }

    fn resize(&self, _new_size: usize) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn metadata(&self) -> Result<Metadata> {
        // Interim shape: the metadata assembly reads the descriptor
        // with T-024; until then this reports an empty read-only
        // directory owned by root (ino/type_ are already real — they
        // derive from the transitional handle). Erofs records no
        // birth time on disk, so `birth_at: None` is final.
        let fs = self.fs()?;
        let nr_hard_links = if self.type_() == InodeType::Dir { 2 } else { 1 };
        Ok(Metadata {
            ino: self.ino(),
            size: 0,
            optimal_block_size: BLOCK_SIZE,
            nr_sectors_allocated: 0,
            last_access_at: Duration::ZERO,
            last_modify_at: Duration::ZERO,
            last_meta_change_at: Duration::ZERO,
            type_: self.type_(),
            mode: InodeMode::from_bits_truncate(0o555),
            nr_hard_links,
            uid: Uid::new_root(),
            gid: Gid::new_root(),
            container_dev_id: fs.container_device_id(),
            self_dev_id: None,
            birth_at: None,
        })
    }

    fn ino(&self) -> u64 {
        self.ino()
    }

    fn type_(&self) -> InodeType {
        self.type_()
    }

    fn mode(&self) -> Result<InodeMode> {
        // Interim shape: 0555 — a read-only directory — until the
        // metadata assembly lands (T-024).
        Ok(InodeMode::from_bits_truncate(0o555))
    }

    fn set_mode(&self, _mode: InodeMode) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn owner(&self) -> Result<Uid> {
        // Interim shape: root-owned until the metadata assembly
        // lands (T-024).
        Ok(Uid::new_root())
    }

    fn set_owner(&self, _uid: Uid) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn group(&self) -> Result<Gid> {
        Ok(Gid::new_root())
    }

    fn set_group(&self, _gid: Gid) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn atime(&self) -> Duration {
        // Interim shape: the decoded timestamps land with the
        // metadata assembly (T-024).
        Duration::ZERO
    }

    fn set_atime(&self, _time: Duration) {
        // No-op by design: erofs never records atime writes.
    }

    fn mtime(&self) -> Duration {
        Duration::ZERO
    }

    fn set_mtime(&self, _time: Duration) {
        // No-op by design: the filesystem is read-only.
    }

    fn ctime(&self) -> Duration {
        Duration::ZERO
    }

    fn set_ctime(&self, _time: Duration) {
        // No-op by design: the filesystem is read-only.
    }

    fn page_cache(&self) -> Option<Arc<Vmo>> {
        // No page cache until the data path lands (T-025).
        None
    }

    fn create(&self, _name: &str, _type_: InodeType, _mode: InodeMode) -> Result<Arc<dyn Inode>> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn create_tmpfile(
        &self,
        _mode: InodeMode,
        _hard_linkability: HardLinkability,
    ) -> Result<Arc<dyn Inode>> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn mknod(&self, _name: &str, _mode: InodeMode, _type_: MknodType) -> Result<Arc<dyn Inode>> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn link(&self, _old: &Arc<dyn Inode>, _name: &str) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn unlink(&self, _name: &str) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn rmdir(&self, _name: &str) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn lookup(&self, _name: &str) -> Result<Arc<dyn Inode>> {
        // Namei lands with T-024.
        return_errno_with_message!(Errno::EOPNOTSUPP, "erofs lookup is not implemented yet");
    }

    fn rename(
        &self,
        _old_name: &str,
        _target: &Arc<dyn Inode>,
        _new_name: &str,
        _mode: RenameMode,
    ) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn write_link(&self, _target: &str) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn fallocate(&self, _mode: FallocMode, _offset: usize, _len: usize) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn fs(&self) -> Arc<dyn FileSystem> {
        // Invariant: a live `Inode` always belongs to a live `Erofs`
        // instance — the mount holds a strong reference for as long as
        // any inode it handed out is reachable, so the guarded
        // upgrade in the internal `fs()` cannot fail here.
        self.fs().unwrap()
    }

    fn extension(&self) -> &Extension {
        self.extension()
    }

    fn set_xattr(
        &self,
        _name: XattrName,
        _value_reader: &mut VmReader,
        _flags: XattrSetFlags,
    ) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn remove_xattr(&self, _name: XattrName) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }
}
