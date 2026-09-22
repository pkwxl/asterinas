// SPDX-License-Identifier: MPL-2.0

//! VFS inode trait implementations for the erofs
//! [`Inode`](super::super::Inode).
//!
//! Dispatch-only surface — the terminal shape of T-024 S05
//! (`docs/T-013/S08/index.md` §4, `docs/T-013/analysis.md` §7.4):
//! every body below is one of the three sanctioned forms (S08-D3)
//! — a one-line forward into an inherent method (possibly with a
//! view conversion), a single-line descriptor-field getter, or a
//! write-face minimal body. No logic lives here; the bodies are
//! hosted by the inherent faces (the `inode/` submodules, and
//! `xattr.rs` for the xattr pair) and cited per member. The one
//! conditional landed with T-025 S07: `read_at` dispatches on the
//! direct-I/O status flag before forwarding (F7) — a flag-based
//! choice between two one-line forwards, still "dispatch only"
//! (ext2 `impl_for_vfs/inode.rs:35-47` the exact precedent), and
//! the SINGLE place in erofs that reads the flag.
//!
//! Same-name pairs (`metadata`/`lookup`/`open`/`read_link`/
//! `page_cache`/`fs`, and since T-026 `get_xattr`/`list_xattr`)
//! resolve to the TYPED INHERENT faces through Rust's
//! inherent-method precedence (the S08 §7.2 shadowing table, the
//! xattr pair its +2 continuation): the framework only ever sees
//! the trait face, while erofs-internal callers use the inherent
//! faces directly.
//!
//! Write faces: `write_at`, `resize`, `set_mode`, `set_owner`, and
//! `set_group` answer `EROFS` (the S07-D5 minimal bodies); the
//! no-`Result` time setters are no-ops (G-N07 — erofs never
//! records atime writes anywhere, including directory reads); and
//! `set_xattr`/`remove_xattr` answer `EROFS` deliberately (the
//! W-X01 state-B terminal bodies, `docs/T-015/S09/index.md` §2.1):
//! unlike the directory-entry family, the xattr write path has no
//! VFS mount-writable front gate (`check_mount_writable` is only
//! wired into directory entry mutations), so those overrides are
//! the only `EROFS` source for setxattr(2)/removexattr(2) on
//! erofs. The xattr read faces forward: `get_xattr`/`list_xattr`
//! are one-line forwards into the inherent gate chains hosted by
//! `xattr.rs` (T-026 S06/S07, the acl channel S08; every gate
//! lives there — this file stays dispatch-only).
//!
//! Everything else walks the trait defaults, by design: the
//! directory-entry mutation family (`create`, `create_tmpfile`,
//! `mknod`, `link`, `unlink`, `rmdir`, `rename`, `write_link`) is
//! refused with `EROFS` by the VFS front gate
//! (`check_dir_entry_mutation` — erofs keeps `FsFlags::RDONLY`
//! permanently set, `fs.rs`) before any filesystem member is
//! reached, so those trait defaults are structurally unreachable
//! from syscalls and their errno differences stay REGISTERED
//! (`docs/T-013/analysis.md` §9.1), never simulated here;
//! `fallocate` keeps the `EOPNOTSUPP` default (Linux erofs has no
//! fallocate file operation either); `sync_all`/`sync_data` keep
//! the `Ok` defaults (no dirty pages on a read-only filesystem);
//! `check_permission` uses the framework mode-bit face; and ioctl
//! has no handler at all, so the observed `ENOTTY` comes from the
//! framework (G-P03).

use super::super::{Inode as ErofsInode, prelude::*};
use crate::{
    fs::{
        file::{AccessMode, PerOpenFileOps, StatusFlags},
        vfs::{
            file_system::FileSystem,
            inode::{Extension, FileOps, Inode, Metadata, SymbolicLink},
            xattr::{XattrName, XattrNamespace, XattrSetFlags},
        },
    },
    process::{Gid, Uid},
    vm::page_cache::{PageCache, Vmo},
};

impl FileOps for ErofsInode {
    fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
        status_flags: StatusFlags,
    ) -> Result<usize> {
        // F7: THE direct-I/O dispatch point — the only line in erofs
        // that reads the flag (it is visible at this layer alone;
        // pushing it into the inherent faces would sink a VFS
        // per-open concept into the FS family). A missing dispatch
        // would silently degrade flagged preads into buffered reads
        // (the S10-4 hidden-drift trap), so the single grep hit is
        // the mechanical defense. Both arms begin with the same
        // EISDIR guard (file.rs), so directory fds read EISDIR
        // either way.
        if status_flags.contains(StatusFlags::O_DIRECT) {
            // file.rs read_direct_at: EISDIR, zero-length early out,
            // the G-P01 512-byte three-factor gate, then the Y3
            // no-fallback extent walk.
            self.read_direct_at(offset, writer)
        } else {
            // file.rs read_at: EISDIR guard first, zero-length early
            // exit, then the DataBacked page-cache read.
            self.read_at(offset, writer)
        }
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        // Write-face minimal body (S07-D5).
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn readdir_at(&self, offset: usize, visitor: &mut dyn DirentVisitor) -> Result<usize> {
        // dir.rs iteration half: cursor walk, seven-element cookie
        // model (F18).
        self.readdir_at(offset, visitor)
    }
}

impl Inode for ErofsInode {
    fn size(&self) -> usize {
        // X7: I7 caps the decoded size at i64::MAX — the cast is
        // lossless on 64-bit targets.
        self.desc().size as usize
    }

    fn resize(&self, _new_size: usize) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn metadata(&self) -> Result<Metadata> {
        // Infallible by construction (X16): the statx assembly
        // reads in-memory state only.
        Ok(self.metadata())
    }

    fn ino(&self) -> u64 {
        self.ino() // X2: st_ino = nid
    }

    fn type_(&self) -> InodeType {
        // `From<FileKind>` single source (S03-D3).
        self.kind().into()
    }

    fn mode(&self) -> Result<InodeMode> {
        Ok(self.desc().mode)
    }

    fn set_mode(&self, _mode: InodeMode) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn owner(&self) -> Result<Uid> {
        // X5: zero-extended at decode.
        Ok(Uid::new(self.desc().uid))
    }

    fn set_owner(&self, _uid: Uid) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    fn group(&self) -> Result<Gid> {
        Ok(Gid::new(self.desc().gid))
    }

    fn set_group(&self, _gid: Gid) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "erofs is a read-only filesystem");
    }

    // X8: one decoded `Duration`, three copies (D10).
    fn atime(&self) -> Duration {
        self.desc().time
    }

    fn set_atime(&self, _time: Duration) {
        // No-op by design (G-N07): erofs records no atime writes.
    }

    fn mtime(&self) -> Duration {
        self.desc().time
    }

    fn set_mtime(&self, _time: Duration) {
        // No-op by design: the filesystem is read-only.
    }

    fn ctime(&self) -> Duration {
        self.desc().time
    }

    fn set_ctime(&self, _time: Duration) {
        // No-op by design: the filesystem is read-only.
    }

    fn page_cache(&self) -> Option<Arc<Vmo>> {
        // Internal `Option<&PageCache>` → trait `Option<Arc<Vmo>>`:
        // one view of the single DataBacked payload (S02 §2.6).
        self.page_cache().map(PageCache::as_vmo).cloned()
    }

    fn open(
        &self,
        access_mode: AccessMode,
        status_flags: StatusFlags,
    ) -> Option<Result<Box<dyn PerOpenFileOps>>> {
        // G-N03: the seven-kind arm table lives in the inherent
        // body (inode/mod.rs).
        self.open(access_mode, status_flags)
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        // Inherent precedence plus the `Arc` upcast; the framework
        // caches the hit/ENOENT face (N14).
        Ok(self.lookup(name)?)
    }

    fn read_link(&self) -> Result<SymbolicLink> {
        // EROFS always yields `Plain` (the `Path` variant is
        // procfs-only).
        self.read_link().map(SymbolicLink::Plain)
    }

    fn fs(&self) -> Arc<dyn FileSystem> {
        // Unreachable-failure upgrade: with the strong inode cache
        // the mount always outlives the inodes it handed out
        // (S01 §2.4).
        self.fs().unwrap()
    }

    fn seek_end(&self) -> Option<usize> {
        // G-N06: Dir|Reg → Some(i_size); the remaining kinds keep
        // the default `None` face.
        self.seek_end()
    }

    fn extension(&self) -> &Extension {
        self.extension()
    }

    fn get_xattr(&self, name: XattrName, value_writer: &mut VmWriter) -> Result<usize> {
        // One-line forward to the inherent face (same-name
        // shadowing: Rust resolves the inherent method first — not
        // a recursion). The whole matrix-one gate chain — acl
        // dispatch, type/permission, name resolution (prefix
        // self-strip lives in `resolve_query_name`, the ext2-B4
        // anti-copy placement), nouser_xattr, lazy init, bloom,
        // the dual walk — is the inherent body (`xattr.rs`, T-026
        // S06; the System half S08).
        self.get_xattr(name, value_writer)
    }

    fn list_xattr(&self, namespace: XattrNamespace, list_writer: &mut VmWriter) -> Result<usize> {
        // One-line forward (same shadowing form as above). The
        // matrix-two chain — the X35 ENODATA conversion, the
        // W-X02 state-B namespace-as-capability-signal
        // consumption, the unconditionally ordered dual walk, and
        // the single-point terminal write — is the inherent body
        // (`xattr.rs`, T-026 S07).
        self.list_xattr(namespace, list_writer)
    }

    // W-X01 (state B; no landing marker — the degradation
    // condition is declared inline): The framework syscall layer
    // has no mount-level write gate on the xattr path —
    // `check_mount_writable` is only wired into directory entry
    // mutations — so these overrides are the layer-(1) equivalent
    // of the Linux mnt_want_write rejection: every write reaches
    // here only after the path resolved, and is rejected with
    // EROFS for any name, flags, value and inode type. If a
    // framework-level gate is ever added to the
    // setxattr/removexattr syscalls (state A1/A2 candidates),
    // these overrides become unreachable and may be removed with
    // no behavior change. The trait defaults (EOPNOTSUPP) below
    // remain the layer-(2)/(3) equivalents — precisely equivalent
    // and, as in Linux, permanently unreachable.
    fn set_xattr(
        &self,
        _name: XattrName,
        _value_reader: &mut VmReader,
        _flags: XattrSetFlags,
    ) -> Result<()> {
        // Write-face minimal body (T-013 §7.4 form ③; the S09 §2.1
        // terminal text above). Message per S09-D2 — deliberately
        // not the T-024 family string: this pair follows its own
        // sample anchor (decision 6 of `docs/T-026/subtasks.md`).
        return_errno_with_message!(Errno::EROFS, "the filesystem is read-only");
    }

    fn remove_xattr(&self, _name: XattrName) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "the filesystem is read-only");
    }
}
