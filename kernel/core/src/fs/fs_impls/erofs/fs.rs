// SPDX-License-Identifier: MPL-2.0

//! Core `Erofs` filesystem state for a mounted erofs volume.
//!
//! This module owns `Erofs`, the top-level handle for a mounted erofs
//! volume, together with the FS-level inode cache and the mount-option
//! carrier. The mount-time assembly sequence (parse options -> read
//! superblock -> validate magic/blkszbits/features/checksum -> read the
//! root inode -> construct the handle via `Arc::new_cyclic`) is owned
//! by `Erofs::open` and lands stepwise with T-023: option parsing (the
//! first step) is in force and fails malformed data strings with the
//! parser's `EINVAL` surface, while every mount that survives parsing
//! is still rejected with `EOPNOTSUPP` until the remaining steps land
//! — a clear error, no panic, no swallowing.
//!
//! Erofs is strictly read-only: there is no write path, no dirty
//! tracking, and no block allocation anywhere below this handle, so the
//! superblock, mount options, and geometry are decoded once during
//! `open` and stay immutable for the lifetime of the instance.
//!
//! # Locking
//!
//! All filesystem-wide state in `Erofs` is immutable after `open`
//! returns: the superblock, mount options, and geometry are decoded
//! once and never written back (erofs is read-only), so they carry no
//! locks. `flags` and `fs_event_subscriber_stats` use atomics. The only
//! lock is `inode_cache`, an nid-to-inode map guarded by an `RwMutex`
//! with double-checked locking: the fast path probes under a read lock;
//! on a miss, the slow path revalidates under the write lock,
//! constructs the inode (which may read metadata blocks), and inserts
//! it before releasing the guard. Nothing else may be locked while
//! `inode_cache` is held. Strong reference cycles are forbidden: the
//! handle keeps a weak self reference (`self_ref`) and hands out
//! `Weak<Erofs>` clones to inodes.

use core::sync::atomic::Ordering;

use device_id::DeviceId;

use super::{inode::Inode, prelude::*, super_block::SuperBlock};
use crate::fs::vfs::file_system::{AtomicFsFlags, FsEventSubscriberStats, FsFlags};

/// Top-level handle for a mounted erofs filesystem.
///
/// Owns the decoded superblock, the parsed mount options, and the
/// FS-level inode cache (keyed by nid: erofs has no block groups, so
/// the per-group cache host of allocation-based filesystems is lifted
/// to the filesystem handle).
pub struct Erofs {
    /// Backing block device.
    block_device: Arc<dyn BlockDevice>,
    /// Decoded and validated superblock (immutable after `open`).
    #[expect(dead_code)]
    super_block: SuperBlock,
    /// Parsed mount options (immutable after `open`).
    #[expect(dead_code)]
    mount_options: ErofsMountOptions,
    /// Recorded VFS filesystem flags.
    flags: AtomicFsFlags,
    /// FS event stats for VFS.
    fs_event_subscriber_stats: FsEventSubscriberStats,
    /// FS-level inode cache: nid -> inode identity anchor.
    #[expect(dead_code)]
    inode_cache: RwMutex<BTreeMap<ErofsNid, Arc<Inode>>>,
    /// Weak self reference handed out to inodes.
    self_ref: Weak<Erofs>,
}

/// Parsed erofs mount options (main column: XATTR=y, POSIX_ACL=y,
/// ZIP/ONDEMAND/DAX/BACKED_BY_FILE=n).
///
/// Decoded once from the mount data string; immutable afterwards except
/// for the remount whole-reset path (see the remount design).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ErofsMountOptions {
    /// Visibility of `user.*` xattrs (Linux mount_opt XATTR_USER,
    /// `user_xattr`/`nouser_xattr`; default on).
    user_xattr: bool,
    /// Acceptance of POSIX ACL options (Linux mount_opt POSIX_ACL,
    /// `acl`/`noacl`; default on). Accepted with degraded semantics:
    /// there is no ACL enforcement layer (AUTO-FIXME(G-M07) at the
    /// match arms below).
    posix_acl: bool,
    /// Paths registered via `device=` (parse-time registration only,
    /// in given order; path validity and device-count matching are
    /// validated later by the mount-time device scan, not here).
    extra_devices: Vec<String>,
}

// Hand-written rather than derived: the Linux defaults (kzalloc zeroed,
// then XATTR_USER/POSIX_ACL explicitly set) leave both flags ON, while
// a derived `bool` default is `false`.
impl Default for ErofsMountOptions {
    fn default() -> Self {
        Self {
            user_xattr: true,
            posix_acl: true,
            extra_devices: Vec::new(),
        }
    }
}

impl ErofsMountOptions {
    // First consumer: the xattr visibility gate (T-015).
    #[expect(dead_code)]
    pub(super) fn user_xattr(&self) -> bool {
        self.user_xattr
    }

    // First consumer: the ACL read path (T-015).
    #[expect(dead_code)]
    pub(super) fn posix_acl(&self) -> bool {
        self.posix_acl
    }

    // First consumer: the mount-time device scan count check
    // (`scan_devices`, T-023).
    #[expect(dead_code)]
    pub(super) fn extra_devices(&self) -> &[String] {
        &self.extra_devices
    }

    /// Parses an erofs mount-option data string (`key[=value][,…]`).
    ///
    /// Pure function: no I/O, no global mutable state (log output aside),
    /// always starts from `Self::default()` — suitable for ktest and for
    /// reuse by the remount whole-reset path.
    ///
    /// Unknown keys, malformed values, and the dax family yield
    /// `Errno::EINVAL` (Linux parity; the ext2 sample's trim-plus-silent-
    /// ignore shape is a negative example and must not be copied).
    // AUTO-FIXME(W-M02): The aster framework resolves the block device before
    // this parser runs (FsCache::get_or_create), so with both a bad source
    // and bad options aster fails with ENODEV while Linux fails with EINVAL
    // from option parsing first. The ordering lives in the framework layer
    // and cannot be closed inside erofs; what erofs does control is the
    // parse-before-superblock-read ordering inside `Erofs::open` (mount-path
    // design). Accepted drift; see the drift-ledger summary for the row.
    pub(super) fn parse(data: Option<&str>) -> Result<Self> {
        let mut options = Self::default();
        let Some(data) = data else {
            // data == NULL -> zero tokens (fs_context.c:210-211).
            return Ok(options);
        };
        for token in data.split(',') {
            // (a) empty token: skipped — "a,,b" is equivalent to "a,b"
            //     (strsep empty field, guarded by `if (*key)` in Linux)
            if token.is_empty() {
                continue;
            }
            // (b) '='-headed token: skipped — "=foo" is silently
            //     ignored (Linux: `value == key -> continue`,
            //     fs_context.c:222-223)
            if token.starts_with('=') {
                continue;
            }
            // (c) split at the FIRST '='; later '='s stay inside the
            //     value — "device==v" gives value "=v"
            //     (strchr + *value++ = 0)
            let (key, value) = match token.split_once('=') {
                Some((key, value)) => (key, Some(value)),
                None => (token, None),
            };
            match (key, value) {
                // ---- #1-#4: flag / flag_no storage arms ----
                ("user_xattr", None) => options.user_xattr = true,
                ("nouser_xattr", None) => options.user_xattr = false,
                // AUTO-FIXME(G-M07): `acl`/`noacl` are parsed and stored (default on) for
                // Linux parity, but the target tree has no ACL enforcement semantics —
                // only a system.posix_acl_* name-mapping layer exists in the xattr
                // domain. The options are accepted with degraded semantics and no ACL is
                // actually enforced. The MS_POSIXACL mount-flag loss is a separate
                // framework row (W-M01) and is not handled here.
                ("acl", None) => options.posix_acl = true,
                ("noacl", None) => options.posix_acl = false,
                // ---- #16: directio/nodirectio — one shared message,
                //      no state ----
                ("directio", None) | ("nodirectio", None) => {
                    warn!("directio option not supported");
                }
                // ---- generic layer: a flag-type key with a value is a
                //      shape error (fs_parser "Unexpected value") ----
                (
                    "user_xattr" | "nouser_xattr" | "acl" | "noacl" | "directio" | "nodirectio",
                    Some(_),
                ) => {
                    return_errno_with_message!(Errno::EINVAL, "unexpected value for mount option");
                }
                // ---- #5: legal cache_strategy values — warn and
                //      ignore (G-M01 two-layer, legal half) ----
                ("cache_strategy", Some("disabled" | "readahead" | "readaround")) => {
                    warn!("compression not supported, cache_strategy ignored");
                }
                // ---- #6 (+ bare / empty): bad value; the warn arm and
                //      the reject arm stay physically separate (G-M01) ----
                ("cache_strategy", _) => {
                    return_errno_with_message!(Errno::EINVAL, "bad value for mount option");
                }
                // ---- #7-#9: the dax family is explicitly enumerated,
                //      always EINVAL (G-M02) ----
                ("dax", None) | ("dax", Some(_)) => {
                    return_errno_with_message!(Errno::EINVAL, "dax options not supported");
                }
                // ---- #10: nodax — explicit arm, errno and message
                //      identical to the unknown-key fallback (G-M02) ----
                ("nodax", _) => {
                    return_errno_with_message!(Errno::EINVAL, "unknown erofs mount option");
                }
                // ---- #11: device=<non-empty> registers the path as
                //      given; path and count checks belong to the
                //      mount-time device scan (G-M12 registration half) ----
                ("device", Some(value)) if !value.is_empty() => {
                    options.extra_devices.push(value.to_string());
                }
                // ---- #12/#13: bare or empty device ----
                ("device", _) => {
                    return_errno_with_message!(Errno::EINVAL, "bad value for mount option");
                }
                // ---- #14: fsid/domain_id=<non-empty> — warn and
                //      ignore (G-M03/G-O07) ----
                ("fsid", Some(value)) if !value.is_empty() => {
                    warn!("fsid option not supported");
                }
                ("domain_id", Some(value)) if !value.is_empty() => {
                    warn!("domain_id option not supported");
                }
                // ---- #15: bare or empty fsid/domain_id ----
                ("fsid", _) | ("domain_id", _) => {
                    return_errno_with_message!(Errno::EINVAL, "bad value for mount option");
                }
                // AUTO-FIXME(G-M06): Linux consumes the reserved "source" key in the VFS
                // fs_context layer before filesystem parsing, so `source=<dev>` legally
                // sets the mount source there. The aster framework hands the raw data
                // string to this parser, so any "source" token hits this EINVAL arm: the
                // errno collides with Linux's EINVAL family but the semantics differ (a
                // valid source specification is rejected). Accepted drift per the scope
                // ledger; revisit if the framework ever routes the source key itself.
                ("source", _) => {
                    return_errno_with_message!(
                        Errno::EINVAL,
                        "source is not an erofs mount option"
                    );
                }
                // ---- #17: unknown key (G-M05, parity row — no marker) ----
                _ => {
                    return_errno_with_message!(Errno::EINVAL, "unknown erofs mount option");
                }
            }
        }
        Ok(options)
    }
}

impl Erofs {
    /// Opens and loads an erofs filesystem from a block device.
    ///
    /// Interim shape (T-023 in progress): step 1 of the assembly
    /// sequence — parse the mount-option data string before any
    /// on-disk structure is read — is in force, so a malformed data
    /// string fails fast with the parser's `EINVAL` surface. The
    /// remaining steps — read the superblock, validate
    /// magic/blkszbits/features/checksum, scan the device table, read
    /// the root inode, and construct the handle via `Arc::new_cyclic`
    /// — land with the rest of T-023; until then every mount that
    /// survives parsing is rejected with a clear `EOPNOTSUPP`
    /// ("capability deferred"), deliberately distinct from the
    /// `EINVAL`/`EUCLEAN`/`EBADMSG` door that the final validation
    /// sequence will report, so no interim observation can be confused
    /// with the formal error surface.
    // AUTO-FIXME(G-M21): Several Linux mount-path allocation sites can
    // return -ENOMEM (superblock-private data, device slots, inode-cache
    // nodes, xattr scratch). Under Rust global-allocation semantics a failed
    // allocation aborts rather than yielding an error, and any intermediate
    // failure in `open` unwinds through Drop, so this implementation has no
    // reachable ENOMEM errno path. Do not add ENOMEM error arms here;
    // revisit only if fallible allocation APIs are introduced.
    pub(super) fn open(
        device: Arc<dyn BlockDevice>,
        flags: FsFlags,
        data: Option<&str>,
    ) -> Result<Arc<Self>> {
        // Step 1 — mount options FIRST (timing decision of the
        // mount-path design): Linux parses the monolithic data string
        // token by token before get_tree/fill_super ever reads the
        // superblock, so unknown keys and malformed values fail with
        // EINVAL regardless of the image content.
        let _mount_options = ErofsMountOptions::parse(data)?;
        // Steps 2.. — read_superblock (V1–V10 incl. the device scan),
        // handle construction, and the packed/root inode reads land
        // with the remaining T-023 subtasks; `device` and `flags` are
        // only consumed by those steps.
        let _ = (device, flags);
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "erofs mount assembly is not implemented yet"
        );
    }

    /// Returns the device ID of the underlying block device.
    pub(super) fn container_device_id(&self) -> DeviceId {
        self.block_device.id()
    }

    /// Returns the per file system flags.
    pub(super) fn fs_flags(&self) -> FsFlags {
        self.flags.load(Ordering::Relaxed)
    }

    /// Returns the fs event subscriber stats.
    pub(super) fn fs_event_subscriber_stats(&self) -> &FsEventSubscriberStats {
        &self.fs_event_subscriber_stats
    }

    /// Returns the root inode.
    ///
    /// Interim shape (T-021 skeleton): the real lookup — decode the
    /// root nid from the superblock and resolve it through
    /// `inode_cache` so a single nid always maps to a single inode
    /// identity — lands with the T-023 assembly sequence. Since `open`
    /// rejects every mount for now, this path is unreachable; it
    /// returns a placeholder directory inode so the `FileSystem`
    /// trait surface stays total.
    pub(super) fn root_inode(&self) -> Arc<Inode> {
        Arc::new(Inode::placeholder_dir(self.self_ref.clone()))
    }
}
