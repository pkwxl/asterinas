// SPDX-License-Identifier: MPL-2.0

//! Core `Erofs` filesystem state for a mounted erofs volume.
//!
//! This module owns `Erofs`, the top-level handle for a mounted erofs
//! volume, together with the FS-level inode cache, the mount-option
//! carrier, and the mount-time assembly sequence `Erofs::open` — the
//! merged face of linux `erofs_fc_get_tree` + `erofs_fc_fill_super`:
//! parse the mount-option data string, read and validate the
//! superblock (the V1–V10 order, ending in the device scan), construct
//! the read-only handle, then walk the F10 packed-inode and F11/F12
//! root-inode doors. The code order of that sequence is the single
//! ordering authority of the erofs mount path (first failure stops;
//! the errno priority chain mirrors the linux fill_super order); the
//! decoder layer supplies mirrors and predicates only.
//!
//! Erofs is strictly read-only: there is no write path, no dirty
//! tracking, and no block allocation anywhere below this handle, so the
//! superblock, device table, and geometry are decoded once during
//! `open` and stay immutable for the lifetime of the instance (the
//! mount options are the one guarded exception — remount swaps the
//! whole carrier, see `# Locking`).
//!
//! # Locking
//!
//! Filesystem-wide state in `Erofs` falls into three classes:
//! immutable values, atomics, and two short-held `RwMutex`es. The
//! superblock mirror, the device table, and the geometry derived
//! from them are decoded once in `open` and never written back
//! (erofs is read-only), so they carry no locks. `flags` and
//! `fs_event_subscriber_stats` use atomics. `mount_options` is
//! whole-replaced only by the remount path (`set_fs_flags`), and
//! readers take a read guard just long enough to copy out the
//! values they need. `inode_cache` is the nid-to-inode map, an
//! `RwMutex` with double-checked locking: the fast path probes
//! under a read lock; on a miss, the slow path revalidates under
//! the write lock, constructs the inode (which may read metadata
//! blocks), and inserts it before releasing the guard. The two
//! locks never nest — neither may be held while acquiring the
//! other — and neither may be taken in interrupt context. Strong
//! reference cycles are forbidden: the handle keeps a weak self
//! reference (`self_ref`) and hands out `Weak<Erofs>` clones to
//! inodes.
//!
//! The `xattr_prefixes` cell holds the decoded long-prefix table: it
//! is published exactly once at mount step 6 (before the handle
//! becomes reachable through the FsCache) and is immutable
//! afterwards. It is a once-cell, not an OS lock — it adds no
//! lock-order constraint, and loading reads only the superblock
//! mirror, the device byte stream / the packed inode's page cache
//! (via a guaranteed cache-hit iget), never the two locks above.

use core::sync::atomic::Ordering;

use device_id::DeviceId;
use ostd::mm::VmIo;

use super::{
    inode::Inode,
    prelude::*,
    super_block::{
        BLKSZBITS_MAX, BLKSZBITS_MIN, DEVT_SLOT_SIZE, FeatureCompatSet, FeatureIncompatSet,
        NAME_LEN, RawDeviceSlot, RawSuperBlock, SUPER_MAGIC_V1, SUPER_OFFSET, SUPER_REGION_MAX,
        SUPPORTED_BLKSZBITS, SuperBlock, verify_superblock_checksum,
    },
    xattr::{XattrPrefixes, load_xattr_prefixes},
};
use crate::fs::vfs::file_system::{
    AtomicFsFlags, FsEventSubscriberStats, FsFlags, SuperBlock as VfsSuperBlock,
};

/// Top-level handle for a mounted erofs filesystem.
///
/// Owns the decoded superblock, the device table, the parsed mount
/// options, and the FS-level inode cache (keyed by nid: erofs has no
/// block groups, so the per-group cache host of allocation-based
/// filesystems is lifted to the filesystem handle).
pub struct Erofs {
    /// Backing block device.
    block_device: Arc<dyn BlockDevice>,
    /// Decoded and validated superblock (immutable after `open`).
    // Live since T-023 S04: read by `Erofs::root_inode` (root_nid) and
    // `Erofs::iget` (meta_blkaddr/blkszbits of the iloc formula),
    // both live through the `FileSystem` trait face. The bridging
    // `expect` was removed when the first consumer landed.
    super_block: SuperBlock,
    /// Device table assembled by the V10 device scan (immutable
    /// after `open`; remount never rescans).
    // Live since T-023 S06: read by `Erofs::vfs_super_block` through
    // `DeviceTable::total_blocks()` — the statfs f_blocks single
    // source; the data-path accessors (slots, mask) join with the
    // data-path domain, their own expects stay until then. The
    // bridging `expect` was removed when the first consumer landed.
    device_table: DeviceTable,
    /// Parsed mount options, guarded for the remount whole-reset
    /// path (readers copy out under a short guard; see `# Locking`).
    // Live since T-023 S07: whole-replaced by `Erofs::reconfigure`
    // (the remount face — the sole write site); the later readers
    // are the option getters of the xattr domain (short-guard
    // copy-out, T-015). The bridging `expect` was removed when the
    // first consumer landed.
    mount_options: RwMutex<ErofsMountOptions>,
    /// Recorded VFS filesystem flags.
    flags: AtomicFsFlags,
    /// FS event stats for VFS.
    fs_event_subscriber_stats: FsEventSubscriberStats,
    /// FS-level inode cache: nid -> inode identity anchor.
    // Live since T-023 S04: probed and filled by `Erofs::iget`, live
    // through the `FileSystem` trait face. The bridging `expect` was
    // removed when the first consumer landed.
    inode_cache: RwMutex<BTreeMap<ErofsNid, Arc<Inode>>>,
    /// Weak self reference handed out to inodes.
    self_ref: Weak<Erofs>,
    /// The decoded long-xattr name-prefix table: published exactly
    /// once by the F15 call at mount step 6 and frozen for the mount
    /// lifetime (a once-cell — see `# Locking` and `xattr.rs`).
    xattr_prefixes: XattrPrefixes,
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

    // Live since T-023 S02: the V10 device scan (`scan_devices` in
    // this file) consumes the given-device list for the count check
    // and the flatdev/multi-device discrimination. The bridging
    // `expect` was removed when the first consumer landed.
    pub(super) fn extra_devices(&self) -> &[String] {
        &self.extra_devices
    }

    /// O3 helper for the remount whole-reset path: drops the
    /// `device=` registrations parsed into this value and returns
    /// it. Linux reconfigure never copies the dev context
    /// (`sbi->opt = new_sbi->opt` copies the opt word only,
    /// super.c:805), so registrations parsed on the remount face
    /// live and die inside the caller's local value. Sole caller:
    /// `Erofs::reconfigure` step 2 — the mount face keeps consuming
    /// the registrations through the V10 device scan instead (two
    /// strictness regimes by context, exactly as in linux).
    pub(super) fn without_devices(mut self) -> Self {
        self.extra_devices.clear();
        self
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
    /// Opens and assembles an erofs filesystem from a block device.
    ///
    /// This is the merged face of linux `erofs_fc_get_tree` +
    /// `erofs_fc_fill_super` (`super.c:625-757`): the assembly order
    /// of the mount-path design (`docs/T-012/S04/index.md` §2, folded
    /// into `docs/T-012/analysis.md` §5.1) is the single ordering
    /// authority for the erofs mount path — the decoder layer
    /// supplies mirrors and predicates only (T-010 layering rule 4).
    ///
    /// Seven straight-line steps, first failure stops (the errno
    /// priority chain mirrors the linux fill_super order): (1) parse
    /// the mount-option data string BEFORE any on-disk read; (2) read
    /// and validate the superblock — the V1–V10 order ending in the
    /// device scan; (3) construct the handle, forcibly read-only
    /// (`flags | RDONLY`, F1 — the FsCache RO/RW reuse semantics
    /// depend on it); (4) F10: when the FRAGMENTS bit pairs with a
    /// non-zero packed_nid, iget the packed inode and run the
    /// layer-3 compressed-data gate on it; (5) F11/F12: iget the root
    /// inode, layer-3 gate BEFORE the directory type judgement, so a
    /// compressed root (EOPNOTSUPP) stays errno-distinguishable from
    /// a readable non-directory root (EINVAL); (6) the F15 long-xattr
    /// prefix-table load (state-A full load; errors fail the mount);
    /// (7) success. Step 3 is pure-memory
    /// construction — no errno path — and any later failure unwinds
    /// the whole handle through Drop, leaving no half-assembled
    /// instance and no FsCache entry (M1–M6 single-track rollback).
    // AUTO-FIXME(G-M21): Several Linux mount-path allocation sites can
    // return -ENOMEM (superblock-private data, device slots, inode-cache
    // nodes, xattr scratch). Under Rust global-allocation semantics a failed
    // allocation aborts rather than yielding an error, and any intermediate
    // failure in `open` unwinds through Drop, so this implementation has no
    // reachable ENOMEM errno path. Do not add ENOMEM error arms here;
    // revisit only if fallible allocation APIs are introduced.
    // AUTO-TODO(G-M17/G-M19): The packed inode is iget-validated at
    // mount time (F10) but is deliberately NOT kept as a resident
    // sbi->packed_inode counterpart: linux's resident-ownership face and
    // its put_super drop (U4) have no equivalent here — the inode cache
    // holds the only strong reference, uniform with every other inode,
    // and the xattr-prefix table below is the only post-root assembly
    // step. Do not add a dedicated resident-assembly face (shrinker,
    // module caches, per-mount sysfs dir) in this function; those cuts
    // are registered in the skeleton ledger.
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
        let mount_options = ErofsMountOptions::parse(data)?;
        // Step 2 — superblock read + validation order V1–V10
        // (`read_superblock` above, incl. the V10 device scan).
        // Read errors pass through; the option handle only feeds the
        // V10 count check.
        let (super_block, device_table) = read_superblock(&device, &mount_options)?;
        // Step 3 — construct the handle (F1: erofs is forcibly
        // read-only, `s_flags |= SB_RDONLY`, super.c:632; the FsCache
        // RO/RW reuse semantics depend on it). Pure-memory
        // construction: no errno path (allocation failure aborts,
        // G-M21).
        let erofs = Arc::new_cyclic(|weak_self| Erofs {
            block_device: device,
            super_block,
            device_table,
            mount_options: RwMutex::new(mount_options),
            flags: AtomicFsFlags::new(flags | FsFlags::RDONLY),
            fs_event_subscriber_stats: FsEventSubscriberStats::new(),
            inode_cache: RwMutex::new(BTreeMap::new()),
            self_ref: weak_self.clone(),
            xattr_prefixes: XattrPrefixes::new(),
        });

        // Step 4 — F10 packed inode (super.c:724-729): FRAGMENTS bit AND
        // packed_nid != 0 → iget through the inode cache; any I-family
        // error fails the mount. Layer 3 (G-M15, rejection chain): a
        // compressed payload on a REG/DIR/LNK inode fails here with
        // EOPNOTSUPP, mirroring the a_ops assignment in erofs_fill_inode
        // (special files return early there and stay exempt).
        // G-Z05 (negative): this gate checks ONLY for compressed payloads —
        // there is deliberately NO "packed inode must be compressed"
        // cross-check; dual-malformed images (plain packed inode) keep
        // mounting (matrix §5.1 row 6).
        if erofs
            .super_block
            .feature_incompat()
            .contains(FeatureIncompatSet::FRAGMENTS)
            && erofs.super_block.packed_nid != 0
        {
            let packed = erofs.iget(erofs.super_block.packed_nid)?;
            if packed.is_data_compressed() {
                return_errno_with_message!(
                    Errno::EOPNOTSUPP,
                    "compressed inode data is not supported"
                );
            }
        }

        // Step 5 — F11 root inode + F12 type gate (super.c:731-740).
        // The layer-3 gate runs BEFORE the F12 type judgement, so
        // "compressed root" (EOPNOTSUPP) stays errno-distinguishable from
        // "readable non-directory root" (F12 EINVAL) — the order IS the
        // assertion surface (matrix §2.2 G-M15 row).
        let root = erofs.iget(ErofsNid::from(erofs.super_block.root_nid))?;
        if root.is_data_compressed() {
            return_errno_with_message!(Errno::EOPNOTSUPP, "compressed inode data is not supported");
        }
        if !root.is_dir() {
            return_errno_with_message!(Errno::EINVAL, "root inode is not a directory");
        }

        // Step 6 — F15: the long-xattr name-prefix table load
        // (super.c:746-748, `erofs_xattr_prefixes_init` — the body is
        // `load_xattr_prefixes` in `xattr.rs`). The state-A full load,
        // gated by the on-disk prefix count alone (P1: count == 0 →
        // zero reads, zero allocation; no incompat-bit cross-check,
        // G-X04); prefix bytes flow through the G-X02 dual mapping —
        // the packed inode's page cache when the FRAGMENTS door (step
        // 4) paired with a non-zero packed_nid, the device byte stream
        // otherwise. Errors pass through and fail the whole mount
        // (P4 EFSCORRUPTED → EUCLEAN; channel codes uncollapsed); on
        // success the decoded table is published into the frozen
        // `xattr_prefixes` cell (compute-then-publish — see the
        // `# Locking` section).
        load_xattr_prefixes(&erofs)?;

        // F17 — success log (erofs_info "mounted with root inode @ nid",
        // super.c:755): optional info!, not part of the parity surface.
        Ok(erofs)
    }

    /// Reconfigures the fs for remount: the merged face of linux
    /// `erofs_fc_reconfigure` (`super.c:789-809`).
    ///
    /// Order is the parity surface (mirrors the linux call chain
    /// parse_monolithic_mount_data → reconfigure_super → fc op):
    /// the mount-option parser runs FIRST and is the very same pure
    /// function as the mount path (RM4, per-token errno family
    /// identical); a parse failure leaves options and flags both
    /// untouched (a failed remount changes nothing). On success the
    /// whole option set is replaced, default-started (RM12; `None`
    /// data ≡ "" ⇒ zero tokens ⇒ defaults), minus any `device=`
    /// registrations which are silently dropped here (O3), and the
    /// flags are stored with RDONLY forced (RM13) — erofs stays
    /// read-only forever and the framework does not force the bit
    /// (`Mount::remount` fact M18). Always `Ok` on the store path:
    /// the syscall returns 0.
    ///
    /// No own errno arms anywhere: the sole failure source is the
    /// Step 1 parse passthrough (`?` forwards it bare, no message
    /// added). RM9's DBG_BUGON is omitted — every store site in
    /// this file ORs RDONLY in, so the assertion is structurally
    /// true. Remount never rescans devices, never re-reads the
    /// superblock, and never touches the inode cache (RM12 replaces
    /// the option word only, exactly `sbi->opt = new_sbi->opt`).
    pub(super) fn reconfigure(&self, flags: FsFlags, data: Option<&str>) -> Result<()> {
        // Step 1 — RM4: parse FIRST, with the very same pure parser as
        // the mount path (S01). Linux parses the monolithic data string
        // into a fresh fs_context (default-started, `erofs_init_fs_context`
        // super.c:859-879) BEFORE `reconfigure_super` runs the fs op, so
        // a bad token fails the whole remount with EINVAL regardless of
        // the instance state — and a failure here changes nothing else:
        // `Mount::remount` propagates the `?` before touching per-mount
        // flags (mount.rs:659-661), matching "failed reconfigure changes
        // nothing" on the linux side.
        //
        // No ENOMEM arm: parser allocations abort rather than yield an
        // errno (G-M21 family; the mount-side marker at `open` covers
        // the family, no second marker here).
        let new_opt = ErofsMountOptions::parse(data)?;

        // Step 2 — RM12 whole reset + O3 device= silent drop.
        // `parse` always starts from defaults, so `None` (≡ "") yields
        // the default option set: a bare remount resets user_xattr/acl
        // back to on (matrix §2.5 row 1). The `device=` registrations
        // parsed into `new_opt.extra_devices` are deliberately NOT
        // installed: linux reconfigure never copies the dev context
        // (`sbi->opt = new_sbi->opt` copies the opt word only), so the
        // registrations live and die inside this local value. Bare
        // `device` / empty `device=` already failed EINVAL in Step 1
        // (generic parser layer, identical on both faces). Contrast
        // with the mount face, where the same registrations are
        // consumed by the V10 device scan (G-M12 count EINVAL /
        // G-M13 EOPNOTSUPP) — two strictness regimes by context,
        // exactly as in linux.
        *self.mount_options.write() = new_opt.without_devices();

        // Step 3 — RM13 forced read-only: store, then Ok (syscall 0).
        // The framework does not force the bit (fact M18), so erofs
        // must — every store site in the file ORs RDONLY in, which is
        // what makes the omitted RM9 assertion structurally true.
        // Live-snapshot consumers of this store: FileSystem::flags()
        // (FsCache G6/G7 reuse checks), sb().flags → statfs ST_RDONLY
        // (SF11, S06 D5), /proc/self/mountinfo fs flag field (M23),
        // and the fs half of the write-path EROFS double check (M20).
        self.flags.store(flags | FsFlags::RDONLY, Ordering::Relaxed);
        Ok(())
    }

    /// Read-side snapshot of the per-fs flags (ext2 fs.rs:212-215
    /// shape). RDONLY is permanently present: set by the open
    /// constructor (F1) and re-forced by every remount (RM13, S07).
    /// One single source feeds the FsCache RO/RW reuse check
    /// (G6/G7 via FileSystem::flags) and the statfs f_flags
    /// assembly (SF11 via vfs_super_block).
    pub(super) fn fs_flags(&self) -> FsFlags {
        self.flags.load(Ordering::Relaxed)
    }

    /// The VFS-facing superblock: the erofs_statfs translation
    /// (super.c:984-1003) plus the framework-only container_dev_id
    /// field (mountinfo major:minor, fact M23). Assembled fresh on
    /// every call — pure arithmetic over immutable mirrors plus the
    /// live flag snapshot, no I/O, no caching (a cached copy would
    /// freeze f_flags across remount, S07/RM13).
    // AUTO-FIXME(W-M03): Linux always sets ST_VALID (1 << 31) in
    // f_flags (vfs_statfs assembles it outside the filesystem). The
    // aster statfs syscall layer has no ST_VALID bit in its flag set,
    // so statfs(2) here always reports bit31 == 0 where Linux reports
    // 1 — a registered framework-level drift, asserted as-is by the
    // baseline matrix. The fix belongs to the statfs syscall layer
    // (one constant, every filesystem benefits; scope ledger keeps it
    // as a candidacy). It cannot be emulated from this side:
    // StatfsFlags::from_bits_truncate strips any bit the syscall flag
    // set does not define, and setting bit31 in sb().flags would be
    // silently dropped here while polluting every other FsFlags
    // consumer. Do not try either.
    pub(super) fn vfs_super_block(&self) -> VfsSuperBlock {
        // SF2/SF10 — one evaluation, two consumers. Linux sets
        // f_bsize = s_blocksize and relies on the vfs_statfs
        // fallback for f_frsize; aster has no fallback (M12), so
        // both fields carry the same explicit value.
        let bsize = self.super_block.block_size();

        // SF8/SF9 — fsid two-branch. `uuid_is_null` is a plain
        // 16-zero-byte test. The linux "no bdev -> 0" sub-branch
        // (super.c:998, fscache mode) is unreachable in the main
        // column: bdev mounts only.
        let fsid = if self.super_block.uuid == [0u8; 16] {
            new_encode_dev(self.block_device.id()) as u64
        } else {
            fold_uuid_to_fsid(&self.super_block.uuid)
        };

        // SF11 — live flag snapshot; see the flags field row below
        // for the assembly notes (RDONLY permanence, no-NOATIME
        // structural guarantee).
        let fs_flags = self.fs_flags();

        VfsSuperBlock {
            // SF1 — the V1 magic constant, NOT the mirror field
            // (the mirror's magic is the V2 gate input only,
            // T-011/S02 §5.2 note).
            magic: SUPER_MAGIC_V1 as u64,
            bsize,
            // SF3 — single source: DeviceTable::total_blocks()
            // (primary + Σ flatdev slot blocks, AT6-26/MD8);
            // do NOT re-sum from the mirror here (S03 §6).
            blocks: self.device_table.total_blocks() as usize,
            // SF4 — a read-only fs is always full: free = 0
            // (super.c:992). Explicit on purpose; SuperBlock::new
            // would silently default the same value — do not
            // "fix" in either direction.
            bfree: 0,
            bavail: 0,
            // SF5 — linux fills ULLONG_MAX; the framework default
            // is 0, so this MUST be explicit (anti-default-drift,
            // matrix §2.4 names this field).
            files: u64::MAX as usize,
            // SF6 — inos is a mount-time snapshot (mirror field,
            // immutable afterwards); inos = 0 -> ULLONG_MAX, and
            // ULLONG_MAX - inos cannot underflow.
            ffree: (u64::MAX - self.super_block.inos) as usize,
            fsid,
            // SF7 — EROFS_NAME_LEN = 255 (erofs_fs.h:289; XA2
            // host: super_block.rs, usize).
            namelen: NAME_LEN,
            frsize: bsize,
            // SF11 — FsFlags bits only. RDONLY is always set
            // (F1/RM13); FsFlags has no NOATIME bit, so a "silent
            // noatime" cannot leak into f_flags — the per-mount
            // ST_NOATIME bit is assembled by the syscall layer
            // from PerMountFlags for explicit `-o noatime` only
            // (same shape as linux flags_by_sb, which maps
            // RDONLY/SYNC/MANDLOCK only, not SB_NOATIME).
            flags: fs_flags.bits() as u64,
            // Framework-only field (no kstatfs counterpart):
            // mountinfo major:minor consumes the same value (M23).
            container_dev_id: self.block_device.id(),
        }
    }

    /// Returns the fs event subscriber stats.
    pub(super) fn fs_event_subscriber_stats(&self) -> &FsEventSubscriberStats {
        &self.fs_event_subscriber_stats
    }

    /// Returns the backing block device handle (immutable after
    /// `open`).
    ///
    /// Read-side accessor for the inode family: the decode entry
    /// (`read_inode_desc`, inode/mod.rs) and the minimal data backend
    /// (inode/data.rs) read through it. Returns the `Arc` itself so
    /// backend construction can clone the handle.
    pub(super) fn block_device(&self) -> &Arc<dyn BlockDevice> {
        &self.block_device
    }

    /// Returns the decoded superblock mirror (immutable after
    /// `open`).
    ///
    /// Read-side accessor for the inode family: the base-point
    /// formula family (`inode_location` and friends) and the
    /// block-size geometry derive from it.
    pub(super) fn super_block(&self) -> &SuperBlock {
        &self.super_block
    }

    /// Returns the weak self reference handed out to inodes and data
    /// backends (the strong-reference-cycle prohibition, see
    /// `# Locking`).
    pub(super) fn self_ref(&self) -> &Weak<Erofs> {
        &self.self_ref
    }

    /// Returns the assembled device table (immutable after `open`;
    /// remount never rescans — O3 drops `device=` silently).
    ///
    /// Read-side accessor for the data-path map walk
    /// (`inode/data.rs`): the flatdev translation and the slot
    /// lookup of `map_dev`, plus the chunk device-id mask (S03-D8 —
    /// the DeviceTable stays the single source of those values).
    pub(super) fn device_table(&self) -> &DeviceTable {
        &self.device_table
    }

    /// Assembles a device-less handle for the pure-geometry ktest
    /// suites (T-024/S04): the null device below is never read — the
    /// fast/slow symlink criterion and the base-point family consume
    /// only the superblock geometry and descriptor fields. The mount
    /// options, flags, and cache all take their defaults; the
    /// self-reference is wired through `new_cyclic` exactly like
    /// `open` does, so handle-derived paths behave identically.
    ///
    /// Lives here (not in `test_utils`) because the private fields of
    /// `Erofs`/`DeviceTable` are only visible inside this module.
    /// The real image-builder fixture (staged disk bytes + `open`)
    /// lands with T-027; until then no ktest may assume readable
    /// device content (the data-path suites use `ktest_new_with`
    /// with an explicit in-memory disk instead).
    #[cfg(ktest)]
    pub(super) fn ktest_new(super_block: SuperBlock) -> Arc<Self> {
        Self::ktest_new_with(
            Arc::new(super::test_utils::ErofsNullDevice),
            super_block,
            DeviceTable::single_device(0),
        )
    }

    /// The extended ktest constructor behind [`Erofs::ktest_new`]
    /// (T-025 S02): an explicit backing device and device table —
    /// the data-path fixtures pair the in-memory disk with crafted
    /// flatdev tables. Everything else takes the same defaults as
    /// `ktest_new`; handle-derived paths behave identically to
    /// `open`-assembled mounts.
    #[cfg(ktest)]
    pub(super) fn ktest_new_with(
        block_device: Arc<dyn BlockDevice>,
        super_block: SuperBlock,
        device_table: DeviceTable,
    ) -> Arc<Self> {
        Arc::new_cyclic(|weak_self| Self {
            block_device,
            super_block,
            device_table,
            mount_options: RwMutex::new(ErofsMountOptions::default()),
            flags: AtomicFsFlags::new(FsFlags::RDONLY),
            fs_event_subscriber_stats: FsEventSubscriberStats::new(),
            inode_cache: RwMutex::new(BTreeMap::new()),
            self_ref: weak_self.clone(),
            xattr_prefixes: XattrPrefixes::new(),
        })
    }

    /// Looks up an inode by nid through the FS-level inode cache,
    /// constructing it on a miss — the iget parity (`erofs_iget`),
    /// with the cache contract of the inode-domain design
    /// (`docs/T-013/analysis.md` §1.2).
    ///
    /// Cache shape: strong `Arc` values, no eviction, insert only on
    /// success — one nid resolves to one inode identity for the
    /// lifetime of the mount, and a failed construction leaves no
    /// entry, so every error replays on each call (no negative
    /// cache). Double-checked locking (the family template of
    /// `ext2/block_group.rs`): the fast path probes under a read
    /// lock; on a miss the slow path revalidates under the write
    /// lock, decodes the inode — reading metadata blocks inside the
    /// critical section is allowed — and inserts before releasing
    /// the guard.
    ///
    /// The construction chain lives in `Inode::new` (inode/mod.rs,
    /// T-024 final shape): the five-step decode (step 1, the iloc
    /// formula, migrated there as `inode_location`) plus the payload
    /// assembly and the `Arc` wrap. This function body stays
    /// gate-free (C-2): the I12 arm-head gate sits inside
    /// `InodePayload::new` — the Linux shape, where `iget5_locked`
    /// carries no check and `erofs_fill_inode` rejects — so the two
    /// cache paths above perform zero checks (G4 hit-never-refills)
    /// and this locking skeleton is untouched since T-023.
    ///
    /// Error face — forwarded with `?` unchanged, no message added
    /// here: I2 device reads pass through, I3/I4/I10 report
    /// `EOPNOTSUPP`, I7/I8 report `EUCLEAN`, and I12 (the assembly
    /// gate) reports `EOPNOTSUPP`; mount-time callers (F10/F11) and
    /// runtime callers (lookup tails) get the same face — iget does
    /// not distinguish callers. No nid range pre-check (Linux has
    /// none; a past-the-volume nid surfaces as the I2 device error).
    ///
    /// G-M21: no ENOMEM arm (the cache-node allocation aborts in
    /// this tree, never an errno). Locking (R1): the critical
    /// section consumes the block device, the superblock mirror,
    /// and a weak-self clone only — the mount-options lock is never
    /// taken here.
    pub(super) fn iget(&self, nid: ErofsNid) -> Result<Arc<Inode>> {
        // Fast path: cache hit under read lock.
        if let Some(inode) = self.inode_cache.read().get(&nid) {
            return Ok(inode.clone());
        }

        // Slow path: revalidate under the write lock — another
        // thread may have inserted the inode between the read and
        // write lock acquisition.
        let mut inode_cache = self.inode_cache.write();
        if let Some(inode) = inode_cache.get(&nid) {
            return Ok(inode.clone());
        }

        // The construction chain (S01-D7: inside the critical
        // section — decode + payload assembly + Arc wrap all run in
        // `Inode::new`). Only the successful construction reaches
        // the insert below; every failure returned early and left
        // no entry (G5 — the error replays on the next call).
        let inode = Inode::new(self, nid)?;
        inode_cache.insert(nid, inode.clone());
        Ok(inode)
    }

    /// Returns the root inode.
    ///
    /// Final shape: identity resolves through the inode cache —
    /// `iget(root_nid)` hits the entry the mount-time F11 read
    /// inserted, and the cache only grows, so every call returns
    /// the same `Arc<Inode>` (no resident root field: the F10–F12
    /// mount doors plus the cache are the single source of root
    /// identity and validity). The root nid is zero-extended from
    /// the le16 mirror with no range check (see `iget`). The family
    /// face stays fallible; the `FileSystem` trait face unwraps on
    /// the structural-unreachability argument (the mount validated
    /// the root and the strong cache pins it — the ext2 precedent).
    pub(super) fn root_inode(&self) -> Result<Arc<Inode>> {
        self.iget(ErofsNid::from(self.super_block.root_nid))
    }
}

// ---------------------------------------------------------------------------
// Mount-time superblock read: `read_superblock` — the V1–V10
// validation order of `erofs_read_superblock` (`super.c:276-367`) as
// one straight-line function (design: `docs/T-012/S02/index.md`,
// folded into `docs/T-012/analysis.md` §2).
// ---------------------------------------------------------------------------

/// Reads and validates the erofs superblock: the mount validation
/// order V1–V10 of `erofs_read_superblock` (`super.c:276-367`),
/// expressed as ONE straight-line function whose code order is the
/// assertion surface for the order-crossing rows (baseline matrix
/// §2.2: first failure stops; V5 before V6, V3 before V5, V7 before
/// V8/V9/V10).
///
/// Layering: this function owns the validation ORDER; `super_block.rs`
/// supplies the decode mirror and predicates only. Reads are exact
/// byte intervals (read sites #1/#2 of the decoder contract).
///
/// G-M21: no ENOMEM arm anywhere on this path (stack buffers only;
/// allocation failure is an abort in this tree, not an errno).
// Live since T-023 S05: step 2 of `Erofs::open` above calls it;
// ktest fixtures call it directly from the same host (design §9).
// The bridging `expect` was removed when the first consumer landed.
fn read_superblock(
    device: &Arc<dyn BlockDevice>,
    mount_options: &ErofsMountOptions,
) -> Result<(SuperBlock, DeviceTable)> {
    // V1 — superblock read (read site #1, `super.c:284-288`).
    // Read errors pass through unchanged (media -> EIO; beyond device
    // end -> EINVAL from the device stack, see the G-M10 note at V5).
    let raw: RawSuperBlock = device.read_val(SUPER_OFFSET)?;
    // Decode-then-gate (decision D2): pure field decode first — no
    // errors, no side effects, no ordering. Every gate below reads
    // host-order mirror fields or predicates; `raw` survives (Copy)
    // solely as the csum expected-value input (E1 category ②).
    let sb = SuperBlock::from(raw);

    // V2 — magic (`super.c:290-295`).
    if sb.magic != SUPER_MAGIC_V1 {
        return_errno_with_message!(Errno::EINVAL, "cannot find valid erofs superblock");
    }
    // V3a — blkszbits range, Linux parity [9, PAGE_SHIFT]
    // (`super.c:297-301`).
    if sb.blkszbits < BLKSZBITS_MIN || sb.blkszbits > BLKSZBITS_MAX {
        return_errno_with_message!(Errno::EINVAL, "blkszbits isn't supported");
    }
    // V3b — 4k-only gate (scope decision AR-S01-1).
    // AUTO-FIXME(G-M08): Linux accepts blkszbits in [9, PAGE_SHIFT]
    // (512B/1k/2k/4k block images all mount, super.c:298). This tree is
    // 4k-only by scope decision AR-S01-1: every blkszbits != 12 is
    // rejected here, so healthy 512B/1k/2k images that Linux mounts fail
    // with EINVAL (registered drift, matrix row G-M08 / AT6-8). Two
    // downstream judgements deliberately stay in general form although
    // only the 4k row is reachable: the csum coverage formula and the
    // page-bound sb_size check below. Reopening requires a dedicated
    // scope task (see the AR-S01-1 revival notes in the scope ledger).
    if sb.blkszbits != SUPPORTED_BLKSZBITS {
        return_errno_with_message!(Errno::EINVAL, "currently only 4096-byte block size");
    }
    // V4 — dirblkbits (`super.c:302-305`).
    if sb.dirblkbits != 0 {
        return_errno_with_message!(Errno::EINVAL, "dirblkbits isn't supported");
    }
    // V5 — superblock checksum, conditional on SB_CHKSUM
    // (`super.c:307-312`, algorithm `super.c:55-80`).
    if sb.feature_compat().contains(FeatureCompatSet::SB_CHKSUM) {
        // AUTO-FIXME(G-M10): Reads here are exact byte intervals into the
        // block device; an interval extending past the device end fails in
        // the device stack with EINVAL. Linux reads page-granular data and
        // zero-fills the tail, so a truncated image that declares blkszbits=12
        // with SB_CHKSUM set reaches the checksum compare and fails with
        // EBADMSG, where aster fails the interval read with EINVAL. A device
        // shorter than the superblock itself fails with EINVAL on both sides
        // (Linux: zero-fill then bad magic) — errno-identical, different
        // mechanism. Registered drift (zero-fill emulation rejected as
        // candidate B); the same family covers out-of-range slot and inode
        // reads later in the mount path. See the drift-ledger summary.
        let mut buf = [0u8; SUPER_REGION_MAX];
        let len = sb.checksummed_len(); // general formula; 4k row effective
        device.read_bytes(SUPER_OFFSET, &mut buf[..len])?;
        // kmemdup ENOMEM unreachable: stack buffer, no heap allocation
        // (G-M21 family).
        if !verify_superblock_checksum(&mut buf[..len], raw.checksum) {
            return_errno_with_message!(Errno::EBADMSG, "invalid checksum");
        }
    }
    // V6 — unknown incompat bits (`super.c:314-320`). The known-bit
    // union is NOT shrinkable (G3); known compression bits are
    // parsed-but-ignored, zero linkage with V9 (G-Z03).
    // AUTO-TODO(G-Z03): The known compression-half incompat bits —
    // ZERO_PADDING, COMPR_CFGS, ZTAILPACKING, and the compression
    // halves behind the dual-name bits 0x8/0x20 — are parsed into the
    // feature set but deliberately carry no mount-time action under
    // the compression shelving (scope decision AR-S01-5): accepting
    // them is the parity surface, an image with any of them set mounts
    // exactly as if they were clear. The V9 guard below does NOT
    // consult COMPR_CFGS either — compressed-image rejection flows
    // from the u1 test alone — and ZERO_PADDING's runtime zero-fill
    // optimisation has no counterpart. Do not reject or special-case
    // these bits, and do not cross-check them against u1 or against
    // inode datalayouts. Revive together with the compression
    // takeover (scope ledger G-Z01).
    if sb.has_unknown_incompat() {
        return_errno_with_message!(Errno::EINVAL, "unidentified incompatible feature");
    }
    // V7 — sb_size upper bound (`super.c:322-327`). The judgement is
    // PAGE-derived (PAGE_SIZE − SUPER_OFFSET) and MUST NOT be rewritten
    // as a block-size bound (matrix §2.2 hard requirement; under
    // 4k-only the two coincide, which is exactly why the simplification
    // would be wrong).
    if sb.sb_size() > SUPER_REGION_MAX {
        return_errno_with_message!(Errno::EINVAL, "invalid sb_extslots");
    }
    // V8 — volume_name NIL gate (`super.c:346-352`). Must run before
    // any `volume_name()` consumption: the accessor silently truncates
    // (T-011 §5.5). This function never calls the accessor itself.
    if !sb.volume_name_is_nul_terminated() {
        return_errno_with_message!(Errno::EUCLEAN, "bad volume name without nil terminator");
    }
    // V9 — compression cfg guard, rejection-chain layer 1
    // (`super.c:147-157,354-357`). Unconditional u1 zero test; the
    // stub does NOT consult the COMPR_CFGS bit (G-Z03). Chain-level
    // narrative (layers 1/3, G-M11/G-M15) belongs to the compression
    // rejection-chain design (`docs/T-012/S05/index.md` §2).
    if sb.u1 != 0 {
        return_errno_with_message!(
            Errno::EOPNOTSUPP,
            "compression disabled, unable to mount compressed erofs"
        );
    }
    // V10 — device scan (`super.c:159-274,359-360`): G-M12 count
    // check / G-M14 flatdev / G-M13 transitional rejection — body:
    // `scan_devices` below.
    let device_table = scan_devices(device, &sb, mount_options)?;
    Ok((sb, device_table))
    // (linux tail: fscache deprecation warning `super.c:362-363` —
    // no such branch in the main column; not migrated.)
}

// ---------------------------------------------------------------------------
// V10 device scan: `scan_devices` and the `DeviceTable` it produces
// (design: `docs/T-012/S03/index.md`, folded into `docs/T-012/analysis.md`
// §4). The scan is the tail step of `read_superblock` above; the table
// is installed into `Erofs` as an immutable field by the assembly
// sequence.
// ---------------------------------------------------------------------------

/// V10 device scan (`erofs_scan_devices`, `super.c:159-274`):
/// G-M12 count check / G-M14 flatdev acceptance / G-M13 transitional
/// rejection of true multi-device mounts. Produces the `DeviceTable`
/// consumed by statfs (total_blocks) and the data path (slots, mask).
///
/// Layering note (S02 D1): this is the tail step of `read_superblock`;
/// ordering decisions live there, this body only implements the V10
/// internal arm order, which is a straight translation of
/// `super.c:224-270`.
///
/// G-M21: no ENOMEM arm (Vec growth failure aborts in this tree).
// Live since T-023 S03: the V10 tail call of `read_superblock` above
// invokes it; ktest fixtures call it directly from the same host
// (design §9). The bridging `expect` was removed when the first
// consumer landed.
fn scan_devices(
    device: &Arc<dyn BlockDevice>,
    sb: &SuperBlock,
    mount_options: &ErofsMountOptions,
) -> Result<DeviceTable> {
    // total_blocks seeded from the primary-device block count
    // (`sbi->total_blocks = sbi->dif0.blocks`, super.c:224; dif0.blocks
    // is seeded at super.c:328 from dsb->blocks). The mirror field is
    // u32 (on-disk __le32, no truncation on either side); the u64 here
    // is the accumulator for multi-slot sums, matching linux's u64
    // total_blocks (S06 §4 correction; revised in place by S10).
    let mut total_blocks = u64::from(sb.blocks);

    // On-disk extra count is gated by the DEVICE_TABLE feature bit
    // (super.c:225-228): without the bit the on-disk field reads as 0.
    // `from_bits_truncate` drops unknown incompat bits but DEVICE_TABLE
    // is a known bit (0x8), so the contains() test is unaffected (G4).
    let ondisk: usize = if sb
        .feature_incompat()
        .contains(FeatureIncompatSet::DEVICE_TABLE)
    {
        sb.extra_devices as usize // u16 mirror, host order
    } else {
        0
    };
    let given = mount_options.extra_devices().len();
    // (given <= 455 in practice: the mount data string is capped at
    // 4096 bytes by the framework, M2; usize compare, no overflow.)

    // G-M12 — count check (parity arm, super.c:230-235). Fires only
    // when the user DID pass `device=`; covers the main-column case
    // "single-device image + any device=" (ondisk reads 0 there).
    if given != 0 && given != ondisk {
        return_errno_with_message!(Errno::EINVAL, "extra devices don't match");
    }

    // Early return for images without extra devices (super.c:236-237).
    // Here given == 0 (otherwise the arm above fired). flatdev stays
    // false for single-device images — the early return precedes the
    // flatdev assignment (MD5, T-002 assembly fix ④).
    if ondisk == 0 {
        return Ok(DeviceTable::single_device(total_blocks));
    }

    // device_id_mask (super.c:242): roundup_pow_of_two(ondisk+1) - 1,
    // precomputed here for the data path (G-O06, T-014 consumes it).
    // ondisk <= 65535 (u16 field) so ondisk+1 <= 65536: no overflow,
    // and the result 65535 still fits; stored as u32 (decision D6).
    let device_id_mask = (ondisk as u32 + 1).next_power_of_two() - 1;

    if given == 0 {
        // G-M14 — flatdev acceptance (super.c:239-240 flag + the
        // self-allocating loop :251-270 calling erofs_init_device).
        // Main column has no fscache mode, so linux's
        // `!erofs_is_fscache_mode(sb)` guard is constant-true here
        // (F9 note); no rwsem (single-threaded assembly, no idr).
        let pos_base = sb.devt_slotoff as usize * DEVT_SLOT_SIZE;
        // Upper bound 65535 slots * 8 bytes = 512 KiB, one-shot
        // allocation; growth failure aborts, not an errno (G-M21).
        let mut slots = Vec::with_capacity(ondisk);
        for i in 0..ondisk {
            // Slot read (read site family of T-011 S07 §3.2 row 4,
            // revival form verbatim: devt_slotoff × DEVT_SLOT_SIZE +
            // i × 128). Exact interval read.
            //
            // (G-M10 family read point: a slot interval extending
            // past the device end fails with EINVAL from the device
            // stack where Linux fails the metabuf read with EIO —
            // same registered-drift family as the V5 read, see the
            // G-M10 note at the checksum arm in read_superblock;
            // collected by the drift-ledger summary.)
            let raw: RawDeviceSlot = device.read_val(pos_base + i * DEVT_SLOT_SIZE)?;
            // flatdev guards skip tag handling and device opening
            // (super.c:171-205 are guarded by `!flatdev`): the tag
            // field is neither read nor validated (MD4 — corrupted
            // tag images must mount), no bdev/file/fscache open, and
            // blocks/mapped_blkaddr are taken as-is (MD13 trust
            // semantics, no capacity cross-check, AR-S01-4).
            let blocks = u32::from_le(raw.blocks);
            let mapped_blkaddr = u32::from_le(raw.mapped_blkaddr);
            total_blocks += blocks as u64;
            slots.push(DeviceSlot {
                blocks,
                mapped_blkaddr,
            });
        }
        Ok(DeviceTable {
            flatdev: true,
            slots,
            total_blocks,
            device_id_mask,
        })
    } else {
        // G-M13 — true multi-device transitional rejection (given ==
        // ondisk > 0 here; every linux path below the count check is
        // unreachable behind this arm).
        // AUTO-FIXME(G-M13): A count-matching `device=` list is a valid Linux
        // multi-device mount: each given path is opened as a block device and
        // the image mounts. This tree is transitionally without a multi-device
        // runtime (only the flatdev translation half is implemented, see the
        // data-path design), so the mount is rejected here before any device
        // open. Registered drift: Linux mounts this image, aster fails with
        // EOPNOTSUPP (errno chosen by the scope-authorized design decision:
        // "capability not implemented yet" family, same as the compression
        // rejection; EINVAL is reserved for a future realignment with the
        // count-mismatch family if the scope ever flips to an explicit
        // rejection policy). Transitional compatibility layer — remove when a
        // multi-device data path is scoped in; at that point the per-path
        // device opens and the tag validation move into this scan.
        return_errno_with_message!(Errno::EOPNOTSUPP, "unable to mount multi-device erofs");
    }
}

/// Device table assembled by the V10 device scan (`scan_devices`).
///
/// Flat projection of linux's `erofs_dev_context` + per-device
/// `erofs_device_info` records (`internal.h:49-58,72-78`): flat
/// images carry no slots and no flatdev flag (total_blocks = the
/// primary block count); flatdev images record per-slot
/// blocks/mapped_blkaddr read from the PRIMARY device and accumulate
/// total_blocks (statfs f_blocks source, AT6-26/MD8). True
/// multi-device mounts never produce a table — they are rejected
/// inside the scan (G-M13).
///
/// Immutable after assembly (installed into `Erofs` once, read-only
/// afterwards; remount never rescans — O3 drops `device=` silently).
#[derive(Clone, Debug)]
pub(super) struct DeviceTable {
    flatdev: bool,
    slots: Vec<DeviceSlot>,
    total_blocks: u64,
    device_id_mask: u32,
}

/// One flatdev device slot (flatdev projection of
/// `erofs_device_info`: only the two fields the translation path
/// consumes; tag/path/bdev/fscache have no flatdev consumer).
#[derive(Clone, Copy, Debug)]
pub(super) struct DeviceSlot {
    blocks: u32,
    mapped_blkaddr: u32,
}

impl DeviceTable {
    fn single_device(total_blocks: u64) -> Self {
        // mask = roundup_pow_of_two(0+1) - 1 = 0: device ids always
        // resolve to the primary device (MD7).
        Self {
            flatdev: false,
            slots: Vec::new(),
            total_blocks,
            device_id_mask: 0,
        }
    }

    /// Direct ktest construction (T-025 S02): every field is a knob
    /// so the crafted-table vectors of the map-dev suite (S04-IF-2/3:
    /// extra=1/mask=1 and extra=2/mask=3, mirroring
    /// `roundup_pow_of_two(extra + 1) - 1`) bypass the V10 scan
    /// without crafting on-disk slots. `slots` are
    /// `(blocks, mapped_blkaddr)` pairs addressed 1-based by
    /// `slot(id)` — `slots[0]` is extra device 1. `total_blocks`
    /// collapses to 0: only the statfs path reads it, and the
    /// data-path fixtures never call statfs.
    ///
    /// Lives here (not in `test_utils`) because the fields are
    /// only visible inside this module, exactly like
    /// [`Erofs::ktest_new_with`].
    #[cfg(ktest)]
    pub(super) fn ktest_new(flatdev: bool, slots: &[(u32, u32)], device_id_mask: u32) -> Self {
        Self {
            flatdev,
            slots: slots
                .iter()
                .map(|&(blocks, mapped_blkaddr)| DeviceSlot {
                    blocks,
                    mapped_blkaddr,
                })
                .collect(),
            total_blocks: 0,
            device_id_mask,
        }
    }

    // Live since T-025 S03: `DataBackend::map_dev` reads the flag as
    // the construction-face invariant of the translation arm (the
    // flatdev discrimination of the map-dev walk, design G-O06).
    pub(super) fn flatdev(&self) -> bool {
        self.flatdev
    }

    /// statfs f_blocks single source (SF3/AT6-26; consumed by the
    /// statfs design — must NOT re-sum from the mirror there).
    // Live since T-023 S06: the SF3 field of `Erofs::vfs_super_block`
    // above consumes it. The bridging `expect` was removed when the
    // first consumer landed.
    pub(super) fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    /// Valid-bit mask for chunk device ids (super.c:242; data-path
    /// consumption, G-O06 → T-014).
    // Live since T-025 S04: the chunk-8B device-id masking of the
    // map walk (`DataBackend::map_blocks_chunked`, through the
    // fs-upgrade single source S03-D8).
    pub(super) fn device_id_mask(&self) -> u32 {
        self.device_id_mask
    }

    /// (blocks, mapped_blkaddr) of extra device `id`, 1-based
    /// (linux `idr_find(&tree, id - 1)`, data.c:209). `None` = id
    /// past the slot array; the ENODEV mapping of the unreachable
    /// true-multi-device runtime (MD10) is owned by the data path.
    // Contract (design §3.3): `id == 0` (the primary device) is not
    // served by this table — the caller checks for zero first and
    // reads `Erofs.block_device` directly.
    // Live since T-025 S03: `DataBackend::map_dev` consumes the slot
    // pair on every nonzero-id walk (the ENODEV arm on a miss).
    pub(super) fn slot(&self, id: u32) -> Option<(u32, u32)> {
        self.slots
            .get(id as usize - 1)
            .map(|s| (s.blocks, s.mapped_blkaddr))
    }
}

// ---------------------------------------------------------------------------
// statfs fsid folds: the two private pure functions consumed by the
// SF8/SF9 branches of `Erofs::vfs_super_block` (design:
// `docs/T-012/S06/index.md` §3, folded into `docs/T-012/analysis.md`
// §5.2). No I/O, no state — direct ktest vectors at the tail of this
// file.
// ---------------------------------------------------------------------------

/// SF8 — the `uuid_to_fsid` fold (statfs.h:54-59 via super.c:1000-
/// 1001): v = le64(uuid[0..8]) XOR le64(uuid[8..16]). aster's
/// f_fsid is a single u64; on little-endian targets the low 32
/// bits land in fsid_t.val[0] and the high 32 in val[1], which is
/// byte-identical to Linux's two-u32 layout (x86_64/riscv64/
/// loongarch64 are all LE; revisit on any big-endian port).
fn fold_uuid_to_fsid(uuid: &[u8; 16]) -> u64 {
    // try_into on fixed-length slices cannot fail; unwrap is
    // infallible.
    let lo = u64::from_le_bytes(uuid[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(uuid[8..16].try_into().unwrap());
    lo ^ hi
}

/// SF9 — device-encoded fsid for zero-uuid images (super.c:997-999):
/// `huge_encode_dev` literally returns `new_encode_dev(dev)`
/// (kdev_t.h:53-56, verified in-tree), so u64_to_fsid yields
/// { val[0] = new_encode_dev(dev), val[1] = 0 }. Replicated from
/// the DeviceId accessors (12-bit major / 20-bit minor, device-id
/// crate lib.rs:38-45); every term fits in u32, no overflow.
fn new_encode_dev(id: DeviceId) -> u32 {
    let major = id.major().get() as u32;
    let minor = id.minor().get();
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

#[cfg(ktest)]
mod tests {
    use device_id::{MajorId, MinorId};
    use ostd::prelude::*;

    use super::*;

    /// fold vectors (the design's §7 fold family). The all-zero
    /// input actually takes the SF9 branch at runtime and never
    /// reaches the fold — the row locks the pure formula itself.
    /// Single-byte probes pin the byte order end to end: uuid[0]
    /// is the lowest byte of the result, uuid[15] the top byte
    /// (little-endian layout lock).
    #[ktest]
    fn fold_uuid_to_fsid_vectors() {
        // all-zero -> 0 (formula lock; runtime goes the SF9 branch)
        assert_eq!(fold_uuid_to_fsid(&[0u8; 16]), 0);
        // lo = 1, hi = 0 -> 1
        let mut uuid = [0u8; 16];
        uuid[0] = 1;
        assert_eq!(fold_uuid_to_fsid(&uuid), 1);
        // lo = 0, hi = 1 -> 1 (uuid[8] is the high half's low byte)
        let mut uuid = [0u8; 16];
        uuid[8] = 1;
        assert_eq!(fold_uuid_to_fsid(&uuid), 1);
        // uuid[15] = 1 -> top byte (the LE byte-order lock)
        let mut uuid = [0u8; 16];
        uuid[15] = 1;
        assert_eq!(fold_uuid_to_fsid(&uuid), 0x0100_0000_0000_0000);
        // two equal halves -> 0 (all-0xFF form)
        assert_eq!(fold_uuid_to_fsid(&[0xffu8; 16]), 0);
        // the 1..=8 ladder against a zero half -> the le64 ladder
        // (the design §7 "interleaved vector" row's expectation)
        let mut uuid = [0u8; 16];
        for (i, slot) in uuid.iter_mut().enumerate().take(8) {
            *slot = i as u8 + 1;
        }
        assert_eq!(fold_uuid_to_fsid(&uuid), 0x0807_0605_0403_0201);
        // the full 0..=15 ladder: staggered halves XOR to 0x08 per
        // byte (genuine two-half coverage)
        let ladder: [u8; 16] = core::array::from_fn(|i| i as u8);
        assert_eq!(fold_uuid_to_fsid(&ladder), 0x0808_0808_0808_0808);
    }

    /// new_encode_dev vectors (the design's §7 encode family):
    /// (0,0) -> 0; (8,0) -> 0x800 — the classic /dev/sda value;
    /// (8,16) -> 0x810; (1,0xFFFFF) -> 0xFFF001FF — 20-bit minor
    /// boundary; (0xFFF,0) -> 0xFFF00 — 12-bit major boundary.
    #[ktest]
    fn new_encode_dev_vectors() {
        let dev = |major: u16, minor: u32| DeviceId::new(MajorId::new(major), MinorId::new(minor));
        assert_eq!(new_encode_dev(dev(0, 0)), 0x0);
        assert_eq!(new_encode_dev(dev(8, 0)), 0x800);
        assert_eq!(new_encode_dev(dev(8, 16)), 0x810);
        assert_eq!(new_encode_dev(dev(1, 0xFFFFF)), 0xFFF0_01FF);
        assert_eq!(new_encode_dev(dev(0xFFF, 0)), 0xFFF00);
    }
}
