// SPDX-License-Identifier: MPL-2.0

//! VFS filesystem-type registration for erofs.
//!
//! `ErofsType` implements the `FsType` trait so the VFS layer can
//! discover and mount erofs volumes by name (`"erofs"`). Mount
//! deduplication follows the framework `FsCache`: one instance per
//! backing device, weak-upgrade based, with live RO/RW mismatches
//! surfacing as `EBUSY` from the framework.
//!
//! This module also owns the static erofs systree presence:
//! [`FsType::sysnode`] hands the registry a two-node tree — the
//! attribute-less `erofs` root and its `features` subdirectory with
//! ten read-only announcement attributes — which the registry
//! attaches under `/sys/fs` at registration time.

use aster_systree::{
    AttrLessBranchNodeFields, BranchNodeFields, Error, Result as SysTreeResult, SysAttrSetBuilder,
    SysNode, SysPerms, SysStr, inherit_sys_branch_node,
};
use aster_util::printer::VmPrinter;
use device_id::DeviceId;
use inherit_methods_macro::inherit_methods;
use spin::Once;

use super::{fs::Erofs, prelude::*};
use crate::fs::vfs::{
    file_system::FileSystem,
    registry::{FsCache, FsCreationCtx, FsProperties, FsType},
};

/// VFS-visible erofs filesystem type.
pub(super) struct ErofsType {
    cache: FsCache<DeviceId>,
}

pub(super) static EROFS_TYPE: ErofsType = ErofsType {
    cache: FsCache::new(),
};

impl FsType for ErofsType {
    type Key = DeviceId;

    fn name(&self) -> &'static str {
        "erofs"
    }

    fn properties(&self) -> FsProperties {
        FsProperties::NEED_DISK
    }

    fn create(&self, fs_creation_ctx: &mut FsCreationCtx) -> Result<Arc<dyn FileSystem>> {
        let disk = fs_creation_ctx.resolve_block_device()?.clone();
        let flags = fs_creation_ctx.flags();
        let args = fs_creation_ctx.args();
        Erofs::open(disk, flags, args).map(|fs| fs as Arc<dyn FileSystem>)
    }

    fn obtain_key_and_cache(
        &self,
        fs_creation_ctx: &mut FsCreationCtx,
    ) -> Option<(DeviceId, &FsCache<DeviceId>)> {
        let key = fs_creation_ctx
            .resolve_block_device()
            .ok()
            .map(|disk| disk.id())?;

        Some((key, &self.cache))
    }

    fn sysnode(&self) -> Option<Arc<dyn SysNode>> {
        // The tree is built once and cached in the `Once` static, so
        // repeated calls return the same node (the `FsType::sysnode`
        // contract). The registry attaches it under `/sys/fs`.
        Some(EROFS_SYSNODE_ROOT.call_once(build_sysnode).clone())
    }
}

/// Names of the erofs feature attributes under `/sys/fs/erofs/features`,
/// copied verbatim (order included) from Linux `erofs_feat_attrs[]`
/// (linux/fs/erofs/sysfs.c:74-83). The list is a static announcement and
/// intentionally does NOT track compile-time capabilities (e.g. the ZIP
/// features are announced even when ZIP support is disabled).
const EROFS_FEATURE_ATTRS: [&str; 10] = [
    "zero_padding",
    "compr_cfgs",
    "big_pcluster",
    "chunked_file",
    "device_table",
    "compr_head2",
    "sb_chksum",
    "ztailpacking",
    "fragments",
    "dedupe",
];

/// A systree node representing the `/sys/fs/erofs` directory.
///
/// It is the static root of the erofs sysfs presence: an attribute-less
/// branch that carries exactly one child, the `features` subdirectory
/// (see `ErofsFeaturesNode`). It corresponds to the `erofs_root` kset
/// created at module init time in Linux (linux/fs/erofs/sysfs.c:249-270);
/// in the target it is built once at FsType registration time. Under the
/// baseline config the root has no attributes of its own (the two ZIP-gated
/// RW attributes exist only when CONFIG_EROFS_FS_ZIP is enabled,
/// linux/fs/erofs/sysfs.c:59-70), hence the attribute-less variant.
#[derive(Debug)]
struct ErofsSysNodeRoot {
    fields: AttrLessBranchNodeFields<dyn SysNode, Self>,
}

#[inherit_methods(from = "self.fields")]
impl ErofsSysNodeRoot {
    /// Creates a new `ErofsSysNodeRoot` instance named "erofs".
    fn new() -> Arc<Self> {
        Arc::new_cyclic(|weak_self| {
            let fields = AttrLessBranchNodeFields::new(SysStr::from("erofs"), weak_self.clone());
            ErofsSysNodeRoot { fields }
        })
    }

    /// Adds an erofs `SysNode` to this root.
    fn add_child(&self, new_child: Arc<dyn SysNode>) -> SysTreeResult<()>;
}

inherit_sys_branch_node!(ErofsSysNodeRoot, fields, {
    fn perms(&self) -> SysPerms {
        SysPerms::DEFAULT_RW_PERMS
    }
});

/// A systree node representing the `/sys/fs/erofs/features` directory.
///
/// It hosts the ten static feature announcement attributes copied from
/// Linux (linux/fs/erofs/sysfs.c:74-97). Every attribute is read-only
/// (0444) and always reads "supported\n" (linux `attr_feature` branch,
/// linux/fs/erofs/sysfs.c:118-120). The announcements intentionally do
/// not track compile-time capabilities: the six ZIP-family features are
/// announced even though ZIP support is disabled in the baseline config
/// (the "M3 quirk"; see docs/T-012/S08/index.md section 4.2). The node
/// has no children and no writeable attributes.
#[derive(Debug)]
struct ErofsFeaturesNode {
    fields: BranchNodeFields<dyn SysNode, Self>,
}

#[inherit_methods(from = "self.fields")]
impl ErofsFeaturesNode {
    /// Creates a new `ErofsFeaturesNode` instance named "features",
    /// populated with the ten RO feature attributes.
    fn new() -> Arc<Self> {
        let name = SysStr::from("features");

        let mut builder = SysAttrSetBuilder::new();
        for attr in EROFS_FEATURE_ATTRS {
            builder.add(SysStr::from(attr), SysPerms::DEFAULT_RO_ATTR_PERMS);
        }
        let attrs = builder
            .build()
            .expect("erofs feature attribute set is within the capacity");

        Arc::new_cyclic(|weak_self| {
            let fields = BranchNodeFields::new(name, attrs, weak_self.clone());
            ErofsFeaturesNode { fields }
        })
    }
}

inherit_sys_branch_node!(ErofsFeaturesNode, fields, {
    fn read_attr_at(
        &self,
        name: &str,
        offset: usize,
        writer: &mut VmWriter,
    ) -> SysTreeResult<usize> {
        if EROFS_FEATURE_ATTRS.contains(&name) {
            // Every feature attribute announces the same fixed string,
            // as does the Linux `attr_feature` show branch.
            let mut printer = VmPrinter::new_skip(writer, offset);
            writeln!(printer, "supported")?;
            Ok(printer.bytes_written())
        } else {
            Err(Error::AttributeError)
        }
    }

    fn write_attr(&self, _name: &str, _reader: &mut VmReader) -> SysTreeResult<usize> {
        // All feature attributes are read-only (0444).
        Err(Error::AttributeError)
    }

    fn perms(&self) -> SysPerms {
        SysPerms::DEFAULT_RW_PERMS
    }
});

static EROFS_SYSNODE_ROOT: Once<Arc<ErofsSysNodeRoot>> = Once::new();

/// Builds the static `/sys/fs/erofs` systree (root + features subtree)
/// in one shot. Called at most once via `EROFS_SYSNODE_ROOT`; the tree
/// is immutable after registration (no runtime add/remove surface).
fn build_sysnode() -> Arc<ErofsSysNodeRoot> {
    let root = ErofsSysNodeRoot::new();
    let features = ErofsFeaturesNode::new();
    root.add_child(features)
        .expect("the fresh erofs sysnode root accepts its only child");
    root
}
