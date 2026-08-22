// SPDX-License-Identifier: MPL-2.0

//! Linear target implementation

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
};
use core::any::Any;

use aster_block::BlockDevice;

use crate::target::{CtrOutcome, MappedIo, TargetType, TargetVersion};

/// The linear target type singleton (for registration)
pub struct LinearTargetType;

impl LinearTargetType {
    /// Get the singleton instance
    pub const fn new() -> Self {
        LinearTargetType
    }
}

/// Private data of a linear target instance
pub struct LinearPrivate {
    /// The underlying block device
    pub dev: Arc<dyn BlockDevice>,
    /// The physical start sector on the underlying device
    pub offset: u64,
}

/// Resolve a device argument (a device path like "/dev/vdd" or a bare device
/// name like "vdd") to a registered block device.
pub(crate) fn resolve_device(name: &str) -> Result<Arc<dyn BlockDevice>, &'static str> {
    let bare = name.strip_prefix("/dev/").unwrap_or(name);
    aster_block::collect_all()
        .into_iter()
        .find(|dev| dev.name() == bare)
        .ok_or("linear: underlying device not found")
}

/// Parse a strict non-negative decimal sector offset.
fn parse_offset(s: &str) -> Result<u64, &'static str> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("linear: offset must be a non-negative decimal integer");
    }
    s.parse::<u64>().map_err(|_| "linear: invalid offset")
}

impl TargetType for LinearTargetType {
    fn name(&self) -> &str {
        "linear"
    }

    fn version(&self) -> TargetVersion {
        TargetVersion::new(1, 0, 0)
    }

    fn ctr(&self, _len: u64, params: &[&str]) -> Result<CtrOutcome, &'static str> {
        if params.len() != 2 {
            return Err("linear: expected \"<dev> <offset>\"");
        }
        let dev = resolve_device(params[0])?;
        let offset = parse_offset(params[1])?;
        Ok(CtrOutcome {
            private: Box::new(LinearPrivate { dev, offset }),
            max_io_len: 0,
        })
    }

    fn map(&self, private: &dyn Any, sector_in_target: u64) -> Result<MappedIo, &'static str> {
        let p = private
            .downcast_ref::<LinearPrivate>()
            .ok_or("linear: invalid target private type")?;
        Ok(MappedIo {
            device: p.dev.clone(),
            sector: p.offset + sector_in_target,
        })
    }

    fn status(&self, private: &dyn Any) -> String {
        match private.downcast_ref::<LinearPrivate>() {
            Some(p) => {
                let mut s = String::from(p.dev.name());
                s.push(' ');
                s.push_str(&p.offset.to_string());
                s
            }
            None => String::new(),
        }
    }
}
