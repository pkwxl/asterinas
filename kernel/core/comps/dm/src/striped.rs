// SPDX-License-Identifier: MPL-2.0

//! Striped target implementation (cf. Linux `drivers/md/dm-stripe.c`).
//!
//! The striped target interleaves fixed-size chunks across two or more
//! underlying devices. A single bio never crosses a chunk boundary because
//! the target reports `max_io_len == chunk_size` and the DM core splits
//! larger bios accordingly (cf. Linux `dm_set_target_max_io_len`).

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::any::Any;

use aster_block::BlockDevice;

use crate::{
    linear::resolve_device,
    target::{CtrOutcome, MappedIo, TargetType, TargetVersion},
};

/// The striped target type singleton (for registration)
pub struct StripedTargetType;

impl StripedTargetType {
    /// Get the singleton instance
    pub const fn new() -> Self {
        StripedTargetType
    }
}

/// One stripe leg: an underlying device and the physical start sector on it
/// (cf. Linux `struct stripe`, without the error-counting machinery).
pub struct StripeLeg {
    /// The underlying block device of this leg.
    pub dev: Arc<dyn BlockDevice>,
    /// The physical start sector on the underlying device.
    pub physical_start: u64,
}

/// Private data of a striped target instance
/// (cf. Linux `struct stripe_c`, trimmed down).
pub struct StripedPrivate {
    /// The number of stripe legs (`legs.len()`).
    pub stripes: u32,
    /// The chunk size in sectors; also the per-target `max_io_len`.
    pub chunk_size: u64,
    /// The stripe legs; `legs.len() == stripes`.
    pub legs: Vec<StripeLeg>,
}

/// Parse a strict non-negative decimal integer (no signs, no trailing junk).
fn parse_decimal(s: &str) -> Result<u64, &'static str> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("striped: expected a non-negative decimal integer");
    }
    s.parse::<u64>()
        .map_err(|_| "striped: decimal integer out of range")
}

impl TargetType for StripedTargetType {
    fn name(&self) -> &str {
        "striped"
    }

    fn version(&self) -> TargetVersion {
        // Matches Linux dm-stripe.c's target version.
        TargetVersion::new(1, 6, 0)
    }

    fn ctr(&self, len: u64, params: &[&str]) -> Result<CtrOutcome, &'static str> {
        // Validation order mirrors Linux `stripe_ctr` (dm-stripe.c:88-188).
        if params.len() < 2 {
            return Err("striped: not enough arguments");
        }

        let stripes = parse_decimal(params[0])?;
        if stripes == 0 || stripes > u32::MAX as u64 {
            return Err("striped: invalid stripe count");
        }

        let chunk_size = parse_decimal(params[1])?;
        if chunk_size == 0 {
            return Err("striped: invalid chunk_size");
        }

        if len % stripes != 0 {
            return Err("striped: target length not divisible by number of stripes");
        }

        let width = len / stripes;
        if width % chunk_size != 0 {
            return Err("striped: target length not divisible by chunk size");
        }

        if params.len() != 2 + 2 * stripes as usize {
            return Err("striped: not enough destinations specified");
        }

        let mut legs = Vec::with_capacity(stripes as usize);
        for i in 0..stripes as usize {
            let dev = resolve_device(params[2 + 2 * i])
                .map_err(|_| "striped: underlying device not found")?;
            let physical_start = parse_decimal(params[2 + 2 * i + 1])?;
            legs.push(StripeLeg {
                dev,
                physical_start,
            });
        }

        Ok(CtrOutcome {
            private: Box::new(StripedPrivate {
                stripes: stripes as u32,
                chunk_size,
                legs,
            }),
            max_io_len: chunk_size,
        })
    }

    fn map(&self, private: &dyn Any, sector_in_target: u64) -> Result<MappedIo, &'static str> {
        let p = private
            .downcast_ref::<StripedPrivate>()
            .ok_or("striped: invalid target private type")?;

        // Cf. Linux `stripe_map_sector` (dm-stripe.c:202-228). Always use
        // div/mod (the shift optimization for power-of-2 geometries is an
        // optional follow-up).
        let chunk = sector_in_target;
        let stripes = u64::from(p.stripes);
        let stripe = (chunk / p.chunk_size) % stripes;
        let dev_sector = (chunk / (p.chunk_size * stripes)) * p.chunk_size + chunk % p.chunk_size;

        let leg = &p.legs[stripe as usize];
        Ok(MappedIo {
            device: leg.dev.clone(),
            sector: dev_sector + leg.physical_start,
        })
    }

    fn status(&self, private: &dyn Any) -> String {
        match private.downcast_ref::<StripedPrivate>() {
            Some(p) => {
                // STATUSTYPE_TABLE only, cf. Linux `stripe_status`
                // (dm-stripe.c:379-385): "<stripes> <chunk_size>
                // [<dev_name> <physical_start>]+". Device names are bare
                // kernel names (no "/dev/" prefix).
                let mut s = p.stripes.to_string();
                s.push(' ');
                s.push_str(&p.chunk_size.to_string());
                for leg in &p.legs {
                    s.push(' ');
                    s.push_str(leg.dev.name());
                    s.push(' ');
                    s.push_str(&leg.physical_start.to_string());
                }
                s
            }
            None => String::new(),
        }
    }
}
