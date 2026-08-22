// SPDX-License-Identifier: MPL-2.0

//! Device Mapper (DM) core component for Asterinas
//!
//! This crate provides the data-plane logic for DM:
//! - Target type registration and lookup
//! - DmTable with target management
//! - Linear, error and striped targets

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::sync::Arc;

mod device;
mod error;
mod linear;
mod split;
mod striped;
mod table;
mod target;

#[cfg(ktest)]
mod tests;

pub use device::DmDevice;
pub use error::{DmError, ErrorTargetType};
pub use linear::LinearTargetType;
pub use striped::StripedTargetType;
pub use table::{DmTable, DmTarget};
pub use target::{
    CtrOutcome, MappedIo, TargetType, TargetVersion, lookup_target, register_target,
    snapshot_targets,
};

/// Register all built-in target types.
///
/// Called once by the control-plane glue (`device::dm`) during the
/// first_kthread init stage.
pub fn init() {
    register_target(Arc::new(LinearTargetType::new())).expect("failed to register linear target");
    register_target(Arc::new(ErrorTargetType::new())).expect("failed to register error target");
    register_target(Arc::new(StripedTargetType::new())).expect("failed to register striped target");
}
