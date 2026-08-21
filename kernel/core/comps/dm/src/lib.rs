// SPDX-License-Identifier: MPL-2.0

//! Device Mapper (DM) core component for Asterinas
//!
//! This crate provides the data-plane logic for DM:
//! - Target type registration and lookup
//! - DmTable with target management
//! - Linear and error targets

#![no_std]
#![deny(unsafe_code)]
// Temporarily allow unsafe until we refactor to avoid it
#![allow(unsafe_code)]

extern crate alloc;

mod device;
mod error;
mod linear;
mod table;
mod target;

// Debug is required by BlockDevice trait - implemented in table.rs

pub use device::DmDevice;
pub use error::DmError;
pub use linear::{LinearTargetType, register_linear_target};
pub use table::{DmTable, DmTarget, TargetPrivate};
pub use target::{TargetType, TargetVersion, lookup_target, register_target};
