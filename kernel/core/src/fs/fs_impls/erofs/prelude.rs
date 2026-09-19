// SPDX-License-Identifier: MPL-2.0

//! Re-exports used throughout the erofs module.
//!
//! Types and traits only: constants and functions are imported by
//! path at their consumption sites, never forwarded here.

pub(super) use core::time::Duration;

pub(super) use aster_block::BlockDevice;
pub(super) use ostd::sync::RwMutex;

pub(super) use super::inode::ErofsNid;
pub(super) use crate::{
    fs::{
        file::{InodeMode, InodeType},
        utils::DirentVisitor,
    },
    prelude::*,
};
