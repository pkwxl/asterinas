// SPDX-License-Identifier: MPL-2.0

//! Test-only fixtures and helpers for erofs kernel tests.
//!
//! This module will own the in-memory block device and the erofs
//! image builder used by the ktest suites (mirroring the ext2
//! `test_utils` shape with the erofs on-disk format). It is compiled
//! only under `#[cfg(ktest)]` and is never referenced by production
//! files.
//!
//! Interim placeholder (T-021 skeleton): the fixture body lands with
//! T-027. The vector suite for `utils` lives inside `utils.rs` itself
//! (pure functions need no disk fixtures).
