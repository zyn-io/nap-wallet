//! Deterministic fixed-point arithmetic.
//!
//! Moved into the microchain VM spec: two VMs that round differently cannot be
//! settled against the same commitment, so the type belongs to the contract
//! rather than to any one application. Re-exported here because ZynZap's
//! arithmetic reads better against `crate::fixed` and because a path change is
//! not worth a diff in every module.

pub use zyn_vm::fixed::{mul_div, mul_div_ceil, Fixed, WAD};
