//! SwapVM — the deterministic state-transition core of the Zyn microchain.
//!
//! ZynZap's execution layer. Borrowed from elastic-perps' `perpvm`: the same
//! architecture, a different domain. There it was per-lane perpetual markets
//! settling to Robinhood Chain; here it is one shared swap microchain settling
//! to Zcash.
//!
//! This crate is *truth*. The control plane decides the canonical order of
//! intents; this crate decides what those intents mean. Pricing happens here,
//! not upstream: fills are **emitted as receipts**, never accepted as input. If
//! the sequencer could submit a fill, a proof over this VM would attest only
//! that bookkeeping was applied correctly, not that the AMM priced honestly —
//! which is the entire property a future proof exists to establish.
//!
//! Constraints this crate holds itself to, so it can later run as a zkVM guest:
//!
//! - no I/O, no clock, no randomness, no threads
//! - no floating point
//! - no `HashMap` (iteration order must never affect a state root; `BTreeMap`)
//! - every arithmetic operation checked
//!
//! The one shared execution environment deliberately holds *all* pools —
//! CAT/xZEC, DOG/xZEC, CAT/DOG — so routing between them is atomic inside a
//! single intent rather than a hope about cross-lane sequencing.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod amm;
pub mod bridge;
pub mod cave;
pub mod codec;
pub mod fixed;
pub mod guest;
pub mod launch;
pub mod merkle;
pub mod microchain;
pub mod revenue;
pub mod state;
pub mod tx;
pub mod typed;
pub mod types;
pub mod vm;
pub mod wire;

pub use fixed::{Fixed, WAD};
pub use merkle::{merkle_root, Hash};
pub use revenue::Revenue;
pub use state::{Account, Pool, SwapState, TokenInfo};
pub use tx::{Intent, Receipt, Reject, SequencedIntent};
pub use types::{AccountId, AssetId, Params, PoolId, XZEC};
pub use vm::{apply, apply_batch, checkpoint, transition};
