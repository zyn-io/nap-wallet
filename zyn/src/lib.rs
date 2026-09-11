//! Zyn — the microchain underneath ZynZap.
//!
//! `swapvm` decides what a swap *means*. This crate decides what a microchain
//! *is*: when an epoch closes, what gets carried to Zcash, what a holder can
//! prove without asking anyone, and what the whole arrangement costs per trade.
//!
//! ## Why the microchain, and not just an AMM on Zcash
//!
//! Zcash settles on the order of a block. A memecoin market does not trade on
//! the order of a block, and it does not trade one settlement at a time: the
//! flow is thousands of small swaps, most of which never need to touch an L1 at
//! all. Settling each one directly is not merely slow, it is *uneconomic* —
//! every trade would carry a full L1 fee regardless of its size, which prices
//! out exactly the small, frequent trades that make a market liquid.
//!
//! The microchain absorbs that flow and settles the compression:
//!
//! ```text
//!   25,000 microchain actions
//!             |
//!             v
//!      15 Zcash transactions
//! ```
//!
//! That ratio is not a demo statistic. It is the business:
//!
//! - **Traction** is what the ratio makes possible — sub-second swaps, at a
//!   cost per trade low enough that a small trade is worth making. Zcash keeps
//!   custody and final settlement; the microchain keeps the interaction.
//! - **Revenue** is a slice of the fee on that flow, against an L1 cost that is
//!   amortised across every action inside an anchor. The margin per trade is
//!   `fee_share - (settlement_cost / actions_per_anchor)`, and the denominator
//!   is the thing this crate controls.
//!
//! So the compression ratio is a tunable, measured, first-class part of the
//! infrastructure — [`epoch::EpochPolicy`] sets it, [`epoch::Economics`] prices
//! it, and [`anchor::Anchor`] carries the evidence of it on chain.
//!
//! ## What is here
//!
//! - [`epoch`] — the compression policy and its unit economics
//! - [`node`] — the sequencer: orders intents, seals epochs, emits anchors
//! - [`anchor`] — the Zcash-bound commitment, its signer certificate, and the
//!   lineage rules that keep one canonical history
//! - [`da`] — the self-verifying snapshot that makes the exit hatch real when
//!   the sequencer is gone
//! - [`store`] — full-state persistence, so a dead node resumes rather than
//!   merely being provably dead
//! - [`journal`] — every applied intent in the VM's own bytes, so a replica can
//!   reproduce each anchored root instead of taking it on trust
//!
//! Everything except [`store`] is `no_std`-capable: anchor and DA verification
//! are things a light client — or eventually a guest — must be able to do.
//!
//! ## Generic over the VM
//!
//! Nothing here names an application. [`node::Node`] is parameterised by
//! [`zyn_vm::MicrochainVm`], so it sequences intents it cannot interpret and
//! anchors roots it did not compute. The crate does not even depend on
//! `swapvm` — ZynZap is a dev-dependency used to test the abstraction against
//! a real application, which is the only way to find out whether it fits one.
//!
//! Anything genuinely application-shaped — what a fee is, what revenue means,
//! what a pool is — lives above this layer, in the application or in the
//! operator's own reporting. The line is drawn where it has to be for a second
//! application to arrive without moving the first.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod anchor;
pub mod da;
pub mod epoch;
pub mod host;
pub mod node;
#[cfg(feature = "std")]
pub mod journal;
#[cfg(feature = "std")]
pub mod replay;
#[cfg(feature = "std")]
pub mod store;
pub mod verify;

pub use anchor::{Anchor, AnchorId, Certificate, LineageError, Ledger, SignerSet};
pub use da::{proof_from, verify_record, Snapshot, SnapshotError};
pub use epoch::{Compression, Economics, EpochPolicy, Report, Unit};
pub use node::{Node, Sealed, Step};
