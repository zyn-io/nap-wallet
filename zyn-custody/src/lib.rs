//! Custody operations: watching for deposits, and signing for the vault.
//!
//! ```text
//!   zyn-vm        the specification
//!     |
//!     +-- zyn-bridge    custody rules, enforced in-VM
//!     |     |
//!     |     +-- zyn-custody   custody *operations*, outside the VM  <- here
//!     |
//!     +-- swapvm / zyn
//! ```
//!
//! Everything in this crate touches the outside world. That is exactly why it
//! is not in the VM and never can be: a program that could see Zcash would not
//! be deterministic (**S1**). What it produces is *intents*, which the VM then
//! judges by rules it enforces itself. The split matters — a watcher bug
//! produces a rejected intent, not a corrupted chain.
//!
//! Two halves:
//!
//! - [`memo`] is how a Zcash deposit says which Zyn account it is for, and is
//!   deliberately strict: a memo that is not exactly an instruction is not a
//!   deposit with a problem, it is a manual refund.
//! - [`watcher`] turns confirmed on-chain deposits into the intents that credit
//!   them. All the logic that is easy to get wrong and has nothing to do with
//!   cryptography lives here: confirmation depth, reorgs, deduplication, and
//!   the order the VM requires.
//! - [`ceremony`] and [`signing`] hold the vault key as a threshold of shares
//!   and produce signatures with it, using `reddsa`'s FROST over RedPallas —
//!   the Zcash Foundation's implementation of the scheme Orchard spend
//!   authorization uses.
//!
//! **No cryptography is implemented here.** Threshold signing fails silently and
//! totally when it is got wrong, so this crate integrates an audited
//! implementation and reimplements no part of it.

// The FROST core, so a binary can name a ciphersuite bound without taking its
// own dependency on the exact version this crate was built against.
pub use frost_core;

pub mod ceremony;
pub mod compact;
pub mod custodian;
pub mod custody_net;
pub mod dkg_net;
pub mod evm;
pub mod lightd;
pub mod memo;
pub mod notes;
pub mod payout;
pub mod shares;
pub mod shielded;
pub mod signing;
pub mod solana;
pub mod transparent;
pub mod watcher;
pub mod zebra;

pub use ceremony::{Ceremony, CeremonyError, VaultKeys};
pub use memo::{MemoError, MEMO_TAG, MEMO_VERSION};
pub use signing::{SigningError, SigningSession};
pub use watcher::{ChainView, ObservedDeposit, Watcher, WatcherAction, WatcherError};
