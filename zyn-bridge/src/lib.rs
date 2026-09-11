//! Custody rules, shared by any VM that issues units against another chain.
//!
//! ```text
//!   zyn-vm        the specification
//!     |
//!     +-- zyn-bridge   custody: vaults, exits, settlement   <- you are here
//!     |     |
//!     |     +-- swapvm    ZynZap embeds it
//!     |
//!     +-- zyn          the microchain
//! ```
//!
//! # Why a component and not a microchain
//!
//! "BridgeVM" is the natural instinct and it does not work. A VM's state is its
//! own, so an asset custodied by a separate bridge VM could not be swapped
//! inside ZynZap without cross-VM atomicity — which does not exist, and whose
//! eventual form is deliberately *not* synchronous calls (`DECISIONS` §3.1,
//! §8.5). Bridged balances have to live in the VM that trades them.
//!
//! What does not have to live there is the logic. A vault's rules are identical
//! whether the units end up in an AMM, an auction or a game:
//!
//! - a deposit is credited once and only once
//! - an exit is committed before it is paid, and is refundable if it never is
//! - a payout below the far chain's dust limit cannot be broadcast at all
//! - exits to one chain in one epoch are one transaction
//!
//! So an application embeds a [`Vault`] per bridged asset and a [`PendingExit`]
//! per outstanding exit, and calls these rules from its own handlers. It keeps
//! what only it can do — moving its own balances — and owns none of the custody
//! reasoning.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod settle;
pub mod vault;

#[cfg(feature = "evm")]
pub mod evm;

#[cfg(feature = "solana")]
pub mod solana;

pub use settle::{group, Payout, Settlement};
pub use vault::{Binding, BridgeError, ChainOrigin, PendingCredit, PendingExit, Vault};
pub use vault::{ORIGIN_BITCOIN, ORIGIN_ETHEREUM, ORIGIN_SOLANA, ORIGIN_ZCASH};
