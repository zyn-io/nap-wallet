//! The node's process layer, as a library so it can be tested without a
//! process. `main.rs` is a thin shell over this.

pub mod alert;
pub mod backing;
pub mod deposits;
pub mod anchor;
pub mod boot;
pub mod bridge;
pub mod config;
pub mod rpc;
pub mod settle;
pub mod wallet;
pub mod client;
pub mod app;
mod restore;
pub mod exitproof;
pub mod feeds;
pub mod publish;
pub mod replica;
