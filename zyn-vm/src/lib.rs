//! The Zyn microchain VM specification.
//!
//! What any state machine must be to run as a Zyn microchain: deterministic,
//! sequenced, committed, sealable, carriable. Nothing here knows what an
//! application does — that is the point.
//!
//! ```text
//!   zyn-vm    the specification            <- you are here
//!      |
//!      +-- swapvm    ZynZap: application #1
//!      |
//!      +-- zyn       the microchain: sequencing, anchoring, exits, recovery
//! ```
//!
//! The layering is what makes Zyn permissionless later without moving ZynZap
//! now. `zyn` is generic over [`spec::MicrochainVm`], so a second application
//! is a new crate beside `swapvm` rather than a change underneath it. A third
//! party writing a VM depends on this crate and nothing else, and
//! [`conformance`] tells them whether they got it right.
//!
//! Start at [`spec`] for the contract, [`conformance`] for the suite that
//! checks it.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate self as zyn_vm;

pub mod auth;
pub mod checkpoint;
pub mod collection;
pub mod commit;
pub mod conformance;
pub mod derive;
pub mod eip712;
pub mod fixed;
pub mod manifest;
pub mod read;
pub mod session;
pub mod spec;
pub mod verify;
pub mod zvm;

pub use auth::{signing_digest, signing_payload, AuthError, Authorization};
pub use checkpoint::Checkpoint;
pub use collection::{
    collection_root, item_leaf, item_proof, transfer_item, verify_item, Item, ItemId,
};
pub use commit::{
    fold_intent, hash_leaf, hash_node, merkle_proof, merkle_root, verify_proof, Encoder, Hash,
    ProofIndex, ProofStep,
};
pub use derive::{
    asset_address, bridged_address, collection_address, derive, derive_for, item_address,
    lp_address, native_address, pool_address, program_scope, program_scope_of, vault_address,
    Address,
};
pub use fixed::{Fixed, WAD};
pub use manifest::{verify_manifest, verify_media, Attribute, Manifest, Media, MediaRole};
pub use read::{decode_capped, Decoder, WireError};
pub use spec::{AccountId, MicrochainVm, Provable, SECTION_ACCOUNTS, SECTION_HEADER};
pub use zvm::{
    apply_batch, apply_committed_batch, run, transition, transition_committed, Output, ZvmError,
};
