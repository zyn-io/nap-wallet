//! Private objects: value held as commitments, consumed and recreated.
//!
//! An account today *is* a balance sheet — `id → {ZEC.zy: 12.4, MOLE: 820}` —
//! and every holder of a data-availability bundle can read it. This module is
//! the other shape: value lives in **objects**, the chain stores only a
//! commitment to each, and spending one publishes a nullifier that retires it
//! without saying which commitment it retired.
//!
//! ```text
//!   in    C₁₂ (17 ZEC, Alice)
//!   out   C₄₁ (5 ZEC, Bob)  C₄₂ (12 ZEC, Alice — change)
//!   chain   nullifier(C₁₂),  C₄₁,  C₄₂
//! ```
//!
//! Nothing published says `C₄₂` succeeded `C₁₂`. That unlinkability is the
//! whole point; hiding the *amounts* is a later and separate step
//! (DECISIONS §130.6), and this module deliberately keeps them readable so
//! that conservation still checks the way it always has.
//!
//! # Why this is not [`crate::collection`]
//!
//! The collection tree is the same construction pointed at items, and it is
//! the precedent this follows. But it **sorts by id**, and a commitment tree
//! must not sort — see [`Commitments`]. That single difference is why this is
//! a separate module rather than a second caller of the first.
//!
//! # What is committed, and what is not
//!
//! A commitment binds the asset, the amount, the owner and a nonce. The nonce
//! is what makes it *hiding*: without one, a commitment over a known asset,
//! a plausible amount and a guessable owner is a dictionary away from being
//! opened, and "is this Alice's 10 ZEC?" becomes a question anyone can answer.
//! So a zero nonce is refused rather than treated as a default.

use alloc::vec::Vec;

use crate::commit::{merkle_proof, merkle_root, Encoder, Hash, ProofStep};
use crate::derive::Address;
use crate::fixed::Fixed;
use crate::spec::AccountId;

/// The secret that authorises spending an object and derives its nullifier.
///
/// Distinct from the account's signing key by design: the nullifier key can be
/// handed to a watch-only process that needs to know which objects are spent
/// without being able to spend any.
pub type NullifierKey = [u8; 32];

/// One object, in the clear. The chain sees [`commitment`] of it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Note {
    /// Which asset this is value in.
    pub asset: Address,
    /// How much. Readable at this tier, a commitment at the next.
    pub amount: Fixed,
    /// Who may spend it.
    pub owner: AccountId,
    /// Randomness, and the reason the commitment hides anything at all.
    pub nonce: Hash,
}

/// Why a note could not be committed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectError {
    /// A zero nonce makes the commitment openable by guessing.
    ZeroNonce,
    /// A note of nothing is not a note; it would be a free entry in the tree.
    /// An amount of zero or less.
    ///
    /// Zero is not a note. **Negative is worse than not a note**: conservation
    /// is a per-asset sum, so a negative output subtracts from what the
    /// outputs total and pays for an inflated positive one. Spend 10, create
    /// 1,000 and −990, and the books balance while the spender holds a
    /// hundred times what they put in (§136.6). Refusing it here covers every
    /// path, because a note that cannot be committed cannot enter any tree.
    NotPositive,
}

/// The commitment the chain stores for a note.
///
/// Length-prefixing is unnecessary here and deliberately absent: every field
/// is fixed-width, so no two distinct notes can share a preimage by
/// re-splitting the same bytes.
pub fn commitment(note: &Note) -> Result<Hash, ObjectError> {
    if note.nonce == [0u8; 32] {
        return Err(ObjectError::ZeroNonce);
    }
    if note.amount.0 <= 0 {
        return Err(ObjectError::NotPositive);
    }
    let mut e = Encoder::new();
    e.bytes(b"zyn.object.v1")
        .bytes(&note.asset)
        .fixed(note.amount)
        .bytes(&note.owner)
        .bytes(&note.nonce);
    Ok(e.leaf())
}

/// The nullifier that retires a commitment.
///
/// Three properties this must have, and the reason the key is an input:
///
/// - **Deterministic.** The same note always yields the same nullifier, or the
///   double-spend check does not work.
/// - **Unlinkable forwards.** A public observer holding a commitment cannot
///   compute its nullifier, because they do not hold the key.
/// - **Unlinkable backwards.** A public observer holding a nullifier cannot
///   find its commitment, for the same reason.
///
/// The second and third are what stop the transaction graph from being
/// readable even though both halves are published.
pub fn nullifier(key: &NullifierKey, commitment: &Hash) -> Hash {
    let mut e = Encoder::new();
    e.bytes(b"zyn.nullifier.v1").bytes(key).bytes(commitment);
    e.leaf()
}

/// The commitment tree: append-only, and never sorted.
///
/// [`crate::collection`] sorts its items by id so that two nodes holding the
/// same collection agree. A commitment tree **must not**, and the reason is
/// witnesses: a holder keeps the path from their commitment to the root, and
/// sorting would move existing leaves whenever a new one arrived, silently
/// invalidating every outstanding witness in the system. Append order is what
/// makes a position permanent.
///
/// Agreement therefore comes from the sequence rather than from the data, which
/// is the same trade Zcash's own note commitment tree makes.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Commitments {
    leaves: Vec<Hash>,
}

impl Commitments {
    pub fn new() -> Self {
        Commitments { leaves: Vec::new() }
    }

    /// Append a commitment and return the position it will keep forever.
    ///
    /// **Call this only once a batch is known to be accepted.** Conformance S3
    /// requires the committed leaves to be byte-identical after a *rejected*
    /// batch; appending on submission rather than on commit moves the tree on
    /// rejection and fails it.
    pub fn append(&mut self, commitment: Hash) -> usize {
        self.leaves.push(commitment);
        self.leaves.len() - 1
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn root(&self) -> Hash {
        merkle_root(&self.leaves)
    }

    /// The inclusion path for a position.
    pub fn proof(&self, position: usize) -> Option<(Hash, Vec<ProofStep>)> {
        let leaf = *self.leaves.get(position)?;
        Some((leaf, merkle_proof(&self.leaves, position)))
    }

    pub fn leaves(&self) -> &[Hash] {
        &self.leaves
    }
}

/// The spent set.
///
/// Sorted, unlike [`Commitments`]: nothing holds a witness into this tree, so
/// ordering by value costs nothing and buys agreement from the data rather than
/// from the sequence. Only membership is ever asked of it.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Nullifiers {
    spent: Vec<Hash>,
}

impl Nullifiers {
    pub fn new() -> Self {
        Nullifiers { spent: Vec::new() }
    }

    /// Record a nullifier. `false` if it was already present — which is a
    /// double spend, and the caller's job to refuse.
    pub fn insert(&mut self, nullifier: Hash) -> bool {
        match self.spent.binary_search(&nullifier) {
            Ok(_) => false,
            Err(at) => {
                self.spent.insert(at, nullifier);
                true
            }
        }
    }

    pub fn contains(&self, nullifier: &Hash) -> bool {
        self.spent.binary_search(nullifier).is_ok()
    }

    pub fn len(&self) -> usize {
        self.spent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    pub fn root(&self) -> Hash {
        merkle_root(&self.spent)
    }

    /// The spent set in sorted order, for a VM that must encode its state.
    pub fn spent(&self) -> &[Hash] {
        &self.spent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(amount: i64, owner: u8, nonce: u8) -> Note {
        Note {
            asset: [7u8; 32],
            amount: Fixed::whole(amount),
            owner: [owner; 32],
            nonce: [nonce; 32],
        }
    }

    /// The nonce is the whole reason a commitment hides anything.
    ///
    /// Without it, an observer who can guess the asset, a plausible amount and
    /// an owner can confirm the guess by recomputing the hash. "Is this
    /// Alice's 10 ZEC?" must not be a question anyone can answer offline.
    #[test]
    fn the_nonce_is_what_makes_a_commitment_hiding() {
        let a = commitment(&note(10, 0xAA, 1)).unwrap();
        let b = commitment(&note(10, 0xAA, 2)).unwrap();
        assert_ne!(a, b, "the same value under two nonces must not collide");
        assert_eq!(commitment(&note(10, 0xAA, 1)).unwrap(), a, "and it is deterministic");
    }

    #[test]
    fn a_zero_nonce_is_refused_rather_than_defaulted() {
        let mut n = note(10, 0xAA, 1);
        n.nonce = [0u8; 32];
        assert_eq!(commitment(&n), Err(ObjectError::ZeroNonce));
        n.nonce = [1u8; 32];
        n.amount = Fixed::ZERO;
        assert_eq!(commitment(&n), Err(ObjectError::NotPositive));
    }

    /// Every field is bound. Two notes differing anywhere are two commitments.
    #[test]
    fn every_field_is_bound_into_the_commitment() {
        let base = commitment(&note(10, 0xAA, 1)).unwrap();
        assert_ne!(commitment(&note(11, 0xAA, 1)).unwrap(), base, "amount");
        assert_ne!(commitment(&note(10, 0xBB, 1)).unwrap(), base, "owner");
        let mut other_asset = note(10, 0xAA, 1);
        other_asset.asset = [8u8; 32];
        assert_ne!(commitment(&other_asset).unwrap(), base, "asset");
    }

    /// The property the published graph rests on: holding one half tells you
    /// nothing about the other without the key.
    #[test]
    fn a_nullifier_does_not_follow_from_its_commitment() {
        let c = commitment(&note(10, 0xAA, 1)).unwrap();
        let mine = nullifier(&[0x11; 32], &c);
        let theirs = nullifier(&[0x22; 32], &c);
        assert_ne!(mine, theirs, "the key must matter, or anyone could derive it");
        assert_ne!(mine, c, "and it must not be the commitment restated");
        assert_eq!(nullifier(&[0x11; 32], &c), mine, "deterministic, or double spends pass");
    }

    /// Sorting would move existing leaves, and every witness anyone holds
    /// points at a position. This is why `Commitments` appends.
    #[test]
    fn appending_never_moves_an_existing_position() {
        let mut t = Commitments::new();
        let first = commitment(&note(10, 0xAA, 1)).unwrap();
        let at = t.append(first);
        let (leaf, path) = t.proof(at).unwrap();
        let root_before = t.root();
        assert_eq!(crate::commit::verify_proof(leaf, &path, root_before), true);

        // A commitment that sorts *before* the first one.
        let mut low = note(10, 0xAA, 1);
        low.nonce = [0x01; 32];
        let mut lower = commitment(&low).unwrap();
        lower[0] = 0x00;
        t.append(lower);

        assert_eq!(t.proof(at).unwrap().0, first, "position {at} still holds the same leaf");
        assert_eq!(t.leaves()[at], first);
    }

    /// The double-spend check, which is the only thing the set is for.
    #[test]
    fn a_nullifier_can_only_be_spent_once() {
        let mut set = Nullifiers::new();
        let n = nullifier(&[0x11; 32], &commitment(&note(10, 0xAA, 1)).unwrap());
        assert!(set.insert(n), "first spend");
        assert!(!set.insert(n), "second spend must be refused");
        assert!(set.contains(&n));
        assert_eq!(set.len(), 1);
    }

    /// Order of arrival must not change the set's root, or two honest nodes
    /// that saw the same spends in a different order would disagree.
    #[test]
    fn the_spent_set_agrees_regardless_of_arrival_order() {
        let a = nullifier(&[0x11; 32], &commitment(&note(1, 0xAA, 1)).unwrap());
        let b = nullifier(&[0x22; 32], &commitment(&note(2, 0xBB, 2)).unwrap());
        let mut one = Nullifiers::new();
        one.insert(a);
        one.insert(b);
        let mut two = Nullifiers::new();
        two.insert(b);
        two.insert(a);
        assert_eq!(one.root(), two.root());
    }
}
