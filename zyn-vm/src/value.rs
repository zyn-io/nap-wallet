//! Tier 3: amounts the operator cannot read.
//!
//! At tier 2 a note carries a [`Fixed`](crate::fixed::Fixed) the sequencer
//! sums to check conservation. That is the whole reason it can still see what
//! you hold. This module replaces the readable amount with a **Pedersen
//! commitment**, which nobody can open and which still adds up:
//!
//! ```text
//!   commit(v, r)  =  v·G + r·H
//!   commit(a, r₁) + commit(b, r₂)  =  commit(a + b, r₁ + r₂)
//! ```
//!
//! So conservation stops being "sum the amounts and compare" and becomes "the
//! inputs minus the outputs are the identity point" — a check that reveals
//! nothing about any individual amount. It is the same construction Zcash's
//! own Sapling and Orchard value balances use, and it needs no circuit, no
//! trusted setup and no proving key.
//!
//! # This is not safe on its own, and the API says so
//!
//! An amount here is a scalar modulo the group order. A "negative" amount is
//! therefore an enormous positive one, and a spender who is allowed to pick
//! freely can balance `10 = 11 + (−1)` and mint value out of nothing. Pedersen
//! commitments hide, they do not constrain.
//!
//! The fix is a **range proof** on every output, and it needs the circuit
//! rather than a library of its own (§134). Rather than leave that as a
//! comment someone might miss,
//! [`RangeProof::verify`] returns [`ValueError::RangeProofsNotImplemented`] —
//! so a VM that wires this in refuses every spend rather than accepting
//! unsound ones. Tier 3 is not finished until that function does real work.
//!
//! # The other thing tier 3 breaks
//!
//! `ZYN_BACKING_SIGNERS` compares a plaintext deposit amount against the note
//! values a Zcash transaction actually paid the vault (DECISIONS §130.13).
//! Commit the deposit amount and the only *external* solvency check in the
//! system has nothing on one side of that comparison. Hiding amounts on the
//! deposit path therefore needs a replacement for that check first, and this
//! module deliberately does not provide one.

use alloc::vec::Vec;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::Sha512;

use crate::commit::Hash;

/// Why a value operation was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValueError {
    /// A commitment that is not a valid Ristretto point.
    Malformed,
    /// Range proofs are required and are not implemented. Every spend refuses
    /// until they are, because without them a spender can balance a
    /// transaction by claiming a negative output.
    RangeProofsNotImplemented,
}

/// A hidden amount: `v·G + r·H`, compressed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ValueCommitment(pub Hash);

/// The blinding factor. Whoever knows it can open the commitment, so it
/// travels with the note and never with the chain.
pub type Blind = Scalar;

/// The second generator.
///
/// Derived by hashing a domain string to a point, so that nobody — including
/// us — knows its discrete logarithm with respect to the basepoint. If anyone
/// did, they could open any commitment to any value they liked, and the whole
/// construction would be decoration.
fn h_generator() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(b"zyn.value.generator.v1")
}

/// Commit to an amount under a blinding factor.
///
/// The amount is `u64` rather than `Fixed`: a commitment is over a group
/// scalar, and signed fixed-point has no meaning there. Converting at the
/// boundary is deliberate — it is the point where "an amount" stops being
/// arithmetic the VM can do and becomes a point it can only add.
pub fn commit_value(amount: u64, blind: &Blind) -> ValueCommitment {
    let point = RistrettoPoint::mul_base(&Scalar::from(amount)) + h_generator() * blind;
    ValueCommitment(point.compress().to_bytes())
}

fn decompress(c: &ValueCommitment) -> Result<RistrettoPoint, ValueError> {
    CompressedRistretto(c.0)
        .decompress()
        .ok_or(ValueError::Malformed)
}

/// Whether the inputs and the outputs commit to the same total.
///
/// True exactly when `Σ inputs − Σ outputs` is the identity, which happens
/// when both the amounts and the blinding factors balance. The spender is the
/// one who must arrange the second, by choosing output blinds that sum to the
/// input blinds — the same obligation a Zcash wallet has.
///
/// **This says nothing about whether the amounts were sensible.** A balanced
/// transaction with a negative output balances perfectly. See [`RangeProof`].
pub fn balances(
    inputs: &[ValueCommitment],
    outputs: &[ValueCommitment],
) -> Result<bool, ValueError> {
    let mut acc = RistrettoPoint::identity();
    for c in inputs {
        acc += decompress(c)?;
    }
    for c in outputs {
        acc -= decompress(c)?;
    }
    Ok(acc == RistrettoPoint::identity())
}

/// A proof that a committed amount is inside `[0, 2^64)`.
///
/// **Not implemented.** This type exists now, with a verifier that always
/// refuses, so that the rest of tier 3 can be built and tested against the
/// shape it will have — and so that no VM can wire value commitments in and
/// quietly accept spends that mint value.
///
/// **The intended construction changed on 21 Sep (DECISIONS §134).** It is
/// not Bulletproofs: that crate depends on `clear_on_drop`, which does not
/// build for `riscv32im-unknown-none-elf`. More to the point, Zcash does not
/// attach range proofs at all — Orchard constrains a note's value *inside*
/// its Halo 2 circuit, as part of the same proof that checks everything else.
///
/// So this type will not be filled in on its own. The range check arrives
/// with the membership circuit, built on the `halo2_proofs` and
/// `halo2_gadgets` already vendored through `orchard`, and until then this
/// verifier refuses — which is what keeps a VM from wiring value commitments
/// in and quietly accepting spends that mint value.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RangeProof {
    pub bytes: Vec<u8>,
}

impl RangeProof {
    /// Whether `commitments` are each proven to be in range.
    ///
    /// Always refuses today. That is the point: a spend path that calls this
    /// fails closed, and tier 3 is finished when this function is real.
    pub fn verify(&self, _commitments: &[ValueCommitment]) -> Result<(), ValueError> {
        Err(ValueError::RangeProofsNotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blind(b: u8) -> Blind {
        Scalar::from_bytes_mod_order([b; 32])
    }

    /// The property the whole tier rests on: commitments add the way the
    /// amounts inside them do.
    #[test]
    fn commitments_add_the_way_their_amounts_do() {
        let (r1, r2) = (blind(1), blind(2));
        let a = commit_value(5, &r1);
        let b = commit_value(12, &r2);
        let both = commit_value(17, &(r1 + r2));

        assert!(balances(&[both], &[a, b]).unwrap(), "17 splits into 5 and 12");
    }

    /// Spending 17 as 5 + 12 balances; spending it as 5 + 13 does not.
    #[test]
    fn a_transaction_that_does_not_conserve_does_not_balance() {
        let (r_in, r1, r2) = (blind(9), blind(3), blind(4));
        let input = commit_value(17, &r_in);
        // Blinds chosen to balance, so only the amounts can be wrong.
        let out_a = commit_value(5, &r1);
        let out_b = commit_value(12, &(r_in - r1));
        assert!(balances(&[input], &[out_a, out_b]).unwrap());

        let wrong = commit_value(13, &(r_in - r1));
        assert!(!balances(&[input], &[out_a, wrong]).unwrap());
        let _ = r2;
    }

    /// Hiding: the same amount under two blinds is two different commitments,
    /// so a commitment cannot be recognised by recomputing it.
    #[test]
    fn the_same_amount_twice_is_not_the_same_commitment() {
        assert_ne!(commit_value(10, &blind(1)), commit_value(10, &blind(2)));
        assert_eq!(commit_value(10, &blind(1)), commit_value(10, &blind(1)));
    }

    /// The attack range proofs exist to stop, demonstrated rather than
    /// described: a spender who may choose freely can balance a transaction
    /// that creates value, because a negative amount is a very large one.
    #[test]
    fn without_range_proofs_a_balanced_transaction_can_mint_value() {
        let r_in = blind(7);
        let input = commit_value(10, &r_in);

        // Claim an output of 11 and an output of −1. In the scalar field
        // that is 11 + (l − 1), and the two sum to 10.
        let r1 = blind(3);
        let r2 = r_in - r1;
        let eleven = commit_value(11, &r1);
        let minus_one = ValueCommitment(
            (RistrettoPoint::mul_base(&-Scalar::from(1u64)) + h_generator() * r2)
                .compress()
                .to_bytes(),
        );

        assert!(
            balances(&[input], &[eleven, minus_one]).unwrap(),
            "the sum checks out, and one output is worth minus one"
        );

        // Which is exactly why the verifier refuses until range proofs exist.
        assert_eq!(
            RangeProof::default().verify(&[eleven, minus_one]),
            Err(ValueError::RangeProofsNotImplemented)
        );
    }

    #[test]
    fn a_malformed_commitment_is_refused_not_panicked_on() {
        let bad = ValueCommitment([0xFF; 32]);
        assert_eq!(balances(&[bad], &[]), Err(ValueError::Malformed));
    }
}
