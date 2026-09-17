//! Submitting intents as a threshold-controlled account.
//!
//! A treasury authors intents the same way a single-key wallet does. The
//! submission frame carries a verifying key and a 64-byte signature
//! ([`crate::client::frame_submission`]), and a FROST group over Ed25519
//! produces exactly those — an ordinary verifying key and an ordinary
//! signature. So the frame a treasury emits is **byte-identical in shape** to
//! one signed by a single key, and the sequencer cannot tell the difference.
//!
//! That is the whole reason a treasury needs no protocol support: the only
//! thing that changes is who holds the ability to produce the signature.

use std::collections::BTreeMap;

use swapvm::state::SwapState;
use swapvm::tx::Intent;
use zyn_custody::ceremony::{IdentifierFor, ThresholdKeys};
use zyn_custody::treasury::{PublicKeyPackage, ZynAccount};
use zyn_vm::auth::{signed_bytes_as, Authorization, Scheme, Signed};

use swapvm::wire;
use zyn_vm::commit::Encoder;

/// What a treasury signs for `intent` — the identical payload a single-key
/// wallet would sign under the identical authorization.
pub fn payload(chain: u32, now_epoch: u64, intent: &Intent) -> (Authorization, Vec<u8>) {
    let auth = Authorization::for_vm::<SwapState>(chain, now_epoch, 100);
    let bytes = match signed_bytes_as::<SwapState>(Scheme::Ed25519, &auth, intent) {
        Signed::Message(m) => m,
        Signed::Prehash(h) => h.to_vec(),
    };
    (auth, bytes)
}

/// Threshold-sign `intent` and return the submission frame.
///
/// `signers` names which holders take part; there must be at least the group's
/// threshold of them, and each must appear in `shares`. Every signer commits a
/// fresh nonce to *this* payload — a nonce committed to one message cannot be
/// reused for another, which is what stops an untrusted coordinator swapping
/// the intent between rounds.
pub fn frame_submission_threshold(
    shares: &BTreeMap<IdentifierFor<ZynAccount>, ThresholdKeys<ZynAccount>>,
    signers: &[IdentifierFor<ZynAccount>],
    chain: u32,
    now_epoch: u64,
    intent: &Intent,
) -> Result<Vec<u8>, String> {
    let (auth, payload_bytes) = payload(chain, now_epoch, intent);

    let (group_key, sig_bytes) = zyn_custody::treasury::sign(shares, signers, &payload_bytes)
        .map_err(|e| format!("threshold signing failed: {:?}", e))?;

    let mut e = Encoder::new();
    e.bytes(&auth.vm_id)
        .u64(auth.valid_until_epoch)
        .u8(Scheme::Ed25519.tag())
        .bytes(&group_key)
        .bytes(&sig_bytes);
    wire::encode_intent(&mut e, intent);
    Ok(e.finish().to_vec())
}


/// The same frame, signed by custodians that each hold one share.
///
/// [`frame_submission_threshold`] needs every share in one process. The
/// mainnet treasury's shares are deliberately on three separate machines, so
/// the sequencer builds the payload, asks each custodian to sign it, and
/// assembles the frame — holding no share itself.
///
/// The frame this returns is byte-identical in shape to the in-process one:
/// the network is a detail of how the signature was produced, not of what the
/// chain accepts.
pub fn frame_submission_across(
    custodians: &[String],
    public: &PublicKeyPackage<ZynAccount>,
    threshold: usize,
    chain: u32,
    now_epoch: u64,
    intent: &Intent,
    request_id: u64,
) -> Result<Vec<u8>, String> {
    let (auth, payload_bytes) = payload(chain, now_epoch, intent);

    let (group_key, sig_bytes) =
        zyn_custody::treasury::sign_across(custodians, public, threshold, &payload_bytes, request_id)
            .map_err(|e| format!("threshold signing across custodians failed: {:?}", e))?;

    let mut e = Encoder::new();
    e.bytes(&auth.vm_id)
        .u64(auth.valid_until_epoch)
        .u8(Scheme::Ed25519.tag())
        .bytes(&group_key)
        .bytes(&sig_bytes);
    wire::encode_intent(&mut e, intent);
    Ok(e.finish().to_vec())
}


#[cfg(test)]
mod tests {
    use super::*;
    use zyn_custody::treasury::Treasury;

    fn an_intent(to: [u8; 32]) -> Intent {
        Intent::Transfer {
            from: [1u8; 32],
            to,
            asset: swapvm::types::XZEC,
            amount: swapvm::Fixed::raw(1),
        }
    }

    /// The property the whole design rests on: a treasury's frame is accepted
    /// by the same verification a single-key wallet's frame goes through.
    #[test]
    fn a_threshold_frame_verifies_as_an_ordinary_signature() {
        let t = Treasury::provision(2, 3).expect("provision");
        let ids: Vec<_> = t.shares.keys().copied().take(2).collect();
        let intent = an_intent([7u8; 32]);
        let frame = frame_submission_threshold(&t.shares, &ids, 26460, 5, &intent).expect("sign");

        let (_, payload_bytes) = payload(26460, 5, &intent);
        // The frame ends with the intent; the signature sits before it.
        let key_at = 32 + 8 + 1;
        let key: [u8; 32] = frame[key_at..key_at + 32].try_into().unwrap();
        let sig: [u8; 64] = frame[key_at + 32..key_at + 96].try_into().unwrap();

        assert_eq!(key, t.group_key, "the frame carries the group key");
        assert_eq!(
            zyn_vm::auth::account_of(Scheme::Ed25519, &key),
            t.account,
            "and therefore speaks for the treasury account"
        );
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&key).expect("key");
        vk.verify_strict(&payload_bytes, &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("an ordinary Ed25519 verification must accept it");
    }

    /// Below the threshold there is no signature to be had.
    #[test]
    fn one_signer_of_a_two_of_three_cannot_sign_alone() {
        let t = Treasury::provision(2, 3).expect("provision");
        let one: Vec<_> = t.shares.keys().copied().take(1).collect();
        assert!(
            frame_submission_threshold(&t.shares, &one, 26460, 5, &an_intent([8u8; 32])).is_err(),
            "one of three must not produce a valid signature"
        );
    }

    /// Any two of the three suffice, and they agree on the account.
    #[test]
    fn any_two_holders_can_act_for_the_treasury() {
        let t = Treasury::provision(2, 3).expect("provision");
        let all: Vec<_> = t.shares.keys().copied().collect();
        for pair in [[all[0], all[1]], [all[0], all[2]], [all[1], all[2]]] {
            let frame = frame_submission_threshold(&t.shares, &pair, 26460, 9, &an_intent([3u8; 32]))
                .expect("any two must be able to sign");
            let key_at = 32 + 8 + 1;
            let key: [u8; 32] = frame[key_at..key_at + 32].try_into().unwrap();
            assert_eq!(zyn_vm::auth::account_of(Scheme::Ed25519, &key), t.account);
        }
    }
}
