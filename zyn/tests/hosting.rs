//! One node, two applications that have never heard of each other.
//!
//! The platform claim is that Zyn hosts applications rather than an
//! application. `second_app.rs` shows a second VM *can* be written; this shows
//! both running side by side in one registry, addressed by chain id, with
//! neither able to reach the other's state.

use k256::ecdsa::SigningKey;
use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{wire, Fixed, Params};
use zyn::epoch::{Economics, EpochPolicy};
use zyn::host::{encode_submission, HostError, Registry};
use zyn::node::Node;
use zyn_vm::auth::{account_of, eip712_digest, Authorization, Scheme};
use zyn_vm::spec::MicrochainVm;

mod tally;
use tally::{Limits, TallyVm};

const ZAP: u32 = 21;
const TALLY: u32 = 22;

fn policy() -> EpochPolicy {
    EpochPolicy {
        intents_per_epoch: 10_000,
        epochs_per_anchor: 10_000,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    }
}

fn wallet() -> SigningKey {
    SigningKey::from_bytes(&[13u8; 32].into()).unwrap()
}

fn wallet_account() -> [u8; 32] {
    let k = wallet();
    let p = k.verifying_key().to_encoded_point(false);
    let h = zyn_vm::eip712::keccak(&[&p.as_bytes()[1..]]);
    account_of(Scheme::Secp256k1Eip712, &h[12..])
}

fn registry() -> Registry {
    let mut zap: Node<SwapState> =
        Node::new(ZAP, Params::testnet(), policy(), Economics::flat(10_000));
    let who = wallet_account();
    let amount = Fixed::whole(1_000);
    let observed = zap.state().backing_of(XZEC).add(amount).unwrap();
    zap.submit_operator(
        Intent::AttestVaultBalance {
            asset: XZEC,
            observed,
        },
        0,
    );
    let d = Intent::next_deposit(zap.state(), who, XZEC, amount, [0u8; 32]);
    zap.submit_operator(d, 0);
    let e = zap.state().epoch();
    zap.submit_operator(Intent::Checkpoint, 0);
    zap.submit_operator(Intent::ConfirmAnchor { epoch: e }, 0);

    let tally: Node<TallyVm> = Node::new(
        TALLY,
        Limits { max_step: 1_000 },
        policy(),
        Economics::flat(10_000),
    );

    let mut r = Registry::new();
    r.register(Box::new(zap)).expect("register zap");
    r.register(Box::new(tally)).expect("register tally");
    r
}

/// Sign a ZynZap intent the way a wallet would, and frame it for the host.
fn signed_swap(to: [u8; 32], amount: i64) -> Vec<u8> {
    let intent = Intent::Transfer {
        from: wallet_account(),
        to,
        asset: XZEC,
        amount: Fixed::whole(amount),
    };
    let auth = Authorization {
        chain_id: ZAP,
        vm_id: zyn_vm::zvm::vm_id::<SwapState>(),
        valid_until_epoch: u64::MAX,
    };
    let digest = eip712_digest::<SwapState>(&auth, &intent);
    let (sig, rid) = wallet().sign_prehash_recoverable(&digest).unwrap();
    let mut cred = [0u8; 65];
    cred[..64].copy_from_slice(&sig.to_bytes());
    cred[64] = rid.to_byte() + 27;
    encode_submission(
        &auth,
        Scheme::Secp256k1Eip712,
        &cred,
        &wire::encode_intent_bytes(&intent),
    )
}

#[test]
fn one_registry_holds_two_unrelated_applications() {
    let r = registry();
    assert_eq!(r.chain_ids(), vec![ZAP, TALLY]);
    assert_eq!(r.get(ZAP).unwrap().vm_name(), "zynzap");
    assert_eq!(r.get(TALLY).unwrap().vm_name(), "tally");
    // Two machines with unrelated intent types, held together — the thing a
    // `dyn MicrochainVm` could never have done.
    assert_ne!(
        r.get(ZAP).unwrap().state_root(),
        r.get(TALLY).unwrap().state_root()
    );
}

/// The host routes by chain id and applies without knowing what it applied.
#[test]
fn a_signed_intent_reaches_the_right_application() {
    let mut r = registry();
    let before = r.get(TALLY).unwrap().state_root();

    let applied = r
        .submit_signed(ZAP, &signed_swap([9u8; 32], 10), 0)
        .expect("submit");
    assert!(!applied.rejected, "the transfer was rejected");
    assert_eq!(
        applied.account,
        wallet_account(),
        "the host resolved the wrong signer"
    );

    // The other application did not move.
    assert_eq!(
        r.get(TALLY).unwrap().state_root(),
        before,
        "an intent crossed applications"
    );
}

/// A submission for a chain nobody runs is refused by name.
#[test]
fn an_unknown_chain_is_refused() {
    let mut r = registry();
    assert_eq!(
        r.submit_signed(999, &signed_swap([9u8; 32], 1), 0),
        Err(HostError::NoSuchChain(999))
    );
}

/// The signature is bound to a chain id (**S12**), so a frame aimed at the
/// wrong application cannot verify even though both are running here.
#[test]
fn an_intent_signed_for_one_chain_does_not_execute_on_another() {
    let mut zap_on_other_id: Node<SwapState> =
        Node::new(TALLY, Params::testnet(), policy(), Economics::flat(10_000));
    let _ = &mut zap_on_other_id;

    let mut r = Registry::new();
    let zap: Node<SwapState> = Node::new(ZAP, Params::testnet(), policy(), Economics::flat(10_000));
    let decoy: Node<SwapState> =
        Node::new(TALLY, Params::testnet(), policy(), Economics::flat(10_000));
    r.register(Box::new(zap)).unwrap();
    r.register(Box::new(decoy)).unwrap();

    // Signed for chain 21, submitted to chain 22.
    let out = r.submit_signed(TALLY, &signed_swap([9u8; 32], 1), 0);
    assert!(
        matches!(out, Err(HostError::Unauthorised(_))),
        "a signature crossed chains inside one node: {:?}",
        out
    );
}

/// Registering over a live chain would unseat it silently.
#[test]
fn a_chain_id_cannot_be_taken_twice() {
    let mut r = registry();
    let another: Node<SwapState> =
        Node::new(ZAP, Params::testnet(), policy(), Economics::flat(10_000));
    assert!(r.register(Box::new(another)).is_err());
    assert_eq!(r.len(), 2);
}

/// **S10** at the host boundary: the frame comes off a socket.
#[test]
fn malformed_frames_are_refused_rather_than_fatal() {
    let mut r = registry();
    let full = signed_swap([9u8; 32], 1);
    for cut in 0..full.len() {
        let out = r.submit_signed(ZAP, &full[..cut], 0);
        assert!(out.is_err(), "a truncated frame at {} was applied", cut);
    }
    assert!(r.submit_signed(ZAP, &[], 0).is_err());
}

/// A hosted application still answers the questions an exit needs.
#[test]
fn a_hosted_application_still_proves_its_accounts() {
    let r = registry();
    let zap = r.get(ZAP).unwrap();
    assert!(
        zap.account_record(&wallet_account()).is_some(),
        "no record for a funded account"
    );
    assert!(zap.account_record(&[0xEE; 32]).is_none());
    assert!(!zap.encode_state().is_empty());
}

/// A batch must reach the same conclusion as submitting one at a time, in the
/// same order, with the same sequence numbers. An optimisation that changes
/// what a chain does is not an optimisation.
#[test]
fn a_batch_matches_one_at_a_time() {
    let frames: Vec<Vec<u8>> = (1..=12u8).map(|n| signed_swap([n; 32], 1)).collect();
    let refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();

    let mut serial = registry();
    let mut expected = Vec::new();
    for f in &refs {
        expected.push(
            serial
                .submit_signed(ZAP, f, 0)
                .map(|a| (a.seq, a.account, a.rejected)),
        );
    }

    let mut batched = registry();
    let got: Vec<_> = batched
        .get_mut(ZAP)
        .unwrap()
        .submit_signed_batch(&refs, 0)
        .into_iter()
        .map(|r| r.map(|a| (a.seq, a.account, a.rejected)))
        .collect();

    assert_eq!(got, expected, "the batch path diverged from the serial one");
    assert_eq!(
        serial.get(ZAP).unwrap().state_root(),
        batched.get(ZAP).unwrap().state_root(),
        "the two paths produced different chains"
    );
}

/// One bad frame in a batch fails alone, and the rest still sequence in order.
#[test]
fn a_bad_frame_does_not_spoil_the_batch() {
    let mut frames: Vec<Vec<u8>> = (1..=8u8).map(|n| signed_swap([n; 32], 1)).collect();
    let last = frames[3].len() - 1;
    frames[3][last] ^= 0xFF; // corrupt one intent's trailing byte
    frames[5].truncate(10); // and truncate another
    let refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();

    let mut r = registry();
    let out = r.get_mut(ZAP).unwrap().submit_signed_batch(&refs, 0);
    assert_eq!(out.len(), 8);
    assert!(out[3].is_err(), "a corrupted frame was accepted");
    assert!(out[5].is_err(), "a truncated frame was accepted");
    for (i, o) in out.iter().enumerate() {
        if i != 3 && i != 5 {
            assert!(
                o.is_ok(),
                "frame {} failed alongside the bad ones: {:?}",
                i,
                o
            );
        }
    }
    // Sequence numbers are still strictly increasing across the survivors.
    let seqs: Vec<u64> = out
        .iter()
        .filter_map(|o| o.as_ref().ok().map(|a| a.seq))
        .collect();
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "sequencing was not monotonic: {:?}",
        seqs
    );
}

/// **S14** survives the fast path: a valid signature over someone else's
/// account authorises nothing, batched or not.
#[test]
fn entitlement_is_checked_in_the_batch_path_too() {
    let intent = Intent::Transfer {
        from: [0xAB; 32], // not the wallet's account
        to: [1u8; 32],
        asset: XZEC,
        amount: Fixed::whole(1),
    };
    let auth = Authorization {
        chain_id: ZAP,
        vm_id: zyn_vm::zvm::vm_id::<SwapState>(),
        valid_until_epoch: u64::MAX,
    };
    let digest = eip712_digest::<SwapState>(&auth, &intent);
    let (sig, rid) = wallet().sign_prehash_recoverable(&digest).unwrap();
    let mut cred = [0u8; 65];
    cred[..64].copy_from_slice(&sig.to_bytes());
    cred[64] = rid.to_byte() + 27;
    let frame = encode_submission(
        &auth,
        Scheme::Secp256k1Eip712,
        &cred,
        &wire::encode_intent_bytes(&intent),
    );

    let mut r = registry();
    let out = r.get_mut(ZAP).unwrap().submit_signed_batch(&[&frame], 0);
    assert!(
        out[0].is_err(),
        "a signature over another account was accepted in a batch"
    );
}
