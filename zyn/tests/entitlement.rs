//! A signature says who signed. It never says what they may touch.
//!
//! Connecting the two is the check nothing fails without, which is why it is
//! the one most easily left out — and why it is worth its own file.

use ed25519_dalek::{Signer, SigningKey as EdKey};
use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{Fixed, Params};
use zyn::verify::{authorize_intent, Authority, AuthorityError, Authorized, Credential, VerifyError};
use zyn_vm::auth::{account_of, signed_bytes_as, Authorization, Scheme, Signed};

const CHAIN: u32 = 11;

fn key(seed: u8) -> EdKey {
    EdKey::from_bytes(&[seed; 32])
}

fn account(seed: u8) -> [u8; 32] {
    account_of(Scheme::Ed25519, &key(seed).verifying_key().to_bytes())
}

fn envelope() -> Authorization {
    Authorization::for_vm::<SwapState>(CHAIN, 0, 100)
}

fn credential(seed: u8, auth: &Authorization, intent: &Intent) -> Credential {
    let k = key(seed);
    let Signed::Message(msg) = signed_bytes_as::<SwapState>(Scheme::Ed25519, auth, intent) else {
        unreachable!()
    };
    Credential::Ed25519 { key: k.verifying_key().to_bytes(), signature: k.sign(&msg).to_bytes() }
}

fn swap_for(acct: [u8; 32]) -> Intent {
    Intent::SwapExactIn {
        account: acct,
        asset_in: XZEC,
        path: vec![1],
        amount_in: Fixed::whole(100),
        min_out: Fixed::whole(90),
    }
}

/// The attack. Alice signs, correctly and verifiably, an intent that spends
/// Bob's account. Every signature check passes. Only entitlement stops it.
#[test]
fn a_valid_signature_over_someone_elses_account_is_refused() {
    let st = SwapState::new(CHAIN, Params::v1());
    let auth = envelope();
    let bobs_swap = swap_for(account(2));

    // Alice's signature really is valid over these exact bytes.
    let alice = credential(1, &auth, &bobs_swap);
    assert_eq!(
        zyn::verify::signer_of::<SwapState>(&alice, &auth, &bobs_swap),
        Ok(account(1)),
        "the signature itself should verify — that is the point"
    );

    // And it authorises nothing.
    assert_eq!(
        authorize_intent::<SwapState>(&[alice], &auth, bobs_swap, &st).map(|a| a.authority().clone()),
        Err(VerifyError::Authority(AuthorityError::MissingSignature))
    );
}

#[test]
fn the_account_holder_can_of_course_authorise_their_own() {
    let st = SwapState::new(CHAIN, Params::v1());
    let auth = envelope();
    let mine = swap_for(account(1));
    let cred = credential(1, &auth, &mine);
    let ok = authorize_intent::<SwapState>(&[cred], &auth, mine, &st).expect("own swap");
    assert_eq!(ok.authority(), &Authority::Accounts(vec![account(1)]));
}

/// A settled trade is two agreements. One signature is a proposal, not a deal.
#[test]
fn a_two_party_trade_needs_both_parties() {
    let st = SwapState::new(CHAIN, Params::v1());
    let auth = envelope();
    let trade = Intent::AcceptOffer {
        maker: account(1),
        taker: account(2),
        offer_asset: XZEC,
        offer_amount: Fixed::whole(10),
        want_asset: 2,
        want_amount: Fixed::whole(5),
    };

    let maker = credential(1, &auth, &trade);
    let taker = credential(2, &auth, &trade);

    assert_eq!(
        authorize_intent::<SwapState>(core::slice::from_ref(&maker), &auth, trade.clone(), &st).err(),
        Some(VerifyError::Authority(AuthorityError::MissingSignature)),
        "one side settled a trade alone"
    );
    assert!(
        authorize_intent::<SwapState>(&[maker, taker], &auth, trade, &st).is_ok(),
        "both sides signing should settle"
    );
}

/// Operator intents are unreachable by any user signature, however valid.
#[test]
fn a_user_cannot_sign_an_operator_intent() {
    let st = SwapState::new(CHAIN, Params::v1());
    let auth = envelope();
    let minting = Intent::CreditDeposit {
        account: account(1),
        asset: XZEC,
        amount: Fixed::whole(1_000_000),
        index: 1,
        external_ref: [0u8; 32],
    };
    let cred = credential(1, &auth, &minting);
    assert_eq!(
        authorize_intent::<SwapState>(&[cred], &auth, minting, &st).err(),
        Some(VerifyError::Authority(AuthorityError::OperatorOnly)),
        "a user minted themselves a deposit"
    );
}

/// Every credential presented must be doing work. A spare one is either a
/// mistake or someone probing which accounts a key controls.
#[test]
fn a_signature_that_entitles_nothing_is_refused_rather_than_ignored() {
    let st = SwapState::new(CHAIN, Params::v1());
    let auth = envelope();
    let mine = swap_for(account(1));
    let mine_cred = credential(1, &auth, &mine);
    let spare = credential(3, &auth, &mine);
    assert_eq!(
        authorize_intent::<SwapState>(&[mine_cred, spare], &auth, mine, &st).err(),
        Some(VerifyError::Authority(AuthorityError::NotEntitled))
    );
}

/// The compile-time half: a node accepts `Authorized`, and the only ways to
/// make one are to verify signatures or to claim operator authority in writing.
#[test]
fn operator_authority_must_be_stated_not_assumed() {
    let checkpoint = Authorized::operator(Intent::Checkpoint);
    assert_eq!(checkpoint.authority(), &Authority::Operator);
    assert_eq!(checkpoint.into_intent(), Intent::Checkpoint);
}
