//! Signing once with a mainstream wallet, then trading without popups.

use ed25519_dalek::{Signer, SigningKey as EdKey};
use k256::ecdsa::SigningKey;
use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{Fixed, Params};
use zyn::verify::{
    authorize_delegated, authorize_delegated_intent, decode_authorized, decode_committed_intent,
    encode_authorized, CommittedError, Credential, Delegated, VerifyError,
};
use zyn_vm::auth::{account_of, delegation_bytes_as, Authorization, Scheme, Signed};
use zyn_vm::session::{session_payload, Delegation, CAP_SWAP, CAP_TRANSFER, CAP_WITHDRAW};
use zyn_vm::spec::MicrochainVm;

const CHAIN: u32 = 11;

fn state() -> SwapState {
    SwapState::new(CHAIN, Params::v1())
}

fn envelope() -> Authorization {
    Authorization::for_vm::<SwapState>(CHAIN, 0, 100)
}

fn owner() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32].into()).unwrap()
}

/// The account the owner's MetaMask controls.
fn owner_account() -> [u8; 32] {
    let key = owner();
    let point = key.verifying_key().to_encoded_point(false);
    let hash = zyn_vm::eip712::keccak(&[&point.as_bytes()[1..]]);
    account_of(Scheme::Secp256k1Eip712, &hash[12..])
}

fn session_key() -> EdKey {
    EdKey::from_bytes(&[42u8; 32])
}

fn swap() -> Intent {
    Intent::SwapExactIn {
        account: owner_account(),
        asset_in: XZEC,
        path: vec![swapvm::types::legacy_id(1)],
        amount_in: Fixed::whole(100),
        min_out: Fixed::whole(90),
    }
}

fn withdrawal() -> Intent {
    Intent::RequestWithdrawal {
        account: owner_account(),
        asset: XZEC,
        amount: Fixed::whole(10),
        destination: [5u8; 32],
    }
}

/// One MetaMask popup, opening a session.
fn open_session(caps: u32, until: u64) -> (Delegation, Credential) {
    let mut d = Delegation::session(
        owner_account(),
        session_key().verifying_key().to_bytes(),
        0,
        until,
    );
    d.capabilities = caps;
    let Signed::Prehash(digest) =
        delegation_bytes_as::<SwapState>(Scheme::Secp256k1Eip712, CHAIN, &d)
    else {
        panic!("an EVM wallet signs a prehash")
    };
    let (sig, rid) = owner().sign_prehash_recoverable(&digest).unwrap();
    let mut bytes = [0u8; 65];
    bytes[..64].copy_from_slice(&sig.to_bytes());
    bytes[64] = rid.to_byte() + 27;
    (d, Credential::Evm { signature: bytes })
}

/// A trade, signed in the page with no wallet involved.
fn sign_with_session(d: &Delegation, auth: &Authorization, intent: &Intent) -> [u8; 64] {
    let id = d.id(CHAIN, &auth.vm_id);
    session_key()
        .sign(&session_payload::<SwapState>(&id, auth, intent))
        .to_bytes()
}

#[test]
fn one_wallet_popup_authorises_many_trades() {
    let (d, owner_cred) = open_session(CAP_SWAP, 50);
    let auth = envelope();
    let st = state();

    // Three different swaps, no further wallet interaction.
    for min_out in [90i64, 80, 70] {
        let intent = Intent::SwapExactIn {
            account: owner_account(),
            asset_in: XZEC,
            path: vec![swapvm::types::legacy_id(1)],
            amount_in: Fixed::whole(100),
            min_out: Fixed::whole(min_out),
        };
        let del = Delegated {
            delegation: d.clone(),
            owner: owner_cred.clone(),
            session_signature: sign_with_session(&d, &auth, &intent),
        };
        assert_eq!(
            authorize_delegated::<SwapState>(&del, &auth, &intent, &st),
            Ok(owner_account()),
            "a session trade was refused"
        );
    }
}

/// The property that makes a browser-held key survivable.
#[test]
fn a_session_key_cannot_withdraw() {
    let (d, owner_cred) = open_session(CAP_SWAP, 50);
    let auth = envelope();
    let intent = withdrawal();
    let del = Delegated {
        delegation: d.clone(),
        owner: owner_cred,
        session_signature: sign_with_session(&d, &auth, &intent),
    };
    assert_eq!(
        authorize_delegated::<SwapState>(&del, &auth, &intent, &state()),
        Err(VerifyError::OutOfScope),
        "a trade-only session moved value off the chain"
    );
}

/// Staying on Zyn does not make a payment recoverable. A default agent session
/// must not be able to transfer the account to an attacker-controlled account.
#[test]
fn a_swap_session_cannot_transfer_on_chain() {
    let (d, owner_cred) = open_session(CAP_SWAP, 50);
    let auth = envelope();
    let intent = Intent::Transfer {
        from: owner_account(),
        to: [0xAA; 32],
        asset: XZEC,
        amount: Fixed::whole(10),
    };
    let del = Delegated {
        delegation: d.clone(),
        owner: owner_cred,
        session_signature: sign_with_session(&d, &auth, &intent),
    };
    assert_eq!(
        authorize_delegated::<SwapState>(&del, &auth, &intent, &state()),
        Err(VerifyError::OutOfScope),
        "a swap-only session transferred value to another Zyn account"
    );

    let (transfer, owner_cred) = open_session(CAP_TRANSFER, 50);
    let del = Delegated {
        delegation: transfer.clone(),
        owner: owner_cred,
        session_signature: sign_with_session(&transfer, &auth, &intent),
    };
    assert_eq!(
        authorize_delegated::<SwapState>(&del, &auth, &intent, &state()),
        Ok(owner_account()),
        "an explicitly granted transfer capability was ignored"
    );
}

#[test]
fn a_committed_delegation_is_reverified_from_its_own_bytes() {
    let (delegation, owner) = open_session(CAP_SWAP, 50);
    let auth = envelope();
    let intent = swap();
    let delegated = Delegated {
        delegation: delegation.clone(),
        owner,
        session_signature: sign_with_session(&delegation, &auth, &intent),
    };
    let authorized =
        authorize_delegated_intent::<SwapState>(&delegated, &auth, intent.clone(), &state())
            .expect("sequencer verification");
    let committed = encode_authorized::<SwapState>(&authorized);

    let replayed = decode_authorized::<SwapState>(&committed, &state())
        .expect("replica verification from committed bytes");
    assert_eq!(replayed.intent(), &intent);
    assert_eq!(
        decode_committed_intent::<SwapState>(&committed).unwrap(),
        intent
    );

    let mut changed = committed;
    let last_signature_byte = changed.len() - swapvm::wire::encode_intent_bytes(&swap()).len() - 5;
    changed[last_signature_byte] ^= 1;
    assert!(matches!(
        decode_authorized::<SwapState>(&changed, &state()),
        Err(CommittedError::Unauthorised(VerifyError::BadSignature))
            | Err(CommittedError::Malformed)
    ));
}

/// Nor rebind where a payout lands, which is the other irreversible power.
#[test]
fn a_session_key_cannot_rebind_a_withdrawal_destination() {
    let (d, owner_cred) = open_session(CAP_SWAP | CAP_WITHDRAW, 50);
    let auth = envelope();
    let intent = Intent::BindWithdrawal {
        account: owner_account(),
        destination: [9u8; 32],
    };
    let del = Delegated {
        delegation: d.clone(),
        owner: owner_cred,
        session_signature: sign_with_session(&d, &auth, &intent),
    };
    assert_eq!(
        authorize_delegated::<SwapState>(&del, &auth, &intent, &state()),
        Err(VerifyError::OutOfScope),
        "a session redirected a payout"
    );
}

/// Anyone can write a delegation naming anyone's account. Only the owner can
/// sign one.
#[test]
fn a_delegation_over_someone_elses_account_is_refused() {
    let (mut d, owner_cred) = open_session(CAP_SWAP, 50);
    d.account = [0xAB; 32]; // a victim's account, signed by us
    let auth = envelope();
    let intent = swap();
    let del = Delegated {
        delegation: d.clone(),
        owner: owner_cred,
        session_signature: sign_with_session(&d, &auth, &intent),
    };
    assert!(matches!(
        authorize_delegated::<SwapState>(&del, &auth, &intent, &state()),
        Err(VerifyError::NotTheOwner) | Err(VerifyError::BadSignature)
    ));
}

#[test]
fn a_session_expires_even_though_the_intent_has_not() {
    let (d, owner_cred) = open_session(CAP_SWAP, 3);
    let auth = envelope();
    let intent = swap();
    let del = Delegated {
        delegation: d.clone(),
        owner: owner_cred,
        session_signature: sign_with_session(&d, &auth, &intent),
    };
    let mut st = state();
    assert!(authorize_delegated::<SwapState>(&del, &auth, &intent, &st).is_ok());

    while st.epoch() <= 3 {
        let at = st.seq();
        swapvm::vm::apply(
            &mut st,
            &swapvm::tx::SequencedIntent {
                seq: at + 1,
                intent: Intent::Checkpoint,
            },
        );
    }
    // The intent envelope is still good; the session is not.
    assert!(auth.is_live(&st).is_ok());
    assert_eq!(
        authorize_delegated::<SwapState>(&del, &auth, &intent, &st),
        Err(VerifyError::SessionExpired)
    );
}

/// A session signature is bound to the delegation that authorised it, so a key
/// delegated by two accounts cannot have a signature moved between them.
#[test]
fn a_session_signature_does_not_travel_between_delegations() {
    let (short, _) = open_session(CAP_SWAP, 5);
    let (long, long_cred) = open_session(CAP_SWAP, 500);
    let auth = envelope();
    let intent = swap();

    // The long delegation is genuinely the owner's — that check passes. What
    // fails is the session signature, which was taken under the short one, so
    // a session cannot have its lifetime extended by re-presenting its work
    // under a longer certificate.
    let del = Delegated {
        delegation: long,
        owner: long_cred,
        session_signature: sign_with_session(&short, &auth, &intent),
    };
    assert_eq!(
        authorize_delegated::<SwapState>(&del, &auth, &intent, &state()),
        Err(VerifyError::BadSignature),
        "a session signature was reused under a longer-lived delegation"
    );
}

/// What the user actually reads before granting a session.
#[test]
fn the_session_prompt_names_the_powers_in_words() {
    let d = Delegation::session(owner_account(), [2u8; 32], 0, 50);
    let typed = d.typed();
    assert_eq!(
        typed.encode_type(),
        "AuthorizeSession(bytes32 account,bytes32 sessionKey,string mayOnly,bytes32 policyHash,uint256 validFromEpoch,uint256 validUntilEpoch)"
    );
    let rendered = format!("{:?}", typed.fields);
    assert!(
        rendered.contains("swap"),
        "the prompt did not say what it grants"
    );
    assert!(
        !rendered.contains("withdraw"),
        "a default session claimed withdrawal"
    );

    // And the Solana prompt says it too, in the text the wallet displays.
    let msg = zyn_vm::auth::delegation_message::<SwapState>(CHAIN, &d);
    assert!(msg.contains("It cannot withdraw."));
}
