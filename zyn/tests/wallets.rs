//! Signing a ZynZap intent with the wallet a user already has.
//!
//! The unit tests prove the encoding matches EIP-712. These prove the whole
//! path: an EVM wallet signs a swap, and the chain works out which account
//! made it without ever being told.

use k256::ecdsa::SigningKey;
use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{Fixed, Params};
use zyn::verify::{recover_address, signer_of, Credential, VerifyError};
use zyn_vm::auth::{account_of, eip712_digest, signed_bytes_as, Authorization, Scheme, Signed};
use zyn_vm::spec::MicrochainVm;

const CHAIN: u32 = 11;

fn swap(min_out: i64) -> Intent {
    Intent::SwapExactIn {
        account: [0u8; 32],
        asset_in: XZEC,
        path: vec![swapvm::types::legacy_id(1)],
        amount_in: Fixed::whole(100),
        min_out: Fixed::whole(min_out),
    }
}

fn envelope(chain: u32) -> Authorization {
    Authorization::for_vm::<SwapState>(chain, 0, 10)
}

fn wallet() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32].into()).expect("key")
}

/// Exactly what MetaMask does for `eth_signTypedData_v4`: sign the EIP-712
/// digest and return `r || s || v`.
fn sign_as_metamask(key: &SigningKey, auth: &Authorization, intent: &Intent) -> [u8; 65] {
    let digest = eip712_digest::<SwapState>(auth, intent);
    let (sig, rid) = key.sign_prehash_recoverable(&digest).expect("sign");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = rid.to_byte() + 27;
    out
}

#[test]
fn an_evm_wallet_can_authorise_a_swap_without_ever_revealing_a_public_key() {
    let key = wallet();
    let auth = envelope(CHAIN);
    let intent = swap(90);
    let sig = sign_as_metamask(&key, &auth, &intent);

    let account = signer_of::<SwapState>(&Credential::Evm { signature: sig }, &auth, &intent)
        .expect("a well-formed signature should authorise");

    // The account is derived from the address the signature recovers to —
    // which is the same address MetaMask would show the user.
    let digest = eip712_digest::<SwapState>(&auth, &intent);
    let address = recover_address(&digest, &sig).unwrap();
    assert_eq!(account, account_of(Scheme::Secp256k1Eip712, &address));
}

/// The whole point of putting fields in the signature: a relayer that rewrites
/// the trade invalidates it.
#[test]
fn a_rewritten_trade_does_not_verify() {
    let key = wallet();
    let auth = envelope(CHAIN);
    let sig = sign_as_metamask(&key, &auth, &swap(90));

    // Someone between the wallet and the sequencer weakens the slippage bound.
    let tampered = swap(1);
    let cred = Credential::Evm { signature: sig };
    let got = signer_of::<SwapState>(&cred, &auth, &tampered);

    // ECDSA recovery always yields *some* key, so the failure shows up as a
    // different account rather than an error. That is why the account is an
    // output: an account nobody holds cannot pay for a swap.
    match got {
        Err(_) => {}
        Ok(other) => assert_ne!(
            other,
            signer_of::<SwapState>(&cred, &auth, &swap(90)).unwrap(),
            "a tampered trade resolved to the signer's own account"
        ),
    }
}

#[test]
fn a_signature_does_not_carry_to_another_chain() {
    let key = wallet();
    let intent = swap(90);
    let sig = sign_as_metamask(&key, &envelope(CHAIN), &intent);
    let cred = Credential::Evm { signature: sig };

    let here = signer_of::<SwapState>(&cred, &envelope(CHAIN), &intent).unwrap();
    match signer_of::<SwapState>(&cred, &envelope(CHAIN + 1), &intent) {
        Err(_) => {}
        Ok(there) => assert_ne!(there, here, "a signature was valid on a second chain"),
    }
}

/// For every ECDSA signature there is a second one over the same message with
/// `s` negated. Accepting both means one authorisation with two identities.
#[test]
fn the_second_valid_signature_over_the_same_swap_is_refused() {
    let key = wallet();
    let auth = envelope(CHAIN);
    let intent = swap(90);
    let sig = sign_as_metamask(&key, &auth, &intent);
    assert!(signer_of::<SwapState>(&Credential::Evm { signature: sig }, &auth, &intent).is_ok());

    // n, the order of secp256k1's group.
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let mut flipped = sig;
    // s' = n - s, and the recovery bit flips with it.
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = N[i] as i16 - sig[32 + i] as i16 - borrow;
        flipped[32 + i] = d.rem_euclid(256) as u8;
        borrow = if d < 0 { 1 } else { 0 };
    }
    flipped[64] = if sig[64] == 27 { 28 } else { 27 };

    assert_eq!(
        signer_of::<SwapState>(&Credential::Evm { signature: flipped }, &auth, &intent),
        Err(VerifyError::MalleableSignature),
        "the mirrored signature was accepted"
    );
}

#[test]
fn a_malformed_recovery_byte_is_refused_rather_than_guessed() {
    let key = wallet();
    let auth = envelope(CHAIN);
    let intent = swap(90);
    let mut sig = sign_as_metamask(&key, &auth, &intent);
    sig[64] = 42;
    assert_eq!(
        signer_of::<SwapState>(&Credential::Evm { signature: sig }, &auth, &intent),
        Err(VerifyError::BadRecoveryId)
    );
}

/// The same 32 bytes of key material under two schemes are two unrelated
/// accounts, so there is no scheme to confuse and nothing to downgrade to.
#[test]
fn one_key_under_two_schemes_is_two_accounts() {
    let key = [3u8; 32];
    assert_ne!(
        account_of(Scheme::Ed25519, &key),
        account_of(Scheme::Ed25519Solana, &key)
    );
    // And an address is not a public key, so no EVM account can collide with
    // an ed25519 one by construction.
    assert_ne!(Scheme::Secp256k1Eip712.key_len(), Scheme::Ed25519.key_len());
}

/// A Solana wallet signs the text it displays. If we verified a hash of it
/// instead, every real Phantom signature would be rejected — and any scheme
/// that "fixed" that by rehashing would be verifying something the user never
/// read.
#[test]
fn a_solana_wallet_signs_the_words_it_shows() {
    let auth = envelope(CHAIN);
    let intent = swap(90);
    let Signed::Message(msg) = signed_bytes_as::<SwapState>(Scheme::Ed25519Solana, &auth, &intent)
    else {
        panic!("a Solana signature is over a message, not a prehash");
    };
    let text = String::from_utf8(msg).expect("the message must be displayable text");
    assert!(text.starts_with("Zyn intent authorization"));
    assert!(text.contains(&format!("Chain: {}", CHAIN)));
    assert!(text.contains("Valid until epoch: 10"));
}

/// An expired envelope is rejected before any curve arithmetic, so an
/// unauthenticated submitter cannot choose how much work we do.
#[test]
fn an_expired_envelope_is_refused_before_the_signature_is_examined() {
    let mut state = SwapState::new(CHAIN, Params::v1());
    let auth = envelope(CHAIN);
    let intent = swap(90);
    let sig = sign_as_metamask(&wallet(), &auth, &intent);
    let cred = Credential::Evm { signature: sig };

    assert!(zyn::verify::authorize(&cred, &auth, &intent, &state).is_ok());

    for _ in 0..=auth.valid_until_epoch {
        let at = state.seq();
        swapvm::vm::apply(
            &mut state,
            &swapvm::tx::SequencedIntent {
                seq: at + 1,
                intent: Intent::Checkpoint,
            },
        );
    }
    assert!(state.epoch() > auth.valid_until_epoch);
    assert_eq!(
        zyn::verify::authorize(&cred, &auth, &intent, &state),
        Err(VerifyError::Envelope(zyn_vm::auth::AuthError::Expired))
    );
}

// --- ed25519 schemes: our own keys, and Solana wallets ---

use ed25519_dalek::{Signer, SigningKey as EdKey};

fn ed_key() -> EdKey {
    EdKey::from_bytes(&[9u8; 32])
}

fn sign_ed(key: &EdKey, scheme: Scheme, auth: &Authorization, intent: &Intent) -> [u8; 64] {
    let Signed::Message(msg) = signed_bytes_as::<SwapState>(scheme, auth, intent) else {
        panic!("an ed25519 scheme signs a message");
    };
    key.sign(&msg).to_bytes()
}

#[test]
fn a_native_key_authorises_and_resolves_to_its_own_account() {
    let key = ed_key();
    let pk = key.verifying_key().to_bytes();
    let auth = envelope(CHAIN);
    let intent = swap(90);
    let sig = sign_ed(&key, Scheme::Ed25519, &auth, &intent);

    assert_eq!(
        signer_of::<SwapState>(
            &Credential::Ed25519 {
                key: pk,
                signature: sig
            },
            &auth,
            &intent
        ),
        Ok(account_of(Scheme::Ed25519, &pk))
    );
}

#[test]
fn a_solana_wallet_authorises_a_swap() {
    let key = ed_key();
    let pk = key.verifying_key().to_bytes();
    let auth = envelope(CHAIN);
    let intent = swap(90);
    let sig = sign_ed(&key, Scheme::Ed25519Solana, &auth, &intent);

    assert_eq!(
        signer_of::<SwapState>(
            &Credential::Solana {
                key: pk,
                signature: sig
            },
            &auth,
            &intent
        ),
        Ok(account_of(Scheme::Ed25519Solana, &pk))
    );
}

/// The sharpest cross-scheme case: the same ed25519 key, the same intent, two
/// schemes. Unlike the EVM/ed25519 pair there is no difference in curve or key
/// length to save us — only the domain separation is doing the work.
#[test]
fn a_solana_signature_is_not_a_native_one() {
    let key = ed_key();
    let pk = key.verifying_key().to_bytes();
    let auth = envelope(CHAIN);
    let intent = swap(90);
    let solana_sig = sign_ed(&key, Scheme::Ed25519Solana, &auth, &intent);

    assert_eq!(
        signer_of::<SwapState>(
            &Credential::Ed25519 {
                key: pk,
                signature: solana_sig
            },
            &auth,
            &intent
        ),
        Err(VerifyError::BadSignature),
        "a Solana signature authorised a native account"
    );
}

#[test]
fn a_tampered_ed25519_swap_is_refused_outright() {
    let key = ed_key();
    let pk = key.verifying_key().to_bytes();
    let auth = envelope(CHAIN);
    let sig = sign_ed(&key, Scheme::Ed25519, &auth, &swap(90));

    // Ed25519 verifies against a stated key rather than recovering one, so
    // unlike ECDSA a tampered message fails outright rather than resolving to
    // some other account.
    assert_eq!(
        signer_of::<SwapState>(
            &Credential::Ed25519 {
                key: pk,
                signature: sig
            },
            &auth,
            &swap(1)
        ),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn a_key_that_is_not_a_point_is_refused_rather_than_panicking() {
    let auth = envelope(CHAIN);
    let cred = Credential::Ed25519 {
        key: [0xFF; 32],
        signature: [0u8; 64],
    };
    assert!(matches!(
        signer_of::<SwapState>(&cred, &auth, &swap(90)),
        Err(VerifyError::BadKey) | Err(VerifyError::BadSignature)
    ));
}

/// Regression guard for the reason a Zyn intent is signable at all.
///
/// MetaMask compares `domain.chainId` against the network the user has
/// selected and refuses to sign on a mismatch — and when the id is one it has
/// never seen, the request does not fail, it hangs. A Zyn chain id is never an
/// EVM network id, so declaring one here would mean every user had to add a
/// fake custom network before they could trade.
///
/// The field must therefore be absent, and the chain binding must survive
/// anyway.
#[test]
fn the_zyn_domain_declares_no_evm_chain_id() {
    let (domain, _) = zyn_vm::auth::typed_data::<SwapState>(&envelope(CHAIN), &swap(90));
    assert_eq!(domain.chain_id, None, "a Zyn domain named an EVM chain id");
    assert!(
        !domain.as_struct().encode_type().contains("chainId"),
        "chainId reached the domain type: {}",
        domain.as_struct().encode_type()
    );

    // The binding is not lost — it moved into `salt`, which no wallet
    // inspects. Two chains, two separators.
    let (other, _) = zyn_vm::auth::typed_data::<SwapState>(&envelope(CHAIN + 1), &swap(90));
    assert_ne!(domain.salt, other.salt);
    assert_ne!(domain.separator(), other.separator());
}

/// A Solana wallet signing our message must not be signing a transaction.
///
/// This is the same concern EIP-712's `0x19` prefix answers, and Solana
/// answers it the same way: the offchain-message spec begins
/// `\xff"solana offchain"` precisely because `\xff` is illegal as the first
/// byte of a transaction `MessageHeader`.
///
/// We do not use that envelope. `signMessage` displays the bytes it is given,
/// and a wallet showing `\xffsolana offchain` before the text would be worse
/// to read — plain text is also what Sign In With Solana and every
/// sign-in-with-wallet flow hands over today. So the property has to be
/// established rather than inherited, and *checked*, not assumed: a signature
/// over bytes that could also deserialise as a transaction message would be a
/// valid transaction signature.
///
/// Two independent reasons ours cannot, both derived from the live message so
/// that editing the text cannot quietly invalidate them.
#[test]
fn a_solana_signature_over_our_message_can_never_be_a_transaction() {
    let Signed::Message(msg) =
        signed_bytes_as::<SwapState>(Scheme::Ed25519Solana, &envelope(CHAIN), &swap(90))
    else {
        unreachable!()
    };

    // Legacy layout: [required_sigs, readonly_signed, readonly_unsigned,
    // <compact-u16 account count>, 32 bytes per account, ...].
    assert_eq!(
        msg[0] & 0x80,
        0,
        "must parse as legacy, not as a versioned transaction"
    );
    let required_sigs = msg[0] as usize;
    let readonly_signed = msg[1] as usize;
    let account_count = msg[3] as usize;
    assert!(
        msg[3] < 0x80,
        "the account count must be a one-byte compact-u16 for this reasoning"
    );

    // 1. Every required signer must be one of the accounts, and every
    //    read-only signed account one of the signers. Ours are neither.
    assert!(
        required_sigs > account_count || readonly_signed > required_sigs,
        "the header is structurally valid: {} sigs, {} readonly-signed, {} accounts",
        required_sigs,
        readonly_signed,
        account_count
    );

    // 2. And the message is far too short to hold the accounts its own header
    //    claims, let alone a blockhash and an instruction.
    let needed = 3 + 1 + account_count * 32 + 32;
    assert!(
        needed > msg.len(),
        "the message is long enough to be a transaction: needs {}, has {}",
        needed,
        msg.len()
    );
}
