//! Who signed an intent — checked identically by sequencers, replicas, and proof guests.
//!
//! Signature arithmetic is deterministic consensus work. The sequencer runs
//! it before assigning a sequence number, while replicas and proof guests run
//! it again from the committed record. [`crate::auth`] fixes what is signed;
//! this module proves who signed it and what that signer may do.
//!
//! # The account is an output, not an input
//!
//! [`signer_of`] returns the account that signed. It does not take a claimed
//! account and check it. That is deliberate: an API that hands back a boolean
//! for a caller to compare invites the one line of code that forgets to
//! compare, and that line has drained more bridges than any cryptographic
//! flaw. There is nothing here to forget — either you get an account back or
//! you get an error, and the account you get is the only one you can act on.
//!
//! # What a stolen key can still do
//!
//! Everything a signing key authorises is, by construction, everything the
//! thief authorises. The narrowing is elsewhere and it matters more than
//! anything in this file: a withdrawal destination is bound in state and
//! changing it waits out `exit_timeout_epochs`, so a key theft costs trading
//! control rather than the balance. See `zyn_bridge::vault::Binding`.

use alloc::vec::Vec;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use crate::auth::{
    account_of, delegation_bytes_as, signed_bytes_as, AuthError, Authorization, Scheme, Signed,
};
use crate::commit::Encoder;
use crate::read::Decoder;
use crate::session::{session_payload, AssetLimit, Delegation, DelegationPolicyError, MAX_POLICY_ITEMS};
use crate::eip712::keccak;
use crate::spec::{AccountId, MicrochainVm};

/// A signature together with whatever the scheme needs to identify its signer.
///
/// The EVM variant carries no key on purpose. `eth_signTypedData_v4` returns a
/// signature and nothing else — the wallet never exposes a public key — so the
/// signer is recovered, not asserted. Making that a property of the type means
/// no caller can pass an address it merely hopes is right.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Credential {
    /// Zyn's own keys: ed25519 over the canonical payload.
    Ed25519 { key: [u8; 32], signature: [u8; 64] },
    /// A Solana wallet's `signMessage`: ed25519 over the displayed text.
    Solana { key: [u8; 32], signature: [u8; 64] },
    /// An EVM wallet's `eth_signTypedData_v4`: 65 bytes of `r || s || v`.
    Evm { signature: [u8; 65] },
}

impl Credential {
    pub fn scheme(&self) -> Scheme {
        match self {
            Credential::Ed25519 { .. } => Scheme::Ed25519,
            Credential::Solana { .. } => Scheme::Ed25519Solana,
            Credential::Evm { .. } => Scheme::Secp256k1Eip712,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VerifyError {
    /// The signature does not check out under the scheme's own rules.
    BadSignature,
    /// The public key is not a point on the curve, or is otherwise unusable.
    BadKey,
    /// A second valid signature over the same message exists.
    ///
    /// For any ECDSA signature `(r, s)`, `(r, -s mod n)` is equally valid.
    /// Ethereum banned the high half in [EIP-2], and so does this: a message
    /// with two signatures is a message with two identities in any log,
    /// cache or replay index keyed by signature.
    ///
    /// [EIP-2]: https://eips.ethereum.org/EIPS/eip-2
    MalleableSignature,
    /// The `v` byte is not 27 or 28 (nor the raw 0 or 1 some libraries emit).
    BadRecoveryId,
    /// The envelope was rejected before any signature was looked at.
    Envelope(AuthError),
    /// The delegation was signed by someone other than the account it grants
    /// authority over. The most important check in the chain: without it,
    /// anyone could issue themselves a session over anyone's balance.
    NotTheOwner,
    /// The session's window has closed.
    SessionExpired,
    /// The intent needs authority this session was not given — a session key
    /// reaching for a withdrawal, most likely.
    OutOfScope,
    /// An owner-signed agent constraint did not allow this exact action.
    Policy(DelegationPolicyError),
    /// The signatures were valid but do not entitle this intent.
    Authority(AuthorityError),
}

impl From<AuthError> for VerifyError {
    fn from(e: AuthError) -> Self {
        VerifyError::Envelope(e)
    }
}

/// The account that signed this intent under this envelope.
pub fn signer_of<V: MicrochainVm>(
    cred: &Credential,
    auth: &Authorization,
    intent: &V::Intent,
) -> Result<AccountId, VerifyError> {
    let scheme = cred.scheme();
    let signed = signed_bytes_as::<V>(scheme, auth, intent);
    match cred {
        Credential::Ed25519 { key, signature } | Credential::Solana { key, signature } => {
            let Signed::Message(msg) = signed else {
                return Err(VerifyError::BadSignature);
            };
            verify_ed25519(key, signature, &msg)?;
            Ok(account_of(scheme, key))
        }
        Credential::Evm { signature } => {
            let Signed::Prehash(digest) = signed else {
                return Err(VerifyError::BadSignature);
            };
            let address = recover_address(&digest, signature)?;
            Ok(account_of(scheme, &address))
        }
    }
}

/// [`signer_of`], plus the envelope check against a live chain.
///
/// The envelope is checked *first*. A signature over an expired or
/// wrong-chain envelope is a perfectly valid signature over something we will
/// not execute, and spending curve arithmetic to discover that is work an
/// unauthenticated submitter gets to choose for us.
pub fn authorize<V: MicrochainVm>(
    cred: &Credential,
    auth: &Authorization,
    intent: &V::Intent,
    state: &V,
) -> Result<AccountId, VerifyError> {
    auth.is_live(state)?;
    signer_of::<V>(cred, auth, intent)
}

fn verify_ed25519(key: &[u8; 32], signature: &[u8; 64], msg: &[u8]) -> Result<(), VerifyError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|_| VerifyError::BadKey)?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    // `verify_strict` rejects small-order and torsion-component keys, so a
    // single signature cannot be valid under two different public keys.
    vk.verify_strict(msg, &sig).map_err(|_| VerifyError::BadSignature)
}

/// The 20-byte Ethereum address that produced this signature over this digest.
///
/// `keccak256(uncompressed public key without its 0x04 tag)[12..]` — the
/// definition Ethereum uses, reproduced rather than imported so that nothing
/// silently changes it.
pub fn recover_address(digest: &[u8; 32], signature: &[u8; 65]) -> Result<[u8; 20], VerifyError> {
    let v = signature[64];
    let rid = match v {
        27 | 28 => v - 27,
        // Some libraries hand back a bare recovery id. Accepting both costs
        // nothing: 0 and 1 are not valid EIP-155 `v` values, so there is no
        // input that could mean two things.
        0 | 1 => v,
        _ => return Err(VerifyError::BadRecoveryId),
    };
    let sig = K256Signature::from_slice(&signature[..64]).map_err(|_| VerifyError::BadSignature)?;
    if sig.normalize_s().is_some() {
        return Err(VerifyError::MalleableSignature);
    }
    let rid = RecoveryId::from_byte(rid).ok_or(VerifyError::BadRecoveryId)?;
    let vk = VerifyingKey::recover_from_prehash(digest, &sig, rid)
        .map_err(|_| VerifyError::BadSignature)?;
    let point = vk.to_encoded_point(false);
    let hash = keccak(&[&point.as_bytes()[1..]]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    Ok(out)
}

#[allow(unused_imports)]
use k256::elliptic_curve::sec1::ToEncodedPoint;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eip712::{Domain, TypedData, Value};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The EIP-712 specification's own worked example, signed by its own
    /// stated account.
    ///
    /// This is the only test in the tree that proves our typed-data encoding
    /// matches the rest of the world's. Everything else could be
    /// self-consistently wrong: the same mistake in the encoder and in the
    /// expected value passes forever. Here the signature was produced by
    /// someone else, years ago, from bytes we had no part in choosing — so if
    /// a single byte of our `encodeType`, `encodeData`, domain separator or
    /// `0x1901` prefix is wrong, recovery lands on a different address and
    /// this fails.
    #[test]
    fn our_eip712_encoding_recovers_the_specifications_own_signer() {
        let person = |name: &str, wallet: &str| {
            TypedData::new("Person")
                .field("name", Value::String(name.into()))
                .field("wallet", Value::Address(hex(wallet).try_into().unwrap()))
        };
        let mail = TypedData::new("Mail")
            .field("from", Value::Struct(person("Cow", "CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")))
            .field("to", Value::Struct(person("Bob", "bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")))
            .field("contents", Value::String("Hello, Bob!".into()));
        let domain = Domain {
            name: "Ether Mail".into(),
            version: "1".into(),
            chain_id: Some(1),
            verifying_contract: Some(
                hex("CcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC").try_into().unwrap(),
            ),
            salt: None,
        };

        let digest = zyn_vm::eip712::digest(&domain, &mail);
        let sig: [u8; 65] = hex(
            "4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d\
             07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562\
             1c",
        )
        .try_into()
        .unwrap();

        assert_eq!(
            recover_address(&digest, &sig).expect("recovery"),
            hex("CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826").as_slice(),
            "our EIP-712 encoding disagrees with the specification's example"
        );
    }
}


/// An intent signed by a session key, with the certificate that authorised it.
///
/// Two signatures travel together: the owner's over the delegation, made once
/// in a mainstream wallet, and the session's over this intent, made silently in
/// the page. Neither is useful alone.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Delegated {
    pub delegation: Delegation,
    /// The owner's authorisation of the delegation, under whatever scheme the
    /// owner's wallet uses.
    pub owner: Credential,
    /// The session key's signature over this particular intent.
    pub session_signature: [u8; 64],
}

/// The account a delegated intent acts for, or why it may not.
///
/// The order of checks is the order of cheapness, and also of blast radius:
/// envelope, then session window, then scope, then two signatures. An
/// unauthenticated submitter should not be able to make us do curve arithmetic
/// by sending nonsense.
pub fn authorize_delegated<V: MicrochainVm>(
    d: &Delegated,
    auth: &Authorization,
    intent: &V::Intent,
    state: &V,
) -> Result<AccountId, VerifyError> {
    auth.is_live(state)?;

    if !d.delegation.policy_is_well_formed() {
        return Err(VerifyError::Policy(DelegationPolicyError::Malformed));
    }
    if state.epoch() < d.delegation.valid_from_epoch {
        return Err(VerifyError::Policy(DelegationPolicyError::NotStarted));
    }
    if state.epoch() > d.delegation.valid_until_epoch {
        return Err(VerifyError::SessionExpired);
    }
    if !d.delegation.permits(V::intent_capability(intent)) {
        return Err(VerifyError::OutOfScope);
    }
    state
        .delegation_policy(&d.delegation, intent)
        .map_err(VerifyError::Policy)?;

    // 1. The owner really did issue this delegation — and issued it over their
    //    own account, not someone else's.
    let chain = state.chain_id();
    let signer = match &d.owner {
        Credential::Ed25519 { key, signature } | Credential::Solana { key, signature } => {
            let scheme = d.owner.scheme();
            let Signed::Message(msg) = delegation_bytes_as::<V>(scheme, chain, &d.delegation)
            else {
                return Err(VerifyError::BadSignature);
            };
            verify_ed25519(key, signature, &msg)?;
            account_of(scheme, key)
        }
        Credential::Evm { signature } => {
            let Signed::Prehash(digest) =
                delegation_bytes_as::<V>(Scheme::Secp256k1Eip712, chain, &d.delegation)
            else {
                return Err(VerifyError::BadSignature);
            };
            account_of(Scheme::Secp256k1Eip712, &recover_address(&digest, signature)?)
        }
    };
    if signer != d.delegation.account {
        return Err(VerifyError::NotTheOwner);
    }

    // 2. The session key really did sign this intent, under this delegation.
    let id = d.delegation.id(chain, &auth.vm_id);
    let payload = session_payload::<V>(&id, auth, intent);
    verify_ed25519(&d.delegation.session_key, &d.session_signature, &payload)?;

    Ok(d.delegation.account)
}

// --- Making the check impossible to skip ---

/// Why an intent is allowed to execute.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Authority {
    /// The operator issued this itself: a credited deposit, an attested vault
    /// balance, a confirmed anchor, a checkpoint. Nothing a user signs.
    Operator,
    /// Every account required by `intent_authorities` produced a signature.
    Accounts(Vec<AccountId>),
}

/// An intent that has been established as authorised.
///
/// The point of the type is that it has no public field and no constructor
/// except the two below: one that verifies signatures, and one that says
/// `Operator` out loud. [`Authorized`] takes this rather than a
/// bare intent, so an RPC cannot be written that forgets to authenticate —
/// it will not compile.
///
/// This is the same move as [`signer_of`] returning an account instead of a
/// boolean, one level up. The check that is easiest to omit is the one nothing
/// fails without, so the omission is made unavailable rather than discouraged.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Authorized<I> {
    intent: I,
    by: Authority,
    evidence: Evidence,
}

/// The authorization material committed beside an intent.
///
/// A replica decodes and verifies this again before applying the action. The
/// sequencer's successful check is therefore an optimization, not an assertion
/// a replica has to trust.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Evidence {
    Operator,
    Signed {
        authorization: Authorization,
        credentials: Vec<Credential>,
    },
    Delegated {
        authorization: Authorization,
        delegated: Delegated,
    },
}

impl<I> Authorized<I> {
    /// The operator's own intent.
    ///
    /// Deliberately blunt to write and easy to grep for: every use is a place
    /// where the node is asserting authority on its own behalf, and those
    /// should be countable.
    pub fn operator(intent: I) -> Authorized<I> {
        Authorized {
            intent,
            by: Authority::Operator,
            evidence: Evidence::Operator,
        }
    }

    pub fn intent(&self) -> &I {
        &self.intent
    }

    pub fn authority(&self) -> &Authority {
        &self.by
    }

    pub fn into_intent(self) -> I {
        self.intent
    }

    /// Build from signers this crate has already verified.
    ///
    /// `pub(crate)` and not one letter more. The whole value of this type is
    /// that outside code cannot make one without checking a signature; a batch
    /// path that needs to verify first and construct second is exactly the
    /// caller that must stay inside the boundary rather than widen it.
    #[doc(hidden)]
    pub fn checked(
        intent: I,
        signers: Vec<AccountId>,
        authorization: Authorization,
        credential: Credential,
    ) -> Authorized<I> {
        Authorized {
            intent,
            by: Authority::Accounts(signers),
            evidence: Evidence::Signed {
                authorization,
                credentials: alloc::vec![credential],
            },
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthorityError {
    /// A signature was valid, but over an intent naming an account the signer
    /// does not control. The attack this exists to stop.
    NotEntitled,
    /// An intent requiring two parties arrived with one.
    MissingSignature,
    /// No user signature can authorise this intent — it is operator-only.
    OperatorOnly,
}

/// Verify signatures **and** establish that they entitle this intent.
///
/// One credential per required account, in any order. Every account named by
/// `intent_authorities` must be covered, or the intent does not execute.
pub fn authorize_intent<V: MicrochainVm>(
    creds: &[Credential],
    auth: &Authorization,
    intent: V::Intent,
    state: &V,
) -> Result<Authorized<V::Intent>, VerifyError> {
    let required = V::intent_authorities(&intent);
    if required.is_empty() {
        return Err(VerifyError::Authority(AuthorityError::OperatorOnly));
    }
    auth.is_live(state)?;

    let mut signers = Vec::with_capacity(creds.len());
    for c in creds {
        signers.push(signer_of::<V>(c, auth, &intent)?);
    }
    for account in &required {
        if !signers.contains(account) {
            return Err(VerifyError::Authority(AuthorityError::MissingSignature));
        }
    }
    // Every signature presented must be doing work. A credential for an
    // account the intent does not name is either a mistake or an attempt to
    // find out which accounts a key controls.
    if signers.iter().any(|s| !required.contains(s)) {
        return Err(VerifyError::Authority(AuthorityError::NotEntitled));
    }
    Ok(Authorized {
        intent,
        by: Authority::Accounts(required),
        evidence: Evidence::Signed {
            authorization: *auth,
            credentials: creds.to_vec(),
        },
    })
}

/// The session-key equivalent: one delegated signature, covering an intent
/// that requires exactly that one account.
///
/// A multi-party intent cannot be settled by a session key. Both sides of a
/// trade agreeing is precisely the thing a browser key should not be able to
/// assert on someone's behalf.
pub fn authorize_delegated_intent<V: MicrochainVm>(
    d: &Delegated,
    auth: &Authorization,
    intent: V::Intent,
    state: &V,
) -> Result<Authorized<V::Intent>, VerifyError> {
    let required = V::intent_authorities(&intent);
    if required.is_empty() {
        return Err(VerifyError::Authority(AuthorityError::OperatorOnly));
    }
    if required.len() != 1 {
        return Err(VerifyError::Authority(AuthorityError::MissingSignature));
    }
    let account = authorize_delegated::<V>(d, auth, &intent, state)?;
    if account != required[0] {
        return Err(VerifyError::Authority(AuthorityError::NotEntitled));
    }
    Ok(Authorized {
        intent,
        by: Authority::Accounts(required),
        evidence: Evidence::Delegated {
            authorization: *auth,
            delegated: d.clone(),
        },
    })
}

// --- Canonical committed authorization ---

const COMMITTED_MAGIC: &[u8; 8] = b"ZYNAUTH1";
const COMMITTED_OPERATOR: u8 = 0;
const COMMITTED_SIGNED: u8 = 1;
const COMMITTED_DELEGATED: u8 = 2;
const MAX_CREDENTIALS: usize = 4;

/// A failure while reconstructing an authorized action from committed bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommittedError {
    Malformed,
    Unauthorised(VerifyError),
}

fn encode_authorization(e: &mut Encoder, auth: &Authorization) {
    e.u32(auth.chain_id)
        .bytes(&auth.vm_id)
        .u64(auth.valid_until_epoch);
}

fn decode_authorization(d: &mut Decoder) -> Result<Authorization, CommittedError> {
    Ok(Authorization {
        chain_id: d.u32().map_err(|_| CommittedError::Malformed)?,
        vm_id: d.array::<32>().map_err(|_| CommittedError::Malformed)?,
        valid_until_epoch: d.u64().map_err(|_| CommittedError::Malformed)?,
    })
}

fn encode_credential(e: &mut Encoder, credential: &Credential) {
    e.u8(credential.scheme().tag());
    match credential {
        Credential::Ed25519 { key, signature } | Credential::Solana { key, signature } => {
            e.bytes(key).bytes(signature);
        }
        Credential::Evm { signature } => {
            e.bytes(signature);
        }
    }
}

fn decode_credential(d: &mut Decoder) -> Result<Credential, CommittedError> {
    let tag = d.u8().map_err(|_| CommittedError::Malformed)?;
    match Scheme::from_tag(tag).ok_or(CommittedError::Malformed)? {
        Scheme::Ed25519 => Ok(Credential::Ed25519 {
            key: d.array::<32>().map_err(|_| CommittedError::Malformed)?,
            signature: d.array::<64>().map_err(|_| CommittedError::Malformed)?,
        }),
        Scheme::Ed25519Solana => Ok(Credential::Solana {
            key: d.array::<32>().map_err(|_| CommittedError::Malformed)?,
            signature: d.array::<64>().map_err(|_| CommittedError::Malformed)?,
        }),
        Scheme::Secp256k1Eip712 => Ok(Credential::Evm {
            signature: d.array::<65>().map_err(|_| CommittedError::Malformed)?,
        }),
    }
}

fn encode_delegation_policy(e: &mut Encoder, delegation: &Delegation) {
    e.u8(delegation.allowed_assets.len() as u8);
    for asset in &delegation.allowed_assets { e.u32(*asset); }
    e.u8(delegation.allowed_pools.len() as u8);
    for pool in &delegation.allowed_pools { e.u32(*pool); }
    e.u8(delegation.max_per_action.len() as u8);
    for limit in &delegation.max_per_action { e.u32(limit.asset).fixed(limit.amount); }
    e.u16(delegation.max_slippage_bps)
        .u64(delegation.valid_from_epoch)
        .bytes(&delegation.salt);
}

fn decode_ids(d: &mut Decoder) -> Result<Vec<u32>, CommittedError> {
    let n = d.u8().map_err(|_| CommittedError::Malformed)? as usize;
    if n > MAX_POLICY_ITEMS { return Err(CommittedError::Malformed); }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n { out.push(d.u32().map_err(|_| CommittedError::Malformed)?); }
    Ok(out)
}

fn decode_limits(d: &mut Decoder) -> Result<Vec<AssetLimit>, CommittedError> {
    let n = d.u8().map_err(|_| CommittedError::Malformed)? as usize;
    if n > MAX_POLICY_ITEMS { return Err(CommittedError::Malformed); }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(AssetLimit {
            asset: d.u32().map_err(|_| CommittedError::Malformed)?,
            amount: d.fixed().map_err(|_| CommittedError::Malformed)?,
        });
    }
    Ok(out)
}

fn decode_intent<V: MicrochainVm>(d: &mut Decoder) -> Result<V::Intent, CommittedError> {
    let len = d.u32().map_err(|_| CommittedError::Malformed)? as usize;
    let bytes = d.take_bytes(len).map_err(|_| CommittedError::Malformed)?;
    let mut intent_decoder = Decoder::new(bytes);
    let intent = V::decode_intent(&mut intent_decoder).ok_or(CommittedError::Malformed)?;
    if intent_decoder.remaining() != 0 {
        return Err(CommittedError::Malformed);
    }
    Ok(intent)
}

/// Encode exactly the authorization evidence, envelope, and application intent
/// that replicas must re-check. These bytes are the journal record and the
/// input folded into the epoch intent commitment.
pub fn encode_authorized<V: MicrochainVm>(authorized: &Authorized<V::Intent>) -> Vec<u8> {
    let mut e = Encoder::new();
    e.bytes(COMMITTED_MAGIC);
    match &authorized.evidence {
        Evidence::Operator => {
            e.u8(COMMITTED_OPERATOR);
        }
        Evidence::Signed {
            authorization,
            credentials,
        } => {
            e.u8(COMMITTED_SIGNED);
            encode_authorization(&mut e, authorization);
            e.u8(credentials.len() as u8);
            for credential in credentials {
                encode_credential(&mut e, credential);
            }
        }
        Evidence::Delegated {
            authorization,
            delegated,
        } => {
            e.u8(COMMITTED_DELEGATED);
            encode_authorization(&mut e, authorization);
            e.bytes(&delegated.delegation.account)
                .bytes(&delegated.delegation.session_key)
                .u32(delegated.delegation.capabilities);
            encode_delegation_policy(&mut e, &delegated.delegation);
            e.u64(delegated.delegation.valid_until_epoch);
            encode_credential(&mut e, &delegated.owner);
            e.bytes(&delegated.session_signature);
        }
    }
    let intent = V::encode_intent(&authorized.intent);
    e.u32(intent.len() as u32).bytes(&intent);
    e.finish().to_vec()
}

/// Decode and independently verify a committed action against the state at the
/// point where it will execute.
pub fn decode_authorized<V: MicrochainVm>(
    bytes: &[u8],
    state: &V,
) -> Result<Authorized<V::Intent>, CommittedError> {
    let mut d = Decoder::new(bytes);
    if d.take_bytes(COMMITTED_MAGIC.len()).map_err(|_| CommittedError::Malformed)?
        != COMMITTED_MAGIC
    {
        return Err(CommittedError::Malformed);
    }
    let kind = d.u8().map_err(|_| CommittedError::Malformed)?;
    let authorized = match kind {
        COMMITTED_OPERATOR => {
            let intent = decode_intent::<V>(&mut d)?;
            if !V::intent_authorities(&intent).is_empty() {
                return Err(CommittedError::Unauthorised(VerifyError::Authority(
                    AuthorityError::NotEntitled,
                )));
            }
            Authorized::operator(intent)
        }
        COMMITTED_SIGNED => {
            let authorization = decode_authorization(&mut d)?;
            let count = d.u8().map_err(|_| CommittedError::Malformed)? as usize;
            if count == 0 || count > MAX_CREDENTIALS {
                return Err(CommittedError::Malformed);
            }
            let mut credentials = Vec::with_capacity(count);
            for _ in 0..count {
                credentials.push(decode_credential(&mut d)?);
            }
            let intent = decode_intent::<V>(&mut d)?;
            authorize_intent::<V>(&credentials, &authorization, intent, state)
                .map_err(CommittedError::Unauthorised)?
        }
        COMMITTED_DELEGATED => {
            let authorization = decode_authorization(&mut d)?;
            let delegation = Delegation {
                account: d.array::<32>().map_err(|_| CommittedError::Malformed)?,
                session_key: d.array::<32>().map_err(|_| CommittedError::Malformed)?,
                capabilities: d.u32().map_err(|_| CommittedError::Malformed)?,
                allowed_assets: decode_ids(&mut d)?,
                allowed_pools: decode_ids(&mut d)?,
                max_per_action: decode_limits(&mut d)?,
                max_slippage_bps: d.u16().map_err(|_| CommittedError::Malformed)?,
                valid_from_epoch: d.u64().map_err(|_| CommittedError::Malformed)?,
                salt: d.array::<32>().map_err(|_| CommittedError::Malformed)?,
                valid_until_epoch: d.u64().map_err(|_| CommittedError::Malformed)?,
            };
            let owner = decode_credential(&mut d)?;
            let session_signature = d.array::<64>().map_err(|_| CommittedError::Malformed)?;
            let intent = decode_intent::<V>(&mut d)?;
            let delegated = Delegated {
                delegation,
                owner,
                session_signature,
            };
            authorize_delegated_intent::<V>(&delegated, &authorization, intent, state)
                .map_err(CommittedError::Unauthorised)?
        }
        _ => return Err(CommittedError::Malformed),
    };
    if d.remaining() != 0 {
        return Err(CommittedError::Malformed);
    }
    Ok(authorized)
}

/// Read the application intent from a committed record without making an
/// authorization decision. Use only after [`decode_authorized`] has already
/// succeeded for the same record, such as indexing a verified journal.
pub fn decode_committed_intent<V: MicrochainVm>(
    bytes: &[u8],
) -> Result<V::Intent, CommittedError> {
    let mut d = Decoder::new(bytes);
    if d.take_bytes(COMMITTED_MAGIC.len())
        .map_err(|_| CommittedError::Malformed)?
        != COMMITTED_MAGIC
    {
        return Err(CommittedError::Malformed);
    }
    match d.u8().map_err(|_| CommittedError::Malformed)? {
        COMMITTED_OPERATOR => {}
        COMMITTED_SIGNED => {
            let _ = decode_authorization(&mut d)?;
            let count = d.u8().map_err(|_| CommittedError::Malformed)? as usize;
            if count == 0 || count > MAX_CREDENTIALS {
                return Err(CommittedError::Malformed);
            }
            for _ in 0..count {
                let _ = decode_credential(&mut d)?;
            }
        }
        COMMITTED_DELEGATED => {
            let _ = decode_authorization(&mut d)?;
            d.take_bytes(32 + 32 + 4)
                .map_err(|_| CommittedError::Malformed)?;
            let _ = decode_ids(&mut d)?;
            let _ = decode_ids(&mut d)?;
            let _ = decode_limits(&mut d)?;
            d.take_bytes(2 + 8 + 32 + 8).map_err(|_| CommittedError::Malformed)?;
            let _ = decode_credential(&mut d)?;
            d.take_bytes(64).map_err(|_| CommittedError::Malformed)?;
        }
        _ => return Err(CommittedError::Malformed),
    }
    let intent = decode_intent::<V>(&mut d)?;
    if d.remaining() != 0 {
        return Err(CommittedError::Malformed);
    }
    Ok(intent)
}

// --- Verifying many at once ---

/// One signature waiting to be checked, reduced to bytes.
///
/// The reduction is the point. Building this is cheap and needs the VM's
/// concrete `Intent` type; checking it is expensive and needs nothing but
/// bytes — so the expensive half can cross a thread boundary without dragging
/// `Send + Sync` bounds onto every VM in the workspace.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pending {
    pub signed: Signed,
    pub credential: Credential,
}

impl Pending {
    /// Reduce one submission to the bytes its signature covers.
    pub fn of<V: MicrochainVm>(
        credential: Credential,
        auth: &Authorization,
        intent: &V::Intent,
    ) -> Pending {
        let signed = signed_bytes_as::<V>(credential.scheme(), auth, intent);
        Pending { signed, credential }
    }

    fn resolve(&self) -> Result<AccountId, VerifyError> {
        match (&self.signed, &self.credential) {
            (Signed::Message(msg), Credential::Ed25519 { key, signature }) => {
                verify_ed25519(key, signature, msg)?;
                Ok(account_of(Scheme::Ed25519, key))
            }
            (Signed::Message(msg), Credential::Solana { key, signature }) => {
                verify_ed25519(key, signature, msg)?;
                Ok(account_of(Scheme::Ed25519Solana, key))
            }
            (Signed::Prehash(digest), Credential::Evm { signature }) => {
                let address = recover_address(digest, signature)?;
                Ok(account_of(Scheme::Secp256k1Eip712, &address))
            }
            // A message credential against a prehash, or the reverse. The
            // scheme decides both, so this is unreachable through `Pending::of`
            // and is a caller who built one by hand.
            _ => Err(VerifyError::BadSignature),
        }
    }
}

/// Check a batch across every core, and return the results in order.
///
/// Measured at 115 µs for a secp256k1 recovery against 1.6 µs to apply the
/// swap it authorises, verification is where a sequencer spends its time —
/// and unlike sequencing, it is embarrassingly parallel. Nothing here shares
/// state: each signature is independent arithmetic over its own bytes.
///
/// Order is preserved because sequence numbers are assigned from it. A batch
/// that came back reordered would be a batch that executed in a different
/// order on a different machine, which is **S1** broken by an optimisation.
#[cfg(feature = "std")]
pub fn resolve_batch(pending: &[Pending]) -> Vec<Result<AccountId, VerifyError>> {
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

    // Below this, the threads cost more than the work. Measured against a
    // ~115 µs unit of work and a ~20 µs spawn, the crossover is a handful.
    if threads < 2 || pending.len() < 4 {
        return pending.iter().map(Pending::resolve).collect();
    }

    let chunk = pending.len().div_ceil(threads);
    let mut out: Vec<Result<AccountId, VerifyError>> = Vec::with_capacity(pending.len());

    std::thread::scope(|s| {
        let handles: Vec<_> = pending
            .chunks(chunk)
            .map(|c| s.spawn(move || c.iter().map(Pending::resolve).collect::<Vec<_>>()))
            .collect();
        for h in handles {
            // A panic in a verifier is a bug in the crypto library, not an
            // input we should absorb; but absorbing it beats taking the
            // sequencer down with it.
            match h.join() {
                Ok(mut part) => out.append(&mut part),
                Err(_) => out.push(Err(VerifyError::BadSignature)),
            }
        }
    });
    out
}

/// Serial verifier used by deterministic no-std guests.
#[cfg(not(feature = "std"))]
pub fn resolve_batch(pending: &[Pending]) -> Vec<Result<AccountId, VerifyError>> {
    pending.iter().map(Pending::resolve).collect()
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use crate::auth::Authorization;

    // A VM-free fixture: `Pending` is bytes, so the batch path can be tested
    // without any application at all — which is the property that makes it
    // parallelisable in the first place.
    fn ed(seed: u8, msg: &[u8]) -> (Pending, AccountId) {
        use ed25519_dalek::{Signer, SigningKey};
        let k = SigningKey::from_bytes(&[seed; 32]);
        let key = k.verifying_key().to_bytes();
        let p = Pending {
            signed: Signed::Message(msg.to_vec()),
            credential: Credential::Ed25519 { key, signature: k.sign(msg).to_bytes() },
        };
        (p, account_of(Scheme::Ed25519, &key))
    }

    #[test]
    fn a_batch_agrees_with_one_at_a_time() {
        let items: Vec<(Pending, AccountId)> =
            (1..=40u8).map(|n| ed(n, format!("intent {}", n).as_bytes())).collect();
        let pending: Vec<Pending> = items.iter().map(|(p, _)| p.clone()).collect();

        let batched = resolve_batch(&pending);
        let one_at_a_time: Vec<_> = pending.iter().map(Pending::resolve).collect();
        assert_eq!(batched, one_at_a_time, "parallel verification disagreed with serial");
        for (i, (_, who)) in items.iter().enumerate() {
            assert_eq!(batched[i], Ok(*who));
        }
    }

    /// Order is load-bearing: sequence numbers come from it.
    #[test]
    fn results_come_back_in_the_order_they_went_in() {
        let mut pending = Vec::new();
        let mut expected = Vec::new();
        for n in 1..=33u8 {
            let (p, who) = ed(n, b"same message");
            pending.push(p);
            expected.push(Ok(who));
        }
        assert_eq!(resolve_batch(&pending), expected);
    }

    /// One bad signature must not spoil the batch, and must be the one that
    /// fails.
    #[test]
    fn a_single_bad_signature_fails_alone() {
        let mut pending: Vec<Pending> =
            (1..=20u8).map(|n| ed(n, b"payload").0).collect();
        // Corrupt exactly one.
        if let Credential::Ed25519 { signature, .. } = &mut pending[7].credential {
            signature[0] ^= 0xFF;
        }
        let out = resolve_batch(&pending);
        assert_eq!(out.len(), 20);
        assert_eq!(out[7], Err(VerifyError::BadSignature));
        for (i, r) in out.iter().enumerate() {
            if i != 7 {
                assert!(r.is_ok(), "signature {} failed alongside the bad one", i);
            }
        }
    }

    #[test]
    fn a_small_batch_still_works() {
        for n in 0..5usize {
            let pending: Vec<Pending> =
                (1..=n as u8).map(|k| ed(k, b"x").0).collect();
            assert_eq!(resolve_batch(&pending).len(), n);
        }
    }

    #[test]
    fn a_mismatched_credential_is_refused_not_guessed() {
        let p = Pending {
            signed: Signed::Prehash([0u8; 32]),
            credential: Credential::Ed25519 { key: [1u8; 32], signature: [0u8; 64] },
        };
        assert_eq!(p.resolve(), Err(VerifyError::BadSignature));
        let _ = Authorization { chain_id: 1, vm_id: [0u8; 32], valid_until_epoch: 0 };
    }
}
