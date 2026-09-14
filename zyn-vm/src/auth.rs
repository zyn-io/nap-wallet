//! What a user signs — the envelope around an intent.
//!
//! The VM itself checks no signatures: the sequencer establishes who authorised
//! what, upstream of the transition. But *what gets signed* is a consensus
//! concern, because a signature is only as narrow as the bytes underneath it.
//! Getting this shape wrong is not something an authorisation layer can fix
//! later — the signatures are already out there.
//!
//! Two failures this exists to prevent, both borrowed from VMs that learned
//! them the hard way.
//!
//! # Replay across chains and applications
//!
//! An intent's canonical encoding is the same bytes on every microchain running
//! the same VM. Signed bare, `swap 100 ZEC.zy for CAT` authorises that swap on
//! *any* Zyn chain, and — if two applications ever share an intent shape — on
//! any of those too.
//!
//! Ethereum hit this before EIP-712 and fixed it with a domain separator
//! binding a signature to a chain id and a contract. The same fix applies:
//! [`Authorization`] binds the signature to a chain id and a
//! [`vm_id`](crate::zvm::vm_id), so a signature taken on one is meaningless on
//! the other.
//!
//! # Replay across time
//!
//! Sequence numbers stop an intent executing twice, but they do not stop it
//! executing *late*. The sequencer chooses the sequence number, so a signed
//! swap can be held in a mempool and submitted a week later, at whatever price
//! suits whoever held it. That is not a hypothetical: it is ordinary sequencer
//! MEV.
//!
//! Solana bounds this with `recent_blockhash`, which gives a signed transaction
//! a short validity window. Zyn cannot copy that directly — a VM has no clock,
//! and consulting one inside a transition would break determinism (**S1**). But
//! it has an epoch, and epochs advance on a policy that already includes a time
//! failsafe. So validity is expressed in epochs: deterministic, replayable, and
//! still an expiry in wall-clock terms.

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::commit::{Encoder, Hash};
use crate::spec::{AccountId, MicrochainVm};

/// Domain tag. Distinct from every other hash in the crate, so a signing
/// payload can never be confused with a commitment leaf or an internal node.
const AUTH_DOMAIN: &[u8] = b"zyn.auth.v1";

/// The envelope binding an intent to where, what and when it is valid.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Authorization {
    /// Which microchain. A signature does not travel between them.
    pub chain_id: u32,
    /// Which program, as `H(VM_NAME, VM_VERSION)`. A signature does not travel
    /// between applications, nor across a version bump that changed what an
    /// intent means.
    pub vm_id: Hash,
    /// Last epoch in which this may be applied.
    ///
    /// Inclusive. `u64::MAX` means no expiry, which should be rare and
    /// deliberate — it is the mempool-forever case.
    pub valid_until_epoch: u64,
}

impl Authorization {
    /// An envelope for `V` on `chain_id`, expiring `epochs` after `now_epoch`.
    pub fn for_vm<V: MicrochainVm>(chain_id: u32, now_epoch: u64, epochs: u64) -> Authorization {
        Authorization {
            chain_id,
            vm_id: crate::zvm::vm_id::<V>(),
            valid_until_epoch: now_epoch.saturating_add(epochs),
        }
    }

    /// Whether this envelope is still usable against a live chain.
    ///
    /// Checked by the sequencer before an intent is given a sequence number,
    /// and by anything replaying the history to confirm it should have been.
    pub fn is_live<V: MicrochainVm>(&self, state: &V) -> Result<(), AuthError> {
        if self.chain_id != state.chain_id() {
            return Err(AuthError::WrongChain);
        }
        if self.vm_id != crate::zvm::vm_id::<V>() {
            return Err(AuthError::WrongProgram);
        }
        if state.epoch() > self.valid_until_epoch {
            return Err(AuthError::Expired);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthError {
    /// Signed for a different microchain.
    WrongChain,
    /// Signed for a different application, or a different version of one.
    WrongProgram,
    /// The validity window has closed.
    Expired,
}

/// The exact bytes a user signs.
///
/// Every field is length-prefixed, so no regrouping of the same bytes produces
/// the same payload — the same discipline as [`crate::derive`], and for the
/// same reason.
pub fn signing_payload<V: MicrochainVm>(auth: &Authorization, intent: &V::Intent) -> Vec<u8> {
    let encoded = V::encode_intent(intent);
    let mut e = Encoder::new();
    e.bytes(AUTH_DOMAIN)
        .u8(Scheme::Ed25519.tag())
        .u32(auth.chain_id)
        .bytes(&auth.vm_id)
        .u64(auth.valid_until_epoch)
        .u32(encoded.len() as u32)
        .bytes(&encoded);
    e.finish().to_vec()
}

/// The digest a signature is taken over.
pub fn signing_digest<V: MicrochainVm>(auth: &Authorization, intent: &V::Intent) -> Hash {
    crate::commit::hash_leaf(&signing_payload::<V>(auth, intent))
}

/// Which signature scheme an account is controlled by.
///
/// # Why more than one
///
/// Requiring a new wallet is the largest tax a chain can levy on its first
/// users, and it is levied at the worst possible moment — before they have
/// seen anything work. Someone bridging SOL in already runs Phantom. Someone
/// bridging ETH in already runs MetaMask. Both should be able to trade what
/// they bridged with the wallet they bridged it from.
///
/// None of these schemes needs a browser extension written by us, and none
/// needs a MetaMask Snap: `eth_signTypedData_v4` and Solana's `signMessage`
/// are methods every mainstream wallet in each ecosystem already exposes.
///
/// # Why the tag is bound into the account id
///
/// The alternative is a registry — an intent that says "this account uses
/// scheme 2 with this key" — which is state, which can be changed, and which
/// is therefore a second thing to authorise and a second thing to steal. There
/// is no registry here. An account id *is* the commitment:
///
/// ```text
///   account = H("zyn.account.v1" | scheme | len(key) | key)
/// ```
///
/// so the scheme cannot be swapped under an account, the same key bytes under
/// two schemes are two unrelated accounts, and an account exists the moment
/// someone deposits to it — with nothing to register first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scheme {
    /// Ed25519 over the canonical payload. Zyn's own keys and the CLI.
    Ed25519,
    /// secp256k1 over an [EIP-712](crate::eip712) digest, recovered to a
    /// 20-byte Ethereum address. MetaMask, Rabby, Coinbase Wallet, Ledger, and
    /// anything reachable over WalletConnect.
    Secp256k1Eip712,
    /// Ed25519 over a human-readable message, as Solana wallets sign with
    /// `signMessage`. Phantom, Solflare, Backpack.
    Ed25519Solana,
}

impl Scheme {
    pub fn tag(self) -> u8 {
        match self {
            Scheme::Ed25519 => 1,
            Scheme::Secp256k1Eip712 => 2,
            Scheme::Ed25519Solana => 3,
        }
    }

    pub fn from_tag(t: u8) -> Option<Scheme> {
        match t {
            1 => Some(Scheme::Ed25519),
            2 => Some(Scheme::Secp256k1Eip712),
            3 => Some(Scheme::Ed25519Solana),
            _ => None,
        }
    }

    /// The length of a key under this scheme, in bytes.
    ///
    /// Ethereum is 20 because a wallet never reveals its public key — only the
    /// address recovered from a signature — so the address is the identity we
    /// can actually check.
    pub fn key_len(self) -> usize {
        match self {
            Scheme::Ed25519 | Scheme::Ed25519Solana => 32,
            Scheme::Secp256k1Eip712 => 20,
        }
    }
}

/// Domain tag for account derivation. Distinct from [`AUTH_DOMAIN`] and from
/// every commitment prefix, so an account id can never be some other hash
/// reinterpreted.
const ACCOUNT_DOMAIN: &[u8] = b"zyn.account.v1";

/// The account a key controls under a scheme.
///
/// Length-prefixed for the same reason [`crate::derive`] length-prefixes seeds:
/// without it, a 20-byte key and a 32-byte key could in principle be arranged
/// to produce the same preimage.
pub fn account_of(scheme: Scheme, key: &[u8]) -> AccountId {
    let mut e = Encoder::new();
    e.bytes(ACCOUNT_DOMAIN)
        .u8(scheme.tag())
        .u32(key.len() as u32)
        .bytes(key);
    let mut h = Sha256::new();
    h.update(e.finish());
    h.finalize().into()
}

/// Exactly what a signature is taken over, which is not the same shape for
/// every scheme.
///
/// Ed25519 signs a message and hashes it internally; ECDSA as EVM wallets use
/// it signs a 32-byte prehash. Flattening those into one "digest" would mean
/// verifying something other than what the wallet signed — which produces a
/// system that rejects every real signature, or worse, accepts a rehashed one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Signed {
    /// The signature covers these bytes directly.
    Message(Vec<u8>),
    /// The signature covers this 32-byte digest.
    Prehash(Hash),
}

/// What a wallet using `scheme` puts its signature over.
///
/// The schemes are separated three times over: by the account id, by the hash
/// function, and by the tag inside the payload. Any one would do; all three are
/// here because a cross-scheme confusion is not a bug that gets noticed, it is
/// a bug that gets exploited.
pub fn signed_bytes_as<V: MicrochainVm>(
    scheme: Scheme,
    auth: &Authorization,
    intent: &V::Intent,
) -> Signed {
    match scheme {
        Scheme::Ed25519 => Signed::Message(signing_payload::<V>(auth, intent)),
        Scheme::Secp256k1Eip712 => Signed::Prehash(eip712_digest::<V>(auth, intent)),
        // Solana wallets sign the bytes they display, so the message is the
        // payload — hashing it first would verify something the user never saw.
        Scheme::Ed25519Solana => Signed::Message(solana_message::<V>(auth, intent).into_bytes()),
    }
}

/// The typed data an EVM wallet displays and signs.
///
/// The envelope is split the way EIP-712 intends: what the signature is *bound
/// to* — chain and program — goes in the domain, and what the user is *agreeing
/// to* goes in the message. Expiry is in the message because it is a term of
/// the agreement, and because a domain separator is cached by wallets.
///
/// The intent is nested rather than flattened so that a VM can never collide
/// with `validUntilEpoch` by naming a field that way. A VM author should not
/// have to know a reserved word to keep expiry signed.
pub fn typed_data<V: MicrochainVm>(
    auth: &Authorization,
    intent: &V::Intent,
) -> (crate::eip712::Domain, crate::eip712::TypedData) {
    use crate::eip712::{Domain, TypedData, Value};
    use alloc::string::ToString;

    let domain = Domain {
        name: V::VM_NAME.to_string(),
        version: alloc::format!("{}", V::VM_VERSION),
        // Deliberately absent: a Zyn chain id is not an EVM network id, and
        // MetaMask refuses — or worse, hangs — when it cannot match this
        // against the user's selected network. The binding moves to `salt`.
        chain_id: None,
        verifying_contract: None,
        salt: Some(domain_salt(auth)),
    };
    let message = TypedData::new("ZynIntent")
        .field("intent", Value::Struct(V::typed_intent(intent)))
        .field("validUntilEpoch", Value::uint(auth.valid_until_epoch));
    (domain, message)
}

/// The chain-and-program binding, carried in the domain's `salt`.
///
/// This is the whole of **S12**'s domain half — everything a signature must not
/// travel across — reduced to 32 bytes a wallet will pass through untouched.
fn domain_salt(auth: &Authorization) -> Hash {
    let mut e = Encoder::new();
    e.bytes(b"zyn.domain.v1")
        .u32(auth.chain_id)
        .bytes(&auth.vm_id);
    let mut h = Sha256::new();
    h.update(e.finish());
    h.finalize().into()
}

pub fn eip712_digest<V: MicrochainVm>(auth: &Authorization, intent: &V::Intent) -> Hash {
    let (domain, message) = typed_data::<V>(auth, intent);
    crate::eip712::digest(&domain, &message)
}

/// The message a Solana wallet shows for `signMessage`.
///
/// Solana wallets sign raw bytes and render them as text, so unlike EIP-712
/// there is no structure to lean on — the readability *is* the encoding. It is
/// therefore fixed here rather than left to an application, because a signing
/// prompt an application could rewrite is a signing prompt an application could
/// lie in.
///
/// The intent appears as a hash, not as fields. That is a real limitation of
/// this scheme and the reason to prefer EIP-712 where there is a choice: the
/// user is trusting the interface, not reading the trade.
pub fn solana_message<V: MicrochainVm>(
    auth: &Authorization,
    intent: &V::Intent,
) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::new();
    let intent_hash: Hash = {
        let mut h = Sha256::new();
        h.update(V::encode_intent(intent));
        h.finalize().into()
    };
    let _ = write!(
        s,
        "Zyn intent authorization\n\nChain: {}\nProgram: ",
        auth.chain_id
    );
    for b in auth.vm_id {
        let _ = write!(s, "{:02x}", b);
    }
    let _ = write!(
        s,
        "\nValid until epoch: {}\nIntent: ",
        auth.valid_until_epoch
    );
    for b in intent_hash {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// What a wallet using `scheme` signs to open a session.
///
/// The same three-way split as [`signed_bytes_as`], for the same reason: what
/// a wallet signs must be what we verify. The EIP-712 path renders the
/// delegation's own fields, so the user reads "may only: trade" rather than a
/// capability bitmask.
pub fn delegation_bytes_as<V: MicrochainVm>(
    scheme: Scheme,
    chain_id: u32,
    delegation: &crate::session::Delegation,
) -> Signed {
    let vm_id = crate::zvm::vm_id::<V>();
    match scheme {
        Scheme::Ed25519 => Signed::Message(delegation.payload(chain_id, &vm_id)),
        Scheme::Secp256k1Eip712 => {
            use alloc::string::ToString;
            let domain = crate::eip712::Domain {
                name: V::VM_NAME.to_string(),
                version: alloc::format!("{}", V::VM_VERSION),
                chain_id: None,
                verifying_contract: None,
                salt: Some(domain_salt(&Authorization {
                    chain_id,
                    vm_id,
                    valid_until_epoch: delegation.valid_until_epoch,
                })),
            };
            Signed::Prehash(crate::eip712::digest(&domain, &delegation.typed()))
        }
        Scheme::Ed25519Solana => {
            Signed::Message(delegation_message::<V>(chain_id, delegation).into_bytes())
        }
    }
}

/// The words a Solana wallet shows when opening a session.
pub fn delegation_message<V: MicrochainVm>(
    chain_id: u32,
    d: &crate::session::Delegation,
) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::new();
    let _ = write!(
        s,
        "Zyn session authorization\n\nThis key may trade on your behalf.\nIt cannot withdraw.\n\nChain: {}\nSession key: ",
        chain_id
    );
    for b in d.session_key {
        let _ = write!(s, "{:02x}", b);
    }
    let _ = write!(s, "\nCapabilities: {:#06x}\nPolicy: ", d.capabilities);
    for b in d.policy_hash() {
        let _ = write!(s, "{:02x}", b);
    }
    let _ = write!(
        s,
        "\nValid from epoch: {}\nValid until epoch: {}\nAccount: ",
        d.valid_from_epoch, d.valid_until_epoch
    );
    for b in d.account {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::Fixture;

    // A throwaway VM, so the auth tests do not depend on any application.
    use crate::checkpoint::Checkpoint;
    use crate::commit::Hash as H;
    use crate::fixed::Fixed;
    use alloc::vec;

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Toy {
        chain_id: u32,
        epoch: u64,
        seq: u64,
    }

    impl MicrochainVm for Toy {
        type Intent = u64;
        type Receipt = ();
        type Params = ();
        const VM_NAME: &'static str = "toy";
        const VM_VERSION: u16 = 1;
        fn genesis(chain_id: u32, _: ()) -> Self {
            Toy {
                chain_id,
                epoch: 0,
                seq: 0,
            }
        }
        fn chain_id(&self) -> u32 {
            self.chain_id
        }
        fn seq(&self) -> u64 {
            self.seq
        }
        fn epoch(&self) -> u64 {
            self.epoch
        }
        fn apply(&mut self, seq: u64, _: &u64) -> Vec<()> {
            self.seq = seq;
            vec![()]
        }
        fn sections(&self) -> Vec<H> {
            vec![[0u8; 32], [0u8; 32]]
        }
        fn seal_intent() -> u64 {
            0
        }
        fn sealed(_: &[()]) -> Option<Checkpoint> {
            None
        }
        fn as_sealed(&self, _: &Checkpoint) -> Option<Self> {
            None
        }
        fn rejected(_: &()) -> bool {
            false
        }
        fn unprovable(_: &()) -> bool {
            false
        }
        fn encode_intent(i: &u64) -> Vec<u8> {
            i.to_be_bytes().to_vec()
        }
        fn decode_intent(d: &mut crate::read::Decoder) -> Option<u64> {
            d.u64().ok()
        }
        fn encode(&self) -> Vec<u8> {
            Vec::new()
        }
        fn decode(_: &[u8]) -> Option<Self> {
            None
        }
        fn account_ids(&self) -> Vec<crate::spec::AccountId> {
            Vec::new()
        }
        fn account_leaves(&self) -> Vec<H> {
            Vec::new()
        }
        fn account_record(&self, _: &crate::spec::AccountId) -> Option<Vec<u8>> {
            None
        }
        fn leaf_of_record(r: &[u8]) -> H {
            crate::commit::hash_leaf(r)
        }
        fn gross_volume(&self) -> Fixed {
            Fixed::ZERO
        }
        fn conserved(&self) -> Result<(), &'static str> {
            Ok(())
        }
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Toy2(Toy);
    // Same intents, different program — the case a bare signature cannot tell
    // apart.
    impl MicrochainVm for Toy2 {
        type Intent = u64;
        type Receipt = ();
        type Params = ();
        const VM_NAME: &'static str = "toy";
        const VM_VERSION: u16 = 2;
        fn genesis(c: u32, _: ()) -> Self {
            Toy2(Toy::genesis(c, ()))
        }
        fn chain_id(&self) -> u32 {
            self.0.chain_id
        }
        fn seq(&self) -> u64 {
            self.0.seq
        }
        fn epoch(&self) -> u64 {
            self.0.epoch
        }
        fn apply(&mut self, s: u64, i: &u64) -> Vec<()> {
            self.0.apply(s, i)
        }
        fn sections(&self) -> Vec<H> {
            self.0.sections()
        }
        fn seal_intent() -> u64 {
            0
        }
        fn sealed(_: &[()]) -> Option<Checkpoint> {
            None
        }
        fn as_sealed(&self, _: &Checkpoint) -> Option<Self> {
            None
        }
        fn rejected(_: &()) -> bool {
            false
        }
        fn unprovable(_: &()) -> bool {
            false
        }
        fn encode_intent(i: &u64) -> Vec<u8> {
            i.to_be_bytes().to_vec()
        }
        fn decode_intent(d: &mut crate::read::Decoder) -> Option<u64> {
            d.u64().ok()
        }
        fn encode(&self) -> Vec<u8> {
            Vec::new()
        }
        fn decode(_: &[u8]) -> Option<Self> {
            None
        }
        fn account_ids(&self) -> Vec<crate::spec::AccountId> {
            Vec::new()
        }
        fn account_leaves(&self) -> Vec<H> {
            Vec::new()
        }
        fn account_record(&self, _: &crate::spec::AccountId) -> Option<Vec<u8>> {
            None
        }
        fn leaf_of_record(r: &[u8]) -> H {
            crate::commit::hash_leaf(r)
        }
        fn gross_volume(&self) -> Fixed {
            Fixed::ZERO
        }
        fn conserved(&self) -> Result<(), &'static str> {
            Ok(())
        }
    }

    fn auth(chain: u32, until: u64) -> Authorization {
        Authorization {
            chain_id: chain,
            vm_id: crate::zvm::vm_id::<Toy>(),
            valid_until_epoch: until,
        }
    }

    /// The EIP-712 lesson: the same intent signed for one chain must not
    /// authorise it on another.
    #[test]
    fn a_signature_does_not_travel_between_chains() {
        let a = signing_digest::<Toy>(&auth(1, 100), &42);
        let b = signing_digest::<Toy>(&auth(2, 100), &42);
        assert_ne!(a, b, "the same signed intent was valid on two chains");
    }

    /// Nor between applications, nor across a version bump — a version change
    /// is exactly when an intent's meaning may have moved under the signature.
    #[test]
    fn a_signature_does_not_travel_between_programs() {
        let toy = Authorization::for_vm::<Toy>(1, 0, 10);
        let toy2 = Authorization::for_vm::<Toy2>(1, 0, 10);
        assert_ne!(toy.vm_id, toy2.vm_id);
        assert_ne!(
            signing_digest::<Toy>(&toy, &42),
            signing_digest::<Toy2>(&toy2, &42),
            "a signature crossed a version boundary"
        );
    }

    /// The Solana `recent_blockhash` lesson, in epochs so it stays
    /// deterministic: a signed intent must not sit in a mempool forever waiting
    /// for a price that suits whoever is holding it.
    #[test]
    fn an_intent_expires() {
        let mut vm = Toy::genesis(1, ());
        let a = auth(1, 5);
        vm.epoch = 5;
        assert_eq!(a.is_live(&vm), Ok(()), "expiry should be inclusive");
        vm.epoch = 6;
        assert_eq!(a.is_live(&vm), Err(AuthError::Expired));
    }

    #[test]
    fn the_envelope_is_checked_against_the_live_chain() {
        let vm = Toy::genesis(1, ());
        assert_eq!(auth(2, 100).is_live(&vm), Err(AuthError::WrongChain));

        let mut wrong_program = auth(1, 100);
        wrong_program.vm_id = crate::zvm::vm_id::<Toy2>();
        assert_eq!(wrong_program.is_live(&vm), Err(AuthError::WrongProgram));

        assert_eq!(auth(1, 100).is_live(&vm), Ok(()));
    }

    #[test]
    fn different_intents_never_share_a_payload() {
        let a = auth(1, 100);
        assert_ne!(signing_digest::<Toy>(&a, &1), signing_digest::<Toy>(&a, &2));
    }

    /// The intent is length-prefixed inside the payload, so its bytes cannot be
    /// slid against the envelope's.
    #[test]
    fn the_intent_boundary_cannot_be_slid() {
        let a = auth(1, 0);
        let p = signing_payload::<Toy>(&a, &0);
        // Domain, chain, vm_id, expiry, length, then exactly the intent.
        assert_eq!(p.len(), AUTH_DOMAIN.len() + 1 + 4 + 32 + 8 + 4 + 8);
        assert!(p.starts_with(AUTH_DOMAIN));
    }

    #[test]
    fn a_signing_payload_is_not_a_commitment() {
        let a = auth(1, 0);
        assert_ne!(signing_digest::<Toy>(&a, &0), crate::commit::hash_leaf(&[]));
        let _ = Fixture::<Toy> {
            state: Toy::genesis(1, ()),
            accepted: 1,
            rejected: 2,
            sequence: Vec::new(),
        };
    }
}
