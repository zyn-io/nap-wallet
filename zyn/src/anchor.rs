//! The Zcash-bound commitment, and the rules that keep one canonical history.
//!
//! An anchor is what a Zcash transaction actually carries. It commits the five
//! fields the project plan requires of a checkpoint — chain id, epoch, previous
//! root, new root, and the transaction commitment — and two more that are the
//! point of the exercise: how many epochs and how many microchain actions this
//! one L1 transaction is settling.
//!
//! Putting the compression figure *inside* the commitment means the ratio is
//! attested rather than asserted. Anyone reading the chain can add up what was
//! anchored and get the same number the operator publishes, without being asked
//! to take a dashboard's word for it.
//!
//! ## What Zcash can hold
//!
//! An anchor is 148 bytes. A transparent `OP_RETURN` holds 80. So the
//! transaction carries a single 32-byte [`AnchorId`] — a domain-separated hash
//! of the whole anchor — and the anchor itself is published alongside, where it
//! is self-verifying: recompute the id and it either matches what is on chain
//! or it does not. The chain holds the commitment; the network holds the data.
//!
//! ## Chaining
//!
//! The one job that must not be got wrong is chaining. Each anchor names the
//! root the previous one committed, and a [`Ledger`] refuses anything that does
//! not continue from what it already holds. Getting this wrong does not produce
//! a wrong balance — it produces a permanently stuck chain, because every
//! subsequent anchor is refused against a base that no longer matches.

use alloc::vec::Vec;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use zyn_vm::commit::{Encoder, Hash};
use zyn_vm::read::Decoder;
use zyn_vm::Checkpoint;

/// A 32-byte commitment to one anchor. This is what goes on Zcash.
pub type AnchorId = [u8; 32];

/// Identifies an anchor payload, so a hash of something else can never be read
/// as one.
const ANCHOR_DOMAIN: &[u8] = b"zyn.anchor.v1";

/// Marks a memo as a Zyn anchor, so an indexer can find them without decoding
/// every transaction on the network — and so a deposit memo (`ZYN…`) and an
/// anchor memo can never be read as each other: they differ in the first
/// three bytes, not in what happens to follow. `zyn_custody::memo::ANCHOR_TAG`
/// carries the same value; `zynzapd` tests that they agree.
pub const MEMO_MAGIC: &[u8; 3] = b"ZYA";
pub const MEMO_VERSION: u8 = 1;
/// magic + version + chain id + epoch + anchor id.
pub const MEMO_LEN: usize = 3 + 1 + 4 + 8 + 32;

/// One Zcash transaction's worth of microchain history.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Anchor {
    /// The sealed epoch this anchor commits.
    pub checkpoint: Checkpoint,
    /// State root the previous anchor committed. `[0; 32]` for the first.
    ///
    /// Distinct from `checkpoint.parent_root`, which links *epochs*. Epochs
    /// seal far more often than anchors, so this skips over the ones that were
    /// never carried to Zcash and links what the L1 actually saw.
    pub previous_root: Hash,
    /// Sealed epochs covered since the previous anchor.
    pub epochs: u64,
    /// Microchain actions covered since the previous anchor.
    ///
    /// The compression, attested. One Zcash transaction stands for this many
    /// user actions.
    pub actions: u64,
}

impl Anchor {
    /// Canonical bytes. Fixed width, big-endian, no optional fields — the same
    /// discipline as the VM's state encoding, for the same reason.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.bytes(ANCHOR_DOMAIN)
            .u32(self.checkpoint.chain_id)
            .u64(self.checkpoint.epoch)
            .bytes(&self.checkpoint.parent_root)
            .bytes(&self.checkpoint.state_root)
            .bytes(&self.checkpoint.intent_root)
            .u64(self.checkpoint.seq)
            .u64(self.checkpoint.intents)
            .fixed(self.checkpoint.gross_volume)
            .bytes(&self.previous_root)
            .u64(self.epochs)
            .u64(self.actions);
        e.finish().to_vec()
    }

    /// The exact inverse of [`Anchor::encode`]: refuses a wrong domain, a
    /// short payload and trailing bytes, so a replica cannot be handed an
    /// anchor that hashes to something other than what it decodes to.
    pub fn decode(b: &[u8]) -> Option<Anchor> {
        let mut d = Decoder::new(b);
        if d.take_bytes(ANCHOR_DOMAIN.len()).ok()? != ANCHOR_DOMAIN {
            return None;
        }
        let checkpoint = Checkpoint {
            chain_id: d.u32().ok()?,
            epoch: d.u64().ok()?,
            parent_root: d.hash().ok()?,
            state_root: d.hash().ok()?,
            intent_root: d.hash().ok()?,
            seq: d.u64().ok()?,
            intents: d.u64().ok()?,
            gross_volume: d.fixed().ok()?,
        };
        let previous_root = d.hash().ok()?;
        let epochs = d.u64().ok()?;
        let actions = d.u64().ok()?;
        if d.remaining() != 0 {
            return None;
        }
        Some(Anchor {
            checkpoint,
            previous_root,
            epochs,
            actions,
        })
    }

    /// The commitment that goes on Zcash.
    pub fn id(&self) -> AnchorId {
        let mut h = Sha256::new();
        h.update(self.encode());
        h.finalize().into()
    }

    /// The bytes for the Zcash transaction's `OP_RETURN`.
    ///
    /// Carries the chain id and epoch in the clear so an indexer can order and
    /// attribute anchors without fetching the payload, and the id so the
    /// payload can be checked once fetched.
    pub fn memo(&self) -> [u8; MEMO_LEN] {
        let mut out = [0u8; MEMO_LEN];
        out[..3].copy_from_slice(MEMO_MAGIC);
        out[3] = MEMO_VERSION;
        out[4..8].copy_from_slice(&self.checkpoint.chain_id.to_be_bytes());
        out[8..16].copy_from_slice(&self.checkpoint.epoch.to_be_bytes());
        out[16..].copy_from_slice(&self.id());
        out
    }

    /// Read a memo back, returning `(chain_id, epoch, anchor_id)`.
    pub fn parse_memo(bytes: &[u8]) -> Option<(u32, u64, AnchorId)> {
        if bytes.len() != MEMO_LEN || &bytes[..3] != MEMO_MAGIC || bytes[3] != MEMO_VERSION {
            return None;
        }
        let chain_id = u32::from_be_bytes(bytes[4..8].try_into().ok()?);
        let epoch = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
        let id: AnchorId = bytes[16..].try_into().ok()?;
        Some((chain_id, epoch, id))
    }

    /// Actions per Zcash transaction for this anchor alone.
    pub fn ratio(&self) -> u64 {
        self.actions
    }
}

/// Why an anchor could not be accepted into a lineage.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineageError {
    /// An anchor for a different microchain.
    WrongChain,
    /// Does not continue from the root the ledger holds. The stuck-chain case:
    /// worth surfacing loudly rather than retrying.
    StaleBase,
    /// Epoch did not advance, or went backwards.
    EpochNotAdvancing,
    /// Sequence did not advance, so the anchor covers no new history.
    SequenceNotAdvancing,
    /// The anchor claims epochs or actions that its own sequence range cannot
    /// account for.
    ImpossibleCoverage,
    /// A different state root has already been anchored at this epoch. Two
    /// histories claiming the same height is the fork case, and it is the one
    /// thing settlement must never quietly accept.
    Fork,
    /// The certificate does not carry enough distinct authorised signers.
    InsufficientSignatures,
    /// A stored certificate is for a different anchor than the one beside it.
    CertificateMismatch,
}

/// The settlement signers and the threshold they must reach.
///
/// V1 custody is a threshold vault — the plan's 7-of-10 — so an anchor is only
/// settleable when enough independent signers have endorsed it.
///
/// Signers are **ed25519 public keys**, and endorsements are verified against
/// them. Independent signatures rather than an aggregate scheme, because an
/// anchor certificate never leaves Zyn: aggregation buys a smaller on-chain
/// footprint, and there is no chain here to be small on. A threshold scheme is
/// needed for the *Zcash* side — one signature has to come out of the vault key
/// — and that is a different problem, solved with a different tool, outside
/// this crate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignerSet {
    /// Signer identities, in canonical order. Duplicates are refused at
    /// construction so the threshold cannot be met by one signer twice.
    signers: Vec<[u8; 32]>,
    threshold: usize,
}

impl SignerSet {
    pub fn new(mut signers: Vec<[u8; 32]>, threshold: usize) -> Result<Self, &'static str> {
        signers.sort_unstable();
        let before = signers.len();
        signers.dedup();
        if signers.len() != before {
            return Err("signer set contains duplicates");
        }
        if threshold == 0 {
            return Err("threshold must require at least one signer");
        }
        if threshold > signers.len() {
            return Err("threshold exceeds the number of signers");
        }
        // A bare majority is the weakest arrangement worth calling a threshold:
        // below it, two disjoint quorums could endorse conflicting anchors and
        // both would verify.
        if threshold * 2 <= signers.len() {
            return Err("threshold must exceed half the signer set");
        }
        Ok(SignerSet { signers, threshold })
    }

    /// The plan's candidate: 7 of 10.
    pub fn threshold_of(signers: Vec<[u8; 32]>, threshold: usize) -> Result<Self, &'static str> {
        SignerSet::new(signers, threshold)
    }

    pub fn len(&self) -> usize {
        self.signers.len()
    }
    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
    }
    pub fn threshold(&self) -> usize {
        self.threshold
    }
    pub fn contains(&self, signer: &[u8; 32]) -> bool {
        self.signers.binary_search(signer).is_ok()
    }
}

/// Signatures gathered over one anchor id.
///
/// Enforces both halves. The cryptographic half: every endorsement is a valid
/// ed25519 signature over this anchor's id, under a key in the set. And the
/// half that is easy to get wrong and has nothing to do with cryptography: the
/// endorsements are over *this* anchor, every signer is in the set, and no
/// signer is counted twice.
///
/// Both matter. Checking signatures without checking distinctness lets one
/// signer meet a 7-of-10 threshold seven times; checking distinctness without
/// checking signatures — which is what this did before — lets anyone assemble a
/// certificate out of public key material and nothing else.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Certificate {
    pub anchor: AnchorId,
    /// `(signer, signature)`, in signer order.
    pub signatures: Vec<([u8; 32], [u8; 64])>,
}

impl Certificate {
    pub fn new(anchor: AnchorId) -> Self {
        Certificate {
            anchor,
            signatures: Vec::new(),
        }
    }

    /// Canonical bytes: `anchor ‖ n ‖ (signer ‖ signature)*`, signers in order.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.bytes(&self.anchor).u32(self.signatures.len() as u32);
        for (s, sig) in &self.signatures {
            e.bytes(s).bytes(sig);
        }
        e.finish().to_vec()
    }

    /// Inverse of [`Certificate::encode`]. Goes through [`Certificate::add`], so
    /// a duplicated signer on disk is refused exactly as it would be live.
    pub fn decode(b: &[u8]) -> Option<Certificate> {
        let mut d = Decoder::new(b);
        let anchor = d.hash().ok()?;
        let n = d.u32().ok()? as usize;
        if n > 1024 {
            return None;
        }
        let mut c = Certificate::new(anchor);
        for _ in 0..n {
            let s = d.array::<32>().ok()?;
            let sig = d.array::<64>().ok()?;
            c.add(s, sig).ok()?;
        }
        if d.remaining() != 0 {
            return None;
        }
        Some(c)
    }

    /// Add an endorsement. Refuses a second one from the same signer, which is
    /// the only way a threshold can be met without the independence it is meant
    /// to represent.
    pub fn add(&mut self, signer: [u8; 32], signature: [u8; 64]) -> Result<(), &'static str> {
        if self.signatures.iter().any(|(s, _)| *s == signer) {
            return Err("signer already endorsed this anchor");
        }
        self.signatures.push((signer, signature));
        self.signatures.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(())
    }

    /// Whether one endorsement is a valid signature over `anchor` by `signer`.
    fn endorses(signer: &[u8; 32], signature: &[u8; 64], anchor: AnchorId) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(signer) else {
            return false;
        };
        key.verify_strict(&anchor, &Signature::from_bytes(signature))
            .is_ok()
    }

    /// Distinct authorised signers whose signatures actually verify.
    ///
    /// Both conditions, counted together. A key in the set with a bad signature
    /// contributes nothing, and so does a valid signature from a key outside
    /// it.
    pub fn weight(&self, set: &SignerSet) -> usize {
        self.signatures
            .iter()
            .filter(|(s, sig)| set.contains(s) && Self::endorses(s, sig, self.anchor))
            .count()
    }

    /// Whether the certificate is over `anchor` and clears the threshold.
    pub fn verify(&self, anchor: &Anchor, set: &SignerSet) -> Result<(), LineageError> {
        if self.anchor != anchor.id() {
            // A certificate over a different anchor is not a weak certificate,
            // it is an unrelated one.
            return Err(LineageError::Fork);
        }
        if self.weight(set) < set.threshold() {
            return Err(LineageError::InsufficientSignatures);
        }
        Ok(())
    }
}

/// The anchors that have reached Zcash, and the rules for what may join them.
///
/// The authority on what an anchor must chain from. A submitter caches its own
/// last anchor, but a cache and the chain diverge the moment a transaction
/// fails, lands out of order, or is submitted by another process — so the
/// ledger, not the cache, decides.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ledger {
    chain_id: u32,
    anchors: Vec<Anchor>,
    /// The certificate each anchor settled under, parallel to `anchors`. Empty
    /// (no signatures) for a trusted-operator acceptance, so what is on disk
    /// says which posture the chain ran in.
    certificates: Vec<Certificate>,
}

impl Ledger {
    pub fn new(chain_id: u32) -> Self {
        Ledger {
            chain_id,
            anchors: Vec::new(),
            certificates: Vec::new(),
        }
    }

    /// Rebuild a ledger from what was persisted, re-running the lineage rules
    /// on every entry. Signatures are **not** re-verified here — the signer
    /// set may not be configured at load — which is why the certificates are
    /// kept: they can be checked later against whatever set is supplied.
    pub fn restore(
        chain_id: u32,
        entries: Vec<(Anchor, Certificate)>,
    ) -> Result<Ledger, LineageError> {
        let mut l = Ledger::new(chain_id);
        for (a, c) in entries {
            if c.anchor != a.id() {
                return Err(LineageError::CertificateMismatch);
            }
            l.check(&a)?;
            l.anchors.push(a);
            l.certificates.push(c);
        }
        Ok(l)
    }

    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }
    pub fn len(&self) -> usize {
        self.anchors.len()
    }
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
    pub fn anchors(&self) -> &[Anchor] {
        &self.anchors
    }
    pub fn last(&self) -> Option<&Anchor> {
        self.anchors.last()
    }

    /// The root a new anchor must continue from.
    pub fn head_root(&self) -> Hash {
        self.anchors
            .last()
            .map(|a| a.checkpoint.state_root)
            .unwrap_or([0u8; 32])
    }

    /// Check an anchor against the lineage without accepting it.
    pub fn check(&self, a: &Anchor) -> Result<(), LineageError> {
        if a.checkpoint.chain_id != self.chain_id {
            return Err(LineageError::WrongChain);
        }
        if a.previous_root != self.head_root() {
            return Err(LineageError::StaleBase);
        }
        if let Some(prev) = self.anchors.last() {
            if a.checkpoint.epoch <= prev.checkpoint.epoch {
                // Same epoch with a different root is the fork case; the same
                // root again is merely a replay. Both are refused, and the
                // distinction is worth reporting accurately.
                return Err(if a.checkpoint.state_root != prev.checkpoint.state_root {
                    LineageError::Fork
                } else {
                    LineageError::EpochNotAdvancing
                });
            }
            if a.checkpoint.seq <= prev.checkpoint.seq {
                return Err(LineageError::SequenceNotAdvancing);
            }
            // An anchor cannot cover more epochs than it advanced, nor more
            // actions than its sequence range contains. Both are claims about
            // compression, so both have to be checkable rather than trusted.
            let epochs_advanced = a.checkpoint.epoch - prev.checkpoint.epoch;
            let seqs_advanced = a.checkpoint.seq - prev.checkpoint.seq;
            if a.epochs > epochs_advanced || a.actions > seqs_advanced {
                return Err(LineageError::ImpossibleCoverage);
            }
        } else {
            if a.epochs == 0 {
                return Err(LineageError::EpochNotAdvancing);
            }
            if a.actions > a.checkpoint.seq {
                return Err(LineageError::ImpossibleCoverage);
            }
        }
        if a.epochs == 0 || a.actions == 0 {
            return Err(LineageError::ImpossibleCoverage);
        }
        Ok(())
    }

    /// Accept an anchor, given a certificate that clears the threshold.
    pub fn accept(
        &mut self,
        a: Anchor,
        cert: &Certificate,
        set: &SignerSet,
    ) -> Result<(), LineageError> {
        self.check(&a)?;
        cert.verify(&a, set)?;
        self.anchors.push(a);
        self.certificates.push(cert.clone());
        Ok(())
    }

    /// Accept without a certificate, for a V0 trusted-operator deployment.
    ///
    /// Named so it cannot be reached by accident: the plan allows a trusted
    /// operator to move quickly, but the trust assumption should be visible at
    /// every call site rather than hidden behind an `Option`.
    ///
    /// **Not for a deployment holding real value.** A node configured with a
    /// signer set uses [`Ledger::accept`]; this exists for local runs and tests
    /// where there is no signer set to configure.
    pub fn accept_trusted_operator(&mut self, a: Anchor) -> Result<(), LineageError> {
        self.check(&a)?;
        self.certificates.push(Certificate::new(a.id()));
        self.anchors.push(a);
        Ok(())
    }

    /// Totals across everything anchored — the attested compression.
    pub fn totals(&self) -> (u64, u64, u64) {
        let mut epochs = 0u64;
        let mut actions = 0u64;
        for a in &self.anchors {
            epochs = epochs.saturating_add(a.epochs);
            actions = actions.saturating_add(a.actions);
        }
        (actions, epochs, self.anchors.len() as u64)
    }

    /// Walk the whole lineage from genesis, re-checking every link.
    ///
    /// What an auditor runs: it trusts nothing the ledger did on the way in,
    /// and rebuilds the same conclusion from the anchors alone.
    pub fn verify_lineage(&self) -> Result<(), LineageError> {
        let mut replay = Ledger::new(self.chain_id);
        for a in &self.anchors {
            replay.check(a)?;
            replay.anchors.push(*a);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn cp(epoch: u64, seq: u64, parent: u8, state: u8) -> Checkpoint {
        Checkpoint {
            chain_id: 1,
            epoch,
            parent_root: [parent; 32],
            state_root: [state; 32],
            intent_root: [(epoch as u8).wrapping_add(70); 32],
            seq,
            intents: 100,
            gross_volume: zyn_vm::Fixed::whole(42),
        }
    }

    fn anchor(epoch: u64, seq: u64, prev: u8, state: u8, actions: u64) -> Anchor {
        Anchor {
            checkpoint: cp(epoch, seq, prev, state),
            previous_root: if prev == 0 { [0u8; 32] } else { [prev; 32] },
            epochs: 7,
            actions,
        }
    }

    /// Deterministic test keys. Real deployments generate these in a ceremony;
    /// here they only have to be distinct and reproducible.
    fn key(i: u8) -> SigningKey {
        SigningKey::from_bytes(&[i; 32])
    }

    fn signers(n: u8) -> Vec<[u8; 32]> {
        (1..=n).map(|i| key(i).verifying_key().to_bytes()).collect()
    }

    /// A certificate with `n` genuine signatures over the anchor.
    fn certify(a: &Anchor, _set: &SignerSet, n: u8) -> Certificate {
        let mut c = Certificate::new(a.id());
        for i in 1..=n {
            let k = key(i);
            c.add(k.verifying_key().to_bytes(), k.sign(&a.id()).to_bytes())
                .unwrap();
        }
        c
    }

    // --- the commitment itself ---

    #[test]
    fn the_id_commits_to_every_field() {
        let base = anchor(7, 700, 0, 9, 1_750);
        let id = base.id();

        let mut a = base;
        a.actions += 1;
        assert_ne!(a.id(), id, "the compression figure must be committed");

        let mut a = base;
        a.epochs += 1;
        assert_ne!(a.id(), id, "epoch coverage must be committed");

        let mut a = base;
        a.previous_root = [3u8; 32];
        assert_ne!(a.id(), id, "the anchor lineage must be committed");

        let mut a = base;
        a.checkpoint.state_root = [3u8; 32];
        assert_ne!(a.id(), id);

        let mut a = base;
        a.checkpoint.intent_root = [3u8; 32];
        assert_ne!(a.id(), id, "the transaction commitment must be committed");

        let mut a = base;
        a.checkpoint.chain_id += 1;
        assert_ne!(
            a.id(),
            id,
            "an anchor must not be replayable on another chain"
        );
    }

    #[test]
    fn the_memo_fits_an_op_return_and_round_trips() {
        let a = anchor(7, 700, 0, 9, 1_750);
        let memo = a.memo();
        assert!(memo.len() <= 80, "memo does not fit in an OP_RETURN");
        assert_eq!(Anchor::parse_memo(&memo), Some((1, 7, a.id())));
    }

    #[test]
    fn a_foreign_memo_is_not_mistaken_for_an_anchor() {
        assert_eq!(Anchor::parse_memo(&[]), None);
        assert_eq!(Anchor::parse_memo(&[0u8; MEMO_LEN]), None);
        let mut m = anchor(1, 10, 0, 9, 10).memo();
        m[3] = 99; // wrong version
        assert_eq!(Anchor::parse_memo(&m), None);
        let a = anchor(1, 10, 0, 9, 10);
        assert_eq!(Anchor::parse_memo(&a.memo()[..MEMO_LEN - 1]), None);
    }

    // --- lineage ---

    #[test]
    fn anchors_chain_through_the_roots_zcash_actually_saw() {
        let mut l = Ledger::new(1);
        assert_eq!(l.head_root(), [0u8; 32]);
        l.accept_trusted_operator(anchor(7, 700, 0, 9, 700))
            .unwrap();
        assert_eq!(l.head_root(), [9u8; 32]);
        l.accept_trusted_operator(anchor(14, 1_400, 9, 11, 700))
            .unwrap();
        assert_eq!(l.len(), 2);
        l.verify_lineage()
            .expect("a ledger it built itself must re-verify");
    }

    #[test]
    fn an_anchor_that_does_not_continue_the_chain_is_refused() {
        let mut l = Ledger::new(1);
        l.accept_trusted_operator(anchor(7, 700, 0, 9, 700))
            .unwrap();
        // Continues from a root Zcash never saw.
        assert_eq!(
            l.accept_trusted_operator(anchor(14, 1_400, 5, 11, 700)),
            Err(LineageError::StaleBase)
        );
        assert_eq!(l.len(), 1, "a refused anchor was recorded anyway");
    }

    #[test]
    fn a_second_history_at_the_same_height_is_a_fork() {
        let mut l = Ledger::new(1);
        l.accept_trusted_operator(anchor(7, 700, 0, 9, 700))
            .unwrap();
        let mut sneaky = anchor(7, 900, 9, 12, 200);
        sneaky.previous_root = [9u8; 32];
        assert_eq!(l.accept_trusted_operator(sneaky), Err(LineageError::Fork));
    }

    #[test]
    fn replaying_the_same_anchor_is_refused_as_a_replay_not_a_fork() {
        let mut l = Ledger::new(1);
        let a = anchor(7, 700, 0, 9, 700);
        l.accept_trusted_operator(a).unwrap();
        let mut again = a;
        again.previous_root = [9u8; 32];
        assert_eq!(
            l.accept_trusted_operator(again),
            Err(LineageError::EpochNotAdvancing)
        );
    }

    #[test]
    fn an_anchor_from_another_microchain_is_refused() {
        let mut l = Ledger::new(2);
        assert_eq!(
            l.accept_trusted_operator(anchor(7, 700, 0, 9, 700)),
            Err(LineageError::WrongChain)
        );
    }

    /// The compression figure is a claim, so it has to be checkable. An anchor
    /// cannot cover more actions than its own sequence range contains.
    #[test]
    fn an_overstated_compression_claim_is_refused() {
        let mut l = Ledger::new(1);
        l.accept_trusted_operator(anchor(7, 700, 0, 9, 700))
            .unwrap();

        // Claims 5,000 actions across a 700-sequence advance.
        let mut inflated = anchor(14, 1_400, 9, 11, 5_000);
        inflated.previous_root = [9u8; 32];
        assert_eq!(
            l.accept_trusted_operator(inflated),
            Err(LineageError::ImpossibleCoverage)
        );

        // Claims more epochs than it advanced.
        let mut wide = anchor(8, 1_400, 9, 11, 700);
        wide.previous_root = [9u8; 32];
        wide.epochs = 50;
        assert_eq!(
            l.accept_trusted_operator(wide),
            Err(LineageError::ImpossibleCoverage)
        );

        // Claims nothing at all — an anchor that settles no history is a Zcash
        // fee spent on air.
        let mut empty = anchor(14, 1_400, 9, 11, 0);
        empty.previous_root = [9u8; 32];
        assert_eq!(
            l.accept_trusted_operator(empty),
            Err(LineageError::ImpossibleCoverage)
        );
    }

    #[test]
    fn a_sequence_that_does_not_advance_covers_no_history() {
        let mut l = Ledger::new(1);
        l.accept_trusted_operator(anchor(7, 700, 0, 9, 700))
            .unwrap();
        let mut stuck = anchor(14, 700, 9, 11, 1);
        stuck.previous_root = [9u8; 32];
        assert_eq!(
            l.accept_trusted_operator(stuck),
            Err(LineageError::SequenceNotAdvancing)
        );
    }

    #[test]
    fn the_first_anchor_cannot_claim_more_than_the_chain_has_run() {
        let mut l = Ledger::new(1);
        let mut a = anchor(7, 100, 0, 9, 500);
        a.previous_root = [0u8; 32];
        assert_eq!(
            l.accept_trusted_operator(a),
            Err(LineageError::ImpossibleCoverage)
        );
    }

    #[test]
    fn totals_are_the_attested_compression() {
        let mut l = Ledger::new(1);
        l.accept_trusted_operator(anchor(7, 700, 0, 9, 700))
            .unwrap();
        let mut b = anchor(14, 1_400, 9, 11, 700);
        b.previous_root = [9u8; 32];
        l.accept_trusted_operator(b).unwrap();
        let (actions, epochs, anchors) = l.totals();
        assert_eq!((actions, epochs, anchors), (1_400, 14, 2));
        // 700 user actions per Zcash transaction, readable off the chain.
        assert_eq!(actions / anchors, 700);
    }

    // --- threshold custody ---

    #[test]
    fn a_signer_set_must_be_a_real_majority() {
        assert!(SignerSet::new(signers(10), 7).is_ok());
        assert!(
            SignerSet::new(signers(10), 0).is_err(),
            "zero threshold accepted"
        );
        assert!(
            SignerSet::new(signers(10), 11).is_err(),
            "threshold above the set accepted"
        );
        // 5 of 10 lets two disjoint quorums endorse conflicting anchors.
        assert!(
            SignerSet::new(signers(10), 5).is_err(),
            "a non-majority threshold accepted"
        );
        assert!(SignerSet::new(signers(10), 6).is_ok());
        // Duplicates would let one signer count twice toward the threshold.
        let mut dupes = signers(9);
        dupes.push(key(1).verifying_key().to_bytes());
        assert!(
            SignerSet::new(dupes, 7).is_err(),
            "a duplicated signer was accepted"
        );
    }

    #[test]
    fn an_anchor_needs_the_threshold_to_settle() {
        let set = SignerSet::new(signers(10), 7).unwrap();
        let mut l = Ledger::new(1);
        let a = anchor(7, 700, 0, 9, 700);

        let short = certify(&a, &set, 6);
        assert_eq!(
            l.accept(a, &short, &set),
            Err(LineageError::InsufficientSignatures),
            "six of ten settled"
        );
        assert!(l.is_empty());

        let enough = certify(&a, &set, 7);
        l.accept(a, &enough, &set)
            .expect("seven of ten must settle");
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn one_signer_cannot_reach_the_threshold_alone() {
        let set = SignerSet::new(signers(10), 7).unwrap();
        let a = anchor(7, 700, 0, 9, 700);
        let mut c = Certificate::new(a.id());
        let k = key(1);
        c.add(k.verifying_key().to_bytes(), k.sign(&a.id()).to_bytes())
            .unwrap();
        assert!(
            c.add(k.verifying_key().to_bytes(), k.sign(&a.id()).to_bytes())
                .is_err(),
            "a signer endorsed twice"
        );
        assert_eq!(c.weight(&set), 1);
    }

    #[test]
    fn signers_outside_the_set_do_not_count() {
        let set = SignerSet::new(signers(10), 7).unwrap();
        let a = anchor(7, 700, 0, 9, 700);
        let mut c = Certificate::new(a.id());
        for i in 1..=6u8 {
            let k = key(i);
            c.add(k.verifying_key().to_bytes(), k.sign(&a.id()).to_bytes())
                .unwrap();
        }
        // Four outsiders sign honestly; they pad the count but not the weight.
        for i in 100..=103u8 {
            let k = key(i);
            c.add(k.verifying_key().to_bytes(), k.sign(&a.id()).to_bytes())
                .unwrap();
        }
        assert_eq!(c.signatures.len(), 10);
        assert_eq!(c.weight(&set), 6);
        assert_eq!(
            c.verify(&a, &set),
            Err(LineageError::InsufficientSignatures)
        );
    }

    /// The hole this closed: a certificate used to be a list of signer ids with
    /// no signature checked, so anyone holding public key material could
    /// assemble one out of nothing.
    #[test]
    fn a_forged_certificate_carries_no_weight() {
        let set = SignerSet::new(signers(10), 7).unwrap();
        let a = anchor(7, 700, 0, 9, 700);

        // Every authorised signer named, every signature garbage.
        let mut forged = Certificate::new(a.id());
        for i in 1..=10u8 {
            forged
                .add(key(i).verifying_key().to_bytes(), [0xAA; 64])
                .unwrap();
        }
        assert_eq!(forged.signatures.len(), 10);
        assert_eq!(
            forged.weight(&set),
            0,
            "unverified signatures counted toward a threshold"
        );
        assert_eq!(
            forged.verify(&a, &set),
            Err(LineageError::InsufficientSignatures)
        );

        let mut l = Ledger::new(1);
        assert_eq!(
            l.accept(a, &forged, &set),
            Err(LineageError::InsufficientSignatures)
        );
        assert!(l.is_empty());
    }

    /// A signature over a *different* anchor does not count either — the id is
    /// what is signed, so a valid endorsement of one anchor is not an
    /// endorsement of another.
    #[test]
    fn a_signature_for_one_anchor_does_not_endorse_a_second() {
        let set = SignerSet::new(signers(10), 7).unwrap();
        let a = anchor(7, 700, 0, 9, 700);
        let b = anchor(7, 700, 0, 12, 700);

        let mut lifted = Certificate::new(b.id());
        for i in 1..=10u8 {
            // Signed over `a`, presented for `b`.
            lifted
                .add(
                    key(i).verifying_key().to_bytes(),
                    key(i).sign(&a.id()).to_bytes(),
                )
                .unwrap();
        }
        assert_eq!(lifted.weight(&set), 0, "a lifted signature counted");
        assert_eq!(
            lifted.verify(&b, &set),
            Err(LineageError::InsufficientSignatures)
        );
    }

    /// One tampered byte is enough.
    #[test]
    fn a_mangled_signature_is_not_a_signature() {
        let set = SignerSet::new(signers(10), 7).unwrap();
        let a = anchor(7, 700, 0, 9, 700);
        let mut c = certify(&a, &set, 7);
        assert_eq!(c.weight(&set), 7);
        c.signatures[3].1[0] ^= 0x01;
        assert_eq!(c.weight(&set), 6, "a mangled signature still counted");
        assert_eq!(
            c.verify(&a, &set),
            Err(LineageError::InsufficientSignatures)
        );
    }

    #[test]
    fn a_certificate_cannot_be_moved_to_another_anchor() {
        let set = SignerSet::new(signers(10), 7).unwrap();
        let a = anchor(7, 700, 0, 9, 700);
        let b = anchor(7, 700, 0, 12, 700);
        let cert = certify(&a, &set, 7);
        assert_eq!(
            cert.verify(&b, &set),
            Err(LineageError::Fork),
            "certificate was portable"
        );
    }

    /// Lineage is checked before signatures: a fully-signed anchor that does not
    /// continue the chain is still refused, because a threshold of signers is
    /// not authority to rewrite history.
    #[test]
    fn a_signed_anchor_still_has_to_chain() {
        let set = SignerSet::new(signers(10), 7).unwrap();
        let mut l = Ledger::new(1);
        let a = anchor(7, 700, 0, 9, 700);
        l.accept(a, &certify(&a, &set, 10), &set).unwrap();

        let bad = anchor(14, 1_400, 5, 11, 700);
        assert_eq!(
            l.accept(bad, &certify(&bad, &set, 10), &set),
            Err(LineageError::StaleBase)
        );
    }

    // --- Task 1: codecs and ledger restore ---

    #[test]
    fn an_anchor_round_trips_through_its_bytes() {
        let a = anchor(3, 300, 1, 2, 50);
        assert_eq!(Anchor::decode(&a.encode()), Some(a));
        let enc = a.encode();
        assert_eq!(Anchor::decode(&enc[..enc.len() - 1]), None, "truncated");
        let mut junk = a.encode();
        junk[0] ^= 1;
        assert_eq!(Anchor::decode(&junk), None, "wrong domain");
        let mut long = a.encode();
        long.push(0);
        assert_eq!(Anchor::decode(&long), None, "trailing bytes");
    }

    #[test]
    fn a_certificate_round_trips_and_keeps_signer_order() {
        let a = anchor(1, 100, 0, 1, 10);
        let set = SignerSet::new(signers(3), 2).unwrap();
        let c = certify(&a, &set, 2);
        assert_eq!(Certificate::decode(&c.encode()), Some(c.clone()));
        assert!(Certificate::decode(&c.encode()[..40]).is_none());
        let empty = Certificate::new(a.id());
        assert_eq!(Certificate::decode(&empty.encode()), Some(empty));
    }

    #[test]
    fn a_ledger_restores_from_its_entries_and_refuses_a_broken_lineage() {
        let mut l = Ledger::new(1);
        let a1 = anchor(7, 700, 0, 9, 700);
        let a2 = anchor(14, 1_400, 9, 11, 700);
        l.accept_trusted_operator(a1).unwrap();
        l.accept_trusted_operator(a2).unwrap();
        assert_eq!(l.certificates().len(), 2);
        let entries: Vec<(Anchor, Certificate)> = l
            .anchors()
            .iter()
            .cloned()
            .zip(l.certificates().iter().cloned())
            .collect();
        let r = Ledger::restore(1, entries.clone()).unwrap();
        assert_eq!(r.head_root(), l.head_root());
        assert_eq!(r.len(), 2);
        let mut broken = entries.clone();
        broken.swap(0, 1);
        assert!(Ledger::restore(1, broken).is_err());
        let mut mismatched = entries;
        mismatched[1].1 = Certificate::new([9u8; 32]);
        assert_eq!(
            Ledger::restore(1, mismatched).unwrap_err(),
            LineageError::CertificateMismatch
        );
    }
}
