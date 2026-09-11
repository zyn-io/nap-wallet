//! The microchain VM specification.
//!
//! A Zyn microchain is a deterministic state machine that the network can
//! sequence, anchor to Zcash, prove balances out of, and recover after a crash
//! — without knowing what the machine is *for*. This trait is the boundary
//! between those two concerns. ZynZap is the first implementation; an auction,
//! a prediction market or a game would be others, and none of them should
//! require the infrastructure to change.
//!
//! # The contract
//!
//! **S1 — Determinism.** `apply` must be a pure function of `(state, seq,
//! intent)`. No I/O, no clock, no randomness, no threads, no floating point, no
//! iteration over an unordered map. Two nodes given the same intents in the
//! same order must reach byte-identical roots, forever, on any machine.
//!
//! **S2 — A contiguous sequence space.** An intent is applied only at
//! `state.seq() + 1`. Anything else is refused and changes nothing at all —
//! not the sequence, not the intent commitment. An intent that was never in the
//! history must not appear in the epoch's commitment either.
//!
//! **S3 — Rejections are events.** An intent that breaks a rule produces a
//! rejection receipt and leaves the application state untouched, but still
//! consumes its sequence number and still folds into the intent commitment.
//! Replaying the history must reproduce the rejection.
//!
//! **S4 — Outcomes are emitted, never accepted.** Prices, fills, allocations —
//! whatever the application computes, it computes. A VM that accepted an
//! outcome as input would make a proof over it attest that bookkeeping was
//! applied faithfully while saying nothing about whether the outcome was
//! honest, which is the whole property a proof exists to establish.
//!
//! **S5 — Total commitment.** Every field that can affect a future transition
//! must be committed by [`MicrochainVm::sections`]. A field outside the root is
//! a field two nodes can disagree about without either noticing.
//!
//! **S6 — Section layout.** The state root is a Merkle root over an ordered
//! list of section commitments. Section 0 is the header. Section 1 is the
//! accounts section, whose leaves are the holder records the exit hatch opens.
//! Later sections are application-defined. This is what lets one settlement
//! verifier serve every VM.
//!
//! **S7 — Sealing.** [`MicrochainVm::seal_intent`] is an ordinary intent: it
//! takes a sequence number and folds into the commitment it closes. The
//! checkpoint it produces commits the root **as of the seal**, before any epoch
//! advance, and [`MicrochainVm::as_sealed`] must be able to recover that view
//! for as long as the accounts section has not moved.
//!
//! **S8 — Carriable state.** `encode`/`decode` must round-trip to the same
//! state root. A node that restarted must be indistinguishable from one that
//! did not.
//!
//! **S9 — Checked arithmetic.** Every operation is checked. A VM that wraps on
//! overflow is a VM that mints value. Arithmetic that cannot be completed is
//! reported through [`MicrochainVm::unprovable`], because a half-applied intent
//! is an unprovable execution rather than a rejected one, and the batch
//! containing it must be discarded whole.
//!
//! **S10 — No panics on input.** A VM must never abort on bytes it did not
//! choose. Decoding returns a value; malformed input is refused, not fatal.
//!
//! **S11 — Conservation.** A VM MUST declare what it conserves and be able to
//! check it. [`crate::zvm::transition`] runs that check after every batch and
//! discards the batch if it fails, so a state that has created or destroyed
//! value outside its own rules can never reach a committed root.
//!
//! This is the one rule borrowed from a VM Zyn is not: Move enforces asset
//! conservation with linear types, so "forgot to decrement the balance" is a
//! type error rather than an audit finding. Zyn cannot have linear types
//! without a new language — but it can move the same guarantee from the type
//! system into the specification, checked per batch instead of per expression.
//! Coarser than Move, and unlike an audit it is not optional.
//!
//! [`crate::conformance`] checks S2, S3, S5, S6, S7 and S8 mechanically against
//! any implementation. S1, S4, S9 and S10 are design obligations that a test
//! suite can support but not establish.

use alloc::vec::Vec;

use crate::checkpoint::Checkpoint;
use crate::commit::{merkle_root, merkle_proof, Hash, ProofStep};

/// A holder identity. Fixed at 32 bytes across every Zyn VM so one exit path,
/// one proof format and one settlement verifier serve all of them.
///
/// In ZynZap this is derived from a shielded spending key, so the execution
/// layer never learns the Zcash address behind it. Another application may
/// derive it differently; the infrastructure only ever compares and commits it.
pub type AccountId = [u8; 32];

/// Index of the header section in [`MicrochainVm::sections`].
pub const SECTION_HEADER: usize = 0;
/// Index of the accounts section. The exit hatch opens this one.
pub const SECTION_ACCOUNTS: usize = 1;
/// The minimum number of sections: a header and the accounts it heads.
pub const MIN_SECTIONS: usize = 2;

/// A deterministic state machine the Zyn microchain can run.
pub trait MicrochainVm: Clone + Sized {
    /// The only input.
    type Intent: Clone;
    /// The only output. Whatever the outside world learns about what happened,
    /// it learns here.
    type Receipt: Clone;
    /// Configuration the VM enforces and never computes.
    type Params: Clone;

    /// Identifies this VM in a checkpoint and in a guest's public output, so a
    /// proof or an anchor for one machine can never be replayed as another's.
    const VM_NAME: &'static str;
    /// Incremented when the encoding or the transition changes in a way that
    /// makes two builds disagree.
    const VM_VERSION: u16;

    fn genesis(chain_id: u32, params: Self::Params) -> Self;

    fn chain_id(&self) -> u32;
    fn seq(&self) -> u64;
    fn epoch(&self) -> u64;

    /// Apply one sequenced intent. **S1, S2, S3.**
    fn apply(&mut self, seq: u64, intent: &Self::Intent) -> Vec<Self::Receipt>;

    /// Apply an intent while committing the complete authorization envelope.
    ///
    /// `committed` is the canonical record independently verified by the
    /// execution layer. A VM whose state carries an epoch intent accumulator
    /// must fold these bytes, rather than only [`Self::encode_intent`], so a
    /// root commits to the credential and mandate that made the action legal.
    /// The default preserves compatibility for VMs without such an accumulator.
    fn apply_committed(
        &mut self,
        seq: u64,
        intent: &Self::Intent,
        _committed: &[u8],
    ) -> Vec<Self::Receipt> {
        self.apply(seq, intent)
    }

    /// The ordered section commitments. **S5, S6.**
    fn sections(&self) -> Vec<Hash>;

    /// The state root. Not overridable: one definition, or the layers above
    /// disagree with the layer below about what they are anchoring.
    fn state_root(&self) -> Hash {
        merkle_root(&self.sections())
    }

    /// The intent that seals an epoch. **S7.**
    fn seal_intent() -> Self::Intent;

    /// The checkpoint a seal produced, if these receipts carry one.
    fn sealed(receipts: &[Self::Receipt]) -> Option<Checkpoint>;

    /// The intent recording that `epoch` reached settlement, if this VM has a
    /// notion of external finality.
    ///
    /// A VM that holds value custodied elsewhere needs one: units credited
    /// against an outside deposit should not be spendable until a quorum has
    /// endorsed the epoch containing them, and something has to tell the VM
    /// when that happened. A VM with nothing outside itself returns `None` and
    /// the microchain simply never asks again.
    ///
    /// Sequenced like any other intent, so finality is part of the history
    /// rather than a side channel into it.
    fn finality_intent(_epoch: u64) -> Option<Self::Intent> {
        None
    }

    /// The state as `cp` sealed it, or `None` if it can no longer be recovered.
    /// **S7.**
    fn as_sealed(&self, cp: &Checkpoint) -> Option<Self>;

    /// Whether a receipt reports a rejected intent.
    fn rejected(r: &Self::Receipt) -> bool;

    /// Whether a receipt reports an execution that could not be completed.
    /// **S9.** A batch containing one must be discarded whole.
    fn unprovable(r: &Self::Receipt) -> bool;

    /// Every account that must have authorised this intent.
    ///
    /// A signature establishes *who signed*, never *what they may touch*. The
    /// two are only connected here. Without this, a perfectly valid signature
    /// over an intent naming somebody else's account is a perfectly valid
    /// authorisation to drain it — the check that closes that is the one most
    /// easily left out, because nothing fails without it.
    ///
    /// A `Vec` rather than an `Option` because some intents genuinely need two
    /// parties: a settled trade between a maker and a taker is one intent and
    /// two agreements, and letting either side alone authorise it would let
    /// either side alone impose it.
    ///
    /// The default is empty, which means **no user signature can authorise
    /// this intent at all** — operator-only. A VM that adds an intent and
    /// forgets this method makes it unusable, never unguarded.
    fn intent_authorities(_intent: &Self::Intent) -> Vec<AccountId> {
        Vec::new()
    }

    /// Which capabilities an intent requires, for [`crate::session`].
    ///
    /// The default demands **all** of them, so no session key can execute any
    /// intent of a VM that has not classified its own. That is deliberate: the
    /// failure of an under-classified intent should be that a session cannot
    /// use it, never that a session can use it unsupervised. A VM adding an
    /// intent and forgetting this method loses convenience, not money.
    fn intent_capability(_intent: &Self::Intent) -> u32 {
        crate::session::CAP_OPERATE
            | crate::session::CAP_WITHDRAW
            | crate::session::CAP_DELEGATE
    }

    /// Application-specific checks for an owner-signed constrained session.
    ///
    /// Capability-only sessions need no application interpretation. A
    /// constrained mandate fails closed unless the VM implements this method,
    /// preserving the rule that a future intent or application cannot become
    /// agent-accessible by omission.
    fn delegation_policy(
        &self,
        delegation: &crate::session::Delegation,
        _intent: &Self::Intent,
    ) -> Result<(), crate::session::DelegationPolicyError> {
        if delegation.constrained() {
            Err(crate::session::DelegationPolicyError::UnsupportedIntent)
        } else {
            Ok(())
        }
    }

    /// Canonical bytes for one intent, for the epoch's intent commitment.
    fn encode_intent(intent: &Self::Intent) -> Vec<u8>;

    /// Read one intent back.
    ///
    /// Needed because a VM's inputs cross a boundary it does not control: the
    /// sequencer's wire, a guest's input tape, a peer catching up. `None` on
    /// anything malformed — **S10**, a VM never aborts on bytes it did not
    /// choose.
    fn decode_intent(d: &mut crate::read::Decoder) -> Option<Self::Intent>;

    /// How this intent is presented to an external wallet — **S13**.
    ///
    /// A wallet renders exactly these fields and nothing else. That makes this
    /// the VM's user interface at the one moment that matters, when a person
    /// decides whether to approve, so it is part of the spec rather than of a
    /// front end: a front end can be swapped, phished or served by someone
    /// else, and the signing prompt has to be true regardless.
    ///
    /// The default is honest rather than helpful — an opaque hash of the
    /// canonical encoding, which is what the user is really approving if the VM
    /// declines to describe itself. A VM meant for humans should override it.
    /// A VM whose intents only ever come from other machines need not.
    ///
    /// Field names travel into signatures already given, so renaming one is a
    /// version bump, not a cosmetic change.
    fn typed_intent(intent: &Self::Intent) -> crate::eip712::TypedData {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(Self::encode_intent(intent));
        let digest: [u8; 32] = h.finalize().into();
        crate::eip712::TypedData::new("OpaqueIntent")
            .field("intent", crate::eip712::Value::Bytes32(digest))
    }

    /// Full state, enough to carry the chain. **S8.**
    fn encode(&self) -> Vec<u8>;
    fn decode(bytes: &[u8]) -> Option<Self>;

    /// Holder ids in commitment order.
    fn account_ids(&self) -> Vec<AccountId>;

    /// Holder leaves, in the same order. The accounts section is the Merkle
    /// root over these.
    fn account_leaves(&self) -> Vec<Hash>;

    /// The committed record behind one holder's leaf, in the VM's own encoding.
    ///
    /// Published alongside the leaf so a holder can rebuild it themselves and
    /// read what it says. A snapshot of bare hashes would still prove inclusion,
    /// but it would ask the holder to trust the publisher about *what* was
    /// included — which is the thing the escape hatch exists not to require.
    fn account_record(&self, id: &AccountId) -> Option<Vec<u8>>;

    /// The leaf a record hashes to. Must agree with [`Self::account_leaves`],
    /// which is what makes a published record checkable against the anchored
    /// root rather than merely readable.
    fn leaf_of_record(record: &[u8]) -> Hash;

    /// Value this epoch has moved so far, for [`Checkpoint::gross_volume`].
    fn gross_volume(&self) -> crate::fixed::Fixed;

    /// Whether the VM's conserved quantities still reconcile. **S11.**
    ///
    /// What "conserved" means is the application's to define — a token supply
    /// equalling the sum of balances, a vault's liabilities equalling its
    /// backing, a tally equalling the sum of its parts. What is *not* the
    /// application's to decide is whether the check runs: `transition` calls
    /// this after every batch and refuses to commit a state that fails it.
    ///
    /// Write it as an independent recomputation, not as a restatement of what
    /// the transition just did. A check that repeats the transition's own
    /// arithmetic confirms the code agrees with itself and catches nothing.
    ///
    /// The cost is a full scan per batch, which is real and is paid again
    /// inside a guest. That is the price of the guarantee; see `ZVM.md` for the
    /// incremental version that would replace it.
    fn conserved(&self) -> Result<(), &'static str>;
}

/// Everything the exit hatch needs from a VM, derived from the spec alone.
///
/// A blanket implementation: any conforming VM gets a working escape hatch
/// without writing one, which is the point of fixing the section layout in
/// **S6**. An application author does not get to reinvent — or get wrong — the
/// path their users' funds depend on.
pub trait Provable: MicrochainVm {
    /// The accounts section root.
    fn accounts_root(&self) -> Hash {
        merkle_root(&self.account_leaves())
    }

    /// The committed leaf for one holder.
    fn account_leaf(&self, id: &AccountId) -> Option<Hash> {
        let i = self.account_ids().iter().position(|a| a == id)?;
        self.account_leaves().into_iter().nth(i)
    }

    /// The inclusion path from a holder's leaf to the state root.
    ///
    /// Built in two parts: up through the accounts tree, then the steps that
    /// bind the accounts section into the root. The second part is derived from
    /// the section list rather than hard-coded, so a VM with three sections and
    /// one with six both get a correct path.
    fn account_proof(&self, id: &AccountId) -> Option<Vec<ProofStep>> {
        let i = self.account_ids().iter().position(|a| a == id)?;
        let mut path = merkle_proof(&self.account_leaves(), i);
        path.extend(merkle_proof(&self.sections(), SECTION_ACCOUNTS));
        Some(path)
    }
}

impl<V: MicrochainVm> Provable for V {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::verify_proof;

    /// The indices are a wire contract with every VM and every verifier.
    /// Pinned as a compile-time check so reordering them breaks the build
    /// rather than silently invalidating every exit proof in existence.
    const _: () = {
        assert!(SECTION_HEADER == 0);
        assert!(SECTION_ACCOUNTS == 1);
        assert!(MIN_SECTIONS == 2);
    };

    /// The derived proof path must verify for any section count, because a VM
    /// author chooses how many sections they have and must not have to think
    /// about it again.
    #[test]
    fn the_derived_account_path_works_for_any_section_count() {
        use crate::commit::hash_leaf;
        for sections in MIN_SECTIONS..=9 {
            let leaves: Vec<Hash> = (0..7u8).map(|i| hash_leaf(&[i])).collect();
            let accounts_root = merkle_root(&leaves);
            let mut secs: Vec<Hash> = (0..sections as u8).map(|i| hash_leaf(&[200 + i])).collect();
            secs[SECTION_ACCOUNTS] = accounts_root;
            let root = merkle_root(&secs);

            for (i, leaf) in leaves.iter().enumerate() {
                let mut path = merkle_proof(&leaves, i);
                path.extend(merkle_proof(&secs, SECTION_ACCOUNTS));
                assert!(
                    verify_proof(*leaf, &path, root),
                    "{} sections, leaf {} did not verify",
                    sections,
                    i
                );
            }
        }
    }
}
