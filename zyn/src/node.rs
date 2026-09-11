//! The sequencer: the process that actually runs the microchain.
//!
//! It owns one `SwapState`, assigns the canonical order, applies intents, seals
//! epochs when the policy says to, and emits anchors bound for Zcash. Everything
//! upstream of it is a queue; everything downstream is a commitment.
//!
//! ## What the node may and may not decide
//!
//! The node decides **order** and **when to settle**. It does not decide
//! outcomes: pricing happens in the VM, which is why an anchor over a batch is
//! worth something. That division is what makes the sequencer replaceable — a
//! successor with the same intents in the same order reaches the same roots, so
//! a failed sequencer is an availability problem rather than a solvency one.
//!
//! ## Time
//!
//! Every entry point takes `now` as a parameter. The node needs a clock for its
//! failsafes — a thin market must still seal and anchor — but reading one
//! internally would make the node untestable and put a non-deterministic input
//! next to a deterministic state machine. Passing it in keeps the boundary
//! explicit: the clock influences *when* an epoch closes, never *what* is in it.

use crate::verify::{encode_authorized, Authorized};
use alloc::boxed::Box;
use alloc::vec::Vec;

use zyn_vm::spec::MicrochainVm;
use zyn_vm::Checkpoint;

use crate::anchor::{Anchor, AnchorId, Certificate, Ledger, LineageError, SignerSet};
use crate::da::Snapshot;
use crate::epoch::{Compression, Economics, EpochPolicy, Report};

/// One applied intent and whatever it triggered.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Step<V: MicrochainVm> {
    pub seq: u64,
    pub receipts: Vec<V::Receipt>,
    /// The epoch this action closed, if it closed one.
    pub sealed: Option<Checkpoint>,
    /// The Zcash-bound commitment this action produced, if any.
    pub anchor: Option<Anchor>,
    /// The recorder refused to journal this intent, so it was **not applied**:
    /// no sequence number was consumed and `receipts` is empty. History must
    /// never outrun its own evidence.
    pub unrecorded: bool,
}

/// Where applied intents are written before they are applied.
///
/// The sequencer's journal implements this; a replica needs no recorder. The
/// hook returns `false` to refuse, and a refused intent is not applied — the
/// alternative, a state that has moved past what the journal can prove, is
/// exactly the situation the journal exists to rule out.
pub trait Recorder {
    fn record(&mut self, epoch: u64, seq: u64, encoded: &[u8]) -> bool;
}

/// Why a proposed anchor could not be confirmed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfirmError {
    /// No proposal with that id is in flight.
    NotProposed,
    /// The lineage or the certificate refused it.
    Lineage(LineageError),
    /// The recorder refused the finality intent; nothing was committed.
    Unrecorded,
}

impl From<LineageError> for ConfirmError {
    fn from(e: LineageError) -> Self {
        ConfirmError::Lineage(e)
    }
}

impl<V: MicrochainVm> Step<V> {
    pub fn rejected(&self) -> bool {
        self.receipts.iter().any(V::rejected)
    }
    /// Whether the intent could not be executed at all — an unprovable step,
    /// which the caller must treat as fatal to the batch rather than as an
    /// ordinary refusal.
    pub fn unprovable(&self) -> bool {
        self.receipts.iter().any(V::unprovable)
    }
}

/// A sealed epoch waiting to be carried to Zcash.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Sealed<V: MicrochainVm> {
    pub checkpoint: Checkpoint,
    /// Actions this epoch covered.
    pub actions: u64,
    /// The accounts tree as this epoch sealed it.
    ///
    /// Captured at the seal and not later, because that is the only moment it
    /// can be: the next intent to land changes an account, and the sealed view
    /// stops being recoverable from the live state. A node that deferred this
    /// would find itself unable to publish the very data its users' exits
    /// depend on.
    pub snapshot: Snapshot<V>,
}

/// The microchain node.
///
/// Generic over the VM it runs. Nothing below this line names an application:
/// the node sequences intents it cannot interpret, seals epochs it cannot read,
/// and anchors roots it did not compute. That is what makes a second
/// application a new crate rather than a change here.
pub struct Node<V: MicrochainVm> {
    state: V,
    policy: EpochPolicy,
    economics: Economics,

    compression: Compression,
    ledger: Ledger,

    /// Actions since the last seal, and when that seal happened.
    since_seal: u64,
    sealed_at: u64,
    /// Epochs and actions since the last anchor, and when that anchor happened.
    epochs_since_anchor: u64,
    actions_since_anchor: u64,
    anchored_at: u64,
    /// Epochs sealed but not yet carried to Zcash. Kept so an operator can see
    /// what is exposed if the chain stops anchoring.
    pending: Vec<Sealed<V>>,
    /// The snapshot opening the newest anchored root.
    published: Option<Snapshot<V>>,
    /// The settlement signers, if this node is configured with any.
    ///
    /// `None` is a V0 trusted-operator run: anchors are accepted on the
    /// sequencer's word alone. A node holding real value configures a set, and
    /// then an anchor without enough genuine signatures over it does not
    /// settle — which is what the deposit rules in the VM ultimately rest on.
    signers: Option<SignerSet>,
    /// Certificates gathered for anchors not yet accepted, by anchor id.
    pending_certificates: Vec<(crate::anchor::AnchorId, Certificate)>,
    /// The journal, if this node keeps one.
    recorder: Option<Box<dyn Recorder + Send>>,
    /// When set, sealing never anchors by itself: an operator proposes an
    /// anchor, carries it to Zcash, and confirms it once the chain has it.
    manual_anchoring: bool,
    /// The anchor in flight under manual anchoring, and how many of `pending`
    /// it covers.
    proposed: Option<(Anchor, usize)>,
    /// Actions applied since the last seal that no sealed epoch has counted
    /// yet — the finality intent an anchor sequences after the epoch it
    /// finalised. Folded into the next seal, so the next anchor attests it.
    unattributed: u64,
}

impl<V: MicrochainVm> Node<V> {
    pub fn new(chain_id: u32, params: V::Params, policy: EpochPolicy, economics: Economics) -> Self {
        Node {
            state: V::genesis(chain_id, params),
            policy,
            economics,
            compression: Compression::default(),
            ledger: Ledger::new(chain_id),
            since_seal: 0,
            sealed_at: 0,
            epochs_since_anchor: 0,
            actions_since_anchor: 0,
            anchored_at: 0,
            pending: Vec::new(),
            published: None,
            signers: None,
            pending_certificates: Vec::new(),
            recorder: None,
            manual_anchoring: false,
            proposed: None,
            unattributed: 0,
        }
    }

    /// Journal every intent before it is applied.
    pub fn with_recorder(mut self, r: Box<dyn Recorder + Send>) -> Self {
        self.recorder = Some(r);
        self
    }

    /// Anchors are proposed and confirmed by an operator rather than accepted
    /// the moment they are built — the posture for a chain whose anchors
    /// actually travel to Zcash.
    pub fn with_manual_anchoring(mut self) -> Self {
        self.manual_anchoring = true;
        self
    }

    /// Require a threshold of signatures before an anchor settles.
    ///
    /// Until a set is configured a node runs as a trusted operator, which is
    /// the plan's V0 posture and must not be a mainnet one.
    pub fn with_signers(mut self, set: SignerSet) -> Self {
        self.signers = Some(set);
        self
    }

    /// Supply a certificate for an anchor the node is waiting to settle.
    pub fn submit_certificate(&mut self, cert: Certificate) {
        self.pending_certificates.retain(|(id, _)| *id != cert.anchor);
        self.pending_certificates.push((cert.anchor, cert));
    }

    /// Fold one signer's endorsement of an anchor into its pending
    /// certificate. Counted only if a set is configured, the signer is in it,
    /// and the signature opens the id — so a replica that reproduced a root
    /// contributes, and nobody else does. Returns whether it was counted.
    pub fn add_endorsement(&mut self, anchor_id: AnchorId, signer: [u8; 32], signature: [u8; 64]) -> bool {
        let Some(set) = &self.signers else { return false };
        if !set.contains(&signer) {
            return false;
        }
        // A probe certificate reuses the same verification the ledger will.
        let mut probe = Certificate::new(anchor_id);
        if probe.add(signer, signature).is_err() {
            return false;
        }
        if probe.weight(set) == 0 {
            return false; // the signature does not open this id under this key
        }
        match self.pending_certificates.iter_mut().find(|(id, _)| *id == anchor_id) {
            Some((_, cert)) => {
                let _ = cert.add(signer, signature); // a repeat is refused and harmless
            }
            None => self.pending_certificates.push((anchor_id, probe)),
        }
        true
    }

    /// The certificate gathered for an anchor so far.
    pub fn certificate_for(&self, anchor_id: AnchorId) -> Option<&Certificate> {
        self.pending_certificates.iter().find(|(id, _)| *id == anchor_id).map(|(_, c)| c)
    }

    /// Whether the gathered endorsements clear the configured set. Always
    /// false with no set — there is nothing to clear.
    pub fn certificate_clears(&self, anchor_id: AnchorId) -> bool {
        match (&self.signers, self.certificate_for(anchor_id)) {
            (Some(set), Some(cert)) => cert.weight(set) >= set.threshold(),
            _ => false,
        }
    }

    /// Whether this node demands signatures before settling.
    pub fn requires_signatures(&self) -> bool {
        self.signers.is_some()
    }

    /// Resume from a state recovered after a restart.
    ///
    /// The counters start clean: they describe this process's activity, not the
    /// chain's whole history, which is in the state and the ledger. A restart
    /// therefore seals on its own schedule rather than immediately, and the
    /// realised ratio a fresh process reports is its own.
    pub fn resume(state: V, policy: EpochPolicy, economics: Economics, now: u64) -> Self {
        let chain_id = state.chain_id();
        Self::resume_with_ledger(state, policy, economics, Ledger::new(chain_id), now)
    }

    /// Resume with the persisted lineage, so the next anchor continues from
    /// the root Zcash last saw rather than from nothing.
    pub fn resume_with_ledger(state: V, policy: EpochPolicy, economics: Economics, ledger: Ledger, now: u64) -> Self {
        Node {
            state,
            policy,
            economics,
            compression: Compression::default(),
            ledger,
            since_seal: 0,
            sealed_at: now,
            epochs_since_anchor: 0,
            actions_since_anchor: 0,
            anchored_at: now,
            pending: Vec::new(),
            published: None,
            signers: None,
            pending_certificates: Vec::new(),
            recorder: None,
            manual_anchoring: false,
            proposed: None,
            unattributed: 0,
        }
    }

    /// Install the snapshot a replica verified, so it serves proofs against the
    /// anchored root exactly as the sequencer would.
    pub fn set_published(&mut self, s: Snapshot<V>) {
        self.published = Some(s);
    }

    /// Put back the sealed epochs a previous process had not anchored — with
    /// manual anchoring they survive a restart on disk, because the snapshot
    /// an exit needs can only be taken at the seal.
    pub fn restore_pending(&mut self, sealed: Vec<Sealed<V>>) {
        self.pending = sealed;
        self.epochs_since_anchor = self.pending.len() as u64;
        self.actions_since_anchor = self.pending.iter().map(|s| s.actions).sum();
    }

    /// Put back the proposal in flight. Refused unless it is exactly the
    /// anchor this node would build over the first `covered` pending epochs.
    pub fn restore_proposal(&mut self, a: Anchor, covered: usize) -> Result<(), &'static str> {
        if covered == 0 || covered > self.pending.len() {
            return Err("proposal covers epochs the node does not have pending");
        }
        let expected = Anchor {
            checkpoint: self.pending[covered - 1].checkpoint,
            previous_root: self.ledger.head_root(),
            epochs: covered as u64,
            actions: self.pending[..covered].iter().map(|s| s.actions).sum(),
        };
        if expected != a {
            return Err("proposal does not match the pending epochs and the lineage");
        }
        self.proposed = Some((a, covered));
        Ok(())
    }

    /// The proposal and how many pending epochs it covers.
    pub fn proposal(&self) -> Option<(Anchor, usize)> {
        self.proposed
    }

    /// The snapshot the proposed anchor opens — the sealed view of the last
    /// epoch it covers. What signers verify against before the anchor settles,
    /// so the bundle can be published at broadcast rather than at release.
    pub fn proposal_snapshot(&self) -> Option<Snapshot<V>> {
        let (_, covered) = self.proposed?;
        self.pending.get(covered - 1).map(|s| s.snapshot.clone())
    }

    /// The anchor in flight, if an operator has proposed one.
    pub fn proposed(&self) -> Option<&Anchor> {
        self.proposed.as_ref().map(|(a, _)| a)
    }

    fn record(&mut self, epoch: u64, seq: u64, committed: &[u8]) -> bool {
        match self.recorder.as_mut() {
            None => true,
            Some(r) => r.record(epoch, seq, committed),
        }
    }

    pub fn state(&self) -> &V {
        &self.state
    }
    pub fn policy(&self) -> &EpochPolicy {
        &self.policy
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub fn compression(&self) -> Compression {
        self.compression
    }
    /// Epochs sealed but not yet anchored — the window a Zcash outage exposes.
    pub fn pending(&self) -> &[Sealed<V>] {
        &self.pending
    }

    /// The snapshot a holder needs to exit against the newest anchored root.
    ///
    /// This is the artefact that has to reach somewhere durable and public. The
    /// anchor on Zcash is only a commitment; without this, nobody can build the
    /// proof it would verify.
    pub fn publishable(&self) -> Option<&Snapshot<V>> {
        self.published.as_ref()
    }

    /// The headline figures: compression, revenue, and what it costs.
    pub fn report(&self) -> Report {
        Report::build(self.compression, self.economics)
    }

    /// Submit one intent.
    ///
    /// Returns what the VM did, plus the epoch and anchor it may have triggered.
    /// A rejected intent still counts: it consumed a sequence number and the
    /// settlement capacity that goes with it, so pretending otherwise would
    /// overstate the compression ratio.
    /// Submit an intent on the operator's own authority.
    ///
    /// For the intents the node itself produces: credited deposits, attested
    /// vault balances, confirmed anchors, checkpoints. Exactly as safe as
    /// `submit(Authorized::operator(i), now)`, which is what it is — the
    /// guarantee both give is that operator authority must be *claimed*, in
    /// writing, at a site someone can grep for. Neither can stop a claim that
    /// is false; both stop one that is merely forgotten.
    pub fn submit_operator(&mut self, intent: V::Intent, now: u64) -> Step<V> {
        self.submit(Authorized::operator(intent), now)
    }

    /// [`Self::submit_operator`] for a batch.
    pub fn submit_all_operator(&mut self, intents: Vec<V::Intent>, now: u64) -> Vec<Step<V>> {
        intents.into_iter().map(|i| self.submit_operator(i, now)).collect()
    }

    /// Sequence and apply an authorised intent.
    ///
    /// Takes [`Authorized`] rather than a bare intent so that an RPC which
    /// forgets to authenticate does not compile. The VM still checks no
    /// signatures (**S1**); this is the boundary where authorship is settled,
    /// and the type is what stops the boundary being walked around.
    pub fn submit(&mut self, authorized: Authorized<V::Intent>, now: u64) -> Step<V> {
        let committed = encode_authorized::<V>(&authorized);
        let intent = authorized.into_intent();
        let seq = self.state.seq() + 1;
        if !self.record(self.state.epoch(), seq, &committed) {
            return Step { seq, receipts: Vec::new(), sealed: None, anchor: None, unrecorded: true };
        }
        let receipts = self.state.apply_committed(seq, &intent, &committed);

        self.compression.actions = self.compression.actions.saturating_add(1);
        self.since_seal = self.since_seal.saturating_add(1);
        self.actions_since_anchor = self.actions_since_anchor.saturating_add(1);

        let sealed = if self.policy.should_seal(self.since_seal, now.saturating_sub(self.sealed_at))
        {
            self.seal(now)
        } else {
            None
        };
        let anchor = if sealed.is_some()
            && !self.manual_anchoring
            && self
                .policy
                .should_anchor(self.epochs_since_anchor, now.saturating_sub(self.anchored_at))
        {
            self.make_anchor(now)
        } else {
            None
        };

        Step { seq, receipts, sealed, anchor, unrecorded: false }
    }

    /// Submit several intents in order.
    pub fn submit_all(&mut self, intents: Vec<Authorized<V::Intent>>, now: u64) -> Vec<Step<V>> {
        intents.into_iter().map(|i| self.submit(i, now)).collect()
    }

    /// Seal now regardless of policy — for a clean shutdown, where leaving
    /// execution unattested is worse than an early epoch.
    pub fn seal_now(&mut self, now: u64) -> Option<Checkpoint> {
        if self.since_seal == 0 {
            return None;
        }
        self.seal(now)
    }

    /// Seal only if the policy says the epoch is due — enough intents, or
    /// enough time since the last seal. The main loop's tick uses this, so
    /// that a batch window is the policy's window and not the tick's.
    pub fn seal_if_due(&mut self, now: u64) -> Option<Checkpoint> {
        if self.since_seal == 0 {
            return None;
        }
        if !self.policy.should_seal(self.since_seal, now.saturating_sub(self.sealed_at)) {
            return None;
        }
        self.seal(now)
    }

    /// Anchor now regardless of policy, for the same reason.
    pub fn anchor_now(&mut self, now: u64) -> Option<Anchor> {
        if self.epochs_since_anchor == 0 {
            return None;
        }
        self.make_anchor(now)
    }

    /// Seal the epoch by sequencing a `Checkpoint` intent.
    ///
    /// The seal goes *through* the VM rather than around it: an epoch boundary
    /// is part of the history it closes, so it takes a sequence number and folds
    /// into the epoch's own transaction commitment like any other action. A node
    /// that mutated the state directly here would produce roots no replayer
    /// could reproduce.
    fn seal(&mut self, now: u64) -> Option<Checkpoint> {
        let seq = self.state.seq() + 1;
        let seal = V::seal_intent();
        let authorized = Authorized::operator(seal);
        let committed = encode_authorized::<V>(&authorized);
        let seal = authorized.into_intent();
        if !self.record(self.state.epoch(), seq, &committed) {
            return None;
        }
        let receipts = self.state.apply_committed(seq, &seal, &committed);
        let cp = V::sealed(&receipts)?;

        // The checkpoint intent is itself an action of the chain.
        self.compression.actions = self.compression.actions.saturating_add(1);
        self.compression.epochs = self.compression.epochs.saturating_add(1);
        let covered = self.since_seal.saturating_add(1).saturating_add(self.unattributed);
        self.unattributed = 0;
        self.actions_since_anchor = self.actions_since_anchor.saturating_add(1);

        // Recoverable now and only now: the snapshot is taken before anything
        // else can land on the state.
        let snapshot = Snapshot::at_checkpoint(&self.state, &cp)
            .expect("the sealed view is always recoverable immediately after sealing");
        self.pending.push(Sealed { checkpoint: cp, actions: covered, snapshot });
        self.epochs_since_anchor = self.epochs_since_anchor.saturating_add(1);
        self.since_seal = 0;
        self.sealed_at = now;
        Some(cp)
    }

    /// The anchor over everything sealed since the last one, not yet accepted.
    fn build_anchor(&self) -> Option<Anchor> {
        let newest = self.pending.last()?.checkpoint;
        // Claims come from the sealed epochs themselves, so an anchor over a
        // window that opened while another was in flight attests exactly what
        // those epochs covered and not the counters' running totals.
        Some(Anchor {
            checkpoint: newest,
            previous_root: self.ledger.head_root(),
            epochs: self.pending.len() as u64,
            actions: self.pending.iter().map(|s| s.actions).sum(),
        })
    }

    /// Everything the lineage and the signer set require of `a`, without
    /// mutating anything. The certificate, when a set is configured.
    fn admissible(&self, a: &Anchor, cert: Option<&Certificate>) -> Result<(), LineageError> {
        self.ledger.check(a)?;
        if let Some(set) = &self.signers {
            cert.ok_or(LineageError::InsufficientSignatures)?.verify(a, set)?;
        }
        Ok(())
    }

    /// Commit an admissible anchor: the ledger, the published snapshot, the
    /// pending window, and the finality intent the VM may want sequenced.
    ///
    /// `covered` is how many of `pending` the anchor stands for. The finality
    /// intent is journaled **before** anything mutates, so a refusal leaves
    /// the node exactly as it was.
    fn commit_anchor(&mut self, a: Anchor, cert: Option<&Certificate>, covered: usize, now: u64) -> Result<(), ConfirmError> {
        self.admissible(&a, cert)?;
        let finality = V::finality_intent(a.checkpoint.epoch).map(|intent| {
            let seq = self.state.seq() + 1;
            let authorized = Authorized::operator(intent);
            let committed = encode_authorized::<V>(&authorized);
            (seq, authorized.into_intent(), committed)
        });
        if let Some((seq, _, committed)) = &finality {
            if !self.record(self.state.epoch(), *seq, committed) {
                return Err(ConfirmError::Unrecorded);
            }
        }
        match (&self.signers, cert) {
            (Some(set), Some(c)) => self.ledger.accept(a, c, set)?,
            (Some(_), None) => return Err(ConfirmError::Lineage(LineageError::InsufficientSignatures)),
            (None, _) => self.ledger.accept_trusted_operator(a)?,
        }
        self.pending_certificates.retain(|(id, _)| *id != a.id());

        self.compression.anchors = self.compression.anchors.saturating_add(1);
        let covered = covered.clamp(1, self.pending.len().max(1));
        self.published = Some(self.pending[covered - 1].snapshot.clone());
        self.pending.drain(..covered);
        self.epochs_since_anchor = self.pending.len() as u64;
        self.actions_since_anchor = self.pending.iter().map(|s| s.actions).sum();
        self.anchored_at = now;

        // Tell the VM the epoch settled, so anything held pending on it — a
        // deposit credited against an outside vault — becomes spendable.
        //
        // Sequenced rather than written directly: finality is part of the
        // history a replayer must reproduce, not a side channel into state. A
        // VM with nothing outside itself supplies no such intent and this is a
        // no-op for it.
        if let Some((seq, intent, committed)) = finality {
            self.state.apply_committed(seq, &intent, &committed);
            self.compression.actions = self.compression.actions.saturating_add(1);
            self.actions_since_anchor = self.actions_since_anchor.saturating_add(1);
            self.unattributed = self.unattributed.saturating_add(1);
        }
        Ok(())
    }

    /// Build and accept the anchor in one step — the V0 trusted-operator path,
    /// where nothing travels to Zcash and the ledger is the node's own memory.
    ///
    /// With a signer set configured this needs a certificate already
    /// submitted; without one the anchor does not settle and the epoch it would
    /// have finalised stays unfinalised — so the deposits in it stay
    /// unspendable. Failing closed is the whole point.
    fn make_anchor(&mut self, now: u64) -> Option<Anchor> {
        let a = self.build_anchor()?;
        let cert = self.pending_certificates.iter().find(|(id, _)| *id == a.id()).map(|(_, c)| c.clone());
        let covered = self.pending.len();
        self.commit_anchor(a, cert.as_ref(), covered, now).ok()?;
        Some(a)
    }

    /// Propose the anchor over everything sealed so far, for an operator to
    /// carry to Zcash. Nothing is accepted yet: `pending` keeps growing, and
    /// [`Self::confirm_anchor`] settles exactly what this proposal covered.
    /// One proposal at a time — two anchors in flight would race for the same
    /// `previous_root`.
    pub fn propose_anchor(&mut self, _now: u64) -> Option<Anchor> {
        if self.proposed.is_some() || self.pending.is_empty() {
            return None;
        }
        let a = self.build_anchor()?;
        self.ledger.check(&a).ok()?;
        self.proposed = Some((a, self.pending.len()));
        Some(a)
    }

    /// The chain has the proposed anchor: accept it, publish its snapshot, and
    /// release what it finalised. Epochs sealed while it was in flight stay
    /// pending for the next one.
    pub fn confirm_anchor(&mut self, id: AnchorId, cert: Option<&Certificate>, now: u64) -> Result<Anchor, ConfirmError> {
        let (a, covered) = match &self.proposed {
            Some((a, c)) if a.id() == id => (*a, *c),
            _ => return Err(ConfirmError::NotProposed),
        };
        self.commit_anchor(a, cert, covered, now)?;
        self.proposed = None;
        Ok(a)
    }

    /// Drop the proposal in flight — for an operator abandoning a transaction
    /// that never confirmed. The next proposal covers everything again.
    pub fn withdraw_proposal(&mut self) -> Option<Anchor> {
        self.proposed.take().map(|(a, _)| a)
    }
}

#[cfg(test)]
mod tests {
    // ZynZap is the VM these tests drive. It is a dev-dependency: the generic
    // layer is exercised against a real application, because an abstraction
    // tested only against a mock is an abstraction that fits a mock.
    use super::*;
    use alloc::vec;
    use swapvm::state::SwapState;
    use swapvm::tx::Intent;
    use swapvm::types::{AccountId, Params, XZEC};
    use swapvm::Fixed;

    type Chain = Node<SwapState>;

    fn acct(n: u8) -> AccountId {
        [n; 32]
    }

    fn policy() -> EpochPolicy {
        EpochPolicy {
            intents_per_epoch: 10,
            epochs_per_anchor: 3,
            max_seconds_per_epoch: 0,
            max_seconds_per_anchor: 0,
        }
    }

    fn node() -> Chain {
        // These tests exercise sequencing, not custody. Seed the vault's
        // observation directly rather than through an intent, so it does not
        // count as an action and skew the compression figures under test.
        let mut s = SwapState::new(1, Params::v1());
        s.tokens.get_mut(&XZEC).unwrap().vault.as_mut().unwrap().observed =
            Fixed::whole(1_000_000_000);
        Node::resume(s, policy(), Economics::flat(1_000), 0)
    }

    /// The deposit index comes from the chain, so a helper needs to read it.
    fn deposit(node: &Chain, n: u8) -> Intent {
        Intent::next_deposit(node.state(), acct(n), XZEC, Fixed::whole(100), [0u8; 32])
    }

    #[test]
    fn a_node_seals_on_the_action_count() {
        let mut n = node();
        for i in 1..=9 {
            assert!({ let d = deposit(&n, 1); n.submit_operator(d, 0) }.sealed.is_none(), "sealed early at {}", i);
        }
        let step = { let d = deposit(&n, 1); n.submit_operator(d, 0) };
        let cp = step.sealed.expect("the tenth action should have sealed");
        assert_eq!(cp.epoch, 0);
        assert_eq!(n.compression().epochs, 1);
        // Ten submissions plus the checkpoint intent that sealed them.
        assert_eq!(n.compression().actions, 11);
        assert_eq!(n.state().epoch, 1);
    }

    #[test]
    fn a_node_anchors_on_the_epoch_count() {
        let mut n = node();
        let mut anchors = vec![];
        for _ in 0..30 {
            if let Some(a) = { let d = deposit(&n, 1); n.submit_operator(d, 0) }.anchor {
                anchors.push(a);
            }
        }
        assert_eq!(anchors.len(), 1, "three epochs should be one Zcash transaction");
        assert_eq!(n.compression().anchors, 1);
        assert_eq!(n.compression().epochs, 3);
        assert_eq!(anchors[0].epochs, 3);
        assert!(n.pending().is_empty(), "anchored epochs stayed pending");
        n.ledger().verify_lineage().unwrap();
    }

    /// The point of the whole architecture, measured rather than asserted.
    #[test]
    fn many_actions_become_one_zcash_transaction() {
        let mut n = node();
        for _ in 0..300 {
            { let d = deposit(&n, 1); n.submit_operator(d, 0) };
        }
        let c = n.compression();
        assert_eq!(c.anchors, 10);
        assert!(c.actions > 300);
        // ~33 user actions per Zcash transaction under this test policy.
        assert_eq!(c.realised_ratio(), Some(c.actions / 10));
        assert!(c.transactions_saved() > 300 - 10);

        // The ledger's attested totals account for everything up to the last
        // anchor. They trail the node's own counters by exactly what has
        // happened since — here, the finality intent each anchor emits, which
        // by construction lands after the anchor that triggered it and is
        // carried by the next one.
        let (actions, epochs, anchored) = n.ledger().totals();
        assert_eq!(anchored, c.anchors);
        assert_eq!(epochs, c.epochs);
        assert!(actions <= c.actions, "the ledger attested more than happened");
        assert_eq!(c.actions - actions, 1, "only the trailing finality intent is unattested");
    }

    #[test]
    fn the_clock_seals_a_market_too_thin_to_fill_an_epoch() {
        let mut n = Chain::new(
            1,
            Params::v1(),
            EpochPolicy {
                intents_per_epoch: 1_000,
                epochs_per_anchor: 100,
                max_seconds_per_epoch: 60,
                max_seconds_per_anchor: 900,
            },
            Economics::flat(1_000),
        );
        assert!({ let d = deposit(&n, 1); n.submit_operator(d, 10) }.sealed.is_none());
        let step = { let d = deposit(&n, 1); n.submit_operator(d, 61) };
        assert!(step.sealed.is_some(), "the failsafe did not seal a quiet market");
        // And the anchor failsafe eventually carries it to Zcash regardless of
        // volume, so an exit is never hostage to someone else trading.
        assert!({ let d = deposit(&n, 1); n.submit_operator(d, 200) }.anchor.is_none());
        let step = { let d = deposit(&n, 1); n.submit_operator(d, 1_000) };
        assert!(step.anchor.is_some(), "a quiet market never anchored");
    }

    #[test]
    fn an_empty_chain_neither_seals_nor_anchors() {
        let mut n = node();
        assert_eq!(n.seal_now(0), None, "sealed an epoch with no history");
        assert_eq!(n.anchor_now(0), None, "anchored with nothing sealed");
        assert_eq!(n.compression(), Compression::default());
    }

    #[test]
    fn a_clean_shutdown_seals_and_anchors_what_is_outstanding() {
        let mut n = node();
        for _ in 0..4 {
            { let d = deposit(&n, 1); n.submit_operator(d, 0) };
        }
        assert!(n.seal_now(5).is_some());
        let a = n.anchor_now(5).expect("shutdown should carry the epoch to Zcash");
        assert_eq!(a.epochs, 1);
        assert_eq!(a.actions, 5, "four actions plus the seal");
        assert!(n.pending().is_empty());
    }

    #[test]
    fn rejected_actions_still_consume_settlement_capacity() {
        let mut n = node();
        // Nobody holds anything, so every transfer is rejected.
        for _ in 0..10 {
            let s = n.submit_operator(
                Intent::Transfer {
                    from: acct(9),
                    to: acct(8),
                    asset: XZEC,
                    amount: Fixed::whole(1),
                },
                0,
            );
            assert!(s.rejected());
        }
        assert_eq!(n.compression().actions, 11, "rejections were not counted");
        assert_eq!(n.compression().epochs, 1);
    }

    #[test]
    fn anchors_chain_across_the_whole_run() {
        let mut n = node();
        let mut previous: Option<Anchor> = None;
        for _ in 0..200 {
            if let Some(a) = { let d = deposit(&n, 1); n.submit_operator(d, 0) }.anchor {
                if let Some(p) = previous {
                    assert_eq!(
                        a.previous_root, p.checkpoint.state_root,
                        "an anchor did not continue the previous one"
                    );
                }
                previous = Some(a);
            }
        }
        assert!(n.ledger().len() > 1);
        n.ledger().verify_lineage().expect("the run's lineage must verify");
    }

    /// The report is what a dashboard and a pitch both read from, so the
    /// figures in it must be the measured ones.
    #[test]
    fn the_report_prices_the_compression() {
        let mut n = node();
        for _ in 0..300 {
            { let d = deposit(&n, 1); n.submit_operator(d, 0) };
        }
        let rep = n.report();
        assert_eq!(rep.compression, n.compression());
        assert!(rep.ratio.unwrap() > 30);
        // Ten Zcash transactions instead of one per action.
        assert_eq!(rep.l1_saved, 1_000 * (rep.compression.actions - 10));
        assert!(rep.transactions_saved > 300 - 10);

        // 10 anchors at 1,000 zatoshi spread over every action, rounded up.
        let actions = rep.compression.actions;
        assert_eq!(rep.cost_per_action, Some((10 * 1_000u64).div_ceil(actions)));
        assert!(
            rep.cost_per_action.unwrap() < 1_000,
            "compression did not reduce the per-action cost below one transaction"
        );

        // Tightening the policy compresses harder and costs less per trade.
        let mut wide = Chain::new(
            1,
            Params::v1(),
            EpochPolicy {
                intents_per_epoch: 50,
                epochs_per_anchor: 6,
                max_seconds_per_epoch: 0,
                max_seconds_per_anchor: 0,
            },
            Economics::flat(1_000),
        );
        for _ in 0..300 {
            { let d = deposit(&wide, 1); wide.submit_operator(d, 0) };
        }
        let wide_rep = wide.report();
        assert!(
            wide_rep.cost_per_action.unwrap() < rep.cost_per_action.unwrap(),
            "more compression did not lower the per-action cost"
        );
    }

    /// The node must be able to hand out the data an exit needs, for the root
    /// it actually anchored.
    #[test]
    fn the_node_publishes_what_an_exit_needs() {
        let mut n = node();
        for i in 0..40 {
            let d = deposit(&n, 1 + (i % 5) as u8);
            n.submit_operator(d, 0);
        }
        let a = n.anchor_now(0).or_else(|| {
            n.seal_now(0);
            n.anchor_now(0)
        });
        let a = a.expect("anchor");
        let snap = n.publishable().expect("an anchored chain must publish its snapshot");
        snap.verifies_against(a.checkpoint.state_root)
            .expect("the published snapshot must open the anchored root");
        for id in snap.ids() {
            assert!(snap.prove_against(id, a.checkpoint.state_root).unwrap());
        }
    }

    /// A node configured with signers fails closed: without a certificate the
    /// anchor does not settle, so the epoch stays unfinalised and the deposits
    /// in it stay unspendable.
    ///
    /// This is the property the whole deposit story rests on. If a missing
    /// certificate merely logged a warning and carried on, every safety rule in
    /// the VM would be advisory.
    #[test]
    fn a_node_with_signers_will_not_settle_without_one() {
        use crate::anchor::{Certificate, SignerSet};
        use ed25519_dalek::{Signer, SigningKey};

        let keys: Vec<SigningKey> = (1..=10u8).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
        let set = SignerSet::new(keys.iter().map(|k| k.verifying_key().to_bytes()).collect(), 7)
            .unwrap();

        let mut n = node().with_signers(set);
        assert!(n.requires_signatures());
        for _ in 0..40 {
            let d = deposit(&n, 1);
            let step = n.submit_operator(d, 0);
            assert!(step.anchor.is_none(), "an anchor settled with no certificate");
        }
        assert_eq!(n.compression().anchors, 0);
        assert!(n.ledger().is_empty());
        // Epochs sealed and waiting, which is exactly what an operator should
        // see when signatures have stopped arriving.
        assert!(!n.pending().is_empty());

        // With a genuine certificate for the anchor it is trying to make, it
        // settles. The id is over the anchor the node would build next.
        let sealed = n.pending().last().unwrap().checkpoint;
        let a = crate::anchor::Anchor {
            checkpoint: sealed,
            previous_root: n.ledger().head_root(),
            epochs: n.pending().len() as u64,
            actions: n.compression().actions,
        };
        let mut cert = Certificate::new(a.id());
        for k in keys.iter().take(7) {
            cert.add(k.verifying_key().to_bytes(), k.sign(&a.id()).to_bytes()).unwrap();
        }
        n.submit_certificate(cert);
        assert!(n.anchor_now(0).is_some(), "a certified anchor did not settle");
        assert_eq!(n.compression().anchors, 1);
        n.ledger().verify_lineage().unwrap();
    }

    /// A restarted node continues the same chain: the state carries the
    /// sequence and the lineage, so nothing about the history is re-derived
    /// from the process that happened to be running.
    #[test]
    fn a_resumed_node_continues_the_same_chain() {
        let mut n = node();
        for _ in 0..25 {
            { let d = deposit(&n, 1); n.submit_operator(d, 0) };
        }
        let root = n.state().state_root();
        let seq = n.state().seq;

        let carried = SwapState::decode_state(&n.state().encode_state()).unwrap();
        let mut resumed = Node::resume(carried, policy(), Economics::flat(1_000), 100);
        assert_eq!(resumed.state().state_root(), root);
        assert_eq!(resumed.state().seq, seq);

        let step = { let d = deposit(&resumed, 1); resumed.submit_operator(d, 100) };
        assert_eq!(step.seq, seq + 1);
        assert!(!step.rejected(), "a resumed node could not apply an intent");
        resumed.state().check_invariants().unwrap();
    }

    // --- Task 4: recorder, propose/confirm, resume with ledger ---

    struct Tape(alloc::vec::Vec<(u64, u64, alloc::vec::Vec<u8>)>, bool);
    impl Recorder for Tape {
        fn record(&mut self, e: u64, s: u64, b: &[u8]) -> bool {
            if !self.1 {
                return false;
            }
            self.0.push((e, s, b.to_vec()));
            true
        }
    }

    /// A recorder that shares its tape so a test can read it after the node
    /// has taken ownership.
    struct Shared(alloc::sync::Arc<std::sync::Mutex<Tape>>);
    impl Recorder for Shared {
        fn record(&mut self, e: u64, s: u64, b: &[u8]) -> bool {
            self.0.lock().unwrap().record(e, s, b)
        }
    }

    #[test]
    fn every_applied_intent_is_recorded_before_it_is_applied_including_seals() {
        let tape = alloc::sync::Arc::new(std::sync::Mutex::new(Tape(vec![], true)));
        let mut n = node().with_recorder(Box::new(Shared(tape.clone())));
        for _ in 0..10 {
            { let d = deposit(&n, 1); n.submit_operator(d, 0) };
        }
        let t = tape.lock().unwrap();
        // 10 deposits, the checkpoint that sealed them, and — because the
        // policy anchors every 3 epochs — no finality intent yet.
        assert_eq!(t.0.len(), 11);
        assert!(t.0.windows(2).all(|w| w[0].1 + 1 == w[1].1), "seqs are contiguous");
        assert!(t.0[..11].iter().all(|r| r.0 == 0), "all in epoch 0");
        assert_eq!(
            t.0[10].2,
            crate::verify::encode_authorized::<SwapState>(&Authorized::operator(
                Intent::Checkpoint
            ))
        );
        assert_eq!(n.state().seq(), 11);
    }

    #[test]
    fn a_refused_record_means_nothing_was_applied() {
        let mut n = node().with_recorder(Box::new(Tape(vec![], false)));
        let before = n.state().seq();
        let step = { let d = deposit(&n, 1); n.submit_operator(d, 0) };
        assert!(step.unrecorded);
        assert!(step.receipts.is_empty());
        assert_eq!(n.state().seq(), before, "a refused intent consumed a sequence number");
        assert_eq!(n.seal_now(0), None, "a seal the journal refused must not happen");
    }

    #[test]
    fn an_anchor_is_proposed_then_confirmed_and_only_then_published() {
        let mut n = node().with_manual_anchoring();
        for _ in 0..30 {
            { let d = deposit(&n, 1); n.submit_operator(d, 0) };
        }
        assert_eq!(n.pending().len(), 3, "manual anchoring must not anchor by itself");
        assert!(n.publishable().is_none());
        let a = n.propose_anchor(0).expect("a proposal");
        assert_eq!(a.epochs, 3);
        assert!(n.propose_anchor(0).is_none(), "one anchor in flight at a time");
        assert!(n.publishable().is_none(), "nothing is published before confirmation");
        // Another epoch seals while the anchor is in flight.
        for _ in 0..10 {
            { let d = deposit(&n, 1); n.submit_operator(d, 0) };
        }
        assert_eq!(n.pending().len(), 4);
        assert_eq!(n.confirm_anchor([7u8; 32], None, 0), Err(ConfirmError::NotProposed));
        let confirmed = n.confirm_anchor(a.id(), None, 5).unwrap();
        assert_eq!(confirmed.checkpoint, a.checkpoint);
        assert_eq!(n.publishable().unwrap().root, a.checkpoint.state_root);
        assert_eq!(n.pending().len(), 1, "the epoch sealed in flight stays pending");
        assert_eq!(n.ledger().head_root(), a.checkpoint.state_root);
        assert!(n.proposed().is_none());
        // The finality intent was sequenced: the anchored epoch is final.
        assert_eq!(n.state().finalized_epoch, a.checkpoint.epoch);
        // And the next proposal continues from this root and covers only the epoch left over.
        let b = n.propose_anchor(0).expect("next proposal");
        assert_eq!(b.previous_root, a.checkpoint.state_root);
        assert_eq!(b.epochs, 1);
    }

    #[test]
    fn a_withdrawn_proposal_can_be_proposed_again() {
        let mut n = node().with_manual_anchoring();
        for _ in 0..10 {
            { let d = deposit(&n, 1); n.submit_operator(d, 0) };
        }
        let a = n.propose_anchor(0).unwrap();
        assert_eq!(n.withdraw_proposal(), Some(a));
        assert_eq!(n.propose_anchor(0), Some(a), "same pending, same anchor, same id");
    }

    #[test]
    fn resume_with_a_ledger_continues_the_lineage() {
        let mut n = node();
        for _ in 0..30 {
            { let d = deposit(&n, 1); n.submit_operator(d, 0) };
        }
        let head = n.ledger().head_root();
        assert_ne!(head, [0u8; 32]);
        let entries: Vec<(Anchor, Certificate)> =
            n.ledger().anchors().iter().cloned().zip(n.ledger().certificates().iter().cloned()).collect();
        let ledger = Ledger::restore(1, entries).unwrap();
        let mut back = Chain::resume_with_ledger(n.state().clone(), policy(), Economics::flat(1_000), ledger, 0)
            .with_manual_anchoring();
        for _ in 0..10 {
            { let d = deposit(&back, 1); back.submit_operator(d, 0) };
        }
        let next = back.propose_anchor(0).unwrap();
        assert_eq!(next.previous_root, head, "a resumed node must continue from the root Zcash saw");
        let plain = Chain::resume(n.state().clone(), policy(), Economics::flat(1_000), 0);
        assert_eq!(plain.ledger().head_root(), [0u8; 32], "without the ledger the lineage is forgotten — the reason it is persisted");
    }

    #[test]
    fn pending_and_a_proposal_survive_being_restored() {
        let mut n = node().with_manual_anchoring();
        for _ in 0..20 {
            { let d = deposit(&n, 1); n.submit_operator(d, 0) };
        }
        let a = n.propose_anchor(0).unwrap();
        let (pa, covered) = n.proposal().unwrap();
        assert_eq!((pa, covered), (a, 2));
        let pending: Vec<Sealed<SwapState>> = n.pending().to_vec();
        let mut back = Chain::resume(n.state().clone(), policy(), Economics::flat(1_000), 0).with_manual_anchoring();
        assert!(back.restore_proposal(a, 2).is_err(), "nothing pending yet");
        back.restore_pending(pending);
        back.restore_proposal(a, 2).unwrap();
        assert_eq!(back.proposed(), Some(&a));
        assert!(back.restore_proposal(a, 1).is_err(), "a proposal over fewer epochs is a different anchor");
        let c = back.confirm_anchor(a.id(), None, 1).unwrap();
        assert_eq!(c, a);
        assert_eq!(back.publishable().unwrap().root, a.checkpoint.state_root);
    }

    #[test]
    fn endorsements_accumulate_and_clear_only_at_threshold() {
        use crate::anchor::SignerSet;
        use ed25519_dalek::{Signer as _, SigningKey};
        let keys: Vec<SigningKey> = (1..=3u8).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
        let set = SignerSet::new(keys.iter().map(|k| k.verifying_key().to_bytes()).collect(), 2).unwrap();
        let mut n = node().with_manual_anchoring().with_signers(set);
        for _ in 0..30 { let d = deposit(&n, 1); n.submit_operator(d, 0); }
        let a = n.propose_anchor(0).unwrap();
        // No certificate: it will not settle.
        assert_eq!(n.confirm_anchor(a.id(), None, 0), Err(ConfirmError::Lineage(LineageError::InsufficientSignatures)));
        // An outsider and a bad signature carry no weight.
        let outsider = SigningKey::from_bytes(&[9u8; 32]);
        assert!(!n.add_endorsement(a.id(), outsider.verifying_key().to_bytes(), outsider.sign(&a.id()).to_bytes()));
        assert!(!n.add_endorsement(a.id(), keys[0].verifying_key().to_bytes(), [0u8; 64]));
        assert!(!n.certificate_clears(a.id()));
        // One real endorsement: still short.
        assert!(n.add_endorsement(a.id(), keys[0].verifying_key().to_bytes(), keys[0].sign(&a.id()).to_bytes()));
        assert!(!n.certificate_clears(a.id()));
        // The second clears it, and now it settles.
        assert!(n.add_endorsement(a.id(), keys[1].verifying_key().to_bytes(), keys[1].sign(&a.id()).to_bytes()));
        assert!(n.certificate_clears(a.id()));
        let cert = n.certificate_for(a.id()).cloned().unwrap();
        let confirmed = n.confirm_anchor(a.id(), Some(&cert), 0).unwrap();
        assert_eq!(confirmed, a);
        assert_eq!(n.publishable().unwrap().root, a.checkpoint.state_root);
        assert_eq!(n.ledger().certificates().last().unwrap().weight(&SignerSet::new((1..=3u8).map(|i| SigningKey::from_bytes(&[i; 32]).verifying_key().to_bytes()).collect(), 2).unwrap()), 2);
    }
}
