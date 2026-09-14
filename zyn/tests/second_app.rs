//! A second application on Zyn, to prove the boundary is real.
//!
//! The architecture claims that opening Zyn to other applications will not
//! require moving ZynZap. The only honest way to check that is to write a
//! second VM that has nothing to do with swapping, run it through the same
//! node, and see whether anything in `zyn` had to change.
//!
//! Nothing did. `TallyVm` below is roughly two hundred lines with no AMM, no
//! pools, no fees and no tokens, and it gets sequencing, epoch policy,
//! anchoring to Zcash, threshold settlement, the exit hatch and crash recovery
//! for free — because those live above the spec rather than inside ZynZap.
//!
//! This file is the load-bearing test of the whole layering. If it ever needs a
//! change in `zyn` to keep compiling, the abstraction has leaked.

use zyn::anchor::{Certificate, Ledger, SignerSet};
use zyn::da::Snapshot;
use zyn::epoch::{Economics, EpochPolicy};
use zyn::node::Node;
use zyn::store::Saved;
use zyn_vm::commit::Hash;
use zyn_vm::conformance::{assert_conforms, Fixture};
use zyn_vm::read::Decoder;
use zyn_vm::spec::{AccountId, MicrochainVm};
use zyn_vm::{Checkpoint, Fixed};

// ---------------------------------------------------------------------------
// A microchain that counts things
// ---------------------------------------------------------------------------

mod tally;
pub use tally::{acct, seeded, Limits, Note, TallyVm, Tick};

#[test]
fn a_second_application_conforms() {
    assert_conforms(Fixture {
        state: seeded(),
        accepted: Tick::Add { who: acct(9), n: 7 },
        rejected: Tick::Add {
            who: acct(9),
            n: 999_999,
        }, // over max_step
        sequence: vec![
            Tick::Add { who: acct(1), n: 3 },
            Tick::Add { who: acct(2), n: 5 },
            Tick::Seal,
        ],
    });
}

/// And runs on the unmodified microchain: sequencing, epoch policy, anchoring.
#[test]
fn the_node_runs_it_without_knowing_what_it_is() {
    let policy = EpochPolicy {
        intents_per_epoch: 10,
        epochs_per_anchor: 3,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let mut node: Node<TallyVm> = Node::new(
        77,
        Limits { max_step: 1_000 },
        policy,
        Economics::flat(1_000),
    );

    let mut anchors = 0;
    for i in 0..300u32 {
        let step = node.submit_operator(
            Tick::Add {
                who: acct((i % 7) as u8 + 1),
                n: 1,
            },
            0,
        );
        assert!(!step.rejected());
        if step.anchor.is_some() {
            anchors += 1;
        }
    }
    let c = node.compression();
    assert_eq!(c.anchors, anchors);
    assert!(c.anchors == 10, "expected 10 anchors, got {}", c.anchors);
    assert!(c.realised_ratio().unwrap() > 30);
    node.ledger()
        .verify_lineage()
        .expect("lineage must verify for any VM");

    // The compression economics are the same argument for any application.
    let rep = node.report();
    assert!(rep.cost_per_action.unwrap() < 1_000);
    assert!(rep.transactions_saved > 290);
}

/// The exit hatch works for an application the infrastructure has never seen,
/// which is the whole reason the section layout is part of the spec.
#[test]
fn holders_can_exit_a_vm_the_infrastructure_never_heard_of() {
    let policy = EpochPolicy {
        intents_per_epoch: 5,
        epochs_per_anchor: 2,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let mut node: Node<TallyVm> = Node::new(
        77,
        Limits { max_step: 1_000 },
        policy,
        Economics::flat(1_000),
    );
    for n in 1..=8u8 {
        node.submit_operator(
            Tick::Add {
                who: acct(n),
                n: n as u64 * 3,
            },
            0,
        );
    }
    node.seal_now(0);
    let anchor = node.anchor_now(0).expect("anchor");
    let snap = node.publishable().expect("published snapshot");

    let anchored = anchor.checkpoint.state_root;
    snap.verifies_against(anchored)
        .expect("the snapshot must open the anchored root");
    assert_eq!(snap.len(), 8);
    for id in snap.ids() {
        assert!(
            snap.prove_against(id, anchored).unwrap(),
            "holder {} could not exit",
            id[0]
        );
    }

    // A falsified record still fails, with no application-specific check.
    let mut tampered = snap.clone();
    tampered.records[0].1 = b"not the committed record".to_vec();
    assert!(tampered.verifies_against(anchored).is_err());
}

/// Threshold settlement is application-agnostic too.
#[test]
fn threshold_custody_settles_any_conforming_vm() {
    let policy = EpochPolicy {
        intents_per_epoch: 4,
        epochs_per_anchor: 1,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let mut node: Node<TallyVm> = Node::new(
        77,
        Limits { max_step: 1_000 },
        policy,
        Economics::flat(1_000),
    );
    // The policy anchors inside `submit`, so the anchor is taken from the step
    // that produced it rather than forced afterwards.
    let mut anchor = None;
    for n in 1..=4u8 {
        if let Some(a) = node
            .submit_operator(Tick::Add { who: acct(n), n: 5 }, 0)
            .anchor
        {
            anchor = Some(a);
        }
    }
    let anchor = anchor.expect("four actions at four-per-epoch should have anchored");

    use ed25519_dalek::{Signer, SigningKey};
    let keys: Vec<SigningKey> = (1..=10u8)
        .map(|i| SigningKey::from_bytes(&[i; 32]))
        .collect();
    let set = SignerSet::new(
        keys.iter().map(|k| k.verifying_key().to_bytes()).collect(),
        7,
    )
    .unwrap();
    let mut cert = Certificate::new(anchor.id());
    for k in keys.iter().take(7) {
        cert.add(
            k.verifying_key().to_bytes(),
            k.sign(&anchor.id()).to_bytes(),
        )
        .unwrap();
    }
    let mut ledger = Ledger::new(77);
    ledger
        .accept(anchor, &cert, &set)
        .expect("7 of 10 must settle a tally chain too");
    assert_eq!(ledger.len(), 1);
}

/// Recovery is not application-specific either.
#[test]
fn a_tally_chain_recovers_from_a_saved_state() {
    let vm = seeded();
    let saved = Saved::of(&vm);
    let back: TallyVm = saved.restore().expect("restore");
    assert_eq!(back.state_root(), vm.state_root());
    assert_eq!(back, vm);

    let mut live = vm.clone();
    let mut resumed = back;
    let at = live.seq();
    live.apply(at + 1, &Tick::Add { who: acct(3), n: 4 });
    resumed.apply(at + 1, &Tick::Add { who: acct(3), n: 4 });
    assert_eq!(live.state_root(), resumed.state_root());
}

/// Two applications on the same infrastructure must not be able to settle into
/// each other's lineage.
#[test]
fn one_chains_anchor_is_not_valid_on_another() {
    let policy = EpochPolicy {
        intents_per_epoch: 2,
        epochs_per_anchor: 1,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let mut tally: Node<TallyVm> =
        Node::new(77, Limits { max_step: 100 }, policy, Economics::flat(1_000));
    tally.submit_operator(Tick::Add { who: acct(1), n: 1 }, 0);
    let a = tally
        .submit_operator(Tick::Add { who: acct(2), n: 1 }, 0)
        .anchor
        .expect("two actions at two-per-epoch should have anchored");

    // A ledger for a different microchain refuses it outright.
    let mut other = Ledger::new(78);
    assert!(other.accept_trusted_operator(a).is_err());
}

/// The snapshot type is generic, so a tally snapshot cannot be read as a swap
/// one — the type system carries the distinction the roots already encode.
#[test]
fn snapshots_are_bound_to_the_vm_that_produced_them() {
    let vm = seeded();
    let snap: Snapshot<TallyVm> = Snapshot::of(&vm);
    snap.verify().unwrap();
    assert_eq!(snap.chain_id, 77);
    // Sections: header, accounts, total.
    assert_eq!(snap.sections.len(), 3);
}

/// A second application gets a zkVM entry point without writing one.
///
/// The ZVM ABI is the spec's, not ZynZap's, so `run` works for any conforming
/// program — which is what lets one settlement verifier serve every application
/// Zyn ever hosts, instead of one contract redeployed per app.
#[test]
fn a_second_application_gets_a_zvm_entry_point_for_free() {
    use zyn_vm::zvm;

    let vm = seeded();
    let base = vm.state_root();
    let batch = vec![
        (vm.seq() + 1, Tick::Add { who: acct(2), n: 5 }),
        (vm.seq() + 2, Tick::Clear { who: acct(1) }),
        (vm.seq() + 3, Tick::Seal),
    ];

    // Native execution and the ZVM run must agree, or the proof would attest to
    // something other than what the chain did.
    let mut native = vm.clone();
    zvm::apply_batch(&mut native, &batch).expect("apply");

    let tape = zvm::encode_input::<TallyVm>(base, &vm, &batch);
    let out = zvm::Output::decode(&zvm::run::<TallyVm>(&tape).expect("run")).expect("output");
    assert_eq!(out.base_root, base);
    assert_eq!(out.final_root, native.state_root());
    assert_eq!(out.seq, native.seq());
    assert_eq!(out.epoch, native.epoch());
    assert_eq!(out.vm_id, zvm::vm_id::<TallyVm>());

    // Deterministic, and bound to its base root.
    assert_eq!(
        zvm::run::<TallyVm>(&tape).unwrap(),
        zvm::run::<TallyVm>(&tape).unwrap()
    );
    let wrong = zvm::encode_input::<TallyVm>([0xAB; 32], &vm, &batch);
    assert_eq!(
        zvm::run::<TallyVm>(&wrong),
        Err(zvm::ZvmError::BaseRootMismatch)
    );
    for cut in 0..tape.len() {
        assert!(
            zvm::run::<TallyVm>(&tape[..cut]).is_err(),
            "truncation at {} ran",
            cut
        );
    }
}

/// Two programs cannot be confused for each other, which is the failure that
/// matters most once Zyn hosts more than one application.
#[test]
fn a_run_is_bound_to_the_program_that_produced_it() {
    use zyn_vm::zvm;
    assert_ne!(
        zvm::vm_id::<TallyVm>(),
        zvm::vm_id::<swapvm::state::SwapState>(),
        "two applications share a program identity"
    );
}

// ---------------------------------------------------------------------------
// S11: the guarantee borrowed from Move, without Move
// ---------------------------------------------------------------------------

/// A VM that creates value out of nothing. Identical to `TallyVm` except that
/// `Add` credits the holder without crediting the running total — the shape of
/// the bug Move's linear types make unwriteable and every other VM leaves to an
/// auditor.
#[derive(Clone, PartialEq, Eq, Debug)]
struct LeakyVm(TallyVm);

impl MicrochainVm for LeakyVm {
    type Intent = Tick;
    type Receipt = Note;
    type Params = Limits;
    const VM_NAME: &'static str = "leaky";
    const VM_VERSION: u16 = 1;

    fn genesis(c: u32, p: Limits) -> Self {
        LeakyVm(TallyVm::genesis(c, p))
    }
    fn chain_id(&self) -> u32 {
        self.0.chain_id()
    }
    fn seq(&self) -> u64 {
        self.0.seq()
    }
    fn epoch(&self) -> u64 {
        self.0.epoch()
    }

    fn apply(&mut self, seq: u64, intent: &Tick) -> Vec<Note> {
        // The whole difference: the tally goes up, the total does not.
        let before = self.0.total;
        let out = self.0.apply(seq, intent);
        if matches!(intent, Tick::Add { .. }) {
            self.0.total = before;
        }
        out
    }

    fn sections(&self) -> Vec<Hash> {
        self.0.sections()
    }
    fn seal_intent() -> Tick {
        Tick::Seal
    }
    fn sealed(r: &[Note]) -> Option<Checkpoint> {
        TallyVm::sealed(r)
    }
    fn as_sealed(&self, cp: &Checkpoint) -> Option<Self> {
        self.0.as_sealed(cp).map(LeakyVm)
    }
    fn rejected(r: &Note) -> bool {
        TallyVm::rejected(r)
    }
    fn unprovable(r: &Note) -> bool {
        TallyVm::unprovable(r)
    }
    fn encode_intent(i: &Tick) -> Vec<u8> {
        TallyVm::encode_intent(i)
    }
    fn decode_intent(d: &mut Decoder) -> Option<Tick> {
        TallyVm::decode_intent(d)
    }
    fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
    fn decode(b: &[u8]) -> Option<Self> {
        TallyVm::decode(b).map(LeakyVm)
    }
    fn account_ids(&self) -> Vec<AccountId> {
        self.0.account_ids()
    }
    fn account_leaves(&self) -> Vec<Hash> {
        self.0.account_leaves()
    }
    fn account_record(&self, id: &AccountId) -> Option<Vec<u8>> {
        self.0.account_record(id)
    }
    fn leaf_of_record(r: &[u8]) -> Hash {
        TallyVm::leaf_of_record(r)
    }
    fn gross_volume(&self) -> Fixed {
        self.0.gross_volume()
    }
    fn conserved(&self) -> Result<(), &'static str> {
        self.0.conserved()
    }
}

/// A batch that creates value cannot reach a committed root.
///
/// The VM's own transition accepts the intent — it has no idea anything is
/// wrong, exactly as an EVM contract with a missing decrement would not. What
/// stops it is S11, enforced by the infrastructure rather than by the
/// application, which is the guarantee Move gets from linear types and every
/// other VM leaves to an audit.
#[test]
fn a_batch_that_creates_value_is_refused() {
    use zyn_vm::zvm;

    let mut leaky = LeakyVm::genesis(77, Limits { max_step: 1_000 });
    let batch = vec![(
        1u64,
        Tick::Add {
            who: acct(1),
            n: 50,
        },
    )];

    // Applied directly, the bug goes unnoticed: the state accepts it.
    let mut unchecked = leaky.clone();
    let receipts = unchecked.apply(
        1,
        &Tick::Add {
            who: acct(1),
            n: 50,
        },
    );
    assert!(
        !receipts.iter().any(LeakyVm::rejected),
        "the VM caught its own bug"
    );
    assert!(
        unchecked.conserved().is_err(),
        "the state is out of balance"
    );

    // Through the transition, it cannot commit.
    let before = leaky.state_root();
    assert!(
        matches!(
            zvm::apply_batch(&mut leaky, &batch),
            Err(zvm::ZvmError::NotConserved(_))
        ),
        "a value-creating batch was committed"
    );
    assert_eq!(
        leaky.state_root(),
        before,
        "a refused batch still moved state"
    );

    // And no proof can be produced for it either.
    let tape = zvm::encode_input::<LeakyVm>(before, &leaky, &batch);
    assert!(matches!(
        zvm::run::<LeakyVm>(&tape),
        Err(zvm::ZvmError::NotConserved(_))
    ));
}

/// The honest VM is unaffected: conservation costs correctness nothing.
#[test]
fn a_conserving_vm_passes_the_same_batch() {
    use zyn_vm::zvm;

    let mut honest = TallyVm::genesis(77, Limits { max_step: 1_000 });
    let batch = vec![(
        1u64,
        Tick::Add {
            who: acct(1),
            n: 50,
        },
    )];
    zvm::apply_batch(&mut honest, &batch).expect("an honest batch must commit");
    assert_eq!(honest.total, 50);
    honest.conserved().unwrap();
}
