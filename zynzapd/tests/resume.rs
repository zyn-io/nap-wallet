//! A restarted node continues the lineage it left, and its journal is enough
//! to reproduce the state it saved.

use std::sync::{Arc, Mutex};

use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{Fixed, Params};
use zyn::epoch::{Economics, EpochPolicy};
use zyn::journal;
use zyn_vm::spec::MicrochainVm;
use zynzapd::boot;

fn policy() -> EpochPolicy {
    EpochPolicy {
        intents_per_epoch: 10,
        epochs_per_anchor: 1,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("zyn-resume-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn a_restart_keeps_the_lineage_and_the_journal_reproduces_the_state() {
    let dir = tmp("lineage");
    let first = boot::open_at(
        &dir,
        9,
        Params::testnet(),
        policy(),
        Economics::flat(10_000),
        0,
        false,
        &dir.join("da"),
    )
    .unwrap();
    assert!(!first.resumed);
    let shared = Arc::new(Mutex::new(first.node));
    {
        let mut n = shared.lock().unwrap();
        let observed = n.state().backing_of(XZEC).add(Fixed::whole(1_000)).unwrap();
        n.submit_operator(
            Intent::AttestVaultBalance {
                asset: XZEC,
                observed,
            },
            0,
        );
        for i in 0..12u8 {
            let d = Intent::next_deposit(n.state(), [i + 1; 32], XZEC, Fixed::whole(1), [0u8; 32]);
            let step = n.submit_operator(d, 0);
            assert!(
                !step.unrecorded && !step.rejected(),
                "deposit {} failed: {:?}",
                i,
                step.receipts
            );
        }
        n.seal_now(1);
        n.anchor_now(1);
        assert_eq!(n.ledger().len(), 2, "two epochs sealed, two anchors");
    }
    boot::save(&first.store, &first.journal, &shared);
    let head = shared.lock().unwrap().ledger().head_root();
    let root = shared.lock().unwrap().state().state_root();
    let epoch = shared.lock().unwrap().state().epoch();
    drop(shared);

    let second = boot::open_at(
        &dir,
        9,
        Params::testnet(),
        policy(),
        Economics::flat(10_000),
        5,
        false,
        &dir.join("da"),
    )
    .unwrap();
    assert!(second.resumed);
    assert_eq!(second.node.ledger().len(), 2);
    assert_eq!(
        second.node.ledger().head_root(),
        head,
        "the lineage did not survive the restart"
    );
    assert_eq!(second.node.state().state_root(), root);

    // Every epoch is on disk, and replaying them from genesis lands on the
    // same root the node saved — including the finality intents the anchors
    // sequenced, which the journal must carry for the root to reproduce.
    let files = journal::files_for(&dir, 9, 0..=epoch).unwrap();
    let epochs: Vec<_> = files
        .iter()
        .map(|(_, b)| journal::read_epoch(b).unwrap())
        .collect();
    let out = journal::replay(SwapState::new(9, Params::testnet()), &epochs).unwrap();
    assert_eq!(
        out.state.state_root(),
        root,
        "the journal does not reproduce the saved state"
    );
    assert_eq!(out.checkpoints.len(), 2);
    assert_eq!(out.checkpoints[1].state_root, head);
}

#[test]
fn a_ledger_without_a_state_and_a_stale_state_are_both_refused() {
    let dir = tmp("stale");
    let b = boot::open_at(
        &dir,
        9,
        Params::testnet(),
        policy(),
        Economics::flat(10_000),
        0,
        false,
        &dir.join("da"),
    )
    .unwrap();
    let shared = Arc::new(Mutex::new(b.node));
    {
        let mut n = shared.lock().unwrap();
        let observed = n.state().backing_of(XZEC).add(Fixed::whole(10)).unwrap();
        n.submit_operator(
            Intent::AttestVaultBalance {
                asset: XZEC,
                observed,
            },
            0,
        );
        n.seal_now(0);
        n.anchor_now(0);
    }
    // Save only the ledger, not the state: evidence with no subject.
    b.store
        .save_ledger(shared.lock().unwrap().ledger())
        .unwrap();
    let err = boot::open_at(
        &dir,
        9,
        Params::testnet(),
        policy(),
        Economics::flat(10_000),
        0,
        false,
        &dir.join("da"),
    )
    .map(|_| ())
    .unwrap_err();
    assert!(err.contains("no saved state"), "{}", err);
    // Now a state from *before* the anchor beside a ledger that has it.
    let genesis = SwapState::new(9, Params::testnet());
    b.store.save(&zyn::store::Saved::of(&genesis)).unwrap();
    let err = boot::open_at(
        &dir,
        9,
        Params::testnet(),
        policy(),
        Economics::flat(10_000),
        0,
        false,
        &dir.join("da"),
    )
    .map(|_| ())
    .unwrap_err();
    assert!(err.contains("older than the last anchor"), "{}", err);
}
