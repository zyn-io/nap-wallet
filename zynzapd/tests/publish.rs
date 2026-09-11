//! A confirmed anchor produces a bundle that verifies without the sequencer.

use std::sync::{Arc, Mutex};

use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{Fixed, Params};
use zyn::anchor::Anchor;
use zyn::da::Published;
use zyn::epoch::{Economics, EpochPolicy};
use zyn::journal;
use zynzapd::{boot, publish};

#[test]
fn a_confirmed_anchor_yields_a_bundle_that_checks_out_end_to_end() {
    let dir = std::env::temp_dir().join(format!("zyn-publish-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let policy = EpochPolicy { intents_per_epoch: 5, epochs_per_anchor: 100, max_seconds_per_epoch: 0, max_seconds_per_anchor: 0 };
    let b = boot::open_at(&dir, 21, Params::testnet(), policy, Economics::flat(1), 0, true, &dir.join("da")).unwrap();
    let shared = Arc::new(Mutex::new(b.node));
    let anchor: Anchor = {
        let mut n = shared.lock().unwrap();
        let observed = n.state().backing_of(XZEC).add(Fixed::whole(100)).unwrap();
        n.submit_operator(Intent::AttestVaultBalance { asset: XZEC, observed }, 0);
        for i in 0..9u8 {
            let d = Intent::next_deposit(n.state(), [i + 1; 32], XZEC, Fixed::whole(1), [0u8; 32]);
            assert!(!n.submit_operator(d, 0).rejected());
        }
        assert_eq!(n.pending().len(), 2, "two epochs sealed, none anchored yet");
        let a = n.propose_anchor(0).unwrap();
        // Stand in for Zcash: the settler would confirm at depth.
        n.confirm_anchor(a.id(), None, 1).unwrap();
        a
    };
    boot::save(&b.store, &b.journal, &shared);

    let bundle = {
        let n = shared.lock().unwrap();
        publish::bundle_for(&n, &dir, 21, &anchor, "cafe", 4_400_000).unwrap()
    };
    let da = dir.join("da");
    publish::write_local(&da, 21, &bundle).unwrap();

    // --- what a stranger with the mirror's files and the memo's id can check ---
    let root = |name: &str| std::fs::read(da.join(format!("chain-21/{}/{}", anchor.checkpoint.epoch, name))).unwrap();
    let a = Anchor::decode(&root("anchor.bin")).unwrap();
    assert_eq!(a.id(), anchor.id(), "anchor.bin hashes to the id the memo carries");
    assert_eq!(a.epochs, 2);
    let p = Published::decode(&root("published.bin")).unwrap();
    p.verify().unwrap();
    assert_eq!(p.root, a.checkpoint.state_root, "the leaves open the anchored root");
    let files: Vec<_> = (0..=1u64)
        .map(|e| journal::read_epoch(&root(&format!("intents/epoch-{}.intents", e))).unwrap())
        .collect();
    let out = journal::replay(SwapState::new(21, Params::testnet()), &files).unwrap();
    assert_eq!(out.checkpoints.last(), Some(&a.checkpoint), "replaying the intents reproduces the anchored checkpoint");
    let index = std::fs::read_to_string(da.join("chain-21/index")).unwrap();
    let entries = publish::parse_index(&index);
    assert_eq!(entries[0].txid, "cafe");
    assert_eq!(entries[0].anchor_id, a.id());
    // And a flipped byte anywhere is caught by one of those checks.
    let mut bad = root("published.bin");
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(Published::decode(&bad).map(|p| p.verify().is_err()).unwrap_or(true));
}

/// The 8 Sep 2026 outage, as a test.
///
/// A bundle is assembled by reading the journal back off disk. Catch an epoch
/// mid-write — records present, the `Checkpoint` that seals them not yet
/// flushed — and the published bundle is one no verifier can reproduce. Worse,
/// it deadlocks: signers halt on it, so the anchor never gathers signatures,
/// so the corrected bundle is never written either. Live, that was epoch 2215
/// published at 62 bytes with 96 on disk, and twenty minutes of no deposits
/// becoming spendable.
///
/// Refusing to publish costs one pass. Publishing costs the chain.
#[test]
fn an_epoch_not_yet_sealed_on_disk_is_refused_rather_than_published() {
    let dir = std::env::temp_dir().join(format!("zyn-publish-unsealed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let policy = EpochPolicy { intents_per_epoch: 5, epochs_per_anchor: 100, max_seconds_per_epoch: 0, max_seconds_per_anchor: 0 };
    let b = boot::open_at(&dir, 21, Params::testnet(), policy, Economics::flat(1), 0, true, &dir.join("da")).unwrap();
    let shared = Arc::new(Mutex::new(b.node));
    let anchor: Anchor = {
        let mut n = shared.lock().unwrap();
        let observed = n.state().backing_of(XZEC).add(Fixed::whole(100)).unwrap();
        n.submit_operator(Intent::AttestVaultBalance { asset: XZEC, observed }, 0);
        for i in 0..9u8 {
            let d = Intent::next_deposit(n.state(), [i + 1; 32], XZEC, Fixed::whole(1), [0u8; 32]);
            assert!(!n.submit_operator(d, 0).rejected());
        }
        let a = n.propose_anchor(0).unwrap();
        n.confirm_anchor(a.id(), None, 1).unwrap();
        a
    };
    boot::save(&b.store, &b.journal, &shared);

    // A whole journal publishes.
    {
        let n = shared.lock().unwrap();
        publish::bundle_for(&n, &dir, 21, &anchor, "cafe", 4_400_000).expect("a sealed journal publishes");
    }

    // Now take the last epoch's seal off the end of the file, exactly as an
    // unflushed write would leave it.
    let last = anchor.checkpoint.epoch;
    let path = dir.join(format!("journal/chain-21/epoch-{}.intents", last));
    let raw = std::fs::read(&path).unwrap();
    let file = journal::read_epoch(&raw).unwrap();
    let (_, sealed_bytes) = file.records.last().unwrap().clone();
    let truncated = raw.len() - (8 + 4 + sealed_bytes.len());
    std::fs::write(&path, &raw[..truncated]).unwrap();
    assert!(journal::read_epoch(&std::fs::read(&path).unwrap()).unwrap().records.len() < file.records.len());

    let n = shared.lock().unwrap();
    let err = publish::bundle_for(&n, &dir, 21, &anchor, "cafe", 4_400_000).unwrap_err();
    assert!(err.contains("not sealed on disk yet"), "{}", err);
    assert!(err.contains(&last.to_string()), "it names the epoch: {}", err);
}
