//! A replica reproduces the chain from Zcash sightings and mirror files alone,
//! and stops at the first thing that does not add up.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{Fixed, Params};
use zyn::anchor::Anchor;
use zyn::epoch::{Economics, EpochPolicy};
use zyn::verify_record;
use zyn_vm::spec::MicrochainVm;
use zynzapd::replica::{Fetch, Halt, Local, Replica, Sighting};
use zynzapd::{boot, publish};

const CHAIN: u32 = 31;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("zyn-replica-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A sequencer that anchors on demand, writing bundles to `da`.
struct Seq {
    dir: PathBuf,
    da: PathBuf,
    shared: Arc<Mutex<zyn::node::Node<SwapState>>>,
    store: zyn::store::FileStore,
    journal: Arc<Mutex<zyn::journal::Journal>>,
    next_height: u64,
    sightings: Vec<Sighting>,
}

impl Seq {
    fn new(name: &str) -> Seq {
        let dir = tmp(&format!("{}-seq", name));
        let policy = EpochPolicy {
            intents_per_epoch: 4,
            epochs_per_anchor: 100,
            max_seconds_per_epoch: 0,
            max_seconds_per_anchor: 0,
        };
        let b = boot::open_at(
            &dir,
            CHAIN,
            Params::testnet(),
            policy,
            Economics::flat(1),
            0,
            true,
            &dir.join("da"),
        )
        .unwrap();
        let shared = Arc::new(Mutex::new(b.node));
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
        }
        let da = dir.join("da");
        Seq {
            dir: dir.clone(),
            da,
            shared,
            store: b.store,
            journal: b.journal,
            next_height: 4_400_000,
            sightings: Vec::new(),
        }
    }

    fn trade(&self, n_intents: u32) {
        let mut n = self.shared.lock().unwrap();
        for i in 0..n_intents {
            let who = [(i % 7 + 1) as u8; 32];
            let d = Intent::next_deposit(n.state(), who, XZEC, Fixed::whole(1), [0u8; 32]);
            assert!(!n.submit_operator(d, 0).rejected());
        }
    }

    /// Propose, "confirm on Zcash", bundle. Returns the anchor.
    fn anchor(&mut self) -> Anchor {
        let a = {
            let mut n = self.shared.lock().unwrap();
            let a = n.propose_anchor(0).expect("something pending");
            n.confirm_anchor(a.id(), None, 1).unwrap();
            a
        };
        boot::save(&self.store, &self.journal, &self.shared);
        let bundle = {
            let n = self.shared.lock().unwrap();
            publish::bundle_for(&n, &self.dir, CHAIN, &a, &"ab".repeat(32), self.next_height)
                .unwrap()
        };
        publish::write_local(&self.da, CHAIN, &bundle).unwrap();
        let mut txid = [0u8; 32];
        txid[0] = (self.sightings.len() + 1) as u8;
        self.sightings.push(Sighting {
            height: self.next_height,
            txid,
            chain_id: CHAIN,
            epoch: a.checkpoint.epoch,
            id: a.id(),
        });
        self.next_height += 20;
        a
    }

    fn head_root(&self) -> [u8; 32] {
        self.shared.lock().unwrap().ledger().head_root()
    }
}

fn replica(name: &str) -> (Replica, PathBuf) {
    let dir = tmp(&format!("{}-rep", name));
    (Replica::open(&dir, CHAIN, Params::testnet()).unwrap(), dir)
}

fn copy_dir(from: &Path, to: &Path) {
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let dest = to.join(e.file_name());
        if e.path().is_dir() {
            std::fs::create_dir_all(&dest).unwrap();
            copy_dir(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

#[test]
fn a_replica_reproduces_every_anchored_root_from_sightings_and_mirrors_alone() {
    let mut s = Seq::new("reproduce");
    s.trade(8);
    let a1 = s.anchor();
    s.trade(4);
    s.trade(4);
    let a2 = s.anchor();
    s.trade(4);
    let a3 = s.anchor();
    assert_eq!(a3.previous_root, a2.checkpoint.state_root);

    let (mut r, _) = replica("reproduce");
    let p = r
        .apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();
    assert_eq!((p.verified, p.skipped), (3, 0));
    assert_eq!(r.verified_epoch, Some(a3.checkpoint.epoch));
    assert_eq!(r.ledger().head_root(), s.head_root());
    assert_eq!(r.ledger().len(), 3);
    assert_eq!(r.snapshot().unwrap().root, a3.checkpoint.state_root);
    assert!(r.halted.is_none());
    // The replica's live state is the sequencer's live state up to the
    // finality intents that landed after the last anchor.
    let seq_state = s.shared.lock().unwrap().state().clone();
    assert_eq!(r.state().epoch(), seq_state.epoch());
    assert_eq!(
        a1.checkpoint.epoch, 1,
        "first anchor covered epochs 0 and 1"
    );
    // Seeing the same anchors again changes nothing.
    let p = r
        .apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();
    assert_eq!((p.verified, p.skipped), (0, 3));
    // And the replica re-serves a complete, verifiable copy.
    let (mut second, _) = replica("reproduce-2");
    second
        .apply_sightings(&s.sightings, &Local(r.da_dir()))
        .unwrap();
    assert_eq!(second.ledger().head_root(), s.head_root());
}

#[test]
fn a_flipped_byte_in_any_artefact_is_detected_and_the_replica_stops() {
    let mut s = Seq::new("tamper");
    s.trade(8);
    let a = s.anchor();
    let rel = publish::rel_dir(CHAIN, a.checkpoint.epoch);
    for file in [
        "anchor.bin",
        "certificate.bin",
        "published.bin",
        "intents/epoch-0.intents",
        "intents/epoch-1.intents",
    ] {
        let bad_da = tmp(&format!("tamper-{}", file.replace('/', "-")));
        copy_dir(&s.da, &bad_da);
        let path = bad_da.join(&rel).join(file);
        let mut bytes = std::fs::read(&path).unwrap();
        let i = bytes.len() - 5;
        bytes[i] ^= 0x10;
        std::fs::write(&path, &bytes).unwrap();
        let (mut r, _) = replica(&format!("tamper-{}", file.replace('/', "-")));
        let err = r.apply_sightings(&s.sightings, &Local(bad_da)).unwrap_err();
        assert!(
            matches!(err, Halt::BadBundle { .. } | Halt::Diverged { .. }),
            "{}: {:?}",
            file,
            err
        );
        assert_eq!(r.verified_epoch, None, "{}: nothing may be believed", file);
        assert!(r.halted.is_some());
        // Halted stays halted: a later good sighting does not un-halt it.
        assert!(r
            .apply_sightings(&s.sightings, &Local(s.da.clone()))
            .is_err());
    }
}

#[test]
fn a_second_anchor_for_the_same_epoch_is_a_fork_and_the_replica_stops() {
    let mut s = Seq::new("fork");
    s.trade(8);
    let a = s.anchor();
    let (mut r, _) = replica("fork");
    r.apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();
    let mut rival = s.sightings[0];
    rival.id = [0xEE; 32];
    rival.height += 1;
    let err = r
        .apply_sightings(&[rival], &Local(s.da.clone()))
        .unwrap_err();
    assert_eq!(
        err,
        Halt::Fork {
            epoch: a.checkpoint.epoch,
            seen: a.id(),
            other: [0xEE; 32]
        }
    );
    assert_eq!(
        r.verified_epoch,
        Some(a.checkpoint.epoch),
        "the verified root stands"
    );
}

#[test]
fn a_holder_exit_proof_from_the_replica_verifies_against_the_anchored_root() {
    let mut s = Seq::new("exit");
    s.trade(8);
    let a = s.anchor();
    let (mut r, _) = replica("exit");
    r.apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();
    let snap = r.snapshot().unwrap();
    let holder = [3u8; 32];
    let (record, _index, path) = snap
        .record_proof(&holder)
        .expect("a depositor has a record");
    assert!(
        verify_record::<SwapState>(&record, &path, a.checkpoint.state_root),
        "the exit proof must open the anchored root"
    );
    let mut wrong = record.clone();
    wrong[0] ^= 1;
    assert!(!verify_record::<SwapState>(
        &wrong,
        &path,
        a.checkpoint.state_root
    ));
}

#[test]
fn a_replica_resumes_from_disk_and_continues() {
    let mut s = Seq::new("resume");
    s.trade(8);
    s.anchor();
    s.trade(4);
    let a2 = s.anchor();
    let (mut r, dir) = replica("resume");
    r.apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();
    assert_eq!(r.verified_epoch, Some(a2.checkpoint.epoch));
    drop(r);
    s.trade(4);
    let a3 = s.anchor();
    let mut back = Replica::open(&dir, CHAIN, Params::testnet()).unwrap();
    assert_eq!(back.verified_epoch, Some(a2.checkpoint.epoch));
    assert_eq!(
        back.snapshot().map(|p| p.root),
        Some(a2.checkpoint.state_root)
    );
    let p = back
        .apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();
    assert_eq!((p.verified, p.skipped), (1, 2));
    assert_eq!(back.verified_epoch, Some(a3.checkpoint.epoch));
    assert_eq!(back.ledger().head_root(), s.head_root());
}

#[test]
fn a_missing_mirror_is_reported_not_believed() {
    let mut s = Seq::new("nomirror");
    s.trade(8);
    s.anchor();
    let (mut r, _) = replica("nomirror");
    struct Nothing;
    impl Fetch for Nothing {
        fn get(&self, rel: &str) -> Result<Vec<u8>, String> {
            Err(format!("no such file {}", rel))
        }
    }
    assert!(matches!(
        r.apply_sightings(&s.sightings, &Nothing).unwrap_err(),
        Halt::Fetch { .. }
    ));
}

/// A chain older than its journal: the replica starts from an attested base
/// and replays everything after it.
#[test]
fn a_replica_starts_from_an_attested_base_when_the_journal_is_younger_than_the_chain() {
    let mut s = Seq::new("base");
    // History from before the journal existed: trade, then throw the journal
    // away and "upgrade" — reboot into manual anchoring, which writes the base.
    s.trade(8);
    let before = s.shared.lock().unwrap().state().state_root();
    boot::save(&s.store, &s.journal, &s.shared);
    std::fs::remove_dir_all(s.dir.join("journal")).unwrap();
    // Before the upgrade nothing waited on a trip to Zcash, so no pending
    // epochs were on disk either.
    for e in std::fs::read_dir(&s.dir).unwrap().flatten() {
        if e.file_name().to_string_lossy().ends_with(".sealed") {
            std::fs::remove_file(e.path()).unwrap();
        }
    }
    let _ = std::fs::remove_dir_all(&s.da);
    drop(std::mem::replace(
        &mut s.journal,
        Arc::new(Mutex::new(zyn::journal::Journal::open(&s.dir, 99).unwrap())),
    ));
    let policy = EpochPolicy {
        intents_per_epoch: 4,
        epochs_per_anchor: 100,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let b = boot::open_at(
        &s.dir,
        CHAIN,
        Params::testnet(),
        policy,
        Economics::flat(1),
        0,
        true,
        &s.da,
    )
    .unwrap();
    let base_root = b.base_root.expect("manual boot writes the base");
    assert_eq!(
        base_root, before,
        "the base is the state at the moment journaling began"
    );
    s.shared = Arc::new(Mutex::new(b.node));
    s.store = b.store;
    s.journal = b.journal;
    let base_bytes = std::fs::read(s.da.join(format!("chain-{}/base.state", CHAIN))).unwrap();

    s.trade(4);
    let a = s.anchor();
    assert_eq!(a.epochs, 1, "only the journaled epoch is anchored");

    let dir = tmp("base-rep");
    let err = Replica::open_from(
        &dir,
        CHAIN,
        Params::testnet(),
        Some((&base_bytes, [9u8; 32])),
    )
    .map(|_| ())
    .unwrap_err();
    assert!(err.contains("attested root"), "{}", err);
    let mut r = Replica::open_from(
        &dir,
        CHAIN,
        Params::testnet(),
        Some((&base_bytes, base_root)),
    )
    .unwrap();
    let p = r
        .apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();
    assert_eq!(p.verified, 1);
    assert_eq!(r.ledger().head_root(), a.checkpoint.state_root);
    // From genesis it cannot: the journaled epochs do not start there.
    let (mut g, _) = replica("base-genesis");
    assert!(g
        .apply_sightings(&s.sightings, &Local(s.da.clone()))
        .is_err());
}

// --- rung 1: forced inclusion ---

fn forced_frame_for(key_seed: u8, epoch: u64) -> (zyn_custody::shielded::ForcedSighting, [u8; 32]) {
    use ed25519_dalek::SigningKey;
    let k = SigningKey::from_bytes(&[key_seed; 32]);
    let intent = Intent::Transfer {
        from: zynzapd::client::account(&k),
        to: [0xAB; 32],
        asset: XZEC,
        amount: Fixed::whole(1),
    };
    let frame = zynzapd::client::frame_submission(&k, CHAIN, epoch, &intent);
    let hash = zynzapd::replica::intent_hash(&swapvm::wire::encode_intent_bytes(&intent));
    (
        zyn_custody::shielded::ForcedSighting {
            txid: [key_seed; 32],
            height: 4_400_000,
            amount: Fixed::raw(1),
            frame,
        },
        hash,
    )
}

#[test]
fn a_forced_intent_the_sequencer_ignores_is_reported_as_censorship_after_the_grace() {
    let mut s = Seq::new("censor");
    let (mut r, _) = replica("censor");
    let epoch = s.shared.lock().unwrap().state().epoch();
    let (sighting, _) = forced_frame_for(7, epoch);
    assert_eq!(r.note_forced(&[sighting.clone()]), 1);
    assert_eq!(r.note_forced(&[sighting.clone()]), 0, "noted once");
    assert_eq!(r.forced_pending().len(), 1);
    // Junk and a foreign-chain frame are not owed.
    let mut junk = sighting.clone();
    junk.txid = [8; 32];
    junk.frame = b"nope".to_vec();
    assert_eq!(r.note_forced(&[junk]), 0);
    // Anchors before the grace: still pending, not censorship.
    s.trade(8);
    s.next_height = 4_400_000 + zynzapd::replica::FORCED_GRACE - 1;
    s.anchor();
    r.apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();
    assert_eq!(r.forced_pending().len(), 1);
    assert!(r.censored().is_empty());
    // An anchor at or past the grace without it: censorship, recorded.
    s.trade(4);
    s.next_height = 4_400_000 + zynzapd::replica::FORCED_GRACE;
    s.anchor();
    r.apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();
    assert!(r.forced_pending().is_empty());
    assert_eq!(r.censored().len(), 1);
    assert_eq!(r.censored()[0].txid, [7; 32]);
    assert!(
        r.halted.is_none(),
        "censorship is an alarm, not a halt: the roots are still right"
    );
}

#[test]
fn a_forced_intent_the_sequencer_applies_is_satisfied() {
    let mut s = Seq::new("satisfied");
    let (mut r, dir) = replica("satisfied");
    let epoch = s.shared.lock().unwrap().state().epoch();
    let (sighting, hash) = forced_frame_for(9, epoch);
    r.note_forced(&[sighting.clone()]);
    // The sequencer applies exactly that intent (as the bridge would), then anchors.
    {
        let mut n = s.shared.lock().unwrap();
        let (cred, auth, intent) = zynzapd::rpc::decode_frame(CHAIN, &sighting.frame).unwrap();
        assert_eq!(
            zynzapd::replica::intent_hash(&swapvm::wire::encode_intent_bytes(&intent)),
            hash
        );
        let authorized =
            zyn::verify::authorize_intent(std::slice::from_ref(&cred), &auth, intent, n.state())
                .unwrap();
        let step = n.submit(authorized, 0);
        assert!(
            step.rejected(),
            "unfunded, so the VM rejects it — still included"
        );
    }
    s.trade(4);
    s.next_height = 4_400_000 + zynzapd::replica::FORCED_GRACE + 5;
    s.anchor();
    r.apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();
    assert!(r.forced_pending().is_empty());
    assert!(
        r.censored().is_empty(),
        "applied in time, even though rejected"
    );
    // The record survives a restart.
    drop(r);
    let back = Replica::open(&dir, CHAIN, Params::testnet()).unwrap();
    assert!(back.censored().is_empty());
    assert!(back.note_forced_seen(&[9; 32]));
}

// --- rung 2: a replica that requires endorsement ---

#[test]
fn a_replica_requiring_endorsement_halts_on_an_unendorsed_root_and_believes_a_full_one() {
    use ed25519_dalek::{Signer, SigningKey};
    let keys: Vec<SigningKey> = (1..=3u8)
        .map(|i| SigningKey::from_bytes(&[i; 32]))
        .collect();
    let set = zyn::anchor::SignerSet::new(
        keys.iter().map(|k| k.verifying_key().to_bytes()).collect(),
        2,
    )
    .unwrap();

    // A sequencer that anchors as trusted-operator (empty certificates).
    let mut s = Seq::new("unendorsed");
    s.trade(8);
    let a = s.anchor();
    let dir = tmp("unendorsed-rep");
    let mut r = Replica::open(&dir, CHAIN, Params::testnet())
        .unwrap()
        .requiring(set.clone());
    let err = r
        .apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap_err();
    assert!(matches!(err, Halt::Unendorsed { need: 2, .. }), "{:?}", err);
    assert_eq!(r.verified_epoch, None, "an unendorsed root is not believed");

    // Rewrite that anchor's certificate with two real endorsements, as the
    // signer path would have produced, and a fresh replica believes it.
    let mut cert = zyn::anchor::Certificate::new(a.id());
    cert.add(
        keys[0].verifying_key().to_bytes(),
        keys[0].sign(&a.id()).to_bytes(),
    )
    .unwrap();
    cert.add(
        keys[1].verifying_key().to_bytes(),
        keys[1].sign(&a.id()).to_bytes(),
    )
    .unwrap();
    let cert_path =
        s.da.join(publish::rel_dir(CHAIN, a.checkpoint.epoch))
            .join("certificate.bin");
    std::fs::write(&cert_path, cert.encode()).unwrap();
    let dir2 = tmp("endorsed-rep");
    let mut r2 = Replica::open(&dir2, CHAIN, Params::testnet())
        .unwrap()
        .requiring(set);
    let p = r2
        .apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();
    assert_eq!(p.verified, 1, "an endorsed root is believed");
    assert_eq!(r2.verified_epoch, Some(a.checkpoint.epoch));
    // And it exposes the anchor for a signer to endorse.
    assert_eq!(r2.take_newly_verified().len(), 1);
}

// ------------------------------------------------------------------
// Deposit backing: endorsement means the money was seen, not only that
// the arithmetic was honest.
// ------------------------------------------------------------------

/// A chain view under the test's control.
struct FakeBacking {
    /// Credits this view refuses to confirm, by external_ref.
    missing: std::collections::BTreeSet<[u8; 32]>,
    /// Every credit it was asked about.
    asked: Mutex<Vec<zynzapd::backing::SeenCredit>>,
}

impl FakeBacking {
    fn accepting() -> FakeBacking {
        FakeBacking {
            missing: Default::default(),
            asked: Mutex::new(Vec::new()),
        }
    }
}

impl zynzapd::backing::Backing for FakeBacking {
    fn check(&self, credits: &[zynzapd::backing::SeenCredit]) -> Result<(), String> {
        self.asked.lock().unwrap().extend_from_slice(credits);
        for c in credits {
            if self.missing.contains(&c.external_ref) {
                return Err(format!(
                    "credited against {:02x?}, which our node does not have",
                    &c.external_ref[..4]
                ));
            }
        }
        Ok(())
    }
}

/// The credits really are found in the replayed intents, and a backing that
/// confirms them changes nothing about what the replica concludes.
#[test]
fn a_backed_replica_sees_every_credit_and_still_reproduces_the_root() {
    let mut s = Seq::new("backed");
    s.trade(8);
    let a1 = s.anchor();

    let backing = std::sync::Arc::new(FakeBacking::accepting());
    struct Shared(std::sync::Arc<FakeBacking>);
    impl zynzapd::backing::Backing for Shared {
        fn check(&self, c: &[zynzapd::backing::SeenCredit]) -> Result<(), String> {
            self.0.check(c)
        }
    }

    let dir = tmp("backed-rep");
    let mut r = Replica::open(&dir, CHAIN, Params::testnet())
        .unwrap()
        .backed_by(Box::new(Shared(std::sync::Arc::clone(&backing))));
    let p = r
        .apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();

    assert_eq!((p.verified, p.skipped), (1, 0));
    assert_eq!(r.verified_epoch, Some(a1.checkpoint.epoch));
    assert!(r.halted.is_none());

    // It was actually asked, and about exactly the credits the anchor covers:
    // epochs 0 and 1 at four intents each, the first of which is the vault
    // attestation, so seven of the eight deposits. The eighth is still in an
    // unsealed epoch and is nobody's to check yet.
    let asked = backing.asked.lock().unwrap();
    assert_eq!(asked.len(), 7, "every credit the anchor covers was checked");
    assert!(asked
        .iter()
        .all(|c| c.asset == XZEC && c.amount == Fixed::whole(1)));
    // Indices are the vault's, and distinct.
    let mut idx: Vec<u64> = asked.iter().map(|c| c.index).collect();
    idx.sort_unstable();
    idx.dedup();
    assert_eq!(idx.len(), 7, "seven distinct deposit indices");
}

/// The fabrication this closes: a credit whose transaction the verifier's own
/// node cannot show. The root still reproduces — that is the point — so
/// nothing but the backing check catches it.
#[test]
fn a_credit_the_chain_does_not_show_is_refused_and_the_replica_will_not_endorse() {
    let mut s = Seq::new("unbacked");
    s.trade(8);
    let a1 = s.anchor();

    // The deposits in this fixture all carry external_ref [0u8; 32], so
    // refusing that one refuses the epoch.
    let mut missing = std::collections::BTreeSet::new();
    missing.insert([0u8; 32]);
    let backing = FakeBacking {
        missing,
        asked: Mutex::new(Vec::new()),
    };

    let dir = tmp("unbacked-rep");
    let mut r = Replica::open(&dir, CHAIN, Params::testnet())
        .unwrap()
        .backed_by(Box::new(backing));
    let err = r
        .apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap_err();

    assert!(matches!(err, Halt::Unbacked { .. }), "{:?}", err);
    assert!(
        matches!(r.halted, Some(Halt::Unbacked { .. })),
        "halted: {:?}",
        r.halted
    );
    assert_eq!(r.verified_epoch, None, "it did not advance past the epoch");
    assert!(
        r.take_newly_verified().is_empty(),
        "a signer has nothing to endorse"
    );
    let msg = r.halted.as_ref().unwrap().to_string();
    assert!(msg.contains("UNBACKED"), "{}", msg);

    // The same bundle, believed by a replica with no chain view of its own:
    // the root reproduces perfectly. Reproducing a root is not the same
    // question as whether the money exists.
    let (mut blind, _) = replica("unbacked-blind");
    let p = blind
        .apply_sightings(&s.sightings, &Local(s.da.clone()))
        .unwrap();
    assert_eq!(p.verified, 1);
    assert_eq!(blind.verified_epoch, Some(a1.checkpoint.epoch));
}

/// Epoch N was reorged off Zcash and re-sent, so its transaction sits far
/// ahead of the epochs that were built on it. A replica scanning forward in
/// windows therefore meets N+1 while N's block is still ahead of its cursor.
/// While there is chain left to read that is an *incomplete view*, not a
/// broken chain — and holding it is what keeps an honest signer in the set
/// instead of latching a halt that drops the set below threshold (§62).
#[test]
fn a_lineage_break_is_held_while_the_scan_is_behind_and_clears_when_the_repair_arrives() {
    let mut s = Seq::new("deferred-repair");
    s.trade(8);
    let _a1 = s.anchor();
    s.trade(4);
    let _a2 = s.anchor();
    s.trade(4);
    let a3 = s.anchor();

    let first = s.sightings[0];
    let repaired = s.sightings[1]; // its block is still ahead of the cursor
    let later = s.sightings[2];

    let (mut r, _) = replica("deferred-repair");
    let da = Local(s.da.clone());

    // A window carrying the first and third anchors, but not the repair.
    let p = r
        .apply_sightings_scanned(&[first, later], &da, false)
        .unwrap();
    assert_eq!(
        p.verified, 1,
        "only the anchor that continues the lineage applies"
    );
    assert_eq!(
        p.deferred, 1,
        "the rest is held for a later pass, not rejected"
    );
    assert!(
        r.halted.is_none(),
        "an incomplete view must never latch a halt"
    );

    // A later window reaches the block holding the repair.
    let p = r.apply_sightings_scanned(&[repaired], &da, true).unwrap();
    assert_eq!(
        p.verified, 2,
        "the repair, and the anchor that was waiting on it"
    );
    assert!(r.halted.is_none());
    assert_eq!(r.verified_epoch, Some(a3.checkpoint.epoch));
    assert_eq!(
        r.ledger().head_root(),
        s.head_root(),
        "the same root, reached the long way round"
    );
}

/// The same break, once the whole safe range has been read, is a real break:
/// deferring changes when the decision is made, never what is accepted.
#[test]
fn a_lineage_break_that_survives_a_complete_scan_still_halts() {
    let mut s = Seq::new("complete-break");
    s.trade(8);
    let _a1 = s.anchor();
    s.trade(4);
    let _a2 = s.anchor();
    s.trade(4);
    let _a3 = s.anchor();

    let (mut r, _) = replica("complete-break");
    let da = Local(s.da.clone());
    let (first, later) = (s.sightings[0], s.sightings[2]);

    let e = r
        .apply_sightings_scanned(&[first, later], &da, true)
        .unwrap_err();
    assert!(
        matches!(e, Halt::Lineage { .. }),
        "expected a lineage halt, got {:?}",
        e
    );
    assert!(r.halted.is_some(), "a break on a complete view is final");
}
