//! The verifying replica: everything the sequencer claims, checked.
//!
//! A replica holds the vault's *viewing* key and nothing that can spend. It
//! finds the vault's anchor self-sends on Zcash, fetches each anchor's bundle
//! from any mirror, and refuses to believe a root until it has reproduced it:
//! the anchor must hash to the id in the memo, continue the lineage, and be
//! the checkpoint that replaying the published intents from the last verified
//! state actually produces; the published leaves must open it.
//!
//! What it never does is guess. A byte out of place, a second anchor for an
//! epoch, a root the inputs do not produce — it stops, says so, and keeps
//! serving the last root it verified. A verifier that advanced past a
//! contradiction would be worth less than none.
//!
//! Its verified state is a `Saved` a sequencer can resume from, and its
//! verified pending-exit list is what a signer attests to: the standby and the
//! signer are this process with one more job each.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use swapvm::state::SwapState;
use swapvm::Params;
use zyn::anchor::{Anchor, AnchorId, Certificate, Ledger, LineageError};
use zyn::da::{Published, Snapshot};
use zyn::journal::{self, EpochFile, ReplayError};
use zyn::store::{FileStore, Saved};
use zyn_custody::shielded::{AnchorSighting, ForcedSighting};
use zyn_vm::spec::MicrochainVm;

use crate::publish::{self, Bundle};

/// An anchor memo seen on Zcash, parsed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Sighting {
    pub height: u64,
    pub txid: [u8; 32],
    pub chain_id: u32,
    pub epoch: u64,
    pub id: AnchorId,
}

/// This chain's sightings, in the order the anchors chain — by epoch, not by
/// the height Zcash happened to see them at.
///
/// A *repaired* anchor, re-sent after a reorg removed the original, lands at
/// today's height and therefore after everything built on top of it. Ordering
/// by height presents such a chain out of order and the lineage check fails on
/// a chain that is whole. `previous_root` is still checked at every step, so
/// this decides what is *offered*, never what is *accepted*.
fn in_lineage_order(sightings: &[Sighting], chain_id: u32) -> Vec<&Sighting> {
    let mut v: Vec<&Sighting> = sightings
        .iter()
        .filter(|s| s.chain_id == chain_id)
        .collect();
    v.sort_by_key(|s| (s.epoch, s.height));
    v
}

pub fn sighting_from(s: &AnchorSighting) -> Option<Sighting> {
    let (chain_id, epoch, id) = Anchor::parse_memo(&s.memo)?;
    Some(Sighting {
        height: s.height,
        txid: s.txid,
        chain_id,
        epoch,
        id,
    })
}

/// Where bundle files come from. A directory for tests and for a replica's own
/// copy; HTTP mirrors in production.
pub trait Fetch {
    fn get(&self, rel: &str) -> Result<Vec<u8>, String>;
}

pub struct Local(pub PathBuf);

impl Fetch for Local {
    fn get(&self, rel: &str) -> Result<Vec<u8>, String> {
        fs::read(self.0.join(rel)).map_err(|e| format!("{}: {}", rel, e))
    }
}

/// Tries mirrors in order; the first that answers wins. Bad bytes are caught
/// by the caller's checks, so a lying mirror costs one retry, not a belief.
pub struct Http {
    mirrors: Vec<String>,
    agent: ureq::Agent,
}

impl Http {
    pub fn new(mirrors: Vec<String>) -> Http {
        Http {
            mirrors: mirrors
                .into_iter()
                .map(|m| m.trim_end_matches('/').to_string())
                .collect(),
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(20))
                .build(),
        }
    }
}

impl Fetch for Http {
    fn get(&self, rel: &str) -> Result<Vec<u8>, String> {
        let mut last = "no mirrors configured".to_string();
        for m in &self.mirrors {
            match self.agent.get(&format!("{}/{}", m, rel)).call() {
                Ok(r) => {
                    let mut body = Vec::new();
                    if let Err(e) = std::io::Read::read_to_end(&mut r.into_reader(), &mut body) {
                        last = format!("{}: {}", m, e);
                        continue;
                    }
                    return Ok(body);
                }
                Err(e) => last = format!("{}/{}: {}", m, rel, e),
            }
        }
        Err(last)
    }
}

/// Why the replica stopped advancing. Every one is a contradiction between
/// things that should agree, and every one is worth a human's attention.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Halt {
    /// Two anchors for one epoch with different ids on the chain.
    Fork {
        epoch: u64,
        seen: AnchorId,
        other: AnchorId,
    },
    /// The anchor does not continue the verified lineage.
    Lineage { epoch: u64, error: LineageError },
    /// A bundle file is not what the anchor says it is.
    BadBundle { epoch: u64, what: String },
    /// A credit in this epoch is not backed by anything the verifier's own
    /// node can see. The arithmetic was honest; the inputs were not.
    Unbacked { epoch: u64, what: String },
    /// Replaying the published intents does not reach the anchored root.
    Diverged { epoch: u64, seq: u64 },
    /// No mirror would hand over a file.
    Fetch { epoch: u64, error: String },
    /// The certificate does not clear the set this replica requires.
    Unendorsed {
        epoch: u64,
        have: usize,
        need: usize,
    },
}

impl std::fmt::Display for Halt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Halt::Fork { epoch, seen, other } => write!(f, "FORK at epoch {}: anchors {} and {} both claim it", epoch, rawhex(seen), rawhex(other)),
            Halt::Lineage { epoch, error } => write!(f, "LINEAGE break at epoch {}: {:?}", epoch, error),
            Halt::BadBundle { epoch, what } => write!(f, "BAD BUNDLE for epoch {}: {}", epoch, what),
            Halt::Diverged { epoch, seq } => write!(f, "ROOT UNREPRODUCIBLE at epoch {} (seq {}): the anchored root is not what its own intents produce", epoch, seq),
            Halt::Fetch { epoch, error } => write!(f, "MIRRORS DOWN for epoch {}: {}", epoch, error),
            Halt::Unendorsed { epoch, have, need } => write!(f, "UNENDORSED anchor at epoch {}: {} of {} signatures — not enough of the set reproduced this root", epoch, have, need),
            Halt::Unbacked { epoch, what } => write!(f, "UNBACKED credit at epoch {}: {}", epoch, what),
        }
    }
}

/// Blocks a forced intent may wait before its absence is censorship: the
/// sequencer's confirmation depth, a couple of anchor intervals, and slack.
pub const FORCED_GRACE: u64 = 20;

/// How long a censorship event stays *current* for alerting, in Zcash blocks.
///
/// The record is permanent — a sequencer that censored once did, and
/// [`Replica::censored`] keeps it. But a pager is about what is happening now,
/// and an alarm that can never clear is one people learn to scroll past. Ten
/// grace periods is long enough that an operator cannot miss a live incident,
/// and short enough that a demonstration run in the past stops shouting.
pub const CENSORSHIP_CURRENT: u64 = FORCED_GRACE * 10;

/// A forced intent the replica is holding the sequencer to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ForcedPending {
    pub height: u64,
    pub txid: [u8; 32],
    /// `sha256(encode_intent(intent))` — what the journal will show if it is applied.
    pub intent_hash: [u8; 32],
}

/// A forced intent the sequencer did not apply in time. The roots are still
/// right; the operator is refusing service, and this is the record of it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Censored {
    pub height: u64,
    pub txid: [u8; 32],
    /// The anchor height by which it was due and was not there.
    pub due_at: u64,
}

/// What one pass did.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Progress {
    pub verified: usize,
    pub skipped: usize,
    /// Sightings held for a later pass because the scan has not yet reached
    /// the block carrying an older epoch they depend on.
    pub deferred: usize,
}

pub struct Replica {
    pub chain_id: u32,
    dir: PathBuf,
    store: FileStore,
    ledger: Ledger,
    state: SwapState,
    /// The snapshot at the last verified root, exactly as the sequencer
    /// published it.
    published: Option<Snapshot<SwapState>>,
    pub verified_epoch: Option<u64>,
    pub verified_height: u64,
    pub halted: Option<Halt>,
    seen: BTreeMap<u64, AnchorId>,
    /// Forced intents seen on Zcash, not yet found in the journal.
    pending_forced: Vec<ForcedPending>,
    /// Forced intents whose grace ran out unapplied.
    censored: Vec<Censored>,
    /// Hashes of intents applied since the earliest pending sighting.
    applied: BTreeSet<[u8; 32]>,
    /// Txids of forced sightings already noted (pending, resolved or censored).
    noted: BTreeSet<[u8; 32]>,
    /// Anchors verified since the last drain — for a signer to endorse.
    newly_verified: Vec<(AnchorId, [u8; 32])>,
    /// Sightings that did not continue the lineage while the scan was still
    /// behind the chain tip, kept for a later pass.
    deferred: Vec<Sighting>,
    /// If set, an anchor's certificate must clear this set to be believed.
    require_set: Option<zyn::anchor::SignerSet>,
    /// A verifier's own view of the custodying chain, when it has one. With
    /// it, endorsement means the money was seen; without, it means only that
    /// the root is what the published intents produce.
    backing: Option<Box<dyn crate::backing::Backing + Send>>,
}

impl Replica {
    /// Resume from `dir` if a verified state is there, else start at genesis.
    pub fn open(dir: &Path, chain_id: u32, params: Params) -> Result<Replica, String> {
        Self::open_from(dir, chain_id, params, None)
    }

    /// Like [`Self::open`], but a chain that predates its journal starts from
    /// an operator-attested **base**: a `Saved` state whose root the operator
    /// announced. Everything after the base is replayed; the base itself is
    /// the one thing taken on the operator's word, and its root is what a
    /// replica's operator has to have checked out of band.
    pub fn open_from(
        dir: &Path,
        chain_id: u32,
        params: Params,
        base: Option<(&[u8], [u8; 32])>,
    ) -> Result<Replica, String> {
        let store = FileStore::new(dir).map_err(|e| format!("{:?}", e))?;
        let ledger = store
            .load_ledger(chain_id)
            .map_err(|e| format!("verified ledger unreadable: {:?}", e))?
            .unwrap_or_else(|| Ledger::new(chain_id));
        let state: SwapState = match store.load(chain_id).map_err(|e| format!("{:?}", e))? {
            Some(saved) => saved
                .restore()
                .map_err(|e| format!("verified state does not match its root: {:?}", e))?,
            None => match base {
                Some((bytes, root)) => {
                    let saved = Saved::decode(bytes)
                        .map_err(|e| format!("base state does not decode: {:?}", e))?;
                    if saved.chain_id != chain_id {
                        return Err("base state is for another chain".into());
                    }
                    if saved.root != root {
                        return Err(format!(
                            "base state root {} is not the attested root {}",
                            hex(&saved.root),
                            hex(&root)
                        ));
                    }
                    let s: SwapState = saved
                        .restore()
                        .map_err(|e| format!("base state does not match its root: {:?}", e))?;
                    store.save(&saved).map_err(|e| format!("{:?}", e))?;
                    s
                }
                None => SwapState::new(chain_id, params),
            },
        };
        if let Some(last) = ledger.last() {
            if last.checkpoint.epoch >= state.epoch() {
                return Err("the verified state on disk is older than the verified ledger".into());
            }
        }
        let seen = ledger
            .anchors()
            .iter()
            .map(|a| (a.checkpoint.epoch, a.id()))
            .collect();
        let verified_epoch = ledger.last().map(|a| a.checkpoint.epoch);
        let verified_height = fs::read_to_string(dir.join(format!("verified-{}.height", chain_id)))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let published = verified_epoch.and_then(|e| {
            let b = fs::read(
                dir.join("da")
                    .join(publish::rel_dir(chain_id, e))
                    .join("snapshot.bin"),
            )
            .ok()?;
            Snapshot::<SwapState>::decode(&b)
        });
        let (pending_forced, censored, noted) = load_forced(dir, chain_id);
        Ok(Replica {
            chain_id,
            dir: dir.to_path_buf(),
            store,
            ledger,
            state,
            published,
            verified_epoch,
            verified_height,
            halted: None,
            seen,
            pending_forced,
            censored,
            applied: BTreeSet::new(),
            noted,
            newly_verified: Vec::new(),
            deferred: Vec::new(),
            require_set: None,
            backing: None,
        })
    }

    /// Refuse to advance past an anchor whose certificate does not clear this
    /// set — for a replica that only believes k-of-n-endorsed roots.
    pub fn requiring(mut self, set: zyn::anchor::SignerSet) -> Replica {
        self.require_set = Some(set);
        self
    }

    /// Check every credit against this view of the custodying chain before
    /// believing an epoch. Without one a replica still proves the root is what
    /// the intents produce — it just cannot tell whether the intents were true.
    pub fn backed_by(mut self, backing: Box<dyn crate::backing::Backing + Send>) -> Replica {
        self.backing = Some(backing);
        self
    }

    /// The `(anchor_id, root)` pairs verified since the last call — what a
    /// signer signs. Draining, so each is endorsed once.
    pub fn take_newly_verified(&mut self) -> Vec<(AnchorId, [u8; 32])> {
        std::mem::take(&mut self.newly_verified)
    }

    pub fn forced_pending(&self) -> &[ForcedPending] {
        &self.pending_forced
    }

    pub fn censored(&self) -> &[Censored] {
        &self.censored
    }

    /// Whether a forced sighting was already taken note of (pending, satisfied or censored).
    pub fn note_forced_seen(&self, txid: &[u8; 32]) -> bool {
        self.noted.contains(txid)
    }

    /// Take note of forced intents seen on Zcash. A frame that does not decode
    /// or does not verify is nobody's intent and is dropped; the rest the
    /// sequencer now owes.
    pub fn note_forced(&mut self, sightings: &[ForcedSighting]) -> usize {
        let mut added = 0;
        for s in sightings {
            if self.noted.contains(&s.txid) {
                continue;
            }
            self.noted.insert(s.txid);
            let Ok((cred, auth, intent)) = crate::rpc::decode_frame(self.chain_id, &s.frame) else {
                continue;
            };
            let Ok(authorized) = zyn::verify::authorize_intent::<SwapState>(
                core::slice::from_ref(&cred),
                &auth,
                intent,
                &self.state,
            ) else {
                continue;
            };
            let intent_hash =
                intent_hash(&zyn::verify::encode_authorized::<SwapState>(&authorized));
            self.pending_forced.push(ForcedPending {
                height: s.height,
                txid: s.txid,
                intent_hash,
            });
            added += 1;
        }
        if added > 0 {
            let _ = save_forced(
                &self.dir,
                self.chain_id,
                &self.pending_forced,
                &self.censored,
                &self.noted,
            );
        }
        added
    }

    /// After an anchor at `height` is verified: which pending forced intents
    /// were applied, and which are now overdue.
    fn resolve_forced(&mut self, anchor_height: u64) -> Vec<Censored> {
        let mut newly = Vec::new();
        let mut keep = Vec::new();
        for p in std::mem::take(&mut self.pending_forced) {
            if self.applied.contains(&p.intent_hash) {
                eprintln!("zyn-replica: forced intent from Zcash {} was applied by the sequencer — satisfied", hex(&p.txid));
            } else if p.height.saturating_add(FORCED_GRACE) <= anchor_height {
                let c = Censored {
                    height: p.height,
                    txid: p.txid,
                    due_at: anchor_height,
                };
                self.censored.push(c.clone());
                newly.push(c);
            } else {
                keep.push(p);
            }
        }
        self.pending_forced = keep;
        if self.pending_forced.is_empty() {
            self.applied.clear();
        }
        let _ = save_forced(
            &self.dir,
            self.chain_id,
            &self.pending_forced,
            &self.censored,
            &self.noted,
        );
        newly
    }

    pub fn state(&self) -> &SwapState {
        &self.state
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// The snapshot a holder proves against — the one at the verified root.
    pub fn snapshot(&self) -> Option<&Snapshot<SwapState>> {
        self.published.as_ref()
    }

    /// Where this replica re-serves what it verified.
    pub fn da_dir(&self) -> PathBuf {
        self.dir.join("da")
    }

    /// Consume anchors seen on Zcash, **in lineage order**. Stops at the first
    /// contradiction and records it in `halted`.
    ///
    /// Ordered by epoch rather than by block height. Height is where Zcash
    /// happened to see a transaction, and a *repaired* anchor — one re-sent
    /// after a reorg removed the original — necessarily lands at today's
    /// height, long after the anchors that were built on top of it. Sorting by
    /// height then presents the chain out of order and the lineage check fails
    /// on a chain that is in fact whole. Epoch order is the order the anchors
    /// chain in, and `previous_root` still has to match at every step, so
    /// nothing is trusted that was not before: the sort decides what is
    /// *offered*, never what is *accepted* (§50.14).
    /// Apply what has been sighted, treating the sightings as a complete view
    /// of the chain. Equivalent to `apply_sightings_scanned(.., true)`.
    pub fn apply_sightings(
        &mut self,
        sightings: &[Sighting],
        fetch: &dyn Fetch,
    ) -> Result<Progress, Halt> {
        self.apply_sightings_scanned(sightings, fetch, true)
    }

    /// Apply what has been sighted so far.
    ///
    /// `scan_complete` says whether the caller has read Zcash all the way to
    /// its safe tip. It matters because a **repaired** anchor — one re-sent
    /// after a reorg dropped the original — carries its original epoch but
    /// lands at *today's* height, thousands of blocks ahead of the epochs
    /// built on top of it. A replica scanning forward in windows therefore
    /// meets epoch N+1 while the block carrying epoch N is still ahead of its
    /// cursor.
    ///
    /// That is an **incomplete view, not a broken chain**, and the two are
    /// indistinguishable from the failing step alone — which is why the scan
    /// position, not the error, decides. While the scan is behind, the
    /// offending sighting and everything after it are held for a later pass;
    /// only once the whole safe range has been read does a break that still
    /// stands become a halt. Latching early is what takes an honest signer
    /// out of the set and stops deposits becoming spendable (§62).
    ///
    /// `previous_root` is still checked at every step, so deferring changes
    /// only *when* a decision is made, never *what* is accepted.
    pub fn apply_sightings_scanned(
        &mut self,
        sightings: &[Sighting],
        fetch: &dyn Fetch,
        scan_complete: bool,
    ) -> Result<Progress, Halt> {
        if let Some(h) = &self.halted {
            return Err(h.clone());
        }
        // Sightings held back earlier are candidates again now that more of
        // the chain has been read.
        let mut all: Vec<Sighting> = std::mem::take(&mut self.deferred);
        for s in sightings {
            if !all.iter().any(|o| o.epoch == s.epoch && o.id == s.id) {
                all.push(*s);
            }
        }
        let ordered: Vec<Sighting> = in_lineage_order(&all, self.chain_id)
            .into_iter()
            .copied()
            .collect();
        let mut progress = Progress::default();
        for (i, s) in ordered.iter().enumerate() {
            match self.seen.get(&s.epoch) {
                Some(id) if *id == s.id => {
                    progress.skipped += 1;
                    continue;
                }
                Some(id) => {
                    let h = Halt::Fork {
                        epoch: s.epoch,
                        seen: *id,
                        other: s.id,
                    };
                    self.halted = Some(h.clone());
                    return Err(h);
                }
                None => {}
            }
            if let Err(h) = self.verify_one(s, fetch) {
                // A file that cannot be fetched is not a contradiction: the
                // publisher may simply be a few seconds behind the chain, or
                // the mirrors may be down. Try again next pass.
                if matches!(h, Halt::Fetch { .. }) {
                    return Err(h);
                }
                // Nor is a lineage break, while there is still chain to read:
                // the parent may be waiting in a block ahead of the cursor.
                if matches!(h, Halt::Lineage { .. }) && !scan_complete {
                    self.deferred = ordered[i..].to_vec();
                    progress.deferred = self.deferred.len();
                    return Ok(progress);
                }
                // Everything else is a contradiction and stops the replica.
                self.halted = Some(h.clone());
                return Err(h);
            }
            progress.verified += 1;
        }
        Ok(progress)
    }

    fn verify_one(&mut self, s: &Sighting, fetch: &dyn Fetch) -> Result<(), Halt> {
        let epoch = s.epoch;
        let rel = publish::rel_dir(self.chain_id, epoch);
        let get = |name: &str| {
            fetch
                .get(&format!("{}/{}", rel, name))
                .map_err(|error| Halt::Fetch { epoch, error })
        };
        let bad = |what: &str| Halt::BadBundle {
            epoch,
            what: what.to_string(),
        };

        // 1. The anchor is the one the chain committed to.
        let anchor_bytes = get("anchor.bin")?;
        let anchor =
            Anchor::decode(&anchor_bytes).ok_or_else(|| bad("anchor.bin does not decode"))?;
        if anchor.id() != s.id {
            return Err(bad("anchor.bin does not hash to the id in the memo"));
        }
        if anchor.checkpoint.epoch != epoch || anchor.checkpoint.chain_id != self.chain_id {
            return Err(bad("anchor.bin is for another epoch or chain"));
        }
        // 2. It continues what was verified before.
        self.ledger
            .check(&anchor)
            .map_err(|error| Halt::Lineage { epoch, error })?;
        let certificate = Certificate::decode(&get("certificate.bin")?)
            .ok_or_else(|| bad("certificate.bin does not decode"))?;
        if certificate.anchor != anchor.id() {
            return Err(bad("certificate.bin is for another anchor"));
        }
        // A replica that only believes endorsed roots checks the certificate
        // clears its set before it will advance past the anchor.
        if let Some(set) = &self.require_set {
            if certificate.verify(&anchor, set).is_err() {
                return Err(Halt::Unendorsed {
                    epoch,
                    have: certificate.weight(set),
                    need: set.threshold(),
                });
            }
        }
        // 3. Its own inputs produce it.
        let last = anchor.checkpoint.epoch;
        let first = last.saturating_add(1).saturating_sub(anchor.epochs);
        let mut files: Vec<EpochFile> = Vec::new();
        for e in first..=last {
            let raw = get(&format!("intents/epoch-{}.intents", e))?;
            let f = journal::read_epoch(&raw)
                .map_err(|e| bad(&format!("intents file is malformed: {:?}", e)))?;
            if f.chain_id != self.chain_id || f.epoch != e {
                return Err(bad("intents file names the wrong chain or epoch"));
            }
            files.push(f);
        }
        if !self.pending_forced.is_empty() {
            for f in &files {
                for (_, bytes) in &f.records {
                    self.applied.insert(intent_hash(bytes));
                }
            }
        }
        let replayed = match journal::replay(self.state.clone(), &files) {
            Ok(r) => r,
            Err(ReplayError::Undecodable { epoch, seq }) => {
                return Err(Halt::BadBundle {
                    epoch,
                    what: format!("intent at seq {} does not decode", seq),
                })
            }
            Err(e) => return Err(bad(&format!("replay refused: {:?}", e))),
        };
        if replayed.checkpoints.last() != Some(&anchor.checkpoint) {
            return Err(Halt::Diverged {
                epoch,
                seq: replayed.state.seq(),
            });
        }
        // 3b. The credits in it are backed by money this verifier can see for
        //     itself. Reproducing the root only proves the sequencer did its
        //     arithmetic over what it published; a fabricated credit
        //     reproduces just as faithfully. This is the step that asks
        //     whether the inputs were true.
        if let Some(backing) = &self.backing {
            backing
                .check(&credits_in(&files))
                .map_err(|what| Halt::Unbacked { epoch, what })?;
        }
        // 4. The published leaves open that root, and are the leaves of the
        //    state just reproduced — the two must be one tree.
        let published = Published::decode(&get("published.bin")?)
            .ok_or_else(|| bad("published.bin does not decode"))?;
        published.verify().map_err(|e| {
            bad(&format!(
                "published.bin does not open its own root: {:?}",
                e
            ))
        })?;
        if published.root != anchor.checkpoint.state_root {
            return Err(bad("published.bin opens a different root than the anchor"));
        }
        let snapshot = Snapshot::at_checkpoint(&replayed.state, &anchor.checkpoint)
            .ok_or_else(|| bad("the replayed state cannot be viewed at the seal"))?;
        let ours = snapshot.published().map_err(|e| bad(&format!("{:?}", e)))?;
        if ours != published {
            return Err(bad("published.bin is not the tree the intents produce"));
        }
        // 5. Commit: this root is now something this process has proven.
        self.ledger
            .accept_trusted_operator(anchor)
            .map_err(|error| Halt::Lineage { epoch, error })?;
        self.state = replayed.state;
        self.seen.insert(epoch, anchor.id());
        self.verified_epoch = Some(epoch);
        self.verified_height = s.height;
        self.published = Some(snapshot.clone());
        self.newly_verified
            .push((anchor.id(), anchor.checkpoint.state_root));
        self.persist(
            &Bundle {
                anchor,
                certificate,
                published,
                intents: files.iter().map(|f| (f.epoch, encode_epoch(f))).collect(),
                txid: hex(&s.txid),
                height: s.height,
            },
            &snapshot,
        )
        .map_err(|what| Halt::BadBundle { epoch, what })?;
        for c in self.resolve_forced(s.height) {
            eprintln!(
                "zyn-replica: CENSORSHIP — forced intent from Zcash {} (height {}) was not applied by the anchor at height {}; the sequencer is refusing service",
                hex(&c.txid), c.height, c.due_at
            );
        }
        Ok(())
    }

    fn persist(&self, bundle: &Bundle, snapshot: &Snapshot<SwapState>) -> Result<(), String> {
        self.store
            .save(&Saved::of(&self.state))
            .map_err(|e| format!("cannot save verified state: {:?}", e))?;
        self.store
            .save_ledger(&self.ledger)
            .map_err(|e| format!("cannot save verified ledger: {:?}", e))?;
        let da = self.da_dir();
        publish::write_local(&da, self.chain_id, bundle)?;
        let snap_path = da
            .join(publish::rel_dir(
                self.chain_id,
                bundle.anchor.checkpoint.epoch,
            ))
            .join("snapshot.bin");
        fs::write(&snap_path, snapshot.encode()).map_err(|e| e.to_string())?;
        fs::write(
            self.dir.join(format!("verified-{}.height", self.chain_id)),
            self.verified_height.to_string(),
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Re-encode an epoch file exactly as the journal writes it, so what the
/// replica re-serves is byte-identical to what it verified.
fn encode_epoch(f: &EpochFile) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(if f.version == 1 {
        b"ZYNJRNL1"
    } else {
        b"ZYNJRNL2"
    });
    out.extend_from_slice(&f.chain_id.to_be_bytes());
    out.extend_from_slice(&f.epoch.to_be_bytes());
    for (seq, b) in &f.records {
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// Hex as an explorer shows a txid: bytes reversed. Anchor ids and roots
/// printed here are not txids, but the replica prints only txids with this.
fn hex(b: &[u8]) -> String {
    b.iter().rev().map(|x| format!("{:02x}", x)).collect()
}

fn rawhex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn intent_hash(encoded: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"zyn.forced.intent.v1");
    h.update(encoded);
    h.finalize().into()
}

fn forced_path(dir: &Path, chain_id: u32) -> PathBuf {
    dir.join(format!("forced-{}.txt", chain_id))
}

/// `pending <height> <txid> <intent_hash>` / `censored <height> <txid> <due_at>` / `noted <txid>` lines.
fn save_forced(
    dir: &Path,
    chain_id: u32,
    pending: &[ForcedPending],
    censored: &[Censored],
    noted: &BTreeSet<[u8; 32]>,
) -> Result<(), String> {
    let mut s = String::new();
    for p in pending {
        s.push_str(&format!(
            "pending {} {} {}\n",
            p.height,
            rawhex(&p.txid),
            rawhex(&p.intent_hash)
        ));
    }
    for c in censored {
        s.push_str(&format!(
            "censored {} {} {}\n",
            c.height,
            rawhex(&c.txid),
            c.due_at
        ));
    }
    for t in noted {
        s.push_str(&format!("noted {}\n", rawhex(t)));
    }
    let tmp = dir.join(format!(".forced-{}.tmp", chain_id));
    fs::write(&tmp, s).map_err(|e| e.to_string())?;
    fs::rename(&tmp, forced_path(dir, chain_id)).map_err(|e| e.to_string())
}

fn load_forced(
    dir: &Path,
    chain_id: u32,
) -> (Vec<ForcedPending>, Vec<Censored>, BTreeSet<[u8; 32]>) {
    let mut pending = Vec::new();
    let mut censored = Vec::new();
    let mut noted = BTreeSet::new();
    let Ok(s) = fs::read_to_string(forced_path(dir, chain_id)) else {
        return (pending, censored, noted);
    };
    for l in s.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        match f.as_slice() {
            ["pending", h, t, ih] => {
                if let (Ok(h), Some(t), Some(ih)) = (h.parse(), unhex32(t), unhex32(ih)) {
                    pending.push(ForcedPending {
                        height: h,
                        txid: t,
                        intent_hash: ih,
                    });
                }
            }
            ["censored", h, t, d] => {
                if let (Ok(h), Some(t), Ok(d)) = (h.parse(), unhex32(t), d.parse()) {
                    censored.push(Censored {
                        height: h,
                        txid: t,
                        due_at: d,
                    });
                }
            }
            ["noted", t] => {
                if let Some(t) = unhex32(t) {
                    noted.insert(t);
                }
            }
            _ => {}
        }
    }
    (pending, censored, noted)
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// The credits an epoch's intents claim, in order.
///
/// Records that do not decode are skipped rather than refused: `replay` has
/// already been through the same bytes and would have failed first, so nothing
/// unreadable here is a credit.
fn credits_in(files: &[EpochFile]) -> Vec<crate::backing::SeenCredit> {
    use zyn_vm::spec::MicrochainVm;
    let mut out = Vec::new();
    for f in files {
        for (_, bytes) in &f.records {
            let intent = if f.version == 1 {
                let mut d = zyn_vm::read::Decoder::new(bytes);
                let Some(intent) = <SwapState as MicrochainVm>::decode_intent(&mut d) else {
                    continue;
                };
                intent
            } else {
                let Ok(intent) = zyn::verify::decode_committed_intent::<SwapState>(bytes) else {
                    continue;
                };
                intent
            };
            if let swapvm::tx::Intent::CreditDeposit {
                account,
                asset,
                amount,
                index,
                external_ref,
            } = intent
            {
                out.push(crate::backing::SeenCredit {
                    account,
                    asset,
                    amount,
                    index,
                    external_ref,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sighting(epoch: u64, height: u64, chain_id: u32) -> Sighting {
        Sighting {
            height,
            txid: [0u8; 32],
            chain_id,
            epoch,
            id: [epoch as u8; 32],
        }
    }

    /// Epoch 4330 was reorged off Zcash and re-anchored the next day, so it
    /// sits at a *later* height than 4336 and 4474, which were built on it.
    /// Ordering by height offers 4336 before the anchor it chains from and the
    /// lineage check fails on a chain that is whole (§50.13).
    #[test]
    fn a_repaired_anchor_is_offered_in_lineage_order_not_block_order() {
        let seen = vec![
            sighting(4321, 4337722, 11),
            sighting(4336, 4337902, 11),
            sighting(4474, 4337911, 11),
            sighting(4330, 4338929, 11), // repaired: newest block, oldest epoch
        ];
        let order: Vec<u64> = in_lineage_order(&seen, 11)
            .iter()
            .map(|s| s.epoch)
            .collect();
        assert_eq!(
            order,
            vec![4321, 4330, 4336, 4474],
            "the chain must be offered as it chains"
        );
    }

    #[test]
    fn other_chains_are_not_offered_at_all() {
        let seen = vec![
            sighting(1, 100, 11),
            sighting(2, 101, 26460),
            sighting(3, 102, 11),
        ];
        let order: Vec<u64> = in_lineage_order(&seen, 11)
            .iter()
            .map(|s| s.epoch)
            .collect();
        assert_eq!(order, vec![1, 3]);
    }

    /// Two anchors claiming one epoch is the fork case; the order must still be
    /// deterministic so two replicas reach the same verdict.
    #[test]
    fn a_contested_epoch_still_orders_deterministically() {
        let seen = vec![sighting(9, 200, 11), sighting(9, 100, 11)];
        let heights: Vec<u64> = in_lineage_order(&seen, 11)
            .iter()
            .map(|s| s.height)
            .collect();
        assert_eq!(
            heights,
            vec![100, 200],
            "lower height first, always the same way round"
        );
    }
}
