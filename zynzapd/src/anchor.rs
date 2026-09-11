//! Carrying an anchor to Zcash: a self-send with the root in the memo.
//!
//! An exit and an anchor are the same transaction with one field different
//! (`DECISIONS`, the revised anchoring plan): the vault pays *itself* the fee
//! floor, and the memo carries `zyn::anchor::Anchor::memo()`. So this module
//! builds nothing new — it drives `zyn_custody::payout` exactly as
//! `settle::ZcashSettler` does, and keeps its own ledger of what is in flight.
//!
//! # Acceptance moves to confirmation
//!
//! Before this module an anchor was accepted the moment it was built, into a
//! ledger only the sequencer could see. Now the node **proposes** an anchor,
//! this settler broadcasts it, and only when Zebra reports it at depth does
//! the node **confirm** it — which is when the epoch's deposits are released.
//! Until then nothing is final, which is the honest state of affairs.
//!
//! # Failure posture
//!
//! Fail toward anchoring nothing, never toward anchoring twice. One anchor is
//! in flight at a time. A transaction unseen past its expiry is abandoned and
//! the *same* anchor (same id — the proposal did not change) is rebuilt and
//! rebroadcast; the two cannot both land because the second is built after
//! the first is dead.

use std::path::{Path, PathBuf};

use orchard::bundle::BundleVersion;
use orchard::circuit::ProvingKey;
use orchard::keys::{FullViewingKey, Scope};
use orchard::ValuePool;
use zcash_protocol::consensus::Network;
use zyn::anchor::Anchor;
use zyn::node::ConfirmError;
use zyn_custody::ceremony::{Identifier as ZcashId, VaultKeys as ZcashKeys};
use zyn_custody::memo::MEMO_FIELD;
use zyn_custody::payout::{self, Destination, Envelope, Payment};
use zyn_custody::shielded::PoolStores;
use zyn_custody::zebra::Zebra;

use crate::rpc::Shared;

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
use crate::settle::{Entry, Ledger, Status};

/// The ledger file name suffix, beside the per-asset settlement ledgers.
pub const LEDGER_NAME: &str = "anchors";

/// How many recent confirmations to re-examine for a reorg each pass. A reorg
/// reaches a bounded distance back; the ledger does not, so this cannot be
/// "all of them".
const REORG_WATCH: usize = 32;

/// The value an anchor self-send carries: the ZIP-317 floor for its two
/// logical actions. It comes back to the vault as a note; only the fee leaves.
pub const ANCHOR_ZATOSHI: u64 = 10_000;

/// The chain as this module needs it. `Zebra` implements it; tests fake it.
pub trait Chain {
    fn tip(&self) -> Result<u64, String>;
    /// `None` if the node does not know the transaction.
    fn confirmations(&self, txid: &str) -> Result<Option<u64>, String>;
    fn broadcast(&self, hex: &str) -> Result<String, String>;
}

impl Chain for Zebra {
    fn tip(&self) -> Result<u64, String> {
        self.block_count().map_err(|e| e.to_string())
    }
    fn confirmations(&self, txid: &str) -> Result<Option<u64>, String> {
        Zebra::confirmations(self, txid).map_err(|e| e.to_string())
    }
    fn broadcast(&self, hex: &str) -> Result<String, String> {
        self.send_raw_transaction(hex).map_err(|e| e.to_string())
    }
}

/// A signed anchor transaction, ready to send.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Built {
    pub txid: String,
    pub bytes: Vec<u8>,
    /// Height from which it is invalid.
    pub expiry: u64,
    pub pool: ValuePool,
    /// Note positions it spends, forgotten once it is final.
    pub spent: Vec<u64>,
}

/// Turns an anchor into a transaction. The real one proves and threshold-signs;
/// a test's returns fixed bytes.
pub trait Builder {
    fn build(&mut self, anchor: &Anchor, tip: u64) -> Result<Built, String>;
    /// The transaction is final: its spent notes are gone from the chain.
    fn settled(&mut self, pool: ValuePool, spent: &[u64]);
}

/// The 512-byte memo field for an anchor: the anchor memo, zero-padded.
pub fn anchor_memo_field(a: &Anchor) -> [u8; MEMO_FIELD] {
    let mut out = [0u8; MEMO_FIELD];
    let m = a.memo();
    out[..m.len()].copy_from_slice(&m);
    out
}

/// The real builder: the vault's notes, its viewing key, and enough shares.
pub struct ZcashBuilder {
    network: Network,
    shares: Vec<(ZcashId, ZcashKeys)>,
    /// The group's public package — for the coordinator, whether it holds
    /// shares or drives custodians. Aggregation and the group key come from it.
    public: zyn_custody::custody_net::ZcashPublicPackage,
    /// When set, sign through these custodians rather than local shares. The
    /// box then holds no secret share.
    custodians: Option<Vec<String>>,
    threshold: u16,
    fvk: FullViewingKey,
    notes: PoolStores,
    /// To check the tree's root against the node before witnessing on it.
    zebra: Zebra,
    /// Re-seeds and re-walks the trees when they diverge from the node.
    scanner: zyn_custody::shielded::Scanner,
    /// Blocks behind the tip the trees stop at.
    tree_lag: u64,
    /// Built once per bundle version; seconds and hundreds of megabytes.
    proving: Option<(BundleVersion, ProvingKey)>,
}

impl ZcashBuilder {
    pub fn new(
        network: Network,
        shares: Vec<(ZcashId, ZcashKeys)>,
        threshold: u16,
        fvk: FullViewingKey,
        notes: PoolStores,
        zebra: Zebra,
        from_height: u64,
        tree_lag: u64,
        attributions: std::collections::BTreeMap<[u8; 32], zyn_vm::spec::AccountId>,
        public: zyn_custody::custody_net::ZcashPublicPackage,
        custodians: Option<Vec<String>>,
    ) -> Result<ZcashBuilder, String> {
        // Local mode needs a quorum of shares; remote mode needs none — the
        // custodians hold them, and the box holds only the public package.
        if custodians.is_none() && shares.len() < usize::from(threshold) {
            return Err(format!("{} share(s) loaded, {} needed to sign anchors", shares.len(), threshold));
        }
        let group = *public.verifying_key();
        let ak_matches = zyn_custody::ceremony::orchard_viewing_key(&group, [0u8; 32], [0u8; 32])
            .map(|k| k.to_bytes()[..32] == fvk.to_bytes()[..32])
            .unwrap_or(false);
        if !ak_matches {
            return Err("the vault's viewing key is not the threshold key's — see ceremony::orchard_viewing_key".into());
        }
        if let Some(c) = &custodians {
            eprintln!("zynzapd: anchors signed by {} custodian(s), threshold {} — this box holds no share", c.len(), threshold);
        }
        let scanner = zyn_custody::shielded::Scanner::new(zyn_custody::shielded::VaultKeys::from_full_viewing_key(fvk.clone()), from_height, 200)
            .with_notes(notes.clone())
            .with_tree_lag(tree_lag)
            .with_attributions(attributions);
        Ok(ZcashBuilder { network, shares, public, custodians, threshold, fvk, notes, zebra, scanner, tree_lag, proving: None })
    }

    /// The tree must name a root the node has, or the witness is worthless.
    /// A tree that appended a block the chain later dropped fails here, in
    /// one line, instead of in a transaction refused until it expires.
    fn tree_matches_node(&self, pool: ValuePool) -> Result<(), String> {
        let (root, at) = {
            let store = self.notes.of(pool).lock().map_err(|_| "note store poisoned".to_string())?;
            let Some(at) = store.synced_to() else { return Ok(()) };
            (store.root_bytes(), at)
        };
        let ts = self.zebra.tree_state_of(at, pool).map_err(|e| format!("z_gettreestate {}: {}", at, e))?;
        if root == Some(ts.final_root) {
            return Ok(());
        }
        // Diverged. Heal in place: re-seed from the node's frontier and walk
        // the blocks again, then say what was wrong in numbers a human can
        // act on — a count mismatch is a block fed twice or skipped; equal
        // counts with different roots is a reorganised or misordered block.
        let tip = self.zebra.block_count().map_err(|e| e.to_string())?;
        let to = tip.saturating_sub(self.tree_lag);
        // The numbers first, so a re-walk that fails still leaves the evidence.
        let (appended, node_count) = {
            let store = self.notes.of(pool).lock().map_err(|_| "note store poisoned".to_string())?;
            let node_count = zyn_custody::notes::NoteStore::from_frontier(&ts.final_state, at).map(|s| s.appended()).unwrap_or(0);
            (store.appended(), node_count)
        };
        eprintln!(
            "zynzapd: {:?} note tree at {} does not match the node: tree appended {} commitments, node has {} at that height ({}); re-seeding both trees from the vault's birth and re-walking to {}",
            pool, at, appended, node_count,
            if appended == node_count { "same count — different order, or a reorganised block" } else { "COUNT MISMATCH — a block fed twice or skipped" },
            to
        );
        self.scanner.reseed(&self.zebra, pool, to).map_err(|e| format!("re-seeding the {:?} tree failed: {:?}", pool, e))?;
        let store = self.notes.of(pool).lock().map_err(|_| "note store poisoned".to_string())?;
        let at = store.synced_to().unwrap_or(to);
        let ts = self.zebra.tree_state_of(at, pool).map_err(|e| format!("z_gettreestate {}: {}", at, e))?;
        if store.root_bytes() != Some(ts.final_root) {
            return Err(format!("the {:?} note tree still does not match the node at {} after re-seeding — the feeder itself is wrong", pool, at));
        }
        Ok(())
    }
}

impl Builder for ZcashBuilder {
    fn build(&mut self, anchor: &Anchor, tip: u64) -> Result<Built, String> {
        let env = Envelope::at(self.network, tip as u32);
        let to = self.fvk.address_at(0u32, Scope::External);
        let ovk = Some(self.fvk.to_ovk(Scope::External));
        let payment = Payment { to: Destination::Shielded(to), zatoshi: ANCHOR_ZATOSHI, memo: anchor_memo_field(anchor) };

        // Ironwood only: a shielded output is what an anchor is, and under
        // NU6.3 the Orchard pool cannot pay one. With a single note the
        // vault's anchors serialise on the previous change note confirming,
        // which is the policy's cadence anyway — so "no note yet" is a wait,
        // not a fault.
        let pool = ValuePool::Ironwood;
        let version = env.bundle_version_for(pool).map_err(|e| e.to_string())?;
        self.tree_matches_node(pool)?;
        let mut payout = {
            let store = self.notes.of(pool).lock().map_err(|_| "note store poisoned".to_string())?;
            match payout::build(&store, &self.fvk, ovk.clone(), &[payment], to, version, rand::rngs::OsRng) {
                Ok(p) => p,
                Err(payout::PayoutError::Notes(_)) => {
                    return Err("waiting for a spendable Ironwood note (the last anchor's change is still confirming, or the vault needs a top-up)".into())
                }
                Err(e) => return Err(format!("cannot build the anchor transaction: {}", e)),
            }
        };
        let sighash = payout.sighash(&env).map_err(|e| e.to_string())?;
        payout.finalize_io(sighash, rand::rngs::OsRng).map_err(|e| e.to_string())?;
        if self.proving.as_ref().map(|(v, _)| *v != version).unwrap_or(true) {
            eprintln!("zynzapd: building the Orchard proving key ({:?}) for anchors", version.circuit_version());
            self.proving = Some((version, payout::proving_key(version)));
        }
        payout.prove(&self.proving.as_ref().unwrap().1, rand::rngs::OsRng).map_err(|e| e.to_string())?;
        let group = *self.public.verifying_key();
        match &self.custodians {
            Some(addrs) => {
                let mut q = zyn_custody::custody_net::RemoteQuorum::new(addrs.clone());
                payout::sign_all_with(&mut payout, sighash, &mut q, self.threshold, &group, &self.public, now_secs()).map_err(|e| e.to_string())?;
            }
            None => {
                let quorum: Vec<(ZcashId, &ZcashKeys)> = self.shares.iter().take(usize::from(self.threshold)).map(|(i, k)| (*i, k)).collect();
                payout::sign_all(&mut payout, sighash, &quorum, self.threshold, rand::rngs::OsRng).map_err(|e| e.to_string())?;
            }
        }
        let sealed = payout.extract(sighash, &env, rand::rngs::OsRng).map_err(|e| e.to_string())?;
        Ok(Built {
            txid: sealed.txid_hex(),
            bytes: sealed.bytes.clone(),
            expiry: u64::from(u32::from(env.expiry)),
            pool: version.value_pool(),
            spent: sealed.spent.iter().map(|n| u64::from(n.position)).collect(),
        })
    }

    fn settled(&mut self, pool: ValuePool, spent: &[u64]) {
        if let Ok(mut store) = self.notes.of(pool).lock() {
            for pos in spent {
                store.spend((*pos).into());
            }
        }
    }
}

/// An anchor the chain has: what the publisher needs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Confirmed {
    pub anchor: Anchor,
    pub txid: String,
    pub height: u64,
}

/// Proposes, broadcasts, confirms. One in flight at a time.
pub struct AnchorSettler<C: Chain, B: Builder> {
    chain: C,
    builder: B,
    ledger: Ledger,
    dir: PathBuf,
    chain_id: u32,
    confirmations: u64,
    /// Whether the "unfunded" warning was already printed for this proposal.
    warned_unfunded: bool,
    /// Release deposits only when a signer set has endorsed the anchor.
    signing: bool,
    /// The anchor being waited on for signatures, and since when (pass count).
    awaiting: Option<([u8; 32], u32)>,
    /// Anchors this settler recorded as confirmed that are no longer on Zcash.
    /// Non-empty means the lineage rests on something a verifier cannot find.
    lineage_lost: Vec<[u8; 32]>,
    /// Anchors asked to be put back on the chain, retried until one lands.
    /// The vault holds a single note and anchors serialise on it, so a repair
    /// waits its turn behind whatever is in flight rather than failing.
    reanchor_pending: Vec<Anchor>,
}

impl<C: Chain, B: Builder> AnchorSettler<C, B> {
    pub fn new(chain: C, builder: B, confirmations: u64, dir: &Path, chain_id: u32) -> Result<Self, String> {
        let ledger = Ledger::load_named(dir, chain_id, LEDGER_NAME)?;
        Ok(AnchorSettler { chain, builder, ledger, dir: dir.to_path_buf(), chain_id, confirmations, warned_unfunded: false, signing: false, awaiting: None, lineage_lost: Vec::new(), reanchor_pending: Vec::new() })
    }

    /// Release deposits only after a signer set endorses each anchor. The set
    /// itself lives on the node (`with_signers`); this makes the settler wait
    /// for the certificate the node gathers rather than confirm on Zcash depth
    /// alone.
    pub fn requiring_signatures(mut self) -> Self {
        self.signing = true;
        self
    }

    pub fn in_flight(&self) -> Option<&Entry> {
        self.ledger.in_flight().next()
    }

    /// Passes spent waiting on signatures for the current anchor, for alerts.
    pub fn awaiting_passes(&self) -> u32 {
        self.awaiting.map(|(_, c)| c).unwrap_or(0)
    }

    /// What the alerter should make of this settler.
    ///
    /// An anchor that is on Zcash but that the signer set has not endorsed is
    /// not a failure — every pass did what it was asked. It is also the state
    /// in which no deposit becomes spendable, and it can persist for hours
    /// while each pass reports success. Past `limit` passes, say so.
    pub fn endorsement_health(&self, limit: u32) -> Result<(), String> {
        match self.awaiting {
            Some((id, passes)) if limit > 0 && passes >= limit => Err(format!(
                "anchor {} has been confirmed on Zcash but unendorsed for {} passes — no deposit is becoming spendable; check the signer set",
                hex(&id),
                passes
            )),
            _ => Ok(()),
        }
    }

    /// Whether the chain this settler is extending still exists on Zcash.
    ///
    /// Confirmation was treated as permanent, so a reorg that removed a
    /// settled anchor left the sequencer extending a lineage no verifier could
    /// follow — silently, for days (§50.1). Surfaced beside the endorsement
    /// stall so it alerts rather than resting in a journal.
    pub fn lineage_health(&self) -> Result<(), String> {
        match self.lineage_lost.first() {
            Some(id) => Err(format!(
                "anchor {} was settled and is no longer on Zcash: the chain rests on a link no verifier can find. Anchoring is stopped until it is re-anchored",
                hex(id)
            )),
            None => Ok(()),
        }
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    fn save(&self) -> Result<(), String> {
        self.ledger.save_named(&self.dir, self.chain_id, LEDGER_NAME)
    }

    /// One pass: follow up what is in flight, then propose and send the next.
    /// Returns the anchor the chain confirmed this pass, if any.
    pub fn poll_once(&mut self, node: &Shared, now: u64) -> Result<Option<Confirmed>, String> {
        // Reported, not repaired automatically. `confirmations` answers "not
        // known to this node", which a resyncing Zebra says about everything —
        // re-broadcasting on that would be a stampede. An operator re-anchors
        // with `reanchor` once the loss is real (§50.6).
        // Repair before extension: the gate below refuses to extend anyway, and
        // the single vault note means whoever asks first gets it.
        self.drain_reanchors();
        self.lineage_lost = self.reorged().unwrap_or_default();
        for gone in &self.lineage_lost {
            eprintln!(
                "zynzapd: LINEAGE AT RISK: anchor {} is no longer on Zcash; anything built on it cannot be verified until it is re-anchored",
                hex(gone)
            );
        }
        if let Some(c) = self.follow_up(node, now)? {
            return Ok(Some(c));
        }
        if self.ledger.in_flight().next().is_some() {
            return Ok(None);
        }
        self.send_next(node, now)?;
        Ok(None)
    }

    /// Ask for an anchor to be put back on Zcash, and keep asking.
    ///
    /// Not attempted immediately: the note store is only current once the
    /// scanner has caught up, and building against a stale one picks a note
    /// that has since been spent — which the network rejects as
    /// `ironwood double-spend: duplicate nullifier`. Queue it, and let
    /// `poll_once` try when there is a note to spend.
    pub fn queue_reanchor(&mut self, anchor: Anchor) {
        if !self.reanchor_pending.iter().any(|a| a.id() == anchor.id()) {
            self.reanchor_pending.push(anchor);
        }
    }

    /// How many repairs are still waiting for a spendable note.
    pub fn reanchors_pending(&self) -> usize {
        self.reanchor_pending.len()
    }

    /// Put an anchor back on Zcash after a reorg removed it.
    ///
    /// The Zyn side of this anchor settled long ago — deposits burned, its
    /// certificate recorded — and must not happen twice. So this builds and
    /// broadcasts the transaction and deliberately does **not** enter the
    /// settler's ledger: nothing here is to be confirmed again, only
    /// re-published. The `ZYA` memo names the *anchor*, not the transaction,
    /// so a fresh txid settles the same anchor and the lineage reconnects.
    pub fn reanchor(&mut self, anchor: &Anchor) -> Result<String, String> {
        let tip = self.chain.tip()?;
        let built = self.builder.build(anchor, tip)?;
        let hex_tx: String = built.bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let txid = self.chain.broadcast(&hex_tx)?;
        eprintln!(
            "zynzapd: re-anchored epoch {} (root {}) as {} — the previous transaction is gone from the chain",
            anchor.checkpoint.epoch,
            hex(&anchor.checkpoint.state_root),
            txid
        );
        Ok(txid)
    }

    /// Try each queued repair once. A repair that cannot find a note is kept:
    /// "no note yet" is a wait, not a failure, exactly as it is for a new
    /// anchor.
    fn drain_reanchors(&mut self) {
        let queued = std::mem::take(&mut self.reanchor_pending);
        for anchor in queued {
            match self.reanchor(&anchor) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("zynzapd: re-anchor of epoch {} waiting: {}", anchor.checkpoint.epoch, e);
                    self.reanchor_pending.push(anchor);
                }
            }
        }
    }

    /// Anchors that were confirmed and are no longer on the chain.
    ///
    /// `Confirmed` was treated as final: `follow_up` skips anything that is not
    /// `Broadcast`, so a reorg deeper than `confirmations` removed a settled
    /// anchor and nothing ever looked again. Everything built on top then
    /// pointed at a link no verifier could find, which is exactly how epoch
    /// 4330 vanished while the sequencer believed it was settled.
    ///
    /// Only the most recent confirmations are re-checked: a reorg reaches a
    /// bounded distance back, and the ledger grows without limit.
    pub fn reorged(&mut self) -> Result<Vec<[u8; 32]>, String> {
        let mut gone = Vec::new();
        let recent: Vec<usize> = (0..self.ledger.entries.len())
            .rev()
            .filter(|&i| self.ledger.entries[i].status == Status::Confirmed)
            .take(REORG_WATCH)
            .collect();
        for i in recent {
            let id = self.ledger.entries[i].id.clone();
            if self.chain.confirmations(&id)?.is_none() {
                eprintln!(
                    "zynzapd: anchor {} was confirmed as {} and is no longer on the chain — reorged out",
                    hex(&self.ledger.entries[i].nonce),
                    id
                );
                gone.push(self.ledger.entries[i].nonce);
            }
        }
        Ok(gone)
    }

    fn follow_up(&mut self, node: &Shared, now: u64) -> Result<Option<Confirmed>, String> {
        let mut changed = false;
        let mut confirmed = None;
        let tip = self.chain.tip()?;
        for i in 0..self.ledger.entries.len() {
            if self.ledger.entries[i].status != Status::Broadcast {
                continue;
            }
            let id = self.ledger.entries[i].id.clone();
            match self.chain.confirmations(&id)? {
                Some(depth) if depth >= self.confirmations => {
                    let anchor_id = self.ledger.entries[i].nonce;
                    let mut n = node.lock().map_err(|_| "node lock poisoned".to_string())?;
                    // A restarted node may have lost the proposal; rebuilding
                    // it over the same pending epochs yields the same id.
                    if n.proposed().is_none() {
                        n.propose_anchor(now);
                    }
                    // In signer mode a root is not released until the set has
                    // reproduced it. The anchor is on Zcash regardless; only
                    // the deposits behind it wait.
                    let cert = if self.signing {
                        if !n.certificate_clears(anchor_id) {
                            let waited = match self.awaiting {
                                Some((id, c)) if id == anchor_id => c + 1,
                                _ => 1,
                            };
                            self.awaiting = Some((anchor_id, waited));
                            if waited == 1 || waited % 10 == 0 {
                                eprintln!("zynzapd: anchor {} is on Zcash and confirmed; awaiting signatures ({} pass(es)) before releasing its deposits", hex(&anchor_id), waited);
                            }
                            drop(n);
                            continue;
                        }
                        self.awaiting = None;
                        n.certificate_for(anchor_id).cloned()
                    } else {
                        None
                    };
                    let anchor = match n.confirm_anchor(anchor_id, cert.as_ref(), now) {
                        Ok(a) => a,
                        Err(ConfirmError::NotProposed) => {
                            return Err(format!(
                                "anchor {} is final on Zcash but the node cannot reproduce its proposal — the pending epochs on disk do not match; refusing to guess",
                                hex(&anchor_id)
                            ));
                        }
                        Err(e) => return Err(format!("the node refused to confirm anchor {}: {:?}", hex(&anchor_id), e)),
                    };
                    drop(n);
                    let (pool, spent) = (self.ledger.entries[i].pool, self.ledger.entries[i].spent.clone());
                    self.builder.settled(pool, &spent);
                    self.ledger.entries[i].status = Status::Confirmed;
                    changed = true;
                    confirmed = Some(Confirmed { anchor, txid: id, height: tip.saturating_sub(depth).saturating_add(1) });
                    break;
                }
                Some(_) => {} // seen, not deep enough
                None if tip > self.ledger.entries[i].expiry => {
                    eprintln!("zynzapd: anchor transaction {} expired unseen at {}; the same anchor will be rebuilt", id, tip);
                    self.ledger.entries[i].status = Status::Abandoned;
                    changed = true;
                }
                None => {
                    let hex_tx: String = self.ledger.entries[i].transaction.iter().map(|b| format!("{:02x}", b)).collect();
                    if let Err(e) = self.chain.broadcast(&hex_tx) {
                        if is_consensus_refusal(&e) {
                            // The chain will never take it: its witness names
                            // a root the chain does not have. Waiting for the
                            // expiry would only delay the rebuild.
                            eprintln!("zynzapd: anchor {} refused on consensus ({}); abandoned, the same anchor will be rebuilt", id, e);
                            self.ledger.entries[i].status = Status::Abandoned;
                            changed = true;
                        } else {
                            eprintln!("zynzapd: rebroadcast of anchor {} refused: {}", id, e);
                        }
                    }
                }
            }
        }
        if changed {
            self.save()?;
        }
        Ok(confirmed)
    }

    fn send_next(&mut self, node: &Shared, now: u64) -> Result<(), String> {
        // Do not build on a link that is no longer there. Extending it costs
        // nothing now and produces a chain nobody can verify later, which is
        // far worse than stopping: a stalled chain is recoverable, an
        // unverifiable one needs archaeology (§50.1).
        if let Some(id) = self.lineage_lost.first() {
            return Err(format!(
                "refusing to anchor: {} was settled and has left the chain; re-anchor it before extending the lineage",
                hex(id)
            ));
        }
        let proposal = {
            let mut n = node.lock().map_err(|_| "node lock poisoned".to_string())?;
            n.proposed().copied().or_else(|| n.propose_anchor(now))
        };
        let Some(anchor) = proposal else { return Ok(()) };
        let tip = self.chain.tip()?;
        let built = match self.builder.build(&anchor, tip) {
            Ok(b) => b,
            Err(e) => {
                if !self.warned_unfunded {
                    eprintln!("zynzapd: cannot send anchor for epoch {}: {}; waiting", anchor.checkpoint.epoch, e);
                    self.warned_unfunded = true;
                }
                return Err(e);
            }
        };
        self.warned_unfunded = false;
        // Recorded before it is sent, so a crash between the two rebroadcasts
        // rather than rebuilds — and two builds can never both land.
        self.ledger.entries.push(Entry {
            id: built.txid.clone(),
            nonce: anchor.id(),
            transaction: built.bytes.clone(),
            covers: Vec::new(),
            cover_assets: Vec::new(),
            status: Status::Broadcast,
            spent: built.spent,
            expiry: built.expiry,
            pool: built.pool,
        });
        self.save()?;
        let hex_tx: String = built.bytes.iter().map(|b| format!("{:02x}", b)).collect();
        match self.chain.broadcast(&hex_tx) {
            Ok(txid) => eprintln!(
                "zynzapd: anchor for epoch {} (root {}) broadcast as {} from {:?}",
                anchor.checkpoint.epoch,
                hex(&anchor.checkpoint.state_root),
                txid,
                built.pool
            ),
            Err(e) => eprintln!("zynzapd: anchor broadcast deferred: {}", e),
        }
        Ok(())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Whether a node's refusal is final for this transaction: a consensus
/// failure (an unknown anchor, a bad proof) rather than a full mempool or a
/// node that is briefly behind.
pub fn is_consensus_refusal(e: &str) -> bool {
    let e = e.to_ascii_lowercase();
    e.contains("consensus validation") || e.contains("unknown ironwood anchor") || e.contains("unknown orchard anchor") || e.contains("\"code\":-25")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};

    use swapvm::state::SwapState;
    use swapvm::tx::Intent;
    use swapvm::types::XZEC;
    use swapvm::{Fixed, Params};
    use zyn::epoch::{Economics, EpochPolicy};
    use zyn::node::Node;

    #[derive(Default)]
    struct FakeChainState {
        tip: u64,
        /// txid -> depth; absent means unknown to the node.
        depth: BTreeMap<String, u64>,
        broadcasts: Vec<String>,
        /// What `broadcast` answers instead of accepting.
        refuse: Option<String>,
    }
    #[derive(Clone, Default)]
    struct FakeChain(Rc<RefCell<FakeChainState>>);
    impl Chain for FakeChain {
        fn tip(&self) -> Result<u64, String> {
            Ok(self.0.borrow().tip)
        }
        fn confirmations(&self, txid: &str) -> Result<Option<u64>, String> {
            Ok(self.0.borrow().depth.get(txid).copied())
        }
        fn broadcast(&self, hex: &str) -> Result<String, String> {
            if let Some(r) = &self.0.borrow().refuse {
                return Err(r.clone());
            }
            self.0.borrow_mut().broadcasts.push(hex.to_string());
            Ok(format!("tx{}", self.0.borrow().broadcasts.len()))
        }
    }

    #[derive(Default)]
    struct FakeBuilder {
        builds: u32,
        fail: bool,
        settled: Vec<(ValuePool, Vec<u64>)>,
    }
    impl Builder for FakeBuilder {
        fn build(&mut self, anchor: &Anchor, tip: u64) -> Result<Built, String> {
            if self.fail {
                return Err("unfunded".into());
            }
            self.builds += 1;
            Ok(Built {
                txid: format!("tx-{}-{}", anchor.checkpoint.epoch, self.builds),
                bytes: anchor.memo().to_vec(),
                expiry: tip + 40,
                pool: ValuePool::Ironwood,
                spent: vec![7, 9],
            })
        }
        fn settled(&mut self, pool: ValuePool, spent: &[u64]) {
            self.settled.push((pool, spent.to_vec()));
        }
    }

    fn node() -> Shared {
        let policy = EpochPolicy { intents_per_epoch: 10, epochs_per_anchor: 1, max_seconds_per_epoch: 0, max_seconds_per_anchor: 0 };
        let mut s = SwapState::new(1, Params::v1());
        s.tokens.get_mut(&XZEC).unwrap().vault.as_mut().unwrap().observed = Fixed::whole(1_000_000);
        let mut n = Node::resume(s, policy, Economics::flat(1), 0).with_manual_anchoring();
        for _ in 0..10 {
            let d = Intent::next_deposit(n.state(), [1u8; 32], XZEC, Fixed::whole(1), [0u8; 32]);
            n.submit_operator(d, 0);
        }
        assert_eq!(n.pending().len(), 1);
        Arc::new(Mutex::new(n))
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("zyn-anchor-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The stall that hid for three hours on 8 Sep: the anchor is on Zcash,
    /// every pass succeeds, and no deposit becomes spendable because the
    /// signer set never endorsed. Health has to fold that in, or the alerter
    /// reports a chain that is quietly not releasing anything as fine.
    #[test]
    fn an_anchor_left_unendorsed_is_reported_as_down() {
        let dir = tmp("health");
        let chain = FakeChain::default();
        let mut s = AnchorSettler::new(chain, FakeBuilder::default(), 10, &dir, 1).unwrap();

        // Nothing awaiting: healthy.
        assert!(s.endorsement_health(20).is_ok());

        // Awaiting, but not yet long enough to be worth waking anyone.
        s.awaiting = Some(([9u8; 32], 19));
        assert!(s.endorsement_health(20).is_ok());

        // Past the limit, it is a fault even though every pass "worked".
        s.awaiting = Some(([9u8; 32], 20));
        let e = s.endorsement_health(20).unwrap_err();
        assert!(e.contains("unendorsed for 20 passes"), "{}", e);

        // A limit of zero turns it off rather than alerting immediately.
        assert!(s.endorsement_health(0).is_ok());

        // And it clears when the certificate does.
        s.awaiting = None;
        assert!(s.endorsement_health(20).is_ok());
    }

    #[test]
    fn a_proposal_is_sent_then_confirmed_at_depth_and_only_then_published() {
        let dir = tmp("confirm");
        let chain = FakeChain::default();
        chain.0.borrow_mut().tip = 100;
        let mut s = AnchorSettler::new(chain.clone(), FakeBuilder::default(), 10, &dir, 1).unwrap();
        let shared = node();

        assert_eq!(s.poll_once(&shared, 0).unwrap(), None);
        let entry = s.in_flight().expect("one anchor in flight").clone();
        assert_eq!(chain.0.borrow().broadcasts.len(), 1);
        let proposed = shared.lock().unwrap().proposed().copied().expect("the node holds the proposal");
        assert_eq!(entry.nonce, proposed.id());
        assert!(shared.lock().unwrap().publishable().is_none(), "nothing is published before depth");

        // In the mempool: nothing changes, nothing is rebuilt.
        chain.0.borrow_mut().depth.insert(entry.id.clone(), 0);
        assert_eq!(s.poll_once(&shared, 1).unwrap(), None);
        assert_eq!(s.ledger().entries.len(), 1);

        // At depth: confirmed, published, ledger says so, notes forgotten.
        chain.0.borrow_mut().depth.insert(entry.id.clone(), 10);
        chain.0.borrow_mut().tip = 120;
        let c = s.poll_once(&shared, 2).unwrap().expect("confirmed");
        assert_eq!(c.anchor, proposed);
        assert_eq!(c.txid, entry.id);
        assert_eq!(c.height, 111);
        assert_eq!(s.ledger().entries[0].status, Status::Confirmed);
        assert_eq!(s.builder.settled, vec![(ValuePool::Ironwood, vec![7, 9])]);
        let n = shared.lock().unwrap();
        assert_eq!(n.publishable().unwrap().root, proposed.checkpoint.state_root);
        assert_eq!(n.ledger().head_root(), proposed.checkpoint.state_root);
        assert!(n.proposed().is_none());
        drop(n);

        // The ledger was written before the broadcast and survives reload.
        let again = AnchorSettler::new(chain.clone(), FakeBuilder::default(), 10, &dir, 1).unwrap();
        assert_eq!(again.ledger().entries, s.ledger().entries);
        // Nothing pending: nothing to send.
        assert_eq!(s.poll_once(&shared, 3).unwrap(), None);
        assert_eq!(chain.0.borrow().broadcasts.len(), 1);
    }

    /// `Confirmed` was treated as final, so a reorg that removed a settled
    /// anchor was invisible: the sequencer kept building on a link no verifier
    /// could find. This is epoch 4330, reduced (§50.1).
    #[test]
    fn an_anchor_reorged_out_after_confirming_is_noticed() {
        let dir = tmp("reorg");
        let chain = FakeChain::default();
        chain.0.borrow_mut().tip = 100;
        let mut s = AnchorSettler::new(chain.clone(), FakeBuilder::default(), 10, &dir, 1).unwrap();
        let shared = node();
        s.poll_once(&shared, 0).unwrap();
        let tx = s.in_flight().unwrap().id.clone();

        // Seen deeply enough to be accepted as settled.
        chain.0.borrow_mut().depth.insert(tx.clone(), 10);
        chain.0.borrow_mut().tip = 120;
        s.poll_once(&shared, 1).unwrap();
        assert_eq!(s.ledger().entries[0].status, Status::Confirmed);
        assert!(s.reorged().unwrap().is_empty(), "nothing is wrong yet");

        // A reorg deeper than the confirmation depth removes it.
        chain.0.borrow_mut().depth.remove(&tx);
        let gone = s.reorged().unwrap();
        assert_eq!(gone.len(), 1, "a settled anchor that left the chain must be noticed");
        assert_eq!(gone[0], s.ledger().entries[0].nonce, "identified by anchor, not by transaction");
    }

    /// A repair asked for before the vault has a spendable note must wait, not
    /// fail: building against a stale note store picks one that has since been
    /// spent, which the network rejects as a duplicate nullifier (§50.9).
    #[test]
    fn a_queued_reanchor_waits_for_a_note_and_then_goes_out() {
        let dir = tmp("queue");
        let chain = FakeChain::default();
        chain.0.borrow_mut().tip = 100;
        let mut s = AnchorSettler::new(chain.clone(), FakeBuilder::default(), 10, &dir, 1).unwrap();
        let shared = node();
        s.poll_once(&shared, 0).unwrap();
        let anchor = { shared.lock().unwrap().proposed().copied().unwrap() };

        // Nothing to spend: the repair is kept rather than lost.
        chain.0.borrow_mut().refuse = Some("waiting for a spendable Ironwood note".into());
        s.queue_reanchor(anchor);
        s.poll_once(&shared, 1).unwrap();
        assert_eq!(s.reanchors_pending(), 1, "kept while there is no note");

        // A note appears.
        chain.0.borrow_mut().refuse = None;
        let sent = chain.0.borrow().broadcasts.len();
        s.poll_once(&shared, 2).unwrap();
        assert_eq!(s.reanchors_pending(), 0, "done once it lands");
        assert!(chain.0.borrow().broadcasts.len() > sent, "and it was actually sent");
    }

    /// Asking twice for the same anchor must not send it twice.
    #[test]
    fn queueing_the_same_repair_twice_is_one_repair() {
        let dir = tmp("dedupe");
        let chain = FakeChain::default();
        chain.0.borrow_mut().tip = 100;
        let mut s = AnchorSettler::new(chain.clone(), FakeBuilder::default(), 10, &dir, 1).unwrap();
        let shared = node();
        s.poll_once(&shared, 0).unwrap();
        let anchor = { shared.lock().unwrap().proposed().copied().unwrap() };
        chain.0.borrow_mut().refuse = Some("waiting for a spendable Ironwood note".into());
        s.queue_reanchor(anchor);
        s.queue_reanchor(anchor);
        assert_eq!(s.reanchors_pending(), 1);
    }

    /// The point of noticing: a lineage whose foundation has left the chain
    /// must stop being extended. Building on it is silent and cheap now and
    /// produces a chain no verifier can follow later — which is exactly what
    /// happened to epochs 4336 and 4474 (§50.1).
    #[test]
    fn a_vanished_predecessor_stops_anchoring_instead_of_extending_the_chain() {
        let dir = tmp("gate");
        let chain = FakeChain::default();
        chain.0.borrow_mut().tip = 100;
        let mut s = AnchorSettler::new(chain.clone(), FakeBuilder::default(), 10, &dir, 1).unwrap();
        let shared = node();
        s.poll_once(&shared, 0).unwrap();
        let tx = s.in_flight().unwrap().id.clone();

        chain.0.borrow_mut().depth.insert(tx.clone(), 10);
        chain.0.borrow_mut().tip = 120;
        s.poll_once(&shared, 1).unwrap();
        assert_eq!(s.ledger().entries[0].status, Status::Confirmed);
        assert!(s.lineage_health().is_ok(), "healthy while the anchor is on the chain");
        let sent = chain.0.borrow().broadcasts.len();

        // The settled anchor is reorged away.
        chain.0.borrow_mut().depth.remove(&tx);
        let err = s.poll_once(&shared, 2).unwrap_err();
        assert!(err.contains("refusing to anchor"), "stalls rather than extends: {}", err);
        assert_eq!(chain.0.borrow().broadcasts.len(), sent, "nothing new was sent");
        assert!(s.lineage_health().is_err(), "and it is reported, not just refused");
    }

    /// Healing: the anchor goes back on the chain under a new transaction, and
    /// the ledger is left alone — its Zyn side settled long ago and must not
    /// be confirmed twice (§50.6).
    #[test]
    fn reanchoring_rebroadcasts_without_touching_the_ledger() {
        let dir = tmp("reanchor");
        let chain = FakeChain::default();
        chain.0.borrow_mut().tip = 100;
        let mut s = AnchorSettler::new(chain.clone(), FakeBuilder::default(), 10, &dir, 1).unwrap();
        let shared = node();
        s.poll_once(&shared, 0).unwrap();
        let first = s.in_flight().unwrap().clone();
        let entries_before = s.ledger().entries.len();
        let sent_before = chain.0.borrow().broadcasts.len();

        let anchor = { shared.lock().unwrap().proposed().copied().unwrap() };
        let txid = s.reanchor(&anchor).unwrap();

        assert_ne!(txid, first.id, "a new transaction");
        assert_eq!(chain.0.borrow().broadcasts.len(), sent_before + 1, "it was sent");
        assert_eq!(s.ledger().entries.len(), entries_before, "no new ledger entry to confirm again");
    }

    #[test]
    fn an_expired_transaction_is_abandoned_and_the_same_anchor_is_rebuilt() {
        let dir = tmp("expire");
        let chain = FakeChain::default();
        chain.0.borrow_mut().tip = 100;
        let mut s = AnchorSettler::new(chain.clone(), FakeBuilder::default(), 10, &dir, 1).unwrap();
        let shared = node();
        s.poll_once(&shared, 0).unwrap();
        let first = s.in_flight().unwrap().clone();
        // Unseen and past expiry.
        chain.0.borrow_mut().tip = first.expiry + 1;
        assert_eq!(s.poll_once(&shared, 1).unwrap(), None);
        assert_eq!(s.ledger().entries[0].status, Status::Abandoned);
        let second = s.in_flight().expect("rebuilt").clone();
        assert_ne!(second.id, first.id, "a new transaction");
        assert_eq!(second.nonce, first.nonce, "for the same anchor");
        assert_eq!(chain.0.borrow().broadcasts.len(), 2);
    }

    #[test]
    fn a_consensus_refusal_abandons_now_and_rebuilds_the_same_anchor() {
        let dir = tmp("consensus");
        let chain = FakeChain::default();
        chain.0.borrow_mut().tip = 100;
        let mut s = AnchorSettler::new(chain.clone(), FakeBuilder::default(), 10, &dir, 1).unwrap();
        let shared = node();
        s.poll_once(&shared, 0).unwrap();
        let first = s.in_flight().unwrap().clone();
        chain.0.borrow_mut().refuse = Some("node refused: transaction did not pass consensus validation: unknown Ironwood anchor".into());
        assert_eq!(s.poll_once(&shared, 1).unwrap(), None);
        assert_eq!(s.ledger().entries[0].status, Status::Abandoned, "a consensus refusal is final");
        chain.0.borrow_mut().refuse = None;
        s.poll_once(&shared, 2).unwrap();
        let second = s.in_flight().expect("rebuilt").clone();
        assert_eq!(second.nonce, first.nonce, "same anchor");
        assert_ne!(second.id, first.id);
        // A transient refusal is not final.
        chain.0.borrow_mut().refuse = Some("node refused: mempool full".into());
        assert_eq!(s.poll_once(&shared, 3).unwrap(), None);
        assert_eq!(s.in_flight().unwrap().id, second.id, "still in flight");
    }

    #[test]
    fn an_unfunded_anchor_waits_and_keeps_the_proposal() {
        let dir = tmp("unfunded");
        let chain = FakeChain::default();
        chain.0.borrow_mut().tip = 100;
        let mut s = AnchorSettler::new(chain.clone(), FakeBuilder { fail: true, ..Default::default() }, 10, &dir, 1).unwrap();
        let shared = node();
        assert!(s.poll_once(&shared, 0).is_err());
        assert!(s.in_flight().is_none());
        assert!(shared.lock().unwrap().proposed().is_some(), "the proposal stays for the next pass");
        s.builder.fail = false;
        assert_eq!(s.poll_once(&shared, 1).unwrap(), None);
        assert!(s.in_flight().is_some());
    }

    #[test]
    fn a_restarted_node_confirms_an_anchor_it_can_reproduce() {
        let dir = tmp("restart");
        let chain = FakeChain::default();
        chain.0.borrow_mut().tip = 100;
        let mut s = AnchorSettler::new(chain.clone(), FakeBuilder::default(), 10, &dir, 1).unwrap();
        let shared = node();
        s.poll_once(&shared, 0).unwrap();
        let entry = s.in_flight().unwrap().clone();
        // "Restart": a node with the same pending epochs but no proposal.
        let restarted = {
            let n = shared.lock().unwrap();
            let mut fresh = Node::resume(n.state().clone(), *n.policy(), Economics::flat(1), 0).with_manual_anchoring();
            fresh.restore_pending(n.pending().to_vec());
            Arc::new(Mutex::new(fresh))
        };
        chain.0.borrow_mut().depth.insert(entry.id.clone(), 10);
        let c = s.poll_once(&restarted, 5).unwrap().expect("confirmed after restart");
        assert_eq!(c.anchor.id(), entry.nonce);
        assert_eq!(restarted.lock().unwrap().ledger().len(), 1);
    }

    #[test]
    fn the_memo_field_is_the_anchor_memo_zero_padded() {
        let shared = node();
        let a = shared.lock().unwrap().propose_anchor(0).unwrap();
        let f = anchor_memo_field(&a);
        assert_eq!(&f[..zyn::anchor::MEMO_LEN], &a.memo()[..]);
        assert!(f[zyn::anchor::MEMO_LEN..].iter().all(|b| *b == 0));
        assert!(zyn_custody::memo::is_anchor(&f));
    }
}
