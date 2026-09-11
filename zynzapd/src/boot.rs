//! Bringing a chain up from its directory: state, lineage, journal.
//!
//! Three artefacts, one directory, one rule — they must agree. A state that is
//! older than the ledger's last anchor would let the node re-anchor history it
//! already settled; a ledger with no state is a chain with evidence and no
//! subject. Both are refused at boot rather than discovered at the first seal.

use std::path::Path;
use std::sync::{Arc, Mutex};

use swapvm::state::SwapState;
use swapvm::Params;
use zyn::epoch::{Economics, EpochPolicy};
use zyn::journal::Journal;
use zyn::node::{Node, Recorder};
use zyn::store::{FileStore, Saved};
use zyn_vm::spec::MicrochainVm;

use crate::rpc::Shared;

/// What [`open_at`] produced.
pub struct Booted {
    pub node: Node<SwapState>,
    pub store: FileStore,
    pub journal: Arc<Mutex<Journal>>,
    /// Whether a saved state was found and resumed.
    pub resumed: bool,
    /// Under manual anchoring: the root of the base state replicas start
    /// from, written the first time journaling began on this chain.
    pub base_root: Option<[u8; 32]>,
    /// Signatures already applied.
    pub replay: Arc<Mutex<zyn::replay::ReplayIndex>>,
}

/// The node's recorder: every intent goes to the journal before the VM sees
/// it, and an intent the journal cannot take is not applied.
pub struct JournalRecorder(pub Arc<Mutex<Journal>>);

impl Recorder for JournalRecorder {
    fn record(&mut self, epoch: u64, seq: u64, encoded: &[u8]) -> bool {
        match self.0.lock() {
            Ok(mut j) => match j.record(epoch, seq, encoded) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("zynzapd: JOURNAL WRITE FAILED at seq {}: {} — refusing the intent", seq, e);
                    false
                }
            },
            Err(_) => {
                eprintln!("zynzapd: journal lock poisoned — refusing the intent");
                false
            }
        }
    }
}

/// Open or create the chain under `data_dir`.
///
/// `manual` selects manual anchoring: anchors are proposed, carried to Zcash
/// and confirmed at depth, and the sealed epochs waiting on that trip are
/// restored from disk so a restart mid-flight loses nothing.
pub fn open_at(
    data_dir: &Path,
    chain_id: u32,
    params: Params,
    policy: EpochPolicy,
    economics: Economics,
    now: u64,
    manual: bool,
    da_dir: &Path,
) -> Result<Booted, String> {
    let store = FileStore::new(data_dir).map_err(|e| format!("{:?}", e))?;
    let journal = Journal::open(data_dir, chain_id).map_err(|e| format!("cannot open the journal: {}", e))?;
    let journal = Arc::new(Mutex::new(journal));

    let saved = store.load(chain_id).map_err(|e| format!("{:?}", e))?;
    let ledger = store.load_ledger(chain_id).map_err(|e| format!("the anchor ledger on disk is unreadable: {:?}", e))?;

    let (node, resumed) = match (saved, ledger) {
        (None, Some(l)) if !l.is_empty() => {
            return Err(format!("{} anchor(s) on disk but no saved state — refusing to start a fresh chain over settled history", l.len()));
        }
        (None, _) => (Node::new(chain_id, params, policy, economics), false),
        (Some(saved), ledger) => {
            let state: SwapState = saved
                .restore()
                .map_err(|e| format!("refusing to resume from a state that does not match its root: {:?}", e))?;
            let ledger = ledger.unwrap_or_else(|| zyn::anchor::Ledger::new(chain_id));
            if let Some(last) = ledger.last() {
                // A sealed epoch N leaves the state in epoch N+1.
                if last.checkpoint.epoch >= state.epoch() {
                    return Err(format!(
                        "the saved state (epoch {}) is older than the last anchor (epoch {}) — a stale state file; refusing to re-anchor settled history",
                        state.epoch(),
                        last.checkpoint.epoch
                    ));
                }
            }
            (Node::resume_with_ledger(state, policy, economics, ledger, now), true)
        }
    };
    let mut node = node.with_recorder(Box::new(JournalRecorder(Arc::clone(&journal))));
    let mut base_root = None;
    if manual {
        node = node.with_manual_anchoring();
        // A chain older than its journal cannot be replayed from genesis. The
        // state at the moment journaling began is the base a replica starts
        // from — written once, **before any intent is applied under the
        // journal**, so the journal's first record is the base's next
        // sequence number. Its root is what the operator announces.
        let base_path = da_dir.join(format!("chain-{}/base.state", chain_id));
        if !base_path.exists() {
            let saved = Saved::of(node.state());
            std::fs::create_dir_all(base_path.parent().unwrap()).map_err(|e| e.to_string())?;
            std::fs::write(&base_path, saved.encode()).map_err(|e| format!("cannot write the DA base state: {}", e))?;
            eprintln!(
                "zynzapd: DA base state written at epoch {} seq {} — BASE ROOT {} (announce this; replicas start from it)",
                saved.epoch,
                saved.seq,
                saved.root.iter().map(|b| format!("{:02x}", b)).collect::<String>()
            );
        }
        base_root = std::fs::read(&base_path).ok().and_then(|b| Saved::decode(&b).ok()).map(|s| s.root);
        let pending = store
            .load_pending::<SwapState>(chain_id)
            .map_err(|e| format!("the pending epochs on disk are unreadable: {:?}", e))?;
        if !pending.is_empty() {
            eprintln!("zynzapd: {} sealed epoch(s) waiting on an anchor, restored from disk", pending.len());
        }
        node.restore_pending(pending);
        if let Some((a, covered)) = store.load_proposal(chain_id).map_err(|e| format!("the proposal on disk is unreadable: {:?}", e))? {
            node.restore_proposal(a, covered).map_err(|e| {
                format!("the anchor proposal on disk (epoch {}) cannot be reproduced: {} — remove proposal-{}.bin only if you are sure no transaction for it is in flight", a.checkpoint.epoch, e, chain_id)
            })?;
            eprintln!("zynzapd: anchor proposal for epoch {} restored; waiting for Zcash to confirm it", a.checkpoint.epoch);
        }
    }
    let replay = Arc::new(Mutex::new(zyn::replay::ReplayIndex::load(data_dir, chain_id)?));
    Ok(Booted { node, store, journal, resumed, base_root, replay })
}

/// Persist the replay index, pruned of what can no longer be replayed.
pub fn save_replay(data_dir: &Path, chain_id: u32, replay: &Arc<Mutex<zyn::replay::ReplayIndex>>, epoch: u64) {
    if let Ok(mut r) = replay.lock() {
        r.prune(epoch);
        if let Err(e) = r.save(data_dir, chain_id) {
            eprintln!("zynzapd: replay index save failed: {}", e);
        }
    }
}

/// Persist everything the node would need to come back: journal first (the
/// evidence), then the state, then the lineage.
pub fn save(store: &FileStore, journal: &Arc<Mutex<Journal>>, shared: &Shared) {
    if let Ok(mut j) = journal.lock() {
        if let Err(e) = j.sync() {
            eprintln!("zynzapd: journal sync failed: {}", e);
        }
    }
    let Ok(n) = shared.lock() else {
        eprintln!("zynzapd: cannot save, node lock poisoned");
        return;
    };
    // A failed save is not fatal — the chain in memory is still correct, and
    // dying here would guarantee the loss that the save was meant to prevent.
    if let Err(e) = store.save(&Saved::of(n.state())) {
        eprintln!("zynzapd: save failed: {:?}", e);
    }
    if let Err(e) = store.save_ledger(n.ledger()) {
        eprintln!("zynzapd: ledger save failed: {:?}", e);
    }
    let chain_id = n.state().chain_id();
    if let Err(e) = store.save_pending(chain_id, n.pending()) {
        eprintln!("zynzapd: pending-epoch save failed: {:?}", e);
    }
    let r = match n.proposal() {
        Some((a, covered)) => store.save_proposal(chain_id, &a, covered),
        None => store.clear_proposal(chain_id),
    };
    if let Err(e) = r {
        eprintln!("zynzapd: proposal save failed: {:?}", e);
    }
}
