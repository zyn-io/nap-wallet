//! Full-state persistence, so a dead node resumes rather than merely being
//! provably dead.
//!
//! The DA snapshot carries balances so a holder can exit without the sequencer.
//! It deliberately carries nothing else, which makes it useless for resuming: no
//! pool reserves, no parameters, no id counters. A node restarted from one would
//! pass a root check and then diverge on its first swap.
//!
//! This is the other artefact — the whole state. It is operational data, not
//! public data: it is not announced on Zcash and nobody's exit depends on it.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::anchor::{Anchor, Certificate, Ledger};
use crate::da::{decode_checkpoint, encode_checkpoint, Snapshot};
use crate::node::Sealed;
use zyn_vm::commit::{Encoder, Hash};
use zyn_vm::read::Decoder;
use zyn_vm::spec::MicrochainVm;

const MAGIC: &[u8; 10] = b"ZYNSTATE01";
const LEDGER_MAGIC: &[u8; 9] = b"ZYNANCH01";
const SEALED_MAGIC: &[u8; 9] = b"ZYNSEAL01";
const PROPOSAL_MAGIC: &[u8; 9] = b"ZYNPROP01";

/// A saved state, self-describing so an operator staring at a directory of
/// blobs after an incident can tell which chain and which root each one is,
/// without the process that wrote it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Saved {
    pub chain_id: u32,
    pub epoch: u64,
    pub seq: u64,
    pub root: Hash,
    pub blob: Vec<u8>,
}

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    NotAState,
    Truncated,
    Trailing(usize),
    /// The blob does not commit to the root recorded beside it. Refusing here
    /// rather than at first divergence is the point: a node that resumed from a
    /// corrupted state would produce roots nobody else can reproduce.
    RootMismatch,
    Decode,
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

impl Saved {
    pub fn of<V: MicrochainVm>(state: &V) -> Saved {
        Saved {
            chain_id: state.chain_id(),
            epoch: state.epoch(),
            seq: state.seq(),
            root: state.state_root(),
            blob: state.encode(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAGIC.len() + 56 + self.blob.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&(self.blob.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.blob);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Saved, StoreError> {
        if b.len() < MAGIC.len() || &b[..MAGIC.len()] != MAGIC {
            return Err(StoreError::NotAState);
        }
        let mut p = MAGIC.len();
        let need = |p: usize, n: usize| -> Result<(), StoreError> {
            if b.len() - p < n {
                Err(StoreError::Truncated)
            } else {
                Ok(())
            }
        };
        need(p, 4 + 8 + 8 + 32 + 4)?;
        let chain_id = u32::from_be_bytes(b[p..p + 4].try_into().unwrap());
        p += 4;
        let epoch = u64::from_be_bytes(b[p..p + 8].try_into().unwrap());
        p += 8;
        let seq = u64::from_be_bytes(b[p..p + 8].try_into().unwrap());
        p += 8;
        let root: Hash = b[p..p + 32].try_into().unwrap();
        p += 32;
        let n = u32::from_be_bytes(b[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        need(p, n)?;
        let blob = b[p..p + n].to_vec();
        if p + n != b.len() {
            return Err(StoreError::Trailing(b.len() - (p + n)));
        }
        Ok(Saved {
            chain_id,
            epoch,
            seq,
            root,
            blob,
        })
    }

    /// Rebuild the state, refusing a blob that does not commit to the recorded
    /// root.
    pub fn restore<V: MicrochainVm>(&self) -> Result<V, StoreError> {
        let state = V::decode(&self.blob).ok_or(StoreError::Decode)?;
        if state.state_root() != self.root {
            return Err(StoreError::RootMismatch);
        }
        Ok(state)
    }
}

/// Persists to a directory.
///
/// Writes go to a temp file, are fsynced, and are then renamed into place. A
/// node saves on every epoch it seals, so a crash mid-write is not an unlikely
/// event — and a half-written state is worse than none, because it would be
/// refused at restore and the good one it replaced would already be gone.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(FileStore { dir })
    }

    fn path(&self, chain_id: u32) -> PathBuf {
        self.dir.join(format!("chain-{}.state", chain_id))
    }

    pub fn save(&self, s: &Saved) -> Result<(), StoreError> {
        let final_path = self.path(s.chain_id);
        let tmp_path = self.dir.join(format!(".chain-{}.tmp", s.chain_id));
        {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(&s.encode())?;
            // Durability before visibility: a rename that beats its own data to
            // disk would advertise a state the machine cannot read back.
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    fn ledger_path(&self, chain_id: u32) -> PathBuf {
        self.dir.join(format!("chain-{}.anchors", chain_id))
    }

    /// Persist the anchor lineage beside the state. Without this a restarted
    /// node forgets which roots Zcash has seen and its next anchor claims to
    /// continue from nothing, which no outside verifier can accept.
    pub fn save_ledger(&self, l: &Ledger) -> Result<(), StoreError> {
        let final_path = self.ledger_path(l.chain_id());
        let tmp_path = self
            .dir
            .join(format!(".chain-{}.anchors.tmp", l.chain_id()));
        let mut out = Vec::new();
        out.extend_from_slice(LEDGER_MAGIC);
        out.extend_from_slice(&l.chain_id().to_be_bytes());
        out.extend_from_slice(&(l.len() as u32).to_be_bytes());
        for (a, c) in l.anchors().iter().zip(l.certificates()) {
            let ab = a.encode();
            let cb = c.encode();
            out.extend_from_slice(&(ab.len() as u32).to_be_bytes());
            out.extend_from_slice(&ab);
            out.extend_from_slice(&(cb.len() as u32).to_be_bytes());
            out.extend_from_slice(&cb);
        }
        {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(&out)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    /// The persisted lineage, re-checked entry by entry, or `None` on a first
    /// launch. A file that does not rebuild into a valid lineage is refused.
    pub fn load_ledger(&self, chain_id: u32) -> Result<Option<Ledger>, StoreError> {
        let b = match fs::read(self.ledger_path(chain_id)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::Io(e)),
        };
        if b.len() < LEDGER_MAGIC.len() + 8 || &b[..LEDGER_MAGIC.len()] != LEDGER_MAGIC {
            return Err(StoreError::NotAState);
        }
        let mut p = LEDGER_MAGIC.len();
        let take = |p: &mut usize, n: usize| -> Result<&[u8], StoreError> {
            if b.len() - *p < n {
                return Err(StoreError::Truncated);
            }
            let s = &b[*p..*p + n];
            *p += n;
            Ok(s)
        };
        let id = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap());
        if id != chain_id {
            return Err(StoreError::Decode);
        }
        let n = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
        let mut entries = Vec::with_capacity(n.min(1 << 16));
        for _ in 0..n {
            let al = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
            let a = Anchor::decode(take(&mut p, al)?).ok_or(StoreError::Decode)?;
            let cl = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
            let c = Certificate::decode(take(&mut p, cl)?).ok_or(StoreError::Decode)?;
            entries.push((a, c));
        }
        if p != b.len() {
            return Err(StoreError::Trailing(b.len() - p));
        }
        Ledger::restore(chain_id, entries)
            .map(Some)
            .map_err(|_| StoreError::RootMismatch)
    }

    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let tmp_path = self.dir.join(format!(".{}.tmp", name));
        {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, self.dir.join(name))?;
        Ok(())
    }

    fn sealed_name(chain_id: u32, epoch: u64) -> String {
        format!("pending-{}-{}.sealed", chain_id, epoch)
    }

    /// Persist the sealed-but-unanchored epochs, and drop files for epochs no
    /// longer pending. With manual anchoring these are what an exit needs
    /// while the anchor is on its way to Zcash.
    pub fn save_pending<V: MicrochainVm>(
        &self,
        chain_id: u32,
        pending: &[Sealed<V>],
    ) -> Result<(), StoreError> {
        let keep: Vec<String> = pending
            .iter()
            .map(|s| Self::sealed_name(chain_id, s.checkpoint.epoch))
            .collect();
        for s in pending {
            let mut e = Encoder::new();
            e.bytes(SEALED_MAGIC);
            encode_checkpoint(&mut e, &s.checkpoint);
            e.u64(s.actions);
            let snap = s.snapshot.encode();
            e.u32(snap.len() as u32).bytes(&snap);
            self.write_atomic(&Self::sealed_name(chain_id, s.checkpoint.epoch), e.finish())?;
        }
        let prefix = format!("pending-{}-", chain_id);
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&prefix) && name.ends_with(".sealed") && !keep.contains(&name) {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    /// The pending epochs on disk, in epoch order.
    pub fn load_pending<V: MicrochainVm>(
        &self,
        chain_id: u32,
    ) -> Result<Vec<Sealed<V>>, StoreError> {
        let prefix = format!("pending-{}-", chain_id);
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !(name.starts_with(&prefix) && name.ends_with(".sealed")) {
                continue;
            }
            let b = fs::read(entry.path())?;
            let mut d = Decoder::new(&b);
            if d.take_bytes(SEALED_MAGIC.len())
                .map_err(|_| StoreError::Truncated)?
                != SEALED_MAGIC
            {
                return Err(StoreError::NotAState);
            }
            let checkpoint = decode_checkpoint(&mut d).ok_or(StoreError::Decode)?;
            let actions = d.u64().map_err(|_| StoreError::Truncated)?;
            let n = d.u32().map_err(|_| StoreError::Truncated)? as usize;
            let snap = Snapshot::<V>::decode(d.take_bytes(n).map_err(|_| StoreError::Truncated)?)
                .ok_or(StoreError::Decode)?;
            if d.remaining() != 0 {
                return Err(StoreError::Trailing(d.remaining()));
            }
            if snap.root != checkpoint.state_root || snap.verify().is_err() {
                return Err(StoreError::RootMismatch);
            }
            out.push(Sealed {
                checkpoint,
                actions,
                snapshot: snap,
            });
        }
        out.sort_by_key(|s| s.checkpoint.epoch);
        Ok(out)
    }

    fn proposal_name(chain_id: u32) -> String {
        format!("proposal-{}.bin", chain_id)
    }

    /// The anchor in flight and how many pending epochs it covers.
    pub fn save_proposal(
        &self,
        chain_id: u32,
        a: &Anchor,
        covered: usize,
    ) -> Result<(), StoreError> {
        let mut out = Vec::new();
        out.extend_from_slice(PROPOSAL_MAGIC);
        out.extend_from_slice(&(covered as u32).to_be_bytes());
        out.extend_from_slice(&a.encode());
        self.write_atomic(&Self::proposal_name(chain_id), &out)
    }

    pub fn clear_proposal(&self, chain_id: u32) -> Result<(), StoreError> {
        match fs::remove_file(self.dir.join(Self::proposal_name(chain_id))) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    pub fn load_proposal(&self, chain_id: u32) -> Result<Option<(Anchor, usize)>, StoreError> {
        let b = match fs::read(self.dir.join(Self::proposal_name(chain_id))) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::Io(e)),
        };
        if b.len() < PROPOSAL_MAGIC.len() + 4 || &b[..PROPOSAL_MAGIC.len()] != PROPOSAL_MAGIC {
            return Err(StoreError::NotAState);
        }
        let p = PROPOSAL_MAGIC.len();
        let covered = u32::from_be_bytes(b[p..p + 4].try_into().unwrap()) as usize;
        let a = Anchor::decode(&b[p + 4..]).ok_or(StoreError::Decode)?;
        Ok(Some((a, covered)))
    }

    /// The saved state for a chain, or `None` if there is none — a first launch
    /// rather than a failure.
    pub fn load(&self, chain_id: u32) -> Result<Option<Saved>, StoreError> {
        match fs::read(self.path(chain_id)) {
            Ok(b) => Saved::decode(&b).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swapvm::state::SwapState;
    use swapvm::tx::{Intent, SequencedIntent};
    use swapvm::types::XZEC;
    use swapvm::{vm, Fixed, Params};

    fn chain() -> SwapState {
        let mut s = SwapState::new(11, Params::v1());
        for n in 1..=3u8 {
            let at = s.seq;
            let intent =
                Intent::next_deposit(&s, [n; 32], XZEC, Fixed::whole(100 * n as i64), [0u8; 32]);
            vm::apply(
                &mut s,
                &SequencedIntent {
                    seq: at + 1,
                    intent,
                },
            );
        }
        s
    }

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("zyn-store-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_saved_state_restores_to_the_same_root() {
        let s = chain();
        let saved = Saved::of(&s);
        let back = saved.restore::<SwapState>().expect("restore");
        assert_eq!(back.state_root(), s.state_root());
        assert_eq!(back, s);
    }

    #[test]
    fn a_restored_state_keeps_executing_from_where_it_stopped() {
        let s = chain();
        let mut restored = Saved::of(&s).restore::<SwapState>().unwrap();
        let mut live = s.clone();
        let next = SequencedIntent {
            seq: s.seq + 1,
            intent: Intent::Transfer {
                from: [1u8; 32],
                to: [9u8; 32],
                asset: XZEC,
                amount: Fixed::whole(10),
            },
        };
        vm::apply(&mut live, &next);
        vm::apply(&mut restored, &next);
        assert_eq!(restored.state_root(), live.state_root());
    }

    #[test]
    fn a_blob_that_does_not_match_its_root_is_refused() {
        let mut saved = Saved::of(&chain());
        saved.root = [0xAB; 32];
        assert!(matches!(
            saved.restore::<SwapState>(),
            Err(StoreError::RootMismatch)
        ));
    }

    #[test]
    fn a_corrupted_blob_is_refused_rather_than_resumed() {
        let mut saved = Saved::of(&chain());
        let n = saved.blob.len();
        saved.blob[n - 1] ^= 0xFF;
        assert!(
            saved.restore::<SwapState>().is_err(),
            "a corrupted state was resumed"
        );
    }

    #[test]
    fn the_envelope_round_trips_and_rejects_junk() {
        let saved = Saved::of(&chain());
        assert_eq!(Saved::decode(&saved.encode()).unwrap(), saved);
        assert!(matches!(Saved::decode(b"nope"), Err(StoreError::NotAState)));

        let bytes = saved.encode();
        for cut in MAGIC.len()..bytes.len() {
            assert!(
                Saved::decode(&bytes[..cut]).is_err(),
                "truncation at {} decoded",
                cut
            );
        }
        let mut extra = saved.encode();
        extra.push(0);
        assert!(matches!(
            Saved::decode(&extra),
            Err(StoreError::Trailing(1))
        ));
    }

    #[test]
    fn a_file_store_round_trips_and_reports_a_first_launch() {
        let dir = tmpdir("roundtrip");
        let store = FileStore::new(&dir).unwrap();
        assert!(
            store.load(11).unwrap().is_none(),
            "an empty store was not a first launch"
        );

        let s = chain();
        store.save(&Saved::of(&s)).unwrap();
        let loaded = store.load(11).unwrap().expect("saved state should load");
        assert_eq!(
            loaded.restore::<SwapState>().unwrap().state_root(),
            s.state_root()
        );

        // Saving again replaces in place rather than accumulating.
        let mut s2 = s.clone();
        let at = s2.seq;
        vm::apply(
            &mut s2,
            &SequencedIntent {
                seq: at + 1,
                intent: Intent::next_deposit(&s, [9u8; 32], XZEC, Fixed::whole(1), [0u8; 32]),
            },
        );
        store.save(&Saved::of(&s2)).unwrap();
        assert_eq!(
            store
                .load(11)
                .unwrap()
                .unwrap()
                .restore::<SwapState>()
                .unwrap()
                .state_root(),
            s2.state_root()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chains_do_not_overwrite_each_other() {
        let dir = tmpdir("multi");
        let store = FileStore::new(&dir).unwrap();
        let a = chain();
        let mut b = SwapState::new(22, Params::v1());
        let observed = b.backing_of(XZEC).add(Fixed::whole(5)).unwrap();
        let at = b.seq;
        vm::apply(
            &mut b,
            &SequencedIntent {
                seq: at + 1,
                intent: Intent::AttestVaultBalance {
                    asset: XZEC,
                    observed,
                },
            },
        );
        let intent = Intent::next_deposit(&b, [7u8; 32], XZEC, Fixed::whole(5), [0u8; 32]);
        vm::apply(&mut b, &SequencedIntent { seq: 1, intent });
        store.save(&Saved::of(&a)).unwrap();
        store.save(&Saved::of(&b)).unwrap();
        assert_eq!(store.load(11).unwrap().unwrap().root, a.state_root());
        assert_eq!(store.load(22).unwrap().unwrap().root, b.state_root());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_ledger_survives_the_disk() {
        use crate::anchor::{Anchor, Ledger};
        use zyn_vm::Checkpoint;
        let dir = tmpdir("ledger");
        let store = FileStore::new(&dir).unwrap();
        assert!(
            store.load_ledger(7).unwrap().is_none(),
            "a first launch has no ledger"
        );
        let mut l = Ledger::new(7);
        let a = Anchor {
            checkpoint: Checkpoint {
                chain_id: 7,
                epoch: 7,
                parent_root: [0u8; 32],
                state_root: [9u8; 32],
                intent_root: [1u8; 32],
                seq: 700,
                intents: 100,
                gross_volume: Fixed::ZERO,
            },
            previous_root: [0u8; 32],
            epochs: 7,
            actions: 700,
        };
        l.accept_trusted_operator(a).unwrap();
        store.save_ledger(&l).unwrap();
        let back = store.load_ledger(7).unwrap().expect("saved");
        assert_eq!(back.head_root(), l.head_root());
        assert_eq!(back.certificates().len(), 1);
        fs::write(dir.join("chain-7.anchors"), b"garbage").unwrap();
        assert!(
            store.load_ledger(7).is_err(),
            "junk must not load as a ledger"
        );
    }

    #[test]
    fn pending_epochs_and_a_proposal_survive_the_disk() {
        use crate::epoch::{Economics, EpochPolicy};
        use crate::node::Node;
        let dir = tmpdir("pending");
        let store = FileStore::new(&dir).unwrap();
        let policy = EpochPolicy {
            intents_per_epoch: 2,
            epochs_per_anchor: 100,
            max_seconds_per_epoch: 0,
            max_seconds_per_anchor: 0,
        };
        let mut n: Node<SwapState> =
            Node::resume(chain(), policy, Economics::flat(1), 0).with_manual_anchoring();
        for i in 0..4u8 {
            let d = Intent::next_deposit(n.state(), [10 + i; 32], XZEC, Fixed::whole(1), [0u8; 32]);
            n.submit_operator(d, 0);
        }
        assert_eq!(n.pending().len(), 2);
        let a = n.propose_anchor(0).unwrap();
        store.save_pending(11, n.pending()).unwrap();
        store.save_proposal(11, &a, 2).unwrap();
        let back = store.load_pending::<SwapState>(11).unwrap();
        assert_eq!(back, n.pending().to_vec());
        assert_eq!(store.load_proposal(11).unwrap(), Some((a, 2)));
        // Anchoring the first epoch only leaves one pending file behind.
        store.save_pending(11, &n.pending()[1..]).unwrap();
        assert_eq!(store.load_pending::<SwapState>(11).unwrap().len(), 1);
        store.clear_proposal(11).unwrap();
        assert_eq!(store.load_proposal(11).unwrap(), None);
        assert!(store.load_pending::<SwapState>(12).unwrap().is_empty());
    }
}
