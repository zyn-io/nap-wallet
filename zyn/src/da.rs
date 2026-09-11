//! The escape hatch, made load-bearing — for any Zyn VM.
//!
//! A proof only helps someone who has one. If the sequencer disappears without
//! publishing state, nobody can construct one, and the exit path protects
//! nobody — settlement would happily verify a proof no user is able to build.
//! Publishing enough to rebuild the accounts tree is what turns "your funds are
//! recoverable in principle" into "here is the command".
//!
//! The snapshot is **self-verifying**. Rehash each published record into its
//! leaf, merkle the leaves, fold in the other section roots, and the result must
//! equal the root that was anchored to Zcash. A publisher cannot lie about a
//! holder without producing a snapshot that fails to match a root anyone can
//! read off the chain — and cannot hide behind bare hashes either, because the
//! records are published in the VM's own encoding and the holder rebuilds the
//! leaf themselves.
//!
//! Generic over [`MicrochainVm`], so every application gets a working exit path
//! from the section layout alone rather than writing — and getting wrong — the
//! one thing its users' funds depend on.
//!
//! What it deliberately does not carry: the application's other sections. Those
//! are summarised as roots. The snapshot exists so a holder can prove *their*
//! record and exit, not so anyone can resume execution from it, which is
//! [`crate::store`]'s job and is operational rather than public.

use alloc::vec::Vec;
use core::marker::PhantomData;

use zyn_vm::commit::{merkle_proof, merkle_root, verify_proof, Encoder, Hash, ProofStep};
use zyn_vm::read::Decoder;
use zyn_vm::spec::{AccountId, MicrochainVm, Provable, SECTION_ACCOUNTS};
use zyn_vm::Checkpoint;

const SNAPSHOT_MAGIC: &[u8; 9] = b"ZYNSNAP01";
const PUBLISHED_MAGIC: &[u8; 8] = b"ZYNPUB01";
/// Caps on what a decoder will allocate for, so a malformed file is refused
/// rather than read into memory.
const MAX_SECTIONS: usize = 64;
const MAX_LEAVES: usize = 1 << 24;
const MAX_RECORD: usize = 1 << 16;

/// Canonical bytes of a checkpoint, for files that carry one.
pub fn encode_checkpoint(e: &mut Encoder, cp: &Checkpoint) {
    e.u32(cp.chain_id)
        .u64(cp.epoch)
        .bytes(&cp.parent_root)
        .bytes(&cp.state_root)
        .bytes(&cp.intent_root)
        .u64(cp.seq)
        .u64(cp.intents)
        .fixed(cp.gross_volume);
}

pub fn decode_checkpoint(d: &mut Decoder) -> Option<Checkpoint> {
    Some(Checkpoint {
        chain_id: d.u32().ok()?,
        epoch: d.u64().ok()?,
        parent_root: d.hash().ok()?,
        state_root: d.hash().ok()?,
        intent_root: d.hash().ok()?,
        seq: d.u64().ok()?,
        intents: d.u64().ok()?,
        gross_volume: d.fixed().ok()?,
    })
}

/// Everything needed to rebuild a chain's accounts tree at one anchored root.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Snapshot<V: MicrochainVm> {
    pub chain_id: u32,
    pub epoch: u64,
    pub seq: u64,
    /// The root this snapshot claims to open. Checked, never trusted.
    pub root: Hash,
    /// Every section commitment, with the accounts section as the VM committed
    /// it. Carried whole rather than as a handful of named fields, so a VM with
    /// three sections and one with six both publish something the same verifier
    /// can check.
    pub sections: Vec<Hash>,
    /// Holder records in the order the VM committed them, which is account-id
    /// order. The order is part of the commitment, so it is preserved verbatim.
    pub records: Vec<(AccountId, Vec<u8>)>,
    _vm: PhantomData<V>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SnapshotError {
    /// The rebuilt root does not match the claimed one. Either the snapshot is
    /// wrong or the root is; both mean it must not be relied on.
    RootMismatch,
    /// Records are not in the order the commitment used, so any tree built from
    /// them is a different tree.
    OutOfOrder,
    /// No such account in this snapshot.
    UnknownAccount,
    /// The section list is too short to carry an accounts section.
    MalformedSections,
}

impl<V: MicrochainVm> Snapshot<V> {
    /// The whole snapshot, records included — for the operator's own disk,
    /// never for publication (`Published` is the public form).
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.bytes(SNAPSHOT_MAGIC).u32(self.chain_id).u64(self.epoch).u64(self.seq).bytes(&self.root);
        e.u32(self.sections.len() as u32);
        for s in &self.sections {
            e.bytes(s);
        }
        e.u32(self.records.len() as u32);
        for (id, r) in &self.records {
            e.bytes(id).u32(r.len() as u32).bytes(r);
        }
        e.finish().to_vec()
    }

    pub fn decode(b: &[u8]) -> Option<Snapshot<V>> {
        let mut d = Decoder::new(b);
        if d.take_bytes(SNAPSHOT_MAGIC.len()).ok()? != SNAPSHOT_MAGIC {
            return None;
        }
        let chain_id = d.u32().ok()?;
        let epoch = d.u64().ok()?;
        let seq = d.u64().ok()?;
        let root = d.hash().ok()?;
        let ns = d.u32().ok()? as usize;
        if ns > MAX_SECTIONS {
            return None;
        }
        let mut sections = Vec::with_capacity(ns);
        for _ in 0..ns {
            sections.push(d.hash().ok()?);
        }
        let nr = d.u32().ok()? as usize;
        if nr > MAX_LEAVES {
            return None;
        }
        let mut records = Vec::with_capacity(nr.min(1 << 16));
        for _ in 0..nr {
            let id = d.account().ok()?;
            let len = d.u32().ok()? as usize;
            if len > MAX_RECORD {
                return None;
            }
            records.push((id, d.take_bytes(len).ok()?.to_vec()));
        }
        if d.remaining() != 0 {
            return None;
        }
        Some(Snapshot { chain_id, epoch, seq, root, sections, records, _vm: PhantomData })
    }

    /// Publish the accounts tree as one checkpoint sealed it.
    ///
    /// This is the constructor a publisher should use. An anchor carries the
    /// *sealed* root, and the chain keeps executing the moment the epoch turns
    /// over, so a snapshot of the live state opens a root Zcash never saw —
    /// useless to the holder it was published for. `None` if the state has
    /// moved on in ways the sealed header cannot account for, which means the
    /// snapshot had to be taken closer to the seal.
    pub fn at_checkpoint(state: &V, cp: &Checkpoint) -> Option<Snapshot<V>> {
        Some(Snapshot::of(&state.as_sealed(cp)?))
    }

    /// Publish the accounts tree of a state as it stands.
    pub fn of(state: &V) -> Snapshot<V> {
        let records = state
            .account_ids()
            .into_iter()
            .filter_map(|id| state.account_record(&id).map(|r| (id, r)))
            .collect();
        Snapshot {
            chain_id: state.chain_id(),
            epoch: state.epoch(),
            seq: state.seq(),
            root: state.state_root(),
            sections: state.sections(),
            records,
            _vm: PhantomData,
        }
    }

    /// Rebuild the leaves from the published records.
    fn leaves(&self) -> Result<Vec<Hash>, SnapshotError> {
        for w in self.records.windows(2) {
            if w[0].0 >= w[1].0 {
                return Err(SnapshotError::OutOfOrder);
            }
        }
        Ok(self.records.iter().map(|(_, r)| V::leaf_of_record(r)).collect())
    }

    /// The accounts root implied by this snapshot's contents.
    pub fn accounts_root(&self) -> Result<Hash, SnapshotError> {
        Ok(merkle_root(&self.leaves()?))
    }

    /// Rebuild the full state root from the records and the section list.
    pub fn rebuild_root(&self) -> Result<Hash, SnapshotError> {
        if self.sections.len() <= SECTION_ACCOUNTS {
            return Err(SnapshotError::MalformedSections);
        }
        let mut sections = self.sections.clone();
        // The accounts section is recomputed from the records rather than taken
        // on trust; every other section is a summary this snapshot does not
        // expand.
        sections[SECTION_ACCOUNTS] = self.accounts_root()?;
        Ok(merkle_root(&sections))
    }

    /// Whether the snapshot actually opens the root it claims.
    pub fn verify(&self) -> Result<(), SnapshotError> {
        if self.rebuild_root()? != self.root {
            return Err(SnapshotError::RootMismatch);
        }
        Ok(())
    }

    /// Whether the snapshot opens `anchored` — the root a Zcash transaction
    /// committed.
    ///
    /// The check a holder actually runs: the anchor is what settlement verifies
    /// against, and a snapshot that opens some other root is useless to them
    /// however internally consistent it is.
    pub fn verifies_against(&self, anchored: Hash) -> Result<(), SnapshotError> {
        self.verify()?;
        if self.root != anchored {
            return Err(SnapshotError::RootMismatch);
        }
        Ok(())
    }

    /// One holder's published record, in the VM's encoding.
    pub fn record(&self, id: &AccountId) -> Option<&[u8]> {
        self.records.iter().find(|(a, _)| a == id).map(|(_, r)| r.as_slice())
    }

    pub fn ids(&self) -> impl Iterator<Item = &AccountId> {
        self.records.iter().map(|(id, _)| id)
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Build the inclusion path for `id`, all the way to the state root.
    ///
    /// This is the escape hatch itself: a holder with the published snapshot and
    /// an anchored root produces this without asking the sequencer for anything,
    /// and settlement checks it without asking either.
    pub fn proof(&self, id: &AccountId) -> Result<(Hash, Vec<ProofStep>), SnapshotError> {
        if self.sections.len() <= SECTION_ACCOUNTS {
            return Err(SnapshotError::MalformedSections);
        }
        let index = self
            .records
            .iter()
            .position(|(a, _)| a == id)
            .ok_or(SnapshotError::UnknownAccount)?;
        let leaves = self.leaves()?;
        let mut sections = self.sections.clone();
        sections[SECTION_ACCOUNTS] = merkle_root(&leaves);

        let mut path = merkle_proof(&leaves, index);
        path.extend(merkle_proof(&sections, SECTION_ACCOUNTS));
        Ok((leaves[index], path))
    }

    /// Prove `id`'s record against a root read off Zcash, end to end.
    pub fn prove_against(&self, id: &AccountId, anchored: Hash) -> Result<bool, SnapshotError> {
        self.verifies_against(anchored)?;
        let (leaf, path) = self.proof(id)?;
        Ok(verify_proof(leaf, &path, anchored))
    }
}

/// The path a holder rebuilds locally, without any snapshot at all.
///
/// If they kept their own record and the sibling hashes from an earlier
/// snapshot, this is all settlement needs. Present so the exit path does not
/// depend on the snapshot still being retrievable at the moment it is used.
/// What is actually published: the tree, not the records.
///
/// A leaf is `H(record)`, and a record carries the holder's blind once set,
/// so a leaf reveals nothing to anyone but its holder — not a balance, not
/// an item, not whether the account is empty. Holders fetch their own record
/// and path from the operator on a signed request; anyone can check that
/// the leaves rebuild the anchored root.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Published {
    pub chain_id: u32,
    pub epoch: u64,
    pub root: Hash,
    pub sections: Vec<Hash>,
    pub leaves: Vec<Hash>,
}

impl Published {
    /// The bytes a mirror stores and a replica checks.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.bytes(PUBLISHED_MAGIC).u32(self.chain_id).u64(self.epoch).bytes(&self.root);
        e.u32(self.sections.len() as u32);
        for s in &self.sections {
            e.bytes(s);
        }
        e.u32(self.leaves.len() as u32);
        for l in &self.leaves {
            e.bytes(l);
        }
        e.finish().to_vec()
    }

    pub fn decode(b: &[u8]) -> Option<Published> {
        let mut d = Decoder::new(b);
        if d.take_bytes(PUBLISHED_MAGIC.len()).ok()? != PUBLISHED_MAGIC {
            return None;
        }
        let chain_id = d.u32().ok()?;
        let epoch = d.u64().ok()?;
        let root = d.hash().ok()?;
        let ns = d.u32().ok()? as usize;
        if ns > MAX_SECTIONS {
            return None;
        }
        let mut sections = Vec::with_capacity(ns);
        for _ in 0..ns {
            sections.push(d.hash().ok()?);
        }
        let nl = d.u32().ok()? as usize;
        if nl > MAX_LEAVES {
            return None;
        }
        let mut leaves = Vec::with_capacity(nl.min(1 << 16));
        for _ in 0..nl {
            leaves.push(d.hash().ok()?);
        }
        if d.remaining() != 0 {
            return None;
        }
        Some(Published { chain_id, epoch, root, sections, leaves })
    }

    pub fn rebuild_root(&self) -> Result<Hash, SnapshotError> {
        if self.sections.len() <= SECTION_ACCOUNTS {
            return Err(SnapshotError::MalformedSections);
        }
        let mut sections = self.sections.clone();
        sections[SECTION_ACCOUNTS] = merkle_root(&self.leaves);
        Ok(merkle_root(&sections))
    }

    pub fn verify(&self) -> Result<(), SnapshotError> {
        if self.rebuild_root()? != self.root {
            return Err(SnapshotError::RootMismatch);
        }
        Ok(())
    }
}

impl<V: MicrochainVm> Snapshot<V> {
    /// The publishable form: leaves only.
    pub fn published(&self) -> Result<Published, SnapshotError> {
        Ok(Published {
            chain_id: self.chain_id,
            epoch: self.epoch,
            root: self.root,
            sections: self.sections.clone(),
            leaves: self.leaves()?,
        })
    }

    /// A holder's own record with its leaf index and path — served only on a
    /// request the holder signed.
    pub fn record_proof(&self, id: &AccountId) -> Result<(Vec<u8>, u32, Vec<ProofStep>), SnapshotError> {
        let index = self.records.iter().position(|(a, _)| a == id).ok_or(SnapshotError::UnknownAccount)?;
        let (_, path) = self.proof(id)?;
        Ok((self.records[index].1.clone(), index as u32, path))
    }
}

pub fn verify_record<V: MicrochainVm>(
    record: &[u8],
    path: &[ProofStep],
    anchored: Hash,
) -> bool {
    verify_proof(V::leaf_of_record(record), path, anchored)
}

/// A holder's own proof taken straight from a live VM, bypassing publication.
pub fn proof_from<V: MicrochainVm>(state: &V, id: &AccountId) -> Option<(Vec<u8>, Vec<ProofStep>)> {
    Some((state.account_record(id)?, Provable::account_proof(state, id)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use swapvm::state::SwapState;
    use swapvm::tx::Intent;
    use swapvm::types::XZEC;
    use swapvm::{Fixed, Params};

    fn chain() -> SwapState {
        let mut s = SwapState::new(3, Params::v1());
        let observed = s.backing_of(XZEC).add(Fixed::whole(100)).unwrap();
        s.apply(1, &Intent::AttestVaultBalance { asset: XZEC, observed });
        let d = Intent::next_deposit(&s, [1u8; 32], XZEC, Fixed::whole(5), [0u8; 32]);
        s.apply(2, &d);
        let d = Intent::next_deposit(&s, [2u8; 32], XZEC, Fixed::whole(7), [0u8; 32]);
        s.apply(3, &d);
        s
    }

    #[test]
    fn a_snapshot_and_its_published_form_round_trip_and_still_verify() {
        let s = chain();
        let snap = Snapshot::of(&s);
        let back = Snapshot::<SwapState>::decode(&snap.encode()).expect("decode");
        assert_eq!(back, snap);
        back.verify().unwrap();
        let pubd = snap.published().unwrap();
        let pb = Published::decode(&pubd.encode()).expect("decode");
        assert_eq!(pb, pubd);
        pb.verify().unwrap();
        assert_eq!(pb.root, s.state_root());
        assert!(Published::decode(&pubd.encode()[..20]).is_none());
        assert!(Snapshot::<SwapState>::decode(b"junk").is_none());
    }

    #[test]
    fn a_checkpoint_round_trips() {
        let cp = Checkpoint { chain_id: 3, epoch: 9, parent_root: [1; 32], state_root: [2; 32], intent_root: [3; 32], seq: 77, intents: 12, gross_volume: Fixed::whole(4) };
        let mut e = Encoder::new();
        encode_checkpoint(&mut e, &cp);
        let mut d = Decoder::new(e.finish());
        assert_eq!(decode_checkpoint(&mut d), Some(cp));
        assert_eq!(d.remaining(), 0);
    }
}
