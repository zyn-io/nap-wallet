//! `TallyVm` — a complete Zyn application in about 250 lines.
//!
//! Kept as a module rather than buried in one test file because it is the
//! template: the smallest thing that satisfies the specification, with no
//! swap, no bridge, no liquidity and no assets. If a rule is here, it is here
//! because the spec requires it of everything — which makes this the shortest
//! honest answer to "what do I have to write to build on Zyn".
//!
//! It counts. Accounts hold a number; an intent adds to it; the total is
//! conserved. That is the whole application, and everything else in this file
//! is what any Zyn VM owes the infrastructure: canonical encoding, a section
//! layout, account leaves that an exit proof can be built from, sealing, and a
//! conservation check the machine will refuse to commit without.

#![allow(dead_code)]

use std::collections::BTreeMap;

use zyn_vm::commit::{hash_leaf, merkle_root, Encoder, Hash};
use zyn_vm::read::Decoder;
use zyn_vm::spec::{AccountId, MicrochainVm};
use zyn_vm::{Checkpoint, Fixed};

/// The application's parameters. Committed state (**S5**), so every node
/// agrees what a legal step is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Limits {
    /// Largest single increment. Enforced, never computed.
    pub max_step: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Tick {
    Add { who: AccountId, n: u64 },
    Clear { who: AccountId },
    Seal,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Note {
    Added { who: AccountId, total: u64 },
    Cleared { who: AccountId },
    Sealed(Checkpoint),
    Refused(&'static str),
}

/// Three sections: a header, the tallies, and the chain's own running total.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TallyVm {
    pub chain_id: u32,
    pub epoch: u64,
    pub seq: u64,
    pub limits: Limits,
    pub parent_root: Hash,
    pub intent_acc: Hash,
    pub epoch_intents: u64,
    pub tallies: BTreeMap<AccountId, u64>,
    pub total: u64,
}

impl TallyVm {
    fn header_leaf(&self) -> Hash {
        let mut e = Encoder::new();
        e.bytes(b"tally.header.v1")
            .u32(self.chain_id)
            .u64(self.epoch)
            .u64(self.seq)
            .bytes(&self.parent_root)
            .bytes(&self.intent_acc)
            .u64(self.epoch_intents)
            .u64(self.limits.max_step);
        e.leaf()
    }

    fn total_leaf(&self) -> Hash {
        let mut e = Encoder::new();
        e.bytes(b"tally.total.v1").u64(self.total);
        e.leaf()
    }
}

impl MicrochainVm for TallyVm {
    type Intent = Tick;
    type Receipt = Note;
    type Params = Limits;

    const VM_NAME: &'static str = "tally";
    const VM_VERSION: u16 = 1;

    fn genesis(chain_id: u32, limits: Limits) -> Self {
        TallyVm {
            chain_id,
            epoch: 0,
            seq: 0,
            limits,
            parent_root: [0u8; 32],
            intent_acc: [0u8; 32],
            epoch_intents: 0,
            tallies: BTreeMap::new(),
            total: 0,
        }
    }

    fn chain_id(&self) -> u32 {
        self.chain_id
    }
    fn seq(&self) -> u64 {
        self.seq
    }
    fn epoch(&self) -> u64 {
        self.epoch
    }

    fn apply(&mut self, seq: u64, intent: &Tick) -> Vec<Note> {
        // S2: only the next sequence number applies, and anything else is inert.
        if seq != self.seq + 1 {
            return vec![Note::Refused("out of order")];
        }
        // S3: the intent enters the history before it is executed.
        self.seq = seq;
        self.intent_acc = zyn_vm::fold_intent(self.intent_acc, seq, &Self::encode_intent(intent));
        self.epoch_intents += 1;

        match intent {
            Tick::Add { who, n } => {
                if *n == 0 || *n > self.limits.max_step {
                    return vec![Note::Refused("step outside limits")];
                }
                let entry = self.tallies.entry(*who).or_insert(0);
                // S9: checked, always.
                let next = match entry.checked_add(*n) {
                    Some(v) => v,
                    None => return vec![Note::Refused("tally overflow")],
                };
                *entry = next;
                self.total = self.total.saturating_add(*n);
                vec![Note::Added { who: *who, total: next }]
            }
            Tick::Clear { who } => match self.tallies.remove(who) {
                Some(n) => {
                    self.total = self.total.saturating_sub(n);
                    vec![Note::Cleared { who: *who }]
                }
                None => vec![Note::Refused("nothing to clear")],
            },
            Tick::Seal => {
                let state_root = self.state_root();
                let cp = Checkpoint {
                    chain_id: self.chain_id,
                    epoch: self.epoch,
                    parent_root: self.parent_root,
                    state_root,
                    intent_root: self.intent_acc,
                    seq: self.seq,
                    intents: self.epoch_intents,
                    gross_volume: Fixed::whole(self.total as i64),
                };
                self.parent_root = state_root;
                self.epoch += 1;
                self.intent_acc = [0u8; 32];
                self.epoch_intents = 0;
                vec![Note::Sealed(cp)]
            }
        }
    }

    fn sections(&self) -> Vec<Hash> {
        vec![self.header_leaf(), merkle_root(&self.account_leaves()), self.total_leaf()]
    }

    fn seal_intent() -> Tick {
        Tick::Seal
    }

    fn sealed(receipts: &[Note]) -> Option<Checkpoint> {
        receipts.iter().find_map(|r| match r {
            Note::Sealed(cp) => Some(*cp),
            _ => None,
        })
    }

    fn as_sealed(&self, cp: &Checkpoint) -> Option<Self> {
        if cp.chain_id != self.chain_id {
            return None;
        }
        let mut s = self.clone();
        s.epoch = cp.epoch;
        s.seq = cp.seq;
        s.parent_root = cp.parent_root;
        s.intent_acc = cp.intent_root;
        s.epoch_intents = cp.intents;
        (s.state_root() == cp.state_root).then_some(s)
    }

    fn rejected(r: &Note) -> bool {
        matches!(r, Note::Refused(_))
    }

    fn unprovable(_: &Note) -> bool {
        false // every refusal here is an ordinary one
    }

    fn encode_intent(intent: &Tick) -> Vec<u8> {
        let mut e = Encoder::new();
        match intent {
            Tick::Add { who, n } => {
                e.u8(1).bytes(who).u64(*n);
            }
            Tick::Clear { who } => {
                e.u8(2).bytes(who);
            }
            Tick::Seal => {
                e.u8(3);
            }
        }
        e.finish().to_vec()
    }

    fn decode_intent(d: &mut Decoder) -> Option<Tick> {
        Some(match d.u8().ok()? {
            1 => Tick::Add { who: d.account().ok()?, n: d.u64().ok()? },
            2 => Tick::Clear { who: d.account().ok()? },
            3 => Tick::Seal,
            _ => return None,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u16(Self::VM_VERSION)
            .u32(self.chain_id)
            .u64(self.epoch)
            .u64(self.seq)
            .u64(self.limits.max_step)
            .bytes(&self.parent_root)
            .bytes(&self.intent_acc)
            .u64(self.epoch_intents)
            .u64(self.total)
            .u32(self.tallies.len() as u32);
        for (who, n) in &self.tallies {
            e.bytes(who).u64(*n);
        }
        e.finish().to_vec()
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut d = Decoder::new(bytes);
        if d.u16().ok()? != Self::VM_VERSION {
            return None;
        }
        let mut s = TallyVm {
            chain_id: d.u32().ok()?,
            epoch: d.u64().ok()?,
            seq: d.u64().ok()?,
            limits: Limits { max_step: d.u64().ok()? },
            parent_root: d.hash().ok()?,
            intent_acc: d.hash().ok()?,
            epoch_intents: d.u64().ok()?,
            tallies: BTreeMap::new(),
            total: d.u64().ok()?,
        };
        let n = d.u32().ok()?;
        for _ in 0..n {
            let who = d.account().ok()?;
            s.tallies.insert(who, d.u64().ok()?);
        }
        // S10: trailing bytes are refused, not ignored.
        (d.remaining() == 0).then_some(s)
    }

    fn account_ids(&self) -> Vec<AccountId> {
        self.tallies.keys().copied().collect()
    }

    fn account_leaves(&self) -> Vec<Hash> {
        self.account_ids()
            .iter()
            .map(|id| hash_leaf(&self.account_record(id).unwrap()))
            .collect()
    }

    fn account_record(&self, id: &AccountId) -> Option<Vec<u8>> {
        let n = self.tallies.get(id)?;
        let mut e = Encoder::new();
        e.bytes(b"tally.account.v1").bytes(id).u64(*n);
        Some(e.finish().to_vec())
    }

    fn leaf_of_record(record: &[u8]) -> Hash {
        hash_leaf(record)
    }

    fn gross_volume(&self) -> Fixed {
        Fixed::whole(self.total as i64)
    }

    /// S11. Recomputed from the tallies rather than restated from `total`, so
    /// it can actually disagree with the transition that produced it.
    fn conserved(&self) -> Result<(), &'static str> {
        let summed: u64 = self.tallies.values().copied().sum();
        if summed != self.total {
            return Err("running total does not equal the sum of tallies");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------


pub fn acct(n: u8) -> AccountId {
    [n; 32]
}

pub fn seeded() -> TallyVm {
    let mut vm = TallyVm::genesis(77, Limits { max_step: 1_000 });
    for n in 1..=5u8 {
        let at = vm.seq();
        vm.apply(at + 1, &Tick::Add { who: acct(n), n: 10 * n as u64 });
    }
    vm
}
