//! State commitments: the encoding, the tree, and the inclusion proof.
//!
//! Part of the spec rather than of an application, because these are what a
//! settlement verifier, a light client and a data-availability consumer all
//! have to agree on byte-for-byte. A VM that hashed its state differently could
//! not be anchored by the same chain, proved by the same verifier, or exited
//! through the same escape hatch.
//!
//! The rules every Zyn VM inherits by using this module:
//!
//! - **Fixed-width big-endian encoding.** No varints, no length-prefixed
//!   ambiguity, no platform endianness.
//! - **Ordering comes from the data structure, not from history.** Iterate
//!   ordered maps in key order; two nodes that applied the same intents then
//!   agree byte-for-byte.
//! - **Domain-separated hashing.** Leaves and internal nodes hash under
//!   different prefixes, so no leaf can be reinterpreted as an internal node.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Fixed-width big-endian byte sink.
#[derive(Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Encoder { buf: Vec::new() }
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn i128(&mut self, v: i128) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn fixed(&mut self, v: crate::fixed::Fixed) -> &mut Self {
        self.i128(v.0)
    }
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }
    /// An `Option<u32>` as a presence byte plus a fixed-width value, so the
    /// absent case has the same length as the present one.
    pub fn opt_u32(&mut self, v: Option<u32>) -> &mut Self {
        match v {
            Some(x) => self.u8(1).u32(x),
            None => self.u8(0).u32(0),
        }
    }
    /// An optional opaque 32-byte identity as a presence byte plus a fixed
    /// payload. The zero payload in the absent case keeps the shape fixed.
    pub fn opt_hash(&mut self, v: Option<[u8; 32]>) -> &mut Self {
        match v {
            Some(x) => self.u8(1).bytes(&x),
            None => self.u8(0).bytes(&[0u8; 32]),
        }
    }
    pub fn finish(&self) -> &[u8] {
        &self.buf
    }
    pub fn leaf(&self) -> Hash {
        hash_leaf(&self.buf)
    }
}

pub fn hash_leaf(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(data);
    h.finalize().into()
}

pub fn hash_node(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// Binary Merkle root over ordered leaves. An odd node at any level is promoted
/// unchanged rather than duplicated — duplicating enables the CVE-2012-2459
/// style collision where two distinct trees share a root.
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(hash_node(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            next.push(level[i]);
        }
        level = next;
    }
    level[0]
}

/// One step of a Merkle inclusion path: the sibling to hash against, and
/// whether the node being proved sits on the right.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProofStep {
    pub sibling: Hash,
    pub node_is_right: bool,
}

/// Build an inclusion path for `index` in a tree over `leaves`.
///
/// Mirrors `merkle_root` exactly, including odd-node promotion: a promoted node
/// has no sibling at that level, so it contributes **no** step. A verifier must
/// therefore be given the side flags rather than deriving them from the index,
/// since promotion breaks the usual index-parity rule.
pub fn merkle_proof(leaves: &[Hash], index: usize) -> Vec<ProofStep> {
    let mut path = Vec::new();
    if index >= leaves.len() {
        return path;
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    let mut idx = index;

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            if idx == i {
                path.push(ProofStep {
                    sibling: level[i + 1],
                    node_is_right: false,
                });
            } else if idx == i + 1 {
                path.push(ProofStep {
                    sibling: level[i],
                    node_is_right: true,
                });
            }
            next.push(hash_node(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            // Promoted unchanged: no sibling, so no step.
            next.push(level[i]);
        }
        idx /= 2;
        level = next;
    }
    path
}

/// Leaves held once so many proofs can be served from them.
///
/// Building a proof from a state means hashing every leaf. That is the right
/// cost to pay when a proof is taken once — and the wrong one for an endpoint,
/// where it makes each request cost what the whole tree costs. Measured on the
/// account tree: 26 ms per proof at 50,000 accounts, or about forty requests a
/// second on a core, for work that is `log(n)` hashes once the leaves are in
/// hand.
///
/// A node builds one of these when it seals an epoch and serves every proof for
/// that root from it. The leaves are immutable for the life of a root, which is
/// exactly the lifetime a proof is valid for, so there is no invalidation
/// problem to get wrong.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProofIndex {
    /// Every level, leaves first, root last. Holding only the leaves is not
    /// enough: `merkle_proof` rebuilds each level on every call, so an index
    /// over leaves alone is still linear per request — measured at 10.8 ms for
    /// 50,000 accounts, against 26.9 ms for a full rebuild. Keeping the levels
    /// is what makes a proof `log(n)`.
    levels: Vec<Vec<Hash>>,
}

impl ProofIndex {
    pub fn build(leaves: Vec<Hash>) -> ProofIndex {
        let mut levels = alloc::vec![leaves];
        while levels.last().map(|l| l.len()).unwrap_or(0) > 1 {
            let level = levels.last().expect("checked");
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i + 1 < level.len() {
                next.push(hash_node(&level[i], &level[i + 1]));
                i += 2;
            }
            if i < level.len() {
                // Promoted unchanged, exactly as `merkle_root` does.
                next.push(level[i]);
            }
            levels.push(next);
        }
        ProofIndex { levels }
    }

    pub fn root(&self) -> Hash {
        self.levels
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or([0u8; 32])
    }
    pub fn len(&self) -> usize {
        self.levels.first().map(|l| l.len()).unwrap_or(0)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn leaves(&self) -> &[Hash] {
        self.levels.first().map(|l| l.as_slice()).unwrap_or(&[])
    }
    pub fn leaf(&self, index: usize) -> Option<Hash> {
        self.levels.first()?.get(index).copied()
    }

    /// The inclusion path for one leaf: one sibling read per level.
    ///
    /// Must agree with `merkle_proof` exactly, including odd-node promotion — a
    /// promoted node has no sibling at its level and contributes no step, which
    /// is why the side flag is carried rather than derived from index parity.
    pub fn proof(&self, index: usize) -> Option<Vec<ProofStep>> {
        if index >= self.len() {
            return None;
        }
        let mut path = Vec::with_capacity(self.levels.len());
        let mut idx = index;
        for level in self.levels.iter().take(self.levels.len().saturating_sub(1)) {
            let paired = level.len() - (level.len() % 2);
            if idx < paired {
                path.push(ProofStep {
                    sibling: level[idx ^ 1],
                    node_is_right: idx % 2 == 1,
                });
            }
            idx /= 2;
        }
        Some(path)
    }
}

/// Verify a path. Used in tests, by light clients, and as the reference any
/// settlement-side verifier must agree with.
pub fn verify_proof(leaf: Hash, path: &[ProofStep], root: Hash) -> bool {
    let mut node = leaf;
    for step in path {
        node = if step.node_is_right {
            hash_node(&step.sibling, &node)
        } else {
            hash_node(&node, &step.sibling)
        };
    }
    node == root
}

/// Fold one intent into an epoch's rolling transaction commitment.
///
/// A hash chain rather than a tree: it is O(1) in state, it commits to order as
/// well as content, and it can be extended one intent at a time without holding
/// the epoch's whole history in memory — which matters because a checkpoint may
/// cover tens of thousands of actions.
///
/// The chain is seeded with the previous accumulator, so an epoch's commitment
/// cannot be replayed as another epoch's.
pub fn fold_intent(acc: Hash, seq: u64, encoded_intent: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(acc);
    h.update(seq.to_be_bytes());
    h.update(encoded_intent);
    h.finalize().into()
}

#[cfg(test)]
mod index_tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| hash_leaf(&(i as u32).to_be_bytes()))
            .collect()
    }

    /// An index must agree with the one-shot path exactly, or a node serving
    /// from it would hand out proofs a verifier rejects.
    #[test]
    fn an_index_serves_the_same_proofs_as_a_rebuild() {
        for n in [1usize, 2, 3, 7, 33, 128] {
            let ls = leaves(n);
            let idx = ProofIndex::build(ls.clone());
            assert_eq!(idx.root(), merkle_root(&ls));
            for i in 0..n {
                let from_index = idx.proof(i).expect("in range");
                assert_eq!(from_index, merkle_proof(&ls, i), "size {} index {}", n, i);
                assert!(verify_proof(ls[i], &from_index, idx.root()));
            }
            assert!(
                idx.proof(n).is_none(),
                "an out-of-range index produced a proof"
            );
        }
    }

    #[test]
    fn an_empty_index_has_the_empty_root() {
        let idx = ProofIndex::build(Vec::new());
        assert!(idx.is_empty());
        assert_eq!(idx.root(), [0u8; 32]);
        assert!(idx.proof(0).is_none());
    }
}
