//! The note tree: append-only, depth [`DEPTH`], empty leaves are zero.
//!
//! The pools on-chain keep only the filled subtrees and a window of recent
//! roots; this keeps every leaf, because a wallet needs a path.

use crate::{poseidon, DEPTH};
use ark_bn254::Fr;
use ark_ff::Zero;

/// The root of an empty subtree at each height: `zeros()[0]` is an empty
/// leaf, `zeros()[DEPTH]` the root of the empty tree.
pub fn zeros() -> [Fr; DEPTH + 1] {
    let mut z = [Fr::zero(); DEPTH + 1];
    for i in 1..=DEPTH {
        z[i] = poseidon(&[z[i - 1], z[i - 1]]);
    }
    z
}

/// A path from a leaf to the root: the sibling at each level, and whether the
/// leaf's side is the right one (bit set) at that level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path {
    pub siblings: [Fr; DEPTH],
    pub right: [bool; DEPTH],
}

impl Path {
    /// The root this path reaches from `leaf`.
    pub fn root(&self, leaf: Fr) -> Fr {
        let mut cur = leaf;
        for i in 0..DEPTH {
            cur = if self.right[i] { poseidon(&[self.siblings[i], cur]) } else { poseidon(&[cur, self.siblings[i]]) };
        }
        cur
    }
}

#[derive(Clone, Debug)]
pub struct Tree {
    leaves: Vec<Fr>,
    zeros: [Fr; DEPTH + 1],
}

impl Default for Tree {
    fn default() -> Self {
        Tree { leaves: Vec::new(), zeros: zeros() }
    }
}

impl Tree {
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Append a leaf; its index.
    pub fn insert(&mut self, leaf: Fr) -> usize {
        assert!(self.leaves.len() < 1 << DEPTH, "the tree is full");
        self.leaves.push(leaf);
        self.leaves.len() - 1
    }

    /// Every node at `level` (0 = leaves) that is not an empty subtree.
    fn level(&self, level: usize) -> Vec<Fr> {
        let mut nodes = self.leaves.clone();
        for l in 0..level {
            nodes = nodes
                .chunks(2)
                .map(|p| poseidon(&[p[0], *p.get(1).unwrap_or(&self.zeros[l])]))
                .collect();
        }
        nodes
    }

    pub fn root(&self) -> Fr {
        self.level(DEPTH).first().copied().unwrap_or(self.zeros[DEPTH])
    }

    /// The path for the leaf at `index`.
    pub fn path(&self, index: usize) -> Path {
        assert!(index < self.leaves.len(), "no leaf there");
        let mut siblings = [Fr::zero(); DEPTH];
        let mut right = [false; DEPTH];
        let mut nodes = self.leaves.clone();
        let mut at = index;
        for l in 0..DEPTH {
            right[l] = at % 2 == 1;
            let sib = at ^ 1;
            siblings[l] = *nodes.get(sib).unwrap_or(&self.zeros[l]);
            nodes = nodes.chunks(2).map(|p| poseidon(&[p[0], *p.get(1).unwrap_or(&self.zeros[l])])).collect();
            at /= 2;
        }
        Path { siblings, right }
    }
}
