//! Local incremental Merkle tree (host) that mirrors the on-chain pool's tree
//! EXACTLY: depth `DEPTH`, leaves inserted left-to-right starting at index 0,
//! all not-yet-filled positions are the empty-subtree sentinel, internal node =
//! `H2(left, right)` via the SHARED poseidon (== `sol_poseidon`).
//!
//! Unlike the on-chain pool (which keeps only a frontier and cannot reproduce an
//! arbitrary leaf's authentication path), the wallet stores ALL inserted leaves
//! so it can build Merkle paths for the notes it owns. The root it computes is
//! byte-identical to the pool's `PoolState.root` after the same inserts — proven
//! in the `mollusk` integration test.

use ark_bn254::Fr;
use soliton_poseidon as sp;

pub const DEPTH: usize = 32;

#[derive(Clone)]
pub struct LocalTree {
    /// All leaves inserted so far, in insertion order (index == leaf position).
    leaves: Vec<Fr>,
    /// Cached empty-subtree root per level: `empty[l]` = root of an all-empty
    /// subtree of height `l`.
    empty: Vec<Fr>,
    depth: usize,
}

impl Default for LocalTree {
    fn default() -> Self {
        Self::new(DEPTH)
    }
}

impl LocalTree {
    pub fn new(depth: usize) -> Self {
        let empty: Vec<Fr> = (0..=depth).map(sp::empty_subtree_root).collect();
        Self { leaves: Vec::new(), empty, depth }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn next_index(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Insert a leaf at the next free index; returns that index.
    pub fn insert(&mut self, leaf: Fr) -> u64 {
        let idx = self.leaves.len() as u64;
        self.leaves.push(leaf);
        idx
    }

    /// Node value at (`level`, `node_index`). Level 0 = leaves. Positions beyond
    /// the inserted range collapse to the empty-subtree root for that level.
    fn node(&self, level: usize, node_index: usize) -> Fr {
        if level == 0 {
            return self
                .leaves
                .get(node_index)
                .copied()
                .unwrap_or(self.empty[0]);
        }
        // If the whole subtree under this node is empty (its leftmost leaf index
        // is past the last inserted leaf), short-circuit to the empty root.
        let leaves_per_node = 1usize << level;
        let first_leaf = node_index * leaves_per_node;
        if first_leaf >= self.leaves.len() {
            return self.empty[level];
        }
        let l = self.node(level - 1, node_index * 2);
        let r = self.node(level - 1, node_index * 2 + 1);
        sp::hash2(l, r)
    }

    /// Current root (depth-`depth` tree with empty fill).
    pub fn root(&self) -> Fr {
        self.node(self.depth, 0)
    }

    /// Authentication path for the leaf at `leaf_index`: (siblings, bits) from the
    /// bottom up, length = depth. `bit[l] == true` means the current node is the
    /// RIGHT child at level `l` (so its sibling is on the left).
    pub fn path(&self, leaf_index: u64) -> (Vec<Fr>, Vec<bool>) {
        let mut siblings = Vec::with_capacity(self.depth);
        let mut bits = Vec::with_capacity(self.depth);
        let mut idx = leaf_index as usize;
        for level in 0..self.depth {
            let is_right = idx & 1 == 1;
            let sib_index = if is_right { idx - 1 } else { idx + 1 };
            siblings.push(self.node(level, sib_index));
            bits.push(is_right);
            idx >>= 1;
        }
        (siblings, bits)
    }
}
