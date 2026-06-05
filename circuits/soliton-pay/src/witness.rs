//! Build satisfying (and deliberately unsatisfying) SOLITON-Pay witnesses.
//!
//! We construct two input notes, place their commitments at chosen leaf
//! indices in a depth-D Merkle tree (all other leaves are a fixed empty-leaf
//! constant), compute the root with the SAME native Poseidon used in
//! circuit, derive authentication paths, pick balancing output notes, and set
//! the public inputs.

use halo2curves::bn256::Fr;

use crate::circuit::{MerklePath, Note, SolitonCircuit};
use crate::poseidon;

/// Empty-leaf sentinel value for unused tree positions.
fn empty_leaf() -> Fr {
    Fr::from(0xE9E9_E9E9u64)
}

/// Precompute the root of an all-empty subtree at each level: `empty[0]` is an
/// empty leaf, `empty[l] = H(empty[l-1], empty[l-1])`. O(D) — does NOT
/// materialize the 2^D leaves.
fn empty_subtree_roots(depth: usize) -> Vec<Fr> {
    let mut e = Vec::with_capacity(depth + 1);
    e.push(empty_leaf());
    for l in 1..=depth {
        let prev = e[l - 1];
        e.push(poseidon::hash2_native(prev, prev));
    }
    e
}

/// Compute the depth-`depth` Merkle root of a tree whose ONLY non-empty leaves
/// are `cm0` at index 0 and `cm1` at index 1 (they are siblings under the same
/// parent at the bottom). Returns the root and the auth paths for both leaves.
/// O(D): every other subtree is all-empty, so its root is `empty_subtree_roots`.
fn sparse_tree_root_and_paths(
    cm0: Fr,
    cm1: Fr,
    depth: usize,
) -> (Fr, MerklePath, MerklePath) {
    let empty = empty_subtree_roots(depth);

    // Bottom level: leaf 0 (left, bit=false) sibling is leaf 1; leaf 1 (right,
    // bit=true) sibling is leaf 0.
    let mut sib0 = vec![cm1]; // siblings for path of leaf 0
    let mut bit0 = vec![false];
    let mut sib1 = vec![cm0]; // siblings for path of leaf 1
    let mut bit1 = vec![true];

    // The parent node of leaves 0,1 is at index 0 of level 1.
    let mut node = poseidon::hash2_native(cm0, cm1);
    // Above the bottom both leaves share the same node, hence identical
    // remaining path. At each level the current node is the LEFT child (index 0)
    // and its sibling is an all-empty subtree.
    for l in 1..depth {
        let sib = empty[l]; // empty subtree root at this level
        sib0.push(sib);
        bit0.push(false);
        sib1.push(sib);
        bit1.push(false);
        node = poseidon::hash2_native(node, sib);
        let _ = l;
    }

    (
        node,
        MerklePath { siblings: sib0, bits: bit0 },
        MerklePath { siblings: sib1, bits: bit1 },
    )
}

/// Deterministic field element from seed + tag.
fn fe(seed: [u8; 32], tag: u64) -> Fr {
    let mut s = Fr::from(tag + 1);
    for (i, b) in seed.iter().enumerate() {
        s += Fr::from((*b as u64) << (i % 8)) * Fr::from(0x100000001u64 + tag);
    }
    s
}

/// Build a satisfying circuit of Merkle depth `depth`.
pub fn build_satisfying(depth: usize, seed: [u8; 32]) -> SolitonCircuit {
    // Two input notes.
    let in0 = Note { value: 100, sk: fe(seed, 1), rho: fe(seed, 2) };
    let in1 = Note { value: 50, sk: fe(seed, 3), rho: fe(seed, 4) };

    // pub_amount and balancing outputs:
    //   vin0 + vin1 + pub_amount == vout0 + vout1
    //   100 + 50 + 30 = 180 = 120 + 60
    let pub_amount = 30i128;
    let out0 = Note { value: 120, sk: fe(seed, 5), rho: fe(seed, 6) };
    let out1 = Note { value: 60, sk: fe(seed, 7), rho: fe(seed, 8) };

    // Build a Merkle tree containing cm(in0) at idx 0 and cm(in1) at idx 1.
    // Sparse construction (O(D), no 2^D materialization) — all other leaves are
    // the empty-leaf sentinel.
    let (root, path0, path1) = sparse_tree_root_and_paths(in0.cm(), in1.cm(), depth);

    SolitonCircuit {
        depth,
        inputs: [in0, in1],
        paths: [path0, path1],
        outputs: [out0, out1],
        out_pk: [None, None],
        pub_amount,
        root,
        range_break: None,
    }
}

// ---- witness constructor (Stage 2 bridge) ------------------------------------

/// An input note the spender owns: its spending key, value, randomness, and
/// its authenticated position in the on-chain Merkle tree.
#[derive(Clone, Debug)]
pub struct InputNote {
    pub sk: Fr,
    pub value: u64,
    pub rho: Fr,
    pub leaf_index: u64,
    /// Sibling hashes from leaf up to (but not including) the root, length =
    /// tree depth.
    pub merkle_path: Vec<Fr>,
    /// Path bits: false = this node is the LEFT child at that level.
    pub path_bits: Vec<bool>,
}

/// An output note: paid to `pk_owner` (recipient's published key — the
/// builder need NOT know the recipient's sk), of `value`, blinded by `rho`.
#[derive(Clone, Debug)]
pub struct OutputNote {
    pub value: u64,
    pub pk_owner: Fr,
    pub rho: Fr,
}

/// Recompute a Merkle root from a leaf + authentication path (native Poseidon).
/// Mirrors the in-circuit `merkle_root` conditional-swap chain so the verified
/// root is bit-identical to what the circuit computes.
pub fn merkle_root_from_path(leaf: Fr, siblings: &[Fr], bits: &[bool]) -> Fr {
    let mut cur = leaf;
    for (sib, bit) in siblings.iter().zip(bits.iter()) {
        let (l, r) = if *bit { (*sib, cur) } else { (cur, *sib) };
        cur = poseidon::hash2_native(l, r);
    }
    cur
}

/// Build a `SolitonCircuit` + its 6 public inputs from transfer data.
///
/// - input note pk derived in-circuit from `sk` (spender proves knowledge),
/// - output commitments bound to the recipient's published `pk_owner`,
/// - each input's Merkle path is recomputed natively and ASSERTED to equal
///   `root` (so a wrong path is caught here, before proving),
/// - `pub_amount` is the signed external delta (shield +, unshield −, here
///   typically `-fee` for an internal transfer).
///
/// Returns the circuit and the public-input vector `[root, nf1, nf2, cmout1,
/// cmout2, pub_amount]`.
pub fn build_transfer_circuit(
    inputs: [InputNote; 2],
    outputs: [OutputNote; 2],
    pub_amount: i128,
    root: Fr,
    depth: usize,
) -> (SolitonCircuit, Vec<Fr>) {
    let in_notes: [Note; 2] = [
        Note { value: inputs[0].value, sk: inputs[0].sk, rho: inputs[0].rho },
        Note { value: inputs[1].value, sk: inputs[1].sk, rho: inputs[1].rho },
    ];

    // Verify each input's path reproduces `root` (catches a stale/local tree).
    for (i, n) in inputs.iter().enumerate() {
        assert_eq!(n.merkle_path.len(), depth, "input {i} path len != depth");
        assert_eq!(n.path_bits.len(), depth, "input {i} bits len != depth");
        let cm = in_notes[i].cm();
        let r = merkle_root_from_path(cm, &n.merkle_path, &n.path_bits);
        assert_eq!(r, root, "input {i} Merkle path does NOT reproduce root");
    }

    let paths = [
        MerklePath { siblings: inputs[0].merkle_path.clone(), bits: inputs[0].path_bits.clone() },
        MerklePath { siblings: inputs[1].merkle_path.clone(), bits: inputs[1].path_bits.clone() },
    ];

    // Output notes: value+rho in `Note`, pk_owner supplied via out_pk so the
    // commitment binds to the recipient's published key (sk unknown to sender).
    let out_notes: [Note; 2] = [
        Note { value: outputs[0].value, sk: Fr::zero(), rho: outputs[0].rho },
        Note { value: outputs[1].value, sk: Fr::zero(), rho: outputs[1].rho },
    ];

    let circuit = SolitonCircuit {
        depth,
        inputs: in_notes,
        paths,
        outputs: out_notes,
        out_pk: [Some(outputs[0].pk_owner), Some(outputs[1].pk_owner)],
        pub_amount,
        root,
        range_break: None,
    };
    let instance = circuit.instance();
    (circuit, instance)
}

/// Build an UNSATISFYING circuit by breaking the value balance (vout too large),
/// keeping the public inputs consistent with the *claimed* (wrong) notes so the
/// failure is the balance constraint, not an instance mismatch.
///
/// `mode`:
///  - "balance": outputs sum != inputs + pub_amount.
///  - "range":   an output value >= 2^64 (will fail the range lookup/recompose).
///  - "nullifier": tamper the public nf1 so the nf copy-constraint to instance fails.
pub fn build_unsatisfying(depth: usize, seed: [u8; 32], mode: &str) -> (SolitonCircuit, Vec<Fr>) {
    let mut c = build_satisfying(depth, seed);
    match mode {
        "balance" => {
            // Make outputs sum to more than allowed; recompute instance from the
            // tampered outputs so cmout public values still match (isolate the
            // balance gate as the failing constraint).
            c.outputs[1].value = 999; // 120 + 999 != 180
            let inst = c.instance();
            (c, inst)
        }
        "range" => {
            // Exercise the range gate: force value_cell to carry a value that is
            // NOT representable as 8 u8 limbs. We do this with a dedicated
            // circuit field that injects a >2^64 value into the output value cell
            // while the limb decomposition (still from u64) cannot recompose to
            // it, so the recomposition-equality / lookup binds and fails.
            c.range_break = Some(0); // break output 0's range
            let inst = c.instance();
            (c, inst)
        }
        "nullifier" => {
            let mut inst = c.instance();
            inst[1] += Fr::one(); // tamper nf1 public value
            (c, inst)
        }
        _ => {
            let inst = c.instance();
            (c, inst)
        }
    }
}
