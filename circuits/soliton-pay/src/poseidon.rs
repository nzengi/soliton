//! circom-BN254 Poseidon permutation, width t = 3, S-box x^5, over BN254 scalar
//! field `Fr` (halo2curves). This is the IN-CIRCUIT twin of the shared crate
//! `soliton-poseidon` and of `light-poseidon` / the `sol_poseidon` syscall.
//!
//! WHY a custom chip (not `halo2_gadgets`): the workspace pins `halo2_proofs`
//! to the PSE git tag v0.3.0 (commit 73408a1). The crates.io `halo2_gadgets`
//! versions 0.3.0 / 0.3.1 are BOTH YANKED, and 0.5.0 targets a different
//! (post-split) halo2 API. So we implement a minimal Poseidon chip directly
//! against halo2_proofs.
//!
//! Parameters (circom-BN254): t = 3 (rate 2, capacity 1), full rounds R_F = 8,
//! partial rounds R_P = 57, total R = 65, alpha = 5. The round constants (`ark`,
//! flat width*R) and 3x3 MDS matrix are the circomlib constants, decoded HERE
//! from the SAME little-endian byte tables baked into the shared crate
//! (`soliton_poseidon::ARK_LE` / `MDS_LE`) — which were themselves pulled from
//! `light-poseidon`. Decoding the identical bytes into halo2curves `Fr`
//! guarantees the in-circuit hash is bit-for-bit equal to the shared crate, to
//! light-poseidon, and to the `sol_poseidon` syscall. That equality is what
//! lets the on-chain Merkle tree use the cheap syscall.
//!
//! State / sponge convention (circom): state = [domain_tag = 0, in0, in1];
//! per round add ark → S-box → MDS; full rounds S-box all lanes, partial rounds
//! lane 0 only; output is lane 0.

use halo2curves::bn256::Fr;
use halo2curves::ff::{Field, PrimeField};

use soliton_poseidon::{ARK_LE, MDS_LE};

pub const T: usize = 3;
pub const R_F: usize = 8;
pub const R_P: usize = 57;
pub const ROUNDS: usize = R_F + R_P; // 65

/// Decode 32 canonical LE bytes into a halo2curves `Fr`. The baked tables are
/// canonical (produced from light-poseidon / ark `into_bigint().to_bytes_le()`),
/// so `from_repr` (which takes a canonical LE little-endian repr) succeeds.
fn fr_from_le(b: &[u8; 32]) -> Fr {
    let mut repr = <Fr as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(b);
    let ct = Fr::from_repr(repr);
    assert!(bool::from(ct.is_some()), "non-canonical baked constant");
    ct.unwrap()
}

/// Round constants reshaped to ROUNDS rows of T lanes (decoded from the shared
/// crate's `ARK_LE`).
fn gen_round_constants() -> Vec<[Fr; T]> {
    ARK_LE
        .iter()
        .map(|row| [fr_from_le(&row[0]), fr_from_le(&row[1]), fr_from_le(&row[2])])
        .collect()
}

/// circom-BN254 width-3 MDS matrix (decoded from the shared crate's `MDS_LE`).
fn gen_mds() -> [[Fr; T]; T] {
    let mut m = [[Fr::ZERO; T]; T];
    for (i, row) in MDS_LE.iter().enumerate() {
        for (j, e) in row.iter().enumerate() {
            m[i][j] = fr_from_le(e);
        }
    }
    m
}

thread_local! {
    static RC: Vec<[Fr; T]> = gen_round_constants();
    static MDS_M: [[Fr; T]; T] = gen_mds();
}

pub fn round_constants() -> Vec<[Fr; T]> {
    RC.with(|r| r.clone())
}
pub fn mds() -> [[Fr; T]; T] {
    MDS_M.with(|m| *m)
}

#[inline]
fn sbox(x: Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

/// Native circom-BN254 Poseidon permutation on a width-3 state. Mutates `state`
/// in place. Identical round order to `soliton_poseidon::permute`.
pub fn permute_native(state: &mut [Fr; T]) {
    let rc = round_constants();
    let m = mds();
    let half_full = R_F / 2;

    let apply_mds = |s: &[Fr; T]| -> [Fr; T] {
        let mut out = [Fr::ZERO; T];
        for (i, oi) in out.iter_mut().enumerate() {
            let mut acc = Fr::ZERO;
            for j in 0..T {
                acc += m[i][j] * s[j];
            }
            *oi = acc;
        }
        out
    };

    let mut round = 0usize;
    // First half of full rounds.
    for _ in 0..half_full {
        for i in 0..T {
            state[i] += rc[round][i];
        }
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        *state = apply_mds(state);
        round += 1;
    }
    // Partial rounds (S-box on first element only).
    for _ in 0..R_P {
        for i in 0..T {
            state[i] += rc[round][i];
        }
        state[0] = sbox(state[0]);
        *state = apply_mds(state);
        round += 1;
    }
    // Second half of full rounds.
    for _ in 0..half_full {
        for i in 0..T {
            state[i] += rc[round][i];
        }
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        *state = apply_mds(state);
        round += 1;
    }
    debug_assert_eq!(round, ROUNDS);
}

/// 2-to-1 native hash H(a, b): circom convention — state = [domain_tag = 0, a, b],
/// permute, squeeze lane 0.
pub fn hash2_native(a: Fr, b: Fr) -> Fr {
    let mut state = [Fr::ZERO, a, b];
    permute_native(&mut state);
    state[0]
}

/// 3-to-1 native hash: H(a, b, c) = H2( H2(a, b), c ).
pub fn hash3_native(a: Fr, b: Fr, c: Fr) -> Fr {
    hash2_native(hash2_native(a, b), c)
}
