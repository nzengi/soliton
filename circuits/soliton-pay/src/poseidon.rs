//! Minimal self-contained Poseidon permutation, width t = 3, S-box x^5,
//! over BN254 scalar field `Fr`.
//!
//! WHY a custom chip (not `halo2_gadgets`): the workspace pins `halo2_proofs`
//! to the PSE git tag v0.3.0 (commit 73408a1). The crates.io `halo2_gadgets`
//! versions 0.3.0 / 0.3.1 (the ones that match the *crates.io* halo2_proofs
//! 0.3.0 API) are BOTH YANKED on crates.io, and 0.5.0 targets a different
//! (post-split) halo2 API that does not compile against this pinned backend.
//! The PSE git tree at tag v0.3.0 also does not ship a `halo2_gadgets` crate.
//! So per the brief's fallback clause we implement a minimal Poseidon chip
//! directly against halo2_proofs.
//!
//! The SAME constants (`ROUND_CONSTANTS`, `MDS`) drive both the native
//! reference permutation (`permute_native`) used to build the witness/Merkle
//! root and the in-circuit `PoseidonChip`, so the in-circuit hash is bit-for-bit
//! equal to the native hash. That equality — not conformance to an external
//! Poseidon spec — is what soundness of this circuit requires.
//!
//! Parameters: t = 3 (rate 2, capacity 1), full rounds R_F = 8, partial rounds
//! R_P = 56. Total rounds R = 64. Constants are derived deterministically (see
//! `gen_constants`) so they are reproducible and unstructured.

use halo2curves::bn256::Fr;
use halo2curves::ff::Field;

pub const T: usize = 3;
pub const R_F: usize = 8;
pub const R_P: usize = 56;
pub const ROUNDS: usize = R_F + R_P; // 64

/// Deterministic field element from a 64-bit counter, via repeated squaring of
/// a fixed seed mixed with the counter. Unstructured enough for round constants
/// in a *consistency-only* (native == in-circuit) setting.
fn fe_from_counter(seed: u64, ctr: u64) -> Fr {
    // Mix counter into a large value then reduce mod field by Fr::from + powers.
    let mut acc = Fr::from(seed)
        + Fr::from(0x9E3779B97F4A7C15u64) * Fr::from(ctr + 1)
        + Fr::from(0xBF58476D1CE4E5B9u64);
    // A few nonlinear steps to spread bits across the whole field.
    for _ in 0..5 {
        acc = acc.square() + acc + Fr::from(ctr.wrapping_mul(0x94D049BB133111EBu64));
    }
    acc
}

/// Generate round constants: ROUNDS * T values.
fn gen_round_constants() -> Vec<[Fr; T]> {
    let mut out = Vec::with_capacity(ROUNDS);
    let mut ctr = 0u64;
    for _ in 0..ROUNDS {
        let mut row = [Fr::ZERO; T];
        for r in row.iter_mut() {
            *r = fe_from_counter(0xA110CA7Eu64, ctr);
            ctr += 1;
        }
        out.push(row);
    }
    out
}

/// Generate an invertible-by-construction MDS-style matrix (Cauchy matrix:
/// M[i][j] = 1 / (x_i + y_j) with distinct x_i, y_j). Cauchy matrices are MDS.
fn gen_mds() -> [[Fr; T]; T] {
    // x_i = i, y_j = T + j  -> all (x_i + y_j) distinct & nonzero.
    let xs: [Fr; T] = std::array::from_fn(|i| Fr::from(i as u64));
    let ys: [Fr; T] = std::array::from_fn(|j| Fr::from((T + j) as u64));
    let mut m = [[Fr::ZERO; T]; T];
    for i in 0..T {
        for j in 0..T {
            let denom = xs[i] + ys[j];
            m[i][j] = denom.invert().unwrap();
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

/// Native Poseidon permutation on a width-3 state. Mutates `state` in place.
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

/// 2-to-1 native hash: H(a, b). Sponge with capacity element initialised to a
/// domain tag (here the field encoding of `2`), absorb (a,b) into rate, permute,
/// squeeze state[0].
pub fn hash2_native(a: Fr, b: Fr) -> Fr {
    let mut state = [Fr::from(2u64), a, b];
    permute_native(&mut state);
    state[0]
}

/// 3-to-1 native hash: H(a, b, c) via sequential 2-to-1 absorption:
/// H3(a,b,c) = H2( H2(a, b), c ). Documented arity choice: we use the width-3
/// 2-to-1 permutation twice rather than a separate width-4 spec, so a single
/// Poseidon chip serves the whole circuit.
pub fn hash3_native(a: Fr, b: Fr, c: Fr) -> Fr {
    hash2_native(hash2_native(a, b), c)
}
