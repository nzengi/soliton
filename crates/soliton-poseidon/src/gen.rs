//! Host-only constant GENERATION for the circom-BN254 Poseidon (t = 3, x^5,
//! R_F = 8, R_P = 57). The constants (round constants `ark` + MDS matrix) are
//! pulled DIRECTLY from `light-poseidon`'s `bn254_x5` parameter set — the exact
//! same table the `sol_poseidon` syscall uses (the syscall is light-poseidon on
//! host, the SBF native implementation on-chain, both circomlib constants).
//!
//! This module exists so the baked tables in `constants.rs` can be regenerated
//! and proven identical to light-poseidon. The BPF permutation reads the
//! PRE-BAKED tables; it never calls into this module.
//!
//! NOTE: host/regen only (uses `light-poseidon`, which is std).

use ark_bn254::Fr;

use crate::T;

pub const R_F: usize = 8;
pub const R_P: usize = 57;
pub const ROUNDS: usize = R_F + R_P; // 65

/// Fetch the circom-BN254 width-3 parameters from light-poseidon and return the
/// round-constant table as ROUNDS rows of T constants.
///
/// light-poseidon stores `ark` as a FLAT vector of `width * ROUNDS` elements,
/// laid out row-major: round 0 lanes [0,1,2], round 1 lanes [0,1,2], ...
/// `apply_ark(round)` reads `ark[round*width + i]`, so we reshape identically.
pub fn gen_round_constants() -> [[Fr; T]; ROUNDS] {
    let params = light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>(T as u8)
        .expect("light-poseidon bn254_x5 t=3 params");
    assert_eq!(params.width, T, "width must be 3");
    assert_eq!(params.full_rounds, R_F, "R_F must be 8");
    assert_eq!(params.partial_rounds, R_P, "R_P must be 57");
    assert_eq!(params.alpha, 5, "alpha must be 5");
    assert_eq!(params.ark.len(), T * ROUNDS, "ark must be width*ROUNDS");

    let mut out = [[Fr::from(0u64); T]; ROUNDS];
    for (round, row) in out.iter_mut().enumerate() {
        for (i, r) in row.iter_mut().enumerate() {
            *r = params.ark[round * T + i];
        }
    }
    out
}

/// Fetch the circom-BN254 width-3 MDS matrix (3x3) from light-poseidon.
pub fn gen_mds() -> [[Fr; T]; T] {
    let params = light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>(T as u8)
        .expect("light-poseidon bn254_x5 t=3 params");
    let mut m = [[Fr::from(0u64); T]; T];
    for (i, row) in m.iter_mut().enumerate() {
        for (j, e) in row.iter_mut().enumerate() {
            *e = params.mds[i][j];
        }
    }
    m
}

/// Encode an `Fr` as 32 little-endian bytes (canonical, matches
/// `into_bigint().to_bytes_le()`).
pub fn fr_to_le(f: &Fr) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let mut out = [0u8; 32];
    let v = f.into_bigint().to_bytes_le();
    out[..v.len()].copy_from_slice(&v);
    out
}
