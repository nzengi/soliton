//! SOLITON shared Poseidon — the SINGLE source of truth for the hash used both
//! by the SOLITON-Pay circuit (`circuits/soliton-pay`) and the on-chain Merkle
//! tree (`programs/soliton-pool`).
//!
//! This is the **circom-BN254 Poseidon** — bit-for-bit the hash that Solana's
//! `sol_poseidon` syscall computes (`Parameters::Bn254X5`), which is exactly the
//! `light-poseidon` BN254 x^5 hash (circomlib constants). Matching that hash is
//! the load-bearing gate: it lets the on-chain Merkle tree use the cheap
//! `sol_poseidon` SYSCALL instead of pure-Rust field arithmetic.
//!
//! Parameters: width t = 3, S-box x^5, full rounds R_F = 8, partial rounds
//! R_P = 57, total R = 65. The round constants (`ark`, flat width*R table) and
//! 3x3 MDS matrix are the circom-BN254 values, pulled directly from
//! `light-poseidon` (see `gen.rs`) and BAKED into `constants.rs` as little-endian
//! byte tables so the BPF permutation does no per-call constant generation.
//!
//! State / sponge convention (the circom / light-poseidon convention):
//!   * state is initialised to `[domain_tag = 0, in_0, in_1, ...]`,
//!   * each round: add round constants → S-box → MDS,
//!   * full rounds S-box ALL lanes; partial rounds S-box lane 0 only,
//!   * the output is lane 0 of the final state.
//!
//! Note model (matches the circuit):
//!   pk = H2(sk, 0)         cm = H3(value, pk, rho)        nf = H2(sk, rho)
//!   internal node = H2(left, right)
//!
//! H2(a,b)   = circom_hash([a, b])            (2-to-1, width 3, domain tag 0)
//! H3(a,b,c) = H2(H2(a,b), c)                 (sequential 3-input)
//!
//! This crate is `no_std` and depends only on ark-bn254 / ark-ff, so it is
//! BPF-safe.

#![no_std]
#![allow(unexpected_cfgs)]

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};

mod constants;
#[cfg(any(test, feature = "regen"))]
pub mod gen;

pub use constants::{ARK_LE, MDS_LE};

pub const T: usize = 3;
pub const R_F: usize = 8;
pub const R_P: usize = 57;
pub const ROUNDS: usize = R_F + R_P; // 65

/// Decode 32 LE bytes into `Fr` (the baked constants are canonical, so this is
/// exact — no modular reduction needed for them).
#[inline]
fn fr_from_le(b: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(b)
}

/// Encode `Fr` as 32 LE bytes (canonical). This is the on-the-wire / on-chain
/// representation: a field element is its 32-byte LE little-endian repr.
#[inline]
pub fn fr_to_le(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let v = f.into_bigint().to_bytes_le();
    out[..v.len()].copy_from_slice(&v);
    out
}

/// Decode any 32 LE bytes into a field element (reduces mod order). Used for
/// hashing arbitrary 32-byte inputs (leaves, etc.) — but commitments produced
/// by this crate are already canonical, so this is identity on them.
#[inline]
pub fn fr_from_le_bytes(b: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(b)
}

#[inline]
fn sbox(x: Fr) -> Fr {
    // x^5
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

#[inline]
fn ark(round: usize, i: usize) -> Fr {
    fr_from_le(&ARK_LE[round][i])
}

/// circom-BN254 Poseidon permutation on a width-3 state, mutated in place.
/// Round structure (matches `light-poseidon`): add ark → S-box → MDS, with full
/// rounds split R_F/2 before and after the R_P partial rounds.
pub fn permute(state: &mut [Fr; T]) {
    // Precompute MDS as Fr once per permutation (9 LE decodes; cheap vs. 65
    // rounds of arithmetic).
    let m: [[Fr; T]; T] =
        core::array::from_fn(|i| core::array::from_fn(|j| fr_from_le(&MDS_LE[i][j])));

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

    let half_full = R_F / 2;
    let mut round = 0usize;

    // First half of full rounds.
    for _ in 0..half_full {
        for i in 0..T {
            state[i] += ark(round, i);
        }
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        *state = apply_mds(state);
        round += 1;
    }
    // Partial rounds (S-box on lane 0 only).
    for _ in 0..R_P {
        for i in 0..T {
            state[i] += ark(round, i);
        }
        state[0] = sbox(state[0]);
        *state = apply_mds(state);
        round += 1;
    }
    // Second half of full rounds.
    for _ in 0..half_full {
        for i in 0..T {
            state[i] += ark(round, i);
        }
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        *state = apply_mds(state);
        round += 1;
    }
}

/// 2-to-1 hash H(a,b): circom convention — state = [domain_tag=0, a, b], permute,
/// squeeze lane 0.
#[inline]
pub fn hash2(a: Fr, b: Fr) -> Fr {
    let mut state = [Fr::ZERO, a, b];
    permute(&mut state);
    state[0]
}

/// 3-to-1 hash H3(a,b,c) = H2(H2(a,b), c). Sequential 2-to-1 absorption so a
/// single width-3 permutation serves the whole circuit (and `sol_poseidon`
/// nesting matches: hashv([hashv([a,b]), c])).
#[inline]
pub fn hash3(a: Fr, b: Fr, c: Fr) -> Fr {
    hash2(hash2(a, b), c)
}

// ---- byte-oriented wrappers for the on-chain tree (inputs/outputs are 32B LE) -

/// H2 over 32-byte LE field encodings → 32-byte LE.
#[inline]
pub fn hash2_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    fr_to_le(&hash2(fr_from_le(a), fr_from_le(b)))
}

/// H3 over 32-byte LE field encodings → 32-byte LE.
#[inline]
pub fn hash3_bytes(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    fr_to_le(&hash3(fr_from_le(a), fr_from_le(b), fr_from_le(c)))
}

// ---- note model helpers (field domain) ---------------------------------------

/// pk = H2(sk, 0)
#[inline]
pub fn note_pk(sk: Fr) -> Fr {
    hash2(sk, Fr::ZERO)
}

/// cm = H3(value, pk, rho)
#[inline]
pub fn note_cm(value: u64, pk: Fr, rho: Fr) -> Fr {
    hash3(Fr::from(value), pk, rho)
}

/// nf = H2(sk, rho)
#[inline]
pub fn note_nf(sk: Fr, rho: Fr) -> Fr {
    hash2(sk, rho)
}

/// Full commitment from (value, sk, rho): cm = H3(value, H2(sk,0), rho).
#[inline]
pub fn commitment(value: u64, sk: Fr, rho: Fr) -> Fr {
    note_cm(value, note_pk(sk), rho)
}

// ---- empty / zero subtree (for the incremental tree) -------------------------

/// Empty-leaf sentinel = field encoding of 0xE9E9_E9E9 (matches the circuit's
/// `witness::empty_leaf`).
#[inline]
pub fn empty_leaf() -> Fr {
    Fr::from(0xE9E9_E9E9u64)
}

/// Zero-subtree root at level `l`: empty[0] = empty_leaf,
/// empty[l] = H2(empty[l-1], empty[l-1]).
pub fn empty_subtree_root(level: usize) -> Fr {
    let mut e = empty_leaf();
    for _ in 0..level {
        e = hash2(e, e);
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn h2_deterministic_and_nonzero() {
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);
        let h1 = hash2(a, b);
        let h2 = hash2(a, b);
        assert_eq!(h1, h2, "H2 must be deterministic");
        assert_ne!(h1, Fr::zero(), "H2 output should be non-trivial");
        // order matters
        assert_ne!(hash2(a, b), hash2(b, a));
    }

    #[test]
    fn h3_equals_nested_h2() {
        let (a, b, c) = (Fr::from(1u64), Fr::from(2u64), Fr::from(3u64));
        assert_eq!(hash3(a, b, c), hash2(hash2(a, b), c));
    }

    #[test]
    fn bytes_roundtrip() {
        let f = Fr::from(0xDEAD_BEEFu64);
        let le = fr_to_le(&f);
        assert_eq!(fr_from_le_bytes(&le), f);
    }

    #[test]
    fn empty_subtree_chain() {
        // empty[l] = H2(empty[l-1], empty[l-1])
        let e0 = empty_leaf();
        let e1 = hash2(e0, e0);
        assert_eq!(empty_subtree_root(0), e0);
        assert_eq!(empty_subtree_root(1), e1);
        assert_eq!(empty_subtree_root(2), hash2(e1, e1));
    }

    /// shared == light-poseidon: the pure-Rust permutation in this crate
    /// must equal `light_poseidon::Poseidon::<Fr>::new_circom(2).hash([a,b])`
    /// byte-for-byte. This is what makes `sol_poseidon` usable on-chain.
    #[test]
    fn hash2_equals_light_poseidon() {
        use light_poseidon::{Poseidon, PoseidonHasher};
        let cases: [(u64, u64); 6] = [
            (1, 2),
            (0, 0),
            (12345, 67890),
            (0xE9E9_E9E9, 0xE9E9_E9E9),
            (u64::MAX, 1),
            (7, 0),
        ];
        for (a, b) in cases {
            let mut lp = Poseidon::<Fr>::new_circom(2).unwrap();
            let want = lp.hash(&[Fr::from(a), Fr::from(b)]).unwrap();
            let got = hash2(Fr::from(a), Fr::from(b));
            assert_eq!(
                fr_to_le(&got),
                fr_to_le(&want),
                "hash2({a},{b}) != light-poseidon"
            );
        }
    }

    #[test]
    fn hash3_equals_nested_light_poseidon() {
        use light_poseidon::{Poseidon, PoseidonHasher};
        for (a, b, c) in [(1u64, 2u64, 3u64), (100, 200, 300), (0, 0, 0)] {
            let mut lp = Poseidon::<Fr>::new_circom(2).unwrap();
            let ab = lp.hash(&[Fr::from(a), Fr::from(b)]).unwrap();
            let mut lp2 = Poseidon::<Fr>::new_circom(2).unwrap();
            let want = lp2.hash(&[ab, Fr::from(c)]).unwrap();
            let got = hash3(Fr::from(a), Fr::from(b), Fr::from(c));
            assert_eq!(fr_to_le(&got), fr_to_le(&want), "hash3({a},{b},{c})");
        }
    }

    #[cfg(feature = "regen")]
    #[test]
    fn baked_constants_match_generated() {
        // The baked tables must equal a fresh generation (guards against an
        // out-of-date constants.rs).
        let rc = crate::gen::gen_round_constants();
        for (round, row) in rc.iter().enumerate() {
            for (i, e) in row.iter().enumerate() {
                assert_eq!(crate::gen::fr_to_le(e), ARK_LE[round][i]);
            }
        }
        let mds = crate::gen::gen_mds();
        for (i, row) in mds.iter().enumerate() {
            for (j, e) in row.iter().enumerate() {
                assert_eq!(crate::gen::fr_to_le(e), MDS_LE[i][j]);
            }
        }
    }
}
