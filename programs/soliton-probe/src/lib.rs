//! SOLITON load-bearing CU probe.
//!
//! The whole SOLITON design rests on ONE empirical claim: the entire verifier
//! must perform *exactly one* field inversion (via Montgomery batch-inversion),
//! because a pure-Rust BPF `Fr::inverse()` costs ~100k CU and Solana-Plonk died
//! at 2.71M CU running 6 of them un-batched. This program isolates and measures,
//! on the real SBF VM (via Mollusk), the operations that dominate that budget:
//!
//! Instruction-data layout: `[mode: u8 | n: u32 LE | n×Fr(32B LE)…]`
//! (for mode 30 the payload is ignored; the pairing input is built from
//! embedded EIP-197 constants).
//!
//!  * mode  0 — NOOP baseline: parse the n scalars only. Subtract this from
//!              every other mode to remove entrypoint + parse overhead.
//!  * mode 10 — NAIVE: n separate `Fr::inverse()` calls. This is the path that
//!              killed Solana-Plonk; cost should be ≈ n × ~100k CU.
//!  * mode 11 — BATCH: ONE `ark_ff::batch_inversion` over n elements (Montgomery
//!              trick: 1 inverse + 3n muls). The SOLITON spine; cost should be
//!              ≈ one inverse + small, i.e. roughly FLAT in n.
//!  * mode 12 — Fr Horner: n× (mul + add). Measures the pure-Rust Fr arithmetic
//!              that, in Solana-Plonk, hid ~1.57M CU *around* the syscalls.
//!  * mode 30 — 2-pair `alt_bn128_pairing_be` (the verifier's final check).

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{fields::batch_inversion, Field, PrimeField, Zero};

pub mod errors {
    pub const MALFORMED_INPUT: u32 = 0x100;
    pub const UNKNOWN_MODE: u32 = 0x101;
    pub const ZERO_INVERSE: u32 = 0x102;
    pub const SYSCALL_ERROR: u32 = 0x300;
}

/// Parse `[n: u32 LE | n×Fr(32B LE)]` into a Vec<Fr>.
/// Uses `from_le_bytes_mod_order` so any 32 bytes are a valid field element —
/// identical cost across all modes, so it cancels against the mode-0 baseline.
fn read_scalars(payload: &[u8]) -> Result<Vec<Fr>, u32> {
    if payload.len() < 4 {
        return Err(errors::MALFORMED_INPUT);
    }
    let n = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    let body = &payload[4..];
    if body.len() < n * 32 {
        return Err(errors::MALFORMED_INPUT);
    }
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        v.push(Fr::from_le_bytes_mod_order(&body[i * 32..i * 32 + 32]));
    }
    Ok(v)
}

pub fn run(data: &[u8]) -> Result<(), u32> {
    if data.is_empty() {
        return Err(errors::MALFORMED_INPUT);
    }
    let mode = data[0];
    let payload = &data[1..];

    match mode {
        // Baseline: parse only.
        0 => {
            let v = read_scalars(payload)?;
            core::hint::black_box(&v);
            Ok(())
        }
        // Naive: n independent inversions (the Solana-Plonk death path).
        10 => {
            let v = read_scalars(payload)?;
            let mut acc = Fr::zero();
            for x in &v {
                let inv = x.inverse().ok_or(errors::ZERO_INVERSE)?;
                acc += inv;
            }
            core::hint::black_box(acc);
            Ok(())
        }
        // Batch: one Montgomery batch-inversion (the SOLITON spine).
        11 => {
            let mut v = read_scalars(payload)?;
            batch_inversion(&mut v);
            let mut acc = Fr::zero();
            for x in &v {
                acc += x;
            }
            core::hint::black_box(acc);
            Ok(())
        }
        // Pure-Rust Fr mul+add Horner fold (the hidden overhead around syscalls).
        12 => {
            let v = read_scalars(payload)?;
            let mut acc = Fr::zero();
            for x in &v {
                acc = acc * x + x;
            }
            core::hint::black_box(acc);
            Ok(())
        }
        // Final 2-pair pairing check.
        30 => run_pairing(),
        _ => Err(errors::UNKNOWN_MODE),
    }
}

/// BN254 G1 generator (1, 2), BE, 64 bytes.
const G1_GEN: [u8; 64] = {
    let mut b = [0u8; 64];
    b[31] = 1;
    b[63] = 2;
    b
};

/// -G1 generator: x = 1, y = q - 2 (BN254 base-field modulus minus 2), BE.
/// q_BE ends in 0xfd47, so (q-2)_BE ends in 0xfd45 (no borrow).
const NEG_G1: [u8; 64] = {
    let mut b = [0u8; 64];
    b[31] = 1; // x = 1
    // y = q - 2
    let q_minus_2: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
        0xfd, 0x45,
    ];
    let mut i = 0;
    while i < 32 {
        b[32 + i] = q_minus_2[i];
        i += 1;
    }
    b
};

/// BN254 G2 generator, EIP-197 BE order: X.c1 ‖ X.c0 ‖ Y.c1 ‖ Y.c0 (128 bytes).
const G2_GEN: [u8; 128] = [
    0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a, 0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25,
    0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12, 0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
    0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76, 0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79,
    0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd, 0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed,
    0x09, 0x06, 0x89, 0xd0, 0x58, 0x5f, 0xf0, 0x75, 0xec, 0x9e, 0x99, 0xad, 0x69, 0x0c, 0x33, 0x95,
    0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3, 0x55, 0xac, 0xda, 0xdc, 0xd1, 0x22, 0x97, 0x5b,
    0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb, 0x4a, 0xab, 0x71, 0x80, 0x8d, 0xcb, 0x40, 0x8f,
    0xe3, 0xd1, 0xe7, 0x69, 0x0c, 0x43, 0xd3, 0x7b, 0x4c, 0xe6, 0xcc, 0x01, 0x66, 0xfa, 0x7d, 0xaa,
];

/// 2-pair check: e(G1, G2) · e(-G1, G2) = 1. Both points are valid, so the
/// syscall always runs (it errors only on invalid/off-subgroup points, not on
/// result ≠ 1) — the CU cost is what we measure.
fn run_pairing() -> Result<(), u32> {
    use solana_bn254::prelude::alt_bn128_pairing_be;
    let mut buf = [0u8; 384];
    buf[..64].copy_from_slice(&G1_GEN);
    buf[64..192].copy_from_slice(&G2_GEN);
    buf[192..256].copy_from_slice(&NEG_G1);
    buf[256..384].copy_from_slice(&G2_GEN);
    let out = alt_bn128_pairing_be(&buf).map_err(|_| errors::SYSCALL_ERROR)?;
    core::hint::black_box(&out);
    Ok(())
}

#[cfg(feature = "bpf-entrypoint")]
mod entry {
    use pinocchio::{
        account::AccountView, address::Address, entrypoint, error::ProgramError, ProgramResult,
    };

    entrypoint!(process_instruction);

    fn process_instruction(
        _program_id: &Address,
        accounts: &mut [AccountView],
        instruction_data: &[u8],
    ) -> ProgramResult {
        // Payload arrives via accounts[0] (mirrors the verifier).
        if !accounts.is_empty() {
            let acct = &accounts[0];
            // SAFETY: probe-only, ix holds a read-only borrow.
            let data: &[u8] = unsafe { acct.borrow_unchecked() };
            return super::run(data).map_err(ProgramError::Custom);
        }
        super::run(instruction_data).map_err(ProgramError::Custom)
    }
}
