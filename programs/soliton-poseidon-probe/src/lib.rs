//! CU probe for the shared SOLITON Poseidon (`crates/soliton-poseidon`) on the
//! real SBF VM. Two modes (instruction-data byte 0):
//!
//!   * mode 0 — NOOP baseline: parse + black_box a leaf (subtract to isolate).
//!   * mode 1 — ONE H2 permutation (the cost of a single Merkle hash).
//!   * mode 2 — ONE depth-32 incremental insert: 32 H2 hashes via a frontier
//!              (the cost of a `shield`/`flush` tree update, no proof).
//!
//! Instruction data: `[mode: u8 | leaf: 32B LE]` (leaf optional; defaults to 1).

#![no_std]
#![allow(unexpected_cfgs)]

use soliton_poseidon as poseidon;
use solana_poseidon::{hashv, Endianness, Parameters};

pub mod errors {
    pub const MALFORMED: u32 = 0x100;
    pub const UNKNOWN_MODE: u32 = 0x101;
    pub const HASH_FAIL: u32 = 0x102;
}

const DEPTH: usize = 32;

/// 2-to-1 hash via the `sol_poseidon` SYSCALL (circom-BN254, LE field bytes).
#[inline]
#[allow(deprecated)]
fn sys_hash2(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], u32> {
    let h = hashv(Parameters::Bn254X5, Endianness::LittleEndian, &[a, b])
        .map_err(|_| errors::HASH_FAIL)?;
    Ok(h.to_bytes())
}

fn read_leaf(payload: &[u8]) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    if payload.len() >= 32 {
        leaf.copy_from_slice(&payload[..32]);
    } else {
        leaf[0] = 1;
    }
    leaf
}

pub fn run(data: &[u8]) -> Result<(), u32> {
    if data.is_empty() {
        return Err(errors::MALFORMED);
    }
    let mode = data[0];
    let leaf = read_leaf(&data[1..]);

    match mode {
        // Baseline.
        0 => {
            core::hint::black_box(&leaf);
            Ok(())
        }
        // One H2 (sol_poseidon syscall).
        1 => {
            let out = sys_hash2(&leaf, &leaf)?;
            core::hint::black_box(out);
            Ok(())
        }
        // One depth-32 incremental insert (32 H2 via syscall). next_index = 0 →
        // leaf is the first leaf; every level's sibling is an empty-subtree root.
        2 => {
            let mut empty = [[0u8; 32]; DEPTH + 1];
            empty[0] = poseidon::fr_to_le(&poseidon::empty_leaf());
            let mut level = 1;
            while level <= DEPTH {
                empty[level] = sys_hash2(&empty[level - 1], &empty[level - 1])?;
                level += 1;
            }
            let mut cur = leaf;
            let mut idx: u64 = 0; // first leaf
            for level in 0..DEPTH {
                if idx & 1 == 0 {
                    cur = sys_hash2(&cur, &empty[level])?;
                } else {
                    cur = sys_hash2(&cur, &cur)?;
                }
                idx >>= 1;
            }
            core::hint::black_box(cur);
            Ok(())
        }
        // Empty-subtree root chain ONLY (32 H2 via syscall). mode2 - mode3
        // isolates the pure 32-hash insert path cost.
        3 => {
            let mut e = poseidon::fr_to_le(&poseidon::empty_leaf());
            for _ in 0..DEPTH {
                e = sys_hash2(&e, &e)?;
            }
            core::hint::black_box(e);
            Ok(())
        }
        _ => Err(errors::UNKNOWN_MODE),
    }
}

#[cfg(feature = "bpf-entrypoint")]
mod entry {
    use pinocchio::{
        account::AccountView, address::Address, entrypoint, error::ProgramError, ProgramResult,
    };

    // `solana-poseidon` (the `sol_poseidon` syscall wrapper) is not strictly
    // `no_std` (it links `thiserror`), so we use pinocchio's `entrypoint!` —
    // whose std-style panic handler is compatible — rather than the manual
    // `nostd_panic_handler!` setup (which would duplicate the `panic_impl` lang
    // item). This matches `programs/soliton-pool`.
    entrypoint!(process_instruction);

    fn process_instruction(
        _program_id: &Address,
        accounts: &mut [AccountView],
        instruction_data: &[u8],
    ) -> ProgramResult {
        if !accounts.is_empty() {
            let acct = &accounts[0];
            #[allow(unsafe_code)]
            let data: &[u8] = unsafe { acct.borrow_unchecked() };
            return super::run(data).map_err(ProgramError::Custom);
        }
        super::run(instruction_data).map_err(ProgramError::Custom)
    }
}
