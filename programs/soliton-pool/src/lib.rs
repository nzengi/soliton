//! On-chain SOLITON shielded pool (Pinocchio BPF).
//!
//! Custodies SOL in a program-owned vault PDA and enforces the protocol:
//!  * `initialize` — set up `PoolState` (empty zero-subtree root) + record bump.
//!  * `shield`     — payer→vault lamports (System CPI); incremental-insert the
//!                   output commitment into the Poseidon Merkle tree (DEPTH H2
//!                   hashes via the frontier); push new root. ONE tx, no proof.
//!  * `transfer`   — verify a SOLITON-Pay proof (`verify_specialized`); require
//!                   the proof root ∈ history; mark nf1,nf2 spent (nullifier
//!                   PDAs); QUEUE cmout1,cmout2 (no hashing); apply pub_amount as
//!                   fee. Verify is ~1.345M, so this tx does NOT hash the tree.
//!  * `flush`      — permissionless: pop queued commitments and incrementally
//!                   insert them (on-chain Poseidon), updating root + history.
//!  * `unshield`   — verify proof; root ∈ history; mark nf1,nf2 spent; pay
//!                   `amount` lamports vault→recipient; queue any change cmout.
//!
//! The proof/VK/KZG blob exceeds the 1232-byte tx limit, so it is staged into a
//! program-readable account (the `soliton-verifier` blob pattern) and parsed by
//! the shared verifier crate.
//!
//! The on-chain Merkle hash is `crates/soliton-poseidon`, the SAME hash the
//! circuit uses — so membership proofs verify. That equality is the load-bearing
//! correctness gate (see tests/cu_pool.rs).

#![no_std]
#![allow(unexpected_cfgs)]

extern crate alloc;

pub mod state;

use state::{empty_roots, Pool};

use halo2_solana_verifier::{
    curve::{G1, G2},
    kzg::KzgVk,
};

/// Instruction tags (first byte of instruction data).
pub mod tag {
    pub const INITIALIZE: u8 = 0x00;
    pub const SHIELD: u8 = 0x01;
    pub const TRANSFER: u8 = 0x02;
    pub const FLUSH: u8 = 0x03;
    pub const UNSHIELD: u8 = 0x04;
}

pub mod verr {
    pub const UNKNOWN_TAG: u32 = 0x200;
    pub const MALFORMED: u32 = 0x201;
    pub const ROOT_UNKNOWN: u32 = 0x202;
    pub const DOUBLE_SPEND: u32 = 0x203;
    pub const VERIFY_FAIL: u32 = 0x204;
    pub const VERIFY_ERR: u32 = 0x205;
    pub const BAD_NF_PDA: u32 = 0x206;
    pub const INSUFFICIENT_VAULT: u32 = 0x207;
}

// ---- blob parsing (shared with soliton-verifier format) ----------------------

fn read_u32_le(data: &[u8], cur: &mut usize) -> Result<u32, u32> {
    if cur.checked_add(4).map_or(true, |e| e > data.len()) {
        return Err(verr::MALFORMED);
    }
    let v = u32::from_le_bytes([data[*cur], data[*cur + 1], data[*cur + 2], data[*cur + 3]]);
    *cur += 4;
    Ok(v)
}

fn take<'a>(data: &'a [u8], cur: &mut usize, n: usize) -> Result<&'a [u8], u32> {
    if cur.checked_add(n).map_or(true, |e| e > data.len()) {
        return Err(verr::MALFORMED);
    }
    let s = &data[*cur..*cur + n];
    *cur += n;
    Ok(s)
}

/// Parsed verifier inputs + the 6 public inputs (BE 32-byte each) interpreted as
/// `[root, nf1, nf2, cmout1, cmout2, pub_amount]`.
pub struct ProofBundle<'a> {
    pub vk_bytes: &'a [u8],
    pub proof_bytes: &'a [u8],
    pub public_inputs_be: alloc::vec::Vec<[u8; 32]>,
    pub kzg_vk: KzgVk,
}

/// Parse the staged blob (same layout as soliton-verifier).
pub fn parse_blob(data: &[u8]) -> Result<ProofBundle<'_>, u32> {
    let mut cur = 0usize;
    let vk_len = read_u32_le(data, &mut cur)? as usize;
    let vk_bytes = take(data, &mut cur, vk_len)?;
    let proof_len = read_u32_le(data, &mut cur)? as usize;
    let proof_bytes = take(data, &mut cur, proof_len)?;
    let n_pi = read_u32_le(data, &mut cur)? as usize;
    let mut public_inputs_be = alloc::vec::Vec::with_capacity(n_pi);
    for _ in 0..n_pi {
        let s = take(data, &mut cur, 32)?;
        let mut pi = [0u8; 32];
        pi.copy_from_slice(s);
        public_inputs_be.push(pi);
    }
    let g1_one: [u8; 64] = take(data, &mut cur, 64)?.try_into().unwrap();
    let g2_one: [u8; 128] = take(data, &mut cur, 128)?.try_into().unwrap();
    let g2_tau: [u8; 128] = take(data, &mut cur, 128)?.try_into().unwrap();
    Ok(ProofBundle {
        vk_bytes,
        proof_bytes,
        public_inputs_be,
        kzg_vk: KzgVk {
            g1_one: G1(g1_one),
            g2_one: G2(g2_one),
            g2_tau: G2(g2_tau),
        },
    })
}

/// Run the SOUND verifier on a parsed bundle. Ok(()) iff pairing accepted.
pub fn run_verify(b: &ProofBundle) -> Result<(), u32> {
    #[cfg(feature = "specialized")]
    let r = halo2_solana_verifier::verify_specialized(
        b.vk_bytes,
        b.proof_bytes,
        &b.public_inputs_be,
        &b.kzg_vk,
    );
    #[cfg(not(feature = "specialized"))]
    let r = halo2_solana_verifier::verify_generic(
        b.vk_bytes,
        b.proof_bytes,
        &b.public_inputs_be,
        &b.kzg_vk,
    );
    match r {
        Ok(true) => Ok(()),
        Ok(false) => Err(verr::VERIFY_FAIL),
        Err(_) => Err(verr::VERIFY_ERR),
    }
}

/// Convert a BE 32-byte public input to the LE field-byte encoding the tree uses.
pub fn be_to_le(be: &[u8; 32]) -> [u8; 32] {
    let mut le = [0u8; 32];
    for (i, b) in be.iter().rev().enumerate() {
        le[i] = *b;
    }
    le
}

// ---- pure state-transition helpers (host-testable, no AccountView) -----------

/// Apply a shield insert to PoolState bytes. Returns the new root.
pub fn apply_shield(pool_data: &mut [u8], commitment_le: &[u8; 32]) -> Result<[u8; 32], u32> {
    let empty = empty_roots()?;
    let mut pool = Pool::load(pool_data)?;
    pool.insert(commitment_le, &empty)
}

/// Apply a flush of up to `max` queued commitments. Returns count inserted.
pub fn apply_flush(pool_data: &mut [u8], max: usize) -> Result<usize, u32> {
    let empty = empty_roots()?;
    let mut pool = Pool::load(pool_data)?;
    let mut n = 0usize;
    while n < max && pool.queue_len() > 0 {
        let cm = pool.queue_pop_front()?;
        pool.insert(&cm, &empty)?;
        n += 1;
    }
    Ok(n)
}

#[cfg(feature = "bpf-entrypoint")]
mod entry;
