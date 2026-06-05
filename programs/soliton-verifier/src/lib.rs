//! On-chain SOUND SOLITON-Pay verifier (Pinocchio BPF program).
//!
//! This program runs the SAME, host-verified generic verifier
//! (`halo2_solana_verifier::verify_generic`) that already ACCEPTS the
//! SOLITON-Pay proof on host (pairing == TRUE) and rejects tampered proofs —
//! only here it runs on the real SBF VM. It does no placeholder arithmetic and
//! has no structural skeleton: it parses the v2 VK + the halo2 proof bytes +
//! the public inputs + the KZG SRS pieces and returns success iff the
//! single BN254 pairing check returns true.
//!
//! ## Blob format (built by the host client/test)
//!
//! All length prefixes little-endian u32; field/curve elements big-endian.
//!
//! ```text
//! vk_v2_len   : u32 LE
//! vk_bytes : [u8; vk_v2_len]          generic on-chain VK blob
//! proof_len   : u32 LE
//! proof_bytes : [u8; proof_len]          halo2 Keccak-BE proof
//! n_pi        : u32 LE
//! pi[]        : [u8; 32 * n_pi]          public inputs, Fr BE
//! g1_one      : [u8; 64]                 [1]_1  G1 BE
//! g2_one      : [u8; 128]                [1]_2  G2 BE
//! g2_tau      : [u8; 128]                [tau]_2 G2 BE
//! ```

#![no_std]
#![deny(unsafe_code)]
// `target_os = "solana"` is valid under `cargo build-sbf` but unknown to the
// host toolchain during `cargo test`; silence the host-only lint.
#![allow(unexpected_cfgs)]

extern crate alloc;

use alloc::vec::Vec;

use halo2_solana_verifier::{
    curve::{G1, G2},
    kzg::KzgVk,
};

pub mod errors {
    /// Blob was truncated / a length prefix overran the buffer.
    pub const MALFORMED_INPUT: u32 = 0x100;
    /// `verify_generic` returned Err (parse / transcript / syscall failure).
    pub const VERIFY_ERR_BASE: u32 = 0x200;
    /// `verify_generic` returned Ok(false): pairing check FAILED (proof rejected).
    pub const PAIRING_FALSE: u32 = 0x300;
}

// ---- stage-trace compute-unit logger --------------------------------------

#[cfg(all(target_os = "solana", feature = "bpf-entrypoint"))]
fn cu(label: &str) {
    // SAFETY: pinocchio syscall wrappers; label is a valid &str.
    #[allow(unsafe_code)]
    unsafe {
        pinocchio::syscalls::sol_log_(label.as_ptr(), label.len() as u64);
        pinocchio::syscalls::sol_log_compute_units_();
    }
}
#[cfg(not(all(target_os = "solana", feature = "bpf-entrypoint")))]
fn cu(_label: &str) {}

fn read_u32_le(data: &[u8], cur: &mut usize) -> Result<u32, u32> {
    if cur.checked_add(4).map_or(true, |e| e > data.len()) {
        return Err(errors::MALFORMED_INPUT);
    }
    let v = u32::from_le_bytes([data[*cur], data[*cur + 1], data[*cur + 2], data[*cur + 3]]);
    *cur += 4;
    Ok(v)
}

fn take<'a>(data: &'a [u8], cur: &mut usize, n: usize) -> Result<&'a [u8], u32> {
    if cur.checked_add(n).map_or(true, |e| e > data.len()) {
        return Err(errors::MALFORMED_INPUT);
    }
    let s = &data[*cur..*cur + n];
    *cur += n;
    Ok(s)
}

/// Parse the staged blob and run the SOUND generic verifier.
///
/// Returns `Ok(true)` iff the pairing check passed (proof accepted).
pub fn verify(data: &[u8]) -> Result<bool, u32> {
    cu("[stage] enter");

    let mut cur = 0usize;

    // vk_bytes
    let vk_len = read_u32_le(data, &mut cur)? as usize;
    let vk_bytes = take(data, &mut cur, vk_len)?;

    // proof_bytes
    let proof_len = read_u32_le(data, &mut cur)? as usize;
    let proof_bytes = take(data, &mut cur, proof_len)?;

    // public inputs
    let n_pi = read_u32_le(data, &mut cur)? as usize;
    let mut public_inputs: Vec<[u8; 32]> = Vec::with_capacity(n_pi);
    for _ in 0..n_pi {
        let s = take(data, &mut cur, 32)?;
        let mut pi = [0u8; 32];
        pi.copy_from_slice(s);
        public_inputs.push(pi);
    }

    // KZG SRS pieces
    let g1_one: [u8; 64] = take(data, &mut cur, 64)?.try_into().unwrap();
    let g2_one: [u8; 128] = take(data, &mut cur, 128)?.try_into().unwrap();
    let g2_tau: [u8; 128] = take(data, &mut cur, 128)?.try_into().unwrap();

    let kzg_vk = KzgVk {
        g1_one: G1(g1_one),
        g2_one: G2(g2_one),
        g2_tau: G2(g2_tau),
    };
    cu("[stage] after parse blob");

    // ---- the SOUND, host-verified verifier ----
    // `specialized` (default): oracle-equivalent straight-line gate/lookup path.
    // Otherwise: the generic AST oracle. Both share all other machinery.
    #[cfg(feature = "specialized")]
    let r = halo2_solana_verifier::verify_specialized(vk_bytes, proof_bytes, &public_inputs, &kzg_vk);
    #[cfg(not(feature = "specialized"))]
    let r = halo2_solana_verifier::verify_generic(vk_bytes, proof_bytes, &public_inputs, &kzg_vk);
    cu("[stage] after verify");

    match r {
        Ok(true) => Ok(true),
        Ok(false) => Err(errors::PAIRING_FALSE),
        Err(_e) => Err(errors::VERIFY_ERR_BASE),
    }
}

// ---------------------------------------------------------------------------
// Pinocchio entrypoint.
// ---------------------------------------------------------------------------

#[cfg(feature = "bpf-entrypoint")]
mod entry {
    use pinocchio::{
        account::AccountView, address::Address, entrypoint, error::ProgramError, ProgramResult,
    };

    entrypoint!(process_instruction);

    // Instruction tags. The proof+VK blob is far larger than the 1232 B
    // per-tx limit, so it is chunk-written into a program-owned data account
    // (TAG_LOAD) before TAG_VERIFY reads it.
    const TAG_LOAD: u8 = 0x00; // [0x00 | offset:u32 LE | chunk…] → accounts[0].data[off..]
    const TAG_VERIFY: u8 = 0x01; // [0x01] → verify reading accounts[0].data
    const ERR_LOAD: u32 = 0x400;

    fn process_instruction(
        _program_id: &Address,
        accounts: &mut [AccountView],
        instruction_data: &[u8],
    ) -> ProgramResult {
        if let Some((&tag, rest)) = instruction_data.split_first() {
            if tag == TAG_LOAD {
                if rest.len() < 4 || accounts.is_empty() {
                    return Err(ProgramError::Custom(ERR_LOAD));
                }
                let offset = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
                let chunk = &rest[4..];
                let acct = &mut accounts[0];
                #[allow(unsafe_code)]
                let dst: &mut [u8] = unsafe { acct.borrow_unchecked_mut() };
                let end = match offset.checked_add(chunk.len()) {
                    Some(e) if e <= dst.len() => e,
                    _ => return Err(ProgramError::Custom(ERR_LOAD)),
                };
                dst[offset..end].copy_from_slice(chunk);
                return Ok(());
            }
            if tag != TAG_VERIFY {
                return Err(ProgramError::Custom(ERR_LOAD));
            }
            // tag == TAG_VERIFY → fall through to verify.
        }

        // VERIFY: empty instruction-data (Mollusk path) or TAG_VERIFY (devnet).
        let data: &[u8] = if !accounts.is_empty() {
            let acct = &accounts[0];
            #[allow(unsafe_code)]
            unsafe {
                acct.borrow_unchecked()
            }
        } else {
            instruction_data
        };

        match super::verify(data) {
            // Ok(true) only: success == the pairing check ACCEPTED the proof.
            Ok(true) => Ok(()),
            Ok(false) => unreachable!(),
            Err(code) => Err(ProgramError::Custom(code)),
        }
    }
}
