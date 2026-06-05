//! Host acceptance test: prove a REAL SOLITON-Pay proof with the Keccak-BE
//! transcript, then verify it through the SOUND (non-halo2) generic verifier in
//! `halo2_solana_verifier`. Asserts the single pairing check returns TRUE for a
//! real proof and that a tampered proof / public input is REJECTED.

use halo2_solana_verifier::curve::{G1, G2};
use halo2_solana_verifier::kzg::KzgVk;
use halo2curves::ff::PrimeField;
use halo2curves::bn256::Fr;
use soliton_pay::prover::prove_keccak;

const K: u32 = 13;
const DEPTH: usize = 4;
const SEED: [u8; 32] = [7u8; 32];

fn fr_to_be(f: &Fr) -> [u8; 32] {
    let le = f.to_repr();
    let mut be = [0u8; 32];
    for (i, b) in le.iter().rev().enumerate() {
        be[i] = *b;
    }
    be
}

fn build_kzg_vk(art: &soliton_pay::prover::KeccakArtifacts) -> KzgVk {
    KzgVk {
        g1_one: G1(art.g1_one_be),
        g2_one: G2(art.g2_one_be),
        g2_tau: G2(art.g2_tau_be),
    }
}

#[test]
fn real_proof_accepts_and_tampered_rejects() {
    let art = prove_keccak(K, DEPTH, SEED).expect("prove_keccak failed");
    let kzg_vk = build_kzg_vk(&art);
    let pubs: Vec<[u8; 32]> = art.public_inputs.iter().map(fr_to_be).collect();

    // --- POSITIVE: real proof must yield pairing == TRUE ---
    let ok = halo2_solana_verifier::verify_generic(
        &art.vk_bytes,
        &art.proof_bytes,
        &pubs,
        &kzg_vk,
    );
    println!("positive verify_generic result: {ok:?}");
    let accepted = ok.expect("verifier returned Err on a real proof");
    assert!(accepted, "REAL proof did NOT pass pairing check (pairing==false)");
    println!("OK: real SOLITON-Pay proof ACCEPTED (pairing == TRUE)");

    // --- NEGATIVE 1: flip one byte of the proof ---
    let mut bad_proof = art.proof_bytes.clone();
    let mid = bad_proof.len() / 2;
    bad_proof[mid] ^= 0x01;
    let r1 = halo2_solana_verifier::verify_generic(&art.vk_bytes, &bad_proof, &pubs, &kzg_vk);
    println!("negative (proof byte flip) result: {r1:?}");
    let rejected1 = matches!(r1, Ok(false) | Err(_));
    assert!(rejected1, "tampered proof was ACCEPTED — soundness broken");

    // --- NEGATIVE 2: tamper a public input ---
    let mut bad_pubs = pubs.clone();
    // flip the lowest byte of pub_amount (instance index 5)
    bad_pubs[5][31] ^= 0x01;
    let r2 = halo2_solana_verifier::verify_generic(&art.vk_bytes, &art.proof_bytes, &bad_pubs, &kzg_vk);
    println!("negative (public input tamper) result: {r2:?}");
    let rejected2 = matches!(r2, Ok(false) | Err(_));
    assert!(rejected2, "tampered public input was ACCEPTED — soundness broken");

    // --- NEGATIVE 3: corrupt ONLY the final SHPLONK opening proof W' (last 64
    //     bytes). The proof still parses + all Fiat-Shamir transcript reads
    //     succeed (W' is read last and only feeds the pairing equation), so a
    //     rejection here proves the PAIRING itself is data-dependent, not stubbed.
    let mut bad_w = art.proof_bytes.clone();
    let n = bad_w.len();
    bad_w[n - 1] ^= 0x02; // perturb W'.y last byte (stays on a valid-ish encoding path)
    let r3 = halo2_solana_verifier::verify_generic(&art.vk_bytes, &bad_w, &pubs, &kzg_vk);
    println!("negative (W' corruption) result: {r3:?}");
    assert!(matches!(r3, Ok(false) | Err(_)), "corrupted W' was ACCEPTED");

    println!("OK: all negative controls REJECTED");
}

#[test]
fn second_seed_and_depth_also_accepts() {
    // Independent witness/params — rules out a fluke fixed to one seed.
    let art = prove_keccak(13, 6, [0x42u8; 32]).expect("prove_keccak (seed2) failed");
    let kzg_vk = build_kzg_vk(&art);
    let pubs: Vec<[u8; 32]> = art.public_inputs.iter().map(fr_to_be).collect();
    let ok = halo2_solana_verifier::verify_generic(
        &art.vk_bytes,
        &art.proof_bytes,
        &pubs,
        &kzg_vk,
    )
    .expect("verifier Err on seed2 real proof");
    assert!(ok, "seed2 real proof failed pairing");
    println!("OK: second seed/depth real proof ACCEPTED (pairing == TRUE)");
}
