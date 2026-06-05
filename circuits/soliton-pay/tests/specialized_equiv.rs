//! ORACLE-EQUIVALENCE soundness test for the SPECIALIZED SOLITON-Pay verifier.
//!
//! For ≥8 distinct (seed, depth) real proofs we run BOTH the ground-truth
//! `verify_generic` (AST oracle) and the `verify_specialized` straight-line fast
//! path and assert:
//!   1. they return the IDENTICAL accept/reject bool, and
//!   2. their intermediate `expected_h_eval` (the gate+perm+lookup folded value
//!      that the specialization replaces) are BIT-IDENTICAL (BE bytes equal).
//!
//! Any divergence is a hard FAIL — this is the soundness guarantee that the
//! specialization did not change the verified relation. We also re-confirm
//! accept-on-real / reject-on-tampered for the specialized path.

use halo2_solana_verifier::curve::{G1, G2};
use halo2_solana_verifier::kzg::KzgVk;
use halo2curves::bn256::Fr;
use halo2curves::ff::PrimeField;
use soliton_pay::prover::prove_keccak;

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
fn specialized_is_oracle_equivalent() {
    // 8 distinct (seed, depth) pairs — independent witnesses + params.
    let cases: [([u8; 32], usize); 8] = [
        ([7u8; 32], 4),
        ([0x42u8; 32], 6),
        ([1u8; 32], 4),
        ([2u8; 32], 5),
        ([3u8; 32], 7),
        ([0xABu8; 32], 4),
        ([0xCDu8; 32], 8),
        ([0xFEu8; 32], 6),
    ];

    let mut pass = 0usize;
    for (seed, depth) in cases.iter().copied() {
        let art = prove_keccak(13, depth, seed)
            .unwrap_or_else(|e| panic!("prove_keccak(seed={seed:?},depth={depth}) failed: {e}"));
        let kzg_vk = build_kzg_vk(&art);
        let pubs: Vec<[u8; 32]> = art.public_inputs.iter().map(fr_to_be).collect();

        // (1) intermediate expected_h_eval must be bit-identical.
        let (gen_h, spec_h) = halo2_solana_verifier::expected_h_evals_for_test(
            &art.vk_bytes,
            &art.proof_bytes,
            &pubs,
        )
        .expect("expected_h_evals_for_test Err on real proof");
        assert_eq!(
            gen_h, spec_h,
            "DIVERGENCE: expected_h_eval mismatch (seed={seed:?}, depth={depth})\n  generic    = {}\n  specialized= {}",
            hex::encode(gen_h),
            hex::encode(spec_h)
        );

        // (2) full accept/reject bool must be identical.
        let g = halo2_solana_verifier::verify_generic(&art.vk_bytes, &art.proof_bytes, &pubs, &kzg_vk);
        let s = halo2_solana_verifier::verify_specialized(&art.vk_bytes, &art.proof_bytes, &pubs, &kzg_vk);
        assert_eq!(
            g.as_ref().ok(), s.as_ref().ok(),
            "DIVERGENCE: accept bool mismatch (seed={seed:?}, depth={depth}): generic={g:?} specialized={s:?}"
        );
        // and both must ACCEPT the honest proof.
        assert_eq!(g.unwrap(), true, "generic rejected honest proof (seed={seed:?})");
        assert_eq!(s.unwrap(), true, "specialized rejected honest proof (seed={seed:?})");

        // (3) tampered proof: both must reject, identically.
        let mut bad = art.proof_bytes.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        let gb = halo2_solana_verifier::verify_generic(&art.vk_bytes, &bad, &pubs, &kzg_vk);
        let sb = halo2_solana_verifier::verify_specialized(&art.vk_bytes, &bad, &pubs, &kzg_vk);
        let g_rej = matches!(gb, Ok(false) | Err(_));
        let s_rej = matches!(sb, Ok(false) | Err(_));
        assert!(g_rej && s_rej, "tampered proof not rejected by both (seed={seed:?}): generic={gb:?} specialized={sb:?}");

        // (4) tampered public input: both must reject.
        let mut bad_pubs = pubs.clone();
        bad_pubs[5][31] ^= 0x01;
        let gp = halo2_solana_verifier::verify_generic(&art.vk_bytes, &art.proof_bytes, &bad_pubs, &kzg_vk);
        let sp = halo2_solana_verifier::verify_specialized(&art.vk_bytes, &art.proof_bytes, &bad_pubs, &kzg_vk);
        assert!(
            matches!(gp, Ok(false) | Err(_)) && matches!(sp, Ok(false) | Err(_)),
            "tampered public input not rejected by both (seed={seed:?})"
        );

        pass += 1;
        println!(
            "OK [{pass}/8] seed={:02x?}.. depth={depth}: expected_h_eval bit-identical, accept/reject identical",
            &seed[..4]
        );
    }

    assert_eq!(pass, 8, "expected 8 oracle-equivalent cases, got {pass}");
    println!("\nORACLE EQUIVALENCE: {pass}/8 (seed,depth) pairs — generic vs specialized BIT-IDENTICAL on ALL.");
}
