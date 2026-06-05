//! GATE 3: off-chain Alice -> Bob private transfer.
//!
//! Alice shields two notes; both wallets scan the shared ledger so their local
//! trees stay in sync. Alice builds a transfer to Bob; we ASSERT the proof
//! VERIFIES (verify_specialized) against the local-tree root, then Bob scans the
//! output commitment + ciphertext, decrypts, and his balance == amount. Alice's
//! change is correct.
//!
//! "I don't trust tests": the gate is a real verify_specialized(...) == Ok(true)
//! and real balance equalities printed with numbers.

use ark_bn254::Fr;
use halo2curves::bn256::Fr as HFr;
use halo2curves::ff::PrimeField;

use halo2_solana_verifier::curve::{G1, G2};
use halo2_solana_verifier::kzg::KzgVk;

use soliton_sdk::Wallet;

/// A shared append-only ledger: ordered commitments (tree leaves) + ciphertexts.
#[derive(Default)]
struct Ledger {
    commitments: Vec<Fr>,
    ciphertexts: Vec<(Fr, Vec<u8>)>,
}

fn fr_to_be_h(f: &HFr) -> [u8; 32] {
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
fn gate3_offchain_alice_to_bob() {
    let mut alice = Wallet::from_seed(1);
    let mut bob = Wallet::from_seed(2);
    let bob_addr = bob.address();

    let mut ledger = Ledger::default();

    // --- Alice shields two notes (60 and 90) ---
    for amt in [60u64, 90u64] {
        let s = alice.build_shield(amt);
        ledger.commitments.push(s.commitment);
        ledger.ciphertexts.push((s.commitment, s.ciphertext));
    }

    // Everyone scans the ledger in the same order -> trees in sync.
    alice.scan(&ledger.commitments, &ledger.ciphertexts);
    bob.scan(&ledger.commitments, &ledger.ciphertexts);

    assert_eq!(alice.balance(), 150, "Alice should hold 150 after shielding");
    assert_eq!(bob.balance(), 0, "Bob holds nothing yet");
    assert_eq!(alice.note_count(), 2, "Alice should have 2 notes");
    println!("after shield: Alice balance={} notes={}", alice.balance(), alice.note_count());

    // --- Alice transfers 140 to Bob, fee 10 (spends 60+90=150) ---
    let amount = 140u64;
    let fee = 10u64;
    let bundle = alice
        .build_transfer(&bob_addr, amount, fee)
        .expect("build_transfer failed");

    // GATE 3a: the proof VERIFIES against the transfer root.
    let art = &bundle.artifacts;
    let kzg_vk = build_kzg_vk(art);
    let pubs: Vec<[u8; 32]> = art.public_inputs.iter().map(fr_to_be_h).collect();
    let ok = halo2_solana_verifier::verify_specialized(&art.vk_bytes, &art.proof_bytes, &pubs, &kzg_vk)
        .expect("verify_specialized returned Err");
    assert!(ok, "[FAIL] SDK-built transfer proof did NOT verify");
    println!("[PASS] verify_specialized ACCEPTED SDK transfer proof");

    // Sanity: the proof's public root == the local tree root the SDK used.
    // public_inputs[0] is the root (halo2 Fr); compare via bytes to bundle.root.
    let pub_root_be = pubs[0];
    let mut sdk_root_be = soliton_poseidon::fr_to_le(&bundle.root);
    sdk_root_be.reverse();
    assert_eq!(pub_root_be, sdk_root_be, "proof root != SDK transfer root");
    println!("[PASS] proof public root == SDK local-tree root (byte-equal)");

    // --- Outputs hit the ledger (FIFO: payment then change) and get flushed ---
    for (cm, ct) in &bundle.encrypted_outputs {
        ledger.commitments.push(*cm);
        ledger.ciphertexts.push((*cm, ct.clone()));
    }

    // Bob and Alice scan the NEW outputs (only the 2 just added).
    let new_cms = &ledger.commitments[2..];
    let new_cts = &ledger.ciphertexts[2..];
    bob.scan(new_cms, new_cts);
    alice.scan(new_cms, new_cts);

    // GATE 3b: Bob received the payment.
    assert_eq!(bob.balance(), amount, "Bob balance != payment amount");
    println!("[PASS] Bob received {} (balance={})", amount, bob.balance());

    // GATE 3c: Alice's change is correct: 150 - 140 - 10(fee) = 0.
    let expected_change = 150 - amount - fee;
    assert_eq!(alice.balance(), expected_change, "Alice change wrong");
    println!(
        "[PASS] Alice change = {} (150 in - {} pay - {} fee)",
        alice.balance(),
        amount,
        fee
    );
}

#[test]
fn gate3_double_spend_prevented() {
    // Spending the same notes twice must fail at the SDK level (note store
    // removes them after the first transfer).
    let mut alice = Wallet::from_seed(7);
    let bob_addr = Wallet::from_seed(8).address();

    let mut cms = Vec::new();
    let mut cts = Vec::new();
    for amt in [100u64, 100u64] {
        let s = alice.build_shield(amt);
        cms.push(s.commitment);
        cts.push((s.commitment, s.ciphertext));
    }
    alice.scan(&cms, &cts);
    assert_eq!(alice.balance(), 200);

    // First transfer spends both notes.
    let _ = alice
        .build_transfer(&bob_addr, 150, 10)
        .expect("first transfer ok");
    assert_eq!(alice.balance(), 0, "notes should be consumed");

    // Second transfer must fail: no spendable notes left.
    let second = alice.build_transfer(&bob_addr, 10, 0);
    assert!(second.is_err(), "[FAIL] double-spend was allowed");
    println!("[PASS] double-spend prevented: {:?}", second.err().unwrap());
}
