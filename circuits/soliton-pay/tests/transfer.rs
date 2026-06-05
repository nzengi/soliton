//! A witness transfer (built from input/output notes, not a seed) is satisfied
//! by MockProver AND its Keccak-BE proof is ACCEPTED by the sound
//! `verify_specialized`. A bad witness (unbalanced / wrong nullifier) is
//! REJECTED by MockProver.
//!
//! "I don't trust tests": every PASS is backed by a MockProver::verify() Ok/Err
//! or a verify_specialized() Ok(true)/Ok(false).

use halo2_proofs::dev::MockProver;
use halo2curves::bn256::Fr;
use halo2curves::ff::PrimeField;

use halo2_solana_verifier::curve::{G1, G2};
use halo2_solana_verifier::kzg::KzgVk;

use soliton_pay::prover::{prove_transfer, KeccakArtifacts};
use soliton_pay::shared_poseidon as sp;
use soliton_pay::witness::{
    build_transfer_circuit, merkle_root_from_path, InputNote, OutputNote,
};

const K: u32 = 15;
const DEPTH: usize = 32;
const SEED: [u8; 32] = [9u8; 32];

fn fr_to_be(f: &Fr) -> [u8; 32] {
    let le = f.to_repr();
    let mut be = [0u8; 32];
    for (i, b) in le.iter().rev().enumerate() {
        be[i] = *b;
    }
    be
}

fn build_kzg_vk(art: &KeccakArtifacts) -> KzgVk {
    KzgVk {
        g1_one: G1(art.g1_one_be),
        g2_one: G2(art.g2_one_be),
        g2_tau: G2(art.g2_tau_be),
    }
}

/// Bridge: ark Fr (shared poseidon) -> halo2 Fr, via 32-byte LE.
fn ark_to_h2(a: ark_bn254::Fr) -> Fr {
    let le = sp::fr_to_le(&a);
    let mut repr = <Fr as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&le);
    Fr::from_repr(repr).unwrap()
}

/// Build two input notes sitting at leaves 0 and 1 of a depth-D tree whose
/// other leaves are empty, using the SHARED poseidon (ark) to compute cm/root —
/// exactly what the SDK / on-chain pool would produce — then a halo2-Fr path.
fn make_inputs() -> ([InputNote; 2], Fr) {
    // Spending keys + values + rho via the shared (ark) hash.
    let sk0 = ark_bn254::Fr::from(11111u64);
    let sk1 = ark_bn254::Fr::from(22222u64);
    let v0 = 100u64;
    let v1 = 50u64;
    let rho0 = ark_bn254::Fr::from(7u64);
    let rho1 = ark_bn254::Fr::from(8u64);

    let cm0 = sp::commitment(v0, sk0, rho0);
    let cm1 = sp::commitment(v1, sk1, rho1);

    // Sparse depth-D tree: leaves 0,1 = cm0,cm1, rest empty.
    let empty: Vec<ark_bn254::Fr> = (0..=DEPTH).map(sp::empty_subtree_root).collect();

    // Path for leaf 0 (left at bottom, sibling cm1; left at every level above).
    let mut sib0 = vec![cm1];
    let mut bit0 = vec![false];
    let mut sib1 = vec![cm0];
    let mut bit1 = vec![true];
    for e in empty.iter().take(DEPTH).skip(1) {
        sib0.push(*e);
        bit0.push(false);
        sib1.push(*e);
        bit1.push(false);
    }

    let in0 = InputNote {
        sk: ark_to_h2(sk0),
        value: v0,
        rho: ark_to_h2(rho0),
        leaf_index: 0,
        merkle_path: sib0.iter().map(|s| ark_to_h2(*s)).collect(),
        path_bits: bit0,
    };
    let in1 = InputNote {
        sk: ark_to_h2(sk1),
        value: v1,
        rho: ark_to_h2(rho1),
        leaf_index: 1,
        merkle_path: sib1.iter().map(|s| ark_to_h2(*s)).collect(),
        path_bits: bit1,
    };

    // Root computed natively from in0's path (halo2 Fr).
    let cm0_h = soliton_pay::circuit::Note { value: v0, sk: in0.sk, rho: in0.rho }.cm();
    let root = merkle_root_from_path(cm0_h, &in0.merkle_path, &in0.path_bits);
    ([in0, in1], root)
}

#[test]
fn transfer_proof_verifies() {
    let (inputs, root) = make_inputs();

    // Recipient (Bob) is known only by his published pk_owner = H2(sk_bob, 0).
    let sk_bob = ark_bn254::Fr::from(99999u64);
    let pk_bob = ark_to_h2(sp::note_pk(sk_bob));
    // Change back to sender (Alice).
    let sk_alice = ark_bn254::Fr::from(11111u64);
    let pk_alice = ark_to_h2(sp::note_pk(sk_alice));

    // 100 + 50 = 150 inputs. Pay Bob 140, fee 10, change 0 -> pub_amount = -10.
    let fee: i128 = 10;
    let pay = 140u64;
    let change = 0u64;
    let outputs = [
        OutputNote { value: pay, pk_owner: pk_bob, rho: ark_to_h2(ark_bn254::Fr::from(101u64)) },
        OutputNote { value: change, pk_owner: pk_alice, rho: ark_to_h2(ark_bn254::Fr::from(202u64)) },
    ];

    // Build circuit + instance; the builder asserts paths reproduce root.
    let (circuit, instance) =
        build_transfer_circuit(inputs.clone(), outputs.clone(), -fee, root, DEPTH);

    // MockProver MUST be satisfied.
    let mock = MockProver::run(K, &circuit, vec![instance.clone()]).expect("mock run");
    match mock.verify() {
        Ok(()) => println!("[PASS] MockProver Ok (satisfying transfer witness)"),
        Err(e) => panic!("[FAIL] MockProver rejected witness: {e:?}"),
    }

    // Prove + sound-verify.
    let art = prove_transfer(K, inputs, outputs, -fee, root, DEPTH, SEED)
        .expect("prove_transfer failed");
    assert_eq!(art.public_inputs, instance, "instance mismatch builder vs prover");
    let kzg_vk = build_kzg_vk(&art);
    let pubs: Vec<[u8; 32]> = art.public_inputs.iter().map(fr_to_be).collect();

    let ok = halo2_solana_verifier::verify_specialized(&art.vk_bytes, &art.proof_bytes, &pubs, &kzg_vk)
        .expect("verify_specialized Err on proof");
    assert!(ok, "[FAIL] transfer proof did NOT pass pairing");
    println!("[PASS] verify_specialized ACCEPTED transfer proof (pairing == TRUE)");

    // Tamper a public input -> must reject.
    let mut bad = pubs.clone();
    bad[3][31] ^= 0x01; // cmout1
    let r = halo2_solana_verifier::verify_specialized(&art.vk_bytes, &art.proof_bytes, &bad, &kzg_vk);
    assert!(matches!(r, Ok(false) | Err(_)), "tampered cmout ACCEPTED");
    println!("[PASS] verify_specialized REJECTED tampered public input");
}

#[test]
fn bad_witness_rejected() {
    let (inputs, root) = make_inputs();
    let pk_bob = ark_to_h2(sp::note_pk(ark_bn254::Fr::from(99999u64)));
    let pk_alice = ark_to_h2(sp::note_pk(ark_bn254::Fr::from(11111u64)));

    // UNBALANCED: inputs 150, fee 10 -> outputs must sum to 140; make them 200.
    let outputs = [
        OutputNote { value: 150, pk_owner: pk_bob, rho: ark_to_h2(ark_bn254::Fr::from(101u64)) },
        OutputNote { value: 50, pk_owner: pk_alice, rho: ark_to_h2(ark_bn254::Fr::from(202u64)) },
    ];
    let (circuit, instance) =
        build_transfer_circuit(inputs.clone(), outputs, -10i128, root, DEPTH);
    let mock = MockProver::run(K, &circuit, vec![instance]).expect("mock run");
    assert!(mock.verify().is_err(), "[FAIL] unbalanced witness was ACCEPTED");
    println!("[PASS] MockProver REJECTED unbalanced witness");

    // WRONG NULLIFIER: keep a balanced circuit but tamper nf1 in the instance.
    let outputs2 = [
        OutputNote { value: 140, pk_owner: pk_bob, rho: ark_to_h2(ark_bn254::Fr::from(101u64)) },
        OutputNote { value: 0, pk_owner: pk_alice, rho: ark_to_h2(ark_bn254::Fr::from(202u64)) },
    ];
    let (circuit2, mut inst2) =
        build_transfer_circuit(inputs, outputs2, -10i128, root, DEPTH);
    inst2[1] += Fr::one(); // corrupt nf1: copy-constraint to instance must fail
    let mock2 = MockProver::run(K, &circuit2, vec![inst2]).expect("mock run");
    assert!(mock2.verify().is_err(), "[FAIL] wrong-nullifier witness was ACCEPTED");
    println!("[PASS] MockProver REJECTED wrong-nullifier instance");

    // Wrong Merkle path must be caught at build time (assert).
    let (mut bad_inputs, root) = make_inputs();
    bad_inputs[0].merkle_path[5] += Fr::one();
    let res = std::panic::catch_unwind(|| {
        let pk = ark_to_h2(sp::note_pk(ark_bn254::Fr::from(1u64)));
        build_transfer_circuit(
            bad_inputs,
            [
                OutputNote { value: 140, pk_owner: pk, rho: Fr::from(1u64) },
                OutputNote { value: 0, pk_owner: pk, rho: Fr::from(2u64) },
            ],
            -10i128,
            root,
            DEPTH,
        )
    });
    assert!(res.is_err(), "[FAIL] wrong Merkle path was NOT caught at build time");
    println!("[PASS] build_transfer_circuit REJECTED a wrong Merkle path");
}
