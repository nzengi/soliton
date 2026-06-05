//! End-to-end SOLITON-Pay tests: MockProver (satisfiability), SHPLONK
//! prove+verify, and a negative MockProver (constraints bind).
//!
//! "I don't trust tests": every PASS line below is backed by a
//! `MockProver::verify()` Ok / Err or a `verify_proof` Ok.

use halo2_proofs::dev::MockProver;
use halo2curves::bn256::Fr;
use soliton_pay::circuit::SolitonCircuit;
use soliton_pay::prover::prove_and_verify;
use soliton_pay::witness::{build_satisfying, build_unsatisfying};

/// Pick a `k` large enough for the given depth. Determined empirically; we
/// assert MockProver succeeds, which fails loudly if k is too small.
fn k_for(depth: usize) -> u32 {
    // Each Poseidon permutation is 64 rows; the circuit does many permutations,
    // dominated by 2 inputs * (pk + cm(2 perm) + D merkle-hash + nf) plus
    // outputs. depth=4 fits in k=13; depth=32 needs k=15.
    match depth {
        0..=8 => 13,
        9..=20 => 14,
        _ => 15,
    }
}

fn report_params(circuit: &SolitonCircuit) {
    use halo2_proofs::plonk::Circuit;
    let mut cs = halo2_proofs::plonk::ConstraintSystem::<Fr>::default();
    let _ = SolitonCircuit::configure(&mut cs);
    let _ = circuit;
    println!("  advice columns : {}", cs.num_advice_columns());
    println!("  fixed columns  : {}", cs.num_fixed_columns());
    println!("  selectors      : {}", cs.num_selectors());
    println!("  instance cols  : {}", cs.num_instance_columns());
    println!("  lookup args    : {}", cs.lookups().len());
    println!("  gates          : {}", cs.gates().len());
}

fn run_for_depth(depth: usize) {
    let k = k_for(depth);
    let seed = [7u8; 32];
    println!("\n=== SOLITON-Pay depth D={depth}, k={k} (rows=2^{k}) ===");

    // Params snapshot.
    let circuit = build_satisfying(depth, seed);
    report_params(&circuit);

    // Poseidon permutations per proof (each = 64 rows):
    //   per input: pk(1) + cm(2) + D merkle-hashes + nf(1) = 4 + D
    //   per output: pk(1) + cm(2) = 3
    //   total = 2*(4+D) + 2*3 = 14 + 2D
    let perms = 14 + 2 * depth;
    println!("  poseidon perms : {perms} (each 64 rows)");

    // 1. MockProver on satisfying witness MUST be Ok.
    let instance = circuit.instance();
    let mock = MockProver::run(k, &circuit, vec![instance.clone()]).expect("mock run");
    match mock.verify() {
        Ok(()) => println!("  [PASS] MockProver::verify() Ok (satisfying)"),
        Err(e) => panic!("  [FAIL] MockProver rejected satisfying witness: {e:?}"),
    }

    // 2. SHPLONK prove + verify MUST be Ok.
    let art = prove_and_verify(k, depth, seed).expect("prove_and_verify");
    println!("  [PASS] verify_proof() Ok (SHPLONK/Blake2b)");
    println!("  proof bytes    : {}", art.proof_len);
    println!("  {}", art.vk_note);
    match &art.vk_bytes {
        Some(b) => println!("  vk blob bytes  : {}", b.len()),
        None => println!("  vk blob        : none"),
    }
    assert_eq!(art.public_inputs, instance, "instance vectors must match");

    // 3. Negative tests: MockProver MUST reject.
    for mode in ["balance", "nullifier", "range"] {
        let (bad, bad_inst) = build_unsatisfying(depth, seed, mode);
        let mock = MockProver::run(k, &bad, vec![bad_inst]).expect("mock run (neg)");
        match mock.verify() {
            Err(_) => println!("  [PASS] MockProver REJECTED unsatisfying witness (mode={mode})"),
            Ok(()) => panic!("  [FAIL] MockProver ACCEPTED unsatisfying witness (mode={mode}) — constraint does NOT bind!"),
        }
    }
}

#[test]
fn soliton_pay_depth4() {
    run_for_depth(4);
}

#[test]
fn soliton_pay_depth32() {
    run_for_depth(32);
}
