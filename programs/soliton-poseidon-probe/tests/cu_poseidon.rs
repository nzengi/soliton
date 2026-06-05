//! Step 1: measure the on-chain shared-Poseidon cost on the real SBF VM.
//!
//! Reports (Δ vs the parse-only baseline):
//!   * one H2 permutation
//!   * one depth-32 incremental insert path (32 H2, empty roots precomputed off)
//!   * the per-call empty-subtree recomputation (32 H2)
//!   * the full shield-style insert (empty roots + path = 64 H2)
//!
//! This determines whether `shield` (insert only, no proof) fits in 1.4M and
//! confirms verify (~1.345M) + insert cannot share a tx.
//!
//! Build + run:
//!   cargo build-sbf --manifest-path programs/soliton-poseidon-probe/Cargo.toml -- --features bpf-entrypoint
//!   SBF_OUT_DIR=$(pwd)/target/deploy cargo test -p soliton-poseidon-probe --test cu_poseidon -- --nocapture

use mollusk_svm::{result::ProgramResult, Mollusk};
use solana_account::Account;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    rent::Rent,
};

const PROGRAM_NAME: &str = "soliton_poseidon_probe";

fn run_mode(mode: u8) -> (ProgramResult, u64) {
    let program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::new(&program_id, PROGRAM_NAME);
    mollusk.compute_budget.compute_unit_limit = 1_000_000_000;
    mollusk.compute_budget.heap_size = 256 * 1024;

    // Payload via accounts[0] (mirrors the other probes): [mode | leaf32].
    let mut blob = Vec::with_capacity(33);
    blob.push(mode);
    blob.extend_from_slice(&[3u8; 32]); // arbitrary leaf

    let data_acct = Pubkey::new_unique();
    let rent = Rent::default().minimum_balance(blob.len());
    let acct = Account {
        lamports: rent,
        data: blob.clone(),
        owner: program_id,
        executable: false,
        rent_epoch: 0,
    };
    let ix = Instruction {
        program_id,
        accounts: vec![AccountMeta::new_readonly(data_acct, false)],
        data: vec![mode], // unused on-chain (reads accounts[0]); kept non-empty
    };
    let r = mollusk.process_instruction(&ix, &[(data_acct, acct)]);
    (r.program_result, r.compute_units_consumed)
}

#[test]
fn cu_poseidon() {
    let (r0, cu0) = run_mode(0); // baseline parse-only
    let (r1, cu1) = run_mode(1); // 1 H2
    let (r2, cu2) = run_mode(2); // empty roots (32 H2) + insert path (32 H2) = 64 H2
    let (r3, cu3) = run_mode(3); // empty roots only (32 H2)

    for (n, r) in [("baseline", &r0), ("h2", &r1), ("insert64", &r2), ("empty32", &r3)] {
        assert!(matches!(r, ProgramResult::Success), "mode {n} failed: {r:?}");
    }

    let one_h2 = cu1 - cu0;
    let empty32 = cu3 - cu0;
    let insert64 = cu2 - cu0;
    let insert_path32 = cu2.saturating_sub(cu3); // 64H2 - 32H2 = pure 32-hash path

    eprintln!();
    eprintln!("============ SHARED POSEIDON CU (real SBF) ============");
    eprintln!("baseline (parse only)         : {cu0}");
    eprintln!("one H2 permutation            : {one_h2}");
    eprintln!("32 H2 (empty-subtree chain)   : {empty32}");
    eprintln!("32 H2 (insert path, =64-32)   : {insert_path32}");
    eprintln!("full shield insert (64 H2)    : {insert64}   raw cu={cu2}");
    eprintln!("  (= per-call empty roots 32H2 + depth-32 insert path 32H2)");
    eprintln!("approx per-H2 (insert64/64)   : {}", insert64 / 64);
    eprintln!();
    eprintln!("shield = insert only (no proof) fits 1.4M : {}", cu2 <= 1_400_000);
    eprintln!("verify alone ~1,345,000 → verify+insert in one tx would be ~{}",
        1_345_000 + insert64);
    eprintln!("  => verify + insert share a tx under 1.4M : {}",
        1_345_000 + insert64 <= 1_400_000);
    eprintln!("=======================================================");
    if one_h2 > 1_400_000 {
        eprintln!("!! BLOCKER: a SINGLE H2 ({one_h2} CU) already exceeds 1.4M.");
        eprintln!("   The custom ark-ff Poseidon (pure-Rust BN254 Fr arithmetic, no");
        eprintln!("   native syscall) costs ~{} CU per field mul; ~800 muls/permute.",
            one_h2 / 800);
        eprintln!("   On-chain tree hashing is INFEASIBLE with this hash as-is.");
    }

    // This probe DOCUMENTS the measured cost; the hard gate lives in the report, not
    // an assert, because the measured infeasibility IS the deliverable. We still
    // assert the program ran correctly (above) and that H2 is deterministic by
    // construction (equivalence test). Keep the measurement non-fatal:
    let _ = (one_h2, insert_path32, insert64);
}
