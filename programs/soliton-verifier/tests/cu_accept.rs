//! SOUND on-chain acceptance + CU measurement, on the real SBF VM via Mollusk.
//!
//! Builds a REAL SOLITON-Pay proof (`soliton_pay::prover::prove_keccak`), stages
//! the proof+VK+SRS blob into a program-owned account, invokes the BPF program's
//! TAG_VERIFY path (which calls the host-verified `verify_generic`), and:
//!   * measures the TRUE compute-unit cost (CU limit raised to 1e9),
//!   * asserts the program returns SUCCESS for the real proof (== pairing TRUE),
//!   * asserts FAILURE for a 1-byte-tampered proof (negative control).
//!
//! Build + run:
//! ```bash
//! cargo build-sbf --manifest-path programs/soliton-verifier/Cargo.toml -- --features bpf-entrypoint
//! SBF_OUT_DIR=$(pwd)/target/deploy RUST_LOG=off \
//!   cargo test -p soliton-verifier --test cu_accept -- --nocapture
//! ```

use halo2curves::ff::PrimeField;
use halo2curves::bn256::Fr;
use mollusk_svm::{result::ProgramResult, Mollusk};
use solana_account::Account;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    rent::Rent,
};
use solana_svm_log_collector::LogCollector;

const PROGRAM_NAME: &str = "soliton_verifier";
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

/// Build the staged blob:
///   vk_len u32 | vk | proof_len u32 | proof | n_pi u32 | pi*32 | g1[64] | g2[128] | g2tau[128]
fn build_blob(art: &soliton_pay::prover::KeccakArtifacts) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(art.vk_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&art.vk_bytes);
    buf.extend_from_slice(&(art.proof_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&art.proof_bytes);
    buf.extend_from_slice(&(art.public_inputs.len() as u32).to_le_bytes());
    for pi in &art.public_inputs {
        buf.extend_from_slice(&fr_to_be(pi));
    }
    buf.extend_from_slice(&art.g1_one_be);
    buf.extend_from_slice(&art.g2_one_be);
    buf.extend_from_slice(&art.g2_tau_be);
    buf
}

const TAG_VERIFY: u8 = 0x01;

fn run(blob: &[u8]) -> (ProgramResult, u64, Vec<String>) {
    let program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::new(&program_id, PROGRAM_NAME);
    mollusk.compute_budget.compute_unit_limit = 1_000_000_000; // observe full cost
    mollusk.compute_budget.heap_size = 256 * 1024;
    let logger = LogCollector::new_ref_with_limit(None);
    mollusk.logger = Some(logger.clone());

    let data_acct = Pubkey::new_unique();
    let rent = Rent::default().minimum_balance(blob.len());
    let acct = Account {
        lamports: rent,
        data: blob.to_vec(),
        owner: program_id,
        executable: false,
        rent_epoch: 0,
    };

    let ix = Instruction {
        program_id,
        accounts: vec![AccountMeta::new_readonly(data_acct, false)],
        data: vec![TAG_VERIFY],
    };

    let result = mollusk.process_instruction(&ix, &[(data_acct, acct)]);
    let logs: Vec<String> = logger.borrow().get_recorded_content().to_vec();
    (result.program_result, result.compute_units_consumed, logs)
}

#[test]
fn cu_accept() {
    let art = soliton_pay::prover::prove_keccak(K, DEPTH, SEED).expect("prove_keccak failed");
    let blob = build_blob(&art);

    eprintln!();
    eprintln!("SOUND SOLITON-Pay on-chain verifier — Mollusk (real SBF, BN254).");
    eprintln!("real proof: k={K} depth={DEPTH} | blob = {} bytes", blob.len());
    eprintln!("  vk_v2={} proof={} n_pi={}", art.vk_bytes.len(), art.proof_bytes.len(), art.public_inputs.len());
    eprintln!();

    // ---- POSITIVE: real proof must be ACCEPTED (success == pairing TRUE) ----
    let (pos_result, pos_cu, pos_logs) = run(&blob);

    print_stage_breakdown(&pos_logs, pos_cu);
    eprintln!();
    eprintln!("TOTAL CU consumed (real proof): {pos_cu}");
    eprintln!("under 1,400,000 limit: {}", pos_cu <= 1_400_000);
    eprintln!("program result (positive): {pos_result:?}");
    eprintln!();

    assert!(
        matches!(pos_result, ProgramResult::Success),
        "REAL proof was NOT accepted on BPF (verify_generic did not return Ok(true)). result={pos_result:?}"
    );
    eprintln!("OK: real SOLITON-Pay proof ACCEPTED on BPF (pairing == TRUE).");

    // ---- NEGATIVE: flip one proof byte → must FAIL ----
    let mut bad = build_blob(&art);
    // Locate proof_bytes region: 4 + vk_len + 4 ... flip a byte in the middle.
    let vk_len = art.vk_bytes.len();
    let proof_start = 4 + vk_len + 4;
    let mid = proof_start + art.proof_bytes.len() / 2;
    bad[mid] ^= 0x01;

    let (neg_result, neg_cu, _neg_logs) = run(&bad);
    eprintln!();
    eprintln!("negative control (1-byte proof flip): result={neg_result:?} cu={neg_cu}");
    assert!(
        !matches!(neg_result, ProgramResult::Success),
        "TAMPERED proof was ACCEPTED on BPF — soundness broken. result={neg_result:?}"
    );
    eprintln!("OK: tampered proof REJECTED on BPF.");

    eprintln!();
    eprintln!("================ MOLLUSK ACCEPT/CU REPORT ================");
    eprintln!("real proof BPF CU       : {pos_cu}");
    eprintln!("under 1.4M              : {}", pos_cu <= 1_400_000);
    eprintln!("real proof ACCEPTED     : {}", matches!(pos_result, ProgramResult::Success));
    eprintln!("tampered REJECTED       : {}", !matches!(neg_result, ProgramResult::Success));
    eprintln!("structural-harness CU   : 926030");
    eprintln!("delta vs structural     : {:+} ({:+.1}%)",
        pos_cu as i64 - 926_030,
        (pos_cu as i64 - 926_030) as f64 / 926_030.0 * 100.0);
    eprintln!("=========================================================");
}

/// Parse the program log into a per-stage CU table.
fn print_stage_breakdown(logs: &[String], total: u64) {
    let mut stages: Vec<(String, u64)> = Vec::new();
    let mut pending: Option<String> = None;
    for line in logs {
        let l = line.trim();
        if let Some(idx) = l.find("[stage]") {
            pending = Some(l[idx + "[stage]".len()..].trim().to_string());
        } else if let Some(idx) = l.find("[vg]") {
            pending = Some(l[idx + "[vg]".len()..].trim().to_string());
        } else if let Some(rem) = parse_remaining(l) {
            if let Some(label) = pending.take() {
                stages.push((label, rem));
            }
        }
    }

    if stages.len() < 2 {
        eprintln!(
            "(stage trace: {} markers found; total CU below is authoritative.)",
            stages.len()
        );
        for s in &stages {
            eprintln!("   {} -> {} remaining", s.0, s.1);
        }
        return;
    }

    eprintln!("Per-stage CU breakdown (Δ of 'units remaining' between markers):");
    eprintln!();
    eprintln!("| stage                                  |   stage CU | remaining after |");
    eprintln!("|----------------------------------------|-----------:|----------------:|");
    let mut sum_stage = 0u64;
    for w in stages.windows(2) {
        let (_, rem_before) = &w[0];
        let (next_label, rem_after) = &w[1];
        let delta = rem_before.saturating_sub(*rem_after);
        sum_stage += delta;
        eprintln!("| {:38} | {:>10} | {:>15} |", next_label, delta, rem_after);
    }
    let entry_exit = total.saturating_sub(sum_stage);
    eprintln!("|----------------------------------------|-----------:|-----------------|");
    eprintln!("| {:38} | {:>10} |                 |", "entry + exit overhead", entry_exit);
    eprintln!("| {:38} | {:>10} |                 |", "TOTAL", total);
}

fn parse_remaining(l: &str) -> Option<u64> {
    let key = "consumption: ";
    let i = l.find(key)?;
    let rest = &l[i + key.len()..];
    let end = rest.find(' ')?;
    rest[..end].parse::<u64>().ok()
}
