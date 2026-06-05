//! SOLITON load-bearing CU probe — measured on the real SBF VM via Mollusk.
//!
//! Validates the design's central claim: a single Montgomery batch-inversion is
//! ~flat in n, while the naive per-element inversion path (which killed
//! Solana-Plonk at 2.71M CU) is linear at ~100k CU per element.
//!
//! Build + run:
//! ```bash
//! cargo build-sbf --manifest-path programs/soliton-probe/Cargo.toml -- --features bpf-entrypoint
//! cargo test -p soliton-probe --test cu_probe -- --nocapture
//! ```

use ark_ff::UniformRand;
use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::rand::{rngs::StdRng, SeedableRng};

use mollusk_svm::{result::ProgramResult, Mollusk};
use solana_account::Account;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    rent::Rent,
};

type Fr = ark_bn254::Fr;

const PROGRAM_NAME: &str = "soliton_probe";
/// SOLITON's model payment circuit needs ~6-20 denominators (Lagrange +
/// vanishing + Shplonk z_0 + logUp betas). Grid spans that range plus tails.
const NS: &[usize] = &[1, 2, 4, 8, 12, 16, 20, 32];

fn build_payload(n: usize, seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut buf = Vec::with_capacity(4 + n * 32);
    buf.extend_from_slice(&(n as u32).to_le_bytes());
    for _ in 0..n {
        // Nonzero w.h.p.; serialize canonical 32-byte LE.
        let x = Fr::rand(&mut rng);
        let mut le = [0u8; 32];
        x.serialize_with_mode(&mut le[..], Compress::No).unwrap();
        buf.extend_from_slice(&le);
    }
    buf
}

#[test]
fn cu_probe() {
    let program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::new(&program_id, PROGRAM_NAME);
    mollusk.compute_budget.compute_unit_limit = 1_000_000_000; // observe full cost
    mollusk.compute_budget.heap_size = 256 * 1024;

    let data_acct = Pubkey::new_unique();
    let rent = Rent::default().minimum_balance(1 + 4 + 32 * 64);

    let run_mode = |mollusk: &Mollusk, mode: u8, payload: &[u8]| -> Option<u64> {
        let mut acct_data = Vec::with_capacity(1 + payload.len());
        acct_data.push(mode);
        acct_data.extend_from_slice(payload);
        let acct = Account {
            lamports: rent,
            data: acct_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        };
        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new_readonly(data_acct, false)],
            data: vec![],
        };
        let result = mollusk.process_instruction(&ix, &[(data_acct, acct.clone())]);
        match result.program_result {
            ProgramResult::Success => Some(result.compute_units_consumed),
            other => {
                eprintln!("  mode {mode} FAILED: {other:?}");
                None
            }
        }
    };

    eprintln!();
    eprintln!("SOLITON load-bearing CU probe (Mollusk, real SBF, BN254).");
    eprintln!("net = mode CU minus mode-0 parse baseline at same n.");
    eprintln!();
    eprintln!("|  n | baseline |   naive-inv (net) | batch-inv (net) | naive/batch | fr-horner (net) |");
    eprintln!("|---:|---------:|------------------:|----------------:|------------:|----------------:|");

    for &n in NS {
        let payload = build_payload(n, 1024 + n as u64);
        let base = run_mode(&mollusk, 0, &payload);
        let naive = run_mode(&mollusk, 10, &payload);
        let batch = run_mode(&mollusk, 11, &payload);
        let horner = run_mode(&mollusk, 12, &payload);

        let net = |v: Option<u64>| match (v, base) {
            (Some(a), Some(b)) => Some(a.saturating_sub(b)),
            _ => None,
        };
        let nn = net(naive);
        let nb = net(batch);
        let nh = net(horner);
        let ratio = match (nn, nb) {
            (Some(a), Some(b)) if b > 0 => format!("{:>10.1}×", a as f64 / b as f64),
            _ => "         —".to_string(),
        };
        let f = |o: Option<u64>| match o {
            Some(v) => format!("{v:>15}"),
            None => format!("{:>15}", "ERR"),
        };
        eprintln!(
            "| {:2} | {:>8} | {} | {} | {} | {} |",
            n,
            base.map(|v| v.to_string()).unwrap_or_else(|| "ERR".into()),
            f(nn),
            f(nb),
            ratio,
            f(nh),
        );
    }

    // Final pairing check (n-independent).
    let pairing = run_mode(&mollusk, 30, &build_payload(0, 7));
    eprintln!();
    match pairing {
        Some(v) => eprintln!("2-pair alt_bn128_pairing_be: {v} CU"),
        None => eprintln!("2-pair pairing: ERR"),
    }
    eprintln!();
}
