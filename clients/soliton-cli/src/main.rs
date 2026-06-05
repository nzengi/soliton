//! Devnet finale for the SOUND `soliton-verifier` BPF program.
//!
//! Builds the SOLITON-Pay proof via `soliton_pay::prover::prove_keccak`,
//! serializes the proof+VK+SRS blob EXACTLY as `programs/soliton-verifier/
//! tests/cu_accept.rs::build_blob` does, stages it into a program-owned data
//! account (chunked, since the blob exceeds the 1232-byte per-tx limit), then
//! sends the TAG_VERIFY tx with a raised compute budget and reports the
//! on-chain compute-unit consumption from the confirmed tx meta, cross-checked
//! against `simulate_transaction`.
//!
//! A Status==Ok verify tx == the on-chain program returned success == the
//! BN254 pairing check returned TRUE == proof ACCEPTED on devnet.
//!
//! Flow:
//!   tx1:        system::create_account(data_acct, rent, blob.len(), program_id)
//!   tx2..N:     LOAD  [0x00 | offset:u32 LE | chunk] -> accounts[0].data[off..]
//!   final tx:   VERIFY [0x01] with CU limit 1.4M + heap 256KB
//!
//! Usage:
//!   cargo run -p soliton-cli -- <PROGRAM_ID>
//!   SOLITON_PROGRAM_ID=<id> cargo run -p soliton-cli

use anyhow::{anyhow, Context, Result};
use halo2curves::ff::PrimeField;
use solana_client::{
    rpc_client::RpcClient,
    rpc_config::{RpcSimulateTransactionConfig, RpcTransactionConfig},
};
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_program::pubkey::Pubkey;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    signature::{read_keypair_file, Keypair, Signer},
    transaction::Transaction,
};
use solana_system_interface::instruction as system_instruction;

const DEVNET_URL: &str = "https://api.devnet.solana.com";
const KEYPAIR_PATH: &str = "/home/nzengi/.config/solana/id.json";

const K: u32 = 13;
const DEPTH: usize = 4;
const SEED: [u8; 32] = [7u8; 32];

const TAG_LOAD: u8 = 0x00;
const TAG_VERIFY: u8 = 0x01;
const CHUNK: usize = 900;
const CU_LIMIT: u32 = 1_400_000;
const MOLLUSK_CU: i64 = 1_344_697;

/// Big-endian 32-byte encoding of an Fr (matches cu_accept.rs::fr_to_be).
fn fr_to_be(f: &halo2curves::bn256::Fr) -> [u8; 32] {
    let le = f.to_repr();
    let mut be = [0u8; 32];
    for (i, b) in le.iter().rev().enumerate() {
        be[i] = *b;
    }
    be
}

/// Build the staged blob — byte-for-byte identical to cu_accept.rs::build_blob:
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

fn resolve_program_id() -> Result<Pubkey> {
    if let Some(arg) = std::env::args().nth(1) {
        return arg
            .parse()
            .with_context(|| format!("parse program id from arg: {arg}"));
    }
    let env = std::env::var("SOLITON_PROGRAM_ID")
        .context("no program id: pass as CLI arg or set SOLITON_PROGRAM_ID")?;
    env.parse()
        .with_context(|| format!("parse program id from env: {env}"))
}

fn main() -> Result<()> {
    let program_id = resolve_program_id()?;
    eprintln!("program_id = {program_id}");

    let payer =
        read_keypair_file(KEYPAIR_PATH).map_err(|e| anyhow!("read keypair {KEYPAIR_PATH}: {e}"))?;
    let rpc = RpcClient::new_with_commitment(DEVNET_URL.to_string(), CommitmentConfig::confirmed());

    let bal = rpc.get_balance(&payer.pubkey())?;
    eprintln!(
        "payer = {} | balance = {} lamports ({:.4} SOL)",
        payer.pubkey(),
        bal,
        bal as f64 / 1e9
    );

    // ── build the SOLITON-Pay proof blob ──
    eprintln!("proving SOLITON-Pay (k={K}, depth={DEPTH}, seed=[7;32])…");
    let art = soliton_pay::prover::prove_keccak(K, DEPTH, SEED)
        .map_err(|e| anyhow!("prove_keccak failed: {e:?}"))?;
    let blob = build_blob(&art);
    eprintln!(
        "proof: vk_v2={} proof={} n_pi={} | blob = {} bytes",
        art.vk_bytes.len(),
        art.proof_bytes.len(),
        art.public_inputs.len(),
        blob.len()
    );

    // ── tx1: create program-owned data account ──
    let data_acct = Keypair::new();
    let rent = rpc.get_minimum_balance_for_rent_exemption(blob.len())?;
    eprintln!(
        "data_acct = {} | {} bytes | rent {} lamports",
        data_acct.pubkey(),
        blob.len(),
        rent
    );
    let create_ix = system_instruction::create_account(
        &payer.pubkey(),
        &data_acct.pubkey(),
        rent,
        blob.len() as u64,
        &program_id,
    );
    let bh = rpc.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[create_ix],
        Some(&payer.pubkey()),
        &[&payer, &data_acct],
        bh,
    );
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .context("create_account tx")?;
    eprintln!("  create_account confirmed — {sig}");

    // ── tx2..N: chunked LOAD ──
    let total = blob.len();
    let mut off = 0usize;
    let mut n = 0;
    while off < total {
        let end = (off + CHUNK).min(total);
        let mut data = Vec::with_capacity(5 + (end - off));
        data.push(TAG_LOAD);
        data.extend_from_slice(&(off as u32).to_le_bytes());
        data.extend_from_slice(&blob[off..end]);

        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(data_acct.pubkey(), false)],
            data,
        };
        let bh = rpc.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], bh);
        let sig = rpc
            .send_and_confirm_transaction(&tx)
            .with_context(|| format!("load tx (bytes {off}..{end})"))?;
        n += 1;
        eprintln!("  load[{n}] bytes {off}..{end} confirmed — {sig}");
        off = end;
    }
    eprintln!("data account fully populated ({total} bytes in {n} chunks)");

    // ── final tx: VERIFY with raised compute budget ──
    let verify_ix = Instruction {
        program_id,
        accounts: vec![AccountMeta::new_readonly(data_acct.pubkey(), false)],
        data: vec![TAG_VERIFY],
    };
    let ixs = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(CU_LIMIT),
        ComputeBudgetInstruction::request_heap_frame(256 * 1024),
        verify_ix,
    ];

    // Simulate first (cross-check), capturing units_consumed + logs.
    let sim_bh = rpc.get_latest_blockhash()?;
    let sim_tx = Transaction::new_signed_with_payer(&ixs, Some(&payer.pubkey()), &[&payer], sim_bh);
    let sim = rpc.simulate_transaction_with_config(
        &sim_tx,
        RpcSimulateTransactionConfig {
            sig_verify: false,
            replace_recent_blockhash: true,
            commitment: Some(CommitmentConfig::confirmed()),
            ..Default::default()
        },
    )?;
    let sim_units = sim.value.units_consumed;
    eprintln!("simulate units_consumed = {sim_units:?}");
    if let Some(logs) = &sim.value.logs {
        eprintln!("--- simulate logs ---");
        for l in logs {
            eprintln!("  {l}");
        }
        eprintln!("--- end simulate logs ---");
    }
    if let Some(err) = &sim.value.err {
        eprintln!("simulate err: {err:?}");
    }

    // Send + confirm the verify tx.
    eprintln!("sending verify tx (CU limit {CU_LIMIT}, heap 256KB)…");
    let bh = rpc.get_latest_blockhash()?;
    let verify_tx =
        Transaction::new_signed_with_payer(&ixs, Some(&payer.pubkey()), &[&payer], bh);
    let verify_sig = rpc
        .send_and_confirm_transaction(&verify_tx)
        .context("verify tx (Status != Ok means the proof was REJECTED on-chain)")?;
    eprintln!("verify confirmed (Status Ok) — {verify_sig}");

    // ── report on-chain CU from confirmed tx meta ──
    let fetched = rpc
        .get_transaction_with_config(
            &verify_sig,
            RpcTransactionConfig {
                encoding: None,
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        )
        .context("get_transaction")?;

    let meta = fetched
        .transaction
        .meta
        .ok_or_else(|| anyhow!("confirmed tx has no meta"))?;
    let onchain_cu: Option<u64> = meta.compute_units_consumed.into();
    let tx_err: Option<_> = meta.err.clone();

    println!();
    println!("================ DEVNET PROOF CU REPORT ================");
    println!("program_id              : {program_id}");
    println!("data_account            : {}", data_acct.pubkey());
    println!("verify tx signature     : {verify_sig}");
    println!("explorer                : https://explorer.solana.com/tx/{verify_sig}?cluster=devnet");
    println!("tx Status               : {}", if tx_err.is_none() { "Ok (proof ACCEPTED, pairing TRUE)" } else { "FAILED" });
    if let Some(e) = &tx_err {
        println!("tx err                  : {e:?}");
    }
    println!("on-chain CU (tx meta)   : {onchain_cu:?}");
    println!("simulate units_consumed : {sim_units:?}");
    println!("CU limit                : {CU_LIMIT}");
    if let Some(cu) = onchain_cu {
        println!("under 1.4M limit        : {}", cu < CU_LIMIT as u64);
        let delta = cu as i64 - MOLLUSK_CU;
        let pct = delta as f64 / MOLLUSK_CU as f64 * 100.0;
        println!("Mollusk figure          : {MOLLUSK_CU}");
        println!("delta vs Mollusk        : {delta:+} ({pct:+.3}%)");
    }
    println!("--- on-chain program logs (tx meta) ---");
    let log_messages: Option<Vec<String>> = meta.log_messages.into();
    if let Some(logs) = log_messages {
        for l in logs {
            println!("  {l}");
        }
    } else {
        println!("  (no log messages in meta)");
    }
    println!("============================================================");

    if tx_err.is_some() {
        return Err(anyhow!("verify tx Status != Ok: {tx_err:?}"));
    }
    Ok(())
}
