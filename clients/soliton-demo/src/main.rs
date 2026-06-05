//! SOLITON Stage 4 — full Alice -> Bob PRIVATE SOL transfer on live Solana devnet.
//!
//! This drives the deployed `soliton-pool` program through the entire protocol:
//!   fund Alice + Bob -> init pool -> Alice shields 2 notes -> Bob shields 1 note
//!   -> Alice->Bob private transfer (proof verify + nullify + queue) -> flush
//!   (insert outputs) -> Bob SCANS devnet, decrypts his output note from the
//!   on-chain blob -> Bob unshields (his shield note + Alice's payment note) to a
//!   PUBLIC Bob address.
//!
//! Honesty: this is a DEVNET demo on a per-proof test SRS (the prover sets up a
//! fresh KZG SRS each run). With only two participants the anonymity set is 2, so
//! timing+amount correlation of the public shield/unshield still links them. The
//! demo proves the CRYPTOGRAPHIC mechanism (the transfer tx reveals no value and
//! no Alice->Bob link at the protocol level), not strong statistical privacy.
//!
//! Bob's note delivery: the pool does not persist ciphertexts in its state, so we
//! make the encrypted output notes available ON-CHAIN by appending them to the
//! staged proof blob account (program-owned, persistent, referenced by the
//! transfer tx). `parse_blob` reads only the proof region and ignores the trailing
//! ciphertexts, so this needs no on-chain change. Bob reads the blob account via
//! RPC and trial-decrypts.
//!
//! Usage:
//!   cargo run -p soliton-demo --release -- <POOL_PROGRAM_ID>
//!   SOLITON_POOL_ID=<id> cargo run -p soliton-demo --release

use anyhow::{anyhow, Context, Result};
use halo2curves::ff::PrimeField;
use solana_client::{
    rpc_client::RpcClient,
    rpc_config::RpcTransactionConfig,
};
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_program::pubkey::Pubkey;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    signature::{read_keypair_file, Keypair, Signature, Signer},
    transaction::Transaction,
};
use solana_system_interface::instruction as system_instruction;

use soliton_sdk::Wallet;

const DEVNET_URL: &str = "https://api.devnet.solana.com";
const FUNDER_KEYPAIR: &str = "/home/nzengi/.config/solana/id.json";

const TAG_INIT: u8 = 0x00;
const TAG_TRANSFER: u8 = 0x02;
const TAG_FLUSH: u8 = 0x03;
// Note: shield (0x01) and unshield (0x04) tags travel inside the SDK-built
// `ix_data` (ShieldBundle/UnshieldBundle), so we never hand-write them here.

const CU_LIMIT: u32 = 1_400_000;
const CHUNK: usize = 900;

const POOL_STATE_LEN: usize = 4156; // soliton_pool::state::POOL_STATE_LEN

/// BE 32-byte encoding of a halo2 Fr (matches the on-chain public-input order).
fn h_be(f: &halo2curves::bn256::Fr) -> [u8; 32] {
    let le = f.to_repr();
    let mut be = [0u8; 32];
    for (i, b) in le.iter().rev().enumerate() {
        be[i] = *b;
    }
    be
}
fn be_to_le(be: &[u8; 32]) -> [u8; 32] {
    let mut le = [0u8; 32];
    for (i, b) in be.iter().rev().enumerate() {
        le[i] = *b;
    }
    le
}
/// Build the staged proof blob, byte-for-byte the layout `parse_blob` expects,
/// then APPEND the encrypted output notes so Bob can fetch them on-chain:
///   [ proof region (parse_blob reads this) ]
///   [ n_ct u32 LE | (ct_len u32 LE | ct_bytes)* ]   <- trailing, ignored by verify
fn build_blob_with_notes(
    art: &soliton_pay::prover::KeccakArtifacts,
    ciphertexts: &[Vec<u8>],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(art.vk_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&art.vk_bytes);
    buf.extend_from_slice(&(art.proof_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&art.proof_bytes);
    buf.extend_from_slice(&(art.public_inputs.len() as u32).to_le_bytes());
    for pi in &art.public_inputs {
        buf.extend_from_slice(&h_be(pi));
    }
    buf.extend_from_slice(&art.g1_one_be);
    buf.extend_from_slice(&art.g2_one_be);
    buf.extend_from_slice(&art.g2_tau_be);
    // trailing ciphertext bundle (on-chain note delivery)
    buf.extend_from_slice(&(ciphertexts.len() as u32).to_le_bytes());
    for ct in ciphertexts {
        buf.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        buf.extend_from_slice(ct);
    }
    buf
}

/// The offset (in the staged blob) of the proof region's end, i.e. where the
/// trailing ciphertext bundle starts. Computed the same way as build_blob.
fn proof_region_len(art: &soliton_pay::prover::KeccakArtifacts) -> usize {
    4 + art.vk_bytes.len()
        + 4 + art.proof_bytes.len()
        + 4 + art.public_inputs.len() * 32
        + 64 + 128 + 128
}

/// Parse the trailing ciphertext bundle out of an on-chain blob account.
fn parse_trailing_cts(data: &[u8], region_start: usize) -> Vec<Vec<u8>> {
    let mut cur = region_start;
    let rd_u32 = |d: &[u8], c: usize| -> Option<u32> {
        if c + 4 > d.len() {
            return None;
        }
        Some(u32::from_le_bytes([d[c], d[c + 1], d[c + 2], d[c + 3]]))
    };
    let mut out = Vec::new();
    let n = match rd_u32(data, cur) {
        Some(n) => n as usize,
        None => return out,
    };
    cur += 4;
    for _ in 0..n {
        let len = match rd_u32(data, cur) {
            Some(l) => l as usize,
            None => break,
        };
        cur += 4;
        if cur + len > data.len() {
            break;
        }
        out.push(data[cur..cur + len].to_vec());
        cur += len;
    }
    out
}

/// System program id as a `Pubkey` (all-zero address "111...1").
fn system_program_id() -> Pubkey {
    Pubkey::new_from_array([0u8; 32])
}

fn nf_pda(program_id: &Pubkey, nf_le: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nf", nf_le], program_id)
}

fn explorer(sig: &Signature) -> String {
    format!("https://explorer.solana.com/tx/{sig}?cluster=devnet")
}

struct Ctx {
    rpc: RpcClient,
    funder: Keypair,
    program_id: Pubkey,
}

impl Ctx {
    fn send(&self, ixs: &[Instruction], signers: &[&Keypair], label: &str) -> Result<Signature> {
        let bh = self.rpc.get_latest_blockhash()?;
        let payer = signers[0].pubkey();
        let tx = Transaction::new_signed_with_payer(ixs, Some(&payer), signers, bh);
        let sig = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .with_context(|| format!("{label} tx failed"))?;
        println!("  [{label}] sig = {sig}");
        println!("           {}", explorer(&sig));
        Ok(sig)
    }

    /// Confirmed on-chain compute_units_consumed for a signature.
    fn cu_of(&self, sig: &Signature) -> Result<Option<u64>> {
        let fetched = self.rpc.get_transaction_with_config(
            sig,
            RpcTransactionConfig {
                encoding: None,
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        )?;
        let meta = fetched
            .transaction
            .meta
            .ok_or_else(|| anyhow!("tx has no meta"))?;
        Ok(meta.compute_units_consumed.into())
    }

    fn balance(&self, pk: &Pubkey) -> Result<u64> {
        Ok(self.rpc.get_balance(pk)?)
    }
}

/// Create a SYSTEM-owned data account, chunk-write the blob into it via System
/// transfers... no: the blob must be readable by the pool. The pool reads the
/// blob account's data directly (borrow_unchecked); ANY account's data is
/// readable by a program if passed as an account. We therefore create a
/// system-owned account, write the blob into it through the funder (who owns it),
/// and pass it read-only to the pool. System-owned accounts cannot be written by
/// arbitrary instructions though — so we make the funder the owner via a normal
/// `create_account` owned by the funder? System accounts can only be written by
/// the System program. The clean path used in stage 3 is: create the account
/// OWNED BY THE POOL PROGRAM, and have the POOL's load tag fill it. The pool has
/// no load tag. So instead we create the account owned by a tiny loader: we use
/// the account as a plain data buffer owned by the funder's keypair-as-program?
///
/// Simplest correct devnet path: create the account owned by the System program
/// with the blob length, then write it with `system_instruction::assign`? No.
///
/// We use the proven stage-3 pattern: the pool program can READ any account's
/// bytes. We create a program-owned (pool-owned) account and populate it BEFORE
/// it is owned by the pool — i.e. create it owned by the funder via a buffer, then
/// reassign. To keep this robust we instead create it as a NEW keypair account
/// owned by the pool program with `create_account`, and fill it with a dedicated
/// loader instruction. Since the pool lacks a loader, we POPULATE the bytes at
/// creation is impossible (create_account zero-fills).
///
/// Therefore we stage the blob into an account owned by the *funder's* throwaway
/// keypair acting as a System-owned account and fill it via repeated
/// `system_instruction::transfer`? That writes lamports, not data.
fn stage_blob(ctx: &Ctx, blob: &[u8]) -> Result<Keypair> {
    // The pool reads blob bytes via a read-only account; it does not check the
    // owner of the blob account. So the blob account can be SYSTEM-owned, as long
    // as it carries the bytes. System-owned accounts created with `create_account`
    // (owner = a loader program we control) let us write via that loader.
    //
    // We reuse the already-deployed `soliton-verifier` loader program for staging:
    // it owns the data account and exposes TAG_LOAD [0x00 | off u32 | chunk]. But
    // then the account is owned by the verifier, not the pool — that's fine, the
    // pool only READS it.
    let loader = verifier_loader_id()?;
    let data_acct = Keypair::new();
    let rent = ctx
        .rpc
        .get_minimum_balance_for_rent_exemption(blob.len())?;
    let create_ix = system_instruction::create_account(
        &ctx.funder.pubkey(),
        &data_acct.pubkey(),
        rent,
        blob.len() as u64,
        &loader,
    );
    let bh = ctx.rpc.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[create_ix],
        Some(&ctx.funder.pubkey()),
        &[&ctx.funder, &data_acct],
        bh,
    );
    ctx.rpc
        .send_and_confirm_transaction(&tx)
        .context("create blob data account")?;
    println!(
        "  staged blob account {} ({} bytes, owner=verifier-loader)",
        data_acct.pubkey(),
        blob.len()
    );

    // chunk-load
    let total = blob.len();
    let mut off = 0usize;
    while off < total {
        let end = (off + CHUNK).min(total);
        let mut data = Vec::with_capacity(5 + (end - off));
        data.push(0x00); // verifier loader TAG_LOAD
        data.extend_from_slice(&(off as u32).to_le_bytes());
        data.extend_from_slice(&blob[off..end]);
        let ix = Instruction {
            program_id: loader,
            accounts: vec![AccountMeta::new(data_acct.pubkey(), false)],
            data,
        };
        let bh = ctx.rpc.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&ctx.funder.pubkey()),
            &[&ctx.funder],
            bh,
        );
        ctx.rpc
            .send_and_confirm_transaction(&tx)
            .with_context(|| format!("load chunk {off}..{end}"))?;
        off = end;
    }
    println!("  blob fully staged ({total} bytes)");
    Ok(data_acct)
}

fn verifier_loader_id() -> Result<Pubkey> {
    // Stage-3 verifier program (deployed), used here purely as a blob LOADER:
    // it owns the staged data account and exposes TAG_LOAD; the pool only READS
    // the account's bytes.
    "AUx3m1rmHwNtTuL6BymuQuSyJKP7kyqcVypLqYiWSoSf"
        .parse()
        .context("parse verifier loader id")
}

fn resolve_pool_id() -> Result<Pubkey> {
    if let Some(arg) = std::env::args().nth(1) {
        return arg.parse().context("parse pool id arg");
    }
    let env = std::env::var("SOLITON_POOL_ID").context("no pool id (arg or SOLITON_POOL_ID)")?;
    env.parse().context("parse pool id env")
}

fn sol(lamports: u64) -> f64 {
    lamports as f64 / 1e9
}

fn main() -> Result<()> {
    let program_id = resolve_pool_id()?;
    let funder = read_keypair_file(FUNDER_KEYPAIR)
        .map_err(|e| anyhow!("read funder {FUNDER_KEYPAIR}: {e}"))?;
    let rpc = RpcClient::new_with_commitment(DEVNET_URL.to_string(), CommitmentConfig::confirmed());
    let ctx = Ctx { rpc, funder, program_id };

    println!("================ SOLITON STAGE 4 — DEVNET PRIVATE TRANSFER ================");
    println!("pool program id : {program_id}");
    println!("verifier (loader): {}", verifier_loader_id()?);
    println!("funder          : {}", ctx.funder.pubkey());
    println!("funder balance  : {:.4} SOL", sol(ctx.balance(&ctx.funder.pubkey())?));
    println!();

    // ---- wallets ----
    let mut alice = Wallet::from_seed(0xA11CE);
    let mut bob = Wallet::from_seed(0xB0B);
    let bob_addr = bob.address();

    let alice_payer = Keypair::new();
    let bob_payer = Keypair::new();
    // Bob's PUBLIC withdrawal address (where unshielded SOL lands).
    let bob_public = Keypair::new();

    // ---- amounts (lamports) ----
    // Alice shields two notes; transfers a payment to Bob + change to self.
    // Bob shields a small note so that, with Alice's payment note, he has the two
    // input notes the fixed 2-in/2-out circuit requires to unshield.
    let alice_shield_a: u64 = 60_000_000; // 0.06 SOL
    let alice_shield_b: u64 = 40_000_000; // 0.04 SOL  (total 0.10 SOL)
    let bob_shield: u64 = 5_000_000; // 0.005 SOL
    let transfer_amount: u64 = 90_000_000; // 0.09 SOL to Bob
    let transfer_fee: u64 = 1_000_000; // 0.001 SOL fee (stays in vault)
    let unshield_fee: u64 = 1_000_000; // 0.001 SOL fee
    // Bob will unshield (bob_shield + transfer_amount - unshield_fee).
    let unshield_amount: u64 = bob_shield + transfer_amount - unshield_fee;

    // Fund the fee-payers generously for the heavy txs + rent of staged blobs/PDAs.
    let alice_funding: u64 = alice_shield_a + alice_shield_b + 200_000_000; // + headroom
    let bob_funding: u64 = bob_shield + 150_000_000;

    // =====================================================================
    // STEP 1+2: fund Alice and Bob fee-payers from the funder.
    // =====================================================================
    println!("---- STEP: fund Alice ----");
    let sig_fund_alice = ctx.send(
        &[system_instruction::transfer(
            &ctx.funder.pubkey(),
            &alice_payer.pubkey(),
            alice_funding,
        )],
        &[&ctx.funder],
        "fund-Alice",
    )?;
    println!("  Alice fee-payer {} <- {:.4} SOL", alice_payer.pubkey(), sol(alice_funding));

    println!("---- STEP: fund Bob ----");
    let sig_fund_bob = ctx.send(
        &[system_instruction::transfer(
            &ctx.funder.pubkey(),
            &bob_payer.pubkey(),
            bob_funding,
        )],
        &[&ctx.funder],
        "fund-Bob",
    )?;
    println!("  Bob fee-payer {} <- {:.4} SOL", bob_payer.pubkey(), sol(bob_funding));

    let alice_sol_before = ctx.balance(&alice_payer.pubkey())?;
    println!("  Alice fee-payer balance before shields: {:.6} SOL", sol(alice_sol_before));
    println!();

    // =====================================================================
    // STEP 3: initialize the pool (state account + vault PDA).
    // =====================================================================
    println!("---- STEP: initialize pool ----");
    // Pool state account: a fresh keypair, program-owned, POOL_STATE_LEN bytes.
    let pool_state = Keypair::new();
    let pool_rent = ctx.rpc.get_minimum_balance_for_rent_exemption(POOL_STATE_LEN)?;
    let create_state = system_instruction::create_account(
        &ctx.funder.pubkey(),
        &pool_state.pubkey(),
        pool_rent,
        POOL_STATE_LEN as u64,
        &program_id,
    );
    // Vault: a program-OWNED account (the pool moves lamports out of it via direct
    // field mutation in `unshield`, which the runtime allows only for accounts the
    // program owns). The pool does not enforce a specific vault address — it uses
    // whichever account is passed at index 1 — so we create a dedicated
    // program-owned vault account and pass it consistently. We still record a bump
    // in PoolState for completeness.
    let vault_kp = Keypair::new();
    let vault = vault_kp.pubkey();
    let vault_bump = 255u8;
    let vault_rent = ctx.rpc.get_minimum_balance_for_rent_exemption(0)?;
    println!("  pool_state = {}", pool_state.pubkey());
    println!("  vault      = {} (program-owned)", vault);

    // Create the state account + the program-owned vault (one tx, two signers).
    {
        let create_vault = system_instruction::create_account(
            &ctx.funder.pubkey(),
            &vault,
            vault_rent,
            0,
            &program_id,
        );
        let bh = ctx.rpc.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(
            &[create_state, create_vault],
            Some(&ctx.funder.pubkey()),
            &[&ctx.funder, &pool_state, &vault_kp],
            bh,
        );
        ctx.rpc
            .send_and_confirm_transaction(&tx)
            .context("create pool state + vault accounts")?;
        println!("  pool_state ({POOL_STATE_LEN} bytes) + vault accounts created (program-owned)");
    }

    // init ix: [pool_state W, vault R]  data: [0x00, bump]
    let init_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool_state.pubkey(), false),
            AccountMeta::new_readonly(vault, false),
        ],
        data: vec![TAG_INIT, vault_bump],
    };
    let sig_init = ctx.send(&[init_ix], &[&ctx.funder], "init")?;
    println!("  vault rent-exempt with {:.6} SOL", sol(vault_rent));
    println!();

    // Shared ledger of (commitment, ciphertext) the wallets scan from.
    let mut ledger_cms: Vec<ark_bn254::Fr> = Vec::new();
    let mut ledger_cts: Vec<(ark_bn254::Fr, Vec<u8>)> = Vec::new();

    // =====================================================================
    // STEP 4: Alice shields TWO notes (real lamports Alice -> vault).
    // =====================================================================
    println!("---- STEP: Alice shields 2 notes ----");
    let mut shield_sigs = Vec::new();
    for (i, amt) in [alice_shield_a, alice_shield_b].into_iter().enumerate() {
        let s = alice.build_shield(amt);
        ledger_cms.push(s.commitment);
        ledger_cts.push((s.commitment, s.ciphertext.clone()));
        // shield ix: [pool W, vault W, payer W S, system R]  data: [0x01, amt, cm]
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(pool_state.pubkey(), false),
                AccountMeta::new(vault, false),
                AccountMeta::new(alice_payer.pubkey(), true),
                AccountMeta::new_readonly(system_program_id(), false),
            ],
            data: s.ix_data.clone(),
        };
        let label = format!("shield#{}", i + 1);
        let sig = ctx.send(&[ix], &[&alice_payer], &label)?;
        shield_sigs.push((amt, sig));
        println!("  Alice shielded {:.6} SOL (note {})", sol(amt), i + 1);
    }
    println!();

    // =====================================================================
    // STEP 4b: Bob shields a small note (so he has 2 inputs to unshield later).
    // =====================================================================
    println!("---- STEP: Bob shields 1 note ----");
    let sb = bob.build_shield(bob_shield);
    ledger_cms.push(sb.commitment);
    ledger_cts.push((sb.commitment, sb.ciphertext.clone()));
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool_state.pubkey(), false),
            AccountMeta::new(vault, false),
            AccountMeta::new(bob_payer.pubkey(), true),
            AccountMeta::new_readonly(system_program_id(), false),
        ],
        data: sb.ix_data.clone(),
    };
    let sig_bob_shield = ctx.send(&[ix], &[&bob_payer], "shield-bob")?;
    println!("  Bob shielded {:.6} SOL", sol(bob_shield));
    println!();

    // Both wallets scan all shields so their local trees match the pool exactly.
    alice.scan(&ledger_cms, &ledger_cts);
    bob.scan(&ledger_cms, &ledger_cts);
    println!("  Alice shielded balance: {} lamports ({:.6} SOL)", alice.balance(), sol(alice.balance()));
    println!("  Bob   shielded balance: {} lamports ({:.6} SOL)", bob.balance(), sol(bob.balance()));

    let vault_after_shields = ctx.balance(&vault)?;
    println!("  vault balance after shields: {:.6} SOL", sol(vault_after_shields));
    println!();

    // =====================================================================
    // STEP 5: Alice -> Bob private transfer.
    // =====================================================================
    println!("---- STEP: Alice -> Bob private transfer ----");
    println!("  building transfer proof (k=15, depth=32) — this is the heavy step…");
    let bundle = alice
        .build_transfer(&bob_addr, transfer_amount, transfer_fee)
        .map_err(|e| anyhow!("build_transfer: {e}"))?;
    let art = &bundle.artifacts;
    println!("  proof built: vk={}B proof={}B n_pi={}", art.vk_bytes.len(), art.proof_bytes.len(), art.public_inputs.len());

    // Stage proof blob + Bob's encrypted note (and Alice's change ct) on-chain.
    let cts: Vec<Vec<u8>> = bundle.encrypted_outputs.iter().map(|(_, ct)| ct.clone()).collect();
    let blob = build_blob_with_notes(art, &cts);
    let region_start = proof_region_len(art);
    let blob_acct = stage_blob(&ctx, &blob)?;

    // nf PDAs (+ canonical bumps, passed in ix data so the program does ONE
    // create_program_address each instead of a 256-iteration search).
    let nf1_le = be_to_le(&h_be(&art.public_inputs[1]));
    let nf2_le = be_to_le(&h_be(&art.public_inputs[2]));
    let (nf1_key, nf1_bump) = nf_pda(&program_id, &nf1_le);
    let (nf2_key, nf2_bump) = nf_pda(&program_id, &nf2_le);

    // transfer ix: [pool W, blob R, nf1 W, nf2 W, payer W S, system R]
    // data: [0x02, nf1_bump, nf2_bump]
    let mut transfer_data = bundle.ix_data.clone(); // [0x02]
    transfer_data.push(nf1_bump);
    transfer_data.push(nf2_bump);
    let transfer_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool_state.pubkey(), false),
            AccountMeta::new_readonly(blob_acct.pubkey(), false),
            AccountMeta::new(nf1_key, false),
            AccountMeta::new(nf2_key, false),
            AccountMeta::new(alice_payer.pubkey(), true),
            AccountMeta::new_readonly(system_program_id(), false),
        ],
        data: transfer_data,
    };
    let _ = TAG_TRANSFER;
    let sig_transfer = ctx.send(
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(CU_LIMIT),
            ComputeBudgetInstruction::request_heap_frame(256 * 1024),
            transfer_ix,
        ],
        &[&alice_payer],
        "transfer",
    )?;
    let transfer_cu = ctx.cu_of(&sig_transfer)?;
    println!("  transfer on-chain CU = {transfer_cu:?}  (limit {CU_LIMIT})");
    println!("  nullifiers revealed (PDAs created): {nf1_key}, {nf2_key}");
    println!();

    // =====================================================================
    // STEP 5b: flush — insert the 2 queued output commitments on-chain.
    // =====================================================================
    println!("---- STEP: flush (insert outputs) ----");
    let flush_ix = Instruction {
        program_id,
        accounts: vec![AccountMeta::new(pool_state.pubkey(), false)],
        data: vec![TAG_FLUSH, 2u8],
    };
    let sig_flush = ctx.send(
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(CU_LIMIT),
            flush_ix,
        ],
        &[&ctx.funder],
        "flush",
    )?;
    let flush_cu = ctx.cu_of(&sig_flush)?;
    println!("  flush on-chain CU = {flush_cu:?}");
    println!();

    // =====================================================================
    // STEP 6: Bob SCANS devnet — fetch the blob account, read his ciphertext,
    //         decrypt, confirm his shielded balance.
    // =====================================================================
    println!("---- STEP: Bob scans devnet & decrypts ----");
    let onchain_blob = ctx.rpc.get_account_data(&blob_acct.pubkey())?;
    println!("  fetched blob account {} from devnet ({} bytes)", blob_acct.pubkey(), onchain_blob.len());
    let onchain_cts = parse_trailing_cts(&onchain_blob, region_start);
    println!("  recovered {} ciphertext(s) from on-chain blob", onchain_cts.len());

    // The pool inserts queued outputs FIFO: output 0 = Bob's payment, output 1 =
    // Alice's change. Their commitments are bundle.encrypted_outputs[*].0.
    let out_cms: Vec<ark_bn254::Fr> = bundle.encrypted_outputs.iter().map(|(c, _)| *c).collect();
    let out_cts: Vec<(ark_bn254::Fr, Vec<u8>)> = out_cms
        .iter()
        .zip(onchain_cts.iter())
        .map(|(c, ct)| (*c, ct.clone()))
        .collect();

    let bob_before_scan = bob.balance();
    bob.scan(&out_cms, &out_cts);
    let bob_after_scan = bob.balance();
    let received = bob_after_scan - bob_before_scan;
    println!("  Bob balance before scanning transfer outputs: {} lamports", bob_before_scan);
    println!("  Bob balance after  scanning transfer outputs: {} lamports", bob_after_scan);
    if received == transfer_amount {
        println!("  ✓ Bob DECRYPTED his on-chain note: received {:.6} SOL privately", sol(received));
    } else {
        return Err(anyhow!(
            "Bob did not recover the expected payment: got {received}, expected {transfer_amount}"
        ));
    }
    // Alice also scans (to track her change note + keep tree in sync).
    alice.scan(&out_cms, &out_cts);
    println!("  Alice shielded balance after transfer (change): {} lamports", alice.balance());
    println!();

    // =====================================================================
    // STEP 7: Bob unshields (his shield note + Alice's payment note) -> PUBLIC.
    // =====================================================================
    println!("---- STEP: Bob unshields to a PUBLIC address ----");
    println!("  Bob now holds {} note(s), balance {} lamports", bob.note_count(), bob.balance());
    println!("  building unshield proof (k=15, depth=32) — heavy step…");
    let bob_public_pk = bob_public.pubkey();
    let ub = bob
        .build_unshield(unshield_amount, unshield_fee, bob_public_pk.to_bytes())
        .map_err(|e| anyhow!("build_unshield: {e}"))?;
    let uart = &ub.artifacts;

    // Stage unshield blob (change ciphertext to Bob appended for completeness).
    let ucts: Vec<Vec<u8>> = ub
        .encrypted_change
        .iter()
        .map(|(_, ct)| ct.clone())
        .collect();
    let ublob = build_blob_with_notes(uart, &ucts);
    let ublob_acct = stage_blob(&ctx, &ublob)?;

    let unf1_le = be_to_le(&h_be(&uart.public_inputs[1]));
    let unf2_le = be_to_le(&h_be(&uart.public_inputs[2]));
    let (unf1_key, unf1_bump) = nf_pda(&program_id, &unf1_le);
    let (unf2_key, unf2_bump) = nf_pda(&program_id, &unf2_le);

    let bob_public_before = ctx.balance(&bob_public_pk).unwrap_or(0);
    let vault_before_unshield = ctx.balance(&vault)?;

    // unshield ix: [pool W, blob R, vault W, recipient W, nf1 W, nf2 W, payer W S, system R]
    // data: [0x04, amount u64 LE, nf1_bump, nf2_bump]
    let mut unshield_data = ub.ix_data.clone(); // [0x04, amount u64 LE]
    unshield_data.push(unf1_bump);
    unshield_data.push(unf2_bump);
    let unshield_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool_state.pubkey(), false),
            AccountMeta::new_readonly(ublob_acct.pubkey(), false),
            AccountMeta::new(vault, false),
            AccountMeta::new(bob_public_pk, false),
            AccountMeta::new(unf1_key, false),
            AccountMeta::new(unf2_key, false),
            AccountMeta::new(bob_payer.pubkey(), true),
            AccountMeta::new_readonly(system_program_id(), false),
        ],
        data: unshield_data,
    };
    let sig_unshield = ctx.send(
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(CU_LIMIT),
            ComputeBudgetInstruction::request_heap_frame(256 * 1024),
            unshield_ix,
        ],
        &[&bob_payer],
        "unshield",
    )?;
    let unshield_cu = ctx.cu_of(&sig_unshield)?;
    let bob_public_after = ctx.balance(&bob_public_pk)?;
    let vault_after_unshield = ctx.balance(&vault)?;
    println!("  unshield on-chain CU = {unshield_cu:?}  (limit {CU_LIMIT})");
    println!("  Bob PUBLIC address {bob_public_pk}");
    println!("  Bob PUBLIC balance: {:.6} -> {:.6} SOL", sol(bob_public_before), sol(bob_public_after));
    println!("  vault balance: {:.6} -> {:.6} SOL", sol(vault_before_unshield), sol(vault_after_unshield));
    println!();

    // =====================================================================
    // FINAL REPORT
    // =====================================================================
    println!("================ STAGE 4 — FINAL REPORT ================");
    println!("pool program id   : {program_id}");
    println!("verifier (loader) : {}", verifier_loader_id()?);
    println!();
    println!("-- signatures (in order) --");
    println!("fund-Alice : {}\n             {}", sig_fund_alice, explorer(&sig_fund_alice));
    println!("fund-Bob   : {}\n             {}", sig_fund_bob, explorer(&sig_fund_bob));
    println!("init       : {}\n             {}", sig_init, explorer(&sig_init));
    for (amt, sig) in &shield_sigs {
        println!("shield {:.3}: {}\n             {}", sol(*amt), sig, explorer(sig));
    }
    println!("shield-bob : {}\n             {}", sig_bob_shield, explorer(&sig_bob_shield));
    println!("transfer   : {}\n             {}", sig_transfer, explorer(&sig_transfer));
    println!("flush      : {}\n             {}", sig_flush, explorer(&sig_flush));
    println!("unshield   : {}\n             {}", sig_unshield, explorer(&sig_unshield));
    println!();
    println!("-- compute units (confirmed tx meta) --");
    println!("transfer CU : {transfer_cu:?}  (under {CU_LIMIT}: {})", transfer_cu.map(|c| c < CU_LIMIT as u64).unwrap_or(false));
    println!("unshield CU : {unshield_cu:?}  (under {CU_LIMIT}: {})", unshield_cu.map(|c| c < CU_LIMIT as u64).unwrap_or(false));
    println!("flush    CU : {flush_cu:?}");
    println!();
    println!("-- value movement (real lamports) --");
    println!("Alice fee-payer : {:.6} -> {:.6} SOL", sol(alice_sol_before), sol(ctx.balance(&alice_payer.pubkey())?));
    println!("Alice shielded 0.10 SOL into the pool; 0.09 SOL delivered privately to Bob.");
    println!("vault after shields  : {:.6} SOL", sol(vault_after_shields));
    println!("vault after unshield : {:.6} SOL", sol(vault_after_unshield));
    println!("Bob PUBLIC withdrawal: {:.6} SOL landed at {}", sol(bob_public_after - bob_public_before), bob_public_pk);
    println!();
    println!("-- private delivery --");
    println!("Bob scanned devnet (blob account {}), decrypted his note, recovered {:.6} SOL.", blob_acct.pubkey(), sol(received));
    println!();
    println!("-- WHAT'S PUBLIC vs HIDDEN --");
    println!("PUBLIC (on-chain, anyone can read):");
    println!("  * shield amounts: Alice 0.06 + 0.04, Bob 0.005 SOL (the shield ix carries `amount`).");
    println!("  * unshield amount: {:.6} SOL to {} (the unshield ix carries `amount`).", sol(unshield_amount), bob_public_pk);
    println!("  * the two revealed nullifiers per spend (nf PDAs), the output commitments, the");
    println!("    Merkle root, and the full proof bytes (in the staged blob account).");
    println!("HIDDEN (at the protocol level, inside the TRANSFER tx):");
    println!("  * the transferred VALUE (0.09 SOL never appears; pub_amount only leaks the fee).");
    println!("  * the Alice->Bob LINK: the transfer reveals no sender/recipient identity, no");
    println!("    amount, and the output commitments are unlinkable to the input nullifiers.");
    println!("HONEST CAVEAT:");
    println!("  * Anonymity set = 2 (only Alice & Bob). The PUBLIC shield (0.10 in) and PUBLIC");
    println!("    unshield (~0.095 out) can still be correlated by amount + timing, which links");
    println!("    them statistically. This demo shows the CRYPTOGRAPHIC mechanism (the transfer");
    println!("    leaks no value/link on-chain), NOT strong statistical privacy.");
    println!("  * Test SRS: the prover sets up a fresh KZG SRS per run (no trusted ceremony).");
    println!("=======================================================");

    Ok(())
}
