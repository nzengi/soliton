//! Mollusk pool integration.
//!
//! The SDK builds a shield then a transfer; we submit them to the
//! `soliton-pool` program on the real SBF VM (Mollusk) and assert:
//!   (a) the pool ACCEPTS the SDK-built shields (insert) and transfer (verify +
//!       nullify + queue),
//!   (b) flush inserts the queued outputs,
//!   (c) the SDK's locally-computed root == the pool's on-chain PoolState.root,
//!       BYTE-FOR-BYTE, at each step.
//!
//! Build the program first:
//!   cargo build-sbf --manifest-path programs/soliton-pool/Cargo.toml -- \
//!       --features bpf-entrypoint
//!   SBF_OUT_DIR=$(pwd)/target/deploy cargo test -p soliton-sdk --test mollusk_gate4 \
//!       -- --nocapture

use ark_bn254::Fr;
use halo2curves::bn256::Fr as HFr;
use halo2curves::ff::PrimeField;

use mollusk_svm::{result::ProgramResult, Mollusk};
use solana_account::Account;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    rent::Rent,
};

use soliton_pool::state::{Pool, OFF_ROOT, POOL_STATE_LEN};
use soliton_pool::tag;

use soliton_sdk::Wallet;

const PROGRAM_NAME: &str = "soliton_pool";

fn fr_to_le_be(f: &Fr) -> [u8; 32] {
    soliton_poseidon::fr_to_le(f)
}
fn h_be(f: &HFr) -> [u8; 32] {
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

fn new_mollusk(program_id: &Pubkey) -> Mollusk {
    let mut m = Mollusk::new(program_id, PROGRAM_NAME);
    m.compute_budget.compute_unit_limit = 1_000_000_000;
    m.compute_budget.heap_size = 256 * 1024;
    m
}
fn rent_for(len: usize) -> u64 {
    Rent::default().minimum_balance(len)
}
fn init_pool_data() -> Vec<u8> {
    let mut data = vec![0u8; POOL_STATE_LEN];
    Pool::initialize(&mut data, 255).expect("init");
    data
}
fn nf_pda(program_id: &Pubkey, nf_le: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"nf", nf_le], program_id)
}
fn build_blob(art: &soliton_pay::prover::KeccakArtifacts) -> Vec<u8> {
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
    buf
}

fn pool_root(data: &[u8]) -> [u8; 32] {
    data[OFF_ROOT..OFF_ROOT + 32].try_into().unwrap()
}

#[test]
fn sdk_shield_transfer_pool_compatible() {
    let program_id = Pubkey::new_unique();
    let mollusk = new_mollusk(&program_id);

    let pool_key = Pubkey::new_unique();
    let vault_key = Pubkey::new_unique();
    let payer_key = Pubkey::new_unique();
    let (system_key, system_acct) = mollusk_svm::program::keyed_account_for_system_program();

    let mut pool_data = init_pool_data();

    // Pool's initial empty root must equal the SDK's fresh local-tree root.
    let mut alice = Wallet::from_seed(11);
    let bob_addr = Wallet::from_seed(22).address();
    assert_eq!(
        pool_root(&pool_data),
        fr_to_le_be(&alice.root()),
        "[FAIL] initial pool root != SDK empty root"
    );
    println!("[PASS] initial pool root == SDK empty root (byte-equal)");

    // --- 1. SDK builds two shields; submit each to the pool ---
    let mut ledger_cms: Vec<Fr> = Vec::new();
    let mut ledger_cts = Vec::new();
    let shields = [60u64, 90u64];
    for (i, amt) in shields.iter().enumerate() {
        let s = alice.build_shield(*amt);
        ledger_cms.push(s.commitment);
        ledger_cts.push((s.commitment, s.ciphertext));

        // Submit the SDK's shield ix_data to the pool.
        let accts = vec![
            (pool_key, Account { lamports: rent_for(POOL_STATE_LEN), data: pool_data.clone(), owner: program_id, executable: false, rent_epoch: 0 }),
            (vault_key, Account { lamports: rent_for(0), data: vec![], owner: program_id, executable: false, rent_epoch: 0 }),
            (payer_key, Account { lamports: 10_000_000_000, data: vec![], owner: system_key, executable: false, rent_epoch: 0 }),
            (system_key, system_acct.clone()),
        ];
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(pool_key, false),
                AccountMeta::new(vault_key, false),
                AccountMeta::new(payer_key, true),
                AccountMeta::new_readonly(system_key, false),
            ],
            data: s.ix_data.clone(),
        };
        let res = mollusk.process_instruction(&ix, &accts);
        assert!(matches!(res.program_result, ProgramResult::Success), "shield #{i} rejected: {:?}", res.program_result);
        pool_data = res.get_account(&pool_key).unwrap().data.clone();
        println!("shield #{i} accepted (amount={amt}, cu={})", res.compute_units_consumed);
    }

    // SDK scans both shields -> local tree gets the same 2 inserts.
    alice.scan(&ledger_cms, &ledger_cts);
    assert_eq!(alice.balance(), 150);

    // After the 2 shields, SDK root == pool root.
    assert_eq!(
        pool_root(&pool_data),
        fr_to_le_be(&alice.root()),
        "[FAIL] after shields, pool root != SDK root"
    );
    println!("[PASS] after 2 shields: pool root == SDK local root (byte-equal)");

    // --- 2. SDK builds a transfer (Alice -> Bob 140, fee 10) ---
    let bundle = alice.build_transfer(&bob_addr, 140, 10).expect("build_transfer");
    let art = &bundle.artifacts;

    // The proof root must equal the pool's current root (∈ history).
    let proof_root_le = be_to_le(&h_be(&art.public_inputs[0]));
    assert_eq!(proof_root_le, pool_root(&pool_data), "[FAIL] proof root != pool root");
    println!("[PASS] SDK transfer proof root == pool current root");

    // Submit transfer to the pool.
    // accounts: [pool W, blob R, nf1 W, nf2 W, payer W S, system R].
    // The SDK leaves payer/system/bumps to the caller (proof/VK travel in the
    // staged blob); we wire them here exactly as the devnet demo does.
    let blob = build_blob(art);
    let blob_key = Pubkey::new_unique();
    let nf1_le = be_to_le(&h_be(&art.public_inputs[1]));
    let nf2_le = be_to_le(&h_be(&art.public_inputs[2]));
    let (nf1_key, nf1_bump) = nf_pda(&program_id, &nf1_le);
    let (nf2_key, nf2_bump) = nf_pda(&program_id, &nf2_le);

    let accts = vec![
        (pool_key, Account { lamports: rent_for(POOL_STATE_LEN), data: pool_data.clone(), owner: program_id, executable: false, rent_epoch: 0 }),
        (blob_key, Account { lamports: rent_for(blob.len()), data: blob.clone(), owner: program_id, executable: false, rent_epoch: 0 }),
        // First spend: PDAs do not exist yet (System-owned, empty); the program
        // CPI-creates them, funded by `payer`.
        (nf1_key, Account { lamports: 0, data: vec![], owner: system_key, executable: false, rent_epoch: 0 }),
        (nf2_key, Account { lamports: 0, data: vec![], owner: system_key, executable: false, rent_epoch: 0 }),
        (payer_key, Account { lamports: 10_000_000_000, data: vec![], owner: system_key, executable: false, rent_epoch: 0 }),
        (system_key, system_acct.clone()),
    ];
    // data: [tag::TRANSFER, nf1_bump, nf2_bump]
    let mut transfer_data = bundle.ix_data.clone();
    transfer_data.push(nf1_bump);
    transfer_data.push(nf2_bump);
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool_key, false),
            AccountMeta::new_readonly(blob_key, false),
            AccountMeta::new(nf1_key, false),
            AccountMeta::new(nf2_key, false),
            AccountMeta::new(payer_key, true),
            AccountMeta::new_readonly(system_key, false),
        ],
        data: transfer_data,
    };
    let res = mollusk.process_instruction(&ix, &accts);
    assert!(matches!(res.program_result, ProgramResult::Success), "[FAIL] SDK transfer rejected by pool: {:?}", res.program_result);
    pool_data = res.get_account(&pool_key).unwrap().data.clone();
    println!("[PASS] pool ACCEPTED SDK transfer (verify+nullify+queue, cu={})", res.compute_units_consumed);

    // queue should hold the 2 outputs.
    let qlen = u32::from_le_bytes(
        pool_data[soliton_pool::state::OFF_QUEUE_LEN..soliton_pool::state::OFF_QUEUE_LEN + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(qlen, 2, "queue should hold 2 outputs");

    // --- 3. Flush the 2 queued outputs (pool inserts on-chain) ---
    // The pool queues outputs in instruction order: cmout1 (payment), cmout2
    // (change). The SDK's encrypted_outputs are in the SAME order.
    for _ in 0..2 {
        let accts = vec![(pool_key, Account { lamports: rent_for(POOL_STATE_LEN), data: pool_data.clone(), owner: program_id, executable: false, rent_epoch: 0 })];
        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(pool_key, false)],
            data: vec![tag::FLUSH, 1u8],
        };
        let res = mollusk.process_instruction(&ix, &accts);
        assert!(matches!(res.program_result, ProgramResult::Success), "flush rejected: {:?}", res.program_result);
        pool_data = res.get_account(&pool_key).unwrap().data.clone();
    }
    println!("flush: 2 outputs inserted on-chain");

    // SDK inserts the same 2 outputs into its local tree (FIFO order).
    let new_cms: Vec<Fr> = bundle.encrypted_outputs.iter().map(|(c, _)| *c).collect();
    let new_cts: Vec<(Fr, Vec<u8>)> = bundle.encrypted_outputs.clone();
    alice.scan(&new_cms, &new_cts);

    // Load-bearing: SDK local root == on-chain pool root, byte-for-byte.
    let pool_r = pool_root(&pool_data);
    let sdk_r = fr_to_le_be(&alice.root());
    println!("pool root : {}", hex32(&pool_r));
    println!("sdk  root : {}", hex32(&sdk_r));
    assert_eq!(pool_r, sdk_r, "[FAIL] SDK root != on-chain pool root after flush");
    println!("[PASS] SDK local root == on-chain pool root (BYTE-EQUAL)");
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
