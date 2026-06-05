//! Pinocchio BPF entrypoint: account wiring for the pool instructions.
//!
//! Account orderings (W = writable, S = signer, R = readonly):
//!   initialize: [pool_state W, vault R]                         data: [0x00, bump]
//!   shield:     [pool_state W, vault W, payer W S, system R]    data: [0x01, amount u64 LE, cm[32]]
//!   transfer:   [pool_state W, blob R, nf1 W, nf2 W]            data: [0x02]
//!   flush:      [pool_state W]                                  data: [0x03, max u8]
//!   unshield:   [pool_state W, blob R, vault W, recipient W, nf1 W, nf2 W]
//!                                                               data: [0x04, amount u64 LE]
//!
//! Nullifiers: each `nf` is a program-owned PDA `["nf", nf_le]`; data[0]==1 means
//! spent. The program verifies the passed account's address == the derived PDA,
//! then sets data[0]=1 (double-spend → already 1 → reject).

use pinocchio::{
    account::AccountView, address::Address, entrypoint, error::ProgramError, ProgramResult,
};

use crate::state::{empty_roots, Pool};
use crate::{apply_flush, be_to_le, parse_blob, run_verify, tag, verr};

entrypoint!(process_instruction);

#[cfg(all(target_os = "solana", feature = "cu-trace"))]
fn cu(label: &str) {
    #[allow(unsafe_code)]
    unsafe {
        pinocchio::syscalls::sol_log_(label.as_ptr(), label.len() as u64);
        pinocchio::syscalls::sol_log_compute_units_();
    }
}
#[cfg(not(all(target_os = "solana", feature = "cu-trace")))]
fn cu(_label: &str) {}

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (&t, rest) = data.split_first().ok_or(ProgramError::Custom(verr::MALFORMED))?;
    match t {
        tag::INITIALIZE => initialize(accounts, rest),
        tag::SHIELD => shield(accounts, rest),
        tag::TRANSFER => transfer(program_id, accounts, rest),
        tag::FLUSH => flush(accounts, rest),
        tag::UNSHIELD => unshield(program_id, accounts, rest),
        _ => Err(ProgramError::Custom(verr::UNKNOWN_TAG)),
    }
}

#[inline(never)]
fn initialize(accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    if accounts.is_empty() || rest.is_empty() {
        return Err(ProgramError::Custom(verr::MALFORMED));
    }
    let bump = rest[0];
    #[allow(unsafe_code)]
    let ps = unsafe { accounts[0].borrow_unchecked_mut() };
    Pool::initialize(ps, bump).map_err(ProgramError::Custom)?;
    Ok(())
}

#[inline(never)]
fn shield(accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    // data: amount u64 LE | cm[32]
    if rest.len() < 8 + 32 || accounts.len() < 4 {
        return Err(ProgramError::Custom(verr::MALFORMED));
    }
    let amount = u64::from_le_bytes(rest[0..8].try_into().unwrap());
    let mut cm = [0u8; 32];
    cm.copy_from_slice(&rest[8..40]);

    cu("[pool] shield enter");

    // 1. Move lamports payer -> vault via System transfer CPI.
    //    accounts: [pool W, vault W, payer W S, system R]
    transfer_lamports_cpi(&accounts[2], &accounts[1], amount)?;
    cu("[pool] after fund");

    // 2. Incremental insert.
    let empty = empty_roots().map_err(ProgramError::Custom)?;
    #[allow(unsafe_code)]
    let ps = unsafe { accounts[0].borrow_unchecked_mut() };
    let mut pool = Pool::load(ps).map_err(ProgramError::Custom)?;
    pool.insert(&cm, &empty).map_err(ProgramError::Custom)?;
    cu("[pool] after insert");
    Ok(())
}

#[inline(never)]
fn transfer(program_id: &Address, accounts: &mut [AccountView], _rest: &[u8]) -> ProgramResult {
    // accounts: [pool W, blob R, nf1 W, nf2 W]
    if accounts.len() < 4 {
        return Err(ProgramError::Custom(verr::MALFORMED));
    }
    cu("[pool] transfer enter");

    // 1. Parse blob + verify proof.
    #[allow(unsafe_code)]
    let blob = unsafe { accounts[1].borrow_unchecked() };
    let bundle = parse_blob(blob).map_err(ProgramError::Custom)?;
    if bundle.public_inputs_be.len() != 6 {
        return Err(ProgramError::Custom(verr::MALFORMED));
    }
    cu("[pool] after parse");

    run_verify(&bundle).map_err(ProgramError::Custom)?;
    cu("[pool] after verify");

    // public inputs: [root, nf1, nf2, cmout1, cmout2, pub_amount] (BE)
    let root_le = be_to_le(&bundle.public_inputs_be[0]);
    let nf1_le = be_to_le(&bundle.public_inputs_be[1]);
    let nf2_le = be_to_le(&bundle.public_inputs_be[2]);
    let cmout1_le = be_to_le(&bundle.public_inputs_be[3]);
    let cmout2_le = be_to_le(&bundle.public_inputs_be[4]);

    // 2. root ∈ history + 4. queue outputs (single pool borrow).
    {
        #[allow(unsafe_code)]
        let ps = unsafe { accounts[0].borrow_unchecked_mut() };
        let mut pool = Pool::load(ps).map_err(ProgramError::Custom)?;
        if !pool.root_known(&root_le) {
            return Err(ProgramError::Custom(verr::ROOT_UNKNOWN));
        }
        pool.queue_push(&cmout1_le).map_err(ProgramError::Custom)?;
        pool.queue_push(&cmout2_le).map_err(ProgramError::Custom)?;
    }

    // 3. mark nullifiers spent (double-spend → reject).
    spend_nullifier(program_id, &mut accounts[2], &nf1_le)?;
    spend_nullifier(program_id, &mut accounts[3], &nf2_le)?;
    cu("[pool] after nullifiers");
    Ok(())
}

#[inline(never)]
fn flush(accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    if accounts.is_empty() {
        return Err(ProgramError::Custom(verr::MALFORMED));
    }
    let max = if rest.is_empty() { 2usize } else { rest[0] as usize };
    cu("[pool] flush enter");
    #[allow(unsafe_code)]
    let ps = unsafe { accounts[0].borrow_unchecked_mut() };
    apply_flush(ps, max).map_err(ProgramError::Custom)?;
    cu("[pool] after flush");
    Ok(())
}

#[inline(never)]
fn unshield(program_id: &Address, accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    // accounts: [pool W, blob R, vault W, recipient W, nf1 W, nf2 W]
    // data: amount u64 LE
    if accounts.len() < 6 || rest.len() < 8 {
        return Err(ProgramError::Custom(verr::MALFORMED));
    }
    let amount = u64::from_le_bytes(rest[0..8].try_into().unwrap());
    cu("[pool] unshield enter");

    #[allow(unsafe_code)]
    let blob = unsafe { accounts[1].borrow_unchecked() };
    let bundle = parse_blob(blob).map_err(ProgramError::Custom)?;
    if bundle.public_inputs_be.len() != 6 {
        return Err(ProgramError::Custom(verr::MALFORMED));
    }
    run_verify(&bundle).map_err(ProgramError::Custom)?;
    cu("[pool] after verify");

    let root_le = be_to_le(&bundle.public_inputs_be[0]);
    let nf1_le = be_to_le(&bundle.public_inputs_be[1]);
    let nf2_le = be_to_le(&bundle.public_inputs_be[2]);
    let cmout1_le = be_to_le(&bundle.public_inputs_be[3]);

    {
        #[allow(unsafe_code)]
        let ps = unsafe { accounts[0].borrow_unchecked_mut() };
        let mut pool = Pool::load(ps).map_err(ProgramError::Custom)?;
        if !pool.root_known(&root_le) {
            return Err(ProgramError::Custom(verr::ROOT_UNKNOWN));
        }
        pool.queue_push(&cmout1_le).map_err(ProgramError::Custom)?;
    }

    spend_nullifier(program_id, &mut accounts[4], &nf1_le)?;
    spend_nullifier(program_id, &mut accounts[5], &nf2_le)?;

    // pay vault -> recipient (both writable; vault program-owned → direct move).
    // Disjoint mutable borrows via split_at_mut (vault=idx2, recipient=idx3).
    let (left, right) = accounts.split_at_mut(3);
    let vault = &mut left[2];
    let recipient = &mut right[0];
    pay_from_vault(vault, recipient, amount)?;
    cu("[pool] after payout");
    Ok(())
}

// ---- nullifier PDA --------------------------------------------------------

fn spend_nullifier(
    program_id: &Address,
    nf_acct: &mut AccountView,
    nf_le: &[u8; 32],
) -> ProgramResult {
    // Verify the passed account is the program-derived nullifier PDA.
    if !nf_acct.owned_by(program_id) {
        return Err(ProgramError::Custom(verr::BAD_NF_PDA));
    }
    let mut matched = false;
    let mut bump_buf = [0u8; 1];
    for b in (0u8..=255).rev() {
        bump_buf[0] = b;
        let seeds: [&[u8]; 3] = [b"nf", nf_le.as_slice(), &bump_buf];
        if let Ok(pda) = Address::create_program_address(&seeds, program_id) {
            if &pda == nf_acct.address() {
                matched = true;
                break;
            }
        }
    }
    if !matched {
        return Err(ProgramError::Custom(verr::BAD_NF_PDA));
    }

    #[allow(unsafe_code)]
    let buf = unsafe { nf_acct.borrow_unchecked_mut() };
    if buf.is_empty() {
        return Err(ProgramError::Custom(verr::BAD_NF_PDA));
    }
    if buf[0] != 0 {
        return Err(ProgramError::Custom(verr::DOUBLE_SPEND));
    }
    buf[0] = 1;
    Ok(())
}

// ---- lamport movement -----------------------------------------------------

/// Move `amount` lamports from a program-owned `vault` to `recipient` by direct
/// field manipulation (allowed: program owns the vault).
fn pay_from_vault(
    vault: &mut AccountView,
    recipient: &mut AccountView,
    amount: u64,
) -> ProgramResult {
    let vl = vault.lamports();
    if vl < amount {
        return Err(ProgramError::Custom(verr::INSUFFICIENT_VAULT));
    }
    vault.set_lamports(vl - amount);
    recipient.set_lamports(recipient.lamports() + amount);
    Ok(())
}

/// Transfer `amount` lamports from `payer` (system-owned, signer) to `vault` via
/// a System program CPI.
#[cfg(feature = "cpi")]
fn transfer_lamports_cpi(payer: &AccountView, vault: &AccountView, amount: u64) -> ProgramResult {
    use pinocchio::instruction::{cpi::invoke, InstructionAccount, InstructionView};

    // System program transfer: instruction discriminator 2 (u32 LE) | amount u64 LE.
    let mut ix_data = [0u8; 12];
    ix_data[0..4].copy_from_slice(&2u32.to_le_bytes());
    ix_data[4..12].copy_from_slice(&amount.to_le_bytes());

    let system_id = Address::new_from_array([0u8; 32]);
    let metas = [
        InstructionAccount::new(payer.address(), true, true),
        InstructionAccount::new(vault.address(), true, false),
    ];
    let ix = InstructionView {
        program_id: &system_id,
        accounts: &metas,
        data: &ix_data,
    };
    invoke::<2, AccountView>(&ix, &[payer.clone(), vault.clone()])
}

#[cfg(not(feature = "cpi"))]
fn transfer_lamports_cpi(_payer: &AccountView, _vault: &AccountView, _amount: u64) -> ProgramResult {
    Ok(())
}
