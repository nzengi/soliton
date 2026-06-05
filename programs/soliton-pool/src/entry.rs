//! Pinocchio BPF entrypoint: account wiring for the pool instructions.
//!
//! Account orderings (W = writable, S = signer, R = readonly):
//!   initialize: [pool_state W, vault R]                         data: [0x00, bump]
//!   shield:     [pool_state W, vault W, payer W S, system R]    data: [0x01, amount u64 LE, cm[32]]
//!   transfer:   [pool_state W, blob R, nf1 W, nf2 W, payer W S, system R]
//!                                                               data: [0x02]
//!   flush:      [pool_state W]                                  data: [0x03, max u8]
//!   unshield:   [pool_state W, blob R, vault W, recipient W, nf1 W, nf2 W, payer W S, system R]
//!                                                               data: [0x04, amount u64 LE]
//!
//! Nullifiers: each `nf` is a program-owned PDA `["nf", nf_le]`; data[0]==1 means
//! spent. On the FIRST spend the PDA does not exist yet, so the program
//! CPI-creates it (System CreateAccount, signed with the PDA seeds, funded by
//! `payer`) with 1 byte of data, then sets data[0]=1. A second spend finds the
//! PDA already program-owned with data[0]==1 → DOUBLE_SPEND reject.

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
fn transfer(program_id: &Address, accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    // accounts: [pool W, blob R, nf1 W, nf2 W, payer W S, system R]
    // data rest: [nf1_bump u8, nf2_bump u8] — the canonical PDA bumps, supplied by
    // the client so the program needs ONE create_program_address per nullifier
    // (a full 0..=255 search would cost ~hundreds of K CU and blow the budget).
    if accounts.len() < 6 || rest.len() < 2 {
        return Err(ProgramError::Custom(verr::MALFORMED));
    }
    let nf1_bump = rest[0];
    let nf2_bump = rest[1];
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

    // 3. mark nullifiers spent (create-if-absent; double-spend → reject).
    //    accounts: [pool, blob, nf1(2), nf2(3), payer(4), system(5)]
    {
        let (left, right) = accounts.split_at_mut(4);
        let nf1 = &mut left[2];
        let payer = &right[0];
        let system = &right[1];
        spend_nullifier(program_id, nf1, payer, system, &nf1_le, nf1_bump)?;
    }
    {
        let (left, right) = accounts.split_at_mut(4);
        let nf2 = &mut left[3];
        let payer = &right[0];
        let system = &right[1];
        spend_nullifier(program_id, nf2, payer, system, &nf2_le, nf2_bump)?;
    }
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
    // accounts: [pool W, blob R, vault W, recipient W, nf1 W, nf2 W, payer W S, system R]
    // data: [amount u64 LE, nf1_bump u8, nf2_bump u8]
    if accounts.len() < 8 || rest.len() < 10 {
        return Err(ProgramError::Custom(verr::MALFORMED));
    }
    let amount = u64::from_le_bytes(rest[0..8].try_into().unwrap());
    let nf1_bump = rest[8];
    let nf2_bump = rest[9];
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

    // accounts: [pool, blob, vault(2), recipient(3), nf1(4), nf2(5), payer(6), system(7)]
    {
        let (left, right) = accounts.split_at_mut(6);
        let nf1 = &mut left[4];
        let payer = &right[0];
        let system = &right[1];
        spend_nullifier(program_id, nf1, payer, system, &nf1_le, nf1_bump)?;
    }
    {
        let (left, right) = accounts.split_at_mut(6);
        let nf2 = &mut left[5];
        let payer = &right[0];
        let system = &right[1];
        spend_nullifier(program_id, nf2, payer, system, &nf2_le, nf2_bump)?;
    }

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
    payer: &AccountView,
    system: &AccountView,
    nf_le: &[u8; 32],
    bump: u8,
) -> ProgramResult {
    // 1. Confirm the passed account address is the program-derived nullifier PDA
    //    ["nf", nf_le, bump] — exactly ONE create_program_address (the client
    //    supplies the canonical bump, so no 0..=255 search is needed).
    let bump_buf = [bump];
    let seeds: [&[u8]; 3] = [b"nf", nf_le.as_slice(), &bump_buf];
    let derived = Address::create_program_address(&seeds, program_id)
        .map_err(|_| ProgramError::Custom(verr::BAD_NF_PDA))?;
    if &derived != nf_acct.address() {
        return Err(ProgramError::Custom(verr::BAD_NF_PDA));
    }

    // 2. If the PDA is not yet program-owned, it has never been spent: create it
    //    (System CreateAccount, signed with the PDA seeds), funded by `payer`.
    if !nf_acct.owned_by(program_id) {
        create_nullifier_pda(program_id, nf_acct, payer, system, nf_le, bump)?;
        // Freshly created: data is 1 byte of zero. Mark spent.
        #[allow(unsafe_code)]
        let buf = unsafe { nf_acct.borrow_unchecked_mut() };
        if buf.is_empty() {
            return Err(ProgramError::Custom(verr::BAD_NF_PDA));
        }
        buf[0] = 1;
        return Ok(());
    }

    // 3. Already program-owned: data[0]==1 means previously spent → reject.
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

/// CPI-create the nullifier PDA via System CreateAccount, signed with the PDA
/// seeds. 1 byte of data, rent-exempt, owner = this program.
#[cfg(feature = "cpi")]
#[inline(never)]
fn create_nullifier_pda(
    program_id: &Address,
    nf_acct: &AccountView,
    payer: &AccountView,
    system: &AccountView,
    nf_le: &[u8; 32],
    bump: u8,
) -> ProgramResult {
    use pinocchio::instruction::{
        cpi::{invoke_signed, Seed, Signer},
        InstructionAccount, InstructionView,
    };

    const SPACE: u64 = 1;
    // Rent-exempt minimum for a 1-byte account. Devnet/mainnet rent: the
    // lamports-per-byte-year * 2 (2-year exemption) over (128 header + space).
    // 0.00089088 SOL = 890_880 lamports covers a 1-byte account with margin.
    const LAMPORTS: u64 = 1_000_000;

    // System CreateAccount: discriminator 0 (u32 LE) | lamports u64 | space u64 | owner[32]
    let mut ix_data = [0u8; 4 + 8 + 8 + 32];
    ix_data[0..4].copy_from_slice(&0u32.to_le_bytes());
    ix_data[4..12].copy_from_slice(&LAMPORTS.to_le_bytes());
    ix_data[12..20].copy_from_slice(&SPACE.to_le_bytes());
    ix_data[20..52].copy_from_slice(program_id.as_ref());

    let system_id = Address::new_from_array([0u8; 32]);
    let metas = [
        InstructionAccount::new(payer.address(), true, true),
        InstructionAccount::new(nf_acct.address(), true, true),
    ];
    let ix = InstructionView {
        program_id: &system_id,
        accounts: &metas,
        data: &ix_data,
    };

    let bump_arr = [bump];
    let seeds = [
        Seed::from(b"nf".as_slice()),
        Seed::from(nf_le.as_slice()),
        Seed::from(bump_arr.as_slice()),
    ];
    let signer = Signer::from(&seeds);

    let _ = system;
    invoke_signed::<2, AccountView>(&ix, &[payer.clone(), nf_acct.clone()], &[signer])
}

#[cfg(not(feature = "cpi"))]
fn create_nullifier_pda(
    _program_id: &Address,
    _nf_acct: &AccountView,
    _payer: &AccountView,
    _system: &AccountView,
    _nf_le: &[u8; 32],
    _bump: u8,
) -> ProgramResult {
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
