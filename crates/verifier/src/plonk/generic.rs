//! Generic (AST-driven) PLONK verifier for arbitrary halo2 circuits, consuming
//! the v2 VK (`crate::vk_generic`). Reuses the existing SHPLONK + pairing skeleton.
//!
//! Implements the exact protocol order of `halo2_proofs::plonk::verifier::
//! verify_proof` for the single-proof, QUERY_INSTANCE=false, no-shuffle path:
//! advice → theta → lookup permuted → beta,gamma → perm product → lookup
//! product → vanishing random → y → vanishing h → x → advice evals → fixed
//! evals → vanishing random eval → perm common evals → perm product evals →
//! lookup evals → SHPLONK.
//!
//! Gate, permutation, and lookup identities are evaluated generically and folded
//! with `y` (Horner), matching halo2's `vanishing.verify` ordering.

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, Zero};

use crate::{
    curve::G1,
    field::{self, fr_to_bytes_be},
    kzg::{shplonk, shplonk::VerifierQuery, KzgVk},
    pairing,
    plonk::lagrange,
    transcript::Keccak256Transcript,
    vk_generic::{
        parse_vk_generic, GenericVk, OP_ADVICE, OP_CONST, OP_FIXED, OP_INSTANCE, OP_NEG,
        OP_PRODUCT, OP_SCALED, OP_SUM,
    },
    Error,
};

/// Internal CU stage-trace marker. No-op unless the `cu-trace` feature is on
/// AND we are compiling for the Solana BPF target (so host builds are unaffected
/// and the verifier's logic is never changed — these only emit syscall logs).
#[cfg(all(feature = "cu-trace", target_os = "solana"))]
#[inline(never)]
fn cu(label: &str) {
    solana_program::log::sol_log(label);
    solana_program::log::sol_log_compute_units();
}
#[cfg(not(all(feature = "cu-trace", target_os = "solana")))]
#[inline(always)]
fn cu(_label: &str) {}

/// Per-lookup proof data.
#[derive(Clone, Debug)]
struct LookupData {
    permuted_input_commit: G1,
    permuted_table_commit: G1,
    product_commit: G1,
    product_eval: Fr,
    product_next_eval: Fr,
    permuted_input_eval: Fr,
    permuted_input_inv_eval: Fr,
    permuted_table_eval: Fr,
}

struct GenericProof {
    advice_commits: Vec<G1>,
    permutation_product_commits: Vec<G1>,
    random_poly_commit: G1,
    vanishing_h_commits: Vec<G1>,
    advice_evals: Vec<Fr>,
    fixed_evals: Vec<Fr>,
    instance_evals: Vec<Fr>,
    random_poly_eval: Fr,
    permutation_common_evals: Vec<Fr>,
    permutation_product_evals: Vec<(Fr, Fr, Option<Fr>)>,
    lookups: Vec<LookupData>,
    opening_proof_w: G1,
    opening_proof_w_prime: G1,
}

struct GenericChallenges {
    theta: Fr,
    beta: Fr,
    gamma: Fr,
    y: Fr,
    x: Fr,
    shplonk_y: Fr,
    shplonk_v: Fr,
    shplonk_u: Fr,
}

// ===========================================================================
// Expression evaluation
// ===========================================================================

/// Evaluate a length-tagged expression blob at the given evals.
//
// `#[inline(never)]`: keep this (and its arkworks BigInt temporaries) in its own
// SBF stack frame so it is NOT inlined into `lookup_expressions`, whose frame
// would otherwise exceed the 4096-byte SBF stack cap.
#[inline(never)]
fn eval_expr(
    blob: &[u8],
    advice_evals: &[Fr],
    fixed_evals: &[Fr],
    instance_evals: &[Fr],
) -> Result<Fr, Error> {
    let mut pos = 0usize;
    let v = eval_node(blob, &mut pos, advice_evals, fixed_evals, instance_evals)?;
    if pos != blob.len() {
        return Err(Error::Protocol("eval_expr: trailing bytes in AST"));
    }
    Ok(v)
}

fn read_u32(blob: &[u8], pos: &mut usize) -> Result<u32, Error> {
    if *pos + 4 > blob.len() {
        return Err(Error::Protocol("AST: truncated u32"));
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&blob[*pos..*pos + 4]);
    *pos += 4;
    Ok(u32::from_le_bytes(b))
}

fn read_fr(blob: &[u8], pos: &mut usize) -> Result<Fr, Error> {
    if *pos + 32 > blob.len() {
        return Err(Error::Protocol("AST: truncated Fr"));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&blob[*pos..*pos + 32]);
    *pos += 32;
    field::fr_from_bytes_be(&b)
}

fn eval_node(
    blob: &[u8],
    pos: &mut usize,
    advice_evals: &[Fr],
    fixed_evals: &[Fr],
    instance_evals: &[Fr],
) -> Result<Fr, Error> {
    if *pos >= blob.len() {
        return Err(Error::Protocol("AST: truncated opcode"));
    }
    let op = blob[*pos];
    *pos += 1;
    match op {
        OP_CONST => read_fr(blob, pos),
        OP_FIXED => {
            let idx = read_u32(blob, pos)? as usize;
            fixed_evals
                .get(idx)
                .copied()
                .ok_or(Error::Protocol("AST: fixed idx OOB"))
        }
        OP_ADVICE => {
            let idx = read_u32(blob, pos)? as usize;
            advice_evals
                .get(idx)
                .copied()
                .ok_or(Error::Protocol("AST: advice idx OOB"))
        }
        OP_INSTANCE => {
            let idx = read_u32(blob, pos)? as usize;
            instance_evals
                .get(idx)
                .copied()
                .ok_or(Error::Protocol("AST: instance idx OOB"))
        }
        OP_NEG => {
            let a = eval_node(blob, pos, advice_evals, fixed_evals, instance_evals)?;
            Ok(-a)
        }
        OP_SUM => {
            let a = eval_node(blob, pos, advice_evals, fixed_evals, instance_evals)?;
            let b = eval_node(blob, pos, advice_evals, fixed_evals, instance_evals)?;
            Ok(a + b)
        }
        OP_PRODUCT => {
            let a = eval_node(blob, pos, advice_evals, fixed_evals, instance_evals)?;
            let b = eval_node(blob, pos, advice_evals, fixed_evals, instance_evals)?;
            Ok(a * b)
        }
        OP_SCALED => {
            let a = eval_node(blob, pos, advice_evals, fixed_evals, instance_evals)?;
            let c = read_fr(blob, pos)?;
            Ok(a * c)
        }
        _ => Err(Error::Protocol("AST: unknown opcode")),
    }
}

// ===========================================================================
// Proof reading (Fiat-Shamir, v2 protocol order)
// ===========================================================================

#[allow(clippy::too_many_arguments)]
fn read_proof(
    vk: &GenericVk,
    proof_bytes: &[u8],
    public_inputs: &[[u8; 32]],
    omega_inv: Fr,
    transcript: &mut Keccak256Transcript,
) -> Result<(GenericProof, GenericChallenges, Vec<Fr>), Error> {
    // absorb instances
    for inst in public_inputs {
        transcript.absorb_scalar(inst);
    }
    // Decode instance scalars for later Lagrange evaluation.
    let mut instance_values = Vec::with_capacity(public_inputs.len());
    for inst in public_inputs {
        instance_values.push(field::fr_from_bytes_be(inst)?);
    }

    let mut cur = 0usize;

    // (1) advice commits
    let advice_commits = read_g1s(transcript, proof_bytes, &mut cur, vk.num_advice)?;

    // theta
    let theta = transcript.squeeze_challenge();

    // (2) lookup permuted commits (input, table) per lookup
    let mut lk_permuted: Vec<(G1, G1)> = Vec::with_capacity(vk.lookups.len());
    for _ in 0..vk.lookups.len() {
        let inp = transcript.read_g1(proof_bytes, &mut cur)?;
        let tab = transcript.read_g1(proof_bytes, &mut cur)?;
        lk_permuted.push((inp, tab));
    }

    // beta, gamma
    let beta = transcript.squeeze_challenge();
    let gamma = transcript.squeeze_challenge();

    // (3) permutation product commits
    let permutation_product_commits =
        read_g1s(transcript, proof_bytes, &mut cur, vk.num_perm_chunks)?;

    // (4) lookup product commits
    let mut lk_product: Vec<G1> = Vec::with_capacity(vk.lookups.len());
    for _ in 0..vk.lookups.len() {
        lk_product.push(transcript.read_g1(proof_bytes, &mut cur)?);
    }

    // (5) vanishing random poly commit
    let random_poly_commit = transcript.read_g1(proof_bytes, &mut cur)?;

    // y
    let y = transcript.squeeze_challenge();

    // (6) vanishing h pieces
    let h_count = vk.cs_degree.saturating_sub(1);
    let vanishing_h_commits = read_g1s(transcript, proof_bytes, &mut cur, h_count)?;

    // x
    let x = transcript.squeeze_challenge();

    // NOTE: instance evals (QUERY_INSTANCE=false) are computed LATER, in
    // `verify_generic`, so their Lagrange denominators join the SINGLE global
    // batch inversion. They are not absorbed into the transcript, so deferring
    // them does not change any challenge. `proof.instance_evals` is left empty
    // here and filled before gate evaluation / query construction.
    let _ = omega_inv;

    // (7) advice evals, (8) fixed evals
    let advice_evals =
        read_scalars(transcript, proof_bytes, &mut cur, vk.num_advice_queries())?;
    let fixed_evals =
        read_scalars(transcript, proof_bytes, &mut cur, vk.num_fixed_queries())?;

    // (9) vanishing random poly eval
    let random_poly_eval = transcript.read_scalar(proof_bytes, &mut cur)?;

    // (10) permutation common evals
    let permutation_common_evals =
        read_scalars(transcript, proof_bytes, &mut cur, vk.num_perm_columns())?;

    // (11) permutation product evals
    let mut permutation_product_evals = Vec::with_capacity(vk.num_perm_chunks);
    for i in 0..vk.num_perm_chunks {
        let z = transcript.read_scalar(proof_bytes, &mut cur)?;
        let z_omega = transcript.read_scalar(proof_bytes, &mut cur)?;
        let z_last = if i + 1 < vk.num_perm_chunks {
            Some(transcript.read_scalar(proof_bytes, &mut cur)?)
        } else {
            None
        };
        permutation_product_evals.push((z, z_omega, z_last));
    }

    // (12) lookup evals: product, product_next, permuted_input, permuted_input_inv, permuted_table
    let mut lookups = Vec::with_capacity(vk.lookups.len());
    for i in 0..vk.lookups.len() {
        let product_eval = transcript.read_scalar(proof_bytes, &mut cur)?;
        let product_next_eval = transcript.read_scalar(proof_bytes, &mut cur)?;
        let permuted_input_eval = transcript.read_scalar(proof_bytes, &mut cur)?;
        let permuted_input_inv_eval = transcript.read_scalar(proof_bytes, &mut cur)?;
        let permuted_table_eval = transcript.read_scalar(proof_bytes, &mut cur)?;
        lookups.push(LookupData {
            permuted_input_commit: lk_permuted[i].0,
            permuted_table_commit: lk_permuted[i].1,
            product_commit: lk_product[i],
            product_eval,
            product_next_eval,
            permuted_input_eval,
            permuted_input_inv_eval,
            permuted_table_eval,
        });
    }

    // SHPLONK opening
    let shplonk_y = transcript.squeeze_challenge();
    let shplonk_v = transcript.squeeze_challenge();
    let opening_proof_w = transcript.read_g1(proof_bytes, &mut cur)?;
    let shplonk_u = transcript.squeeze_challenge();
    let opening_proof_w_prime = transcript.read_g1(proof_bytes, &mut cur)?;

    if cur != proof_bytes.len() {
        return Err(Error::InvalidProofEncoding);
    }

    Ok((
        GenericProof {
            advice_commits,
            permutation_product_commits,
            random_poly_commit,
            vanishing_h_commits,
            advice_evals,
            fixed_evals,
            instance_evals: Vec::new(), // filled in verify_generic post-batch
            random_poly_eval,
            permutation_common_evals,
            permutation_product_evals,
            lookups,
            opening_proof_w,
            opening_proof_w_prime,
        },
        GenericChallenges {
            theta,
            beta,
            gamma,
            y,
            x,
            shplonk_y,
            shplonk_v,
            shplonk_u,
        },
        instance_values,
    ))
}

/// Per-instance-query plan: the (point − ω^i) denominators were appended to the
/// shared global batch starting at `denom_base` (preceded once by the shared `n`
/// denominator at `n_idx`).
struct InstancePlan {
    n_idx: usize,
    denom_base: usize,
    count: usize,
}

/// COLLECT phase for instance evaluations (QUERY_INSTANCE=false). Appends the
/// `n` denominator (once) plus, per instance query, the `(point − ω^i)`
/// denominators to the shared global batch. NO inverse taken.
fn collect_instance_denoms(
    vk: &GenericVk,
    instance_values: &[Fr],
    x: Fr,
    omega_inv: Fr,
    denoms: &mut Vec<Fr>,
) -> Result<Vec<InstancePlan>, Error> {
    let mut plans = Vec::with_capacity(vk.instance_queries.len());
    if vk.instance_queries.is_empty() || instance_values.is_empty() {
        return Ok(plans);
    }
    let n_u64: u64 = 1u64 << vk.k;
    let n_idx = denoms.len();
    denoms.push(Fr::from(n_u64)); // shared n denominator (single instance column)
    for (col, rot) in &vk.instance_queries {
        if *col != 0 {
            return Err(Error::Protocol(
                "generic: multiple instance columns not supported",
            ));
        }
        let point = rotate_point(x, vk.omega, omega_inv, *rot);
        let denom_base = denoms.len();
        let mut omega_i = Fr::ONE; // ω^0
        for _ in instance_values {
            denoms.push(point - omega_i);
            omega_i *= vk.omega;
        }
        plans.push(InstancePlan { n_idx, denom_base, count: instance_values.len() });
    }
    Ok(plans)
}

/// CONSUME phase for instance evaluations: read the already-inverted shared
/// denominators (slice `inv`) to produce one eval per instance query.
/// `instance_eval = Σ_i inst[i] · L_i(point)`, L_i(point) = ω^i·(xⁿ−1)/(n·(point−ω^i)).
fn finish_instance_evals(
    vk: &GenericVk,
    instance_values: &[Fr],
    plans: &[InstancePlan],
    xn: Fr,
    inv: &[Fr],
) -> Vec<Fr> {
    let mut out = Vec::with_capacity(plans.len());
    for plan in plans {
        let common = (xn - Fr::ONE) * inv[plan.n_idx]; // (xⁿ − 1) · n⁻¹
        let mut acc = Fr::ZERO;
        let mut omega_i = Fr::ONE; // ω^0
        for idx in 0..plan.count {
            let l_i = omega_i * common * inv[plan.denom_base + idx];
            acc += instance_values[idx] * l_i;
            omega_i *= vk.omega;
        }
        out.push(acc);
    }
    out
}

/// Rotate `x` by `rot` steps along the domain: `x · ω^rot`. Negative rotations
/// use the precomputed `omega_inv` (ω⁻¹ = ω^(n−1), derived by exponentiation in
/// `verify_generic` — NOT by a field inversion), so this function takes no
/// `.inverse()` call.
fn rotate_point(x: Fr, omega: Fr, omega_inv: Fr, rot: i32) -> Fr {
    if rot == 0 {
        x
    } else if rot > 0 {
        x * pow_u64(omega, rot as u64)
    } else {
        x * pow_u64(omega_inv, (-rot) as u64)
    }
}

// ===========================================================================
// Identity expressions (gate + permutation + lookup), folded with y
// ===========================================================================

#[inline(never)]
fn compute_expected_h_eval(
    vk: &GenericVk,
    proof: &GenericProof,
    ch: &GenericChallenges,
    lag: &lagrange::LagrangeEvaluations,
) -> Result<Fr, Error> {
    let mut exprs: Vec<Fr> = Vec::new();

    // gates
    for blob in &vk.gate_polys {
        exprs.push(eval_expr(
            blob,
            &proof.advice_evals,
            &proof.fixed_evals,
            &proof.instance_evals,
        )?);
    }

    // permutation
    permutation_expressions(vk, proof, ch, lag, &mut exprs)?;

    // lookups
    lookup_expressions(vk, proof, ch, lag, &mut exprs)?;

    #[cfg(feature = "debug-trace")]
    {
        for (i, e) in exprs.iter().enumerate() {
            eprintln!("[generic] expr[{i}] = {}", _fr_hex(e));
        }
    }

    let folded = exprs.iter().fold(Fr::ZERO, |acc, e| acc * ch.y + e);
    // (xⁿ − 1)⁻¹ comes from the SINGLE Lagrange batch inversion — no inverse here.
    Ok(folded * lag.xn_minus_one_inv)
}

// ===========================================================================
// SPECIALIZED gate/lookup evaluation for SOLITON-Pay
// ===========================================================================
//
// Straight-line transcription of the EXACT same gate-polynomial algebra the
// generic AST interpreter walks (see `circuits/soliton-pay` create_gate + the
// `dump_ast` diagnostic). Produces the identical 8 gate expression values, with
// ZERO AST byte-parsing and ZERO per-constant `from_bigint` Montgomery decode at
// verify time: every field constant is baked in pre-reduced Montgomery limb form
// via `Fr::new_unchecked` (a limb copy, no modular reduction).
//
// SOUNDNESS: this is a pure re-expression of the same polynomials. The
// `specialized_equiv` oracle test asserts it returns the bit-identical
// `expected_h_eval` (and final accept/reject) as `compute_expected_h_eval` for
// ≥8 distinct (seed,depth) proofs. `compute_expected_h_eval` remains the
// untouched ground-truth oracle.

use ark_ff::BigInt;

/// Build an Fr directly from pre-reduced Montgomery limbs — no modular reduction
/// (`new_unchecked` interprets the limbs as already in Montgomery form, exactly
/// what arkworks stores internally for a canonical field element).
#[inline(always)]
fn fr_mont(limbs: [u64; 4]) -> Fr {
    Fr::new_unchecked(BigInt::new(limbs))
}

// The 9 Poseidon-MDS constants (circom-BN254 width-3 matrix) used by the round
// gate, in Montgomery limb form. The circom MDS is a GENERAL 3x3 matrix (NOT the
// banded Cauchy form the previous custom Poseidon used), so all 9 entries are
// distinct and stored explicitly. These are the EXACT values the live
// SOLITON-Pay VK stores (cross-checked: arkworks `soliton_poseidon::gen::gen_mds`
// Montgomery limbs == halo2curves `soliton_pay::poseidon::mds()` Montgomery
// limbs). MDS rows are output lanes 0,1,2.
const MDS_00: [u64; 4] = [0xf2e8909a56fcf3d7, 0x8019ce3145ed8c1d, 0xdda896a228616418, 0x0e5ed723ffc885e1];
const MDS_01: [u64; 4] = [0x3158f311d66c0469, 0x9511d96f69f040a0, 0xbc6996e5b22127bf, 0x07e69e17a7c9122a];
const MDS_02: [u64; 4] = [0x28f45876169969b0, 0x3d6ded69e30a7649, 0x79aed6124c9b23dd, 0x03cf3048ffadf517];
const MDS_10: [u64; 4] = [0x670d8bd946474dd5, 0x56daed800bf07bae, 0x5c98d51ecca20e6d, 0x1a3491eda18b0028];
const MDS_11: [u64; 4] = [0xf0193e572ba79c47, 0x5fb2e46a6ee2dac5, 0x6892f0d5b6ffb984, 0x0df1dabd49661413];
const MDS_12: [u64; 4] = [0x3293bffccaab272d, 0x85cbae38b11c4e1f, 0x67208956c8757b3c, 0x17ca537ab6c9d981];
const MDS_20: [u64; 4] = [0xcc226561d2802757, 0xfcfbd22f5bb9f4ed, 0xc8ef58acce2b8678, 0x05984bb41bae9c88];
const MDS_21: [u64; 4] = [0x17561a5176bfeefd, 0x1cd5d7be100061af, 0x714cefb2dce7646c, 0x0043bf61f2173fe9];
const MDS_22: [u64; 4] = [0x4c72e3c51c729128, 0xd35b9fd9170d616c, 0x4d095dc74ab700a6, 0x1282bdf76dc5d39b];

#[inline(always)]
fn pow5(x: Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

/// b_i for a Poseidon lane: lane 0 (is_sbox always) → a^5; lanes 1,2 →
/// is_full·a^5 + (1−is_full)·a. Own SBF stack frame.
#[inline(never)]
fn poseidon_b(a_in: Fr, rc: Fr, is_full: Fr, always_sbox: bool) -> Fr {
    let a = a_in + rc;
    if always_sbox {
        pow5(a)
    } else {
        fmul(is_full, pow5(a)) + fmul(Fr::ONE - is_full, a)
    }
}

/// One Poseidon-round output gate: q_round·(adv_next − Σ MDS_row·b). Own frame.
#[inline(never)]
fn poseidon_gate(q_round: Fr, adv_next: Fr, m0: Fr, m1: Fr, m2: Fr, b0: Fr, b1: Fr, b2: Fr) -> Fr {
    let mixed = fmul(m0, b0) + fmul(m1, b1) + fmul(m2, b2);
    fmul(q_round, adv_next - mixed)
}

/// The 3 Poseidon-round gate values (lanes 0,1,2). Own frame.
#[inline(never)]
fn soliton_poseidon_gates(proof: &GenericProof, out: &mut Vec<Fr>) {
    let a = &proof.advice_evals;
    let f = &proof.fixed_evals;
    let (a0, a1, a2, a3, a4, a5) = (a[0], a[1], a[2], a[3], a[4], a[5]);
    let (is_full, rc0, rc1, rc2, q_round) = (f[0], f[1], f[2], f[3], f[7]);

    let b0 = poseidon_b(a0, rc0, is_full, true);
    let b1 = poseidon_b(a1, rc1, is_full, false);
    let b2 = poseidon_b(a2, rc2, is_full, false);

    // circom-BN254 general 3x3 MDS (9 distinct entries).
    let (m00, m01, m02) = (fr_mont(MDS_00), fr_mont(MDS_01), fr_mont(MDS_02));
    let (m10, m11, m12) = (fr_mont(MDS_10), fr_mont(MDS_11), fr_mont(MDS_12));
    let (m20, m21, m22) = (fr_mont(MDS_20), fr_mont(MDS_21), fr_mont(MDS_22));
    // next_j = Σ_i MDS[j][i] · b_i, constrained == advice next (a3,a4,a5).
    out.push(poseidon_gate(q_round, a3, m00, m01, m02, b0, b1, b2));
    out.push(poseidon_gate(q_round, a4, m10, m11, m12, b0, b1, b2));
    out.push(poseidon_gate(q_round, a5, m20, m21, m22, b0, b1, b2));
}

/// The 5 selector-compressed gates (add / swap-bool / swap-left / swap-right /
/// const-mul). Own frame.
#[inline(never)]
fn soliton_selector_gates(proof: &GenericProof, out: &mut Vec<Fr>) {
    let a = &proof.advice_evals;
    let f = &proof.fixed_evals;
    let (a0, a1, a2, a3, a4) = (a[0], a[1], a[2], a[3], a[4]);
    let (mulc, f8) = (f[5], f[8]);

    let one = Fr::ONE;
    let two = one + one;
    let three = two + one;
    // selector-compression Lagrange factors.
    let sel_arith = fmul(fmul(f8, two - f8), three - f8);
    let sel_swap = fmul(fmul(f8, one - f8), three - f8);
    let sel_mulc = fmul(fmul(f8, one - f8), two - f8);

    out.push(fmul(sel_arith, (a0 + a1) - a2)); // add
    out.push(fmul(sel_swap, fmul(a2, a2 - one))); // swap boolean
    out.push(fmul(sel_swap, a3 - (a0 + fmul(a2, a1 - a0)))); // swap left
    out.push(fmul(sel_swap, a4 - (a1 + fmul(a2, a0 - a1)))); // swap right
    out.push(fmul(sel_mulc, a2 - fmul(mulc, a0))); // const-mul
}

/// SOLITON-Pay specialized gate evaluation. Pushes the same 8 gate-polynomial
/// values (in the same order) that `compute_expected_h_eval` obtains from
/// `eval_expr(vk.gate_polys[i])`.
#[inline(never)]
fn soliton_gate_exprs(proof: &GenericProof, out: &mut Vec<Fr>) -> Result<(), Error> {
    if proof.advice_evals.len() < 7 || proof.fixed_evals.len() < 9 {
        return Err(Error::Protocol("specialized: missing advice/fixed evals"));
    }
    soliton_poseidon_gates(proof, out);
    soliton_selector_gates(proof, out);
    Ok(())
}

/// SOLITON-Pay specialized lookup. The single lookup has input = F6*A6 and
/// table = F4, so θ-compression of the one-entry sets is just the value itself.
/// Reuses the generic `lookup_left` / `lookup_right` helpers (each already has
/// its own SBF stack frame) for the heavy product term to stay under the
/// 4096-byte SBF stack cap.
#[inline(never)]
fn soliton_lookup_one(
    p: &LookupData,
    proof: &GenericProof,
    ch: &GenericChallenges,
    lag: &lagrange::LagrangeEvaluations,
    active: Fr,
    out: &mut Vec<Fr>,
) -> Result<(), Error> {
    let f = &proof.fixed_evals;
    let a = &proof.advice_evals;
    if f.len() < 7 || a.len() < 7 {
        return Err(Error::Protocol("specialized: lookup evals missing"));
    }
    // l_0·(1 − z)
    out.push(fmul(lag.l_0, Fr::ONE - p.product_eval));
    // l_last·(z² − z)
    out.push(fmul(lag.l_last, p.product_eval.square() - p.product_eval));
    // product_expression (shared heavy helpers, own frames):
    let left = lookup_left(p, ch);
    let input_c = fmul(f[6], a[6]); // θ-compress of single input entry F6*A6
    let table_c = f[4]; // single table entry F4
    let right = lookup_right(p, ch, input_c, table_c);
    out.push(fmul(left - right, active));
    // l_0·(a' − s')
    out.push(fmul(lag.l_0, p.permuted_input_eval - p.permuted_table_eval));
    // active·(a' − s')·(a' − a'(ω⁻¹X))
    let d_is = p.permuted_input_eval - p.permuted_table_eval;
    let d_ii = p.permuted_input_eval - p.permuted_input_inv_eval;
    out.push(fmul(fmul(d_is, d_ii), active));
    Ok(())
}

/// Specialized counterpart to `compute_expected_h_eval` for SOLITON-Pay. Uses
/// the straight-line gate + lookup evaluators above; the permutation argument is
/// shared with the generic path (already constant-free). Identical fold order.
#[inline(never)]
fn compute_expected_h_eval_specialized(
    vk: &GenericVk,
    proof: &GenericProof,
    ch: &GenericChallenges,
    lag: &lagrange::LagrangeEvaluations,
) -> Result<Fr, Error> {
    // Guard: only the SOLITON-Pay shape is supported by this fast path. Any
    // mismatch falls back to the generic oracle (so the path can never be wrong).
    if vk.gate_polys.len() != 8 || vk.lookups.len() != 1 {
        return compute_expected_h_eval(vk, proof, ch, lag);
    }

    let mut exprs: Vec<Fr> = Vec::new();

    // gates (specialized straight-line)
    soliton_gate_exprs(proof, &mut exprs)?;

    // permutation (shared with generic — constant-free)
    permutation_expressions(vk, proof, ch, lag, &mut exprs)?;

    // lookups (specialized straight-line)
    let active = Fr::ONE - (lag.l_last + lag.l_blind);
    soliton_lookup_one(&proof.lookups[0], proof, ch, lag, active, &mut exprs)?;

    #[cfg(feature = "debug-trace")]
    {
        for (i, e) in exprs.iter().enumerate() {
            eprintln!("[specialized] expr[{i}] = {}", _fr_hex(e));
        }
    }

    let folded = exprs.iter().fold(Fr::ZERO, |acc, e| acc * ch.y + e);
    Ok(folded * lag.xn_minus_one_inv)
}

/// Permutation argument expressions, supporting advice/fixed/instance columns.
fn permutation_expressions(
    vk: &GenericVk,
    proof: &GenericProof,
    ch: &GenericChallenges,
    lag: &lagrange::LagrangeEvaluations,
    out: &mut Vec<Fr>,
) -> Result<(), Error> {
    if vk.num_perm_chunks == 0 {
        return Ok(());
    }
    let chunk_len = vk.cs_degree.saturating_sub(2).max(1);

    // (1) l_0·(1 − z_first)
    let first = proof.permutation_product_evals[0];
    out.push(lag.l_0 * (Fr::ONE - first.0));
    // (2) l_last·(z_last² − z_last)
    let last = proof.permutation_product_evals[vk.num_perm_chunks - 1];
    out.push(lag.l_last * (last.0.square() - last.0));
    // (3) stitching for chunks ≥ 1
    for i in 1..vk.num_perm_chunks {
        let z_i = proof.permutation_product_evals[i].0;
        let z_prev_last = proof.permutation_product_evals[i - 1]
            .2
            .ok_or(Error::Protocol("perm: missing z_last for stitch"))?;
        out.push(lag.l_0 * (z_i - z_prev_last));
    }
    // (4) per-chunk grand product
    let active = Fr::ONE - lag.l_last - lag.l_blind;
    let delta = field::delta();
    for chunk_index in 0..vk.num_perm_chunks {
        let contribution = chunk_grand_product(
            vk, proof, ch, chunk_index, chunk_len, delta,
        )?;
        out.push(active * contribution);
    }
    Ok(())
}

#[inline(never)]
fn column_eval(
    vk: &GenericVk,
    proof: &GenericProof,
    kind: u8,
    col_index: usize,
) -> Result<Fr, Error> {
    // value of the column at Rotation::cur() — look up the query index in the
    // matching query table (column, rot=0).
    match kind {
        0 => {
            let qi = vk
                .advice_queries
                .iter()
                .position(|&(c, r)| c == col_index && r == 0)
                .ok_or(Error::Protocol("perm: advice cur query missing"))?;
            Ok(proof.advice_evals[qi])
        }
        1 => {
            let qi = vk
                .fixed_queries
                .iter()
                .position(|&(c, r)| c == col_index && r == 0)
                .ok_or(Error::Protocol("perm: fixed cur query missing"))?;
            Ok(proof.fixed_evals[qi])
        }
        2 => {
            let qi = vk
                .instance_queries
                .iter()
                .position(|&(c, r)| c == col_index && r == 0)
                .ok_or(Error::Protocol("perm: instance cur query missing"))?;
            Ok(proof.instance_evals[qi])
        }
        _ => Err(Error::Protocol("perm: bad column kind")),
    }
}

// `#[inline(never)]`: own SBF stack frame — keeps `permutation_expressions`
// under the 4096-byte SBF stack cap (this is the heavy inner-product loop).
#[inline(never)]
fn chunk_grand_product(
    vk: &GenericVk,
    proof: &GenericProof,
    ch: &GenericChallenges,
    chunk_index: usize,
    chunk_len: usize,
    delta: Fr,
) -> Result<Fr, Error> {
    let (z, z_omega, _) = proof.permutation_product_evals[chunk_index];
    let col_start = chunk_index * chunk_len;
    let col_end = (col_start + chunk_len).min(vk.perm_columns.len());

    // left = z(ωx) · ∏ (col_eval + β·σ_eval + γ)
    let mut left = z_omega;
    for j in col_start..col_end {
        let pc = vk.perm_columns[j];
        let eval = column_eval(vk, proof, pc.kind, pc.index)?;
        left *= eval + ch.beta * proof.permutation_common_evals[j] + ch.gamma;
    }

    // right = z(x) · ∏ (col_eval + δ^i·β·x + γ)
    let mut current_delta = pow_fr(delta, (chunk_index * chunk_len) as u64) * ch.beta * ch.x;
    let mut right = z;
    for j in col_start..col_end {
        let pc = vk.perm_columns[j];
        let eval = column_eval(vk, proof, pc.kind, pc.index)?;
        right *= eval + current_delta + ch.gamma;
        current_delta *= delta;
    }
    Ok(left - right)
}

/// θ-compress a set of expression blobs: acc = acc·θ + eval_expr(e).
//
// `#[inline(never)]`: own SBF stack frame so the (inlined arkworks BigInt)
// temporaries do not pile into `lookup_expressions`'s frame.
#[inline(never)]
fn lookup_compress(
    exprs: &[Vec<u8>],
    proof: &GenericProof,
    theta: Fr,
) -> Result<Fr, Error> {
    let mut acc = Fr::ZERO;
    for e in exprs {
        let v = eval_expr(e, &proof.advice_evals, &proof.fixed_evals, &proof.instance_evals)?;
        acc = acc * theta + v;
    }
    Ok(acc)
}

// One Fr multiply, kept out-of-line so its montgomery BigInt temporaries get
// their own SBF stack frame rather than piling into the caller's.
#[inline(never)]
fn fmul(a: Fr, b: Fr) -> Fr {
    a * b
}

/// left  = z(ωX)·(a'+β)·(s'+γ).  Own frame.
#[inline(never)]
fn lookup_left(p: &LookupData, ch: &GenericChallenges) -> Fr {
    let t = fmul(p.product_next_eval, p.permuted_input_eval + ch.beta);
    fmul(t, p.permuted_table_eval + ch.gamma)
}

/// right = z(X)·(θ_in+β)·(θ_tab+γ).  Own frame.
#[inline(never)]
fn lookup_right(p: &LookupData, ch: &GenericChallenges, input_c: Fr, table_c: Fr) -> Fr {
    let t = fmul(p.product_eval, input_c + ch.beta);
    fmul(t, table_c + ch.gamma)
}

/// Emit the 5 constraint expressions for a single lookup argument.
//
// `#[inline(never)]`: own SBF stack frame — keeps `lookup_expressions` under
// the 4096-byte SBF stack cap.
#[inline(never)]
fn lookup_expr_one(
    lk: &crate::vk_generic::Lookup,
    p: &LookupData,
    proof: &GenericProof,
    ch: &GenericChallenges,
    lag: &lagrange::LagrangeEvaluations,
    active: Fr,
    out: &mut Vec<Fr>,
) -> Result<(), Error> {
    // l_0·(1 − z)
    out.push(fmul(lag.l_0, Fr::ONE - p.product_eval));
    // l_last·(z² − z)
    out.push(fmul(lag.l_last, p.product_eval.square() - p.product_eval));
    // product_expression:
    //   left  = z(ωX)·(a'+β)·(s'+γ)
    //   right = z(X)·(θ-compress(inputs)+β)·(θ-compress(tables)+γ)
    let left = lookup_left(p, ch);
    let input_c = lookup_compress(&lk.input_exprs, proof, ch.theta)?;
    let table_c = lookup_compress(&lk.table_exprs, proof, ch.theta)?;
    let right = lookup_right(p, ch, input_c, table_c);
    out.push(fmul(left - right, active));
    // l_0·(a' − s')
    out.push(fmul(lag.l_0, p.permuted_input_eval - p.permuted_table_eval));
    // active·(a' − s')·(a' − a'(ω⁻¹ X))
    let d_is = p.permuted_input_eval - p.permuted_table_eval;
    let d_ii = p.permuted_input_eval - p.permuted_input_inv_eval;
    out.push(fmul(fmul(d_is, d_ii), active));
    Ok(())
}

/// Lookup argument expressions (per halo2 lookup verifier).
fn lookup_expressions(
    vk: &GenericVk,
    proof: &GenericProof,
    ch: &GenericChallenges,
    lag: &lagrange::LagrangeEvaluations,
    out: &mut Vec<Fr>,
) -> Result<(), Error> {
    let active = Fr::ONE - (lag.l_last + lag.l_blind);
    for (li, lk) in vk.lookups.iter().enumerate() {
        let p = &proof.lookups[li];
        lookup_expr_one(lk, p, proof, ch, lag, active, out)?;
    }
    Ok(())
}

// ===========================================================================
// Query construction (mirrors halo2 verify_proof queries chain)
// ===========================================================================

#[allow(clippy::too_many_arguments)]
fn build_queries(
    vk: &GenericVk,
    proof: &GenericProof,
    ch: &GenericChallenges,
    omega_inv: Fr,
    h_commitment: G1,
    expected_h_eval: Fr,
) -> Result<(Vec<VerifierQuery>, usize), Error> {
    let mut q: Vec<VerifierQuery> = Vec::new();
    let mut next_id = 0usize;
    let mut id = || {
        let i = next_id;
        next_id += 1;
        i
    };

    let omega = vk.omega;
    let x = ch.x;
    let x_next = rotate_point(x, omega, omega_inv, 1);
    let x_inv = rotate_point(x, omega, omega_inv, -1);
    let n: u64 = 1u64 << vk.k;
    let last_pow = -((vk.blinding_factors as i32) + 1);
    let x_last = rotate_point(x, omega, omega_inv, last_pow);
    let _ = n;

    // commit-id assignment order must mirror halo2's commitment references:
    // advice columns, perm products, lookup (product, perm_input, perm_table),
    // fixed columns, perm common, vanishing (h, random).
    // We assign ids per logical commitment slot.
    let advice_ids: Vec<usize> = proof.advice_commits.iter().map(|_| id()).collect();
    let perm_prod_ids: Vec<usize> = proof.permutation_product_commits.iter().map(|_| id()).collect();
    // lookups: each has product, permuted_input, permuted_table ids
    let lookup_ids: Vec<(usize, usize, usize)> =
        proof.lookups.iter().map(|_| (id(), id(), id())).collect();
    let fixed_ids: Vec<usize> = vk.fixed_commitments.iter().map(|_| id()).collect();
    let perm_common_ids: Vec<usize> =
        vk.permutation_commitments.iter().map(|_| id()).collect();
    let h_id = id();
    let random_id = id();

    // (1) advice queries — at rotated points per query table.
    for (qi, &(col, rot)) in vk.advice_queries.iter().enumerate() {
        let point = rotate_point(x, omega, omega_inv, rot);
        q.push(VerifierQuery {
            commit_id: advice_ids[col],
            commitment: proof.advice_commits[col],
            point,
            eval: proof.advice_evals[qi],
        });
    }

    // (2) permutation product queries — at x, ωx, and ω^last·x for non-last sets.
    for (i, &(z, z_omega, _z_last)) in proof.permutation_product_evals.iter().enumerate() {
        let cid = perm_prod_ids[i];
        let commit = proof.permutation_product_commits[i];
        q.push(VerifierQuery { commit_id: cid, commitment: commit, point: x, eval: z });
        q.push(VerifierQuery { commit_id: cid, commitment: commit, point: x_next, eval: z_omega });
    }
    let last_idx = vk.num_perm_chunks.saturating_sub(1);
    for i in (0..last_idx).rev() {
        let z_last = proof.permutation_product_evals[i]
            .2
            .ok_or(Error::Protocol("perm: z_last missing for query"))?;
        q.push(VerifierQuery {
            commit_id: perm_prod_ids[i],
            commitment: proof.permutation_product_commits[i],
            point: x_last,
            eval: z_last,
        });
    }

    // (3) lookup queries: product@x, permuted_input@x, permuted_table@x,
    //     permuted_input@x_inv, product@x_next.
    for (i, p) in proof.lookups.iter().enumerate() {
        let (prod_id, in_id, tab_id) = lookup_ids[i];
        q.push(VerifierQuery { commit_id: prod_id, commitment: p.product_commit, point: x, eval: p.product_eval });
        q.push(VerifierQuery { commit_id: in_id, commitment: p.permuted_input_commit, point: x, eval: p.permuted_input_eval });
        q.push(VerifierQuery { commit_id: tab_id, commitment: p.permuted_table_commit, point: x, eval: p.permuted_table_eval });
        q.push(VerifierQuery { commit_id: in_id, commitment: p.permuted_input_commit, point: x_inv, eval: p.permuted_input_inv_eval });
        q.push(VerifierQuery { commit_id: prod_id, commitment: p.product_commit, point: x_next, eval: p.product_next_eval });
    }

    // (4) fixed queries — at rotated points per query table.
    for (qi, &(col, rot)) in vk.fixed_queries.iter().enumerate() {
        let point = rotate_point(x, omega, omega_inv, rot);
        q.push(VerifierQuery {
            commit_id: fixed_ids[col],
            commitment: vk.fixed_commitments[col],
            point,
            eval: proof.fixed_evals[qi],
        });
    }

    // (5) permutation common — at x.
    for ((cid, commit), eval) in perm_common_ids
        .iter()
        .zip(vk.permutation_commitments.iter())
        .zip(proof.permutation_common_evals.iter())
    {
        q.push(VerifierQuery { commit_id: *cid, commitment: *commit, point: x, eval: *eval });
    }

    // (6) vanishing — h aggregated + random poly, at x.
    let h_query_index = q.len();
    q.push(VerifierQuery { commit_id: h_id, commitment: h_commitment, point: x, eval: expected_h_eval });
    q.push(VerifierQuery { commit_id: random_id, commitment: proof.random_poly_commit, point: x, eval: proof.random_poly_eval });

    Ok((q, h_query_index))
}

fn aggregate_h_commitment(h_pieces: &[G1], xn: Fr) -> Result<G1, Error> {
    if h_pieces.is_empty() {
        return Err(Error::Protocol("aggregate_h: no pieces"));
    }
    let mut acc_scalar = Fr::ONE;
    let mut acc_g1: Option<G1> = None;
    for p in h_pieces.iter() {
        if !acc_scalar.is_zero() && p != &G1::IDENTITY {
            let term = p.scalar_mul(&fr_to_bytes_be(&acc_scalar))?;
            acc_g1 = Some(match acc_g1 {
                None => term,
                Some(a) => a.add(&term)?,
            });
        }
        acc_scalar *= xn;
    }
    Ok(acc_g1.unwrap_or(G1::IDENTITY))
}

// ===========================================================================
// Top-level entry
// ===========================================================================

pub fn verify_generic(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[[u8; 32]],
    kzg_vk: &KzgVk,
) -> Result<bool, Error> {
    verify_inner(vk_bytes, proof_bytes, public_inputs, kzg_vk, false)
}

/// SPECIALIZED SOLITON-Pay verifier. Bit-identical to `verify_generic` (the
/// oracle), but evaluates the gate + lookup identity with a straight-line,
/// pre-decoded-constant fast path instead of the generic AST interpreter. All
/// other machinery (transcript, permutation argument, SHPLONK, pairing) is the
/// SAME code. For any non-SOLITON-Pay VK shape it transparently falls back to
/// the generic evaluator, so it can never diverge.
pub fn verify_specialized(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[[u8; 32]],
    kzg_vk: &KzgVk,
) -> Result<bool, Error> {
    verify_inner(vk_bytes, proof_bytes, public_inputs, kzg_vk, true)
}

#[inline(always)]
fn verify_inner(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[[u8; 32]],
    kzg_vk: &KzgVk,
    specialized: bool,
) -> Result<bool, Error> {
    cu("[vg] enter");
    let vk = parse_vk_generic(vk_bytes)?;
    cu("[vg] after parse_vk_generic");
    let mut transcript = Keccak256Transcript::new(&vk.transcript_repr);

    // ω⁻¹ = ω^(n−1) since ωⁿ = 1 — computed ONCE by exponentiation, NOT by a
    // field inversion. Threaded into instance-eval + query rotation so neither
    // takes an `.inverse()` call (all field inverses are batched).
    let omega_inv = pow_u64(vk.omega, (1u64 << vk.k) - 1);

    let (proof, ch, instance_values) =
        read_proof(&vk, proof_bytes, public_inputs, omega_inv, &mut transcript)?;
    cu("[vg] after read_proof+transcript");

    // All post-transcript work lives in its own SBF stack frame (the orchestration
    // holds several large Vec/Fr locals at once; keeping them out of
    // `verify_generic`'s frame avoids the 4096-byte SBF stack overflow).
    verify_after_transcript(&vk, proof, &ch, &instance_values, omega_inv, kzg_vk, specialized)
}

/// Test-only oracle hook: re-runs the post-transcript pipeline up to (and
/// including) the gate/perm/lookup identity evaluation and returns BOTH the
/// generic and the specialized `expected_h_eval` as canonical BE bytes. Used by
/// the `specialized_equiv` oracle test to assert bit-identical intermediate
/// results. Logic-neutral: never reachable from the on-chain verifier.
#[cfg(feature = "std")]
pub fn expected_h_evals_for_test(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[[u8; 32]],
) -> Result<([u8; 32], [u8; 32]), Error> {
    let vk = parse_vk_generic(vk_bytes)?;
    let mut transcript = Keccak256Transcript::new(&vk.transcript_repr);
    let omega_inv = pow_u64(vk.omega, (1u64 << vk.k) - 1);
    let (mut proof, ch, instance_values) =
        read_proof(&vk, proof_bytes, public_inputs, omega_inv, &mut transcript)?;

    let xn = pow_u64(ch.x, 1u64 << vk.k);
    let h_commitment = aggregate_h_commitment(&proof.vanishing_h_commits, xn)?;
    let (queries, _h) = build_queries(&vk, &proof, &ch, omega_inv, h_commitment, Fr::ZERO)?;
    let batch = collect_and_invert(&vk, &instance_values, &ch, omega_inv, xn, &queries)?;
    let batch = *batch;

    proof.instance_evals =
        finish_instance_evals(&vk, &instance_values, &batch.instance_plans, xn, &batch.denoms);
    let lag = lagrange::finish_lagrange(&batch.lag_plan, &batch.denoms)?;

    let generic = compute_expected_h_eval(&vk, &proof, &ch, &lag)?;
    let special = compute_expected_h_eval_specialized(&vk, &proof, &ch, &lag)?;
    Ok((fr_to_bytes_be(&generic), fr_to_bytes_be(&special)))
}

/// Everything after the Fiat-Shamir transcript: the single global batch
/// inversion + all consumers + the final pairing. Own SBF stack frame.
/// `proof` is boxed so its (large, G1-inlined) struct lives on the heap, not in
/// this function's SBF stack frame.
#[inline(never)]
fn verify_after_transcript(
    vk: &GenericVk,
    proof: GenericProof,
    ch: &GenericChallenges,
    instance_values: &[Fr],
    omega_inv: Fr,
    kzg_vk: &KzgVk,
    specialized: bool,
) -> Result<bool, Error> {
    let proof = alloc::boxed::Box::new(proof);

    // xⁿ at the challenge point (pure exponentiation — no inverse).
    let xn = pow_u64(ch.x, 1u64 << vk.k);

    // h-commitment MSM (no inverse) — needed for the h query's commitment slot.
    let h_commitment = aggregate_h_commitment(&proof.vanishing_h_commits, xn)?;

    // Query SKELETON (ZERO placeholder for the h-query eval; patched post-batch).
    let (queries, _h_query_index) =
        build_queries(vk, &proof, ch, omega_inv, h_commitment, Fr::ZERO)?;

    // SINGLE GLOBAL BATCH INVERSION (collect → invert once). Boxed so the heavy
    // BatchState lives on the heap, off this function's SBF stack frame.
    let batch = collect_and_invert(vk, instance_values, ch, omega_inv, xn, &queries)?;
    cu("[vg] after SINGLE batch_inversion");

    // `queries` is no longer needed (rotation sets already grouped inside
    // `batch.sets`); the h-query eval is patched in place below.
    drop(queries);

    // Consume the inverses + SHPLONK reduction + pairing (own frame).
    consume_and_pair(vk, proof, ch, instance_values, xn, h_commitment, batch, kzg_vk, specialized)
}

/// Consume the inverted global batch (instance evals, Lagrange evals, gate AST
/// → expected_h_eval), patch the h-query eval, run the SHPLONK reduction + MSM,
/// and the final pairing. Own SBF stack frame.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn consume_and_pair(
    vk: &GenericVk,
    mut proof: alloc::boxed::Box<GenericProof>,
    ch: &GenericChallenges,
    instance_values: &[Fr],
    xn: Fr,
    h_commitment: G1,
    batch: alloc::boxed::Box<BatchState>,
    kzg_vk: &KzgVk,
    specialized: bool,
) -> Result<bool, Error> {
    let mut batch = *batch; // move out of the Box so fields can be consumed

    proof.instance_evals =
        finish_instance_evals(vk, instance_values, &batch.instance_plans, xn, &batch.denoms);
    let lag = lagrange::finish_lagrange(&batch.lag_plan, &batch.denoms)?;
    cu("[vg] after evaluate_lagrange (consume)");

    let expected_h_eval = if specialized {
        compute_expected_h_eval_specialized(vk, &proof, ch, &lag)?
    } else {
        compute_expected_h_eval(vk, &proof, ch, &lag)?
    };
    cu("[vg] after compute_expected_h_eval (gates+perm+lookup)");

    // Patch the h-query eval IN PLACE inside the already-grouped rotation sets
    // (the h-commitment is opened only at point x). Avoids re-running the O(n²)
    // intermediate-set grouping. The denominators (point-only) are unchanged.
    shplonk::patch_commitment_eval(&mut batch.sets, &h_commitment, ch.x, expected_h_eval)?;

    let pairs = shplonk::finish_opening(
        &batch.sets,
        &batch.shplonk_layout,
        &batch.denoms,
        proof.opening_proof_w,
        proof.opening_proof_w_prime,
        ch.shplonk_y,
        ch.shplonk_v,
        ch.shplonk_u,
        kzg_vk,
    )?;
    cu("[vg] after shplonk::finish_opening (MSM)");

    let r = pairing::pairing_check(&pairs.0);
    cu("[vg] after pairing_check");
    r
}

/// State produced by the single global batch inversion, threaded between the
/// collect, consume, and finish frames (heap-backed Vecs keep it light).
struct BatchState {
    denoms: Vec<Fr>,
    instance_plans: Vec<InstancePlan>,
    lag_plan: lagrange::LagrangePlan,
    sets: crate::kzg::shplonk::IntermediateSets,
    shplonk_layout: crate::kzg::shplonk::ShplonkDenomLayout,
}

/// Collect EVERY denominator the whole verifier needs — instance-eval Lagrange
/// denominators, the three Lagrange evaluations' denominators (incl. xⁿ−1), and
/// every SHPLONK z_diff + interpolation denominator — into ONE Vec and invert
/// with ONE `batch_inversion` call. After this the verifier does NO inversion.
/// Own SBF stack frame.
#[inline(never)]
fn collect_and_invert(
    vk: &GenericVk,
    instance_values: &[Fr],
    ch: &GenericChallenges,
    omega_inv: Fr,
    xn: Fr,
    queries: &[shplonk::VerifierQuery],
) -> Result<alloc::boxed::Box<BatchState>, Error> {
    let mut denoms: Vec<Fr> = Vec::new();

    let instance_plans =
        collect_instance_denoms(vk, instance_values, ch.x, omega_inv, &mut denoms)?;
    let lag_plan = lagrange::collect_lagrange_denoms(
        vk.k, vk.omega, ch.x, vk.blinding_factors, xn, omega_inv, &mut denoms,
    )?;
    let (sets, mut shplonk_layout) =
        shplonk::collect_opening_denoms(queries, ch.shplonk_u)?;
    let shplonk_base = denoms.len();
    denoms.extend_from_slice(&shplonk_layout.denoms);
    shplonk::offset_layout(&mut shplonk_layout, shplonk_base);

    // Hard-reject any zero denominator BEFORE inverting.
    if denoms.iter().any(|d| d.is_zero()) {
        return Err(Error::Protocol("verify_generic: zero denominator"));
    }
    ark_ff::batch_inversion(&mut denoms); // <-- THE SOLE inverse() call site in verify_generic

    Ok(alloc::boxed::Box::new(BatchState {
        denoms,
        instance_plans,
        lag_plan,
        sets,
        shplonk_layout,
    }))
}

// ===========================================================================
// Small helpers
// ===========================================================================

#[inline]
fn pow_u64(mut base: Fr, mut exp: u64) -> Fr {
    let mut acc = Fr::ONE;
    while exp != 0 {
        if exp & 1 == 1 {
            acc *= base;
        }
        base = base.square();
        exp >>= 1;
    }
    acc
}

#[inline]
fn pow_fr(base: Fr, exp: u64) -> Fr {
    pow_u64(base, exp)
}

fn read_g1s(
    transcript: &mut Keccak256Transcript,
    proof: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<G1>, Error> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(transcript.read_g1(proof, cursor)?);
    }
    Ok(out)
}

fn read_scalars(
    transcript: &mut Keccak256Transcript,
    proof: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<Fr>, Error> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(transcript.read_scalar(proof, cursor)?);
    }
    Ok(out)
}

#[cfg(feature = "debug-trace")]
fn _fr_hex(f: &Fr) -> alloc::string::String {
    use alloc::string::String;
    use core::fmt::Write;
    let be = crate::field::fr_to_bytes_be(f);
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in &be {
        write!(s, "{b:02x}").unwrap();
    }
    s
}
