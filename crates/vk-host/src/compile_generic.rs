//! Compile a halo2 `VerifyingKey<G1Affine>` into the **v2** on-chain VK format,
//! which carries the FULL ConstraintSystem needed for a generic (non-circuit-
//! specific) verifier: query tables, gate expression ASTs, lookup arguments,
//! and the permutation column kinds.
//!
//! This is what `halo2_solana_verifier::vk_generic::parse_vk_generic` consumes and the
//! generic verifier `plonk::generic::verify_generic` evaluates.

use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_proofs::plonk::{Any, Expression, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;

use crate::compile::Error;
use crate::encode::{fr_to_bytes_be, g1_affine_to_bytes_be};

pub const VK2_MAGIC: &[u8; 8] = b"H2SV0002";
pub const VK2_VERSION: u32 = 2;

// Expression opcodes (postfix-by-recursion preorder encoding).
const OP_CONST: u8 = 0x00;
const OP_FIXED: u8 = 0x02;
const OP_ADVICE: u8 = 0x03;
const OP_INSTANCE: u8 = 0x04;
const OP_NEG: u8 = 0x06;
const OP_SUM: u8 = 0x07;
const OP_PRODUCT: u8 = 0x08;
const OP_SCALED: u8 = 0x09;

fn omega(k: u32) -> Fr {
    use halo2curves::ff::PrimeField;
    let s = Fr::S;
    let mut o = Fr::ROOT_OF_UNITY;
    for _ in 0..(s - k) {
        o = o.square();
    }
    o
}

/// Recursively encode an Expression to bytes. Resolves Advice/Fixed/Instance
/// nodes to their query-index (position in the corresponding `*_queries` table),
/// which is exactly the index halo2's `evaluate` uses (`query.index.unwrap()`).
fn encode_expr(
    e: &Expression<Fr>,
    advice_q: &[(usize, i32)],
    fixed_q: &[(usize, i32)],
    instance_q: &[(usize, i32)],
    out: &mut Vec<u8>,
) {
    match e {
        Expression::Constant(c) => {
            out.push(OP_CONST);
            out.extend_from_slice(&fr_to_bytes_be(c));
        }
        Expression::Selector(_) => {
            panic!("generic compile: virtual selector present (must be substituted by keygen)");
        }
        Expression::Fixed(q) => {
            let idx = fixed_q
                .iter()
                .position(|&(c, r)| c == q.column_index() && r == q.rotation().0)
                .expect("fixed query not found in table");
            out.push(OP_FIXED);
            out.extend_from_slice(&(idx as u32).to_le_bytes());
        }
        Expression::Advice(q) => {
            let idx = advice_q
                .iter()
                .position(|&(c, r)| c == q.column_index() && r == q.rotation().0)
                .expect("advice query not found in table");
            out.push(OP_ADVICE);
            out.extend_from_slice(&(idx as u32).to_le_bytes());
        }
        Expression::Instance(q) => {
            let idx = instance_q
                .iter()
                .position(|&(c, r)| c == q.column_index() && r == q.rotation().0)
                .expect("instance query not found in table");
            out.push(OP_INSTANCE);
            out.extend_from_slice(&(idx as u32).to_le_bytes());
        }
        Expression::Challenge(_) => {
            panic!("generic compile: challenges (phased) not supported");
        }
        Expression::Negated(a) => {
            out.push(OP_NEG);
            encode_expr(a, advice_q, fixed_q, instance_q, out);
        }
        Expression::Sum(a, b) => {
            out.push(OP_SUM);
            encode_expr(a, advice_q, fixed_q, instance_q, out);
            encode_expr(b, advice_q, fixed_q, instance_q, out);
        }
        Expression::Product(a, b) => {
            out.push(OP_PRODUCT);
            encode_expr(a, advice_q, fixed_q, instance_q, out);
            encode_expr(b, advice_q, fixed_q, instance_q, out);
        }
        Expression::Scaled(a, c) => {
            out.push(OP_SCALED);
            encode_expr(a, advice_q, fixed_q, instance_q, out);
            out.extend_from_slice(&fr_to_bytes_be(c));
        }
    }
}

fn put_u32(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u32).to_le_bytes());
}
fn put_i32(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_le_bytes());
}
/// length-prefixed expression blob.
fn put_expr(
    out: &mut Vec<u8>,
    e: &Expression<Fr>,
    aq: &[(usize, i32)],
    fq: &[(usize, i32)],
    iq: &[(usize, i32)],
) {
    let mut blob = Vec::new();
    encode_expr(e, aq, fq, iq, &mut blob);
    put_u32(out, blob.len());
    out.extend_from_slice(&blob);
}

pub fn compile_vk_generic(
    params: &ParamsKZG<halo2curves::bn256::Bn256>,
    vk: &VerifyingKey<G1Affine>,
) -> Result<Vec<u8>, Error> {
    let k = params.k();
    let om = omega(k);
    let cs = vk.cs();

    let advice_q: Vec<(usize, i32)> = cs
        .advice_queries()
        .iter()
        .map(|(c, r)| (c.index(), r.0))
        .collect();
    let fixed_q: Vec<(usize, i32)> = cs
        .fixed_queries()
        .iter()
        .map(|(c, r)| (c.index(), r.0))
        .collect();
    let instance_q: Vec<(usize, i32)> = cs
        .instance_queries()
        .iter()
        .map(|(c, r)| (c.index(), r.0))
        .collect();

    let cs_degree = cs.degree();
    let perm_columns = vk.permutation().commitments().len();
    let chunk_len = cs_degree.saturating_sub(2).max(1);
    let num_perm_chunks = if perm_columns == 0 {
        0
    } else {
        (perm_columns + chunk_len - 1) / chunk_len
    };

    let mut out = Vec::new();
    out.extend_from_slice(VK2_MAGIC);
    out.extend_from_slice(&VK2_VERSION.to_le_bytes());
    put_u32(&mut out, k as usize);
    put_u32(&mut out, cs.num_instance_columns());
    put_u32(&mut out, cs.num_advice_columns());
    put_u32(&mut out, cs.num_fixed_columns());
    put_u32(&mut out, cs_degree);
    put_u32(&mut out, cs.blinding_factors());
    put_u32(&mut out, num_perm_chunks);
    out.extend_from_slice(&fr_to_bytes_be(&om));
    out.extend_from_slice(&fr_to_bytes_be(&vk.transcript_repr()));

    // Query tables.
    put_u32(&mut out, advice_q.len());
    for (c, r) in &advice_q {
        put_u32(&mut out, *c);
        put_i32(&mut out, *r);
    }
    put_u32(&mut out, fixed_q.len());
    for (c, r) in &fixed_q {
        put_u32(&mut out, *c);
        put_i32(&mut out, *r);
    }
    put_u32(&mut out, instance_q.len());
    for (c, r) in &instance_q {
        put_u32(&mut out, *c);
        put_i32(&mut out, *r);
    }

    // Gates: flat list of polynomials (halo2 verifier flattens gates → polys).
    let mut gate_polys: Vec<&Expression<Fr>> = Vec::new();
    for gate in cs.gates() {
        for p in gate.polynomials() {
            gate_polys.push(p);
        }
    }
    put_u32(&mut out, gate_polys.len());
    for p in &gate_polys {
        put_expr(&mut out, p, &advice_q, &fixed_q, &instance_q);
    }

    // Lookups.
    put_u32(&mut out, cs.lookups().len());
    for lk in cs.lookups() {
        put_u32(&mut out, lk.input_expressions().len());
        for e in lk.input_expressions() {
            put_expr(&mut out, e, &advice_q, &fixed_q, &instance_q);
        }
        put_u32(&mut out, lk.table_expressions().len());
        for e in lk.table_expressions() {
            put_expr(&mut out, e, &advice_q, &fixed_q, &instance_q);
        }
    }

    // Permutation columns: (kind u8, col index u32). kind: 0=advice,1=fixed,2=instance.
    let perm_cols = cs.permutation().get_columns();
    put_u32(&mut out, perm_cols.len());
    for c in perm_cols.iter() {
        let kind: u8 = match c.column_type() {
            Any::Advice(_) => 0,
            Any::Fixed => 1,
            Any::Instance => 2,
        };
        out.push(kind);
        put_u32(&mut out, c.index());
    }

    // Commitments.
    let fixed = vk.fixed_commitments();
    put_u32(&mut out, fixed.len());
    for p in fixed {
        out.extend_from_slice(&g1_affine_to_bytes_be(p));
    }
    let perm = vk.permutation().commitments();
    put_u32(&mut out, perm.len());
    for p in perm {
        out.extend_from_slice(&g1_affine_to_bytes_be(p));
    }

    Ok(out)
}
