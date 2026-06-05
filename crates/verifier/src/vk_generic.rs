//! v2 on-chain VK format: carries the full ConstraintSystem (query tables,
//! gate expression ASTs, lookup arguments, permutation column kinds) so a
//! generic verifier can evaluate ANY halo2 circuit's gate/permutation/lookup
//! identities — not just the hard-coded StandardPlonk shape.
//!
//! Mirrors `halo2_solana_vk_host::compile_generic::compile_vk_generic`.

use alloc::vec::Vec;
use ark_bn254::Fr;

use crate::{curve::G1, Error};

pub const VK2_MAGIC: &[u8; 8] = b"H2SV0002";
pub const VK2_VERSION: u32 = 2;

// Expression opcodes.
pub(crate) const OP_CONST: u8 = 0x00;
pub(crate) const OP_FIXED: u8 = 0x02;
pub(crate) const OP_ADVICE: u8 = 0x03;
pub(crate) const OP_INSTANCE: u8 = 0x04;
pub(crate) const OP_NEG: u8 = 0x06;
pub(crate) const OP_SUM: u8 = 0x07;
pub(crate) const OP_PRODUCT: u8 = 0x08;
pub(crate) const OP_SCALED: u8 = 0x09;

/// A column reference inside the permutation argument.
#[derive(Clone, Copy, Debug)]
pub struct PermColumn {
    /// 0 = advice, 1 = fixed, 2 = instance.
    pub kind: u8,
    pub index: usize,
}

/// One lookup argument.
#[derive(Clone, Debug)]
pub struct Lookup {
    /// Each entry is a length-prefixed encoded Expression blob.
    pub input_exprs: Vec<Vec<u8>>,
    pub table_exprs: Vec<Vec<u8>>,
}

/// Full parsed v2 protocol.
#[derive(Clone, Debug)]
pub struct GenericVk {
    pub k: u32,
    pub omega: Fr,
    pub num_instance: usize,
    pub num_advice: usize,
    pub num_fixed: usize,
    pub cs_degree: usize,
    pub blinding_factors: usize,
    pub num_perm_chunks: usize,
    pub transcript_repr: [u8; 32],

    /// (column_index, rotation) per query, in halo2 query-index order.
    pub advice_queries: Vec<(usize, i32)>,
    pub fixed_queries: Vec<(usize, i32)>,
    pub instance_queries: Vec<(usize, i32)>,

    /// Flat list of gate polynomial ASTs (each a length-tagged opcode blob).
    pub gate_polys: Vec<Vec<u8>>,

    pub lookups: Vec<Lookup>,

    pub perm_columns: Vec<PermColumn>,

    pub fixed_commitments: Vec<G1>,
    pub permutation_commitments: Vec<G1>,
}

impl GenericVk {
    pub fn num_advice_queries(&self) -> usize {
        self.advice_queries.len()
    }
    pub fn num_fixed_queries(&self) -> usize {
        self.fixed_queries.len()
    }
    pub fn num_perm_columns(&self) -> usize {
        self.permutation_commitments.len()
    }
}

pub fn parse_vk_generic(bytes: &[u8]) -> Result<GenericVk, Error> {
    let mut r = Reader::new(bytes);
    let magic = r.read_array::<8>()?;
    if &magic != VK2_MAGIC {
        return Err(Error::InvalidVkEncoding);
    }
    if r.read_u32_le()? != VK2_VERSION {
        return Err(Error::InvalidVkEncoding);
    }

    let k = r.read_u32_le()?;
    let num_instance = r.read_u32_le()? as usize;
    let num_advice = r.read_u32_le()? as usize;
    let num_fixed = r.read_u32_le()? as usize;
    let cs_degree = r.read_u32_le()? as usize;
    let blinding_factors = r.read_u32_le()? as usize;
    let num_perm_chunks = r.read_u32_le()? as usize;
    let omega = crate::field::fr_from_bytes_be(&r.read_array::<32>()?)?;
    let transcript_repr = r.read_array::<32>()?;

    let advice_queries = read_query_table(&mut r)?;
    let fixed_queries = read_query_table(&mut r)?;
    let instance_queries = read_query_table(&mut r)?;

    let n_gate = r.read_u32_le()? as usize;
    let mut gate_polys = Vec::with_capacity(n_gate);
    for _ in 0..n_gate {
        gate_polys.push(r.read_blob()?);
    }

    let n_lookup = r.read_u32_le()? as usize;
    let mut lookups = Vec::with_capacity(n_lookup);
    for _ in 0..n_lookup {
        let n_in = r.read_u32_le()? as usize;
        let mut input_exprs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            input_exprs.push(r.read_blob()?);
        }
        let n_tab = r.read_u32_le()? as usize;
        let mut table_exprs = Vec::with_capacity(n_tab);
        for _ in 0..n_tab {
            table_exprs.push(r.read_blob()?);
        }
        lookups.push(Lookup { input_exprs, table_exprs });
    }

    let n_perm = r.read_u32_le()? as usize;
    let mut perm_columns = Vec::with_capacity(n_perm);
    for _ in 0..n_perm {
        let kind = r.read_u8()?;
        let index = r.read_u32_le()? as usize;
        perm_columns.push(PermColumn { kind, index });
    }

    let n_fixed_c = r.read_u32_le()? as usize;
    let mut fixed_commitments = Vec::with_capacity(n_fixed_c);
    for _ in 0..n_fixed_c {
        fixed_commitments.push(G1(r.read_array::<64>()?));
    }
    let n_perm_c = r.read_u32_le()? as usize;
    let mut permutation_commitments = Vec::with_capacity(n_perm_c);
    for _ in 0..n_perm_c {
        permutation_commitments.push(G1(r.read_array::<64>()?));
    }

    if !r.is_empty() {
        return Err(Error::InvalidVkEncoding);
    }

    Ok(GenericVk {
        k,
        omega,
        num_instance,
        num_advice,
        num_fixed,
        cs_degree,
        blinding_factors,
        num_perm_chunks,
        transcript_repr,
        advice_queries,
        fixed_queries,
        instance_queries,
        gate_polys,
        lookups,
        perm_columns,
        fixed_commitments,
        permutation_commitments,
    })
}

fn read_query_table(r: &mut Reader) -> Result<Vec<(usize, i32)>, Error> {
    let n = r.read_u32_le()? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let col = r.read_u32_le()? as usize;
        let rot = r.read_i32_le()?;
        out.push((col, rot));
    }
    Ok(out)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
    fn ensure(&self, n: usize) -> Result<(), Error> {
        if self.pos.checked_add(n).map_or(true, |end| end > self.buf.len()) {
            Err(Error::InvalidVkEncoding)
        } else {
            Ok(())
        }
    }
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.ensure(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }
    fn read_u8(&mut self) -> Result<u8, Error> {
        self.ensure(1)?;
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }
    fn read_u32_le(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }
    fn read_i32_le(&mut self) -> Result<i32, Error> {
        Ok(i32::from_le_bytes(self.read_array::<4>()?))
    }
    fn read_blob(&mut self) -> Result<Vec<u8>, Error> {
        let len = self.read_u32_le()? as usize;
        self.ensure(len)?;
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }
}
