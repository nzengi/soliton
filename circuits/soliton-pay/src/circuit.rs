//! SOLITON-Pay: 2-input / 2-output single-asset shielded payment circuit.
//!
//! Public instance column holds 6 values in this fixed order (row index):
//!   0: root   1: nf1   2: nf2   3: cmout1   4: cmout2   5: pub_amount
//!
//! Constraints enforced:
//!  1. Per input i in {1,2}: pk_i = H(sk_i,0); cm_i = H3(value_i, pk_i, rho_i);
//!     Merkle path depth D from cm_i to public `root`; nf_i = H(sk_i, rho_i)
//!     constrained == public nf_i.
//!  2. Per output j in {1,2}: cmout_j = H3(value_j, pk_j, rho_j) == public cmout_j.
//!  3. Balance: value_in1 + value_in2 + pub_amount == value_out1 + value_out2.
//!  4. Range: each output value is 64-bit, via an 8-limb x 8-bit lookup against a
//!     fixed 0..256 table (real halo2 lookup argument) + weighted recomposition.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Instance,
        Selector, TableColumn,
    },
    poly::Rotation,
};
use halo2curves::bn256::Fr;

use crate::poseidon::{self, T};
use crate::poseidon_chip::{PoseidonChip, PoseidonConfig};

pub const NUM_LIMBS: usize = 8; // 8 limbs * 8 bits = 64 bits
pub const LIMB_BITS: usize = 8;

/// A note in clear (witness data).
#[derive(Clone, Copy, Debug, Default)]
pub struct Note {
    pub value: u64,
    pub sk: Fr,
    pub rho: Fr,
}

impl Note {
    pub fn pk(&self) -> Fr {
        poseidon::hash2_native(self.sk, Fr::zero())
    }
    pub fn cm(&self) -> Fr {
        poseidon::hash3_native(Fr::from(self.value), self.pk(), self.rho)
    }
    pub fn nf(&self) -> Fr {
        poseidon::hash2_native(self.sk, self.rho)
    }
}

#[derive(Clone, Debug)]
pub struct SolitonConfig {
    /// Shared advice for Poseidon state + general assignment.
    pub adv: [Column<Advice>; T],
    /// Poseidon sub-chip.
    pub poseidon: PoseidonConfig,
    /// Range-check: limb advice column + fixed lookup table + selector.
    pub limb: Column<Advice>,
    pub table: TableColumn,
    pub q_lookup: Selector,
    /// Generic add gate: q_arith * (adv0 + adv1 - adv2) = 0.
    pub q_arith: Selector,
    /// Conditional-swap gate (booleanity + swap relation) over adv columns,
    /// rows 0 (cur,sib,bit) and 1 (left,right).
    pub q_swap: Selector,
    /// Constant-multiply gate: adv2 == const_mul * adv0  (limb weighting).
    pub q_mulc: Selector,
    /// Fixed column carrying the per-row multiply constant for q_mulc.
    pub mulc: Column<halo2_proofs::plonk::Fixed>,
    /// Public instance column.
    pub instance: Column<Instance>,
}

/// Merkle authentication path for one input note.
#[derive(Clone, Debug)]
pub struct MerklePath {
    pub siblings: Vec<Fr>,
    /// D path bits: false = current node is left child, true = right child.
    pub bits: Vec<bool>,
}

#[derive(Clone, Debug)]
pub struct SolitonCircuit {
    pub depth: usize,
    pub inputs: [Note; 2],
    pub paths: [MerklePath; 2],
    pub outputs: [Note; 2],
    pub pub_amount: u64,
    pub root: Fr,
    /// Negative-test hook: if `Some(j)`, output j's value CELL is forced to a
    /// non-64-bit field element (2^64) so the range gate must reject. None in
    /// all honest proofs.
    pub range_break: Option<usize>,
}

impl SolitonCircuit {
    /// Build the 6-element public instance vector in canonical order.
    pub fn instance(&self) -> Vec<Fr> {
        vec![
            self.root,
            self.inputs[0].nf(),
            self.inputs[1].nf(),
            self.outputs[0].cm(),
            self.outputs[1].cm(),
            Fr::from(self.pub_amount),
        ]
    }
}

impl Default for SolitonCircuit {
    fn default() -> Self {
        Self::dummy(4)
    }
}

impl SolitonCircuit {
    fn dummy(depth: usize) -> Self {
        Self {
            depth,
            inputs: [Note::default(); 2],
            paths: [
                MerklePath { siblings: vec![Fr::zero(); depth], bits: vec![false; depth] },
                MerklePath { siblings: vec![Fr::zero(); depth], bits: vec![false; depth] },
            ],
            outputs: [Note::default(); 2],
            pub_amount: 0,
            root: Fr::zero(),
            range_break: None,
        }
    }
}

impl Circuit<Fr> for SolitonCircuit {
    type Config = SolitonConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::dummy(self.depth)
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let adv: [Column<Advice>; T] = std::array::from_fn(|_| meta.advice_column());
        for c in adv.iter() {
            meta.enable_equality(*c);
        }

        let poseidon = PoseidonChip::configure(meta, adv);

        // Range-check lookup table column + complex selector.
        let limb = meta.advice_column();
        meta.enable_equality(limb);
        let table = meta.lookup_table_column();
        let q_lookup = meta.complex_selector();

        meta.lookup("limb in [0,2^8)", |meta| {
            let q = meta.query_selector(q_lookup);
            let v = meta.query_advice(limb, Rotation::cur());
            vec![(q * v, table)]
        });

        // Generic add gate: adv0 + adv1 = adv2.
        let q_arith = meta.selector();
        meta.create_gate("add: a0 + a1 = a2", |meta| {
            let q = meta.query_selector(q_arith);
            let a0 = meta.query_advice(adv[0], Rotation::cur());
            let a1 = meta.query_advice(adv[1], Rotation::cur());
            let a2 = meta.query_advice(adv[2], Rotation::cur());
            Constraints::with_selector(q, vec![a0 + a1 - a2])
        });

        // Conditional swap gate.
        // Row cur: adv0 = cur, adv1 = sib, adv2 = bit.
        // Row next: adv0 = left, adv1 = right.
        // Constraints (selector on cur row):
        //   bit*(bit-1) == 0                         (boolean)
        //   left  == cur + bit*(sib-cur)
        //   right == sib + bit*(cur-sib)
        let q_swap = meta.selector();
        meta.create_gate("conditional swap", |meta| {
            let q = meta.query_selector(q_swap);
            let cur = meta.query_advice(adv[0], Rotation::cur());
            let sib = meta.query_advice(adv[1], Rotation::cur());
            let bit = meta.query_advice(adv[2], Rotation::cur());
            let left = meta.query_advice(adv[0], Rotation::next());
            let right = meta.query_advice(adv[1], Rotation::next());

            let one = Expression::Constant(Fr::one());
            let boolean = bit.clone() * (bit.clone() - one);
            let left_ok = left - (cur.clone() + bit.clone() * (sib.clone() - cur.clone()));
            let right_ok = right - (sib.clone() + bit * (cur - sib));
            Constraints::with_selector(q, vec![boolean, left_ok, right_ok])
        });

        // Constant-multiply gate: adv2 == mulc * adv0.
        let mulc = meta.fixed_column();
        let q_mulc = meta.selector();
        meta.create_gate("const mul: a2 = k*a0", |meta| {
            let q = meta.query_selector(q_mulc);
            let a0 = meta.query_advice(adv[0], Rotation::cur());
            let a2 = meta.query_advice(adv[2], Rotation::cur());
            let k = meta.query_fixed(mulc, Rotation::cur());
            Constraints::with_selector(q, vec![a2 - k * a0])
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        SolitonConfig {
            adv,
            poseidon,
            limb,
            table,
            q_lookup,
            q_arith,
            q_swap,
            q_mulc,
            mulc,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: SolitonConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let chip = PoseidonChip::construct(config.poseidon.clone());

        // Load the fixed 0..2^8 lookup table.
        layouter.assign_table(
            || "u8 table",
            |mut table| {
                for i in 0..(1usize << LIMB_BITS) {
                    table.assign_cell(
                        || "u8 row",
                        config.table,
                        i,
                        || Value::known(Fr::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        // -- Input notes ----------------------------------------------------
        let mut input_nf_cells: Vec<AssignedCell<Fr, Fr>> = Vec::new();
        for i in 0..2 {
            let note = self.inputs[i];
            let (sk_cell, rho_cell, value_cell, zero_cell, cap_cell) =
                assign_note_scalars(&config, &mut layouter, note)?;

            // pk = H(sk, 0)
            let pk_cell = chip
                .permute(layouter.namespace(|| format!("pk_{i}")),
                         [cap_cell.clone(), sk_cell.clone(), zero_cell.clone()])?[0]
                .clone();

            // cm = H3(value, pk, rho)
            let cm_cell = hash3(&chip, &config, &mut layouter, &format!("cm_in_{i}"),
                                value_cell, pk_cell, rho_cell.clone())?;

            // Merkle path -> root, constrain == instance row 0.
            let computed_root = merkle_root(&chip, &config, &mut layouter,
                                            &format!("merkle_{i}"), cm_cell, &self.paths[i])?;
            layouter.constrain_instance(computed_root.cell(), config.instance, 0)?;

            // nf = H(sk, rho)
            let nf_cell = chip
                .permute(layouter.namespace(|| format!("nf_{i}")),
                         [cap_cell, sk_cell, rho_cell])?[0]
                .clone();
            input_nf_cells.push(nf_cell);
        }
        layouter.constrain_instance(input_nf_cells[0].cell(), config.instance, 1)?;
        layouter.constrain_instance(input_nf_cells[1].cell(), config.instance, 2)?;

        // -- Output notes ---------------------------------------------------
        let mut output_value_cells: Vec<AssignedCell<Fr, Fr>> = Vec::new();
        for j in 0..2 {
            let note = self.outputs[j];
            let (sk_cell, rho_cell, value_cell, zero_cell, cap_cell) =
                assign_note_scalars(&config, &mut layouter, note)?;

            let pk_cell = chip
                .permute(layouter.namespace(|| format!("pk_out_{j}")),
                         [cap_cell, sk_cell, zero_cell])?[0]
                .clone();

            let cmout_cell = hash3(&chip, &config, &mut layouter, &format!("cm_out_{j}"),
                                   value_cell.clone(), pk_cell, rho_cell)?;
            layouter.constrain_instance(cmout_cell.cell(), config.instance, 3 + j)?;

            // Honest path: range-check the real output value. Negative-test hook:
            // if range_break == Some(j), assign a fresh value cell holding 2^64
            // (a non-64-bit element) and range-check THAT — the limb recomposition
            // (built from the real u64) cannot equal it, so the range gate fails.
            if self.range_break == Some(j) {
                let bad = assign_scalar(&config, &mut layouter, &format!("bad_val_{j}"),
                                        Value::known(two_pow_64()))?;
                range_check_64(&config, &mut layouter, &format!("range_out_{j}"),
                               bad, note.value)?;
            } else {
                range_check_64(&config, &mut layouter, &format!("range_out_{j}"),
                               value_cell.clone(), note.value)?;
            }
            output_value_cells.push(value_cell);
        }

        // -- Balance --------------------------------------------------------
        let vin0 = assign_scalar(&config, &mut layouter, "vin0",
                                 Value::known(Fr::from(self.inputs[0].value)))?;
        let vin1 = assign_scalar(&config, &mut layouter, "vin1",
                                 Value::known(Fr::from(self.inputs[1].value)))?;
        let pub_amt = assign_scalar(&config, &mut layouter, "pub_amt",
                                    Value::known(Fr::from(self.pub_amount)))?;
        layouter.constrain_instance(pub_amt.cell(), config.instance, 5)?;

        let s1 = add_cells(&config, &mut layouter, "vin0+vin1", &vin0, &vin1)?;
        let lhs = add_cells(&config, &mut layouter, "+pub_amt", &s1, &pub_amt)?;
        let rhs = add_cells(&config, &mut layouter, "vout0+vout1",
                            &output_value_cells[0], &output_value_cells[1])?;
        layouter.assign_region(
            || "balance eq",
            |mut region| region.constrain_equal(lhs.cell(), rhs.cell()),
        )?;

        Ok(())
    }
}

/// 2^64 as an Fr (a non-64-bit element, used only by the range negative test).
fn two_pow_64() -> Fr {
    // 2^64 = 2^32 * 2^32.
    let p32 = Fr::from(1u64 << 32);
    p32 * p32
}

fn assign_scalar(
    config: &SolitonConfig,
    layouter: &mut impl Layouter<Fr>,
    name: &str,
    val: Value<Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    layouter.assign_region(
        || name.to_string(),
        |mut region| region.assign_advice(|| "v", config.adv[0], 0, || val),
    )
}

type NoteCells = (
    AssignedCell<Fr, Fr>,
    AssignedCell<Fr, Fr>,
    AssignedCell<Fr, Fr>,
    AssignedCell<Fr, Fr>,
    AssignedCell<Fr, Fr>,
);

fn assign_note_scalars(
    config: &SolitonConfig,
    layouter: &mut impl Layouter<Fr>,
    note: Note,
) -> Result<NoteCells, Error> {
    layouter.assign_region(
        || "note scalars",
        |mut region| {
            let sk = region.assign_advice(|| "sk", config.adv[0], 0, || Value::known(note.sk))?;
            let rho = region.assign_advice(|| "rho", config.adv[1], 0, || Value::known(note.rho))?;
            let value = region.assign_advice(|| "value", config.adv[2], 0,
                                             || Value::known(Fr::from(note.value)))?;
            let zero = region.assign_advice(|| "zero", config.adv[0], 1, || Value::known(Fr::zero()))?;
            // circom-BN254 domain tag is 0 (state = [0, in0, in1]).
            let cap = region.assign_advice(|| "cap0", config.adv[1], 1, || Value::known(Fr::zero()))?;
            Ok((sk, rho, value, zero, cap))
        },
    )
}

/// H3(a,b,c) = H2(H2(a,b), c) using the width-3 2-to-1 permutation (circom
/// domain tag = 0).
fn hash3(
    chip: &PoseidonChip,
    config: &SolitonConfig,
    layouter: &mut impl Layouter<Fr>,
    name: &str,
    a: AssignedCell<Fr, Fr>,
    b: AssignedCell<Fr, Fr>,
    c: AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let inner = hash2(chip, config, layouter, &format!("{name}_h2a"), a, b)?;
    hash2(chip, config, layouter, &format!("{name}_h2b"), inner, c)
}

/// H2(a,b) given two cells: permute [domain_tag=0, a, b], squeeze lane 0.
fn hash2(
    chip: &PoseidonChip,
    config: &SolitonConfig,
    layouter: &mut impl Layouter<Fr>,
    name: &str,
    a: AssignedCell<Fr, Fr>,
    b: AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let cap = assign_scalar(config, layouter, &format!("{name}_cap"), Value::known(Fr::zero()))?;
    let out = chip.permute(layouter.namespace(|| name.to_string()), [cap, a, b])?;
    Ok(out[0].clone())
}

/// Compute Merkle root from a leaf up the path, conditionally swapping by bit.
fn merkle_root(
    chip: &PoseidonChip,
    config: &SolitonConfig,
    layouter: &mut impl Layouter<Fr>,
    name: &str,
    leaf: AssignedCell<Fr, Fr>,
    path: &MerklePath,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let mut cur = leaf;
    for (lvl, (sib, bit)) in path.siblings.iter().zip(path.bits.iter()).enumerate() {
        let b_val = if *bit { Fr::one() } else { Fr::zero() };
        let (left, right) = layouter.assign_region(
            || format!("{name}_swap_{lvl}"),
            |mut region| {
                config.q_swap.enable(&mut region, 0)?;
                let cur_in = cur.copy_advice(|| "cur", &mut region, config.adv[0], 0)?;
                region.assign_advice(|| "sib", config.adv[1], 0, || Value::known(*sib))?;
                region.assign_advice(|| "bit", config.adv[2], 0, || Value::known(b_val))?;

                let cur_v = cur_in.value().copied();
                let sib_v = Value::known(*sib);
                let bv = Value::known(b_val);
                let left_v = cur_v + bv * (sib_v - cur_v);
                let right_v = sib_v + bv * (cur_v - sib_v);

                let left = region.assign_advice(|| "left", config.adv[0], 1, || left_v)?;
                let right = region.assign_advice(|| "right", config.adv[1], 1, || right_v)?;
                Ok((left, right))
            },
        )?;
        cur = hash2(chip, config, layouter, &format!("{name}_h_{lvl}"), left, right)?;
    }
    Ok(cur)
}

/// Range-check `value_cell` is 64-bit: decompose into 8 limbs of 8 bits, lookup
/// each limb in u8 table, bind each weighted term via const-mul gate, and
/// constrain the recomposition equals the value.
fn range_check_64(
    config: &SolitonConfig,
    layouter: &mut impl Layouter<Fr>,
    name: &str,
    value_cell: AssignedCell<Fr, Fr>,
    value: u64,
) -> Result<(), Error> {
    let limbs: [u64; NUM_LIMBS] = std::array::from_fn(|k| (value >> (8 * k)) & 0xff);

    // Assign + lookup each limb.
    let limb_cells = layouter.assign_region(
        || format!("{name}_limbs"),
        |mut region| {
            let mut cells = Vec::with_capacity(NUM_LIMBS);
            for (k, &lv) in limbs.iter().enumerate() {
                config.q_lookup.enable(&mut region, k)?;
                let c = region.assign_advice(|| "limb", config.limb, k, || Value::known(Fr::from(lv)))?;
                cells.push(c);
            }
            Ok(cells)
        },
    )?;

    // Weighted recomposition with binding const-mul gate + add chain.
    let mut acc = assign_scalar(config, layouter, &format!("{name}_acc0"), Value::known(Fr::zero()))?;
    for k in 0..NUM_LIMBS {
        let weight = Fr::from(1u64 << (8 * k));
        // w = weight * limb, enforced by q_mulc: adv2 == mulc * adv0.
        let w = layouter.assign_region(
            || format!("{name}_w_{k}"),
            |mut region| {
                config.q_mulc.enable(&mut region, 0)?;
                region.assign_fixed(|| "k", config.mulc, 0, || Value::known(weight))?;
                let limb_copy = limb_cells[k].copy_advice(|| "limb", &mut region, config.adv[0], 0)?;
                let w_val = limb_copy.value().map(|lv| weight * *lv);
                let w_cell = region.assign_advice(|| "w", config.adv[2], 0, || w_val)?;
                Ok(w_cell)
            },
        )?;
        acc = add_cells(config, layouter, &format!("{name}_acc_{k}"), &acc, &w)?;
    }
    layouter.assign_region(
        || format!("{name}_recompose_eq"),
        |mut region| region.constrain_equal(acc.cell(), value_cell.cell()),
    )?;
    Ok(())
}

/// c = a + b via the add gate.
fn add_cells(
    config: &SolitonConfig,
    layouter: &mut impl Layouter<Fr>,
    name: &str,
    a: &AssignedCell<Fr, Fr>,
    b: &AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    layouter.assign_region(
        || name.to_string(),
        |mut region| {
            config.q_arith.enable(&mut region, 0)?;
            let a_c = a.copy_advice(|| "a", &mut region, config.adv[0], 0)?;
            let b_c = b.copy_advice(|| "b", &mut region, config.adv[1], 0)?;
            let c_val = a_c.value().copied() + b_c.value().copied();
            region.assign_advice(|| "c", config.adv[2], 0, || c_val)
        },
    )
}
