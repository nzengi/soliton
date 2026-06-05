//! In-circuit Poseidon (width 3, x^5 S-box) matching `poseidon::permute_native`.
//!
//! Layout: one row per round. Three advice columns hold the round-input state
//! (s0,s1,s2) at the current row; the NEXT row's (s0,s1,s2) hold the round
//! output. A fixed "full/partial" selector column `is_full` tells the gate
//! whether all three lanes get the S-box (full round) or only lane 0 (partial).
//! Three fixed columns carry the per-row round constants. The MDS matrix is a
//! compile-time constant baked into the gate.
//!
//! Round relation (matching native order: add RC -> S-box -> MDS):
//!   let a_i = s_i + rc_i
//!   let b_i = (full || i==0) ? a_i^5 : a_i
//!   next_j  = sum_i MDS[j][i] * b_i
//!
//! The gate constrains next_j (queried at Rotation::next) to equal the MDS image
//! of the post-S-box vector. After ROUNDS rows the final row holds the
//! permutation output; we expose its lane 0 as the hash and copy it out.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

use crate::poseidon::{self, R_F, R_P, ROUNDS, T};

#[derive(Clone, Debug)]
pub struct PoseidonConfig {
    pub state: [Column<Advice>; T],
    pub rc: [Column<Fixed>; T],
    pub is_full: Column<Fixed>,
    pub q_round: Selector,
}

#[derive(Clone, Debug)]
pub struct PoseidonChip {
    config: PoseidonConfig,
}

impl PoseidonChip {
    pub fn construct(config: PoseidonConfig) -> Self {
        Self { config }
    }

    /// Configure the chip. Caller passes 3 advice columns (equality-enabled by
    /// caller) to reuse across the circuit, plus dedicated fixed columns.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        state: [Column<Advice>; T],
    ) -> PoseidonConfig {
        let rc: [Column<Fixed>; T] = std::array::from_fn(|_| meta.fixed_column());
        let is_full = meta.fixed_column();
        let q_round = meta.selector();

        for c in state.iter() {
            meta.enable_equality(*c);
        }

        let mds = poseidon::mds();

        meta.create_gate("poseidon round", |meta| {
            let q = meta.query_selector(q_round);
            let is_full_e = meta.query_fixed(is_full, Rotation::cur());

            // pow5 helper as Expression.
            let pow5 = |x: Expression<Fr>| -> Expression<Fr> {
                let x2 = x.clone() * x.clone();
                let x4 = x2.clone() * x2;
                x4 * x
            };

            // a_i = s_i + rc_i
            let mut a = Vec::with_capacity(T);
            for i in 0..T {
                let s = meta.query_advice(state[i], Rotation::cur());
                let r = meta.query_fixed(rc[i], Rotation::cur());
                a.push(s + r);
            }

            // b_i : lane 0 always S-boxed; lanes 1,2 S-boxed iff full round.
            // b_i = is_full * a_i^5 + (1-is_full) * a_i   for i in {1,2}
            // b_0 = a_0^5  always.
            let one = Expression::Constant(Fr::one());
            let mut b = Vec::with_capacity(T);
            b.push(pow5(a[0].clone()));
            for i in 1..T {
                let full_term = is_full_e.clone() * pow5(a[i].clone());
                let lin_term = (one.clone() - is_full_e.clone()) * a[i].clone();
                b.push(full_term + lin_term);
            }

            // next_j = sum_i MDS[j][i] * b_i, constrained == advice next.
            let mut constraints = Vec::with_capacity(T);
            for j in 0..T {
                let mut acc = Expression::Constant(Fr::zero());
                for i in 0..T {
                    acc = acc + Expression::Constant(mds[j][i]) * b[i].clone();
                }
                let next = meta.query_advice(state[j], Rotation::next());
                constraints.push(next - acc);
            }

            Constraints::with_selector(q, constraints)
        });

        PoseidonConfig {
            state,
            rc,
            is_full,
            q_round,
        }
    }

    /// Assign a full permutation given the three initial-state values (as
    /// already-assigned cells from somewhere, or freshly assigned). Returns the
    /// three output cells (final row state). The caller squeezes lane 0.
    ///
    /// `inputs` are Values for the three initial lanes. We assign the initial
    /// row fresh; copy constraints to bind inputs are the caller's job via the
    /// returned... actually we accept already-assigned cells and copy them in.
    pub fn permute(
        &self,
        mut layouter: impl Layouter<Fr>,
        inputs: [AssignedCell<Fr, Fr>; T],
    ) -> Result<[AssignedCell<Fr, Fr>; T], Error> {
        let cfg = &self.config;
        let rc = poseidon::round_constants();
        let mds = poseidon::mds();
        let half_full = R_F / 2;

        layouter.assign_region(
            || "poseidon permutation",
            |mut region: Region<Fr>| {
                // Row 0: copy inputs into state columns.
                let mut cur: [AssignedCell<Fr, Fr>; T] = [
                    inputs[0].copy_advice(|| "in0", &mut region, cfg.state[0], 0)?,
                    inputs[1].copy_advice(|| "in1", &mut region, cfg.state[1], 0)?,
                    inputs[2].copy_advice(|| "in2", &mut region, cfg.state[2], 0)?,
                ];

                // Native running state to compute witness for each next row.
                let mut native: [Value<Fr>; T] =
                    [cur[0].value().copied(), cur[1].value().copied(), cur[2].value().copied()];

                for round in 0..ROUNDS {
                    let is_full = round < half_full || round >= half_full + R_P;
                    // enable selector + assign fixed for THIS row.
                    cfg.q_round.enable(&mut region, round)?;
                    region.assign_fixed(
                        || "is_full",
                        cfg.is_full,
                        round,
                        || Value::known(if is_full { Fr::one() } else { Fr::zero() }),
                    )?;
                    for i in 0..T {
                        region.assign_fixed(
                            || "rc",
                            cfg.rc[i],
                            round,
                            || Value::known(rc[round][i]),
                        )?;
                    }

                    // Compute next native state.
                    let a: [Value<Fr>; T] =
                        std::array::from_fn(|i| native[i] + Value::known(rc[round][i]));
                    let b: [Value<Fr>; T] = std::array::from_fn(|i| {
                        if is_full || i == 0 {
                            a[i].map(|x| {
                                let x2 = x.square();
                                let x4 = x2.square();
                                x4 * x
                            })
                        } else {
                            a[i]
                        }
                    });
                    let next: [Value<Fr>; T] = std::array::from_fn(|j| {
                        let mut acc = Value::known(Fr::zero());
                        for i in 0..T {
                            acc = acc + b[i].map(|bv| mds[j][i] * bv);
                        }
                        acc
                    });

                    // Assign next row state advice.
                    let next_cells: [AssignedCell<Fr, Fr>; T] = [
                        region.assign_advice(|| "s0", cfg.state[0], round + 1, || next[0])?,
                        region.assign_advice(|| "s1", cfg.state[1], round + 1, || next[1])?,
                        region.assign_advice(|| "s2", cfg.state[2], round + 1, || next[2])?,
                    ];
                    native = next;
                    cur = next_cells;
                }

                Ok(cur)
            },
        )
    }
}

/// Convenience: assign three constants/witnesses then permute — but in this
/// circuit we always feed already-assigned cells, so this is the canonical path.
pub fn hash2_chip(
    chip: &PoseidonChip,
    layouter: impl Layouter<Fr>,
    cap: AssignedCell<Fr, Fr>,
    a: AssignedCell<Fr, Fr>,
    b: AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let out = chip.permute(layouter, [cap, a, b])?;
    Ok(out[0].clone())
}
