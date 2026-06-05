//! CORRECTNESS GATE (Step 0): the shared no_std Poseidon crate
//! (`soliton-poseidon`, ark-bn254) must produce BYTE-IDENTICAL hashes to the
//! circuit's native Poseidon (`soliton_pay::poseidon`, halo2curves). If these
//! ever diverge, on-chain Merkle membership proofs will not verify.
//!
//! We compare the 32-byte little-endian field encodings of:
//!   * the round constants + MDS (the generation must match),
//!   * H2, H3 on shared inputs,
//!   * a full note commitment `cm = H3(value, H2(sk,0), rho)`,
//!   * a nullifier `nf = H2(sk, rho)`,
//!   * an empty-subtree root chain and a 2-leaf parent (Merkle node).
//!
//! Run: `cargo test -p soliton-pay --test poseidon_equivalence -- --nocapture`

use ark_ff::{BigInteger, PrimeField as ArkPrime};
use halo2curves::bn256::Fr as HFr;
use halo2curves::ff::PrimeField as HPrime;

use soliton_pay::poseidon as circ; // circuit's native (halo2curves)
use soliton_poseidon as shared; // shared crate (ark-bn254)

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use soliton_pay::poseidon_chip::{PoseidonChip, PoseidonConfig};

/// Convert an ark `Fr` to a halo2curves `HFr` via the canonical 32-LE repr.
fn ark_to_h(f: &ark_bn254::Fr) -> HFr {
    let mut repr = <HFr as HPrime>::Repr::default();
    repr.as_mut().copy_from_slice(&a_le(f));
    HFr::from_repr(repr).unwrap()
}

/// halo2curves Fr -> 32 LE bytes.
fn h_le(f: &HFr) -> [u8; 32] {
    let r = f.to_repr(); // LE
    let mut out = [0u8; 32];
    out.copy_from_slice(r.as_ref());
    out
}

/// ark Fr -> 32 LE bytes.
fn a_le(f: &ark_bn254::Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let v = f.into_bigint().to_bytes_le();
    out[..v.len()].copy_from_slice(&v);
    out
}

fn hfr(n: u64) -> HFr {
    HFr::from(n)
}
fn afr(n: u64) -> ark_bn254::Fr {
    ark_bn254::Fr::from(n)
}

#[test]
fn constants_match() {
    // Round constants (circom `ark` table).
    let rc = circ::round_constants();
    for (round, row) in rc.iter().enumerate() {
        for (i, e) in row.iter().enumerate() {
            assert_eq!(
                h_le(e),
                shared::ARK_LE[round][i],
                "ARK mismatch at [{round}][{i}]"
            );
        }
    }
    // MDS.
    let m = circ::mds();
    for (i, row) in m.iter().enumerate() {
        for (j, e) in row.iter().enumerate() {
            assert_eq!(h_le(e), shared::MDS_LE[i][j], "MDS mismatch at [{i}][{j}]");
        }
    }
    eprintln!("OK: round constants + MDS byte-identical (circuit == shared crate)");
}

#[test]
fn h2_h3_match() {
    let cases = [(1u64, 2u64), (0, 0), (12345, 67890), (0xE9E9_E9E9, 0xE9E9_E9E9)];
    for (a, b) in cases {
        let c_h2 = h_le(&circ::hash2_native(hfr(a), hfr(b)));
        let s_h2 = a_le(&shared::hash2(afr(a), afr(b)));
        assert_eq!(c_h2, s_h2, "H2({a},{b}) mismatch");
    }
    for (a, b, c) in [(1u64, 2u64, 3u64), (100, 200, 300), (0, 0, 0)] {
        let c_h3 = h_le(&circ::hash3_native(hfr(a), hfr(b), hfr(c)));
        let s_h3 = a_le(&shared::hash3(afr(a), afr(b), afr(c)));
        assert_eq!(c_h3, s_h3, "H3({a},{b},{c}) mismatch");
    }
    eprintln!("OK: H2 + H3 byte-identical across libraries");
}

#[test]
fn note_commitment_and_nullifier_match() {
    // Build a note commitment + nullifier both ways and compare bytes.
    let value = 1_000_000u64;
    let sk = 424242u64;
    let rho = 777u64;

    // Circuit side: pk = H2(sk,0); cm = H3(value, pk, rho); nf = H2(sk, rho).
    let c_pk = circ::hash2_native(hfr(sk), HFr::from(0u64));
    let c_cm = circ::hash3_native(hfr(value), c_pk, hfr(rho));
    let c_nf = circ::hash2_native(hfr(sk), hfr(rho));

    // Shared side via the note helpers.
    let s_cm = shared::commitment(value, afr(sk), afr(rho));
    let s_nf = shared::note_nf(afr(sk), afr(rho));

    assert_eq!(h_le(&c_cm), a_le(&s_cm), "commitment bytes differ");
    assert_eq!(h_le(&c_nf), a_le(&s_nf), "nullifier bytes differ");
    eprintln!("OK: note commitment + nullifier byte-identical");
}

#[test]
fn empty_subtree_and_merkle_node_match() {
    // Empty-leaf sentinel and the empty-subtree chain up to depth 32.
    let c_empty0 = HFr::from(0xE9E9_E9E9u64);
    let s_empty0 = shared::empty_leaf();
    assert_eq!(h_le(&c_empty0), a_le(&s_empty0));

    let mut c = c_empty0;
    for level in 1..=32usize {
        c = circ::hash2_native(c, c);
        let s = shared::empty_subtree_root(level);
        assert_eq!(h_le(&c), a_le(&s), "empty subtree root mismatch at level {level}");
    }

    // A 2-leaf parent node H2(cmA, cmB).
    let cm_a = circ::hash3_native(hfr(100), circ::hash2_native(hfr(7), HFr::from(0u64)), hfr(9));
    let cm_b = circ::hash3_native(hfr(50), circ::hash2_native(hfr(8), HFr::from(0u64)), hfr(11));
    let c_node = circ::hash2_native(cm_a, cm_b);

    let s_a = shared::commitment(100, afr(7), afr(9));
    let s_b = shared::commitment(50, afr(8), afr(11));
    let s_node = shared::hash2(s_a, s_b);
    assert_eq!(h_le(&c_node), a_le(&s_node), "merkle parent node mismatch");
    eprintln!("OK: empty-subtree chain (depth 32) + Merkle parent byte-identical");
}

// ---- the IN-CIRCUIT chip computes the circom hash ----------------------------

/// Minimal circuit that runs the `PoseidonChip` on inputs [0, a, b] and
/// exposes lane 0 of the permutation output as a public instance. If MockProver
/// is satisfied for a given instance, the chip's in-circuit hash EQUALS that
/// instance value. We feed the light-poseidon value as the instance, so a
/// passing prover proves the in-circuit hash == light-poseidon byte-for-byte.
#[derive(Clone, Default)]
struct Hash2Circuit {
    a: Value<HFr>,
    b: Value<HFr>,
}

#[derive(Clone)]
struct Hash2Config {
    poseidon: PoseidonConfig,
    state: [Column<halo2_proofs::plonk::Advice>; 3],
    instance: Column<Instance>,
}

impl Circuit<HFr> for Hash2Circuit {
    type Config = Hash2Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<HFr>) -> Self::Config {
        let state = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        for c in state.iter() {
            meta.enable_equality(*c);
        }
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let poseidon = PoseidonChip::configure(meta, state);
        Hash2Config { poseidon, state, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<HFr>,
    ) -> Result<(), Error> {
        let chip = PoseidonChip::construct(config.poseidon.clone());

        // Assign [domain_tag=0, a, b] as the initial state.
        let (cap, a, b) = layouter.assign_region(
            || "inputs",
            |mut region| {
                let cap = region.assign_advice(
                    || "cap0",
                    config.state[0],
                    0,
                    || Value::known(HFr::zero()),
                )?;
                let a = region.assign_advice(|| "a", config.state[1], 0, || self.a)?;
                let b = region.assign_advice(|| "b", config.state[2], 0, || self.b)?;
                Ok((cap, a, b))
            },
        )?;

        let out = chip.permute(layouter.namespace(|| "permute"), [cap, a, b])?;
        layouter.constrain_instance(out[0].cell(), config.instance, 0)?;
        Ok(())
    }
}

#[test]
fn in_circuit_chip_equals_light_poseidon() {
    use light_poseidon::{Poseidon, PoseidonHasher};

    let cases: [(u64, u64); 5] =
        [(1, 2), (12345, 67890), (0xE9E9_E9E9, 0xE9E9_E9E9), (424242, 777), (0, 0)];

    for (a, b) in cases {
        // light-poseidon reference (ark).
        let mut lp = Poseidon::<ark_bn254::Fr>::new_circom(2).unwrap();
        let want_ark = lp.hash(&[afr(a), afr(b)]).unwrap();
        let want_h = ark_to_h(&want_ark);

        let circuit = Hash2Circuit { a: Value::known(hfr(a)), b: Value::known(hfr(b)) };

        // SAT: instance = light-poseidon value => in-circuit chip output equals it.
        let prover = MockProver::run(7, &circuit, vec![vec![want_h]]).unwrap();
        prover
            .verify()
            .unwrap_or_else(|e| panic!("in-circuit hash2({a},{b}) != light-poseidon: {e:?}"));

        // UNSAT: a wrong instance must fail (confirms the constraint is live).
        let wrong = want_h + HFr::one();
        let bad = MockProver::run(7, &circuit, vec![vec![wrong]]).unwrap();
        assert!(bad.verify().is_err(), "tampered instance unexpectedly accepted");

        // Also confirm the shared crate agrees with light-poseidon (already
        // checked in the crate's own tests, re-checked here for the report).
        assert_eq!(a_le(&shared::hash2(afr(a), afr(b))), a_le(&want_ark));
    }
    eprintln!("OK: IN-CIRCUIT PoseidonChip == light-poseidon == shared (byte-identical)");
}
