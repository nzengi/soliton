//! Off-chain proving pipeline for SOLITON-Pay.
//!
//! Two transcript paths:
//!   * `prove_and_verify` — original Blake2b path (kept for B1 regression tests).
//!   * `prove_keccak`     — Keccak-BE (EVM-style) transcript that the on-chain
//!     `halo2_solana_verifier` consumes. Self-verifies with KeccakBeRead, then
//!     produces (proof_bytes, vk_bytes, kzg_vk) for the sound verifier.

use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2curves::bn256::{Bn256, Fr, G1Affine, G2Affine};
use rand::rngs::StdRng;
use rand_core::SeedableRng;

use crate::keccak_be_transcript::{KeccakBeRead, KeccakBeWrite};
use crate::witness::build_satisfying;

/// Artifacts returned by the full prove+verify pipeline.
pub struct ProofArtifacts {
    pub proof_bytes: Vec<u8>,
    /// On-chain VK blob from vk-host's `compile_vk`, if it succeeded.
    pub vk_bytes: Option<Vec<u8>>,
    pub vk_note: String,
    pub public_inputs: Vec<Fr>,
    pub k: u32,
    pub proof_len: usize,
    pub halo2_vk: VerifyingKey<G1Affine>,
}

/// Build a satisfying SOLITON-Pay witness of Merkle depth `depth`, prove it with
/// SHPLONK + Blake2b transcript, and self-verify. Returns artifacts on success.
pub fn prove_and_verify(k: u32, depth: usize, seed: [u8; 32]) -> Result<ProofArtifacts, anyhow::Error> {
    let mut rng = StdRng::from_seed(seed);

    let circuit = build_satisfying(depth, seed);
    let public_inputs = circuit.instance();

    // 1. KZG params.
    let params: ParamsKZG<Bn256> = ParamsKZG::<Bn256>::setup(k, &mut rng);

    // 2. Keygen.
    let vk: VerifyingKey<G1Affine> =
        keygen_vk(&params, &circuit).map_err(|e| anyhow::anyhow!("keygen_vk: {e:?}"))?;
    let pk: ProvingKey<G1Affine> =
        keygen_pk(&params, vk.clone(), &circuit).map_err(|e| anyhow::anyhow!("keygen_pk: {e:?}"))?;

    // 3. Try compile_vk (vk-host) for an on-chain VK blob.
    let (vk_bytes, vk_note) = match halo2_solana_vk_host::compile_vk(&params, &vk) {
        Ok(b) => (Some(b), "compile_vk: OK".to_string()),
        Err(e) => (None, format!("compile_vk: skipped ({e:?})")),
    };

    // 4. Create proof (SHPLONK, Blake2b transcript).
    let instances: &[&[Fr]] = &[&public_inputs];
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[instances],
        &mut rng,
        &mut transcript,
    )
    .map_err(|e| anyhow::anyhow!("create_proof: {e:?}"))?;
    let proof_bytes = transcript.finalize();
    let proof_len = proof_bytes.len();

    // 5. Verify proof (SingleStrategy).
    let pv: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
    let mut tr = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof_bytes.as_slice());
    let strategy = SingleStrategy::new(&pv);
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
        &pv,
        &vk,
        strategy,
        &[instances],
        &mut tr,
    )
    .map_err(|e| anyhow::anyhow!("verify_proof: {e:?}"))?;

    Ok(ProofArtifacts {
        proof_bytes,
        vk_bytes,
        vk_note,
        public_inputs,
        k,
        proof_len,
        halo2_vk: vk,
    })
}

/// Artifacts for the Keccak-BE / on-chain verifier path.
pub struct KeccakArtifacts {
    pub proof_bytes: Vec<u8>,
    /// v2 (generic) on-chain VK blob.
    pub vk_bytes: Vec<u8>,
    pub public_inputs: Vec<Fr>,
    pub k: u32,
    /// KZG verifying SRS pieces, BE-encoded for the on-chain verifier.
    pub g1_one_be: [u8; 64],
    pub g2_one_be: [u8; 128],
    pub g2_tau_be: [u8; 128],
    pub halo2_vk: VerifyingKey<G1Affine>,
}

/// Prove SOLITON-Pay with the Keccak-BE transcript, self-verify with the matching
/// reader, and emit the v2 VK + KZG pieces consumed by the sound verifier.
pub fn prove_keccak(
    k: u32,
    depth: usize,
    seed: [u8; 32],
) -> Result<KeccakArtifacts, anyhow::Error> {
    prove_keccak_circuit(k, build_satisfying(depth, seed), seed)
}

/// Prove a transfer (Stage 2). Builds the circuit from input/output
/// notes via `witness::build_transfer_circuit` (which asserts the Merkle paths
/// reproduce `root`), proves it with the Keccak-BE transcript, self-verifies,
/// and returns the on-chain-verifier artifacts.
pub fn prove_transfer(
    k: u32,
    inputs: [crate::witness::InputNote; 2],
    outputs: [crate::witness::OutputNote; 2],
    pub_amount: i128,
    root: Fr,
    depth: usize,
    seed: [u8; 32],
) -> Result<KeccakArtifacts, anyhow::Error> {
    let (circuit, _instance) =
        crate::witness::build_transfer_circuit(inputs, outputs, pub_amount, root, depth);
    prove_keccak_circuit(k, circuit, seed)
}

/// Same as `prove_keccak` but with a caller-supplied circuit + explicit instance
/// vector (so negative tests can prove an UNSATISFIED instance — which halo2
/// will reject, so callers should only feed satisfiable circuits here and tamper
/// the resulting bytes / public inputs afterwards).
pub fn prove_keccak_circuit(
    k: u32,
    circuit: crate::circuit::SolitonCircuit,
    seed: [u8; 32],
) -> Result<KeccakArtifacts, anyhow::Error> {
    let mut rng = StdRng::from_seed(seed);
    let public_inputs = circuit.instance();

    let params: ParamsKZG<Bn256> = ParamsKZG::<Bn256>::setup(k, &mut rng);

    let vk: VerifyingKey<G1Affine> =
        keygen_vk(&params, &circuit).map_err(|e| anyhow::anyhow!("keygen_vk: {e:?}"))?;
    let pk: ProvingKey<G1Affine> =
        keygen_pk(&params, vk.clone(), &circuit).map_err(|e| anyhow::anyhow!("keygen_pk: {e:?}"))?;

    let vk_bytes = halo2_solana_vk_host::compile_vk_generic(&params, &vk)
        .map_err(|e| anyhow::anyhow!("compile_vk_generic: {e:?}"))?;

    // Create proof with Keccak-BE transcript.
    let instances: &[&[Fr]] = &[&public_inputs];
    let mut writer: Vec<u8> = Vec::new();
    {
        let mut transcript: KeccakBeWrite<&mut Vec<u8>, _, _> = KeccakBeWrite::init(&mut writer);
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[instances],
            &mut rng,
            &mut transcript,
        )
        .map_err(|e| anyhow::anyhow!("create_proof(keccak): {e:?}"))?;
        let _: &mut Vec<u8> = transcript.finalize();
    }
    let proof_bytes = writer;

    // Self-verify with KeccakBeRead — authoritative internal-consistency check.
    {
        let pv: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
        let mut tr: KeccakBeRead<&[u8], _, _> = KeccakBeRead::init(proof_bytes.as_slice());
        let strategy = SingleStrategy::new(&pv);
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &pv,
            &vk,
            strategy,
            &[instances],
            &mut tr,
        )
        .map_err(|e| anyhow::anyhow!("halo2 self-verify (KeccakBe): {e:?}"))?;
    }

    // KZG verifying SRS pieces.
    let g1_one_be = g1_affine_to_bytes_be(&params.get_g()[0]);
    let g2_one_be = g2_affine_to_bytes_be(&params.g2());
    let g2_tau_be = g2_affine_to_bytes_be(&params.s_g2());

    Ok(KeccakArtifacts {
        proof_bytes,
        vk_bytes,
        public_inputs,
        k,
        g1_one_be,
        g2_one_be,
        g2_tau_be,
        halo2_vk: vk,
    })
}

fn g1_affine_to_bytes_be(p: &G1Affine) -> [u8; 64] {
    use halo2curves::ff::PrimeField;
    use halo2curves::group::prime::PrimeCurveAffine;
    let mut out = [0u8; 64];
    if bool::from(p.is_identity()) {
        return out;
    }
    let mut x = p.x.to_repr();
    let mut y = p.y.to_repr();
    x.as_mut().reverse();
    y.as_mut().reverse();
    out[..32].copy_from_slice(x.as_ref());
    out[32..].copy_from_slice(y.as_ref());
    out
}

fn g2_affine_to_bytes_be(p: &G2Affine) -> [u8; 128] {
    use halo2curves::ff::PrimeField;
    use halo2curves::group::prime::PrimeCurveAffine;
    let mut out = [0u8; 128];
    if bool::from(p.is_identity()) {
        return out;
    }
    let mut x1 = p.x.c1.to_repr();
    x1.as_mut().reverse();
    let mut x0 = p.x.c0.to_repr();
    x0.as_mut().reverse();
    let mut y1 = p.y.c1.to_repr();
    y1.as_mut().reverse();
    let mut y0 = p.y.c0.to_repr();
    y0.as_mut().reverse();
    out[..32].copy_from_slice(x1.as_ref());
    out[32..64].copy_from_slice(x0.as_ref());
    out[64..96].copy_from_slice(y1.as_ref());
    out[96..].copy_from_slice(y0.as_ref());
    out
}
