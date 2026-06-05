//! SOLITON-Pay: a real, sound 2-input / 2-output single-asset shielded payment
//! circuit on PSE-halo2 (BN254, KZG/SHPLONK), stage B1 (off-chain prover).
//!
//! Note model:
//!  - spending key `sk` -> `pk = H(sk, 0)`
//!  - note = (value, pk_owner, rho); commitment `cm = H3(value, pk_owner, rho)`
//!  - nullifier `nf = H(sk, rho)`
//!  - Merkle tree of commitments, internal node = H(left, right), depth D.
//!
//! Hash H = a self-contained width-3 x^5 Poseidon (see `poseidon` module for why
//! a custom chip rather than `halo2_gadgets`). H3 is built as H2(H2(a,b),c).

pub mod circuit;
pub mod keccak_be_transcript;
pub mod poseidon;
pub mod poseidon_chip;
pub mod prover;
pub mod witness;

pub use circuit::{Note, SolitonCircuit};
pub use prover::{prove_and_verify, ProofArtifacts};
