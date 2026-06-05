# SOLITON Protocol

Native-PLONK shielded payments verified on Solana — no Groth16 wrap.

## Status

Devnet-proven. A real SOLITON-Pay proof verifies on-chain inside Solana's
1.4M compute-unit per-transaction ceiling.

| | |
|---|---|
| Program ID | `Gu2NbGsGwmo5BsB3j4keb2SMUiTkMYuqXAYLRcuj2Fn2` |
| Verify tx | `3Cg4P5ppJ3uq6Wa1RZ63zHVg8BGCZrqy8G9e2f44LTpFVoYqjjHQuGGu9saqBWtnX65hF2QwSjiy5gkSE9cyPXC9` |
| On-chain CU | 1,344,997 (< 1.4M) |

Protocol spec: [`docs/SOLITON-spec-v1.0.md`](docs/SOLITON-spec-v1.0.md).

## What it is

A 2-in / 2-out shielded payment over a Merkle tree of depth 32. The statement
is proven with a PLONKish circuit using KZG/BN254 commitments and the SHPLONK
multi-opening argument, and verified by a sound on-chain verifier at 1.34M CU.
To my knowledge, prior zk work on Solana (groth16-solana, sp1-solana,
risc0-solana, and Light Protocol) wraps down to Groth16 before verifying;
SOLITON verifies the halo2 proof natively. That native path costs more compute
(~1.34M CU vs a few hundred thousand for a Groth16 verify) — a deliberate
trade, not a free lunch. See the spec's positioning section for the comparison.

## Honest status caveats

This is a devnet proof-of-concept. It is NOT safe for real value:

- **Test SRS.** The KZG parameters come from `ParamsKZG::setup`, whose toxic
  waste is known. A production deployment needs a real trusted setup (or a
  transparent alternative). Anyone holding the setup randomness can forge proofs.
- **~100-bit security.** BN254 offers roughly 100 bits of security, below the
  128-bit bar expected for high-value systems.
- **No audit.** The circuit and verifier have not been audited.
- **Single-asset.** Only one asset type is supported.

## Repository layout

The protocol:

| Path | Role |
|---|---|
| `crates/verifier` (`halo2-solana-verifier`) | no_std BN254/KZG/SHPLONK verifier; `verify_generic` (AST-driven) and `verify_specialized` (straight-line) |
| `crates/vk-host` | host-side compiler: halo2 verifying key → flat on-chain VK bytes (`compile_vk_generic`) |
| `circuits/soliton-pay` | SOLITON-Pay circuit + prover (`prove_keccak`) |
| `programs/soliton-verifier` | on-chain BPF program running the sound verifier |
| `programs/soliton-probe` | field/group-op CU probe (the per-op unit costs the budget is built from) |
| `clients/soliton-cli` (`soliton`) | devnet client: stage proof blob, verify on-chain, report CU |
| `docs/SOLITON-spec-v1.0.md` | protocol specification |

Supporting material (not part of the protocol — the StandardPlonk verifier this
grew out of):

| Path | Role |
|---|---|
| `circuits/standard-plonk`, `programs/verifier-program`, `clients/devnet-send` | the earlier StandardPlonk verifier + its devnet client |

## Build & test

```bash
# Host build of the whole workspace.
cargo build --workspace

# Specialized path is bit-identical to the generic oracle.
cargo test -p soliton-pay --test specialized_equiv -- --nocapture

# Real proof accepts; tampered proof rejects.
cargo test -p soliton-pay --test soliton_accept -- --nocapture

# Verifier crate unit tests.
cargo test -p halo2-solana-verifier --features "std,solana-syscalls"

# On-chain CU measurement on the real SBF VM (Mollusk).
cargo build-sbf --manifest-path programs/soliton-verifier/Cargo.toml -- --features bpf-entrypoint
SBF_OUT_DIR=$(pwd)/target/deploy RUST_LOG=off \
  cargo test -p soliton-verifier --test cu_accept -- --nocapture

# Deploy to devnet and accept a real proof on-chain (reports the on-chain CU).
solana program deploy target/deploy/soliton_verifier.so --output json
cargo run -p soliton-cli -- <programId>
```

## License

MIT OR Apache-2.0.
