# SOLITON Protocol

Native-PLONK shielded payments verified on Solana — no Groth16 wrap.

## Status

Devnet-proven verifier, plus a working shielded pool and wallet/SDK. A
SOLITON-Pay proof verifies on-chain inside Solana's 1.4M compute-unit
per-transaction ceiling, and the application layer around it — an on-chain
pool program and an off-chain wallet — now runs end-to-end on Mollusk: an
SDK-built transfer proof is accepted by the on-chain verifier, the wallet's
local Merkle root matches the pool's root byte-for-byte, and the recipient
decrypts the output note to receive funds. This is still a devnet demo on a
test SRS, not a production system.

| | |
|---|---|
| Program ID (verifier) | `Gu2NbGsGwmo5BsB3j4keb2SMUiTkMYuqXAYLRcuj2Fn2` |
| Verify tx | `3Cg4P5ppJ3uq6Wa1RZ63zHVg8BGCZrqy8G9e2f44LTpFVoYqjjHQuGGu9saqBWtnX65hF2QwSjiy5gkSE9cyPXC9` |
| On-chain verify CU | 1,343,241 (measured on Mollusk; < 1.4M) |

Protocol spec: [`docs/SOLITON-spec-v1.0.md`](docs/SOLITON-spec-v1.0.md).

## What it is

A 2-in / 2-out shielded payment over a Merkle tree of depth 32. The statement
is proven with a PLONKish circuit using KZG/BN254 commitments and the SHPLONK
multi-opening argument, and verified by a sound on-chain verifier at ~1.34M CU.
To my knowledge, prior zk work on Solana (groth16-solana, sp1-solana,
risc0-solana, and Light Protocol) wraps down to Groth16 before verifying;
SOLITON verifies the halo2 proof natively. That native path costs more compute
(~1.34M CU vs a few hundred thousand for a Groth16 verify) — a deliberate
trade, not a free lunch. See the spec's positioning section for the comparison.

Around the verifier there are now two more pieces:

- **An on-chain shielded pool** (`programs/soliton-pool`) that custodies SOL in
  a program-owned vault and runs the shield → transfer → unshield flow. It keeps
  an incremental depth-32 Poseidon Merkle tree (hashed via the `sol_poseidon`
  syscall), a root-history ring, and a nullifier set. `shield` deposits SOL and
  inserts an output commitment; `transfer` verifies a proof, spends two
  nullifiers, and queues the output commitments; a separate `flush` inserts the
  queued commitments into the tree; `unshield` verifies a proof and pays SOL
  out. Verify costs ~1.34M CU, so a verify-bearing instruction cannot also hash
  the tree in the same transaction — hence the queue/flush split.
- **A wallet/SDK** (`crates/soliton-sdk`) that holds a spending key and an
  X25519 encryption keypair, encrypts and scans output notes, tracks a local
  copy of the Merkle tree, and builds shield/transfer/unshield bundles
  (witnesses and proofs the pool accepts).

What is hidden: the spent notes, their values, the sender/recipient link inside
the pool, and which leaves were spent. What is public: the deposit and
withdrawal amounts (`pub_amount`), the revealed nullifiers, the output
commitments, and the tree root.

## Honest status caveats

This is a devnet proof-of-concept. It is NOT safe for real value:

- **Test SRS.** The KZG parameters come from `ParamsKZG::setup`, whose toxic
  waste is known. A production deployment needs a real trusted setup (or a
  transparent alternative). Anyone holding the setup randomness can forge proofs.
- **~100-bit security.** BN254 offers roughly 100 bits of security, below the
  128-bit bar expected for high-value systems.
- **No audit.** The circuit, verifier, and pool have not been audited.
- **Single-asset.** Only one asset type (SOL) is supported.
- **Fixed 2-in / 2-out, no dummy-input padding yet.** A transfer spends exactly
  two input notes; there is no dummy/zero input to pad a 1-input spend, and
  no N-in / M-out generalization. Until padding lands, the wallet needs two
  spendable notes to transfer.

## Repository layout

The protocol:

| Path | Role |
|---|---|
| `crates/verifier` (`halo2-solana-verifier`) | no_std BN254/KZG/SHPLONK verifier; `verify_generic` (AST-driven) and `verify_specialized` (straight-line) |
| `crates/vk-host` | host-side compiler: halo2 verifying key → flat on-chain VK bytes (`compile_vk_generic`) |
| `crates/soliton-poseidon` | shared circom-BN254 Poseidon — one source of truth for the hash, used by circuit, tree, and pool; bit-identical to `sol_poseidon` / `light-poseidon` |
| `crates/soliton-sdk` | wallet/SDK: key management, note encryption (X25519 + XSalsa20Poly1305), scanning, local tree, `build_shield`/`build_transfer`/`build_unshield` (witnesses + proofs) |
| `circuits/soliton-pay` | SOLITON-Pay circuit + prover (`prove_keccak`, `prove_transfer`, `build_transfer_circuit`) |
| `programs/soliton-verifier` | on-chain BPF program running the sound verifier |
| `programs/soliton-pool` | on-chain shielded pool: incremental tree (`sol_poseidon`), root history, nullifier PDAs, SOL vault, queue/flush |
| `programs/soliton-probe` | field/group-op CU probe (the per-op unit costs the budget is built from) |
| `programs/soliton-poseidon-probe` | `sol_poseidon` syscall CU probe (the ~862 CU/hash measurement) |
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

# Proof accepts; tampered proof rejects.
cargo test -p soliton-pay --test soliton_accept -- --nocapture

# Verifier crate unit tests.
cargo test -p halo2-solana-verifier --features "std,solana-syscalls"

# On-chain CU measurement on the real SBF VM (Mollusk).
cargo build-sbf --manifest-path programs/soliton-verifier/Cargo.toml -- --features bpf-entrypoint
SBF_OUT_DIR=$(pwd)/target/deploy RUST_LOG=off \
  cargo test -p soliton-verifier --test cu_accept -- --nocapture

# Deploy to devnet and accept a proof on-chain (reports the on-chain CU).
solana program deploy target/deploy/soliton_verifier.so --output json
cargo run -p soliton-cli -- <programId>
```

## License

MIT OR Apache-2.0.
