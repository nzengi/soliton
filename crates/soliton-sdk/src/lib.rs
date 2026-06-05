//! SOLITON wallet / SDK (Stage 2, host std).
//!
//! A `Wallet` holds a spending key `sk` (→ `pk_owner = H2(sk,0)`), an X25519
//! encryption keypair, a store of unspent notes, and a LOCAL incremental Merkle
//! tree it keeps in sync by scanning on-chain commitments + ciphertexts. From
//! these it builds real shield / transfer / unshield bundles whose proofs the
//! pool's verifier accepts and whose output notes the recipient can decrypt.
//!
//! Field domain: the SDK works in `ark_bn254::Fr` (the SHARED-poseidon domain,
//! == the on-chain pool). The circuit prover uses `halo2curves::bn256::Fr`; the
//! two are bridged byte-for-byte via 32-byte LE encodings (`to_h2` / both decode
//! the same canonical field bytes).

pub mod encryption;
pub mod note;
pub mod tree;

use ark_bn254::Fr;
use halo2curves::bn256::Fr as HFr;
use halo2curves::ff::PrimeField;
use soliton_poseidon as sp;

use soliton_pay::prover::{prove_transfer, KeccakArtifacts};
use soliton_pay::witness::{InputNote as CInputNote, OutputNote as COutputNote};

use encryption::EncKeypair;
use note::{NotePlaintext, OwnedNote};
use tree::LocalTree;

/// Bridge an ark-bn254 `Fr` to a halo2curves `Fr` via canonical 32-byte LE bytes
/// (both crates encode the same field; this is the identity on field values).
fn to_h2(a: Fr) -> HFr {
    let le = sp::fr_to_le(&a);
    let mut repr = <HFr as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&le);
    HFr::from_repr(repr).expect("canonical field bytes")
}

/// A recipient's public address: what a sender needs to pay them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// Owner public key `pk_owner = H2(sk, 0)`.
    pub pk_owner: Fr,
    /// X25519 encryption public key (32 bytes).
    pub enc_pk: [u8; 32],
}

/// A built shield bundle: the commitment, a ciphertext to self (so the wallet
/// recovers the note on scan), and the pool `shield` instruction data.
pub struct ShieldBundle {
    pub commitment: Fr,
    pub ciphertext: Vec<u8>,
    /// `[tag::SHIELD, amount u64 LE, cm[32] LE]`.
    pub ix_data: Vec<u8>,
    /// The owned note (so a host harness can also insert it locally if desired).
    pub note: OwnedNote,
}

/// A built transfer bundle: proof artifacts, one encrypted output note per
/// recipient (payment + change), and the pool `transfer` instruction data.
pub struct TransferBundle {
    pub artifacts: KeccakArtifacts,
    /// (output commitment, ciphertext to that output's owner).
    pub encrypted_outputs: Vec<(Fr, Vec<u8>)>,
    /// `[tag::TRANSFER]` — the proof/VK/KZG travel in the staged blob, not here.
    pub ix_data: Vec<u8>,
    /// The transfer root (the local-tree root the proof was built against).
    pub root: Fr,
    pub nullifiers: [Fr; 2],
}

/// A built unshield bundle.
pub struct UnshieldBundle {
    pub artifacts: KeccakArtifacts,
    /// Encrypted change output (if any).
    pub encrypted_change: Option<(Fr, Vec<u8>)>,
    /// `[tag::UNSHIELD, amount u64 LE]`.
    pub ix_data: Vec<u8>,
    pub root: Fr,
    pub nullifiers: [Fr; 2],
}

const TAG_SHIELD: u8 = 0x01;
const TAG_TRANSFER: u8 = 0x02;
const TAG_UNSHIELD: u8 = 0x04;

pub struct Wallet {
    sk: Fr,
    pk_owner: Fr,
    enc: EncKeypair,
    notes: Vec<OwnedNote>,
    tree: LocalTree,
    /// Counter for deterministic-but-unique rho generation.
    rho_ctr: u64,
    /// k for proving (Merkle depth 32 needs k=15).
    k: u32,
}

impl Wallet {
    /// New wallet from a spending key and encryption keypair.
    pub fn new(sk: Fr, enc: EncKeypair) -> Self {
        Self {
            sk,
            pk_owner: sp::note_pk(sk),
            enc,
            notes: Vec::new(),
            tree: LocalTree::default(),
            rho_ctr: 0,
            k: 15,
        }
    }

    /// Deterministic wallet from a seed (test convenience): sk = H2(seed,1),
    /// enc keypair from seed.
    pub fn from_seed(seed: u64) -> Self {
        let sk = sp::hash2(Fr::from(seed), Fr::from(1u64));
        let mut es = [0u8; 32];
        es[..8].copy_from_slice(&seed.to_le_bytes());
        es[8] = 0x5e;
        let enc = EncKeypair::from_seed(es);
        Self::new(sk, enc)
    }

    pub fn address(&self) -> Address {
        Address { pk_owner: self.pk_owner, enc_pk: self.enc.public_bytes() }
    }

    pub fn pk_owner(&self) -> Fr {
        self.pk_owner
    }

    pub fn balance(&self) -> u64 {
        self.notes.iter().map(|n| n.value).sum()
    }

    pub fn note_count(&self) -> usize {
        self.notes.len()
    }

    pub fn root(&self) -> Fr {
        self.tree.root()
    }

    pub fn next_index(&self) -> u64 {
        self.tree.next_index()
    }

    /// Fresh blinding randomness, domain-separated by an internal counter so
    /// every note gets a distinct rho (and thus a distinct nullifier).
    fn fresh_rho(&mut self) -> Fr {
        self.rho_ctr += 1;
        sp::hash2(self.sk, Fr::from(0xDEAD_0000_0000_0000u64 + self.rho_ctr))
    }

    /// Scan a batch of newly-seen on-chain commitments (in insertion order) and
    /// ciphertexts. ALL commitments are inserted into the local tree (so paths +
    /// roots track the pool); ciphertexts are trial-decrypted, and any note whose
    /// recomputed commitment matches a known on-chain commitment is added to the
    /// store with its leaf index recorded.
    pub fn scan(&mut self, commitments: &[Fr], ciphertexts: &[(Fr, Vec<u8>)]) {
        // 1. Insert every commitment into the local tree, recording leaf index.
        let mut index_of = std::collections::HashMap::new();
        for cm in commitments {
            let idx = self.tree.insert(*cm);
            index_of.insert(sp::fr_to_le(cm), idx);
        }

        // 2. Trial-decrypt; accept notes whose cm matches a seen commitment AND
        //    are payable to us (pk_owner == ours).
        for (cm, ct) in ciphertexts {
            if let Some(pt) = encryption::try_decrypt(&self.enc, ct) {
                if pt.commitment() != *cm {
                    continue; // ciphertext/commitment mismatch — not a valid note
                }
                if pt.pk_owner != self.pk_owner {
                    continue; // not ours to spend
                }
                let leaf_index = match index_of.get(&sp::fr_to_le(cm)) {
                    Some(i) => *i,
                    None => continue, // commitment not in this batch's tree insert
                };
                // De-dup: skip if we already hold this note (same cm).
                if self.notes.iter().any(|n| n.commitment() == *cm) {
                    continue;
                }
                self.notes.push(OwnedNote {
                    value: pt.value,
                    rho: pt.rho,
                    sk: self.sk,
                    pk_owner: pt.pk_owner,
                    leaf_index,
                });
            }
        }
    }

    /// Remove a note from the store by commitment (marks it spent locally).
    fn spend_note(&mut self, cm: Fr) -> Option<OwnedNote> {
        if let Some(pos) = self.notes.iter().position(|n| n.commitment() == cm) {
            Some(self.notes.remove(pos))
        } else {
            None
        }
    }

    /// Build a shield of `amount`: a self-owned output note + ciphertext to self.
    /// The caller submits `ix_data` to the pool, then scans the commitment back.
    pub fn build_shield(&mut self, amount: u64) -> ShieldBundle {
        let rho = self.fresh_rho();
        let cm = sp::note_cm(amount, self.pk_owner, rho);
        let leaf_index = self.tree.next_index();
        let pt = NotePlaintext { value: amount, rho, pk_owner: self.pk_owner, leaf_index };
        let ct = encryption::encrypt_note(&self.enc.public_bytes(), &pt);

        let mut ix_data = Vec::with_capacity(1 + 8 + 32);
        ix_data.push(TAG_SHIELD);
        ix_data.extend_from_slice(&amount.to_le_bytes());
        ix_data.extend_from_slice(&sp::fr_to_le(&cm));

        ShieldBundle {
            commitment: cm,
            ciphertext: ct,
            ix_data,
            note: OwnedNote { value: amount, rho, sk: self.sk, pk_owner: self.pk_owner, leaf_index },
        }
    }

    /// Select up to 2 input notes covering `target`. Returns the chosen notes and
    /// the total value selected. The circuit is fixed 2-in/2-out, so we always
    /// use exactly two inputs, padding with a zero-value dummy note if needed.
    fn select_inputs(&self, target: u64) -> anyhow::Result<(Vec<OwnedNote>, u64)> {
        // Greedy: take largest notes until covered.
        let mut sorted: Vec<&OwnedNote> = self.notes.iter().collect();
        sorted.sort_by(|a, b| b.value.cmp(&a.value));
        let mut chosen = Vec::new();
        let mut sum = 0u64;
        for n in sorted {
            if chosen.len() == 2 {
                break;
            }
            chosen.push(n.clone());
            sum += n.value;
            if sum >= target {
                break;
            }
        }
        if sum < target {
            anyhow::bail!("insufficient balance: have {sum}, need {target}");
        }
        Ok((chosen, sum))
    }

    /// Build a transfer paying `to` `amount`, with `fee` (pub_amount = -fee). The
    /// remainder of the spent inputs becomes a change note back to self.
    ///
    /// Requires exactly two REAL spendable input notes whose commitments are
    /// already in the local tree (call `scan` first). Returns the proof bundle +
    /// encrypted outputs.
    pub fn build_transfer(
        &mut self,
        to: &Address,
        amount: u64,
        fee: u64,
    ) -> anyhow::Result<TransferBundle> {
        let target = amount + fee;
        let (inputs, total_in) = self.select_inputs(target)?;
        if inputs.len() != 2 {
            anyhow::bail!(
                "transfer needs exactly 2 input notes (have {} usable); shield more or merge",
                inputs.len()
            );
        }
        let change = total_in
            .checked_sub(target)
            .ok_or_else(|| anyhow::anyhow!("inputs do not cover amount+fee"))?;

        let root = self.tree.root();
        let depth = self.tree.depth();

        // Build circuit input notes with real Merkle paths from the local tree.
        let mut cinputs: Vec<CInputNote> = Vec::with_capacity(2);
        for n in &inputs {
            let (siblings, bits) = self.tree.path(n.leaf_index);
            cinputs.push(CInputNote {
                sk: to_h2(n.sk),
                value: n.value,
                rho: to_h2(n.rho),
                leaf_index: n.leaf_index,
                merkle_path: siblings.iter().map(|s| to_h2(*s)).collect(),
                path_bits: bits,
            });
        }

        // Outputs: payment to `to`, change to self. Fresh rho each.
        let rho_pay = self.fresh_rho();
        let rho_change = self.fresh_rho();
        let pay_cm = sp::note_cm(amount, to.pk_owner, rho_pay);
        let change_cm = sp::note_cm(change, self.pk_owner, rho_change);

        let coutputs = [
            COutputNote { value: amount, pk_owner: to_h2(to.pk_owner), rho: to_h2(rho_pay) },
            COutputNote { value: change, pk_owner: to_h2(self.pk_owner), rho: to_h2(rho_change) },
        ];

        // pub_amount = -fee (internal transfer: value leaves only as fee).
        let pub_amount: i128 = -(fee as i128);

        // Encrypt outputs to their owners. The payment note's leaf index will be
        // known only after the pool flushes; we hint with the current next_index
        // + 0/1 ordering (queue is FIFO; flush inserts in order).
        let next = self.tree.next_index();
        let pay_pt = NotePlaintext { value: amount, rho: rho_pay, pk_owner: to.pk_owner, leaf_index: next };
        let change_pt = NotePlaintext { value: change, rho: rho_change, pk_owner: self.pk_owner, leaf_index: next + 1 };
        let pay_ct = encryption::encrypt_note(&to.enc_pk, &pay_pt);
        let change_ct = encryption::encrypt_note(&self.enc.public_bytes(), &change_pt);

        // Prove (seed derived from the inputs' nullifiers for determinism).
        let seed = self.derive_seed(&inputs);
        let artifacts = prove_transfer(
            self.k,
            [cinputs[0].clone(), cinputs[1].clone()],
            coutputs,
            pub_amount,
            to_h2(root),
            depth,
            seed,
        )?;

        // Mark inputs spent in the local store.
        let nf0 = inputs[0].nullifier();
        let nf1 = inputs[1].nullifier();
        for n in &inputs {
            self.spend_note(n.commitment());
        }

        Ok(TransferBundle {
            artifacts,
            encrypted_outputs: vec![(pay_cm, pay_ct), (change_cm, change_ct)],
            ix_data: vec![TAG_TRANSFER],
            root,
            nullifiers: [nf0, nf1],
        })
    }

    /// Build an unshield of `amount` to `recipient_pubkey` (a Solana address,
    /// passed through to the pool ix). Spends 2 input notes; change returns to
    /// self; pub_amount = -(amount + fee) leaves the shielded set.
    pub fn build_unshield(
        &mut self,
        amount: u64,
        fee: u64,
        recipient_pubkey: [u8; 32],
    ) -> anyhow::Result<UnshieldBundle> {
        let _ = recipient_pubkey; // carried by the caller into the pool ix accounts
        let target = amount + fee;
        let (inputs, total_in) = self.select_inputs(target)?;
        if inputs.len() != 2 {
            anyhow::bail!("unshield needs exactly 2 input notes (have {})", inputs.len());
        }
        let change = total_in - target;
        let root = self.tree.root();
        let depth = self.tree.depth();

        let mut cinputs: Vec<CInputNote> = Vec::with_capacity(2);
        for n in &inputs {
            let (siblings, bits) = self.tree.path(n.leaf_index);
            cinputs.push(CInputNote {
                sk: to_h2(n.sk),
                value: n.value,
                rho: to_h2(n.rho),
                leaf_index: n.leaf_index,
                merkle_path: siblings.iter().map(|s| to_h2(*s)).collect(),
                path_bits: bits,
            });
        }

        // Output 0: change to self (the cmout the pool queues). Output 1: a
        // zero-value note (the public withdrawal carries `amount` via the ix).
        let rho_change = self.fresh_rho();
        let rho_zero = self.fresh_rho();
        let change_cm = sp::note_cm(change, self.pk_owner, rho_change);
        let coutputs = [
            COutputNote { value: change, pk_owner: to_h2(self.pk_owner), rho: to_h2(rho_change) },
            COutputNote { value: 0, pk_owner: to_h2(self.pk_owner), rho: to_h2(rho_zero) },
        ];
        // Balance: vin0 + vin1 + pub_amount == change + 0  ⇒  pub_amount = -(amount+fee).
        let pub_amount: i128 = -((amount + fee) as i128);

        let next = self.tree.next_index();
        let change_pt = NotePlaintext { value: change, rho: rho_change, pk_owner: self.pk_owner, leaf_index: next };
        let change_ct = encryption::encrypt_note(&self.enc.public_bytes(), &change_pt);

        let seed = self.derive_seed(&inputs);
        let artifacts = prove_transfer(
            self.k,
            [cinputs[0].clone(), cinputs[1].clone()],
            coutputs,
            pub_amount,
            to_h2(root),
            depth,
            seed,
        )?;

        let nf0 = inputs[0].nullifier();
        let nf1 = inputs[1].nullifier();
        for n in &inputs {
            self.spend_note(n.commitment());
        }

        let mut ix_data = vec![TAG_UNSHIELD];
        ix_data.extend_from_slice(&amount.to_le_bytes());

        Ok(UnshieldBundle {
            artifacts,
            encrypted_change: Some((change_cm, change_ct)),
            ix_data,
            root,
            nullifiers: [nf0, nf1],
        })
    }

    fn derive_seed(&self, inputs: &[OwnedNote]) -> [u8; 32] {
        let nf = inputs[0].nullifier();
        sp::fr_to_le(&nf)
    }
}
