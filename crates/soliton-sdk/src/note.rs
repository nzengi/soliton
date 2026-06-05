//! Note model for the SDK, in the SHARED-poseidon (ark-bn254) field domain — the
//! same domain the on-chain pool and (via byte-equality) the circuit use.
//!
//! A note is `(value, pk_owner, rho)`; its commitment is
//! `cm = H3(value, pk_owner, rho)`, its nullifier (spendable only by the owner of
//! `sk` where `pk_owner = H2(sk,0)`) is `nf = H2(sk, rho)`.

use ark_bn254::Fr;
use soliton_poseidon as sp;

/// The cleartext payload encrypted to a recipient so they can recognize + spend
/// the note: value, blinding `rho`, the owner public key `pk_owner`, and a
/// `leaf_index` hint (the position the commitment was inserted at, for fast path
/// reconstruction). 8 + 32 + 32 + 8 = 80 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotePlaintext {
    pub value: u64,
    pub rho: Fr,
    pub pk_owner: Fr,
    pub leaf_index: u64,
}

impl NotePlaintext {
    pub const LEN: usize = 8 + 32 + 32 + 8;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&sp::fr_to_le(&self.rho));
        out.extend_from_slice(&sp::fr_to_le(&self.pk_owner));
        out.extend_from_slice(&self.leaf_index.to_le_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != Self::LEN {
            return None;
        }
        let value = u64::from_le_bytes(b[0..8].try_into().ok()?);
        let mut rho_le = [0u8; 32];
        rho_le.copy_from_slice(&b[8..40]);
        let mut pk_le = [0u8; 32];
        pk_le.copy_from_slice(&b[40..72]);
        let leaf_index = u64::from_le_bytes(b[72..80].try_into().ok()?);
        Some(Self {
            value,
            rho: sp::fr_from_le_bytes(&rho_le),
            pk_owner: sp::fr_from_le_bytes(&pk_le),
            leaf_index,
        })
    }

    /// Commitment cm = H3(value, pk_owner, rho).
    pub fn commitment(&self) -> Fr {
        sp::note_cm(self.value, self.pk_owner, self.rho)
    }
}

/// An owned, unspent note in the wallet's store: plaintext + the spending key
/// needed to nullify it.
#[derive(Clone, Debug)]
pub struct OwnedNote {
    pub value: u64,
    pub rho: Fr,
    pub sk: Fr,
    pub pk_owner: Fr,
    pub leaf_index: u64,
}

impl OwnedNote {
    pub fn commitment(&self) -> Fr {
        sp::note_cm(self.value, self.pk_owner, self.rho)
    }
    pub fn nullifier(&self) -> Fr {
        sp::note_nf(self.sk, self.rho)
    }
}
