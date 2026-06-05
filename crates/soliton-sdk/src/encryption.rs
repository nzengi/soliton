//! Note encryption (Stage 2, GATE 2).
//!
//! Each wallet holds an X25519 encryption keypair, SEPARATE from its spending
//! key `sk`. A sender encrypts an output note to the recipient's published
//! X25519 public key using `crypto_box` (NaCl `box` = X25519 + XSalsa20Poly1305),
//! which provides ephemeral-sender anonymity + authenticated encryption.
//!
//! Ciphertext wire format (so the recipient can decrypt with only its own
//! secret key, no out-of-band channel):
//! ```text
//!   [0..32)   ephemeral X25519 public key (the sender's per-note ephemeral pk)
//!   [32..56)  24-byte XSalsa20Poly1305 nonce
//!   [56..)    sealed box (NotePlaintext || 16-byte Poly1305 tag)
//! ```
//! Using a fresh ephemeral keypair per note means the sender's long-term key is
//! never revealed and recipients trial-decrypt with their static secret key.

use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey, SalsaBox, SecretKey,
};

use crate::note::NotePlaintext;

/// Length of the fixed header (ephemeral pk + nonce).
const EPK_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = EPK_LEN + NONCE_LEN;

/// An X25519 encryption keypair for a wallet.
#[derive(Clone)]
pub struct EncKeypair {
    secret: SecretKey,
    public: PublicKey,
}

impl EncKeypair {
    /// Generate a fresh random encryption keypair (OS RNG).
    pub fn generate() -> Self {
        let secret = SecretKey::generate(&mut OsRng);
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Deterministic keypair from a 32-byte seed (test/repro convenience).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = SecretKey::from(seed);
        let public = secret.public_key();
        Self { secret, public }
    }

    /// The public encryption key to publish in an `Address`.
    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    fn secret(&self) -> &SecretKey {
        &self.secret
    }
}

/// Encrypt `note` to `recipient_enc_pk` (32-byte X25519 public key). Uses a fresh
/// ephemeral sender keypair so the sender's identity is not revealed.
pub fn encrypt_note(recipient_enc_pk: &[u8; 32], note: &NotePlaintext) -> Vec<u8> {
    let recipient_pk = PublicKey::from(*recipient_enc_pk);
    let ephemeral = SecretKey::generate(&mut OsRng);
    let ephemeral_pk = ephemeral.public_key();

    let sbox = SalsaBox::new(&recipient_pk, &ephemeral);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ct = sbox
        .encrypt(&nonce, note.to_bytes().as_slice())
        .expect("crypto_box encrypt cannot fail with valid keys");

    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(ephemeral_pk.as_bytes());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    out
}

/// Try to decrypt `ct` with `my_enc_sk` (the wallet's encryption secret). Returns
/// `Some(note)` iff the ciphertext was sealed to this wallet's public key (the
/// Poly1305 tag authenticates), else `None`.
pub fn try_decrypt(my: &EncKeypair, ct: &[u8]) -> Option<NotePlaintext> {
    if ct.len() < HEADER_LEN {
        return None;
    }
    let mut epk = [0u8; 32];
    epk.copy_from_slice(&ct[..EPK_LEN]);
    let sender_pk = PublicKey::from(epk);

    let nonce = crypto_box::Nonce::from_slice(&ct[EPK_LEN..HEADER_LEN]);
    let body = &ct[HEADER_LEN..];

    let sbox = SalsaBox::new(&sender_pk, my.secret());
    let pt = sbox.decrypt(nonce, body).ok()?;
    NotePlaintext::from_bytes(&pt)
}
