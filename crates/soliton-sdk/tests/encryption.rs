//! Note-encryption round-trip.
//! Bob decrypts Alice's ciphertext and recovers the EXACT note; a third party
//! (wrong key) gets None.

use ark_bn254::Fr;
use soliton_sdk::encryption::{encrypt_note, try_decrypt, EncKeypair};
use soliton_sdk::note::NotePlaintext;

#[test]
fn roundtrip_and_wrongkey() {
    let bob = EncKeypair::from_seed([0xB0u8; 32]);
    let eve = EncKeypair::from_seed([0xEEu8; 32]);

    let note = NotePlaintext {
        value: 1_234_567u64,
        rho: Fr::from(0xCAFEu64),
        pk_owner: Fr::from(0x1234_5678u64),
        leaf_index: 42,
    };

    let ct = encrypt_note(&bob.public_bytes(), &note);

    // Bob recovers the exact note.
    let got = try_decrypt(&bob, &ct).expect("Bob must decrypt his note");
    assert_eq!(got, note, "decrypted note != original");
    println!("[PASS] Bob decrypted: value={} leaf={} (exact match)", got.value, got.leaf_index);

    // Eve (wrong key) gets None.
    let eve_res = try_decrypt(&eve, &ct);
    assert!(eve_res.is_none(), "wrong-key decryption MUST be None");
    println!("[PASS] Eve (wrong key) got None");

    // Tampered ciphertext -> None (AEAD tag).
    let mut bad = ct.clone();
    let n = bad.len();
    bad[n - 1] ^= 0x01;
    assert!(try_decrypt(&bob, &bad).is_none(), "tampered ct MUST fail AEAD");
    println!("[PASS] tampered ciphertext rejected (AEAD tag)");
}
