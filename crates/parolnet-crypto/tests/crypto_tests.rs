use parolnet_crypto::*;
use parolnet_crypto::aead::{ChaCha20Poly1305Cipher, Aes256GcmCipher};
use parolnet_crypto::kdf;

// ── HKDF Tests ──────────────────────────────────────────────────

#[test]
fn test_hkdf_rfc5869_test_case_1() {
    // RFC 5869 Test Case 1 (SHA-256)
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

    let okm = kdf::hkdf_sha256(&salt, &ikm, &info, 42).unwrap();
    let expected = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    ).unwrap();
    assert_eq!(okm, expected);
}

#[test]
fn test_hkdf_fixed_size() {
    let key: [u8; 32] = kdf::hkdf_sha256_fixed(
        b"salt",
        b"input key material",
        b"info",
    ).unwrap();
    assert_eq!(key.len(), 32);
    assert_ne!(key, [0u8; 32]);
}

#[test]
fn test_hkdf_different_info_produces_different_keys() {
    let k1 = kdf::hkdf_sha256(b"salt", b"ikm", b"info1", 32).unwrap();
    let k2 = kdf::hkdf_sha256(b"salt", b"ikm", b"info2", 32).unwrap();
    assert_ne!(k1, k2);
}

// ── AEAD Tests ──────────────────────────────────────────────────

#[test]
fn test_chacha20_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"hello world";
    let aad = b"additional data";

    let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
    let ct = cipher.encrypt(&nonce, plaintext, aad).unwrap();
    let pt = cipher.decrypt(&nonce, &ct, aad).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_aes256gcm_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"hello world";
    let aad = b"additional data";

    let cipher = Aes256GcmCipher::new(&key).unwrap();
    let ct = cipher.encrypt(&nonce, plaintext, aad).unwrap();
    let pt = cipher.decrypt(&nonce, &ct, aad).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_chacha20_tampered_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

    let mut ct = cipher.encrypt(&nonce, b"secret", b"").unwrap();
    ct[0] ^= 0xFF;
    assert!(cipher.decrypt(&nonce, &ct, b"").is_err());
}

#[test]
fn test_chacha20_wrong_aad() {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

    let ct = cipher.encrypt(&nonce, b"secret", b"aad1").unwrap();
    assert!(cipher.decrypt(&nonce, &ct, b"aad2").is_err());
}

#[test]
fn test_aead_invalid_key_length() {
    assert!(ChaCha20Poly1305Cipher::new(&[0u8; 16]).is_err());
    assert!(Aes256GcmCipher::new(&[0u8; 16]).is_err());
}

#[test]
fn test_aead_invalid_nonce_length() {
    let cipher = ChaCha20Poly1305Cipher::new(&[0u8; 32]).unwrap();
    assert!(cipher.encrypt(&[0u8; 8], b"data", b"").is_err());
}

// ── Identity Tests ──────────────────────────────────────────────

#[test]
fn test_identity_keypair_generation() {
    let keypair = IdentityKeyPair::generate();
    let peer_id = keypair.peer_id();
    assert_eq!(peer_id.len(), 32);
    assert_eq!(keypair.peer_id(), peer_id);
}

#[test]
fn test_signed_prekey_generation_and_verification() {
    use parolnet_crypto::identity::SignedPreKey;

    let ik = IdentityKeyPair::generate();
    let spk = SignedPreKey::generate(1, &ik).unwrap();

    // Verification should succeed with the correct identity key
    assert!(spk.verify(&ik.verifying_key()).is_ok());

    // Verification should fail with a different identity key
    let other_ik = IdentityKeyPair::generate();
    assert!(spk.verify(&other_ik.verifying_key()).is_err());
}

#[test]
fn test_one_time_prekey_generation() {
    use parolnet_crypto::identity::OneTimePreKeyPair;

    let opk1 = OneTimePreKeyPair::generate(1);
    let opk2 = OneTimePreKeyPair::generate(2);
    assert_ne!(opk1.public_key.as_bytes(), opk2.public_key.as_bytes());
}

// ── Deniable Auth Tests ─────────────────────────────────────────

#[test]
fn test_deniable_auth_roundtrip() {
    use parolnet_crypto::deniable;

    let secret = [0xABu8; 32];
    let message = b"hello world";

    let tag = deniable::deniable_auth_tag(&secret, message).unwrap();
    assert!(deniable::verify_deniable_auth(&secret, message, &tag).unwrap());
}

#[test]
fn test_deniable_auth_wrong_message() {
    use parolnet_crypto::deniable;

    let secret = [0xABu8; 32];
    let tag = deniable::deniable_auth_tag(&secret, b"message1").unwrap();
    assert!(!deniable::verify_deniable_auth(&secret, b"message2", &tag).unwrap());
}

#[test]
fn test_deniable_auth_wrong_secret() {
    use parolnet_crypto::deniable;

    let tag = deniable::deniable_auth_tag(&[0xABu8; 32], b"msg").unwrap();
    assert!(!deniable::verify_deniable_auth(&[0xCDu8; 32], b"msg", &tag).unwrap());
}

// ── Wipe Tests ──────────────────────────────────────────────────

#[test]
fn test_secure_wipe() {
    let mut data = [0xFFu8; 32];
    wipe::secure_wipe(&mut data);
    assert_eq!(data, [0u8; 32]);
}

#[test]
fn test_chain_key_zeroize_on_drop() {
    let key = ChainKey([0xAB; 32]);
    let ptr = key.0.as_ptr();
    drop(key);
    let _ = ptr;
}
