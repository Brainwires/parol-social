//! AEAD cipher implementations.
//!
//! Provides ChaCha20-Poly1305 (primary, constant-time without AES-NI)
//! and AES-256-GCM (secondary, for transport-layer TLS disguise).

use crate::{Aead, CryptoError};

/// ChaCha20-Poly1305 AEAD cipher.
///
/// Primary cipher for all internal encryption. Constant-time on all
/// platforms including mobile ARM without AES-NI hardware support.
pub struct ChaCha20Poly1305Cipher {
    // TODO: key material
}

impl ChaCha20Poly1305Cipher {
    pub fn new(_key: &[u8]) -> Result<Self, CryptoError> {
        todo!("ChaCha20-Poly1305 initialization")
    }
}

impl Aead for ChaCha20Poly1305Cipher {
    fn encrypt(&self, _nonce: &[u8], _plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("ChaCha20-Poly1305 encrypt")
    }

    fn decrypt(&self, _nonce: &[u8], _ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("ChaCha20-Poly1305 decrypt")
    }

    fn key_len(&self) -> usize { 32 }
    fn nonce_len(&self) -> usize { 12 }
}

/// AES-256-GCM AEAD cipher.
///
/// Secondary cipher used at the transport layer to match TLS cipher suites.
/// Provides hardware acceleration on platforms with AES-NI.
pub struct Aes256GcmCipher {
    // TODO: key material
}

impl Aes256GcmCipher {
    pub fn new(_key: &[u8]) -> Result<Self, CryptoError> {
        todo!("AES-256-GCM initialization")
    }
}

impl Aead for Aes256GcmCipher {
    fn encrypt(&self, _nonce: &[u8], _plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("AES-256-GCM encrypt")
    }

    fn decrypt(&self, _nonce: &[u8], _ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("AES-256-GCM decrypt")
    }

    fn key_len(&self) -> usize { 32 }
    fn nonce_len(&self) -> usize { 12 }
}
