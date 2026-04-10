//! Key derivation functions.
//!
//! HKDF-SHA-256 based key derivation for:
//! - X3DH shared secret derivation
//! - Double Ratchet chain key ratcheting
//! - Session key derivation
//! - Relay circuit key expansion (PNP-004)

use crate::CryptoError;

/// Derive key material using HKDF-SHA-256.
///
/// # Arguments
/// - `salt`: Optional salt value (use zeros if none).
/// - `ikm`: Input key material.
/// - `info`: Context and application-specific info string.
/// - `len`: Desired output length in bytes.
pub fn hkdf_sha256(
    _salt: &[u8],
    _ikm: &[u8],
    _info: &[u8],
    _len: usize,
) -> Result<Vec<u8>, CryptoError> {
    todo!("HKDF-SHA-256 derivation")
}

/// Derive a fixed-size key using HKDF-SHA-256.
pub fn hkdf_sha256_fixed<const N: usize>(
    _salt: &[u8],
    _ikm: &[u8],
    _info: &[u8],
) -> Result<[u8; N], CryptoError> {
    todo!("HKDF-SHA-256 fixed-size derivation")
}
