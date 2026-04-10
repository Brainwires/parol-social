//! Key derivation functions.
//!
//! HKDF-SHA-256 based key derivation for:
//! - X3DH shared secret derivation
//! - Double Ratchet chain key ratcheting
//! - Session key derivation
//! - Relay circuit key expansion (PNP-004)

use crate::CryptoError;
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive key material using HKDF-SHA-256 (RFC 5869).
///
/// # Arguments
/// - `salt`: Salt value. Use `&[0u8; 32]` if none.
/// - `ikm`: Input key material.
/// - `info`: Context and application-specific info string.
/// - `len`: Desired output length in bytes.
pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(okm)
}

/// Derive a fixed-size key using HKDF-SHA-256.
pub fn hkdf_sha256_fixed<const N: usize>(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
) -> Result<[u8; N], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; N];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(okm)
}
