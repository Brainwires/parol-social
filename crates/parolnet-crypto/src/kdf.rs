//! Key derivation functions.
//!
//! HKDF-SHA-256 based key derivation for:
//! - X3DH shared secret derivation
//! - Double Ratchet chain key ratcheting
//! - Session key derivation
//! - Relay circuit key expansion (PNP-004)
//!
//! Argon2id (RFC 9106) stretches a passphrase a person typed into a key: the web app's
//! passphrase lock and its backup files (`docs/web-port/backup.md`).

use crate::CryptoError;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

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
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(Zeroizing::new(okm))
}

/// The most memory [`argon2id`] accepts, in KiB (1 GiB). A file from somewhere else names its own
/// cost; this keeps a hostile one from exhausting the device.
pub const ARGON2ID_MAX_MEMORY_KIB: u32 = 1 << 20;
/// The most passes [`argon2id`] accepts.
pub const ARGON2ID_MAX_PASSES: u32 = 16;

/// Stretch a passphrase with Argon2id, version 0x13 (RFC 9106), no secret and no
/// associated data.
///
/// # Arguments
/// - `passphrase`: what the person typed, as bytes (UTF-8, NFKC by the caller's rule).
/// - `salt`: random, at least 8 bytes (16 recommended), stored beside the result's use.
/// - `memory_kib`: memory cost in KiB, up to [`ARGON2ID_MAX_MEMORY_KIB`].
/// - `passes`: time cost, up to [`ARGON2ID_MAX_PASSES`].
/// - `lanes`: parallelism (the computation itself runs on one thread).
/// - `len`: bytes of output, 4 to 64.
pub fn argon2id(
    passphrase: &[u8],
    salt: &[u8],
    memory_kib: u32,
    passes: u32,
    lanes: u32,
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if memory_kib > ARGON2ID_MAX_MEMORY_KIB || passes > ARGON2ID_MAX_PASSES || len > 64 {
        return Err(CryptoError::KdfFailed);
    }
    let params = argon2::Params::new(memory_kib, passes, lanes, Some(len))
        .map_err(|_| CryptoError::KdfFailed)?;
    let hasher = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new(vec![0u8; len]);
    hasher
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(out)
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
