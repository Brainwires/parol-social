//! Identity key management.
//!
//! Ed25519 identity keypairs and their X25519 counterparts for DH operations.
//! The PeerId is derived as SHA-256(Ed25519_public_key).

use crate::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A signed pre-key (medium-term X25519 keypair, signed by the identity key).
///
/// Rotated every 7-30 days. The previous SPK should be retained for one
/// additional rotation period to handle in-flight handshakes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKey {
    pub id: u32,
    #[zeroize(skip)]
    pub private_key: x25519_dalek::StaticSecret,
    #[zeroize(skip)]
    pub public_key: x25519_dalek::PublicKey,
    pub signature: [u8; 64],
}

impl SignedPreKey {
    /// Generate a new signed pre-key and sign it with the identity key.
    pub fn generate(
        _id: u32,
        _identity_key: &crate::IdentityKeyPair,
    ) -> Result<Self, CryptoError> {
        todo!("SignedPreKey generation and signing")
    }
}

/// A one-time pre-key (ephemeral X25519 keypair, used exactly once).
///
/// Peers should maintain a pool of 20-100 OPKs and replenish proactively.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OneTimePreKeyPair {
    pub id: u32,
    #[zeroize(skip)]
    pub private_key: x25519_dalek::StaticSecret,
    #[zeroize(skip)]
    pub public_key: x25519_dalek::PublicKey,
}

impl OneTimePreKeyPair {
    /// Generate a new one-time pre-key.
    pub fn generate(_id: u32) -> Self {
        todo!("OneTimePreKey generation")
    }
}
