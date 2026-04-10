//! Peer identity and addressing.
//!
//! PeerId is derived from SHA-256(Ed25519_identity_public_key).
//! No phone number, email, or any external identifier ever touches the wire.

use serde::{Deserialize, Serialize};

/// A unique peer identifier derived from a cryptographic public key.
///
/// `PeerId = SHA-256(Ed25519_identity_public_key)`
///
/// This is the only form of identity in ParolNet. No phone numbers,
/// email addresses, usernames, or any other external identifiers exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// Create a PeerId from an Ed25519 public key by hashing it.
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        Self(hasher.finalize().into())
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display as hex, truncated for readability
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "...")
    }
}
