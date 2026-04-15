//! Trust roots for the federated relay network.
//!
//! Contains the authority public keys that define which relays are trusted.
//! In production, these keys are injected at build time. The placeholder
//! keys here are for development only.

use sha2::{Digest, Sha256};

/// Authority public keys for this network.
/// In production, these are injected at build time.
/// These are placeholder dev-mode keys.
pub const AUTHORITY_PUBKEYS: &[[u8; 32]] = &[
    [0x01; 32], // Dev authority 1 (placeholder)
    [0x02; 32], // Dev authority 2 (placeholder)
    [0x03; 32], // Dev authority 3 (placeholder)
];

/// Number of authority endorsements required to trust a relay.
pub const AUTHORITY_THRESHOLD: usize = 2;

/// Compute the network identity: SHA-256 of sorted authority pubkeys.
pub fn network_id() -> [u8; 32] {
    let mut sorted = AUTHORITY_PUBKEYS.to_vec();
    sorted.sort();
    let mut hasher = Sha256::new();
    for key in &sorted {
        hasher.update(key);
    }
    hasher.finalize().into()
}

/// Check if a public key is a trusted authority.
pub fn is_trusted_authority(pubkey: &[u8; 32]) -> bool {
    AUTHORITY_PUBKEYS.contains(pubkey)
}
