//! X3DH (Extended Triple Diffie-Hellman) key agreement.
//!
//! Adapted for decentralized use — no central key server required.
//! Pre-key bundles are distributed via the relay network, direct exchange,
//! or the bootstrap protocol (PNP-003).
//!
//! See PNP-002 Section 5.1 for the full specification.

use crate::{
    CryptoError, IdentityKeyPair, KeyAgreement, PreKeyBundle, SharedSecret, X3dhHeader,
};

/// X3DH key agreement implementation.
pub struct X3dhKeyAgreement {
    pub identity: IdentityKeyPair,
}

impl KeyAgreement for X3dhKeyAgreement {
    /// Initiate a handshake with a recipient using their pre-key bundle.
    ///
    /// Computes:
    /// - DH1 = X25519(IK_a, SPK_b)
    /// - DH2 = X25519(EK_a, IK_b)
    /// - DH3 = X25519(EK_a, SPK_b)
    /// - DH4 = X25519(EK_a, OPK_b)  (if OPK available)
    ///
    /// Derives SK via HKDF-SHA-256 with info="ParolNet_X3DH_v1".
    fn initiate(
        &self,
        _recipient_bundle: &PreKeyBundle,
    ) -> Result<(SharedSecret, X3dhHeader), CryptoError> {
        todo!("X3DH initiation")
    }

    /// Respond to an incoming X3DH handshake.
    fn respond(&self, _header: &X3dhHeader) -> Result<SharedSecret, CryptoError> {
        todo!("X3DH response")
    }
}
