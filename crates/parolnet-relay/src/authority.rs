//! Authority trust model for federated relay networks (PNP-004).
//!
//! Provides threshold-based relay endorsement where authority Ed25519 keypairs
//! control which relays are trusted. Only public keys are hardcoded in the app;
//! anyone with authority private keys can endorse relays, but state actors
//! cannot inject malicious relays without the authority signatures.

use crate::RelayError;
use crate::directory::RelayDescriptor;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parolnet_protocol::address::PeerId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Serde helper for `[u8; 64]` arrays (signatures).
mod sig_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(bytes.as_slice()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = serde_bytes::ByteBuf::deserialize(deserializer)?.into_vec();
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
        })
    }
}

/// A single authority's endorsement of a relay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityEndorsement {
    /// Authority's Ed25519 public key.
    pub authority_pubkey: [u8; 32],
    /// PeerId of the endorsed relay.
    pub relay_peer_id: PeerId,
    /// Unix timestamp when endorsement was created.
    pub endorsed_at: u64,
    /// Unix timestamp when endorsement expires.
    pub expires_at: u64,
    /// Ed25519 signature over SHA-256(relay_peer_id || endorsed_at || expires_at).
    #[serde(with = "sig_bytes")]
    pub signature: [u8; 64],
}

/// A relay descriptor with authority endorsements.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndorsedDescriptor {
    /// The relay's self-signed descriptor.
    pub descriptor: RelayDescriptor,
    /// Authority endorsements (need threshold to be considered trusted).
    pub endorsements: Vec<AuthorityEndorsement>,
}

/// A complete signed directory snapshot from an authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedDirectory {
    /// All endorsed descriptors in this directory.
    pub descriptors: Vec<EndorsedDescriptor>,
    /// Unix timestamp of this directory snapshot.
    pub timestamp: u64,
    /// Authority public key that signed this directory.
    pub authority_pubkey: [u8; 32],
    /// Ed25519 signature over SHA-256(CBOR(descriptors || timestamp)).
    #[serde(with = "sig_bytes")]
    pub signature: [u8; 64],
}

impl AuthorityEndorsement {
    /// SHA-256 hash of (relay_peer_id || endorsed_at || expires_at).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.relay_peer_id.0);
        hasher.update(self.endorsed_at.to_be_bytes());
        hasher.update(self.expires_at.to_be_bytes());
        hasher.finalize().to_vec()
    }

    /// Verify the endorsement signature using the `authority_pubkey`.
    pub fn verify(&self) -> Result<bool, RelayError> {
        let verifying_key = VerifyingKey::from_bytes(&self.authority_pubkey)
            .map_err(|e| RelayError::KeyExchangeFailed(format!("invalid authority pubkey: {e}")))?;
        let signature = Signature::from_bytes(&self.signature);
        let signable = self.signable_bytes();
        Ok(verifying_key.verify(&signable, &signature).is_ok())
    }

    /// Check whether this endorsement has expired.
    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs >= self.expires_at
    }
}

impl EndorsedDescriptor {
    /// Check that at least `threshold` valid, non-expired endorsements exist
    /// from distinct authorities in the trusted set.
    pub fn verify_threshold(
        &self,
        authority_pubkeys: &[[u8; 32]],
        threshold: usize,
    ) -> Result<bool, RelayError> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut valid_authorities: Vec<[u8; 32]> = Vec::new();

        for endorsement in &self.endorsements {
            // Must be from a trusted authority
            if !authority_pubkeys.contains(&endorsement.authority_pubkey) {
                continue;
            }
            // Must not be expired
            if endorsement.is_expired(now_secs) {
                continue;
            }
            // Must have valid signature
            if !endorsement.verify()? {
                continue;
            }
            // Must be for this relay
            if endorsement.relay_peer_id != self.descriptor.peer_id {
                continue;
            }
            // Count each distinct authority only once
            if !valid_authorities.contains(&endorsement.authority_pubkey) {
                valid_authorities.push(endorsement.authority_pubkey);
            }
        }

        Ok(valid_authorities.len() >= threshold)
    }
}

/// Helper for CBOR-serializable directory content (without signature).
#[derive(Serialize)]
struct DirectorySignableContent<'a> {
    descriptors: &'a Vec<EndorsedDescriptor>,
    timestamp: u64,
}

impl SignedDirectory {
    /// SHA-256 hash of CBOR-encoded (descriptors + timestamp).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let content = DirectorySignableContent {
            descriptors: &self.descriptors,
            timestamp: self.timestamp,
        };
        let mut cbor_buf = Vec::new();
        ciborium::into_writer(&content, &mut cbor_buf)
            .expect("CBOR serialization should not fail for valid data");
        let mut hasher = Sha256::new();
        hasher.update(&cbor_buf);
        hasher.finalize().to_vec()
    }

    /// Verify the signing authority is in the trusted set and signature is valid.
    pub fn verify(&self, authority_pubkeys: &[[u8; 32]]) -> Result<bool, RelayError> {
        // Check authority is trusted
        if !authority_pubkeys.contains(&self.authority_pubkey) {
            return Ok(false);
        }

        let verifying_key = VerifyingKey::from_bytes(&self.authority_pubkey)
            .map_err(|e| RelayError::KeyExchangeFailed(format!("invalid authority pubkey: {e}")))?;
        let signature = Signature::from_bytes(&self.signature);
        let signable = self.signable_bytes();
        Ok(verifying_key.verify(&signable, &signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signing_key(seed: u8) -> SigningKey {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        SigningKey::from_bytes(&secret)
    }

    fn make_endorsement(
        signing_key: &SigningKey,
        relay_peer_id: PeerId,
        endorsed_at: u64,
        expires_at: u64,
    ) -> AuthorityEndorsement {
        let authority_pubkey = signing_key.verifying_key().to_bytes();
        let mut endorsement = AuthorityEndorsement {
            authority_pubkey,
            relay_peer_id,
            endorsed_at,
            expires_at,
            signature: [0u8; 64],
        };
        let signable = endorsement.signable_bytes();
        let sig = signing_key.sign(&signable);
        endorsement.signature = sig.to_bytes();
        endorsement
    }

    fn make_descriptor(peer_id: PeerId) -> RelayDescriptor {
        RelayDescriptor {
            peer_id,
            identity_key: [0xAA; 32],
            x25519_key: [0xBB; 32],
            addr: "127.0.0.1:9000".parse().unwrap(),
            bandwidth_class: 1,
            uptime_secs: 3600,
            timestamp: 1000,
            signature: [0u8; 64],
            bandwidth_estimate: 1000,
            next_pubkey: None,
        }
    }

    #[test]
    fn test_authority_endorsement_sign_verify() {
        let sk = make_signing_key(1);
        let peer_id = PeerId([0x42; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let endorsement = make_endorsement(&sk, peer_id, now, now + 86400);
        assert!(endorsement.verify().unwrap());
    }

    #[test]
    fn test_authority_endorsement_tampered() {
        let sk = make_signing_key(1);
        let peer_id = PeerId([0x42; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut endorsement = make_endorsement(&sk, peer_id, now, now + 86400);
        // Tamper with the relay_peer_id
        endorsement.relay_peer_id = PeerId([0x99; 32]);
        assert!(!endorsement.verify().unwrap());
    }

    #[test]
    fn test_endorsed_descriptor_threshold() {
        let sk1 = make_signing_key(1);
        let sk2 = make_signing_key(2);
        let peer_id = PeerId([0x42; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let authority_pubkeys = [
            sk1.verifying_key().to_bytes(),
            sk2.verifying_key().to_bytes(),
        ];

        // Two valid endorsements -> threshold 2 passes
        let desc = EndorsedDescriptor {
            descriptor: make_descriptor(peer_id),
            endorsements: vec![
                make_endorsement(&sk1, peer_id, now, now + 86400),
                make_endorsement(&sk2, peer_id, now, now + 86400),
            ],
        };
        assert!(desc.verify_threshold(&authority_pubkeys, 2).unwrap());

        // Only one endorsement -> threshold 2 fails
        let desc_one = EndorsedDescriptor {
            descriptor: make_descriptor(peer_id),
            endorsements: vec![make_endorsement(&sk1, peer_id, now, now + 86400)],
        };
        assert!(!desc_one.verify_threshold(&authority_pubkeys, 2).unwrap());
    }

    #[test]
    fn test_signed_directory_verify() {
        let sk = make_signing_key(1);
        let authority_pubkeys = [sk.verifying_key().to_bytes()];

        let mut dir = SignedDirectory {
            descriptors: Vec::new(),
            timestamp: 12345,
            authority_pubkey: sk.verifying_key().to_bytes(),
            signature: [0u8; 64],
        };
        let signable = dir.signable_bytes();
        let sig = sk.sign(&signable);
        dir.signature = sig.to_bytes();

        assert!(dir.verify(&authority_pubkeys).unwrap());
    }

    #[test]
    fn test_network_id_deterministic() {
        use crate::trust_roots::network_id;
        let id1 = network_id();
        let id2 = network_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_is_trusted_authority() {
        use crate::trust_roots::is_trusted_authority;
        assert!(is_trusted_authority(&[0x01; 32]));
        assert!(is_trusted_authority(&[0x02; 32]));
        assert!(is_trusted_authority(&[0x03; 32]));
        assert!(!is_trusted_authority(&[0xFF; 32]));
    }
}
