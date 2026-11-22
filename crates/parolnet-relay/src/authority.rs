//! Authority trust model for federated relay networks (PNP-004).
//!
//! Provides threshold-based relay endorsement where authority Ed25519 keypairs
//! control which relays are trusted. Only public keys are hardcoded in the app;
//! anyone with authority private keys can endorse relays, but state actors
//! cannot inject malicious relays without the authority signatures.

use crate::RelayError;
use crate::directory::RelayDescriptor;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
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

/// A single authority's endorsement of one relay descriptor.
///
/// The signature covers the whole descriptor (PNP-008-MUST-002): its keys, its
/// address, its timestamp and the relay's own signature. It therefore stands
/// for exactly that descriptor and for as long as that descriptor is valid
/// (seven days, PNP-008-MUST-027 item 3); a relay that publishes a new
/// descriptor needs new endorsements for it. Nothing else is carried: a field
/// outside the signed bytes could be rewritten by whoever passes the
/// endorsement on.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityEndorsement {
    /// Authority's Ed25519 public key.
    pub authority_pubkey: [u8; 32],
    /// Ed25519 signature over [`RelayDescriptor::endorsement_signable_bytes`].
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
    /// Endorse `descriptor` with an authority key.
    pub fn sign(descriptor: &RelayDescriptor, authority_key: &SigningKey) -> Self {
        Self {
            authority_pubkey: authority_key.verifying_key().to_bytes(),
            signature: authority_key
                .sign(&descriptor.endorsement_signable_bytes())
                .to_bytes(),
        }
    }

    /// Whether this is `authority_pubkey`'s signature over `descriptor`
    /// (PNP-008-MUST-002). Any change to the descriptor, its relay signature
    /// included, makes it false.
    pub fn verify(&self, descriptor: &RelayDescriptor) -> Result<bool, RelayError> {
        let verifying_key = VerifyingKey::from_bytes(&self.authority_pubkey)
            .map_err(|e| RelayError::KeyExchangeFailed(format!("invalid authority pubkey: {e}")))?;
        let signature = Signature::from_bytes(&self.signature);
        Ok(verifying_key
            .verify(&descriptor.endorsement_signable_bytes(), &signature)
            .is_ok())
    }
}

/// PNP-008-MUST-027 item 3: a descriptor older than this is rejected.
pub const MAX_ENDORSED_DESCRIPTOR_AGE_SECS: u64 = 7 * 86400;

impl EndorsedDescriptor {
    /// Validate the descriptor (PNP-008-MUST-027) and check that at least
    /// `threshold` distinct authorities of the trusted set endorsed it.
    ///
    /// The descriptor has to be its relay's own statement (PeerId the hash of
    /// its identity key, signed by that key) and no older than seven days.
    /// Each endorsement is then checked over this very descriptor
    /// (PNP-008-MUST-002), so one made for another descriptor of the same
    /// relay, or of any other, does not count.
    pub fn verify_threshold(
        &self,
        authority_pubkeys: &[[u8; 32]],
        threshold: usize,
    ) -> Result<bool, RelayError> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now_secs.saturating_sub(self.descriptor.timestamp) >= MAX_ENDORSED_DESCRIPTOR_AGE_SECS {
            return Ok(false);
        }
        if !self.descriptor.verify_self_signature() {
            return Ok(false);
        }

        let mut valid_authorities: Vec<[u8; 32]> = Vec::new();

        for endorsement in &self.endorsements {
            // Must be from a trusted authority
            if !authority_pubkeys.contains(&endorsement.authority_pubkey) {
                continue;
            }
            // Must be a signature over this descriptor
            if !endorsement.verify(&self.descriptor)? {
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
    use parolnet_protocol::address::PeerId;

    fn make_signing_key(seed: u8) -> SigningKey {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        SigningKey::from_bytes(&secret)
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A descriptor signed by `relay_key`, for the PeerId that key hashes to.
    fn make_descriptor(relay_key: &SigningKey, addr: &str, timestamp: u64) -> RelayDescriptor {
        let identity_key = relay_key.verifying_key().to_bytes();
        crate::directory::RelayDirectory::create_descriptor(
            PeerId::from_public_key(&identity_key),
            identity_key,
            [0xBB; 32],
            addr.parse().unwrap(),
            1,
            3600,
            timestamp,
            relay_key,
        )
    }

    #[test]
    fn test_authority_endorsement_sign_verify() {
        let sk = make_signing_key(1);
        let descriptor = make_descriptor(&make_signing_key(7), "127.0.0.1:9000", now_secs());
        let endorsement = AuthorityEndorsement::sign(&descriptor, &sk);
        assert!(endorsement.verify(&descriptor).unwrap());
    }

    /// PNP-008-MUST-002: the endorsement is over the descriptor, its relay
    /// signature included. Changing any of it voids the endorsement.
    #[test]
    fn test_authority_endorsement_covers_the_whole_descriptor() {
        let sk = make_signing_key(1);
        let relay = make_signing_key(7);
        let descriptor = make_descriptor(&relay, "127.0.0.1:9000", now_secs());
        let endorsement = AuthorityEndorsement::sign(&descriptor, &sk);

        let mutations: [fn(&mut RelayDescriptor); 9] = [
            |d| d.peer_id = PeerId([0x99; 32]),
            |d| d.identity_key[0] ^= 1,
            |d| d.x25519_key[0] ^= 1,
            |d| d.addr = "127.0.0.1:9001".parse().unwrap(),
            |d| d.bandwidth_class += 1,
            |d| d.uptime_secs += 1,
            |d| d.timestamp += 1,
            |d| d.bandwidth_estimate += 1,
            |d| d.next_pubkey = Some([1; 32]),
        ];
        for mutate in mutations {
            let mut altered = descriptor.clone();
            mutate(&mut altered);
            assert!(!endorsement.verify(&altered).unwrap());
            // Also when the relay itself signed the altered descriptor.
            altered.signature = relay.sign(&altered.signable_bytes()).to_bytes();
            assert!(!endorsement.verify(&altered).unwrap());
        }
        let mut resigned = descriptor.clone();
        resigned.signature[0] ^= 1;
        assert!(!endorsement.verify(&resigned).unwrap());

        // Another authority key does not verify it.
        let mut other = endorsement.clone();
        other.authority_pubkey = make_signing_key(2).verifying_key().to_bytes();
        assert!(!other.verify(&descriptor).unwrap());
    }

    #[test]
    fn test_endorsed_descriptor_threshold() {
        let sk1 = make_signing_key(1);
        let sk2 = make_signing_key(2);
        let relay = make_signing_key(7);
        let now = now_secs();
        let descriptor = make_descriptor(&relay, "127.0.0.1:9000", now);

        let authority_pubkeys = [
            sk1.verifying_key().to_bytes(),
            sk2.verifying_key().to_bytes(),
        ];

        // Two valid endorsements -> threshold 2 passes
        let desc = EndorsedDescriptor {
            descriptor: descriptor.clone(),
            endorsements: vec![
                AuthorityEndorsement::sign(&descriptor, &sk1),
                AuthorityEndorsement::sign(&descriptor, &sk2),
            ],
        };
        assert!(desc.verify_threshold(&authority_pubkeys, 2).unwrap());

        // Only one endorsement -> threshold 2 fails
        let desc_one = EndorsedDescriptor {
            endorsements: vec![AuthorityEndorsement::sign(&descriptor, &sk1)],
            descriptor,
        };
        assert!(!desc_one.verify_threshold(&authority_pubkeys, 2).unwrap());
    }

    /// An endorsement must not carry over to a descriptor that claims the same
    /// PeerId with other keys or another address (PNP-008-MUST-002, MUST-027),
    /// nor to a later descriptor the relay itself signed.
    #[test]
    fn test_endorsement_does_not_carry_to_another_descriptor() {
        let authority = make_signing_key(1);
        let authority_pubkeys = [authority.verifying_key().to_bytes()];
        let relay = make_signing_key(7);
        let attacker = make_signing_key(66);
        let now = now_secs();

        let genuine = make_descriptor(&relay, "198.51.100.7:443", now);
        let endorsements = vec![AuthorityEndorsement::sign(&genuine, &authority)];
        let endorsed = |descriptor: RelayDescriptor| EndorsedDescriptor {
            descriptor,
            endorsements: endorsements.clone(),
        };
        assert!(
            endorsed(genuine.clone())
                .verify_threshold(&authority_pubkeys, 1)
                .unwrap()
        );

        // The attacker's keys and address under the endorsed PeerId, signed by the attacker.
        let mut forged = make_descriptor(&attacker, "203.0.113.66:443", now + 1);
        forged.peer_id = genuine.peer_id;
        forged.signature = attacker.sign(&forged.signable_bytes()).to_bytes();
        assert!(
            !endorsed(forged)
                .verify_threshold(&authority_pubkeys, 1)
                .unwrap()
        );

        // The genuine descriptor with the address or the onion key changed.
        let mut moved = genuine.clone();
        moved.addr = "203.0.113.66:443".parse().unwrap();
        assert!(
            !endorsed(moved)
                .verify_threshold(&authority_pubkeys, 1)
                .unwrap()
        );
        let mut rekeyed = genuine.clone();
        rekeyed.x25519_key = [0xEE; 32];
        assert!(
            !endorsed(rekeyed)
                .verify_threshold(&authority_pubkeys, 1)
                .unwrap()
        );

        // A new descriptor of the same relay, validly signed by the relay at
        // another address: the old endorsement is not for it.
        let relocated = make_descriptor(&relay, "203.0.113.66:443", now);
        assert!(relocated.verify_self_signature());
        assert!(
            !endorsed(relocated)
                .verify_threshold(&authority_pubkeys, 1)
                .unwrap()
        );

        // Item 3 of MUST-027: older than seven days, even when endorsed as such.
        let stale = make_descriptor(&relay, "198.51.100.7:443", now - 7 * 86400 - 1);
        let stale = EndorsedDescriptor {
            endorsements: vec![AuthorityEndorsement::sign(&stale, &authority)],
            descriptor: stale,
        };
        assert!(!stale.verify_threshold(&authority_pubkeys, 1).unwrap());
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
