//! Mainline DHT (BEP-44) bootstrap channel (PNP-008 §8.5).
//!
//! The DHT channel is the fourth rung of the §8.1 priority ladder and exists
//! to keep bootstrap surviving even when every compiled-in seed, DNS, and
//! HTTPS endpoint has been censored.
//!
//! ## What this module ships
//!
//! 1. The BEP-44 key-derivation primitives required by MUST-047 / MUST-073:
//!    salt constant, target-hash derivation, sequence-number invariant.
//! 2. A `DhtFetcher` trait abstracting the actual UDP transport so relay
//!    operators can plug in `mainline`, an HTTP-backed mirror, or (for tests)
//!    an in-memory fake.
//! 3. The verification pipeline that applies §6.3 / MUST-049 to a retrieved
//!    BEP-44 value before surfacing a `BootstrapBundle`.
//!
//! ## What is intentionally not here
//!
//! A live UDP DHT node. Running `mainline` inside every relay binary adds a
//! persistent listener, bootstrap-peer tables, and a background maintenance
//! task that operators rarely want on by default. The trait-based split here
//! lets operators opt in via a thin adapter crate without bloating the
//! default build.
//!
//! Clauses pinned here:
//! - **PNP-008-MUST-047** — BEP-44 mutable item keyed by a compiled-in
//!   authority Ed25519 public key ([`DhtBootstrapKey`]).
//! - **PNP-008-MUST-048** — value is deterministic-CBOR `BootstrapBundle`;
//!   sequence number corresponds to `issued_at` truncated to seconds
//!   ([`verify_and_extract_bundle`]).
//! - **PNP-008-MUST-049** — retrieved values MUST pass §6.3 validation
//!   before use ([`verify_and_extract_bundle`]).
//! - **PNP-008-MUST-073** — BEP-44 salt = `"PNP-008-bootstrap"` (17 ASCII
//!   bytes, no trailing null) ([`BEP_44_SALT`]).

use crate::bootstrap::bundle::{BootstrapBundle, BundleError};
use async_trait::async_trait;
use sha1::{Digest as Sha1Digest, Sha1};

/// BEP-44 mutable-item salt for ParolNet bootstrap (PNP-008-MUST-073).
///
/// ASCII, exactly 17 bytes, no trailing null. A different salt MUST be
/// considered a foreign lookup and its value MUST be rejected.
pub const BEP_44_SALT: &[u8; 17] = b"PNP-008-bootstrap";

/// BEP-44 mutable-item target-hash length (SHA-1 output).
pub const BEP_44_TARGET_BYTES: usize = 20;

/// Lookup key for a DHT-hosted bootstrap bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DhtBootstrapKey {
    pub authority_pubkey: [u8; 32],
}

impl DhtBootstrapKey {
    pub fn new(authority_pubkey: [u8; 32]) -> Self {
        Self { authority_pubkey }
    }

    /// Derive the BEP-44 target (SHA-1(pubkey || salt)) that a DHT node
    /// performs `get` against (MUST-047 + MUST-073).
    pub fn bep44_target(&self) -> [u8; BEP_44_TARGET_BYTES] {
        let mut h = Sha1::new();
        h.update(self.authority_pubkey);
        h.update(BEP_44_SALT);
        let out = h.finalize();
        let mut t = [0u8; BEP_44_TARGET_BYTES];
        t.copy_from_slice(&out);
        t
    }
}

/// A BEP-44 mutable item retrieved from the DHT.
#[derive(Clone, Debug)]
pub struct DhtBep44Value {
    /// Deterministic-CBOR encoding of the `BootstrapBundle` (MUST-048).
    pub value_cbor: Vec<u8>,
    /// BEP-44 sequence number. MUST equal `BootstrapBundle.issued_at` in
    /// Unix seconds (MUST-048).
    pub seq: u64,
    /// Ed25519 signature over the BEP-44 `v||seq||salt` prefix (not used by
    /// PNP-008 directly — the bundle's own inner signature is authoritative).
    pub sig: [u8; 64],
}

/// DHT transport abstraction. Implementations MUST apply the per-attempt
/// timeout and cooldown rules from MUST-074.
#[async_trait]
pub trait DhtFetcher: Send + Sync {
    async fn get(&self, target: [u8; BEP_44_TARGET_BYTES]) -> Result<DhtBep44Value, DhtError>;
}

/// Errors specific to the DHT channel.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DhtError {
    #[error("no BEP-44 value at target {target_hex}")]
    NotFound { target_hex: String },
    #[error("DHT transport failure: {0}")]
    Transport(String),
    #[error("BEP-44 value is not CBOR: {0}")]
    ValueNotCbor(String),
    #[error("BEP-44 sequence {seq} does not match bundle issued_at {issued_at}")]
    SeqMismatch { seq: u64, issued_at: u64 },
    #[error("bundle validation failed: {0}")]
    Bundle(#[from] BundleError),
}

/// Decode and validate a BEP-44 value as a `BootstrapBundle` per §8.5.
///
/// Gate order (PNP-008 §8.5):
/// 1. MUST-048 — CBOR-decode the value as a `BootstrapBundle`.
/// 2. MUST-048 — `seq == bundle.issued_at` (truncated to seconds).
/// 3. MUST-049 — apply `bundle.verify_and_validate` with the full §6.3 chain
///    (version → signature → freshness). This is the same pipeline every
///    other §8 channel funnels through so the DHT does not get a validation
///    bypass.
pub fn verify_and_extract_bundle<'a>(
    value: &'a DhtBep44Value,
    authority_pubkeys: &[[u8; 32]],
    now_secs: u64,
) -> Result<BootstrapBundle, DhtError> {
    let bundle: BootstrapBundle = ciborium::from_reader(&value.value_cbor[..])
        .map_err(|e| DhtError::ValueNotCbor(e.to_string()))?;
    if value.seq != bundle.issued_at {
        return Err(DhtError::SeqMismatch {
            seq: value.seq,
            issued_at: bundle.issued_at,
        });
    }
    // MUST-049: same verification as every other channel.
    bundle.verify_and_validate(authority_pubkeys, now_secs)?;
    Ok(bundle)
}

/// In-memory DHT fixture. Useful for unit tests and for operators who want
/// to drive bootstrap from a local cache without running the UDP transport.
#[derive(Default)]
pub struct InMemoryDht {
    entries: std::collections::HashMap<[u8; BEP_44_TARGET_BYTES], DhtBep44Value>,
}

impl InMemoryDht {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, target: [u8; BEP_44_TARGET_BYTES], value: DhtBep44Value) {
        self.entries.insert(target, value);
    }
}

#[async_trait]
impl DhtFetcher for InMemoryDht {
    async fn get(&self, target: [u8; BEP_44_TARGET_BYTES]) -> Result<DhtBep44Value, DhtError> {
        self.entries
            .get(&target)
            .cloned()
            .ok_or_else(|| DhtError::NotFound {
                target_hex: hex::encode(target),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_is_17_ascii_bytes_no_null() {
        // MUST-073: exactly 17 bytes, no trailing null.
        assert_eq!(BEP_44_SALT.len(), 17);
        assert!(BEP_44_SALT.iter().all(|b| *b != 0));
        assert_eq!(BEP_44_SALT, b"PNP-008-bootstrap");
    }

    #[test]
    fn target_derivation_is_sha1_pubkey_then_salt() {
        // MUST-047: target hash = SHA-1(pubkey || salt).
        let key = DhtBootstrapKey::new([7u8; 32]);
        let t = key.bep44_target();
        let mut expected = Sha1::new();
        expected.update([7u8; 32]);
        expected.update(BEP_44_SALT);
        let out = expected.finalize();
        assert_eq!(&t[..], &out[..]);
    }

    #[test]
    fn seq_mismatch_is_rejected() {
        use ed25519_dalek::SigningKey;
        // MUST-048: seq MUST equal bundle.issued_at.
        let now = 1_700_000_000;
        let mut seed = [0u8; 32];
        seed[0] = 42;
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        let bundle = BootstrapBundle::signed(vec![], now, &sk);
        let mut cbor = Vec::new();
        ciborium::into_writer(&bundle, &mut cbor).unwrap();
        let bad = DhtBep44Value {
            value_cbor: cbor,
            seq: now + 99, // MUST-048 violation
            sig: [0u8; 64],
        };
        let err = verify_and_extract_bundle(&bad, &[pk], now).unwrap_err();
        assert!(matches!(err, DhtError::SeqMismatch { .. }));
    }

    #[test]
    fn happy_path_returns_bundle() {
        use ed25519_dalek::SigningKey;
        let now = 1_700_000_100;
        let mut seed = [0u8; 32];
        seed[0] = 7;
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        let bundle = BootstrapBundle::signed(vec![], now, &sk);
        let mut cbor = Vec::new();
        ciborium::into_writer(&bundle, &mut cbor).unwrap();
        let good = DhtBep44Value {
            value_cbor: cbor,
            seq: now,
            sig: [0u8; 64],
        };
        let extracted = verify_and_extract_bundle(&good, &[pk], now).unwrap();
        assert_eq!(extracted.issued_at, now);
    }

    #[tokio::test]
    async fn in_memory_dht_returns_inserted_value() {
        let mut dht = InMemoryDht::new();
        let t = [3u8; BEP_44_TARGET_BYTES];
        let v = DhtBep44Value {
            value_cbor: vec![0xaa; 4],
            seq: 1,
            sig: [0u8; 64],
        };
        dht.insert(t, v.clone());
        let got = dht.get(t).await.unwrap();
        assert_eq!(got.value_cbor, v.value_cbor);
    }

    #[tokio::test]
    async fn in_memory_dht_returns_not_found_on_miss() {
        let dht = InMemoryDht::new();
        let err = dht.get([9u8; BEP_44_TARGET_BYTES]).await.unwrap_err();
        assert!(matches!(err, DhtError::NotFound { .. }));
    }
}
