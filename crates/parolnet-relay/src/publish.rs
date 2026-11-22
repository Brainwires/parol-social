//! A relay's own descriptor: built, signed and published (PNP-004 §5.6 items 1 to 3).
//!
//! Descriptors travel as PNP-005 gossip messages of payload type 0x01
//! (RELAY_DESCRIPTOR). This crate does not depend on the mesh, so the gossip side is the
//! [`DescriptorGossip`] trait; `parolnet-core` implements it over the mesh's
//! `PeerManager`.

use crate::RelayError;
use crate::directory::{DESCRIPTOR_REFRESH_SECS, RelayDescriptor, RelayDirectory};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::gossip::RelayDescriptorGossip;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How often a relay publishes its descriptor. PNP-004-MUST-043 asks for a refresh at
/// least every 6 hours; publishing a little sooner keeps the new one out before the
/// gossip copy of the old one expires.
pub const DESCRIPTOR_PUBLISH_INTERVAL: Duration =
    Duration::from_secs(DESCRIPTOR_REFRESH_SECS - 600);

/// Where a relay sends its descriptor: the gossip mesh (PNP-004-MUST-042).
#[async_trait]
pub trait DescriptorGossip: Send + Sync {
    /// Publish `payload` as a RELAY_DESCRIPTOR gossip message (PNP-005 type 0x01).
    async fn publish_descriptor(&self, payload: Vec<u8>) -> Result<(), RelayError>;
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Builds, signs and publishes this relay's descriptor.
pub struct DescriptorPublisher {
    /// The relay's Ed25519 identity key (zeroized on drop by `ed25519-dalek`).
    signing_key: SigningKey,
    x25519_public: [u8; 32],
    addr: SocketAddr,
    capabilities: u8,
    pow_difficulty: Option<u8>,
    started: Instant,
    uptime_at_start: u64,
}

impl DescriptorPublisher {
    /// `capabilities` is the byte of [`crate::capabilities::pack`]: bandwidth class and
    /// exit policy flags.
    pub fn new(
        signing_key: SigningKey,
        x25519_public: [u8; 32],
        addr: SocketAddr,
        capabilities: u8,
    ) -> Self {
        Self {
            signing_key,
            x25519_public,
            addr,
            capabilities,
            pow_difficulty: None,
            started: Instant::now(),
            uptime_at_start: 0,
        }
    }

    /// Uptime the relay had already accumulated when this process started.
    pub fn with_prior_uptime(mut self, secs: u64) -> Self {
        self.uptime_at_start = secs;
        self
    }

    /// Advertise a proof-of-work difficulty for the network (PNP-005 §5.6 item 4).
    pub fn with_pow_difficulty(mut self, difficulty: u8) -> Self {
        self.pow_difficulty = Some(difficulty);
        self
    }

    /// This relay's PeerId.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_public_key(&self.signing_key.verifying_key().to_bytes())
    }

    /// The descriptor as of `now` (unix seconds): PeerId, identity key, X25519 key,
    /// address, capabilities, uptime, timestamp, and the Ed25519 signature over all of
    /// them (PNP-004-MUST-041).
    pub fn descriptor(&self, now: u64) -> RelayDescriptor {
        let identity_key = self.signing_key.verifying_key().to_bytes();
        RelayDirectory::create_descriptor(
            PeerId::from_public_key(&identity_key),
            identity_key,
            self.x25519_public,
            self.addr,
            self.capabilities,
            self.uptime_at_start + self.started.elapsed().as_secs(),
            now,
            &self.signing_key,
        )
    }

    /// The RELAY_DESCRIPTOR gossip payload for the descriptor as of `now`.
    pub fn gossip_payload(&self, now: u64) -> Result<Vec<u8>, RelayError> {
        let mut descriptor = Vec::new();
        ciborium::into_writer(&self.descriptor(now), &mut descriptor)
            .map_err(|e| RelayError::CellError(format!("descriptor encode: {e}")))?;
        RelayDescriptorGossip {
            descriptor,
            pow_difficulty: self.pow_difficulty,
        }
        .to_cbor()
        .map_err(|e| RelayError::CellError(e.to_string()))
    }

    /// Publish the current descriptor once.
    pub async fn publish_once(&self, gossip: &dyn DescriptorGossip) -> Result<(), RelayError> {
        gossip
            .publish_descriptor(self.gossip_payload(unix_now())?)
            .await
    }

    /// Publish now and then every [`DESCRIPTOR_PUBLISH_INTERVAL`], each time with a
    /// fresh timestamp, uptime and signature (PNP-004-MUST-043).
    pub fn spawn(self: Arc<Self>, gossip: Arc<dyn DescriptorGossip>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(DESCRIPTOR_PUBLISH_INTERVAL);
            loop {
                ticks.tick().await;
                if let Err(e) = self.publish_once(gossip.as_ref()).await {
                    tracing::warn!(error = %e, "relay descriptor not published");
                }
            }
        })
    }
}

/// Take a RELAY_DESCRIPTOR gossip payload into a directory.
///
/// `gossip_src` is the PeerId that signed the gossip message; a descriptor is its
/// relay's own statement, so it has to be the descriptor's PeerId. The descriptor's
/// signature, its PeerId (the hash of its identity key) and its age are then checked by
/// [`RelayDirectory::handle_gossip_descriptor`] (PNP-004-MUST-044). Returns whether the
/// directory took it.
pub fn ingest_descriptor_gossip(
    directory: &mut RelayDirectory,
    gossip_src: &PeerId,
    payload: &[u8],
    now: u64,
) -> bool {
    let Ok(wrapper) = RelayDescriptorGossip::from_cbor(payload) else {
        return false;
    };
    let Ok(descriptor) = ciborium::from_reader::<RelayDescriptor, _>(wrapper.descriptor.as_slice())
    else {
        return false;
    };
    if descriptor.peer_id != *gossip_src {
        return false;
    }
    directory.handle_gossip_descriptor(descriptor, now)
}
