//! # parolnet-mesh
//!
//! Mesh networking and gossip protocol for ParolNet (PNP-005).
//!
//! Provides:
//! - Peer discovery (mDNS, future: BLE)
//! - Gossip protocol for epidemic message propagation
//! - Store-and-forward for delay-tolerant networking
//! - Set reconciliation for reconnection sync
//! - Peer scoring and anti-spam

pub mod clock;
pub mod connection_pool;
pub mod discovery;
pub mod error;
pub mod gossip;
pub mod mdns;
pub mod peer_manager;
pub mod peer_table;
pub mod reconcile;
pub mod store_forward;
pub mod sync;

pub use error::MeshError;

use async_trait::async_trait;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::envelope::Envelope;
use parolnet_protocol::gossip::GossipEnvelope;

/// Discovers nearby peers on local networks or via proximity.
#[async_trait]
pub trait PeerDiscovery: Send + Sync {
    async fn discover(&self) -> Result<Vec<DiscoveredPeer>, MeshError>;
    async fn announce(&self, identity: &PeerId) -> Result<(), MeshError>;
}

/// A peer discovered via mDNS or other local mechanism.
#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    pub peer_id: PeerId,
    pub addr: std::net::SocketAddr,
}

/// Store-and-forward message buffer for delay-tolerant networking (PNP-005 §5.4).
///
/// It holds gossip messages for peers that are known and currently disconnected. What
/// it keeps per message (expiry, remaining TTL, origination timestamp) is what the
/// eviction order of §5.4 item 3 is defined on.
#[async_trait]
pub trait MessageStore: Send + Sync {
    async fn store(&self, recipient: &PeerId, message: &GossipEnvelope) -> Result<(), MeshError>;
    async fn retrieve(&self, recipient: &PeerId) -> Result<Vec<GossipEnvelope>, MeshError>;
    async fn expire(&self) -> Result<usize, MeshError>;
}

/// Gossip protocol for propagating messages through the mesh (PNP-005).
#[async_trait]
pub trait GossipProtocol: Send + Sync {
    async fn broadcast(&self, envelope: Envelope) -> Result<(), MeshError>;
    async fn on_receive(&self, envelope: Envelope) -> Result<GossipAction, MeshError>;
}

/// What became of a received gossip message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipAction {
    /// Valid and new; scheduled for these peers, each after its own jitter.
    Forward { peers: Vec<PeerId> },
    /// Valid and new, for the application here; not forwarded (TTL spent, or no peer
    /// to forward to).
    Deliver,
    /// Valid and new, for the application here, and scheduled for these peers.
    DeliverAndForward { peers: Vec<PeerId> },
    /// Already seen, or valid with nowhere to go — dropped silently.
    Drop,
    /// The source exceeded its rate limit — dropped silently.
    RateLimited,
}
