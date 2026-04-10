//! Gossip protocol implementation (PNP-005).

use crate::{GossipAction, GossipProtocol, MeshError};
use async_trait::async_trait;
use parolnet_protocol::envelope::Envelope;

/// Default gossip fanout (number of peers to forward to).
pub const DEFAULT_FANOUT: usize = 3;
/// Default TTL for gossip messages.
pub const DEFAULT_TTL: u8 = 7;
/// Default expiry duration in seconds.
pub const DEFAULT_EXPIRY_SECS: u64 = 86400;

pub struct StandardGossip;

#[async_trait]
impl GossipProtocol for StandardGossip {
    async fn broadcast(&self, _envelope: Envelope) -> Result<(), MeshError> {
        todo!("Gossip broadcast")
    }

    async fn on_receive(&self, _envelope: Envelope) -> Result<GossipAction, MeshError> {
        todo!("Gossip receive handling")
    }
}
