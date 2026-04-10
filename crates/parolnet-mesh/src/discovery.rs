//! Peer discovery via mDNS (PNP-005 Section 5.9).
//!
//! Service type: `_parolnet._tcp.local.`

use crate::{DiscoveredPeer, MeshError, PeerDiscovery};
use async_trait::async_trait;
use parolnet_protocol::address::PeerId;

pub struct MdnsDiscovery;

#[async_trait]
impl PeerDiscovery for MdnsDiscovery {
    async fn discover(&self) -> Result<Vec<DiscoveredPeer>, MeshError> {
        todo!("mDNS peer discovery")
    }

    async fn announce(&self, _identity: &PeerId) -> Result<(), MeshError> {
        todo!("mDNS peer announcement")
    }
}
