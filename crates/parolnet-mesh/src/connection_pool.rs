//! Connection pool for managing active peer connections and scores.

use crate::MeshError;
use crate::peer_table::{PeerScore, PeerTable};
use parolnet_protocol::address::PeerId;
use parolnet_transport::Connection;
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Maximum number of simultaneous peer connections.
pub const MAX_PEERS: usize = 256;

/// How a peer came to be connected (PNP-005 §5.9). It is recorded and nothing else:
/// no origin, bootstrap peers included, changes how a peer is validated, scored, rate
/// limited or banned (PNP-005-MUST-044).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerOrigin {
    /// Configured by hand.
    Manual,
    /// Found on the local network.
    Discovered,
    /// Learned from a PEER_ANNOUNCEMENT.
    Gossip,
    /// One of the well-known peers compiled into the application.
    Bootstrap,
}

/// Manages active peer connections and their reputation scores.
pub struct ConnectionPool {
    connections: RwLock<HashMap<PeerId, Arc<dyn Connection>>>,
    /// Peers still in the sync phase (§4.2): connected, not yet part of gossip fanout.
    syncing: RwLock<HashSet<PeerId>>,
    origins: RwLock<HashMap<PeerId, PeerOrigin>>,
    table: RwLock<PeerTable>,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            syncing: RwLock::new(HashSet::new()),
            origins: RwLock::new(HashMap::new()),
            table: RwLock::new(PeerTable::new()),
        }
    }

    /// Add a peer connection and initialize its score.
    ///
    /// Returns `MeshError::PeerLimitReached` if MAX_PEERS is exceeded, and
    /// `MeshError::PeerBanned` while the peer is refused (PNP-005-SHOULD-009).
    pub async fn add_peer(
        &self,
        peer_id: PeerId,
        conn: Arc<dyn Connection>,
    ) -> Result<(), MeshError> {
        self.add_peer_from(peer_id, conn, PeerOrigin::Manual).await
    }

    /// As [`Self::add_peer`], recording where the peer came from.
    pub async fn add_peer_from(
        &self,
        peer_id: PeerId,
        conn: Arc<dyn Connection>,
        origin: PeerOrigin,
    ) -> Result<(), MeshError> {
        if self.table.read().await.is_banned(&peer_id) {
            return Err(MeshError::PeerBanned);
        }
        let mut connections = self.connections.write().await;
        if connections.len() >= MAX_PEERS && !connections.contains_key(&peer_id) {
            return Err(MeshError::PeerLimitReached);
        }
        connections.insert(peer_id, conn);
        drop(connections);
        self.origins.write().await.insert(peer_id, origin);
        self.table.write().await.get_or_insert(peer_id);
        Ok(())
    }

    /// Mark a connected peer as still syncing: it gets no gossip fanout until
    /// [`Self::set_active`].
    pub async fn set_syncing(&self, peer_id: PeerId) {
        self.syncing.write().await.insert(peer_id);
    }

    /// The peer's sync phase is over (§4.2 ACTIVE).
    pub async fn set_active(&self, peer_id: &PeerId) {
        self.syncing.write().await.remove(peer_id);
    }

    /// Whether the peer is connected and past its sync phase.
    pub async fn is_active(&self, peer_id: &PeerId) -> bool {
        self.connections.read().await.contains_key(peer_id)
            && !self.syncing.read().await.contains(peer_id)
    }

    /// Whether the peer is connected.
    pub async fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.connections.read().await.contains_key(peer_id)
    }

    /// Where a connected peer came from.
    pub async fn origin(&self, peer_id: &PeerId) -> Option<PeerOrigin> {
        self.origins.read().await.get(peer_id).copied()
    }

    /// Remove a peer's connection. A score that says something is kept for when the
    /// peer comes back.
    pub async fn remove_peer(&self, peer_id: &PeerId) {
        self.connections.write().await.remove(peer_id);
        self.syncing.write().await.remove(peer_id);
        self.origins.write().await.remove(peer_id);
        self.table.write().await.forget_if_default(peer_id);
    }

    /// Get a connection to a specific peer.
    pub async fn get_connection(&self, peer_id: &PeerId) -> Option<Arc<dyn Connection>> {
        self.connections.read().await.get(peer_id).cloned()
    }

    /// Get the current score for a peer.
    pub async fn get_score(&self, peer_id: &PeerId) -> Option<PeerScore> {
        self.table.write().await.get(peer_id).cloned()
    }

    /// Whether the peer is refused at the moment.
    pub async fn is_banned(&self, peer_id: &PeerId) -> bool {
        self.table.read().await.is_banned(peer_id)
    }

    /// Update a connected peer's score using the provided closure.
    ///
    /// A score that falls below zero disconnects the peer and refuses it for an hour
    /// (PNP-005-SHOULD-009).
    pub async fn update_score<F: FnOnce(&mut PeerScore)>(&self, peer_id: &PeerId, f: F) {
        if !self.connections.read().await.contains_key(peer_id) {
            return;
        }
        let banned = {
            let mut table = self.table.write().await;
            let score = table.get_or_insert(*peer_id);
            f(score);
            let banned = score.is_banned();
            if banned {
                table.ban(*peer_id);
            }
            banned
        };
        if banned {
            let conn = self.connections.write().await.remove(peer_id);
            self.syncing.write().await.remove(peer_id);
            self.origins.write().await.remove(peer_id);
            if let Some(conn) = conn {
                let _ = conn.close().await;
            }
        }
    }

    /// Randomly select up to `count` active peers, excluding the given list and banned
    /// peers. With fewer than `count` eligible, all of them (PNP-005-MUST-022).
    pub async fn select_fanout_peers(
        &self,
        exclude: &[PeerId],
        count: usize,
    ) -> Vec<(PeerId, Arc<dyn Connection>)> {
        let connections = self.connections.read().await;
        let syncing = self.syncing.read().await;
        let table = self.table.read().await;

        let mut candidates: Vec<(PeerId, Arc<dyn Connection>)> = connections
            .iter()
            .filter(|(pid, _)| {
                !exclude.contains(pid) && !syncing.contains(pid) && !table.is_banned(pid)
            })
            .map(|(pid, conn)| (*pid, conn.clone()))
            .collect();

        let mut rng = rand::thread_rng();
        candidates.shuffle(&mut rng);
        candidates.truncate(count);
        candidates
    }

    /// Drop bans that ran out.
    pub async fn prune_bans(&self) {
        self.table.write().await.prune_bans();
    }

    /// Number of currently connected peers.
    pub async fn peer_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// List all connected peer IDs.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.connections.read().await.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parolnet_transport::TransportError;
    use std::net::SocketAddr;
    use tokio::sync::Mutex;

    struct MockConnection {
        _sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockConnection {
        fn new() -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    _sent: sent.clone(),
                },
                sent,
            )
        }
    }

    #[async_trait]
    impl Connection for MockConnection {
        async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
            self._sent.lock().await.push(data.to_vec());
            Ok(())
        }
        async fn recv(&self) -> Result<Vec<u8>, TransportError> {
            Err(TransportError::ConnectionClosed)
        }
        async fn close(&self) -> Result<(), TransportError> {
            Ok(())
        }
        fn peer_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    #[tokio::test]
    async fn test_add_remove_peer() {
        let pool = ConnectionPool::new();
        let peer_id = PeerId([1u8; 32]);
        let (conn, _sent) = MockConnection::new();

        pool.add_peer(peer_id, Arc::new(conn)).await.unwrap();
        assert_eq!(pool.peer_count().await, 1);
        assert!(pool.get_connection(&peer_id).await.is_some());
        assert!(pool.get_score(&peer_id).await.is_some());

        pool.remove_peer(&peer_id).await;
        assert_eq!(pool.peer_count().await, 0);
        assert!(pool.get_connection(&peer_id).await.is_none());
    }

    #[tokio::test]
    async fn test_select_fanout_excludes_banned() {
        let pool = ConnectionPool::new();

        let good_peer = PeerId([1u8; 32]);
        let banned_peer = PeerId([2u8; 32]);
        let excluded_peer = PeerId([3u8; 32]);

        let (conn1, _) = MockConnection::new();
        let (conn2, _) = MockConnection::new();
        let (conn3, _) = MockConnection::new();

        pool.add_peer(good_peer, Arc::new(conn1)).await.unwrap();
        pool.add_peer(banned_peer, Arc::new(conn2)).await.unwrap();
        pool.add_peer(excluded_peer, Arc::new(conn3)).await.unwrap();

        // Ban the second peer by reducing score below 0
        pool.update_score(&banned_peer, |s| {
            for _ in 0..20 {
                s.penalize_invalid();
            }
        })
        .await;
        // It is disconnected and refused for an hour.
        assert!(pool.get_connection(&banned_peer).await.is_none());
        let (again, _) = MockConnection::new();
        assert!(matches!(
            pool.add_peer(banned_peer, Arc::new(again)).await,
            Err(MeshError::PeerBanned)
        ));

        let selected = pool.select_fanout_peers(&[excluded_peer], 10).await;

        let selected_ids: Vec<PeerId> = selected.iter().map(|(pid, _)| *pid).collect();
        assert!(selected_ids.contains(&good_peer));
        assert!(!selected_ids.contains(&banned_peer));
        assert!(!selected_ids.contains(&excluded_peer));
    }

    #[tokio::test]
    async fn test_connected_peers() {
        let pool = ConnectionPool::new();
        let p1 = PeerId([1u8; 32]);
        let p2 = PeerId([2u8; 32]);

        let (c1, _) = MockConnection::new();
        let (c2, _) = MockConnection::new();

        pool.add_peer(p1, Arc::new(c1)).await.unwrap();
        pool.add_peer(p2, Arc::new(c2)).await.unwrap();

        let peers = pool.connected_peers().await;
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&p1));
        assert!(peers.contains(&p2));
    }

    #[tokio::test]
    async fn test_update_score() {
        let pool = ConnectionPool::new();
        let peer_id = PeerId([1u8; 32]);
        let (conn, _) = MockConnection::new();

        pool.add_peer(peer_id, Arc::new(conn)).await.unwrap();

        pool.update_score(&peer_id, |s| s.reward()).await;
        let score = pool.get_score(&peer_id).await.unwrap();
        assert_eq!(score.score, 101);
    }
}
