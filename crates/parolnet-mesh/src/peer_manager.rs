//! PeerManager — orchestrates connections, gossip, sync and store-and-forward.
//!
//! A peer's life here follows PNP-005 §4.2: connected, it is SYNCING (set
//! reconciliation, §5.7) for at most 30 seconds, then ACTIVE (normal gossip
//! forwarding), and what was buffered for it while it was away is delivered at that
//! point. Disconnected, messages addressed to it are buffered again.

use crate::clock::Clock;
use crate::connection_pool::{ConnectionPool, PeerOrigin};
use crate::gossip::{StandardGossip, user_message_dest};
use crate::reconcile::{GossipIblt, SYNC_TIMEOUT, SyncFrame, iblt_key};
use crate::store_forward::InMemoryStore;
use crate::{GossipAction, MeshError, MessageStore};
use parolnet_protocol::address::PeerId;
use parolnet_protocol::gossip::{GossipEnvelope, GossipPayloadType, PeerAnnouncement};
use parolnet_transport::Connection;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

/// Housekeeping runs this often: expired messages leave the buffers (PNP-005-MUST-032).
pub const HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(60);
/// A node announces its addresses this often (PNP-005-SHOULD-011).
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// Most message IDs taken from a peer's full-list fallback.
const MAX_FALLBACK_IDS: usize = 100_000;
/// Most messages asked for in one sync.
const MAX_SYNC_REQUEST: usize = 4096;

/// The sync phase with one peer.
struct SyncSession {
    generation: u64,
    /// We sent our full ID list (the fallback).
    sent_ids: bool,
    /// The peer's full ID list, as far as received.
    their_ids: Vec<[u8; 32]>,
    /// The peer answered our request.
    got_data: bool,
    /// We answered the peer's request.
    served: bool,
    /// Messages the peer got from us during the sync.
    sent: HashSet<[u8; 32]>,
}

struct Inner {
    our_peer_id: PeerId,
    pool: Arc<ConnectionPool>,
    gossip: StandardGossip,
    store: InMemoryStore,
    sync: tokio::sync::Mutex<HashMap<PeerId, SyncSession>>,
    generation: AtomicU64,
    /// Peers that have been connected: the ones messages are buffered for.
    known: Mutex<HashSet<PeerId>>,
    subscribers: Mutex<Vec<mpsc::UnboundedSender<GossipEnvelope>>>,
    housekeeping: Mutex<Option<JoinHandle<()>>>,
    listen_addrs: Mutex<Vec<SocketAddr>>,
    last_announce: Mutex<Option<Instant>>,
    /// Addresses other nodes announced.
    announced: Mutex<HashMap<PeerId, Vec<SocketAddr>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(task) = self
            .housekeeping
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            task.abort();
        }
    }
}

fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Orchestrates mesh networking: connections, gossip, and store-and-forward.
#[derive(Clone)]
pub struct PeerManager {
    inner: Arc<Inner>,
}

impl PeerManager {
    /// Create a new PeerManager.
    pub fn new(our_peer_id: PeerId, signing_key: ed25519_dalek::SigningKey) -> Self {
        Self::with_clock(our_peer_id, signing_key, Clock::system())
    }

    /// As [`Self::new`], reading time from `clock`.
    pub fn with_clock(
        our_peer_id: PeerId,
        signing_key: ed25519_dalek::SigningKey,
        clock: Clock,
    ) -> Self {
        let pool = Arc::new(ConnectionPool::new());
        // The buffers are encrypted under a key derived from the identity key.
        let store = InMemoryStore::with_identity_and_clock(&signing_key, clock.clone());
        let gossip = StandardGossip::with_clock(our_peer_id, signing_key, pool.clone(), clock);
        Self {
            inner: Arc::new(Inner {
                our_peer_id,
                pool,
                gossip,
                store,
                sync: tokio::sync::Mutex::new(HashMap::new()),
                generation: AtomicU64::new(0),
                known: Mutex::new(HashSet::new()),
                subscribers: Mutex::new(Vec::new()),
                housekeeping: Mutex::new(None),
                listen_addrs: Mutex::new(Vec::new()),
                last_announce: Mutex::new(None),
                announced: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Start the periodic housekeeping if it is not running: every 60 seconds expired
    /// messages are purged (PNP-005-MUST-032) and, when due, the deduplication filter
    /// rotates and the node's addresses are announced again.
    fn ensure_housekeeping(&self) {
        let mut slot = guard(&self.inner.housekeeping);
        if slot.is_some() || tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let weak: Weak<Inner> = Arc::downgrade(&self.inner);
        *slot = Some(tokio::spawn(async move {
            let mut ticks = tokio::time::interval(HOUSEKEEPING_INTERVAL);
            ticks.tick().await;
            loop {
                ticks.tick().await;
                let Some(inner) = weak.upgrade() else { return };
                let manager = PeerManager { inner };
                if let Err(e) = manager.run_maintenance().await {
                    warn!(error = %e, "mesh housekeeping failed");
                }
            }
        }));
    }

    /// Add a peer connection. The peer starts in the sync phase; what is buffered for
    /// it is delivered when that phase ends (PNP-005-MUST-031).
    pub async fn add_peer(
        &self,
        peer_id: PeerId,
        conn: Arc<dyn Connection>,
    ) -> Result<(), MeshError> {
        self.add_peer_from(peer_id, conn, PeerOrigin::Manual).await
    }

    /// As [`Self::add_peer`], recording how the peer was found. The origin changes
    /// nothing about how the peer is treated (PNP-005-MUST-044).
    pub async fn add_peer_from(
        &self,
        peer_id: PeerId,
        conn: Arc<dyn Connection>,
        origin: PeerOrigin,
    ) -> Result<(), MeshError> {
        let inner = &self.inner;
        inner
            .pool
            .add_peer_from(peer_id, conn.clone(), origin)
            .await?;
        inner.pool.set_syncing(peer_id).await;
        guard(&inner.known).insert(peer_id);
        self.ensure_housekeeping();
        info!(peer = %peer_id, "peer connected");

        // PNP-005-MUST-038: on (re)connection the two peers reconcile their sets.
        let generation = inner.generation.fetch_add(1, Ordering::SeqCst) + 1;
        inner.sync.lock().await.insert(
            peer_id,
            SyncSession {
                generation,
                sent_ids: false,
                their_ids: Vec::new(),
                got_data: false,
                served: false,
                sent: HashSet::new(),
            },
        );
        let ids = inner.gossip.cached_ids();
        let offer = SyncFrame::Offer(GossipIblt::from_ids(ids.iter())).encode()?;
        if let Err(e) = conn.send(&offer).await {
            warn!(peer = %peer_id, error = %e, "failed to send sync offer");
        }

        // PNP-005-MUST-040 / MUST-041: after 30 seconds the peer is ACTIVE whether the
        // sync finished or not; deduplication absorbs what is then sent twice.
        if tokio::runtime::Handle::try_current().is_ok() {
            let manager = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(SYNC_TIMEOUT).await;
                let still_syncing = manager
                    .inner
                    .sync
                    .lock()
                    .await
                    .get(&peer_id)
                    .is_some_and(|s| s.generation == generation);
                if still_syncing {
                    manager.finish_sync(&peer_id).await;
                }
            });
        }
        Ok(())
    }

    /// End a peer's sync phase: it becomes ACTIVE and gets what was buffered for it,
    /// except what the sync already gave it.
    async fn finish_sync(&self, peer_id: &PeerId) {
        let inner = &self.inner;
        let Some(session) = inner.sync.lock().await.remove(peer_id) else {
            return;
        };
        let Some(conn) = inner.pool.get_connection(peer_id).await else {
            return;
        };
        inner.pool.set_active(peer_id).await;

        let stored = match inner.store.retrieve(peer_id).await {
            Ok(stored) => stored,
            Err(e) => {
                warn!(peer = %peer_id, error = %e, "buffered messages unreadable");
                return;
            }
        };
        let mut delivered = 0;
        for message in &stored {
            if message
                .message_id()
                .is_some_and(|id| session.sent.contains(&id))
            {
                continue;
            }
            let Ok(bytes) = message.to_cbor() else {
                continue;
            };
            match conn.send(&bytes).await {
                Ok(()) => delivered += 1,
                Err(e) => warn!(peer = %peer_id, error = %e, "failed to deliver stored message"),
            }
        }
        if delivered > 0 {
            info!(peer = %peer_id, count = delivered, "delivered stored messages");
        }
    }

    /// Whether a peer is still in its sync phase.
    pub async fn is_syncing(&self, peer_id: &PeerId) -> bool {
        self.inner.sync.lock().await.contains_key(peer_id)
    }

    /// Remove a peer from the pool.
    pub async fn remove_peer(&self, peer_id: &PeerId) {
        self.inner.pool.remove_peer(peer_id).await;
        self.inner.sync.lock().await.remove(peer_id);
        info!(peer = %peer_id, "peer disconnected");
    }

    /// Serve one peer over `conn` until the connection ends: add it, read its frames,
    /// remove it.
    pub async fn run_peer(
        &self,
        peer_id: PeerId,
        conn: Arc<dyn Connection>,
    ) -> Result<(), MeshError> {
        self.add_peer(peer_id, conn.clone()).await?;
        while let Ok(frame) = conn.recv().await {
            if let Err(e) = self.handle_incoming(&peer_id, &frame).await {
                tracing::debug!(peer = %peer_id, error = %e, "frame discarded");
            }
            if !self.inner.pool.is_connected(&peer_id).await {
                break;
            }
        }
        self.remove_peer(&peer_id).await;
        Ok(())
    }

    /// Originate a gossip message of `payload_type` (see [`StandardGossip::publish`]).
    pub async fn publish(&self, payload_type: u8, payload: Vec<u8>) -> Result<[u8; 32], MeshError> {
        let gossip = &self.inner.gossip;
        let origin = if payload_type == GossipPayloadType::UserMessage as u8 {
            gossip.user_origin
        } else {
            crate::gossip::Origin::Identity
        };
        let envelope = gossip.build_envelope(
            payload_type,
            payload,
            crate::gossip::GossipParams::for_type(payload_type),
            origin,
        )?;
        self.send_gossip(envelope.clone()).await?;
        Ok(envelope.message_id().expect("built with a 32-byte id"))
    }

    /// Send a gossip envelope this node originated to the mesh. A user message for a
    /// known peer that is away is also buffered for it (PNP-005-SHOULD-004).
    pub async fn send_gossip(&self, gossip_env: GossipEnvelope) -> Result<(), MeshError> {
        self.buffer_if_away(&gossip_env).await;
        self.inner.gossip.originate(&gossip_env).await.map(|_| ())
    }

    /// Buffer a user message for its recipient when that is a known peer currently
    /// disconnected.
    async fn buffer_if_away(&self, envelope: &GossipEnvelope) {
        if envelope.payload_type != GossipPayloadType::UserMessage as u8 {
            return;
        }
        let Some(dest) = user_message_dest(&envelope.payload) else {
            return;
        };
        if dest == self.inner.our_peer_id || !guard(&self.inner.known).contains(&dest) {
            return;
        }
        if self.inner.pool.is_connected(&dest).await {
            return;
        }
        if let Err(e) = self.inner.store.store(&dest, envelope).await {
            warn!(peer = %dest, error = %e, "message not buffered");
        }
    }

    /// Handle a frame from peer `from`: a sync frame or a gossip envelope. Returns the
    /// envelope when it is for the application here.
    pub async fn handle_incoming(
        &self,
        from: &PeerId,
        data: &[u8],
    ) -> Result<Option<GossipEnvelope>, MeshError> {
        if SyncFrame::is_sync_frame(data) {
            self.handle_sync(from, data).await?;
            return Ok(None);
        }
        self.accept(Some(*from), data).await
    }

    /// Hand a gossip envelope to this node as if it had originated here: it is
    /// validated and forwarded like any other, with no peer to send it back to. This
    /// is how an exit relay puts a message that came down a circuit into the mesh
    /// (PNP-005-SHOULD-015).
    pub async fn inject(&self, data: &[u8]) -> Result<Option<GossipEnvelope>, MeshError> {
        self.accept(None, data).await
    }

    async fn accept(
        &self,
        from: Option<PeerId>,
        data: &[u8],
    ) -> Result<Option<GossipEnvelope>, MeshError> {
        let processed = self.inner.gossip.process(from, data).await?;
        if let Some(forward) = &processed.forward {
            self.buffer_if_away(forward).await;
        }
        match processed.action {
            GossipAction::Deliver | GossipAction::DeliverAndForward { .. } => {
                self.note_announcement(&processed.envelope);
                guard(&self.inner.subscribers)
                    .retain(|tx| tx.send(processed.envelope.clone()).is_ok());
                Ok(Some(processed.envelope))
            }
            _ => Ok(None),
        }
    }

    /// One step of the sync exchange with `peer` (PNP-005 §5.7 item 2).
    async fn handle_sync(&self, peer: &PeerId, data: &[u8]) -> Result<(), MeshError> {
        let inner = &self.inner;
        let frame = SyncFrame::decode(data)?;
        let Some(conn) = inner.pool.get_connection(peer).await else {
            return Ok(());
        };
        let send = |frame: SyncFrame| {
            let conn = conn.clone();
            async move {
                let bytes = frame.encode()?;
                conn.send(&bytes)
                    .await
                    .map_err(|e| MeshError::SyncError(e.to_string()))
            }
        };
        let my_ids = inner.gossip.cached_ids();

        match frame {
            SyncFrame::Offer(theirs) => {
                if !inner.sync.lock().await.contains_key(peer) {
                    return Ok(());
                }
                let mut diff = GossipIblt::from_ids(my_ids.iter());
                diff.subtract(&theirs);
                match diff.decode() {
                    // What only the peer has is what we ask for.
                    Ok((_ours, theirs_only)) => {
                        send(SyncFrame::Request {
                            keys: theirs_only,
                            ids: Vec::new(),
                        })
                        .await?
                    }
                    // Too many differences for the table: full ID lists, 500 a frame
                    // (PNP-005-SHOULD-007).
                    Err(_) => self.send_id_list(peer, &my_ids, &send).await?,
                }
            }
            SyncFrame::Ids { ids, fin } => {
                let complete = {
                    let mut sessions = inner.sync.lock().await;
                    let Some(session) = sessions.get_mut(peer) else {
                        return Ok(());
                    };
                    let room = MAX_FALLBACK_IDS.saturating_sub(session.their_ids.len());
                    session.their_ids.extend(ids.into_iter().take(room));
                    fin.then(|| std::mem::take(&mut session.their_ids))
                };
                self.send_id_list(peer, &my_ids, &send).await?;
                if let Some(theirs) = complete {
                    let mine: HashSet<[u8; 32]> = my_ids.into_iter().collect();
                    let wanted: Vec<[u8; 32]> = theirs
                        .into_iter()
                        .filter(|id| !mine.contains(id) && !inner.gossip.dedup.is_seen(id))
                        .take(MAX_SYNC_REQUEST)
                        .collect();
                    send(SyncFrame::Request {
                        keys: Vec::new(),
                        ids: wanted,
                    })
                    .await?;
                }
            }
            SyncFrame::Request { keys, ids } => {
                // One request per sync phase is answered: a peer cannot use the sync
                // to have this node send its cache over and over.
                let first = inner
                    .sync
                    .lock()
                    .await
                    .get(peer)
                    .is_some_and(|session| !session.served);
                if !first {
                    return Ok(());
                }
                let by_key: HashMap<u64, [u8; 32]> =
                    my_ids.iter().map(|id| (iblt_key(id), *id)).collect();
                let wanted: Vec<[u8; 32]> = keys
                    .iter()
                    .filter_map(|k| by_key.get(k).copied())
                    .chain(ids)
                    .collect();
                let mut sent = Vec::new();
                let mut messages = Vec::new();
                for id in wanted {
                    if let Some(bytes) = inner.gossip.cached(&id) {
                        sent.push(id);
                        messages.push(bytes);
                    }
                }
                for frame in SyncFrame::data_frames(messages) {
                    send(frame).await?;
                }
                let done = {
                    let mut sessions = inner.sync.lock().await;
                    sessions.get_mut(peer).is_some_and(|session| {
                        session.sent.extend(sent);
                        session.served = true;
                        session.got_data
                    })
                };
                if done {
                    self.finish_sync(peer).await;
                }
            }
            SyncFrame::Data { messages, fin } => {
                if !inner.sync.lock().await.contains_key(peer) {
                    return Ok(());
                }
                for message in messages {
                    // What we asked for and have meanwhile seen is not a duplicate the
                    // peer is to blame for.
                    let already_seen = GossipEnvelope::decode_unvalidated(&message)
                        .ok()
                        .and_then(|e| e.message_id())
                        .is_some_and(|id| inner.gossip.dedup.is_seen(&id));
                    if already_seen {
                        continue;
                    }
                    // Each goes through the validation every gossip message does.
                    let _ = self.accept(Some(*peer), &message).await;
                }
                if fin {
                    let done = {
                        let mut sessions = inner.sync.lock().await;
                        sessions.get_mut(peer).is_some_and(|session| {
                            session.got_data = true;
                            session.served
                        })
                    };
                    if done {
                        self.finish_sync(peer).await;
                    }
                }
            }
        }
        Ok(())
    }

    /// Send our full ID list to `peer`, once per sync.
    async fn send_id_list<F, Fut>(
        &self,
        peer: &PeerId,
        my_ids: &[[u8; 32]],
        send: &F,
    ) -> Result<(), MeshError>
    where
        F: Fn(SyncFrame) -> Fut,
        Fut: std::future::Future<Output = Result<(), MeshError>>,
    {
        {
            let mut sessions = self.inner.sync.lock().await;
            let Some(session) = sessions.get_mut(peer) else {
                return Ok(());
            };
            if session.sent_ids {
                return Ok(());
            }
            session.sent_ids = true;
        }
        for frame in SyncFrame::id_batches(my_ids) {
            send(frame).await?;
        }
        Ok(())
    }

    /// Receive every gossip message delivered to the application here.
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<GossipEnvelope> {
        let (tx, rx) = mpsc::unbounded_channel();
        guard(&self.inner.subscribers).push(tx);
        rx
    }

    /// Tell the mesh which addresses this node listens on. A change is announced at
    /// once with a PEER_ANNOUNCEMENT; after that one goes out every 30 minutes
    /// (PNP-005-SHOULD-011).
    pub async fn set_listen_addrs(&self, addrs: Vec<SocketAddr>) -> Result<(), MeshError> {
        {
            let mut current = guard(&self.inner.listen_addrs);
            if *current == addrs {
                return Ok(());
            }
            *current = addrs;
        }
        self.ensure_housekeeping();
        self.announce().await
    }

    async fn announce(&self) -> Result<(), MeshError> {
        let addrs: Vec<String> = guard(&self.inner.listen_addrs)
            .iter()
            .map(|a| a.to_string())
            .collect();
        if addrs.is_empty() {
            return Ok(());
        }
        *guard(&self.inner.last_announce) = Some(Instant::now());
        let payload = PeerAnnouncement {
            peer_id: self.inner.our_peer_id,
            addrs,
        }
        .to_cbor()
        .map_err(|e| MeshError::ValidationFailed(e.to_string()))?;
        self.publish(GossipPayloadType::PeerAnnouncement as u8, payload)
            .await
            .map(|_| ())
    }

    /// Record the addresses a PEER_ANNOUNCEMENT carries. The announcement is the
    /// announcing node's own: its `peer_id` is the PeerId that signed the envelope.
    fn note_announcement(&self, envelope: &GossipEnvelope) {
        if envelope.payload_type != GossipPayloadType::PeerAnnouncement as u8 {
            return;
        }
        let Ok(announcement) = PeerAnnouncement::from_cbor(&envelope.payload) else {
            return;
        };
        if announcement.peer_id != envelope.src {
            return;
        }
        let addrs: Vec<SocketAddr> = announcement
            .addrs
            .iter()
            .take(8)
            .filter_map(|a| a.parse().ok())
            .collect();
        let mut announced = guard(&self.inner.announced);
        if announced.len() < 4096 || announced.contains_key(&announcement.peer_id) {
            announced.insert(announcement.peer_id, addrs);
        }
    }

    /// The addresses a node last announced.
    pub fn known_addrs(&self, peer_id: &PeerId) -> Vec<SocketAddr> {
        guard(&self.inner.announced)
            .get(peer_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Our PeerId.
    pub fn peer_id(&self) -> PeerId {
        self.inner.our_peer_id
    }

    /// Get a reference to the connection pool.
    pub fn pool(&self) -> &Arc<ConnectionPool> {
        &self.inner.pool
    }

    /// The gossip engine.
    pub fn gossip(&self) -> &StandardGossip {
        &self.inner.gossip
    }

    /// The store-and-forward buffer.
    pub fn store(&self) -> &InMemoryStore {
        &self.inner.store
    }

    /// Number of connected peers.
    pub async fn peer_count(&self) -> usize {
        self.inner.pool.peer_count().await
    }

    /// One pass of housekeeping: expired messages leave the buffers and the sync
    /// cache, the deduplication filter rotates if 12 hours have passed, expired bans
    /// are dropped, and the node's addresses are announced again if 30 minutes have.
    /// A background task runs this every 60 seconds once a peer has been added.
    pub async fn run_maintenance(&self) -> Result<(), MeshError> {
        let expired = self.inner.store.expire().await?;
        if expired > 0 {
            info!(count = expired, "expired stored messages");
        }
        self.inner.gossip.purge_expired();
        self.inner.gossip.dedup.is_seen(&[0u8; 32]);
        self.inner.pool.prune_bans().await;

        let due =
            guard(&self.inner.last_announce).is_some_and(|at| at.elapsed() >= ANNOUNCE_INTERVAL);
        if due {
            self.announce().await?;
        }
        Ok(())
    }

    /// Securely erase everything buffered: the store-and-forward buffers (and their
    /// file, if persisted), the messages held for sync, and what the node remembers
    /// having seen (PNP-005-SHOULD-016).
    pub async fn panic_wipe(&self) -> Result<(), MeshError> {
        self.inner.store.wipe().await?;
        self.inner.gossip.wipe();
        guard(&self.inner.announced).clear();
        guard(&self.inner.known).clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parolnet_transport::TransportError;
    use tokio::sync::Mutex;

    struct MockConnection {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockConnection {
        fn new() -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (Self { sent: sent.clone() }, sent)
        }
    }

    #[async_trait]
    impl Connection for MockConnection {
        async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
            self.sent.lock().await.push(data.to_vec());
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
        let mgr = PeerManager::new(
            PeerId([0xAA; 32]),
            ed25519_dalek::SigningKey::from_bytes(&[0xAA; 32]),
        );
        let peer_id = PeerId([0xBB; 32]);
        let (conn, sent) = MockConnection::new();

        mgr.add_peer(peer_id, Arc::new(conn)).await.unwrap();
        assert_eq!(mgr.peer_count().await, 1);
        assert!(mgr.is_syncing(&peer_id).await);
        // The first thing a new peer gets is our sync offer.
        assert!(SyncFrame::is_sync_frame(&sent.lock().await[0]));

        mgr.remove_peer(&peer_id).await;
        assert_eq!(mgr.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_run_maintenance() {
        let mgr = PeerManager::new(
            PeerId([0xAA; 32]),
            ed25519_dalek::SigningKey::from_bytes(&[0xAA; 32]),
        );
        // Should not panic with empty state
        mgr.run_maintenance().await.unwrap();
    }
}
