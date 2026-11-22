//! In-process networks for the PNP-004 and PNP-005 conformance tests.
//!
//! Nothing here is under test. It is the wire: in-memory connections that record what
//! crosses them and when, relay services dialing each other through those connections,
//! and fixtures for building gossip envelopes the way an originator would.
//!
//! Relays that carry user traffic are library code and an opt-in relay profile; the
//! default deployment is signaling-only. These tests run that library code for real,
//! between nodes in one process.

#![allow(dead_code)]

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use parolnet_mesh::gossip::{ProofOfWork, SeenBloomFilter};
use parolnet_protocol::address::PeerId;
use parolnet_protocol::gossip::GossipEnvelope;
use parolnet_relay::directory::{RelayDescriptor, RelayDirectory};
use parolnet_relay::relay_node::StandardRelayNode;
use parolnet_relay::service::{ExitCircuit, ExitHandler, LinkDialer, RelayService};
use parolnet_relay::stream::DataCommand;
use parolnet_relay::{CELL_SIZE, CellType, RelayCell, RelayError, RelayInfo};
use parolnet_transport::{Connection, TransportError};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

// ── Connections ───────────────────────────────────────────────

/// One end of an in-memory connection. It records every frame sent on it, with the
/// time, and can be stalled to stand for a congested link.
pub struct PipeEnd {
    tx: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    sent: Mutex<Vec<(Instant, Vec<u8>)>>,
    stalled: AtomicBool,
}

/// A connected pair of ends.
pub fn pipe() -> (Arc<PipeEnd>, Arc<PipeEnd>) {
    let (a_tx, b_rx) = mpsc::unbounded_channel();
    let (b_tx, a_rx) = mpsc::unbounded_channel();
    let end = |tx, rx| {
        Arc::new(PipeEnd {
            tx: Mutex::new(Some(tx)),
            rx: tokio::sync::Mutex::new(rx),
            sent: Mutex::new(Vec::new()),
            stalled: AtomicBool::new(false),
        })
    };
    (end(a_tx, a_rx), end(b_tx, b_rx))
}

impl PipeEnd {
    /// Every frame sent on this end so far.
    pub fn sent(&self) -> Vec<Vec<u8>> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(_, f)| f.clone())
            .collect()
    }

    /// Every frame sent on this end so far, with when it was sent.
    pub fn sent_at(&self) -> Vec<(Instant, Vec<u8>)> {
        self.sent.lock().unwrap().clone()
    }

    /// The cells sent on this end so far (frames that are not cells are skipped).
    pub fn cells(&self) -> Vec<RelayCell> {
        self.sent().iter().filter_map(|f| cell_of(f)).collect()
    }

    /// The cells of one type sent on this end so far.
    pub fn cells_of(&self, cell_type: CellType) -> Vec<RelayCell> {
        self.cells()
            .into_iter()
            .filter(|c| c.cell_type == cell_type)
            .collect()
    }

    /// Stop this end from sending: `send` waits until [`Self::unstall`].
    pub fn stall(&self) {
        self.stalled.store(true, Ordering::SeqCst);
    }

    pub fn unstall(&self) {
        self.stalled.store(false, Ordering::SeqCst);
    }

    /// Close this end: the other end's `recv` fails once it has read what was sent.
    pub fn hang_up(&self) {
        self.tx.lock().unwrap().take();
    }

    /// Next frame, or `None` when none arrives within `within`.
    pub async fn recv_within(&self, within: Duration) -> Option<Vec<u8>> {
        tokio::time::timeout(within, self.recv()).await.ok()?.ok()
    }

    /// Next cell, skipping frames that are not cells.
    pub async fn recv_cell(&self) -> RelayCell {
        loop {
            let frame = self.recv().await.expect("connection closed");
            if let Some(cell) = cell_of(&frame) {
                return cell;
            }
        }
    }
}

pub fn cell_of(frame: &[u8]) -> Option<RelayCell> {
    let buf: [u8; CELL_SIZE] = frame.try_into().ok()?;
    RelayCell::from_bytes(&buf).ok()
}

#[async_trait]
impl Connection for PipeEnd {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        while self.stalled.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let tx = self.tx.lock().unwrap().clone();
        let tx = tx.ok_or(TransportError::ConnectionClosed)?;
        self.sent
            .lock()
            .unwrap()
            .push((Instant::now(), data.to_vec()));
        tx.send(data.to_vec())
            .map_err(|_| TransportError::ConnectionClosed)
    }

    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(TransportError::ConnectionClosed)
    }

    async fn close(&self) -> Result<(), TransportError> {
        self.hang_up();
        Ok(())
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
}

/// Let every task that can run, run. On a paused clock this also lets timers due
/// within the millisecond fire.
pub async fn settle() {
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

// ── Identities ────────────────────────────────────────────────

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An Ed25519 identity from a seed byte, and its PeerId.
pub fn identity(seed: u8) -> (SigningKey, PeerId) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let id = PeerId::from_public_key(&key.verifying_key().to_bytes());
    (key, id)
}

// ── Relay network ─────────────────────────────────────────────

/// A dialed connection: who opened it, to whom, and both ends. `from_end.sent()` is
/// what the dialer sent, `to_end.sent()` what the relay it dialed sent back.
#[derive(Clone)]
pub struct Tap {
    /// `None` when the originator dialed.
    pub from: Option<SocketAddr>,
    pub to: SocketAddr,
    pub from_end: Arc<PipeEnd>,
    pub to_end: Arc<PipeEnd>,
}

/// What a test exit saw: (stream id, command, data).
pub type Delivered = Arc<Mutex<Vec<(u32, DataCommand, Vec<u8>)>>>;

/// An exit that sends every DATA cell back on the stream it came on.
pub struct EchoExit {
    pub seen: Delivered,
}

#[async_trait]
impl ExitHandler for EchoExit {
    async fn on_data(
        &self,
        service: &Arc<RelayService>,
        circuit: ExitCircuit,
        stream_id: u32,
        command: DataCommand,
        data: Vec<u8>,
    ) {
        self.seen
            .lock()
            .unwrap()
            .push((stream_id, command, data.clone()));
        let _ = service.exit_send(circuit, stream_id, command, &data);
    }
}

pub struct TestRelay {
    pub info: RelayInfo,
    pub key: SigningKey,
    pub node: Arc<StandardRelayNode>,
    pub service: Arc<RelayService>,
    pub delivered: Delivered,
}

#[derive(Default)]
struct NetState {
    services: HashMap<SocketAddr, Arc<RelayService>>,
    /// Relays that accept a connection and never answer on it.
    silent: HashSet<SocketAddr>,
    /// How long a dial to an address takes.
    dial_delay: HashMap<SocketAddr, Duration>,
    taps: Vec<Tap>,
    /// Connections to silent relays, kept open.
    parked: Vec<Arc<PipeEnd>>,
}

/// Relays in one process, reaching each other by address.
#[derive(Clone, Default)]
pub struct RelayNet {
    state: Arc<Mutex<NetState>>,
}

struct NetDialer {
    net: RelayNet,
    from: Option<SocketAddr>,
}

#[async_trait]
impl LinkDialer for NetDialer {
    async fn dial(&self, addr: SocketAddr) -> Result<Arc<dyn Connection>, RelayError> {
        let delay = self
            .net
            .state
            .lock()
            .unwrap()
            .dial_delay
            .get(&addr)
            .copied();
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        let (near, far) = pipe();
        let mut state = self.net.state.lock().unwrap();
        state.taps.push(Tap {
            from: self.from,
            to: addr,
            from_end: near.clone(),
            to_end: far.clone(),
        });
        if state.silent.contains(&addr) {
            state.parked.push(far);
            return Ok(near);
        }
        let service = state
            .services
            .get(&addr)
            .cloned()
            .ok_or_else(|| RelayError::CircuitBuildFailed(format!("no relay at {addr}")))?;
        drop(state);
        service.accept(far);
        Ok(near)
    }
}

/// The address of test relay `index`: each in its own /16.
pub fn relay_addr(index: u8) -> SocketAddr {
    format!("10.{index}.0.1:9001").parse().unwrap()
}

/// A signed descriptor for a test relay, timestamped now, with 8 days of uptime.
pub fn descriptor(index: u8, addr: SocketAddr) -> (SigningKey, RelayDescriptor) {
    let (key, peer_id) = identity(index);
    let descriptor = RelayDirectory::create_descriptor(
        peer_id,
        key.verifying_key().to_bytes(),
        [index; 32],
        addr,
        1,
        8 * 24 * 3600,
        now_secs(),
        &key,
    );
    (key, descriptor)
}

impl RelayNet {
    pub fn new() -> Self {
        Self::default()
    }

    /// A dialer for the originator.
    pub fn op_dialer(&self) -> Arc<dyn LinkDialer> {
        Arc::new(NetDialer {
            net: self.clone(),
            from: None,
        })
    }

    /// Start relays `1..=count`, each knowing all of them, each an echo exit.
    pub fn start(&self, count: u8) -> Vec<TestRelay> {
        self.start_with(count, &|_| None)
    }

    /// As [`Self::start`]; `exit_for(index)` may give relay `index` another exit.
    pub fn start_with(
        &self,
        count: u8,
        exit_for: &dyn Fn(u8) -> Option<Arc<dyn ExitHandler>>,
    ) -> Vec<TestRelay> {
        let described: Vec<(SigningKey, RelayDescriptor)> =
            (1..=count).map(|i| descriptor(i, relay_addr(i))).collect();
        described
            .iter()
            .zip(1..=count)
            .map(|((key, own), index)| {
                let mut directory = RelayDirectory::new();
                for (_, d) in &described {
                    directory.insert(d.clone());
                }
                let node = Arc::new(StandardRelayNode::with_directory(directory));
                let delivered: Delivered = Arc::new(Mutex::new(Vec::new()));
                let service = RelayService::new(
                    node.clone(),
                    Arc::new(NetDialer {
                        net: self.clone(),
                        from: Some(own.addr),
                    }),
                    Some(exit_for(index).unwrap_or_else(|| {
                        Arc::new(EchoExit {
                            seen: delivered.clone(),
                        })
                    })),
                );
                self.state
                    .lock()
                    .unwrap()
                    .services
                    .insert(own.addr, service.clone());
                TestRelay {
                    info: own.to_relay_info(),
                    key: key.clone(),
                    node,
                    service,
                    delivered,
                }
            })
            .collect()
    }

    /// Put a relay built by the test at `addr`.
    pub fn register(&self, addr: SocketAddr, service: Arc<RelayService>) {
        self.state.lock().unwrap().services.insert(addr, service);
    }

    /// A dialer for a relay at `addr`.
    pub fn relay_dialer(&self, addr: SocketAddr) -> Arc<dyn LinkDialer> {
        Arc::new(NetDialer {
            net: self.clone(),
            from: Some(addr),
        })
    }

    /// Make the relay at `addr` accept connections and never answer.
    pub fn silence(&self, addr: SocketAddr) {
        self.state.lock().unwrap().silent.insert(addr);
    }

    /// Make dialing `addr` take `delay`.
    pub fn slow_dial(&self, addr: SocketAddr, delay: Duration) {
        self.state.lock().unwrap().dial_delay.insert(addr, delay);
    }

    /// Every connection dialed so far.
    pub fn taps(&self) -> Vec<Tap> {
        self.state.lock().unwrap().taps.clone()
    }

    /// The connections dialed from `from` to `to`, oldest first.
    pub fn taps_between(&self, from: Option<SocketAddr>, to: SocketAddr) -> Vec<Tap> {
        self.taps()
            .into_iter()
            .filter(|t| t.from == from && t.to == to)
            .collect()
    }

    /// The one connection dialed from `from` to `to`.
    pub fn tap(&self, from: Option<SocketAddr>, to: SocketAddr) -> Tap {
        let mut taps = self.taps_between(from, to);
        assert_eq!(taps.len(), 1, "expected one connection {from:?} -> {to}");
        taps.remove(0)
    }
}

// ── Gossip fixtures ───────────────────────────────────────────

/// What an originator decides about a gossip envelope. The defaults are a valid
/// USER_MESSAGE; tests change one thing at a time.
pub struct Draft {
    pub key: SigningKey,
    pub payload_type: u8,
    pub payload: Vec<u8>,
    pub ttl: u8,
    pub ts: u64,
    pub lifetime: u64,
    pub difficulty: u8,
    pub id: [u8; 32],
    pub anonymous: bool,
}

impl Draft {
    pub fn new(key: &SigningKey) -> Self {
        Self {
            key: key.clone(),
            payload_type: 0x02,
            payload: b"hello mesh".to_vec(),
            ttl: 7,
            ts: now_secs(),
            lifetime: 86400,
            difficulty: 16,
            id: rand::random(),
            anonymous: false,
        }
    }

    pub fn payload_type(mut self, t: u8) -> Self {
        self.payload_type = t;
        self
    }
    pub fn payload(mut self, p: Vec<u8>) -> Self {
        self.payload = p;
        self
    }
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }
    pub fn ts(mut self, ts: u64) -> Self {
        self.ts = ts;
        self
    }
    pub fn lifetime(mut self, secs: u64) -> Self {
        self.lifetime = secs;
        self
    }
    pub fn difficulty(mut self, bits: u8) -> Self {
        self.difficulty = bits;
        self
    }
    pub fn anonymous(mut self) -> Self {
        self.anonymous = true;
        self
    }

    /// The envelope: proof of work computed, signed by `key`, `seen` holding the
    /// originator.
    pub fn build(self) -> GossipEnvelope {
        let public = self.key.verifying_key().to_bytes();
        let origin = PeerId::from_public_key(&public);
        let (src, src_pubkey) = if self.anonymous {
            (PeerId([0u8; 32]), Vec::new())
        } else {
            (origin, public.to_vec())
        };
        let mut seen = SeenBloomFilter::new();
        seen.insert(&origin);
        let pow = ProofOfWork::compute(&self.id, &src, self.ts, self.difficulty);
        let mut envelope = GossipEnvelope {
            v: 1,
            id: self.id.to_vec(),
            src,
            src_pubkey,
            ts: self.ts,
            exp: self.ts + self.lifetime,
            ttl: self.ttl,
            hops: 0,
            seen: seen.as_bytes().to_vec(),
            pow: pow.to_vec(),
            sig: vec![0u8; 64],
            payload_type: self.payload_type,
            payload: self.payload,
        };
        resign(&mut envelope, &self.key);
        envelope
    }
}

/// Sign an envelope as its originator would.
pub fn resign(envelope: &mut GossipEnvelope, key: &SigningKey) {
    envelope.sig = key.sign(&envelope.signable_bytes()).to_bytes().to_vec();
}

/// Recompute the proof of work of an envelope at `difficulty`.
pub fn reprove(envelope: &mut GossipEnvelope, difficulty: u8) {
    let id = envelope.message_id().unwrap();
    envelope.pow = ProofOfWork::compute(&id, &envelope.src, envelope.ts, difficulty).to_vec();
}

/// Leading zero bits of `SHA-256(SHA-256("pgmp-pow-v1" || id || src || ts) || nonce)`,
/// computed here from the spec's formula.
pub fn pow_zero_bits(envelope: &GossipEnvelope) -> u32 {
    use sha2::{Digest, Sha256};
    let mut challenge = Sha256::new();
    challenge.update(b"pgmp-pow-v1");
    challenge.update(&envelope.id);
    challenge.update(envelope.src.0);
    challenge.update(envelope.ts.to_be_bytes());
    let mut h = Sha256::new();
    h.update(challenge.finalize());
    h.update(&envelope.pow);
    let digest = h.finalize();
    let mut bits = 0;
    for byte in digest {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// The gossip envelopes among the frames sent on a connection.
pub fn gossip_frames(end: &PipeEnd) -> Vec<GossipEnvelope> {
    end.sent()
        .iter()
        .filter(|f| !parolnet_mesh::reconcile::SyncFrame::is_sync_frame(f))
        .filter_map(|f| GossipEnvelope::decode_unvalidated(f).ok())
        .collect()
}

/// A PNP-001 envelope addressed to `dest`, CBOR-encoded: what a USER_MESSAGE carries.
pub fn user_payload(dest: PeerId, body: &[u8]) -> Vec<u8> {
    use parolnet_protocol::envelope::{CleartextHeader, Envelope};
    let envelope = Envelope {
        cleartext_header: CleartextHeader {
            version: 1,
            msg_type: 0x01,
            dest_peer_id: dest,
            message_id: rand::random(),
            timestamp: now_secs() / 300 * 300,
            ttl_and_hops: 7 << 8,
            source_hint: None,
        },
        ratchet_header: parolnet_crypto::RatchetHeader {
            ratchet_key: [0u8; 32],
            previous_chain_length: 0,
            message_number: 0,
        },
        encrypted_payload: body.to_vec(),
        padding: vec![],
    };
    let mut out = Vec::new();
    ciborium::into_writer(&envelope, &mut out).unwrap();
    out
}

/// Wait (on a paused clock, or a real one) until `cond` holds; panic after `limit`.
pub async fn eventually(limit: Duration, what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
