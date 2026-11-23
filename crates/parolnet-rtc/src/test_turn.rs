//! A minimal in-process TURN server for tests (feature `test-turn`): RFC 8656 over UDP on
//! loopback with one long-term credential. It answers Binding, Allocate (401 challenge, then
//! the authenticated request), Refresh (lifetime 0 releases), CreatePermission and
//! ChannelBind, and relays Send / Data indications and ChannelData between an allocation's
//! own UDP socket and the peers it has a permission for.
//!
//! It stands in for the TURN server a user would run; it is not one. No nonce expiry, no
//! allocation lifetime, no quotas, no TCP.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use rtc::crypto::RTCCryptoProvider;
use rtc::stun::attributes::{
    ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM, ATTR_USERNAME, ATTR_XOR_PEER_ADDRESS,
};
use rtc::stun::error_code::{
    CODE_ALLOC_MISMATCH, CODE_BAD_REQUEST, CODE_UNAUTHORIZED, ErrorCode, ErrorCodeAttribute,
};
use rtc::stun::fingerprint::FINGERPRINT;
use rtc::stun::integrity::MessageIntegrity;
use rtc::stun::message::{
    CLASS_ERROR_RESPONSE, CLASS_INDICATION, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, Getter as _,
    MAGIC_COOKIE, METHOD_ALLOCATE, METHOD_BINDING, METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION,
    METHOD_DATA, METHOD_REFRESH, METHOD_SEND, Message, MessageType, Setter, TransactionId,
    is_stun_message,
};
use rtc::stun::textattrs::TextAttribute;
use rtc::stun::xoraddr::XorMappedAddress;
use rtc::turn::proto::chandata::ChannelData;
use rtc::turn::proto::channum::ChannelNumber;
use rtc::turn::proto::data::Data;
use rtc::turn::proto::lifetime::Lifetime;
use rtc::turn::proto::peeraddr::PeerAddress;
use rtc::turn::proto::relayaddr::RelayedAddress;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const REALM: &str = "parolnet-test";
const NONCE: &str = "test-nonce-0001";
const LIFETIME: Duration = Duration::from_secs(600);

#[derive(Default)]
struct Stats {
    live: AtomicUsize,
    allocated: AtomicU64,
    relayed: AtomicU64,
    refused: AtomicU64,
    refreshes: AtomicU64,
}

/// The server; it stops when dropped.
pub struct TestTurnServer {
    addr: SocketAddr,
    stats: Arc<Stats>,
    task: JoinHandle<()>,
}

impl Drop for TestTurnServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestTurnServer {
    /// Listen on a free loopback port and accept `username` / `password`.
    pub async fn start(username: &str, password: &str) -> std::io::Result<TestTurnServer> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = socket.local_addr()?;
        let provider = rtc::crypto::default_provider().map_err(std::io::Error::other)?;
        let key = MessageIntegrity::long_term_integrity_key(
            username.to_owned(),
            REALM.to_owned(),
            password.to_owned(),
            provider.crypto(),
        )
        .map_err(std::io::Error::other)?;
        let stats = Arc::new(Stats::default());
        let (relayed_tx, relayed_rx) = mpsc::unbounded_channel();
        let server = Server {
            socket,
            username: username.to_owned(),
            key,
            provider,
            allocations: HashMap::new(),
            stats: stats.clone(),
            relayed_tx,
        };
        let task = tokio::spawn(server.run(relayed_rx));
        Ok(TestTurnServer { addr, stats, task })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The URI a user would enter in settings.
    pub fn uri(&self) -> String {
        format!("turn:{}?transport=udp", self.addr)
    }

    /// Allocations that exist now.
    pub fn live_allocations(&self) -> usize {
        self.stats.live.load(Ordering::Relaxed)
    }

    /// Allocations made since the start.
    pub fn allocations_made(&self) -> u64 {
        self.stats.allocated.load(Ordering::Relaxed)
    }

    /// Datagrams relayed in either direction.
    pub fn relayed_datagrams(&self) -> u64 {
        self.stats.relayed.load(Ordering::Relaxed)
    }

    /// Refresh requests that kept an allocation alive (releases not counted).
    pub fn refreshes(&self) -> u64 {
        self.stats.refreshes.load(Ordering::Relaxed)
    }

    /// Requests refused for a missing or wrong credential (the first, unauthenticated
    /// Allocate of every client included).
    pub fn refused_requests(&self) -> u64 {
        self.stats.refused.load(Ordering::Relaxed)
    }
}

struct Allocation {
    relay: Arc<UdpSocket>,
    permissions: HashSet<IpAddr>,
    channel_of: HashMap<SocketAddr, u16>,
    peer_of: HashMap<u16, SocketAddr>,
    reader: JoinHandle<()>,
}

impl Drop for Allocation {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// (the allocation's client, the peer that sent to the relayed address, the datagram)
type Relayed = (SocketAddr, SocketAddr, Vec<u8>);

struct Server {
    socket: UdpSocket,
    username: String,
    key: Vec<u8>,
    provider: Arc<dyn RTCCryptoProvider>,
    allocations: HashMap<SocketAddr, Allocation>,
    stats: Arc<Stats>,
    relayed_tx: mpsc::UnboundedSender<Relayed>,
}

impl Server {
    async fn run(mut self, mut relayed_rx: mpsc::UnboundedReceiver<Relayed>) {
        let mut buf = vec![0u8; 4096];
        loop {
            tokio::select! {
                received = self.socket.recv_from(&mut buf) => {
                    let Ok((n, from)) = received else { continue };
                    self.on_client_datagram(&buf[..n], from).await;
                }
                Some((client, peer, data)) = relayed_rx.recv() => {
                    self.on_peer_datagram(client, peer, &data).await;
                }
            }
        }
    }

    async fn send(&self, to: SocketAddr, bytes: &[u8]) {
        let _ = self.socket.send_to(bytes, to).await;
    }

    /// A response to `request`; signed unless it is the 401 challenge or a Binding answer.
    /// (Built apart from the send: STUN setters are not `Send`.)
    fn reply(
        &self,
        request: &Message,
        class: rtc::stun::message::MessageClass,
        attrs: Vec<Box<dyn Setter>>,
        signed: bool,
    ) -> Vec<u8> {
        let mut setters: Vec<Box<dyn Setter + '_>> = vec![
            Box::new(request.transaction_id),
            Box::new(MessageType::new(request.typ.method, class)),
        ];
        for a in attrs {
            setters.push(a);
        }
        if signed {
            setters.push(Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                self.key.clone(),
                self.provider.crypto(),
            )));
        }
        setters.push(Box::new(FINGERPRINT));
        let mut reply = Message::new();
        match reply.build(&setters) {
            Ok(()) => reply.raw,
            Err(_) => Vec::new(),
        }
    }

    async fn respond(
        &self,
        to: SocketAddr,
        request: &Message,
        class: rtc::stun::message::MessageClass,
        attrs: impl FnOnce() -> Vec<Box<dyn Setter>>,
        signed: bool,
    ) {
        let bytes = self.reply(request, class, attrs(), signed);
        if !bytes.is_empty() {
            self.send(to, &bytes).await;
        }
    }

    async fn error(&self, to: SocketAddr, request: &Message, code: ErrorCode, signed: bool) {
        let attrs = || {
            let mut attrs: Vec<Box<dyn Setter>> = vec![Box::new(ErrorCodeAttribute {
                code,
                reason: b"refused".to_vec(),
            })];
            if code == CODE_UNAUTHORIZED {
                attrs.push(Box::new(TextAttribute::new(ATTR_REALM, REALM.to_owned())));
                attrs.push(Box::new(TextAttribute::new(ATTR_NONCE, NONCE.to_owned())));
            }
            attrs
        };
        self.respond(to, request, CLASS_ERROR_RESPONSE, attrs, signed)
            .await;
    }

    /// Whether `msg` carries the configured username and a MESSAGE-INTEGRITY made with its key.
    fn authentic(&self, msg: &mut Message) -> bool {
        if !msg.contains(ATTR_MESSAGE_INTEGRITY) {
            return false;
        }
        let user = TextAttribute::get_from_as(msg, ATTR_USERNAME).map(|u| u.text);
        user.is_ok_and(|u| u == self.username)
            && MessageIntegrity::check(msg, &self.key, self.provider.crypto()).is_ok()
    }

    async fn on_client_datagram(&mut self, data: &[u8], from: SocketAddr) {
        if !is_stun_message(data) {
            if ChannelData::is_channel_data(data) {
                self.on_channel_data(data, from).await;
            }
            return;
        }
        let mut msg = Message::new();
        msg.raw = data.to_vec();
        if msg.decode().is_err() {
            return;
        }
        if msg.typ.class == CLASS_INDICATION {
            if msg.typ.method == METHOD_SEND {
                self.on_send_indication(&msg, from).await;
            }
            return;
        }
        if msg.typ.class != CLASS_REQUEST {
            return;
        }
        if msg.typ.method == METHOD_BINDING {
            let mapped = || -> Vec<Box<dyn Setter>> {
                vec![Box::new(XorMappedAddress {
                    ip: from.ip(),
                    port: from.port(),
                })]
            };
            self.respond(from, &msg, CLASS_SUCCESS_RESPONSE, mapped, false)
                .await;
            return;
        }
        if !self.authentic(&mut msg) {
            self.stats.refused.fetch_add(1, Ordering::Relaxed);
            self.error(from, &msg, CODE_UNAUTHORIZED, false).await;
            return;
        }
        match msg.typ.method {
            METHOD_ALLOCATE => self.on_allocate(&msg, from).await,
            METHOD_REFRESH => self.on_refresh(&msg, from).await,
            METHOD_CREATE_PERMISSION => self.on_create_permission(&msg, from).await,
            METHOD_CHANNEL_BIND => self.on_channel_bind(&msg, from).await,
            _ => self.error(from, &msg, CODE_BAD_REQUEST, true).await,
        }
    }

    async fn on_allocate(&mut self, msg: &Message, from: SocketAddr) {
        if self.allocations.contains_key(&from) {
            self.error(from, msg, CODE_ALLOC_MISMATCH, true).await;
            return;
        }
        let Ok(relay) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await else {
            return;
        };
        let Ok(relayed) = relay.local_addr() else {
            return;
        };
        let relay = Arc::new(relay);
        let reader = {
            let (relay, tx) = (relay.clone(), self.relayed_tx.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                while let Ok((n, peer)) = relay.recv_from(&mut buf).await {
                    if tx.send((from, peer, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            })
        };
        self.allocations.insert(
            from,
            Allocation {
                relay,
                permissions: HashSet::new(),
                channel_of: HashMap::new(),
                peer_of: HashMap::new(),
                reader,
            },
        );
        self.stats.live.fetch_add(1, Ordering::Relaxed);
        self.stats.allocated.fetch_add(1, Ordering::Relaxed);
        let attrs = || -> Vec<Box<dyn Setter>> {
            vec![
                Box::new(RelayedAddress {
                    ip: relayed.ip(),
                    port: relayed.port(),
                }),
                Box::new(XorMappedAddress {
                    ip: from.ip(),
                    port: from.port(),
                }),
                Box::new(Lifetime(LIFETIME)),
            ]
        };
        self.respond(from, msg, CLASS_SUCCESS_RESPONSE, attrs, true)
            .await;
    }

    async fn on_refresh(&mut self, msg: &Message, from: SocketAddr) {
        if !self.allocations.contains_key(&from) {
            self.error(from, msg, CODE_ALLOC_MISMATCH, true).await;
            return;
        }
        let mut lifetime = Lifetime(LIFETIME);
        let _ = lifetime.get_from(msg);
        if lifetime.0.is_zero() {
            self.allocations.remove(&from);
            self.stats.live.fetch_sub(1, Ordering::Relaxed);
        } else {
            lifetime = Lifetime(LIFETIME);
            self.stats.refreshes.fetch_add(1, Ordering::Relaxed);
        }
        let attrs = || -> Vec<Box<dyn Setter>> { vec![Box::new(lifetime)] };
        self.respond(from, msg, CLASS_SUCCESS_RESPONSE, attrs, true)
            .await;
    }

    async fn on_create_permission(&mut self, msg: &Message, from: SocketAddr) {
        let peers = peer_addresses(msg);
        let Some(allocation) = self.allocations.get_mut(&from) else {
            self.error(from, msg, CODE_ALLOC_MISMATCH, true).await;
            return;
        };
        if peers.is_empty() {
            self.error(from, msg, CODE_BAD_REQUEST, true).await;
            return;
        }
        allocation.permissions.extend(peers.iter().map(|p| p.ip()));
        self.respond(from, msg, CLASS_SUCCESS_RESPONSE, Vec::new, true)
            .await;
    }

    async fn on_channel_bind(&mut self, msg: &Message, from: SocketAddr) {
        let mut number = ChannelNumber::default();
        let mut peer = PeerAddress::default();
        let parsed = number.get_from(msg).is_ok() && peer.get_from(msg).is_ok();
        let Some(allocation) = self.allocations.get_mut(&from) else {
            self.error(from, msg, CODE_ALLOC_MISMATCH, true).await;
            return;
        };
        let peer = SocketAddr::new(peer.ip, peer.port);
        // A channel number or a peer already bound to something else is refused (RFC 8656 §12).
        let conflict = allocation
            .peer_of
            .get(&number.0)
            .is_some_and(|p| *p != peer)
            || allocation
                .channel_of
                .get(&peer)
                .is_some_and(|n| *n != number.0);
        if !parsed || !number.valid() || conflict {
            self.error(from, msg, CODE_BAD_REQUEST, true).await;
            return;
        }
        allocation.peer_of.insert(number.0, peer);
        allocation.channel_of.insert(peer, number.0);
        allocation.permissions.insert(peer.ip());
        self.respond(from, msg, CLASS_SUCCESS_RESPONSE, Vec::new, true)
            .await;
    }

    async fn on_send_indication(&mut self, msg: &Message, from: SocketAddr) {
        let (mut peer, mut data) = (PeerAddress::default(), Data::default());
        if peer.get_from(msg).is_err() || data.get_from(msg).is_err() {
            return;
        }
        let Some(allocation) = self.allocations.get(&from) else {
            return;
        };
        if !allocation.permissions.contains(&peer.ip) {
            return;
        }
        let to = SocketAddr::new(peer.ip, peer.port);
        if allocation.relay.send_to(&data.0, to).await.is_ok() {
            self.stats.relayed.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn on_channel_data(&mut self, raw: &[u8], from: SocketAddr) {
        let mut channel = ChannelData {
            raw: raw.to_vec(),
            ..Default::default()
        };
        if channel.decode().is_err() {
            return;
        }
        let Some(allocation) = self.allocations.get(&from) else {
            return;
        };
        let Some(peer) = allocation.peer_of.get(&channel.number.0) else {
            return;
        };
        if allocation.relay.send_to(&channel.data, peer).await.is_ok() {
            self.stats.relayed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A datagram a peer sent to an allocation's relayed address.
    async fn on_peer_datagram(&mut self, client: SocketAddr, peer: SocketAddr, data: &[u8]) {
        let Some(allocation) = self.allocations.get(&client) else {
            return;
        };
        if !allocation.permissions.contains(&peer.ip()) {
            return;
        }
        let bytes = if let Some(number) = allocation.channel_of.get(&peer) {
            let mut channel = ChannelData {
                data: data.to_vec(),
                number: ChannelNumber(*number),
                ..Default::default()
            };
            // Refused only for data longer than a ChannelData message carries (a UDP
            // datagram never is); drop it as the Data-indication path below does.
            if channel.encode().is_err() {
                return;
            }
            channel.raw
        } else {
            let mut msg = Message::new();
            let built = msg.build(&[
                Box::new(TransactionId::new()),
                Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
                Box::new(PeerAddress {
                    ip: peer.ip(),
                    port: peer.port(),
                }),
                Box::new(Data(data.to_vec())),
                Box::new(FINGERPRINT),
            ]);
            if built.is_err() {
                return;
            }
            msg.raw
        };
        self.stats.relayed.fetch_add(1, Ordering::Relaxed);
        self.send(client, &bytes).await;
    }
}

/// Every XOR-PEER-ADDRESS of a message (a CreatePermission may carry several).
fn peer_addresses(msg: &Message) -> Vec<SocketAddr> {
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let mut out = Vec::new();
    for attr in &msg.attributes.0 {
        if attr.typ != ATTR_XOR_PEER_ADDRESS || attr.value.len() < 8 {
            continue;
        }
        let v = &attr.value;
        let port = u16::from_be_bytes([v[2], v[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
        match (v[1], v.len()) {
            (0x01, 8) => {
                let mut ip = [0u8; 4];
                for (i, b) in ip.iter_mut().enumerate() {
                    *b = v[4 + i] ^ cookie[i];
                }
                out.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port));
            }
            (0x02, 20) => {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&cookie);
                mask[4..].copy_from_slice(&msg.transaction_id.0);
                let mut ip = [0u8; 16];
                for (i, b) in ip.iter_mut().enumerate() {
                    *b = v[4 + i] ^ mask[i];
                }
                out.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port));
            }
            _ => {}
        }
    }
    out
}
