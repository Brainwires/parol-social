//! Local peer discovery over multicast DNS (PNP-005 Section 5.9 item 1).
//!
//! A node advertises the service type `_parolnet._tcp.local.` with a TXT record that
//! carries its PeerId, hex-encoded (PNP-005-MUST-042), listens for the announcements of
//! others and connects to the peers it finds (PNP-005-MUST-043).
//!
//! Advertising on the local network tells that network a ParolNet node is there
//! (PNP-006 §7 item 6). Nothing starts this by itself: a node that should not be seen
//! does not run it.
//!
//! The DNS messages are the subset of RFC 6762 / RFC 6763 this needs: a PTR question
//! for the service type, and an answer of PTR, SRV and TXT records for one instance.

use crate::{DiscoveredPeer, MeshError, PeerDiscovery};
use async_trait::async_trait;
use parolnet_protocol::address::PeerId;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

/// The service type nodes advertise.
pub const SERVICE_TYPE: &str = "_parolnet._tcp.local.";
/// The mDNS multicast group.
pub const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// The mDNS port.
pub const MDNS_PORT: u16 = 5353;
/// Key of the TXT entry that carries the PeerId.
pub const TXT_PEER_ID_KEY: &str = "peerid";
/// How often a running node announces itself unasked.
pub const ANNOUNCE_PERIOD: Duration = Duration::from_secs(60);
/// A discovered peer is not dialed again within this long.
pub const REDIAL_BACKOFF: Duration = Duration::from_secs(60);

const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;
const CLASS_IN: u16 = 1;
/// Class IN with the cache-flush bit (RFC 6762 §10.2).
const CLASS_IN_FLUSH: u16 = 0x8001;
const TTL_SECS: u32 = 120;

fn service_labels() -> Vec<String> {
    SERVICE_TYPE
        .trim_end_matches('.')
        .split('.')
        .map(str::to_string)
        .collect()
}

/// The instance label of a node: `pn-` and the first 16 hex digits of its PeerId.
fn instance_label(peer_id: &PeerId) -> String {
    format!("pn-{}", hex_encode(&peer_id.0[..8]))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn write_name(buf: &mut Vec<u8>, labels: &[String]) {
    for label in labels {
        let bytes = label.as_bytes();
        buf.push(bytes.len().min(63) as u8);
        buf.extend_from_slice(&bytes[..bytes.len().min(63)]);
    }
    buf.push(0);
}

fn write_record(buf: &mut Vec<u8>, name: &[String], rtype: u16, class: u16, rdata: &[u8]) {
    write_name(buf, name);
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&class.to_be_bytes());
    buf.extend_from_slice(&TTL_SECS.to_be_bytes());
    buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(rdata);
}

/// The question a node asks to find others: PTR for `_parolnet._tcp.local.`.
pub fn encode_query() -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    write_name(&mut buf, &service_labels());
    buf.extend_from_slice(&TYPE_PTR.to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());
    buf
}

/// A node's announcement: for the service type a PTR to its instance, and for the
/// instance an SRV record with the port it accepts connections on and a TXT record
/// with `peerid=<64 hex digits>`.
pub fn encode_announcement(peer_id: &PeerId, service_port: u16) -> Vec<u8> {
    let service = service_labels();
    let label = instance_label(peer_id);
    let mut instance = vec![label.clone()];
    instance.extend(service.iter().cloned());
    let host = vec![label, "local".to_string()];

    let mut buf = Vec::with_capacity(256);
    // Response, authoritative; three answers.
    buf.extend_from_slice(&[0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 0]);

    let mut ptr = Vec::new();
    write_name(&mut ptr, &instance);
    write_record(&mut buf, &service, TYPE_PTR, CLASS_IN, &ptr);

    let mut srv = Vec::new();
    srv.extend_from_slice(&[0, 0, 0, 0]);
    srv.extend_from_slice(&service_port.to_be_bytes());
    write_name(&mut srv, &host);
    write_record(&mut buf, &instance, TYPE_SRV, CLASS_IN_FLUSH, &srv);

    let entry = format!("{TXT_PEER_ID_KEY}={}", hex_encode(&peer_id.0));
    let mut txt = vec![entry.len() as u8];
    txt.extend_from_slice(entry.as_bytes());
    write_record(&mut buf, &instance, TYPE_TXT, CLASS_IN_FLUSH, &txt);

    buf
}

/// Read a DNS name at `pos`, following compression pointers. Returns the labels,
/// lower-cased, and the position after the name where it was written.
fn read_name(packet: &[u8], mut pos: usize) -> Option<(Vec<String>, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *packet.get(pos)? as usize;
        if len & 0xC0 == 0xC0 {
            let low = *packet.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            pos = ((len & 0x3F) << 8) | low;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
        } else if len == 0 {
            return Some((labels, end.unwrap_or(pos + 1)));
        } else {
            let label = packet.get(pos + 1..pos + 1 + len)?;
            labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
            pos += 1 + len;
            if labels.len() > 32 {
                return None;
            }
        }
    }
}

fn be16(packet: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *packet.get(pos)?,
        *packet.get(pos + 1)?,
    ]))
}

/// What an mDNS packet says, as far as this service is concerned.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MdnsPacket {
    /// It asks who offers `_parolnet._tcp.local.`.
    pub asks_for_service: bool,
    /// The nodes it announces: PeerId and service port.
    pub peers: Vec<(PeerId, u16)>,
}

/// Parse an mDNS packet. `None` when it is not well-formed DNS.
pub fn parse_packet(packet: &[u8]) -> Option<MdnsPacket> {
    if packet.len() < 12 {
        return None;
    }
    let questions = be16(packet, 4)? as usize;
    let records =
        be16(packet, 6)? as usize + be16(packet, 8)? as usize + be16(packet, 10)? as usize;
    let service = service_labels();
    let mut out = MdnsPacket::default();
    let mut pos = 12;

    for _ in 0..questions {
        let (name, next) = read_name(packet, pos)?;
        let qtype = be16(packet, next)?;
        pos = next + 4;
        if pos > packet.len() {
            return None;
        }
        if name == service && (qtype == TYPE_PTR || qtype == 255) {
            out.asks_for_service = true;
        }
    }

    // Per instance name: the port of its SRV record and the PeerId of its TXT record.
    let mut ports: HashMap<Vec<String>, u16> = HashMap::new();
    let mut ids: HashMap<Vec<String>, PeerId> = HashMap::new();
    for _ in 0..records {
        let (name, next) = read_name(packet, pos)?;
        let rtype = be16(packet, next)?;
        let rdlen = be16(packet, next + 8)? as usize;
        let rdata_at = next + 10;
        let rdata = packet.get(rdata_at..rdata_at + rdlen)?;
        pos = rdata_at + rdlen;

        let of_service = name.len() == service.len() + 1 && name[1..] == service[..];
        if !of_service {
            continue;
        }
        match rtype {
            TYPE_SRV if rdlen >= 6 => {
                ports.insert(name, u16::from_be_bytes([rdata[4], rdata[5]]));
            }
            TYPE_TXT => {
                let mut at = 0;
                while at < rdata.len() {
                    let len = rdata[at] as usize;
                    let Some(entry) = rdata.get(at + 1..at + 1 + len) else {
                        break;
                    };
                    at += 1 + len;
                    let Ok(entry) = std::str::from_utf8(entry) else {
                        continue;
                    };
                    if let Some((key, value)) = entry.split_once('=')
                        && key.eq_ignore_ascii_case(TXT_PEER_ID_KEY)
                        && let Some(id) = hex_decode_32(value)
                    {
                        ids.insert(name.clone(), PeerId(id));
                    }
                }
            }
            _ => {}
        }
    }
    for (name, id) in ids {
        if let Some(port) = ports.get(&name) {
            out.peers.push((id, *port));
        }
    }
    Some(out)
}

/// Connects to a peer discovery found.
#[async_trait]
pub trait PeerConnector: Send + Sync {
    async fn connect(&self, peer: DiscoveredPeer);
}

/// mDNS discovery for one node.
pub struct MdnsDiscovery {
    our_peer_id: PeerId,
    /// The port this node accepts mesh connections on.
    service_port: u16,
    /// The UDP port mDNS runs on: 5353, unless a test moves it.
    mdns_port: u16,
    dialed: Mutex<HashMap<PeerId, Instant>>,
}

impl MdnsDiscovery {
    pub fn new(our_peer_id: PeerId, service_port: u16) -> Self {
        Self {
            our_peer_id,
            service_port,
            mdns_port: MDNS_PORT,
            dialed: Mutex::new(HashMap::new()),
        }
    }

    /// Run mDNS on another UDP port (tests on machines whose 5353 is busy).
    pub fn with_mdns_port(mut self, port: u16) -> Self {
        self.mdns_port = port;
        self
    }

    fn group(&self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(MDNS_GROUP, self.mdns_port))
    }

    /// A socket bound to the mDNS port and joined to the group. Several nodes on one
    /// host share the port.
    fn bind(&self) -> Result<UdpSocket, MeshError> {
        let failed =
            |what: &str, e: std::io::Error| MeshError::DiscoveryFailed(format!("{what}: {e}"));
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|e| failed("socket", e))?;
        socket
            .set_reuse_address(true)
            .map_err(|e| failed("reuse address", e))?;
        #[cfg(unix)]
        socket
            .set_reuse_port(true)
            .map_err(|e| failed("reuse port", e))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| failed("nonblocking", e))?;
        let any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, self.mdns_port));
        socket.bind(&any.into()).map_err(|e| failed("bind", e))?;
        socket
            .join_multicast_v4(&MDNS_GROUP, &Ipv4Addr::UNSPECIFIED)
            .map_err(|e| failed("join group", e))?;
        socket
            .set_multicast_loop_v4(true)
            .map_err(|e| failed("multicast loop", e))?;
        UdpSocket::from_std(socket.into()).map_err(|e| failed("register", e))
    }

    /// The peers a packet from `source` announces, ourselves left out.
    fn peers_in(&self, packet: &MdnsPacket, source: SocketAddr) -> Vec<DiscoveredPeer> {
        packet
            .peers
            .iter()
            .filter(|(id, _)| *id != self.our_peer_id)
            .map(|(id, port)| DiscoveredPeer {
                peer_id: *id,
                addr: SocketAddr::new(source.ip(), *port),
            })
            .collect()
    }

    /// Advertise, listen, and connect to what is found, until dropped.
    ///
    /// Announces at once and every [`ANNOUNCE_PERIOD`], answers questions for the
    /// service type, and hands every newly seen peer to `connector`.
    pub async fn run(&self, connector: Arc<dyn PeerConnector>) -> Result<(), MeshError> {
        let socket = self.bind()?;
        let announcement = encode_announcement(&self.our_peer_id, self.service_port);
        let group = self.group();
        // Ask who else is there, and say that we are.
        let _ = socket.send_to(&encode_query(), group).await;
        let mut announce = tokio::time::interval(ANNOUNCE_PERIOD);
        let mut buf = vec![0u8; 9000];

        loop {
            tokio::select! {
                _ = announce.tick() => {
                    let _ = socket.send_to(&announcement, group).await;
                }
                received = socket.recv_from(&mut buf) => {
                    let Ok((len, source)) = received else { continue };
                    let Some(packet) = parse_packet(&buf[..len]) else { continue };
                    if packet.asks_for_service {
                        let _ = socket.send_to(&announcement, group).await;
                    }
                    for peer in self.peers_in(&packet, source) {
                        if self.should_dial(&peer.peer_id) {
                            let connector = connector.clone();
                            tokio::spawn(async move { connector.connect(peer).await });
                        }
                    }
                }
            }
        }
    }

    /// Whether to attempt a connection to a discovered peer now.
    fn should_dial(&self, peer: &PeerId) -> bool {
        let mut dialed = self.dialed.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        dialed.retain(|_, at| now.duration_since(*at) < REDIAL_BACKOFF);
        if dialed.contains_key(peer) || dialed.len() >= 4096 {
            return false;
        }
        dialed.insert(*peer, now);
        true
    }
}

#[async_trait]
impl PeerDiscovery for MdnsDiscovery {
    /// Ask the local network once and collect the answers for two seconds.
    async fn discover(&self) -> Result<Vec<DiscoveredPeer>, MeshError> {
        let socket = self.bind()?;
        socket
            .send_to(&encode_query(), self.group())
            .await
            .map_err(|e| MeshError::DiscoveryFailed(format!("send: {e}")))?;

        let mut found: Vec<DiscoveredPeer> = Vec::new();
        let mut buf = vec![0u8; 9000];
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                received = socket.recv_from(&mut buf) => {
                    let Ok((len, source)) = received else { continue };
                    let Some(packet) = parse_packet(&buf[..len]) else { continue };
                    for peer in self.peers_in(&packet, source) {
                        if !found.iter().any(|p| p.peer_id == peer.peer_id) {
                            found.push(peer);
                        }
                    }
                }
                _ = &mut deadline => break,
            }
        }
        Ok(found)
    }

    /// Announce `identity` on the local network once.
    async fn announce(&self, identity: &PeerId) -> Result<(), MeshError> {
        let socket = self.bind()?;
        socket
            .send_to(
                &encode_announcement(identity, self.service_port),
                self.group(),
            )
            .await
            .map_err(|e| MeshError::DiscoveryFailed(format!("send: {e}")))?;
        Ok(())
    }
}
