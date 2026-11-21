//! Relay candidates from a TURN server the user configured (RFC 8656 over UDP).
//!
//! The engine's `rtc-turn` client is sans-I/O; this module owns its I/O on the connection's
//! own socket: the allocation before the loop starts, then permissions, channel bindings,
//! refreshes and the data path while the connection runs, and the release when it closes.
//! Authentication is the long-term credential mechanism (username and password).
//!
//! TURN over TCP and TLS is not implemented: only `turn:host[:port][?transport=udp]` is
//! accepted.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::stun::message::TransactionId;
use rtc::turn::client::{Client, ClientConfig, Event};
use tokio::net::UdpSocket;
use zeroize::Zeroize;

use crate::RtcError;

/// The default TURN port (RFC 8656).
const DEFAULT_PORT: u16 = 3478;
/// Datagrams held for one peer address while its permission is being created.
const PENDING_PER_PEER: usize = 16;
/// A refused permission is asked for again after this long, not on every datagram.
const PERMISSION_RETRY: Duration = Duration::from_secs(2);
/// How long closing waits for the server to confirm the release.
const RELEASE_WAIT: Duration = Duration::from_millis(400);

/// A TURN server and the long-term credential for it. The password is wiped when the value
/// is dropped and never shown by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct TurnServer {
    /// `turn:host[:port]`, optionally with `?transport=udp`.
    pub uri: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for TurnServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnServer")
            .field("uri", &self.uri)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Drop for TurnServer {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// `host:port` of a TURN URI (RFC 7065) this driver can use: `turn:host[:port]` reached over
/// UDP. `turns:` and `?transport=tcp` are refused with the reason.
pub fn parse_turn_uri(uri: &str) -> Result<String, RtcError> {
    let bad = |why: &str| RtcError::TurnUri(format!("{why} (expected turn:host:port)"));
    let uri = uri.trim();
    let Some((scheme, rest)) = uri.split_once(':') else {
        return Err(bad("not a TURN URI"));
    };
    if scheme.eq_ignore_ascii_case("turns") {
        return Err(RtcError::TurnUri(
            "TURN over TLS (turns:) is not supported yet; use turn:host:port over UDP".into(),
        ));
    }
    if !scheme.eq_ignore_ascii_case("turn") {
        return Err(bad("not a TURN URI"));
    }
    let (authority, query) = match rest.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (rest, None),
    };
    match query.map(str::to_ascii_lowercase).as_deref() {
        None | Some("transport=udp") => {}
        Some("transport=tcp") => {
            return Err(RtcError::TurnUri(
                "TURN over TCP is not supported yet; use turn:host:port over UDP".into(),
            ));
        }
        Some(_) => return Err(bad("unknown TURN URI parameter")),
    }
    if authority.is_empty() || authority.contains(['/', '@', ' ']) {
        return Err(bad("no host"));
    }
    if let Some(stripped) = authority.strip_prefix('[') {
        let Some((host, after)) = stripped.split_once(']') else {
            return Err(bad("unclosed IPv6 address"));
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(bad("bad IPv6 address"));
        }
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse::<u16>().map_err(|_| bad("bad port"))?,
            None if after.is_empty() => DEFAULT_PORT,
            None => return Err(bad("bad port")),
        };
        return Ok(format!("[{host}]:{port}"));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.is_empty() || host.contains(':') {
                return Err(bad("an IPv6 address needs brackets"));
            }
            let port = port.parse::<u16>().map_err(|_| bad("bad port"))?;
            Ok(format!("{host}:{port}"))
        }
        None => Ok(format!("{authority}:{DEFAULT_PORT}")),
    }
}

enum Permission {
    /// Asked for; datagrams wait here.
    Requested(Vec<(SocketAddr, BytesMut)>),
    Granted,
    /// Refused or unanswered; asked again after the instant.
    Refused(Instant),
}

/// A live allocation and the client that keeps it.
pub(crate) struct Relay {
    client: Client,
    server: SocketAddr,
    local: SocketAddr,
    relayed: SocketAddr,
    permissions: HashMap<IpAddr, Permission>,
    pending: HashMap<TransactionId, IpAddr>,
}

fn turn_error(what: &str, err: impl std::fmt::Display) -> RtcError {
    RtcError::Turn(format!("{what}: {err}"))
}

/// Allocate a relayed address on `server` through `socket` (before the connection's loop
/// reads it). Fails after `timeout` in total.
pub(crate) async fn allocate(
    socket: &UdpSocket,
    server: &TurnServer,
    timeout: Duration,
    keepalive: Duration,
) -> Result<Relay, RtcError> {
    let host_port = parse_turn_uri(&server.uri)?;
    let local = socket.local_addr()?;
    let deadline = tokio::time::Instant::now() + timeout;
    let resolved = tokio::time::timeout_at(deadline, tokio::net::lookup_host(host_port)).await;
    let server_addr = match resolved {
        Ok(Ok(mut addrs)) => addrs
            .find(|a| a.is_ipv4() == local.is_ipv4())
            .ok_or_else(|| RtcError::Turn("the TURN server has no address we can reach".into()))?,
        Ok(Err(err)) => return Err(turn_error("resolving the TURN server", err)),
        Err(_) => return Err(RtcError::Turn("resolving the TURN server timed out".into())),
    };
    let provider = rtc::crypto::default_provider().map_err(|e| turn_error("crypto", e))?;
    let mut client = Client::new(
        ClientConfig {
            turn_serv_addr: server_addr.to_string(),
            local_addr: local,
            transport_protocol: TransportProtocol::UDP,
            username: server.username.clone(),
            password: server.password.clone(),
            allocation_refresh_interval_cap: Some(keepalive),
            ..Default::default()
        },
        provider,
    )
    .map_err(|e| turn_error("TURN client", e))?;
    client
        .allocate(Instant::now())
        .map_err(|e| turn_error("TURN allocate", e))?;

    let mut buf = vec![0u8; 2048];
    loop {
        while let Some(out) = client.poll_write() {
            let _ = socket.send_to(&out.message, out.transport.peer_addr).await;
        }
        while let Some(event) = client.poll_event() {
            match event {
                Event::AllocateResponse(_, relayed) => {
                    tracing::debug!(%server_addr, %relayed, "TURN allocation ready");
                    return Ok(Relay {
                        client,
                        server: server_addr,
                        local,
                        relayed,
                        permissions: HashMap::new(),
                        pending: HashMap::new(),
                    });
                }
                Event::AllocateError(_, err) => {
                    return Err(turn_error("the TURN server refused the allocation", err));
                }
                Event::TransactionTimeout(_) => {
                    return Err(RtcError::Turn("the TURN server did not answer".into()));
                }
                _ => {}
            }
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(RtcError::Turn("the TURN server did not answer".into()));
        }
        let wake = client
            .poll_timeout()
            .map(tokio::time::Instant::from_std)
            .map_or(deadline, |t| t.min(deadline));
        match tokio::time::timeout_at(wake, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) if from == server_addr => {
                if let Err(err) = client.handle_read(tagged(local, from, &buf[..n])) {
                    tracing::debug!(%err, "TURN datagram rejected");
                }
            }
            Ok(Ok((_, from))) => {
                tracing::debug!(%from, "ignoring a datagram during TURN allocation");
            }
            Ok(Err(err)) => tracing::debug!(%err, "TURN receive failed"),
            Err(_) => {
                let _ = client.handle_timeout(Instant::now());
            }
        }
    }
}

fn tagged(local: SocketAddr, from: SocketAddr, data: &[u8]) -> TaggedBytesMut {
    TaggedBytesMut {
        now: Instant::now(),
        transport: TransportContext {
            local_addr: local,
            peer_addr: from,
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: BytesMut::from(data),
    }
}

impl Relay {
    /// The relayed address: the relay candidate, and the local address of what the engine
    /// sends through it.
    pub(crate) fn relayed(&self) -> SocketAddr {
        self.relayed
    }

    pub(crate) fn server(&self) -> SocketAddr {
        self.server
    }

    /// Send `data` to `peer` through the relay. The first datagram to an address asks for
    /// its permission; datagrams wait (a few) until it is granted.
    pub(crate) fn send(&mut self, now: Instant, data: BytesMut, peer: SocketAddr) {
        let ip = peer.ip();
        match self.permissions.get_mut(&ip) {
            Some(Permission::Granted) => self.send_now(now, &data, peer),
            Some(Permission::Requested(queue)) => {
                if queue.len() < PENDING_PER_PEER {
                    queue.push((peer, data));
                }
            }
            Some(Permission::Refused(retry_at)) if now < *retry_at => {}
            _ => self.request_permission(now, peer, data),
        }
    }

    fn send_now(&mut self, now: Instant, data: &[u8], peer: SocketAddr) {
        let sent = self
            .client
            .relay(self.relayed)
            .and_then(|mut relay| relay.send_to(now, data, peer));
        if let Err(err) = sent {
            tracing::debug!(%peer, %err, "relay send failed");
        }
    }

    fn request_permission(&mut self, now: Instant, peer: SocketAddr, data: BytesMut) {
        let asked = self
            .client
            .relay(self.relayed)
            .and_then(|mut relay| relay.create_permission(now, peer));
        match asked {
            Ok(Some(id)) => {
                self.pending.insert(id, peer.ip());
                self.permissions
                    .insert(peer.ip(), Permission::Requested(vec![(peer, data)]));
            }
            Ok(None) => {
                self.permissions.insert(peer.ip(), Permission::Granted);
                self.send_now(now, &data, peer);
            }
            Err(err) => {
                tracing::debug!(%peer, %err, "cannot ask for a TURN permission");
                self.permissions
                    .insert(peer.ip(), Permission::Refused(now + PERMISSION_RETRY));
            }
        }
    }

    fn permission_failed(&mut self, now: Instant, id: TransactionId) {
        if let Some(ip) = self.pending.remove(&id) {
            self.permissions
                .insert(ip, Permission::Refused(now + PERMISSION_RETRY));
        }
    }

    /// A datagram from the server.
    pub(crate) fn handle_datagram(&mut self, data: &[u8]) {
        if let Err(err) = self
            .client
            .handle_read(tagged(self.local, self.server, data))
        {
            tracing::debug!(%err, "TURN datagram rejected");
        }
    }

    /// Apply the client's events; returns the datagrams peers sent to the relayed address.
    pub(crate) fn poll_inbound(&mut self, now: Instant) -> Vec<(SocketAddr, BytesMut)> {
        let mut inbound = Vec::new();
        while let Some(event) = self.client.poll_event() {
            match event {
                Event::DataIndicationOrChannelData(_, from, data) => inbound.push((from, data)),
                Event::CreatePermissionResponse(id, peer) => {
                    let ip = self.pending.remove(&id).unwrap_or(peer.ip());
                    if let Some(Permission::Requested(queue)) =
                        self.permissions.insert(ip, Permission::Granted)
                    {
                        for (peer, data) in queue {
                            self.send_now(now, &data, peer);
                        }
                    }
                }
                Event::CreatePermissionError(id, err) => {
                    tracing::debug!(%err, "TURN permission refused");
                    self.permission_failed(now, id);
                }
                Event::TransactionTimeout(id) => self.permission_failed(now, id),
                Event::AllocateError(_, err) => tracing::debug!(%err, "TURN allocation error"),
                _ => {}
            }
        }
        inbound
    }

    /// The next datagram for the server.
    pub(crate) fn poll_write(&mut self) -> Option<(BytesMut, SocketAddr)> {
        self.client
            .poll_write()
            .map(|out| (out.message, out.transport.peer_addr))
    }

    pub(crate) fn poll_timeout(&mut self) -> Option<Instant> {
        self.client.poll_timeout()
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        let _ = self.client.handle_timeout(now);
    }

    /// Release the allocation (a Refresh with lifetime 0) and wait briefly for the server
    /// to confirm it, retransmitting meanwhile. Best effort: an allocation whose release is
    /// lost expires on the server by its lifetime.
    pub(crate) async fn release(mut self, socket: &UdpSocket) {
        let released = self
            .client
            .relay(self.relayed)
            .and_then(|mut relay| relay.close(Instant::now()));
        if released.is_err() {
            return;
        }
        let deadline = tokio::time::Instant::now() + RELEASE_WAIT;
        let mut buf = vec![0u8; 2048];
        loop {
            while let Some((data, to)) = self.poll_write() {
                let _ = socket.send_to(&data, to).await;
            }
            while self.client.poll_event().is_some() {}
            // The client forgets the allocation when the server confirms the release.
            if self.client.relay(self.relayed).is_err() {
                tracing::debug!(relayed = %self.relayed, "TURN allocation released");
                return;
            }
            let wake = self
                .client
                .poll_timeout()
                .map(tokio::time::Instant::from_std)
                .map_or(deadline, |t| t.min(deadline));
            if tokio::time::Instant::now() >= deadline {
                return;
            }
            match tokio::time::timeout_at(wake, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) if from == self.server => self.handle_datagram(&buf[..n]),
                Ok(_) => {}
                Err(_) => self.handle_timeout(Instant::now()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(uri: &str) -> String {
        parse_turn_uri(uri).unwrap_or_else(|e| panic!("{uri}: {e}"))
    }

    #[test]
    fn turn_uris_over_udp_are_accepted() {
        assert_eq!(ok("turn:turn.example.org"), "turn.example.org:3478");
        assert_eq!(ok("turn:turn.example.org:3479"), "turn.example.org:3479");
        assert_eq!(ok("TURN:1.2.3.4:5?transport=udp"), "1.2.3.4:5");
        assert_eq!(ok(" turn:host?transport=UDP "), "host:3478");
        assert_eq!(ok("turn:[2001:db8::1]:3478"), "[2001:db8::1]:3478");
        assert_eq!(ok("turn:[::1]"), "[::1]:3478");
    }

    #[test]
    fn other_transports_and_malformed_uris_are_refused_with_a_reason() {
        let err = |uri: &str| match parse_turn_uri(uri) {
            Err(RtcError::TurnUri(why)) => why,
            other => panic!("{uri}: {other:?}"),
        };
        assert!(err("turn:host:3478?transport=tcp").contains("TCP"));
        assert!(err("turns:host:5349").contains("TLS"));
        assert!(err("turns:host:443?transport=tcp").contains("TLS"));
        for uri in [
            "",
            "host:3478",
            "stun:host:3478",
            "turn:",
            "turn::3478",
            "turn:host:port",
            "turn:host:99999",
            "turn:host?foo=bar",
            "turn:2001:db8::1",
            "turn:[::1",
            "turn:[nope]:1",
            "turn:user@host",
            "turn:host/path",
        ] {
            assert!(parse_turn_uri(uri).is_err(), "{uri:?} must be refused");
        }
    }

    #[test]
    fn debug_never_shows_the_password() {
        let server = TurnServer {
            uri: "turn:host".into(),
            username: "pat".into(),
            password: "hunter2-secret".into(),
        };
        let shown = format!("{server:?}");
        assert!(shown.contains("pat") && shown.contains("turn:host"));
        assert!(!shown.contains("hunter2"), "{shown}");
    }
}
