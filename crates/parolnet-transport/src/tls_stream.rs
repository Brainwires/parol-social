//! TLS stream transport: HTTP/2 over rustls over TCP (PNP-006 §4.5, §5.3).
//!
//! A connection is one TLS session that negotiated `h2` by ALPN and carries the HTTP/2
//! preface and SETTINGS. ParolNet traffic rides on HTTP/2 streams of it as DATA frames: one
//! dedicated stream per circuit or gossip session, all multiplexed over the one connection
//! ([`TlsConnection::open_stream`] / [`TlsConnection::accept_stream`]). Inside a stream each
//! message (a 512-byte cell, a gossip message) is prefixed with its length.
//!
//! A listener answers everything that is not ParolNet as a web server would: 200,
//! `text/html`, a generic page ([`COVER_PAGE_HTML`]), over HTTP/2 or HTTP/1.1. With a
//! [`StreamGate`] set, a connection's first stream must open with a message the gate accepts
//! (for a relay: a valid circuit CREATE cell) before anything ParolNet is said on it; until
//! then every request gets the page.
//!
//! Connections are closed with HTTP/2 GOAWAY and TLS `close_notify`, and TCP keepalive is on
//! at 30 seconds.

use crate::tls_camouflage::FingerprintProfile;
use crate::{Connection, Listener, Transport, TransportError};
use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, mpsc};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Default SNI hostname used when none is configured.
pub const DEFAULT_SNI: &str = "cdn.jsdelivr.net";

/// TCP keepalive on every connection: the first probe after this long without traffic and
/// one every this long after it (PNP-006-MUST-027).
pub const TCP_KEEPALIVE: Duration = Duration::from_secs(30);

/// The page a non-ParolNet client is served (PNP-006-MUST-033 / MUST-038 / MUST-040): what
/// a web server shows for an unconfigured virtual host. It names nothing.
pub const COVER_PAGE_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Welcome</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, sans-serif; max-width: 42rem; margin: 2rem auto; padding: 0 1rem; color: #222; }
    header { border-bottom: 1px solid #ddd; padding-bottom: 0.5rem; }
    p { line-height: 1.5; }
  </style>
</head>
<body>
  <header><h1>Welcome</h1></header>
  <p>This server is configured and ready.</p>
  <p>If you believe you reached this page in error, please check the address and try again.</p>
</body>
</html>
"#;
/// The cover page's content type.
pub const COVER_CONTENT_TYPE: &str = "text/html; charset=utf-8";

/// The content type of an accepted ParolNet stream's response.
const STREAM_CONTENT_TYPE: &str = "application/octet-stream";
/// The path ParolNet streams are opened on.
const STREAM_PATH: &str = "/";
/// Maximum allowed message size (64 KiB): a malicious length prefix cannot make the
/// receiver allocate without bound.
const MAX_FRAME_SIZE: usize = 65536;
/// How long a listener waits for a new connection's TLS handshake, and for the first
/// message of an ungated stream's request, before treating the peer as a probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a graceful close may take.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a stream we ended waits for the peer to end its side.
const STREAM_DRAIN: Duration = Duration::from_secs(2);

const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Decides whether the first message of a connection's first stream is ParolNet. A relay
/// passes "is a valid circuit CREATE cell" (PNP-006-MUST-041).
pub type StreamGate = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// TLS stream transport using rustls directly over TCP.
pub struct TlsTransport {
    client_config: Arc<rustls::ClientConfig>,
    server_config: Option<Arc<rustls::ServerConfig>>,
    /// SNI hostnames for the TLS ClientHello; one is drawn per connection. They should look
    /// like a CDN or a popular website (PNP-006-MUST-032 / SHOULD-008).
    sni: Vec<String>,
    gate: Option<StreamGate>,
}

/// The client configuration with the ALPN list HTTP/2 needs, if it has none.
fn with_client_alpn(mut config: rustls::ClientConfig) -> rustls::ClientConfig {
    if config.alpn_protocols.is_empty() {
        config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];
    }
    config
}

/// The server configuration with the ALPN list a web server offers, if it has none.
fn with_server_alpn(mut config: rustls::ServerConfig) -> rustls::ServerConfig {
    if config.alpn_protocols.is_empty() {
        config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];
    }
    config
}

fn sni_pool(profile: &FingerprintProfile) -> Vec<String> {
    if profile.sni_hosts.is_empty() {
        vec![DEFAULT_SNI.to_string()]
    } else {
        profile.sni_hosts.clone()
    }
}

impl TlsTransport {
    /// Create a client-only TLS transport with the given fingerprint profile. The SNI of
    /// each connection is drawn from the profile's host pool.
    pub fn client(profile: &FingerprintProfile) -> Result<Self, TransportError> {
        let config = profile
            .build_client_config()
            .map_err(|e| TransportError::TlsHandshakeFailed(e.to_string()))?;
        Ok(Self {
            client_config: Arc::new(with_client_alpn(config)),
            server_config: None,
            sni: sni_pool(profile),
            gate: None,
        })
    }

    /// Create a client-only TLS transport with a custom SNI hostname.
    pub fn client_with_sni(
        profile: &FingerprintProfile,
        sni: String,
    ) -> Result<Self, TransportError> {
        let mut transport = Self::client(profile)?;
        transport.sni = vec![sni];
        Ok(transport)
    }

    /// Create a TLS transport with both client and server capabilities.
    pub fn with_server_config(
        profile: &FingerprintProfile,
        server_config: rustls::ServerConfig,
    ) -> Result<Self, TransportError> {
        let mut transport = Self::client(profile)?;
        transport.server_config = Some(Arc::new(with_server_alpn(server_config)));
        Ok(transport)
    }

    /// Create a TLS transport with both client and server capabilities and a custom SNI.
    pub fn with_server_config_and_sni(
        profile: &FingerprintProfile,
        server_config: rustls::ServerConfig,
        sni: String,
    ) -> Result<Self, TransportError> {
        let mut transport = Self::with_server_config(profile, server_config)?;
        transport.sni = vec![sni];
        Ok(transport)
    }

    /// Create a TLS transport with explicit client and server configs.
    ///
    /// Useful for testing with self-signed certificates where the default
    /// client config (which trusts only webpki roots) would reject the cert.
    pub fn with_configs(
        client_config: rustls::ClientConfig,
        server_config: rustls::ServerConfig,
    ) -> Self {
        Self::with_configs_and_sni(client_config, server_config, DEFAULT_SNI.to_string())
    }

    /// Create a TLS transport with explicit client and server configs and a custom SNI.
    pub fn with_configs_and_sni(
        client_config: rustls::ClientConfig,
        server_config: rustls::ServerConfig,
        sni: String,
    ) -> Self {
        Self {
            client_config: Arc::new(with_client_alpn(client_config)),
            server_config: Some(Arc::new(with_server_alpn(server_config))),
            sni: vec![sni],
            gate: None,
        }
    }

    /// Use these SNI hostnames, one drawn per connection (PNP-006-SHOULD-008).
    pub fn with_sni_pool(mut self, hosts: Vec<String>) -> Self {
        if !hosts.is_empty() {
            self.sni = hosts;
        }
        self
    }

    /// Require a listener's connections to open with a message `gate` accepts before any
    /// ParolNet stream is served on them (PNP-006-MUST-041).
    pub fn with_gate(mut self, gate: StreamGate) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Get the configured SNI hostname (the first of the pool).
    pub fn sni(&self) -> &str {
        &self.sni[0]
    }

    /// The SNI hostnames a connection's SNI is drawn from.
    pub fn sni_hosts(&self) -> &[String] {
        &self.sni
    }

    fn pick_sni(&self) -> &str {
        use rand::Rng;
        &self.sni[rand::rngs::OsRng.gen_range(0..self.sni.len())]
    }
}

/// Enable TCP keepalive at [`TCP_KEEPALIVE`] and return the probe interval in effect.
///
/// Where the socket can be asked (`TCP_KEEPINTVL`, socket2's `tcp_keepalive_interval`) this
/// is what the kernel reports. Windows sets the time and the interval together through
/// `SIO_KEEPALIVE_VALS`, which fails the call when it is refused, and has no option socket2
/// reads them back with: there the interval is the one just set, once `SO_KEEPALIVE` reads
/// back on.
fn enable_keepalive(stream: &TcpStream) -> std::io::Result<Option<Duration>> {
    let sock = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE)
        .with_interval(TCP_KEEPALIVE);
    sock.set_tcp_keepalive(&keepalive)?;
    if !sock.keepalive()? {
        return Ok(None);
    }
    keepalive_interval(&sock).map(Some)
}

/// The keepalive probe interval the kernel reports (the targets socket2 0.6 offers
/// `tcp_keepalive_interval` on, with its `all` feature).
#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "visionos",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "cygwin",
))]
fn keepalive_interval(sock: &socket2::SockRef<'_>) -> std::io::Result<Duration> {
    sock.tcp_keepalive_interval()
}

/// Elsewhere (Windows) the interval cannot be read back: it is the one
/// [`enable_keepalive`] set, which `set_tcp_keepalive` would have failed on otherwise.
#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "ios",
    target_os = "visionos",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "cygwin",
)))]
fn keepalive_interval(_sock: &socket2::SockRef<'_>) -> std::io::Result<Duration> {
    Ok(TCP_KEEPALIVE)
}

fn h2_err(e: h2::Error) -> TransportError {
    if e.is_io() || e.is_go_away() || e.is_remote() {
        TransportError::ConnectionClosed
    } else {
        TransportError::ConnectionFailed(e.to_string())
    }
}

// ── One HTTP/2 stream ─────────────────────────────────────────────

enum Inbound {
    /// Client side: the response headers have not arrived yet.
    Response(h2::client::ResponseFuture),
    Body(RecvStream),
    Closed,
}

struct Reader {
    inbound: Inbound,
    buffer: BytesMut,
}

impl Reader {
    /// More bytes from the peer into `buffer`. False at the end of the stream.
    async fn fill(&mut self) -> Result<bool, TransportError> {
        if let Inbound::Response(_) = &self.inbound {
            let Inbound::Response(response) = std::mem::replace(&mut self.inbound, Inbound::Closed)
            else {
                unreachable!()
            };
            let response = response.await.map_err(h2_err)?;
            let accepted = response.status() == http::StatusCode::OK
                && response
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .is_some_and(|v| v.as_bytes() == STREAM_CONTENT_TYPE.as_bytes());
            if !accepted {
                return Err(TransportError::ConnectionFailed(
                    "the peer did not accept the stream".into(),
                ));
            }
            self.inbound = Inbound::Body(response.into_body());
        }
        let Inbound::Body(body) = &mut self.inbound else {
            return Ok(false);
        };
        match body.data().await {
            Some(Ok(chunk)) => {
                // Hand the window back: the bytes are ours now.
                let _ = body.flow_control().release_capacity(chunk.len());
                self.buffer.extend_from_slice(&chunk);
                Ok(true)
            }
            Some(Err(e)) => Err(h2_err(e)),
            None => {
                self.inbound = Inbound::Closed;
                Ok(false)
            }
        }
    }

    /// The next length-prefixed message, or `None` at a clean end of the stream.
    async fn message(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        loop {
            if self.buffer.len() >= 4 {
                let len = u32::from_be_bytes([
                    self.buffer[0],
                    self.buffer[1],
                    self.buffer[2],
                    self.buffer[3],
                ]) as usize;
                if len > MAX_FRAME_SIZE {
                    return Err(TransportError::ReceiveFailed(
                        "frame exceeds maximum size".into(),
                    ));
                }
                if self.buffer.len() >= 4 + len {
                    self.buffer.advance(4);
                    return Ok(Some(self.buffer.split_to(len).to_vec()));
                }
            }
            if !self.fill().await? {
                return if self.buffer.is_empty() {
                    Ok(None)
                } else {
                    Err(TransportError::ConnectionClosed)
                };
            }
        }
    }
}

/// One HTTP/2 stream of a TLS connection, carrying length-prefixed messages as DATA frames
/// (PNP-006-MUST-037).
///
/// End a stream with [`Connection::close`]. Dropping it instead resets it (RST_STREAM), and
/// a reset can overtake what the peer has not read yet.
pub struct TlsStream {
    writer: Mutex<Option<SendStream<Bytes>>>,
    reader: Mutex<Reader>,
    peer_addr: Option<SocketAddr>,
}

impl TlsStream {
    fn new(send: SendStream<Bytes>, inbound: Inbound, peer_addr: Option<SocketAddr>) -> Self {
        TlsStream {
            writer: Mutex::new(Some(send)),
            reader: Mutex::new(Reader {
                inbound,
                buffer: BytesMut::new(),
            }),
            peer_addr,
        }
    }

    async fn send_message(&self, data: &[u8]) -> Result<(), TransportError> {
        if data.len() > MAX_FRAME_SIZE {
            return Err(TransportError::SendFailed(
                "frame exceeds maximum size".into(),
            ));
        }
        let mut writer = self.writer.lock().await;
        let stream = writer.as_mut().ok_or(TransportError::ConnectionClosed)?;
        let mut frame = BytesMut::with_capacity(4 + data.len());
        frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
        frame.extend_from_slice(data);
        let mut frame = frame.freeze();
        // HTTP/2 flow control: send what the peer's window allows, wait for more.
        while !frame.is_empty() {
            stream.reserve_capacity(frame.len());
            let granted = std::future::poll_fn(|cx| stream.poll_capacity(cx))
                .await
                .ok_or(TransportError::ConnectionClosed)?
                .map_err(h2_err)?;
            let chunk = frame.split_to(granted.min(frame.len()));
            stream.send_data(chunk, false).map_err(h2_err)?;
        }
        Ok(())
    }

    async fn recv_message(&self) -> Result<Vec<u8>, TransportError> {
        self.reader
            .lock()
            .await
            .message()
            .await?
            .ok_or(TransportError::ConnectionClosed)
    }

    /// End our side of the stream (END_STREAM), give the peer a moment to end its side, and
    /// let go of it. A stream both sides ended is closed; one we walk away from is reset,
    /// and a reset that reaches a listener before it has looked at the stream makes the
    /// stream vanish there (HTTP/2 implementations discard those), so we wait briefly.
    async fn finish(&self) {
        if let Some(mut stream) = self.writer.lock().await.take() {
            let _ = stream.send_data(Bytes::new(), true);
        }
        let mut reader = self.reader.lock().await;
        let _ = tokio::time::timeout(STREAM_DRAIN, async {
            while let Ok(true) = reader.fill().await {
                // Nothing reads this stream any more.
                reader.buffer.clear();
            }
        })
        .await;
        reader.inbound = Inbound::Closed;
    }
}

#[async_trait]
impl Connection for TlsStream {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        self.send_message(data).await
    }

    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        self.recv_message().await
    }

    /// Close this stream only; the connection and its other streams stay.
    async fn close(&self) -> Result<(), TransportError> {
        self.finish().await;
        Ok(())
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }
}

// ── The connection ────────────────────────────────────────────────

enum Role {
    Client {
        requests: Mutex<Option<h2::client::SendRequest<Bytes>>>,
        authority: String,
    },
    Server {
        streams: Mutex<mpsc::UnboundedReceiver<TlsStream>>,
        /// Asks the connection task for a graceful shutdown.
        shutdown: Arc<Notify>,
    },
}

/// A TLS connection: an HTTP/2 session and the streams on it. As a [`Connection`] it is its
/// first stream.
pub struct TlsConnection {
    primary: TlsStream,
    role: Role,
    /// The task that drives the HTTP/2 session; it ends once the session is shut down and
    /// TLS `close_notify` has gone out.
    driver: Mutex<Option<tokio::task::JoinHandle<()>>>,
    peer_addr: Option<SocketAddr>,
    keepalive: Option<Duration>,
    sni: Option<String>,
}

impl TlsConnection {
    /// The TCP keepalive interval the kernel reports for this connection's socket (on
    /// Windows, which cannot be asked, the one set), `None` when keepalive is off
    /// (PNP-006-MUST-027).
    pub fn tcp_keepalive(&self) -> Option<Duration> {
        self.keepalive
    }

    /// The SNI this side sent (client side only).
    pub fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    /// Open another stream on this connection (the client side opens streams): a further
    /// circuit or a gossip session over the same TLS connection (PNP-006-MUST-025).
    pub async fn open_stream(&self) -> Result<TlsStream, TransportError> {
        let Role::Client {
            requests,
            authority,
        } = &self.role
        else {
            return Err(TransportError::NotAvailable(
                "only the connecting side opens streams".into(),
            ));
        };
        let guard = requests.lock().await;
        let requests = guard.as_ref().ok_or(TransportError::ConnectionClosed)?;
        open_stream(requests.clone(), authority, self.peer_addr).await
    }

    /// The next stream the peer opened on this connection (the accepting side), `None` once
    /// the connection is over.
    pub async fn accept_stream(&self) -> Result<Option<TlsStream>, TransportError> {
        let Role::Server { streams, .. } = &self.role else {
            return Err(TransportError::NotAvailable(
                "only the accepting side accepts streams".into(),
            ));
        };
        Ok(streams.lock().await.recv().await)
    }
}

async fn open_stream(
    requests: h2::client::SendRequest<Bytes>,
    authority: &str,
    peer_addr: Option<SocketAddr>,
) -> Result<TlsStream, TransportError> {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://{authority}{STREAM_PATH}"))
        .header(http::header::CONTENT_TYPE, STREAM_CONTENT_TYPE)
        .body(())
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
    let mut requests = requests.ready().await.map_err(h2_err)?;
    let (response, send) = requests.send_request(request, false).map_err(h2_err)?;
    Ok(TlsStream::new(send, Inbound::Response(response), peer_addr))
}

#[async_trait]
impl Connection for TlsConnection {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        self.primary.send_message(data).await
    }

    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        self.primary.recv_message().await
    }

    /// Close the connection properly (PNP-006-MUST-026): the stream ends, the HTTP/2
    /// session says GOAWAY, TLS sends `close_notify`. Streams still open on it end too.
    async fn close(&self) -> Result<(), TransportError> {
        self.primary.finish().await;
        match &self.role {
            // With the last request handle gone the session shuts itself down.
            Role::Client { requests, .. } => drop(requests.lock().await.take()),
            Role::Server { shutdown, .. } => shutdown.notify_one(),
        }
        if let Some(driver) = self.driver.lock().await.take() {
            let abort = driver.abort_handle();
            if tokio::time::timeout(CLOSE_TIMEOUT, driver).await.is_err() {
                // An unresponsive peer is not waited for.
                abort.abort();
            }
        }
        Ok(())
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }
}

// ── The listener ──────────────────────────────────────────────────

/// TLS listener accepting incoming connections.
pub struct TlsListener {
    incoming: Mutex<mpsc::UnboundedReceiver<TlsConnection>>,
    local_addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[async_trait]
impl Listener for TlsListener {
    type Conn = TlsConnection;

    /// The next ParolNet connection: one whose first stream passed the gate. Probes and
    /// other web clients are answered with the cover page and never show up here.
    async fn accept(&self) -> Result<Self::Conn, TransportError> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or(TransportError::ConnectionClosed)
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

/// What a connection task needs to hand accepted streams on.
struct Acceptor {
    gate: Option<StreamGate>,
    /// A stream of this connection passed the gate (or there is none).
    unlocked: AtomicBool,
    /// The connection has been handed to `TlsListener::accept`.
    handed: Mutex<Option<Handoff>>,
    streams: mpsc::UnboundedSender<TlsStream>,
    peer_addr: SocketAddr,
}

/// What becomes the `TlsConnection` once the first stream is accepted.
struct Handoff {
    incoming: mpsc::UnboundedSender<TlsConnection>,
    streams: mpsc::UnboundedReceiver<TlsStream>,
    shutdown: Arc<Notify>,
    driver: tokio::sync::oneshot::Receiver<tokio::task::JoinHandle<()>>,
    keepalive: Option<Duration>,
}

fn cover_response() -> http::Response<()> {
    let mut response = http::Response::new(());
    *response.status_mut() = http::StatusCode::OK;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(COVER_CONTENT_TYPE),
    );
    response.headers_mut().insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from(COVER_PAGE_HTML.len()),
    );
    response
}

/// Answer a request the way a web server would (PNP-006-MUST-038): the page, or for a HEAD
/// request its headers alone.
fn serve_cover(mut respond: h2::server::SendResponse<Bytes>, head: bool) {
    if let Ok(mut body) = respond.send_response(cover_response(), head)
        && !head
    {
        let _ = body.send_data(Bytes::from_static(COVER_PAGE_HTML.as_bytes()), true);
    }
}

/// One request of an HTTP/2 connection: a ParolNet stream, or something to show the page.
async fn serve_request(
    acceptor: Arc<Acceptor>,
    request: http::Request<RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
) {
    if request.method() != http::Method::POST {
        return serve_cover(respond, request.method() == http::Method::HEAD);
    }
    let mut reader = Reader {
        inbound: Inbound::Body(request.into_body()),
        buffer: BytesMut::new(),
    };
    let mut first = None;
    if !acceptor.unlocked.load(Ordering::SeqCst) {
        // Nothing ParolNet is said until the gate has seen the first message.
        let gate = acceptor.gate.as_ref().expect("locked only with a gate");
        match tokio::time::timeout(PROBE_TIMEOUT, reader.message()).await {
            Ok(Ok(Some(message))) if gate(&message) => {
                acceptor.unlocked.store(true, Ordering::SeqCst);
                first = Some(message);
            }
            _ => return serve_cover(respond, false),
        }
    }
    let mut respond = respond;
    let mut response = http::Response::new(());
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(STREAM_CONTENT_TYPE),
    );
    let Ok(send) = respond.send_response(response, false) else {
        return;
    };
    // The message the gate read is the stream's first message again.
    if let Some(message) = first {
        let mut restored = BytesMut::with_capacity(4 + message.len() + reader.buffer.len());
        restored.extend_from_slice(&(message.len() as u32).to_be_bytes());
        restored.extend_from_slice(&message);
        restored.extend_from_slice(&reader.buffer);
        reader.buffer = restored;
    }
    let stream = TlsStream {
        writer: Mutex::new(Some(send)),
        reader: Mutex::new(reader),
        peer_addr: Some(acceptor.peer_addr),
    };
    // The connection's first accepted stream is the connection, as far as `accept` goes.
    let handoff = acceptor.handed.lock().await.take();
    match handoff {
        Some(handoff) => {
            let driver = handoff.driver.await.ok();
            let _ = handoff.incoming.send(TlsConnection {
                primary: stream,
                role: Role::Server {
                    streams: Mutex::new(handoff.streams),
                    shutdown: handoff.shutdown,
                },
                driver: Mutex::new(driver),
                peer_addr: Some(acceptor.peer_addr),
                keepalive: handoff.keepalive,
                sni: None,
            });
        }
        None => {
            let _ = acceptor.streams.send(stream);
        }
    }
}

/// Serve one HTTP/2 connection until it ends, then close TLS properly.
async fn serve_h2<IO>(io: IO, acceptor: Arc<Acceptor>, shutdown: Arc<Notify>)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(io).await else {
        return;
    };
    let mut closing = false;
    loop {
        tokio::select! {
            request = connection.accept() => match request {
                Some(Ok((request, respond))) => {
                    tokio::spawn(serve_request(acceptor.clone(), request, respond));
                }
                // The session is over (GOAWAY both ways, or the peer left); the codec has
                // shut the TLS stream down, which is what sends `close_notify`.
                Some(Err(_)) | None => return,
            },
            _ = shutdown.notified(), if !closing => {
                closing = true;
                connection.graceful_shutdown();
            }
        }
    }
}

/// A client that negotiated HTTP/1.1 (or nothing) is a web client: read its request and
/// answer with the page.
async fn serve_http1_cover<IO>(mut io: IO)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    let read = async {
        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16 * 1024 {
            match io.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
        }
    };
    let _ = tokio::time::timeout(PROBE_TIMEOUT, read).await;
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {COVER_CONTENT_TYPE}\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{COVER_PAGE_HTML}",
        COVER_PAGE_HTML.len()
    );
    let _ = io.write_all(response.as_bytes()).await;
    let _ = io.shutdown().await;
}

async fn serve_tcp(
    tcp: TcpStream,
    peer_addr: SocketAddr,
    tls: TlsAcceptor,
    gate: Option<StreamGate>,
    incoming: mpsc::UnboundedSender<TlsConnection>,
) {
    let keepalive = enable_keepalive(&tcp).ok().flatten();
    let Ok(Ok(stream)) = tokio::time::timeout(PROBE_TIMEOUT, tls.accept(tcp)).await else {
        return;
    };
    if stream.get_ref().1.alpn_protocol() != Some(ALPN_H2) {
        return serve_http1_cover(stream).await;
    }
    let (streams_tx, streams_rx) = mpsc::unbounded_channel();
    let shutdown = Arc::new(Notify::new());
    let (driver_tx, driver_rx) = tokio::sync::oneshot::channel();
    let acceptor = Arc::new(Acceptor {
        unlocked: AtomicBool::new(gate.is_none()),
        gate,
        handed: Mutex::new(Some(Handoff {
            incoming,
            streams: streams_rx,
            shutdown: shutdown.clone(),
            driver: driver_rx,
            keepalive,
        })),
        streams: streams_tx,
        peer_addr,
    });
    let driver = tokio::spawn(serve_h2(stream, acceptor, shutdown));
    let _ = driver_tx.send(driver);
}

#[async_trait]
impl Transport for TlsTransport {
    type Conn = TlsConnection;
    type Listen = TlsListener;

    fn name(&self) -> &'static str {
        "tls"
    }

    async fn connect(&self, addr: SocketAddr) -> Result<Self::Conn, TransportError> {
        let tcp_stream = TcpStream::connect(addr).await?;
        let keepalive = enable_keepalive(&tcp_stream)?;
        let connector = TlsConnector::from(self.client_config.clone());

        // The SNI is a plausible hostname, drawn from the configured pool.
        let sni = self.pick_sni().to_owned();
        let server_name = rustls::pki_types::ServerName::try_from(sni.as_str())
            .map_err(|e| TransportError::TlsHandshakeFailed(e.to_string()))?
            .to_owned();

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| TransportError::TlsHandshakeFailed(e.to_string()))?;
        // PNP-006-MUST-035: HTTP/2 or nothing.
        if tls_stream.get_ref().1.alpn_protocol() != Some(ALPN_H2) {
            return Err(TransportError::TlsHandshakeFailed(
                "the peer did not negotiate HTTP/2".into(),
            ));
        }

        // The connection preface and SETTINGS (PNP-006-MUST-036).
        let (requests, connection) = h2::client::handshake(tls_stream)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let driver = tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!(%e, "HTTP/2 connection ended");
            }
        });
        let primary = match open_stream(requests.clone(), &sni, Some(addr)).await {
            Ok(stream) => stream,
            Err(e) => {
                driver.abort();
                return Err(e);
            }
        };

        Ok(TlsConnection {
            primary,
            role: Role::Client {
                requests: Mutex::new(Some(requests)),
                authority: sni.clone(),
            },
            driver: Mutex::new(Some(driver)),
            peer_addr: Some(addr),
            keepalive,
            sni: Some(sni),
        })
    }

    async fn listen(&self, addr: SocketAddr) -> Result<Self::Listen, TransportError> {
        let server_config = self
            .server_config
            .as_ref()
            .ok_or_else(|| TransportError::NotAvailable("no server config".into()))?;

        let tcp_listener = TcpListener::bind(addr).await?;
        let local_addr = tcp_listener.local_addr()?;
        let acceptor = TlsAcceptor::from(server_config.clone());
        let gate = self.gate.clone();
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, peer_addr)) = tcp_listener.accept().await else {
                    // A transient accept error (too many files): try again shortly.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                tokio::spawn(serve_tcp(
                    tcp,
                    peer_addr,
                    acceptor.clone(),
                    gate.clone(),
                    incoming_tx.clone(),
                ));
            }
        });

        Ok(TlsListener {
            incoming: Mutex::new(incoming_rx),
            local_addr,
            task,
        })
    }
}
