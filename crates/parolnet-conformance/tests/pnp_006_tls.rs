//! PNP-006 conformance: connection behaviour (§4.5), TLS fingerprint profiles (§5.1, §5.2,
//! §5.4) and the HTTP/2 application layer (§5.3, §6.3).
//!
//! The library transport (`parolnet_transport::tls_stream`) is tested from the other side of
//! a real TLS connection on loopback: a plain rustls server or client that records the bytes
//! it is sent and how the connection ended. The shipped client's relay socket
//! (`parolnet-app`) is tested the same way, against a scripted relay.
//!
//! Not here, because the code cannot do it (see the report that came with these tests and
//! `parolnet_transport::tls_camouflage`): a ClientHello that matches a browser's
//! (PNP-006-MUST-028 to MUST-030, MUST-044), profile freshness (MUST-039, SHOULD-005),
//! profile distribution by gossip (SHOULD-011) and the listening port (MUST-034,
//! SHOULD-009).

mod common;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt as _, StreamExt as _};
use parolnet_app::{AppConfig, AppEvent, AppHandle, RelayState};
use parolnet_clause::clause;
use parolnet_relay::handshake::CircuitHandshake;
use parolnet_relay::probe::create_gate;
use parolnet_relay::relay_node::StandardRelayNode;
use parolnet_relay::{CELL_SIZE, RelayAction, RelayCell, RelayNode};
use parolnet_transport::conn_manager::{
    ConnectionManager, LIFETIME_MAX, LIFETIME_MIN, MAX_CONNECTIONS, MIN_CONNECTION_LIFETIME,
    MIN_CONNECTIONS, ManagerError, RECONNECT_WAIT,
};
use parolnet_transport::tls_camouflage::{FingerprintProfile, ProfileRegistry};
use parolnet_transport::tls_stream::{COVER_PAGE_HTML, TlsTransport};
use parolnet_transport::{Connection, Listener, Transport, TransportError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::Message;

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const SNI: &str = "cdn.example-assets.net";

// ── Certificates and plain rustls ends ────────────────────────────

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A self-signed certificate for `names`.
struct Cert {
    der: CertificateDer<'static>,
    key: Vec<u8>,
}

impl Cert {
    fn new(names: &[&str]) -> Cert {
        let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(
            names.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        Cert {
            der: cert.der().clone(),
            key: signing_key.serialize_der(),
        }
    }

    fn server_config(&self, alpn: &[&[u8]]) -> rustls::ServerConfig {
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![self.der.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone())),
            )
            .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        config
    }

    fn roots(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.der.clone()).unwrap();
        roots
    }

    fn client_config(&self, alpn: &[&[u8]]) -> rustls::ClientConfig {
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(self.roots())
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        config
    }

    /// The transport under test, trusting this certificate and sending [`SNI`].
    fn transport(&self) -> TlsTransport {
        TlsTransport::with_configs_and_sni(
            FingerprintProfile::chrome()
                .client_config_with_roots(self.roots())
                .unwrap(),
            self.server_config(&[]),
            SNI.to_owned(),
        )
    }
}

async fn tls_connect(
    cert: &Cert,
    addr: SocketAddr,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    TlsConnector::from(Arc::new(cert.client_config(alpn)))
        .connect(ServerName::try_from(SNI).unwrap(), tcp)
        .await
        .expect("TLS handshake with the listener")
}

/// How a TLS connection ended, as its reader saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// The peer sent TLS `close_notify` (the read returned a clean end of stream).
    CloseNotify,
    /// The TCP connection went away without one, or was reset.
    Abrupt(std::io::ErrorKind),
}

/// Read until the connection ends: every byte received, and how it ended.
async fn read_to_end<S: AsyncRead + Unpin>(stream: &mut S, into: &mut Vec<u8>) -> End {
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return End::CloseNotify,
            Ok(n) => into.extend_from_slice(&buf[..n]),
            Err(e) => return End::Abrupt(e.kind()),
        }
    }
}

/// A stream whose owner can change: handed to an HTTP/2 or WebSocket library, and still
/// readable by the test once that library is done with it. It remembers how reading ended.
struct Tap<S> {
    inner: Arc<Mutex<(S, Option<End>)>>,
}

impl<S> Clone for Tap<S> {
    fn clone(&self) -> Self {
        Tap {
            inner: self.inner.clone(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Tap<S> {
    fn new(stream: S) -> Tap<S> {
        Tap {
            inner: Arc::new(Mutex::new((stream, None))),
        }
    }

    /// How the connection ended: what the library already saw, or what reading on shows.
    async fn end(&mut self) -> End {
        if let Some(end) = self.inner.lock().unwrap().1 {
            return end;
        }
        let mut sink = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), read_to_end(self, &mut sink))
            .await
            .expect("the connection ends")
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut guard = self.inner.lock().unwrap();
        let before = buf.filled().len();
        let result = Pin::new(&mut guard.0).poll_read(cx, buf);
        match &result {
            Poll::Ready(Ok(())) if buf.filled().len() == before && buf.remaining() > 0 => {
                guard.1 = Some(End::CloseNotify);
            }
            Poll::Ready(Err(e)) => guard.1 = Some(End::Abrupt(e.kind())),
            _ => {}
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner.lock().unwrap().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner.lock().unwrap().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner.lock().unwrap().0).poll_shutdown(cx)
    }
}

// ── Reading a ClientHello and HTTP/2 frames ───────────────────────

/// The fields of a TLS ClientHello that a fingerprint is made of.
#[derive(Debug, Default)]
struct Hello {
    cipher_suites: Vec<u16>,
    sni: Option<String>,
    alpn: Vec<String>,
    supported_groups: Vec<u16>,
    key_shares: Vec<u16>,
}

fn u16s(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

impl Hello {
    /// Parse the first TLS record of a connection, which must be a ClientHello.
    fn parse(record: &[u8]) -> Hello {
        assert_eq!(record[0], 0x16, "a handshake record");
        let hs = &record[5..];
        assert_eq!(hs[0], 0x01, "a ClientHello");
        let mut at = 4 + 2 + 32;
        at += 1 + hs[at] as usize; // session id
        let n = u16::from_be_bytes([hs[at], hs[at + 1]]) as usize;
        let mut hello = Hello {
            cipher_suites: u16s(&hs[at + 2..at + 2 + n]),
            ..Hello::default()
        };
        at += 2 + n;
        at += 1 + hs[at] as usize; // compression methods
        let end = at + 2 + u16::from_be_bytes([hs[at], hs[at + 1]]) as usize;
        at += 2;
        while at < end {
            let kind = u16::from_be_bytes([hs[at], hs[at + 1]]);
            let len = u16::from_be_bytes([hs[at + 2], hs[at + 3]]) as usize;
            let body = &hs[at + 4..at + 4 + len];
            match kind {
                0x0000 => {
                    let name_len = u16::from_be_bytes([body[3], body[4]]) as usize;
                    hello.sni = Some(String::from_utf8(body[5..5 + name_len].to_vec()).unwrap());
                }
                0x0010 => {
                    let mut p = 2;
                    while p < body.len() {
                        let l = body[p] as usize;
                        hello
                            .alpn
                            .push(String::from_utf8(body[p + 1..p + 1 + l].to_vec()).unwrap());
                        p += 1 + l;
                    }
                }
                0x000A => hello.supported_groups = u16s(&body[2..]),
                0x0033 => {
                    let mut p = 2;
                    while p < body.len() {
                        hello
                            .key_shares
                            .push(u16::from_be_bytes([body[p], body[p + 1]]));
                        p += 4 + u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
                    }
                }
                _ => {}
            }
            at += 4 + len;
        }
        hello
    }

    /// The TLS 1.3 suites, in the order offered.
    fn tls13_suites(&self) -> Vec<u16> {
        self.cipher_suites
            .iter()
            .copied()
            .filter(|s| (0x1301..=0x1303).contains(s))
            .collect()
    }
}

/// Accept one TCP connection and read the ClientHello it opens with. The connection is
/// then dropped: the client's handshake fails, which is all it has to do here.
async fn capture_hello(listener: &TcpListener) -> Hello {
    let (mut tcp, _) = listener.accept().await.unwrap();
    let mut record = vec![0u8; 5];
    tcp.read_exact(&mut record).await.unwrap();
    let len = u16::from_be_bytes([record[3], record[4]]) as usize;
    record.resize(5 + len, 0);
    tcp.read_exact(&mut record[5..]).await.unwrap();
    Hello::parse(&record)
}

/// The ClientHello `transport` sends.
async fn hello_of(transport: &TlsTransport) -> Hello {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (hello, _) = tokio::join!(capture_hello(&listener), transport.connect(addr));
    hello
}

/// One HTTP/2 frame.
#[derive(Debug)]
struct Frame {
    kind: u8,
    stream: u32,
    payload: Vec<u8>,
}

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_GOAWAY: u8 = 0x7;

/// The complete frames at the start of `bytes` (which follow the connection preface).
fn frames(mut bytes: &[u8]) -> Vec<Frame> {
    let mut out = Vec::new();
    while bytes.len() >= 9 {
        let len = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize;
        if bytes.len() < 9 + len {
            break;
        }
        out.push(Frame {
            kind: bytes[3],
            stream: u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) & 0x7fff_ffff,
            payload: bytes[9..9 + len].to_vec(),
        });
        bytes = &bytes[9 + len..];
    }
    out
}

/// A TLS server that speaks no HTTP/2 of its own beyond an empty SETTINGS frame: it
/// records what the client sends until the connection ends. Returns the negotiated ALPN
/// protocol, the bytes and how the connection ended.
async fn recording_server(
    cert: &Cert,
    alpn: &[&[u8]],
) -> (
    SocketAddr,
    tokio::task::JoinHandle<(Option<Vec<u8>>, Vec<u8>, End)>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cert.server_config(alpn)));
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("TLS handshake");
        let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        // The server's half of the HTTP/2 preface: an empty SETTINGS frame.
        let _ = tls
            .write_all(&[0, 0, 0, FRAME_SETTINGS, 0, 0, 0, 0, 0])
            .await;
        let _ = tls.flush().await;
        let mut bytes = Vec::new();
        let end = read_to_end(&mut tls, &mut bytes).await;
        (negotiated, bytes, end)
    });
    (addr, task)
}

fn a_cell() -> [u8; CELL_SIZE] {
    CircuitHandshake::create_cell(0x0101_0101).0.to_bytes()
}

// ── §5.3 Application layer ────────────────────────────────────────

// §5.3.1 to §5.3.3, seen by the server of a connection the transport opened: TLS negotiated
// `h2`; the first bytes are the HTTP/2 connection preface and a SETTINGS frame; and a cell
// given to the connection arrives as DATA frames on one stream that HEADERS opened.
#[clause("PNP-006-MUST-035", "PNP-006-MUST-036", "PNP-006-MUST-037")]
#[tokio::test]
async fn cells_travel_as_http2_data_frames_on_a_dedicated_stream() {
    let cert = Cert::new(&[SNI]);
    let (addr, server) = recording_server(&cert, &[b"h2", b"http/1.1"]).await;
    let conn = cert.transport().connect(addr).await.expect("connect");
    let cell = a_cell();
    conn.send(&cell).await.expect("send a cell");
    let second = RelayCell::padding(7).to_bytes();
    conn.send(&second).await.expect("send another");
    conn.close().await.unwrap();
    let (negotiated, bytes, _) = server.await.unwrap();

    // MUST-035
    assert_eq!(negotiated.as_deref(), Some(&b"h2"[..]), "ALPN");
    // MUST-036
    assert!(bytes.starts_with(H2_PREFACE), "the connection preface");
    let frames = frames(&bytes[H2_PREFACE.len()..]);
    assert_eq!(
        frames[0].kind, FRAME_SETTINGS,
        "SETTINGS follows the preface"
    );
    assert_eq!(frames[0].stream, 0);
    // MUST-037
    let headers: Vec<&Frame> = frames.iter().filter(|f| f.kind == FRAME_HEADERS).collect();
    assert_eq!(headers.len(), 1, "one stream was opened");
    let stream = headers[0].stream;
    assert!(stream != 0, "a stream of its own, not the control stream");
    let first_data = frames.iter().position(|f| f.kind == FRAME_DATA).unwrap();
    let opened = frames.iter().position(|f| f.kind == FRAME_HEADERS).unwrap();
    assert!(opened < first_data, "HEADERS opens the stream before DATA");
    let mut carried = Vec::new();
    for frame in frames.iter().filter(|f| f.kind == FRAME_DATA) {
        assert_eq!(frame.stream, stream, "every cell on the dedicated stream");
        carried.extend_from_slice(&frame.payload);
    }
    let mut expected = Vec::new();
    for c in [&cell, &second] {
        expected.extend_from_slice(&(CELL_SIZE as u32).to_be_bytes());
        expected.extend_from_slice(c);
    }
    assert_eq!(carried, expected, "the cells, in DATA frames");

    // MUST-035 again: a peer that will not speak HTTP/2 is not spoken to at all.
    let (addr, server) = recording_server(&cert, &[b"http/1.1"]).await;
    let refused = cert.transport().connect(addr).await;
    assert!(
        matches!(refused, Err(TransportError::TlsHandshakeFailed(_))),
        "connected without HTTP/2"
    );
    let (negotiated, bytes, _) = server.await.unwrap();
    assert_eq!(negotiated.as_deref(), Some(&b"http/1.1"[..]));
    assert!(bytes.is_empty(), "nothing was sent to a peer without h2");
}

/// Forwards TCP connections to `upstream` and counts them.
async fn counting_proxy(upstream: SocketAddr) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(upstream).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    (addr, count)
}

// §4.5.4: two circuits and a gossip session to one peer use one TLS connection. Counted
// where it cannot be faked: at a TCP proxy between the two ends.
#[clause("PNP-006-MUST-025")]
#[tokio::test]
async fn circuits_and_gossip_to_a_peer_share_one_tls_connection() {
    let cert = Cert::new(&[SNI]);
    let listener = cert
        .transport()
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (proxy, connections) = counting_proxy(listener.local_addr()).await;

    let server = tokio::spawn(async move {
        let conn = listener.accept().await.expect("accept");
        let mut got = vec![conn.recv().await.unwrap()];
        conn.send(b"circuit-1 ack").await.unwrap();
        for _ in 0..2 {
            let stream = conn.accept_stream().await.unwrap().expect("another stream");
            let message = stream.recv().await.unwrap();
            stream
                .send(&[b"ack ", &message[..]].concat())
                .await
                .unwrap();
            stream.close().await.unwrap();
            got.push(message);
        }
        got
    });

    // The manager hands out one connection per peer, however often it is asked.
    let manager = ConnectionManager::new(cert.transport());
    let conn = manager.connect(proxy).await.expect("connect");
    let again = manager.connect(proxy).await.expect("connect again");
    assert!(
        Arc::ptr_eq(&conn, &again),
        "a second connection to one peer"
    );

    let circuit_1 = a_cell();
    conn.send(&circuit_1).await.unwrap();
    assert_eq!(conn.recv().await.unwrap(), b"circuit-1 ack");
    let circuit_2 = conn.open_stream().await.unwrap();
    circuit_2.send(b"circuit-2 cell").await.unwrap();
    assert_eq!(circuit_2.recv().await.unwrap(), b"ack circuit-2 cell");
    circuit_2.close().await.unwrap();
    let gossip = again.open_stream().await.unwrap();
    gossip.send(b"gossip message").await.unwrap();
    assert_eq!(gossip.recv().await.unwrap(), b"ack gossip message");
    gossip.close().await.unwrap();

    let got = server.await.unwrap();
    assert_eq!(
        got,
        [
            circuit_1.to_vec(),
            b"circuit-2 cell".to_vec(),
            b"gossip message".to_vec()
        ]
    );
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "three streams, one TCP connection"
    );
}

// ── §4.5 Connection behaviour ─────────────────────────────────────

// §4.5.5, both ways. The side that closes sends TLS close_notify: a transport connection
// closed by the client ends cleanly for the server, one closed by the listener ends cleanly
// for the client. For contrast, a client that just drops its socket is seen as exactly
// that.
#[clause("PNP-006-MUST-026")]
#[tokio::test]
async fn a_connection_is_closed_with_close_notify() {
    let cert = Cert::new(&[SNI]);

    // The connecting side closes.
    let (addr, server) = recording_server(&cert, &[b"h2"]).await;
    let conn = cert.transport().connect(addr).await.unwrap();
    conn.send(&a_cell()).await.unwrap();
    conn.close().await.unwrap();
    let (_, bytes, end) = server.await.unwrap();
    assert_eq!(end, End::CloseNotify, "the client's close");
    assert!(
        frames(&bytes[H2_PREFACE.len()..])
            .iter()
            .any(|f| f.kind == FRAME_GOAWAY),
        "HTTP/2 said goodbye first"
    );

    // The accepting side closes.
    let listener = cert
        .transport()
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr();
    let mut tap = Tap::new(tls_connect(&cert, addr, &[b"h2"]).await);
    let (mut requests, connection) = h2::client::handshake(tap.clone()).await.unwrap();
    let driver = tokio::spawn(connection);
    let request = http::Request::post(format!("https://{SNI}/"))
        .body(())
        .unwrap();
    let (response, mut body) = requests.send_request(request, false).unwrap();
    body.send_data(bytes::Bytes::from_static(&[0, 0, 0, 2, b'h', b'i']), false)
        .unwrap();
    let conn = listener.accept().await.unwrap();
    assert_eq!(conn.recv().await.unwrap(), b"hi");
    drop((response, body, requests));
    conn.close().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), driver).await;
    assert_eq!(tap.end().await, End::CloseNotify, "the listener's close");

    // The control: no close_notify looks different.
    let (addr, server) = recording_server(&cert, &[b"h2"]).await;
    let rude = tls_connect(&cert, addr, &[b"h2"]).await;
    let (tcp, _) = rude.into_inner();
    drop(tcp);
    let (_, _, end) = server.await.unwrap();
    assert!(
        matches!(end, End::Abrupt(_)),
        "an abrupt end read as {end:?}"
    );
}

// §4.5.6: TCP keepalive is on, at 30 seconds, on the transport's connections (both ends)
// and on the socket the shipped client opens to its relay. Read back from the kernel.
#[clause("PNP-006-MUST-027")]
#[tokio::test]
async fn tcp_keepalive_is_on_at_30_seconds() {
    let thirty = Duration::from_secs(30);
    let cert = Cert::new(&[SNI]);
    let listener = cert
        .transport()
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let client = cert
        .transport()
        .connect(listener.local_addr())
        .await
        .unwrap();
    client.send(b"x").await.unwrap();
    let server = listener.accept().await.unwrap();
    assert_eq!(client.tcp_keepalive(), Some(thirty), "the connecting end");
    assert_eq!(server.tcp_keepalive(), Some(thirty), "the accepting end");

    // The client's relay socket: the TCP connection every relay session rides on.
    let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = relay.local_addr().unwrap().port();
    let stream = parolnet_app::relay_socket::tcp_connect("127.0.0.1", port)
        .await
        .unwrap();
    let socket = socket2::SockRef::from(&stream);
    assert!(socket.keepalive().unwrap(), "SO_KEEPALIVE");
    assert_eq!(socket.tcp_keepalive_time().unwrap(), thirty);
    assert_eq!(socket.tcp_keepalive_interval().unwrap(), thirty);
    assert_eq!(parolnet_app::relay_socket::TCP_KEEPALIVE, thirty);

    // The control: a socket nobody configured has keepalive off.
    let plain = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert!(!socket2::SockRef::from(&plain).keepalive().unwrap());
}

/// A transport that connects to nothing: enough for the manager's bookkeeping.
#[derive(Default, Clone)]
struct FakeTransport {
    opened: Arc<AtomicUsize>,
    closed: Arc<Mutex<Vec<SocketAddr>>>,
}

struct FakeConn {
    addr: SocketAddr,
    closed: Arc<Mutex<Vec<SocketAddr>>>,
}

#[async_trait]
impl Connection for FakeConn {
    async fn send(&self, _: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }
    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        std::future::pending().await
    }
    async fn close(&self) -> Result<(), TransportError> {
        self.closed.lock().unwrap().push(self.addr);
        Ok(())
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        Some(self.addr)
    }
}

struct NoListener;

#[async_trait]
impl Listener for NoListener {
    type Conn = FakeConn;
    async fn accept(&self) -> Result<FakeConn, TransportError> {
        std::future::pending().await
    }
    fn local_addr(&self) -> SocketAddr {
        "0.0.0.0:0".parse().unwrap()
    }
}

#[async_trait]
impl Transport for FakeTransport {
    type Conn = FakeConn;
    type Listen = NoListener;
    fn name(&self) -> &'static str {
        "fake"
    }
    async fn connect(&self, addr: SocketAddr) -> Result<FakeConn, TransportError> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(FakeConn {
            addr,
            closed: self.closed.clone(),
        })
    }
    async fn listen(&self, _: SocketAddr) -> Result<NoListener, TransportError> {
        Err(TransportError::NotAvailable("fake".into()))
    }
}

fn peer(n: u8) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, n], 443))
}

// §4.5.1 in the library's connection manager: a connection is kept, not cycled; closing it
// by choice is refused until it is ten minutes old, and then it is closed properly.
#[clause("PNP-006-MUST-022", "PNP-006-MUST-023")]
#[tokio::test(start_paused = true)]
async fn the_manager_keeps_a_connection_for_at_least_ten_minutes() {
    let transport = FakeTransport::default();
    let manager = ConnectionManager::new(transport.clone());
    manager.connect(peer(1)).await.unwrap();

    assert_eq!(MIN_CONNECTION_LIFETIME, Duration::from_secs(600));
    for minute in 0..10u64 {
        // Nothing ends the connection on its own, and asking to is refused.
        assert!(manager.rotate_expired().await.is_empty());
        match manager.close(peer(1)).await {
            Err(ManagerError::TooYoung(age, left)) => {
                assert_eq!(age + left, MIN_CONNECTION_LIFETIME, "minute {minute}")
            }
            other => panic!("minute {minute}: a voluntary close gave {other:?}"),
        }
        assert_eq!(manager.connection_count().await, 1);
        tokio::time::advance(Duration::from_secs(60) - Duration::from_millis(1)).await;
    }
    assert!(transport.closed.lock().unwrap().is_empty());
    assert_eq!(transport.opened.load(Ordering::SeqCst), 1, "one connection");

    tokio::time::advance(Duration::from_millis(10)).await;
    manager.close(peer(1)).await.expect("ten minutes old");
    assert_eq!(
        *transport.closed.lock().unwrap(),
        [peer(1)],
        "closed properly"
    );

    // An unresponsive peer is the exception: its connection goes at any age.
    let other = ConnectionManager::new(FakeTransport::default());
    other.connect(peer(2)).await.unwrap();
    assert!(other.drop_unresponsive(peer(2)).await);
    assert_eq!(other.connection_count().await, 0);
}

// §4.5.1: each connection gets a lifetime of one to four hours, not the same for all, and is
// closed (properly) when it is over, not before.
#[clause("PNP-006-SHOULD-001")]
#[tokio::test(start_paused = true)]
async fn connection_lifetimes_are_random_between_one_and_four_hours() {
    assert_eq!(LIFETIME_MIN, Duration::from_secs(3600));
    assert_eq!(LIFETIME_MAX, Duration::from_secs(4 * 3600));
    let mut lifetimes = Vec::new();
    for _ in 0..40 {
        let manager = ConnectionManager::new(FakeTransport::default());
        for n in 1..=5 {
            manager.connect(peer(n)).await.unwrap();
            lifetimes.push(manager.lifetime_of(peer(n)).await.unwrap());
        }
    }
    assert!(
        lifetimes
            .iter()
            .all(|l| *l >= LIFETIME_MIN && *l <= LIFETIME_MAX)
    );
    let distinct: HashSet<Duration> = lifetimes.iter().copied().collect();
    assert!(
        distinct.len() > 190,
        "{} different lifetimes in 200",
        distinct.len()
    );
    let (min, max) = (
        lifetimes.iter().min().unwrap(),
        lifetimes.iter().max().unwrap(),
    );
    assert!(
        *min < Duration::from_secs(4500) && *max > Duration::from_secs(13500),
        "200 lifetimes between {min:?} and {max:?}: not spread over one to four hours"
    );

    // The connections end when their lifetimes do.
    let transport = FakeTransport::default();
    let manager = ConnectionManager::new(transport.clone());
    let mut due = HashMap::new();
    for n in 1..=6 {
        manager.connect(peer(n)).await.unwrap();
        due.insert(peer(n), manager.lifetime_of(peer(n)).await.unwrap());
    }
    let mut elapsed = Duration::ZERO;
    let step = Duration::from_secs(60);
    let mut ended: HashMap<SocketAddr, Duration> = HashMap::new();
    while elapsed < LIFETIME_MAX + step {
        for addr in manager.rotate_expired().await {
            ended.insert(addr, elapsed);
        }
        tokio::time::advance(step).await;
        elapsed += step;
    }
    assert_eq!(ended.len(), 6, "every connection was rotated");
    for (addr, at) in &ended {
        let lifetime = due[addr];
        assert!(
            *at >= lifetime && *at < lifetime + step * 2,
            "{addr}: lifetime {lifetime:?}, closed after {at:?}"
        );
    }
    assert_eq!(
        transport.closed.lock().unwrap().len(),
        6,
        "each closed properly"
    );
    assert_eq!(manager.connection_count().await, 0);
}

// §4.5.2 in the manager: after a connection to a peer ended, by choice or because the peer
// went away, no new one is opened to it for thirty seconds.
#[clause("PNP-006-MUST-024")]
#[tokio::test(start_paused = true)]
async fn the_manager_waits_30_seconds_before_reconnecting_to_a_peer() {
    assert_eq!(RECONNECT_WAIT, Duration::from_secs(30));
    let transport = FakeTransport::default();
    let manager = ConnectionManager::new(transport.clone());
    for (round, voluntary) in [(0, true), (1, false)] {
        manager.connect(peer(1)).await.unwrap();
        if voluntary {
            tokio::time::advance(MIN_CONNECTION_LIFETIME).await;
            manager.close(peer(1)).await.unwrap();
        } else {
            assert!(manager.drop_unresponsive(peer(1)).await);
        }
        for second in [0u64, 10, 29] {
            match manager.connect(peer(1)).await {
                Err(ManagerError::ReconnectTooSoon(ago, left)) => {
                    assert_eq!(ago + left, RECONNECT_WAIT);
                    assert!(ago >= Duration::from_secs(second));
                }
                other => panic!(
                    "round {round}: reconnecting after {second} s gave {:?}",
                    other.map(|_| ())
                ),
            }
            // Another peer is not held up.
            manager.connect(peer(2)).await.unwrap();
            tokio::time::advance(Duration::from_secs(if second == 10 { 19 } else { 10 })).await;
        }
        // Nothing was opened to the peer while it was refused.
        assert_eq!(transport.opened.load(Ordering::SeqCst), 2 + round * 2);
        tokio::time::advance(Duration::from_secs(1)).await;
        manager
            .connect(peer(1))
            .await
            .expect("thirty seconds later");
        tokio::time::advance(MIN_CONNECTION_LIFETIME).await;
        manager.close(peer(1)).await.unwrap();
        tokio::time::advance(RECONNECT_WAIT).await;
    }
}

// §4.5.3: the manager brings a node up to two connections and stops at eight.
#[clause("PNP-006-SHOULD-002")]
#[tokio::test(start_paused = true)]
async fn a_node_keeps_two_to_eight_connections() {
    assert_eq!((MIN_CONNECTIONS, MAX_CONNECTIONS), (2, 8));
    let transport = FakeTransport::default();
    let manager = ConnectionManager::new(transport.clone());
    let candidates: Vec<SocketAddr> = (1..=20).map(peer).collect();

    // Left to itself it opens the minimum, from the candidates in order.
    assert_eq!(manager.maintain(&candidates).await, 2);
    assert_eq!(transport.opened.load(Ordering::SeqCst), 2);
    assert_eq!(manager.maintain(&candidates).await, 2, "and no more");
    assert_eq!(transport.opened.load(Ordering::SeqCst), 2);

    // Asked for more, it goes to eight and refuses the ninth.
    for addr in &candidates[2..8] {
        manager.connect(*addr).await.unwrap();
    }
    assert_eq!(manager.connection_count().await, 8);
    assert!(matches!(
        manager.connect(candidates[8]).await,
        Err(ManagerError::TooManyConnections)
    ));
    assert_eq!(transport.opened.load(Ordering::SeqCst), 8);
    // A connection that exists is still handed out at the limit.
    manager.connect(candidates[0]).await.unwrap();

    // When connections go away it tops up to the minimum again.
    for addr in &candidates[..7] {
        manager.drop_unresponsive(*addr).await;
    }
    assert_eq!(manager.connection_count().await, 1);
    assert_eq!(manager.maintain(&candidates[10..]).await, 2);
}

// ── §5.1, §5.2, §5.4 Fingerprint profiles ─────────────────────────

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let dir = common::unique_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// §5.1.4 and §5.4: a fingerprint profile is a CBOR file in the §5.4 format, and what is in
// the file is what goes on the wire, without rebuilding anything: the cipher suite order,
// the group order and key share, the ALPN list and the SNI. Replacing the file changes the
// ClientHello.
#[clause("PNP-006-MUST-031", "PNP-006-SHOULD-007")]
#[tokio::test]
async fn a_profile_file_decides_the_client_hello() {
    let dir = unique_dir("profiles");
    let file = dir.join("custom.cbor");

    // The file is the §5.4 map: these keys, by these names.
    let mut profile = FingerprintProfile::firefox();
    profile.name = "custom-1".into();
    profile.cipher_suites = vec![0x1303, 0x1301, 0x1302];
    profile.supported_groups = vec![0x0017, 0x001D];
    profile.key_shares = vec![0x0017];
    profile.alpn_protocols = vec!["h2".into(), "http/1.1".into()];
    profile.sni_hosts = vec!["static.custom-one.example".into()];
    std::fs::write(&file, profile.to_cbor()).unwrap();
    let map: ciborium::Value = ciborium::from_reader(&std::fs::read(&file).unwrap()[..]).unwrap();
    let keys: HashSet<String> = map
        .as_map()
        .expect("a CBOR map")
        .iter()
        .map(|(k, _)| k.as_text().unwrap().to_owned())
        .collect();
    let spec = [
        "name",
        "tls_version",
        "cipher_suites",
        "extensions",
        "supported_groups",
        "signature_algos",
        "alpn",
        "key_shares",
        "grease",
        "sni_hosts",
    ];
    let spec: HashSet<String> = spec.iter().map(|k| k.to_string()).collect();
    assert_eq!(keys, spec);

    let loaded = FingerprintProfile::load(&file).expect("the profile file loads");
    assert_eq!(loaded, profile);
    let hello = hello_of(&TlsTransport::client(&loaded).unwrap()).await;
    assert_eq!(hello.tls13_suites(), [0x1303, 0x1301, 0x1302]);
    assert_eq!(&hello.supported_groups[..2], [0x0017, 0x001D]);
    assert_eq!(hello.key_shares, [0x0017]);
    assert_eq!(hello.alpn, ["h2", "http/1.1"]);
    assert_eq!(hello.sni.as_deref(), Some("static.custom-one.example"));

    // An update: the same file name, other contents, no new build.
    profile.cipher_suites = vec![0x1302, 0x1303, 0x1301];
    profile.supported_groups = vec![0x001D, 0x0018];
    profile.sni_hosts = vec!["img.custom-two.example".into()];
    std::fs::write(&file, profile.to_cbor()).unwrap();
    let mut registry = ProfileRegistry::builtin();
    let before = registry.len();
    assert_eq!(registry.load_dir(&dir, 10.0).unwrap(), 1);
    assert_eq!(registry.len(), before + 1);
    let updated = registry
        .profiles()
        .find(|p| p.name == "custom-1")
        .expect("installed from the directory")
        .clone();
    let hello = hello_of(&TlsTransport::client(&updated).unwrap()).await;
    assert_eq!(hello.tls13_suites(), [0x1302, 0x1303, 0x1301]);
    assert_eq!(&hello.supported_groups[..2], [0x001D, 0x0018]);
    assert_eq!(hello.key_shares, [0x001D]);
    assert_eq!(hello.sni.as_deref(), Some("img.custom-two.example"));
    // Loading it again replaces it rather than adding a second copy.
    assert_eq!(registry.load_dir(&dir, 10.0).unwrap(), 1);
    assert_eq!(registry.len(), before + 1);

    // A file that is not a usable profile is refused.
    std::fs::write(&file, b"\xa0").unwrap();
    assert!(FingerprintProfile::load(&file).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

fn is_plausible_host(name: &str) -> bool {
    name.contains('.')
        && name.parse::<std::net::IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

// §5.2.1: the SNI is a plausible host name, drawn per connection from a configurable pool
// of CDN-hosted names. For the shipped client the name is its relay's own.
#[clause("PNP-006-MUST-032", "PNP-006-SHOULD-008")]
#[tokio::test]
async fn the_sni_is_a_plausible_host_from_a_configurable_pool() {
    // The built-in pool.
    let profile = FingerprintProfile::chrome();
    assert!(profile.sni_hosts.len() >= 2);
    let transport = TlsTransport::client(&profile).unwrap();
    let mut seen = HashSet::new();
    for _ in 0..40 {
        let sni = hello_of(&transport)
            .await
            .sni
            .expect("an SNI is always sent");
        assert!(is_plausible_host(&sni), "{sni}");
        assert!(profile.sni_hosts.contains(&sni), "{sni} is not in the pool");
        seen.insert(sni);
    }
    assert!(seen.len() >= 2, "forty connections all used {seen:?}");

    // A configured pool replaces it.
    let pool = vec![
        "a.cdn-one.example".to_owned(),
        "b.cdn-two.example".to_owned(),
    ];
    let transport = TlsTransport::client(&profile)
        .unwrap()
        .with_sni_pool(pool.clone());
    let mut seen = HashSet::new();
    for _ in 0..40 {
        seen.insert(hello_of(&transport).await.sni.unwrap());
    }
    let pool: HashSet<String> = pool.into_iter().collect();
    assert_eq!(seen, pool);

    // The shipped client: the SNI of its relay socket is the relay's host name.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let dir = unique_dir("app-sni");
    let (app, _events) = start_app(&dir, format!("wss://localhost:{port}/ws"), Vec::new()).await;
    let hello = tokio::time::timeout(Duration::from_secs(20), capture_hello(&listener))
        .await
        .expect("the client connects to its relay");
    assert_eq!(hello.sni.as_deref(), Some("localhost"));
    app.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The ClientHello rustls sends for `profile`.
async fn hello_for(profile: &FingerprintProfile) -> Hello {
    // PNP-006-SHOULD-006: the TLS library is rustls, and this is its configuration type.
    let config: rustls::ClientConfig = profile.build_client_config().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = async {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let _ = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(SNI).unwrap(), tcp)
            .await;
    };
    let (hello, _) = tokio::join!(capture_hello(&listener), connect);
    hello
}

// §5.1.3 and §7.5: the profiles are built on rustls, and there are Chrome, Firefox and Edge
// profiles. Chrome's and Firefox's put different ClientHellos on the wire (the order of
// their cipher suites); Edge's is Chrome's, as the browsers' are.
#[clause("PNP-006-SHOULD-006", "PNP-006-SHOULD-012")]
#[tokio::test]
async fn chrome_firefox_and_edge_profiles_reach_the_wire() {
    let registry = ProfileRegistry::builtin();
    let find = |browser: &str| {
        registry
            .profiles()
            .find(|p| p.name.starts_with(browser))
            .unwrap_or_else(|| panic!("no {browser} profile"))
            .clone()
    };
    let (chrome, firefox, edge) = (find("chrome"), find("firefox"), find("edge"));
    let (c, f, e) = (
        hello_for(&chrome).await,
        hello_for(&firefox).await,
        hello_for(&edge).await,
    );
    assert_eq!(c.tls13_suites(), [0x1301, 0x1302, 0x1303], "Chrome's order");
    assert_eq!(
        f.tls13_suites(),
        [0x1301, 0x1303, 0x1302],
        "Firefox's order"
    );
    assert_ne!(
        c.cipher_suites, f.cipher_suites,
        "two fingerprints on the wire"
    );
    assert_eq!(e.cipher_suites, c.cipher_suites, "Edge is Chromium");
    for hello in [&c, &f, &e] {
        assert_eq!(hello.alpn, ["h2", "http/1.1"]);
        assert!(hello.key_shares.contains(&0x001D) || hello.key_shares.contains(&0x11EC));
    }
    assert!(chrome.same_fingerprint(&edge) && !chrome.same_fingerprint(&firefox));
}

/// How often each profile is drawn in `n` draws.
fn draw(registry: &ProfileRegistry, n: usize) -> HashMap<String, f64> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..n {
        *counts.entry(registry.select().name.clone()).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(name, c)| (name, c as f64 / n as f64))
        .collect()
}

// §5.4: at least three profiles, and a connection's profile is drawn in proportion to
// browser market share.
#[clause("PNP-006-SHOULD-010")]
#[test]
fn a_profile_is_drawn_in_proportion_to_market_share() {
    let builtin = ProfileRegistry::builtin();
    assert!(builtin.len() >= 3 && builtin.has_enough_profiles());
    assert!(
        !ProfileRegistry::new(vec![(FingerprintProfile::chrome(), 1.0)])
            .unwrap()
            .has_enough_profiles()
    );

    // Three different fingerprints with shares 50 / 30 / 20.
    let mut third = FingerprintProfile::firefox();
    third.name = "third".into();
    third.cipher_suites.reverse();
    let registry = ProfileRegistry::new(vec![
        (FingerprintProfile::chrome(), 50.0),
        (FingerprintProfile::firefox(), 30.0),
        (third, 20.0),
    ])
    .unwrap();
    let drawn = draw(&registry, 40_000);
    for (name, share) in [("chrome-131", 0.5), ("firefox-132", 0.3), ("third", 0.2)] {
        let got = drawn[name];
        assert!(
            (got - share).abs() < 0.015,
            "{name}: drawn {got:.3} of the time; its market share is {share}"
        );
    }
    // The built-in registry draws what it says it does.
    let drawn = draw(&builtin, 40_000);
    for (name, share) in builtin.selection_shares() {
        assert!((drawn[&name] - share).abs() < 0.015, "{name}");
    }
    // Among the profiles of one engine the market shares still decide: Chrome over Edge.
    assert!(drawn["chrome-131"] > drawn["edge-131"] * 3.0);
}

// §7.5: no single fingerprint is drawn for more than half the connections, although the
// Chromium browsers hold far more than half the market. Chrome and Edge are one
// fingerprint.
#[clause("PNP-006-SHOULD-013")]
#[test]
fn no_fingerprint_is_used_for_more_than_half_the_connections() {
    let registry = ProfileRegistry::builtin();
    let drawn = draw(&registry, 40_000);
    let profiles: Vec<FingerprintProfile> = registry.profiles().cloned().collect();
    for profile in &profiles {
        // Everything that looks the same on the wire counts together.
        let together: f64 = profiles
            .iter()
            .filter(|p| p.same_fingerprint(profile))
            .map(|p| drawn[&p.name])
            .sum();
        assert!(
            together <= 0.5 + 0.015,
            "the {} fingerprint was drawn {together:.3} of the time",
            profile.name
        );
    }
    // The cap is what holds Chromium back: it sits at the limit.
    let chromium: f64 = drawn["chrome-131"] + drawn["edge-131"];
    assert!(chromium > 0.47, "{chromium:.3}");

    // A registry dominated by one fingerprint is capped the same way.
    let lopsided = ProfileRegistry::new(vec![
        (FingerprintProfile::chrome(), 97.0),
        (FingerprintProfile::firefox(), 3.0),
    ])
    .unwrap();
    let drawn = draw(&lopsided, 40_000);
    assert!(drawn["chrome-131"] <= 0.515, "{:.3}", drawn["chrome-131"]);
}

// ── §5.2, §5.3.4, §6.3 Probes ─────────────────────────────────────

/// A relay's listener: only a connection that opens with a CREATE cell is ParolNet.
async fn relay_listener(cert: &Cert) -> parolnet_transport::tls_stream::TlsListener {
    cert.transport()
        .with_gate(create_gate())
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap()
}

/// What an HTTP/2 client gets for one request.
struct Answer {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

/// Send one HTTP/2 request with `body` to `addr` and read the whole answer.
async fn h2_request(
    cert: &Cert,
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
) -> Answer {
    let tls = tls_connect(cert, addr, &[b"h2", b"http/1.1"]).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut requests, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(connection);
    let request = http::Request::builder()
        .method(method)
        .uri(format!("https://{SNI}{path}"))
        .body(())
        .unwrap();
    let (response, mut stream) = requests.send_request(request, body.is_empty()).unwrap();
    if !body.is_empty() {
        stream
            .send_data(bytes::Bytes::copy_from_slice(body), true)
            .unwrap();
    }
    let response = tokio::time::timeout(Duration::from_secs(20), response)
        .await
        .expect("an answer")
        .expect("a valid HTTP/2 response");
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let mut recv = response.into_body();
    let mut body = Vec::new();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.unwrap();
        let _ = recv.flow_control().release_capacity(chunk.len());
        body.extend_from_slice(&chunk);
    }
    Answer {
        status,
        content_type,
        body,
    }
}

fn assert_cover_page(answer: &Answer, what: &str) {
    assert_eq!(answer.status, 200, "{what}");
    assert!(
        answer.content_type.starts_with("text/html"),
        "{what}: content type {:?}",
        answer.content_type
    );
    let body = String::from_utf8_lossy(&answer.body);
    assert!(body.contains("<html"), "{what}: not a page: {body}");
    assert!(body.len() >= 256, "{what}: {} bytes", body.len());
    for token in ["parolnet", "relay", "circuit", "onion"] {
        assert!(
            !body.to_ascii_lowercase().contains(token),
            "{what}: the page says {token:?}"
        );
    }
}

/// A plain HTTP/1.1 GET over an existing stream: status, content type, body.
async fn http1_get<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, path: &str) -> Answer {
    let request = format!("GET {path} HTTP/1.1\r\nHost: {SNI}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw)).await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let content_type = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-type")
                .then(|| v.trim().to_owned())
        })
        .unwrap_or_default();
    Answer {
        status,
        content_type,
        body: body.as_bytes().to_vec(),
    }
}

// §5.2.3, §5.3.4 and §6.3: whoever connects and is not ParolNet gets a web page. The
// relay's TLS listener answers an HTTP/2 request and an HTTP/1.1 request with 200,
// text/html and a generic page; the relay binary, in its default profile, serves the same
// page as its front page.
#[clause("PNP-006-MUST-033", "PNP-006-MUST-038", "PNP-006-MUST-040")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_is_not_parolnet_is_served_a_web_page() {
    let cert = Cert::new(&[SNI]);
    let listener = relay_listener(&cert).await;
    let addr = listener.local_addr();

    // MUST-038: HTTP/2 probes.
    for path in ["/", "/index.html", "/wp-login.php"] {
        let answer = h2_request(&cert, addr, "GET", path, b"").await;
        assert_cover_page(&answer, &format!("HTTP/2 GET {path}"));
        assert_eq!(answer.body, COVER_PAGE_HTML.as_bytes());
    }
    // A HEAD request gets the same headers and, as HTTP says, no body.
    let head = h2_request(&cert, addr, "HEAD", "/favicon.ico", b"").await;
    assert_eq!(head.status, 200);
    assert!(head.content_type.starts_with("text/html"));
    assert!(head.body.is_empty());
    // MUST-033: a client that speaks HTTP/1.1 over TLS.
    let mut tls = tls_connect(&cert, addr, &[b"http/1.1"]).await;
    let answer = http1_get(&mut tls, "/").await;
    assert_cover_page(&answer, "HTTPS GET /");
    // None of them was taken for a ParolNet connection.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), listener.accept())
            .await
            .is_err(),
        "a probe was handed to the relay as a connection"
    );

    // MUST-033 / MUST-040: the relay binary as it ships, default (signaling-only) profile.
    // Its front page is the same generic page.
    let relay = common::Relay::start(&[]).await;
    let port: u16 = relay
        .ws_url()
        .trim_start_matches("ws://127.0.0.1:")
        .trim_end_matches("/ws")
        .parse()
        .unwrap();
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let answer = http1_get(&mut tcp, "/").await;
    assert_cover_page(&answer, "relay GET /");
    // A path that is nothing answers as a web server does, and says nothing either.
    for path in ["/index.php", "/admin/login", "/wp-admin/"] {
        let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let answer = http1_get(&mut tcp, path).await;
        assert_eq!(answer.status, 404, "relay GET {path}");
        let body = String::from_utf8_lossy(&answer.body).to_ascii_lowercase();
        for token in ["parolnet", "relay", "circuit", "onion"] {
            assert!(!body.contains(token), "relay GET {path} says {token:?}");
        }
    }
}

// §6.3: a relay's listener says nothing ParolNet until the client has sent a valid circuit
// CREATE cell. A stream that opens with anything else (a PADDING cell, a DATA cell, a
// truncated CREATE, noise) gets the page a web client gets, byte for byte, and the relay
// never sees a connection. A stream that opens with a CREATE cell is served: the relay
// answers CREATED, and further streams on that connection need no second CREATE.
#[clause("PNP-006-MUST-041")]
#[tokio::test]
async fn nothing_is_said_before_a_valid_create_cell() {
    let cert = Cert::new(&[SNI]);
    let listener = relay_listener(&cert).await;
    let addr = listener.local_addr();
    let framed = |message: &[u8]| [&(message.len() as u32).to_be_bytes()[..], message].concat();

    let probe = h2_request(&cert, addr, "GET", "/", b"").await;
    let (create, secret) = CircuitHandshake::create_cell(0x0BAD_CAFE);
    let mut data_cell = create.to_bytes();
    data_cell[4] = 0x05; // the same cell, as DATA
    let not_create: [(&str, Vec<u8>); 5] = [
        ("a PADDING cell", RelayCell::padding(9).to_bytes().to_vec()),
        ("a DATA cell", data_cell.to_vec()),
        ("a truncated CREATE", create.to_bytes()[..400].to_vec()),
        ("noise", vec![0xA5; CELL_SIZE]),
        (
            "a CREATE on circuit 0",
            CircuitHandshake::create_cell(0).0.to_bytes().to_vec(),
        ),
    ];
    for (what, message) in &not_create {
        let answer = h2_request(&cert, addr, "POST", "/", &framed(message)).await;
        assert_cover_page(&answer, what);
        assert_eq!(answer.body, probe.body, "{what}: not the page a probe gets");
        assert_eq!(answer.content_type, probe.content_type, "{what}");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(500), listener.accept())
            .await
            .is_err(),
        "a stream without a CREATE cell reached the relay"
    );
    // The same from the transport's own client: its stream is not accepted.
    let refused = cert.transport().connect(addr).await.unwrap();
    refused
        .send(&RelayCell::padding(9).to_bytes())
        .await
        .unwrap();
    assert!(refused.recv().await.is_err());

    // A CREATE cell opens the door.
    let relay = tokio::spawn(async move {
        let conn = listener.accept().await.expect("a ParolNet connection");
        let first: [u8; CELL_SIZE] = conn.recv().await.unwrap().try_into().unwrap();
        let node = StandardRelayNode::new();
        let created = match node
            .handle_cell(RelayCell::from_bytes(&first).unwrap())
            .await
            .unwrap()
        {
            RelayAction::Respond(cell) => cell,
            _ => panic!("the relay did not answer the CREATE"),
        };
        conn.send(&created.to_bytes()).await.unwrap();
        // The connection is ParolNet now: a second stream carries what it likes.
        let gossip = conn
            .accept_stream()
            .await
            .unwrap()
            .expect("a second stream");
        let message = gossip.recv().await.unwrap();
        gossip.send(&message).await.unwrap();
        gossip.close().await.unwrap();
        node.circuit_count()
    });
    let client = cert.transport().connect(addr).await.unwrap();
    client.send(&create.to_bytes()).await.unwrap();
    let created: [u8; CELL_SIZE] = client.recv().await.unwrap().try_into().unwrap();
    CircuitHandshake::process_created(&RelayCell::from_bytes(&created).unwrap(), &secret)
        .expect("the relay's CREATED completes the handshake");
    let gossip = client.open_stream().await.unwrap();
    gossip.send(b"not a cell at all").await.unwrap();
    assert_eq!(gossip.recv().await.unwrap(), b"not a cell at all");
    gossip.close().await.unwrap();
    assert_eq!(relay.await.unwrap(), 1, "the relay holds the circuit");
}

// ── The shipped client's relay socket ─────────────────────────────

type Events = UnboundedReceiver<AppEvent>;

/// Start the real client against the relay at `url`.
async fn start_app(
    dir: &std::path::Path,
    url: String,
    trust_anchors: Vec<Vec<u8>>,
) -> (AppHandle, Events) {
    let mut cfg = AppConfig::new(dir.join("data"), url);
    cfg.relay_trust_anchors = trust_anchors;
    cfg.stun_servers = Some(Vec::new());
    cfg.bind_ip = Some("127.0.0.1".parse().unwrap());
    parolnet_app::start(cfg).await.expect("start app")
}

async fn registered(events: &mut Events) {
    loop {
        match events.recv().await.expect("the client is running") {
            AppEvent::Relay(RelayState::Registered { .. }) => return,
            _ => continue,
        }
    }
}

/// What a scripted relay saw of its clients.
#[derive(Default)]
struct RelayLog {
    /// When each connection was accepted and when it ended.
    connections: Mutex<Vec<(tokio::time::Instant, Option<tokio::time::Instant>)>>,
    pings: AtomicUsize,
    close_frames: AtomicUsize,
}

/// Serve one client socket the way a relay does (register without a challenge, answer
/// pings). `hang_up_after` closes the TCP connection that long after registering.
async fn serve_relay_socket<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    log: Arc<RelayLog>,
    hang_up_after: Option<Duration>,
) {
    let index = {
        let mut connections = log.connections.lock().unwrap();
        connections.push((tokio::time::Instant::now(), None));
        connections.len() - 1
    };
    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };
    let hang_up = async {
        match hang_up_after {
            Some(after) => tokio::time::sleep(after).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(hang_up);
    loop {
        tokio::select! {
            msg = ws.next() => match msg {
                Some(Ok(Message::Text(text))) => {
                    let reply = if text.contains("\"register\"") {
                        r#"{"type":"registered","peer_id":"00"}"#
                    } else if text.contains("\"ping\"") {
                        log.pings.fetch_add(1, Ordering::SeqCst);
                        r#"{"type":"pong"}"#
                    } else {
                        continue;
                    };
                    if ws.send(Message::Text(reply.into())).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) => {
                    log.close_frames.fetch_add(1, Ordering::SeqCst);
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break,
            },
            _ = &mut hang_up => break,
        }
    }
    log.connections.lock().unwrap()[index].1 = Some(tokio::time::Instant::now());
}

async fn scripted_relay(hang_up_after: Option<Duration>) -> (String, Arc<RelayLog>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let log = Arc::new(RelayLog::default());
    let shared = log.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(serve_relay_socket(tcp, shared.clone(), hang_up_after));
        }
    });
    (url, log)
}

/// The paused clock, driven by hand.
///
/// The client and the scripted relay talk over real loopback TCP, which takes real time,
/// while tokio's paused clock jumps to the next timer whenever every task is waiting. Left
/// alone it would jump over a pong that is still in the kernel. So a task that always
/// yields keeps the clock from moving by itself, and the test moves it in small steps,
/// giving the sockets a moment after each.
struct Stepper {
    busy: tokio::task::JoinHandle<()>,
    started: tokio::time::Instant,
}

impl Stepper {
    const STEP: Duration = Duration::from_millis(250);

    fn start() -> Stepper {
        Stepper {
            busy: tokio::spawn(async {
                loop {
                    tokio::task::yield_now().await;
                }
            }),
            started: tokio::time::Instant::now(),
        }
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Let tasks run and loopback I/O arrive, without moving the clock.
    async fn settle() {
        for _ in 0..4 {
            std::thread::sleep(Duration::from_micros(300));
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
        }
    }

    /// One step of the clock.
    async fn step(&self) {
        tokio::time::advance(Self::STEP).await;
        Self::settle().await;
    }

    /// Step until the client says it is registered (at most `limit` of the clock).
    async fn until_registered(&self, events: &mut Events, limit: Duration) {
        let deadline = self.elapsed() + limit;
        loop {
            Self::settle().await;
            while let Ok(event) = events.try_recv() {
                if matches!(event, AppEvent::Relay(RelayState::Registered { .. })) {
                    return;
                }
            }
            assert!(self.elapsed() < deadline, "the client did not register");
            self.step().await;
        }
    }
}

impl Drop for Stepper {
    fn drop(&mut self) {
        self.busy.abort();
    }
}

// §4.5.1 in the shipped client: the connection to the relay is made once and kept. Over
// twelve minutes (of the paused clock) the client opens one connection, pings on it, and
// never ends it: no voluntary teardown inside the ten-minute minimum, or after it.
#[clause("PNP-006-MUST-022", "PNP-006-MUST-023")]
#[tokio::test(start_paused = true)]
async fn the_clients_relay_connection_is_kept_open() {
    let clock = Stepper::start();
    let (url, log) = scripted_relay(None).await;
    let dir = unique_dir("app-long-lived");
    let (app, mut events) = start_app(&dir, url, Vec::new()).await;
    clock
        .until_registered(&mut events, Duration::from_secs(60))
        .await;

    let from = clock.elapsed();
    let twelve_minutes = Duration::from_secs(12 * 60);
    while clock.elapsed() - from < twelve_minutes {
        clock.step().await;
        while let Ok(event) = events.try_recv() {
            match event {
                AppEvent::Relay(RelayState::Registered { .. }) => {}
                AppEvent::Relay(state) => panic!(
                    "the relay connection changed to {state:?} after {:?}",
                    clock.elapsed() - from
                ),
                _ => {}
            }
        }
    }
    {
        let connections = log.connections.lock().unwrap();
        assert_eq!(connections.len(), 1, "one connection in twelve minutes");
        assert!(connections[0].1.is_none(), "and it is still open");
    }
    // It was alive all along: a ping every 20 seconds.
    let pings = log.pings.load(Ordering::SeqCst);
    assert!(
        (30..=40).contains(&pings),
        "{pings} pings in twelve minutes"
    );
    assert_eq!(log.close_frames.load(Ordering::SeqCst), 0);
    app.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

// §4.5.2 in the shipped client: when its relay connection ends, the next one is opened no
// sooner than thirty seconds later, every time, and a network-change nudge (which asks for
// an immediate reconnect) does not shorten the wait.
#[clause("PNP-006-MUST-024")]
#[tokio::test(start_paused = true)]
async fn the_client_waits_30_seconds_before_reconnecting_to_its_relay() {
    let clock = Stepper::start();
    // The relay drops every connection two seconds after accepting it.
    let (url, log) = scripted_relay(Some(Duration::from_secs(2))).await;
    let dir = unique_dir("app-reconnect");
    let (app, mut events) = start_app(&dir, url, Vec::new()).await;

    let mut disconnects = 0;
    while log.connections.lock().unwrap().len() < 6 {
        assert!(
            clock.elapsed() < Duration::from_secs(400),
            "the client stopped reconnecting"
        );
        clock.step().await;
        while let Ok(event) = events.try_recv() {
            if matches!(event, AppEvent::Relay(RelayState::Disconnected { .. })) {
                disconnects += 1;
                // From the third time on the network "changes" the moment the connection
                // is gone, and again ten seconds later.
                if disconnects >= 3 {
                    app.network_changed();
                    for _ in 0..40 {
                        clock.step().await;
                    }
                    app.network_changed();
                }
            }
        }
    }
    assert!(disconnects >= 5, "{disconnects} disconnects");

    let connections = log.connections.lock().unwrap().clone();
    for pair in connections.windows(2) {
        let ended = pair[0].1.expect("the earlier connection ended");
        let waited = pair[1].0 - ended;
        assert!(
            waited >= Duration::from_secs(30),
            "reconnected {waited:?} after the connection ended"
        );
        assert!(
            waited <= Duration::from_secs(33),
            "reconnected only after {waited:?}"
        );
    }
    app.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

// §4.5.5 in the shipped client: shutting down, it closes its relay connection properly.
// The relay (TLS here, with a certificate the client was told to trust) receives the
// WebSocket close frame and then TLS close_notify, not a dropped socket.
#[clause("PNP-006-MUST-026")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_closes_its_relay_connection_with_close_notify() {
    let cert = Cert::new(&["127.0.0.1"]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("wss://{}/ws", listener.local_addr().unwrap());
    let acceptor = TlsAcceptor::from(Arc::new(cert.server_config(&[])));
    let log = Arc::new(RelayLog::default());
    let relay_log = log.clone();
    let relay = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tap = Tap::new(acceptor.accept(tcp).await.expect("TLS handshake"));
        serve_relay_socket(tap.clone(), relay_log, None).await;
        tap.end().await
    });

    let dir = unique_dir("app-close");
    let (app, mut events) = start_app(&dir, url, vec![cert.der.to_vec()]).await;
    tokio::time::timeout(Duration::from_secs(30), registered(&mut events))
        .await
        .expect("the client registers over TLS");
    app.shutdown().await;

    let end = tokio::time::timeout(Duration::from_secs(20), relay)
        .await
        .expect("the relay sees the connection end")
        .unwrap();
    assert_eq!(
        log.close_frames.load(Ordering::SeqCst),
        1,
        "the WebSocket close"
    );
    assert_eq!(end, End::CloseNotify, "then TLS close_notify");
    let _ = std::fs::remove_dir_all(&dir);
}
