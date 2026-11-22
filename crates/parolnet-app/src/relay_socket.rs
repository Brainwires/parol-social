//! The TCP and TLS side of the relay socket: how the connection is opened and closed, as
//! PNP-006 §4.5 asks of a long-lived TLS connection.

use std::sync::Arc;
use std::time::Duration;

use futures_util::SinkExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

/// TCP keepalive on the relay socket: the first probe after this long without traffic, and
/// one every this long after it (PNP-006-MUST-027).
pub const TCP_KEEPALIVE: Duration = Duration::from_secs(30);

/// How long a graceful close may take before the socket is simply dropped.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) type RelaySocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Open the TCP connection every relay socket rides on, with TCP keepalive enabled at
/// [`TCP_KEEPALIVE`] (PNP-006-MUST-027).
pub async fn tcp_connect(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect((host, port)).await?;
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE)
        .with_interval(TCP_KEEPALIVE);
    socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive)?;
    Ok(stream)
}

/// The TLS configuration for a relay whose certificate chains to one of `anchors` (DER) or
/// to a public root.
fn tls_config(anchors: &[Vec<u8>]) -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for der in anchors {
        roots
            .add(rustls::pki_types::CertificateDer::from(der.clone()))
            .map_err(|e| format!("relay trust anchor: {e}"))?;
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Connect to the relay at `url` (`ws://` or `wss://`): TCP with keepalive, TLS for `wss`
/// with the relay's host name as SNI (PNP-006-MUST-032), then the WebSocket upgrade.
pub(crate) async fn connect(url: &str, anchors: &[Vec<u8>]) -> Result<RelaySocket, String> {
    let request = url
        .into_client_request()
        .map_err(|e| format!("connect: {e}"))?;
    let uri = request.uri();
    let tls = uri.scheme_str() == Some("wss");
    let host = uri
        .host()
        .ok_or_else(|| "connect: the relay URL has no host".to_owned())?
        // An IPv6 literal is bracketed in a URL and bare in a socket address.
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let stream = tcp_connect(&host, port)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let connector = if tls {
        Connector::Rustls(Arc::new(tls_config(anchors)?))
    } else {
        Connector::Plain
    };
    let (ws, _) =
        tokio_tungstenite::client_async_tls_with_config(request, stream, None, Some(connector))
            .await
            .map_err(|e| format!("connect: {e}"))?;
    Ok(ws)
}

/// Close the socket properly (PNP-006-MUST-026): the WebSocket close frame, then TLS
/// `close_notify` and the TCP FIN. Bounded: a relay that does not answer is not waited for.
pub(crate) async fn close(mut ws: RelaySocket) {
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, async {
        let _ = ws.close(None).await;
        let _ = ws.flush().await;
        let _ = ws.get_mut().shutdown().await;
    })
    .await;
}
