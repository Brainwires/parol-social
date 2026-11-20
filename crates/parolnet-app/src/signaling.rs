//! The relay WebSocket client: connects, registers by Ed25519 challenge, keeps the socket
//! alive and reconnects with backoff. It forwards every relay frame to the app core and
//! sends the frames the core gives it. Signaling frames are never queued here: a frame given
//! while the socket is down is dropped (the core retries at its own level).

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::wire::{ClientFrame, ServerFrame};

/// Signs a relay challenge nonce with the identity key.
pub type Signer = Arc<dyn Fn(&[u8]) -> [u8; 64] + Send + Sync>;

/// What the signaling task reports to the core.
#[derive(Debug)]
pub enum SigEvent {
    Connecting,
    Registered { profile: String },
    Frame(ServerFrame),
    Disconnected { reason: String },
}

/// Keepalive interval (the relay closes sockets idle for 60 s).
const PING_EVERY: Duration = Duration::from_secs(25);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

pub struct SigHandle {
    tx: mpsc::UnboundedSender<ClientFrame>,
    task: tokio::task::JoinHandle<()>,
}

impl SigHandle {
    pub fn send(&self, frame: ClientFrame) {
        let _ = self.tx.send(frame);
    }

    pub fn stop(&self) {
        self.task.abort();
    }
}

pub fn spawn(
    url: String,
    peer_id: String,
    public_key_hex: String,
    signer: Signer,
    events: mpsc::UnboundedSender<SigEvent>,
) -> SigHandle {
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(run(url, peer_id, public_key_hex, signer, events, rx));
    SigHandle { tx, task }
}

async fn run(
    url: String,
    peer_id: String,
    public_key_hex: String,
    signer: Signer,
    events: mpsc::UnboundedSender<SigEvent>,
    mut outgoing: mpsc::UnboundedReceiver<ClientFrame>,
) {
    let mut backoff = BACKOFF_MIN;
    loop {
        let _ = events.send(SigEvent::Connecting);
        let reason = match session(
            &url,
            &peer_id,
            &public_key_hex,
            &signer,
            &events,
            &mut outgoing,
        )
        .await
        {
            Ok(registered) => {
                if registered {
                    backoff = BACKOFF_MIN;
                }
                "closed".to_owned()
            }
            Err(e) => e,
        };
        if events
            .send(SigEvent::Disconnected {
                reason: reason.clone(),
            })
            .is_err()
        {
            return;
        }
        tracing::debug!(%reason, ?backoff, "relay socket down; reconnecting");
        // Drop frames given while down: signaling is never queued.
        let sleep = tokio::time::sleep(backoff);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                f = outgoing.recv() => if f.is_none() { return },
            }
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// One socket's life. Returns whether it got registered.
async fn session(
    url: &str,
    peer_id: &str,
    public_key_hex: &str,
    signer: &Signer,
    events: &mpsc::UnboundedSender<SigEvent>,
    outgoing: &mut mpsc::UnboundedReceiver<ClientFrame>,
) -> Result<bool, String> {
    crate::install_crypto_provider();
    let (ws, _) = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_tungstenite::connect_async(url),
    )
    .await
    .map_err(|_| "connect timed out".to_owned())?
    .map_err(|e| format!("connect: {e}"))?;
    let (mut sink, mut stream) = ws.split();

    let send = |frame: &ClientFrame| Message::Text(frame.to_json().into());
    sink.send(send(&ClientFrame::Register {
        peer_id: peer_id.to_owned(),
        pubkey: None,
        signature: None,
        nonce: None,
    }))
    .await
    .map_err(|e| format!("send: {e}"))?;

    let mut registered = false;
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await;
    loop {
        tokio::select! {
            msg = stream.next() => {
                let msg = match msg {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => return Err(format!("read: {e}")),
                    None => return Ok(registered),
                };
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Close(_) => return Ok(registered),
                    _ => continue,
                };
                let Some(frame) = ServerFrame::parse(&text) else { continue };
                match frame {
                    ServerFrame::Challenge { nonce } => {
                        let Ok(nonce_bytes) = hex::decode(&nonce) else { continue };
                        let sig = signer(&nonce_bytes);
                        sink.send(send(&ClientFrame::Register {
                            peer_id: peer_id.to_owned(),
                            pubkey: Some(public_key_hex.to_owned()),
                            signature: Some(hex::encode(sig)),
                            nonce: Some(nonce),
                        }))
                        .await
                        .map_err(|e| format!("send: {e}"))?;
                    }
                    ServerFrame::Registered { profile, .. } => {
                        registered = true;
                        let _ = events.send(SigEvent::Registered {
                            profile: profile.unwrap_or_else(|| "relay".into()),
                        });
                    }
                    ServerFrame::Pong => {}
                    other => {
                        let _ = events.send(SigEvent::Frame(other));
                    }
                }
            }
            frame = outgoing.recv() => {
                let Some(frame) = frame else { return Ok(registered) };
                // Only register / ping may precede registration (PNP-001 §10.6).
                if !registered && !matches!(frame, ClientFrame::Ping { .. }) {
                    tracing::debug!("dropping a frame given before registration");
                    continue;
                }
                sink.send(send(&frame)).await.map_err(|e| format!("send: {e}"))?;
            }
            _ = ping.tick() => {
                sink.send(send(&ClientFrame::Ping { ts: crate::now_ms() }))
                    .await
                    .map_err(|e| format!("send: {e}"))?;
            }
        }
    }
}
