//! Bidirectional CLI peer driver for round-trip / idle-resume smoke tests.
//!
//! A `PeerHandle` owns one WebSocket to the home relay and runs a background
//! task that multiplexes reads, writes, and a 20-second application-layer
//! ping (PNP-001-MUST-065). Orchestrators (round-trip, idle-resume) drive
//! the peer via command/event channels so the test logic lives in one place
//! instead of spread across read loops.
//!
//! The driver intentionally does NOT know about bootstrap, sessions, or
//! plaintext. It only ferries outer frames (`message`, `queued`, `ping`,
//! `pong`) in and out; the orchestrator encrypts/decrypts using
//! parolnet-core primitives and decides what to send next.

use anyhow::{Context, Result, anyhow};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use parolnet_crypto::IdentityKeyPair;
use parolnet_protocol::address::PeerId;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::protocol::Message;

pub const PING_INTERVAL_SECS: u64 = 20;

#[derive(Debug)]
pub enum PeerCmd {
    /// Send an outer `message` frame carrying a pre-encrypted envelope.
    Send {
        to: PeerId,
        token_hex: String,
        envelope: Vec<u8>,
        ack: oneshot::Sender<Result<()>>,
    },
    /// Close the WebSocket and terminate the task.
    Close,
}

#[derive(Debug)]
pub enum PeerEvt {
    /// Auth handshake finished — we're subscribed.
    Registered,
    /// An inbound encrypted envelope arrived (from the relay's store-and-forward or live peer).
    Inbound { envelope: Vec<u8> },
    /// Relay acknowledged our send went to store-and-forward (peer offline).
    Queued,
    /// Relay's pong in response to our ping (MUST-065). `ts` echoes the
    /// client-supplied timestamp; observability only — orchestrators count
    /// pongs but don't act on individual values.
    Pong {
        #[allow(dead_code)]
        ts: u64,
    },
    /// Relay reported an application-layer error.
    RelayError(String),
    /// WS closed, task is exiting.
    Disconnected,
}

pub struct PeerHandle {
    #[allow(dead_code)]
    pub peer_id: PeerId,
    cmd_tx: mpsc::UnboundedSender<PeerCmd>,
    pub evt_rx: mpsc::UnboundedReceiver<PeerEvt>,
    task: JoinHandle<()>,
}

impl PeerHandle {
    /// Open the WS, sign the challenge, wait for `registered`, and return a
    /// handle the orchestrator can use to send messages and drain events.
    pub async fn connect(relay_url: &str, identity: IdentityKeyPair) -> Result<Self> {
        let peer_id = PeerId::from_public_key(&identity.public_key_bytes());
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<PeerCmd>();
        let (evt_tx, evt_rx) = mpsc::unbounded_channel::<PeerEvt>();

        let relay = relay_url.to_string();
        let task = tokio::spawn(async move {
            if let Err(e) = run_peer_task(&relay, identity, peer_id, cmd_rx, evt_tx.clone()).await {
                tracing::warn!("[peer {}] task error: {e}", hex::encode(&peer_id.0[..4]));
                let _ = evt_tx.send(PeerEvt::RelayError(e.to_string()));
            }
            let _ = evt_tx.send(PeerEvt::Disconnected);
        });

        Ok(Self {
            peer_id,
            cmd_tx,
            evt_rx,
            task,
        })
    }

    /// Send one outer-frame `message`. Resolves once the WS write completes.
    pub async fn send(&self, to: PeerId, token_hex: String, envelope: Vec<u8>) -> Result<()> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.cmd_tx
            .send(PeerCmd::Send {
                to,
                token_hex,
                envelope,
                ack: ack_tx,
            })
            .map_err(|_| anyhow!("peer task is gone"))?;
        ack_rx.await.map_err(|_| anyhow!("send ack dropped"))?
    }

    /// Wait for the next event, or time out.
    pub async fn next_evt(&mut self, timeout: std::time::Duration) -> Option<PeerEvt> {
        match tokio::time::timeout(timeout, self.evt_rx.recv()).await {
            Ok(Some(e)) => Some(e),
            _ => None,
        }
    }

    /// Ask the task to close the WS and exit.
    pub async fn close(self) {
        let _ = self.cmd_tx.send(PeerCmd::Close);
        let _ = self.task.await;
    }
}

fn sign(identity: &IdentityKeyPair, message: &[u8]) -> ed25519_dalek::Signature {
    let sk = SigningKey::from_bytes(&identity.secret_bytes());
    sk.sign(message)
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn run_peer_task(
    relay_url: &str,
    identity: IdentityKeyPair,
    peer_id: PeerId,
    mut cmd_rx: mpsc::UnboundedReceiver<PeerCmd>,
    evt_tx: mpsc::UnboundedSender<PeerEvt>,
) -> Result<()> {
    let peer_hex = hex::encode(peer_id.0);
    let (ws, _) = tokio_tungstenite::connect_async(relay_url)
        .await
        .with_context(|| format!("connect {relay_url}"))?;
    let (mut write, mut read) = ws.split();

    // Kick off registration.
    write
        .send(Message::Text(
            serde_json::json!({"type":"register","peer_id":peer_hex})
                .to_string()
                .into(),
        ))
        .await?;

    let mut ping_timer = tokio::time::interval(std::time::Duration::from_secs(PING_INTERVAL_SECS));
    ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Burn the first (immediate) tick — we don't want to ping before we're registered.
    ping_timer.tick().await;

    let mut registered = false;
    loop {
        tokio::select! {
            // Outbound: caller wants to send or close.
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    PeerCmd::Send { to, token_hex, envelope, ack } => {
                        let outer = serde_json::json!({
                            "type":"message",
                            "to": hex::encode(to.0),
                            "token": token_hex,
                            "payload": hex::encode(&envelope),
                        });
                        let r = write.send(Message::Text(outer.to_string().into())).await
                            .map_err(|e| anyhow!("ws send: {e}"));
                        let _ = ack.send(r);
                    }
                    PeerCmd::Close => {
                        let _ = write.send(Message::Close(None)).await;
                        return Ok(());
                    }
                }
            }

            // Heartbeat: MUST-065.
            _ = ping_timer.tick() => {
                if registered {
                    let ping = serde_json::json!({"type":"ping","ts": now_ms()});
                    if let Err(e) = write.send(Message::Text(ping.to_string().into())).await {
                        tracing::warn!("[peer {}] ping send failed: {e}", &peer_hex[..8]);
                        return Err(anyhow!("ping failed: {e}"));
                    }
                }
            }

            // Inbound: WS frame arrived.
            frame = read.next() => {
                let Some(msg) = frame else {
                    tracing::info!("[peer {}] WS stream ended", &peer_hex[..8]);
                    return Ok(());
                };
                let msg = msg?;
                match msg {
                    Message::Text(txt) => {
                        let v: serde_json::Value = match serde_json::from_str(&txt) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        match v.get("type").and_then(|s| s.as_str()).unwrap_or("") {
                            "challenge" => {
                                let nonce_hex = v.get("nonce").and_then(|s| s.as_str())
                                    .ok_or_else(|| anyhow!("challenge missing nonce"))?;
                                let nonce = hex::decode(nonce_hex)?;
                                let sig = sign(&identity, &nonce);
                                let reg = serde_json::json!({
                                    "type":"register",
                                    "peer_id": peer_hex,
                                    "pubkey": hex::encode(identity.public_key_bytes()),
                                    "signature": hex::encode(sig.to_bytes()),
                                    "nonce": nonce_hex,
                                });
                                write.send(Message::Text(reg.to_string().into())).await?;
                            }
                            "registered" => {
                                registered = true;
                                let _ = evt_tx.send(PeerEvt::Registered);
                            }
                            "message" => {
                                let payload_hex = v.get("payload").and_then(|s| s.as_str())
                                    .unwrap_or("");
                                let envelope = hex::decode(payload_hex).unwrap_or_default();
                                let _ = evt_tx.send(PeerEvt::Inbound { envelope });
                            }
                            "queued" => {
                                let _ = evt_tx.send(PeerEvt::Queued);
                            }
                            "pong" => {
                                let ts = v.get("ts").and_then(|n| n.as_u64()).unwrap_or(0);
                                let _ = evt_tx.send(PeerEvt::Pong { ts });
                            }
                            "error" => {
                                let m = v.get("message").and_then(|s| s.as_str()).unwrap_or("").to_string();
                                let _ = evt_tx.send(PeerEvt::RelayError(m));
                            }
                            _ => {}
                        }
                    }
                    Message::Ping(data) => { let _ = write.send(Message::Pong(data)).await; }
                    Message::Close(_) => {
                        tracing::info!("[peer {}] WS close", &peer_hex[..8]);
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }
}
