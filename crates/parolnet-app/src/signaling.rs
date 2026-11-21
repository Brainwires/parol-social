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

/// Keepalive timing of one relay socket (PNP-001 §10.3).
#[derive(Clone, Copy, Debug)]
struct Keepalive {
    /// A `ping` goes out this often while the socket is open (PNP-001-MUST-065).
    ping_every: Duration,
    /// The socket is dead after this long without any frame from the relay
    /// (PNP-001-MUST-066): torn down, then reconnected with the usual backoff.
    dead_after: Duration,
}

/// 20 s pings; dead after 40 s of silence (two ping intervals; the relay itself closes
/// sockets idle for 60 s).
const KEEPALIVE: Keepalive = Keepalive {
    ping_every: Duration::from_secs(20),
    dead_after: Duration::from_secs(40),
};
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
    let task = tokio::spawn(run(
        url,
        peer_id,
        public_key_hex,
        signer,
        events,
        rx,
        KEEPALIVE,
    ));
    SigHandle { tx, task }
}

async fn run(
    url: String,
    peer_id: String,
    public_key_hex: String,
    signer: Signer,
    events: mpsc::UnboundedSender<SigEvent>,
    mut outgoing: mpsc::UnboundedReceiver<ClientFrame>,
    keepalive: Keepalive,
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
            keepalive,
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
    keepalive: Keepalive,
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
    let mut ping = tokio::time::interval(keepalive.ping_every);
    // A late ping is sent once, at once, and the cadence restarts from it: no burst.
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    // Fires when the relay has sent nothing for `dead_after`; every frame from it re-arms it.
    let silence = tokio::time::sleep(keepalive.dead_after);
    tokio::pin!(silence);
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
                // Any frame of the relay shows it is alive, not only a pong.
                silence
                    .as_mut()
                    .reset(tokio::time::Instant::now() + keepalive.dead_after);
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
            _ = &mut silence => {
                // Dropping the socket tears it down; `run` reconnects after its backoff.
                return Err(format!(
                    "no frame from the relay for {} s",
                    keepalive.dead_after.as_secs_f32()
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio::time::Instant;

    #[test]
    fn keepalive_is_what_the_spec_requires() {
        // PNP-001-MUST-065 / MUST-066.
        assert_eq!(KEEPALIVE.ping_every, Duration::from_secs(20));
        assert_eq!(KEEPALIVE.dead_after, Duration::from_secs(40));
    }

    /// What the test relay saw.
    #[derive(Default)]
    struct Seen {
        connections: AtomicUsize,
        pings: AtomicUsize,
    }

    /// A relay that registers every client without a challenge and answers pings while
    /// `answering` is set; when it is not, the socket stays open and silent.
    async fn relay(answering: Arc<AtomicBool>) -> (String, Arc<Seen>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Seen::default());
        let counters = seen.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (answering, seen) = (answering.clone(), counters.clone());
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                        return;
                    };
                    seen.connections.fetch_add(1, Ordering::SeqCst);
                    while let Some(Ok(msg)) = ws.next().await {
                        let Message::Text(text) = msg else { continue };
                        let reply = if text.contains("\"register\"") {
                            r#"{"type":"registered","peer_id":"00"}"#
                        } else if text.contains("\"ping\"") {
                            seen.pings.fetch_add(1, Ordering::SeqCst);
                            r#"{"type":"pong"}"#
                        } else {
                            continue;
                        };
                        if answering.load(Ordering::SeqCst) {
                            let _ = ws.send(Message::Text(reply.into())).await;
                        }
                    }
                });
            }
        });
        (url, seen)
    }

    fn client(
        url: String,
        keepalive: Keepalive,
    ) -> (
        mpsc::UnboundedReceiver<SigEvent>,
        mpsc::UnboundedSender<ClientFrame>,
        tokio::task::JoinHandle<()>,
    ) {
        let (events_tx, events) = mpsc::unbounded_channel();
        let (tx, rx) = mpsc::unbounded_channel();
        let signer: Signer = Arc::new(|_| [0u8; 64]);
        let task = tokio::spawn(run(
            url,
            "00".repeat(32),
            "00".repeat(32),
            signer,
            events_tx,
            rx,
            keepalive,
        ));
        (events, tx, task)
    }

    async fn next_event(events: &mut mpsc::UnboundedReceiver<SigEvent>) -> SigEvent {
        tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("an event in time")
            .expect("the signaling task is running")
    }

    const FAST: Keepalive = Keepalive {
        ping_every: Duration::from_millis(100),
        dead_after: Duration::from_millis(400),
    };

    #[tokio::test]
    async fn pings_on_schedule_and_stays_up_while_the_relay_answers() {
        let (url, seen) = relay(Arc::new(AtomicBool::new(true))).await;
        let (mut events, _tx, task) = client(url, FAST);
        assert!(matches!(
            next_event(&mut events).await,
            SigEvent::Connecting
        ));
        assert!(matches!(
            next_event(&mut events).await,
            SigEvent::Registered { .. }
        ));

        // Several times the silence limit: the pongs keep the socket alive.
        tokio::time::sleep(FAST.dead_after * 4).await;
        assert!(
            events.try_recv().is_err(),
            "no disconnect while pongs arrive"
        );
        assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
        // 1.6 s at one ping per 100 ms; wide bounds for a loaded machine.
        let pings = seen.pings.load(Ordering::SeqCst);
        assert!((8..=17).contains(&pings), "{pings} pings in 1.6 s");
        task.abort();
    }

    #[tokio::test]
    async fn silent_relay_is_dropped_and_reconnected() {
        let answering = Arc::new(AtomicBool::new(true));
        let (url, seen) = relay(answering.clone()).await;
        let (mut events, _tx, task) = client(url, FAST);
        assert!(matches!(
            next_event(&mut events).await,
            SigEvent::Connecting
        ));
        assert!(matches!(
            next_event(&mut events).await,
            SigEvent::Registered { .. }
        ));

        // The relay stops sending but keeps the socket open: no error, no close.
        tokio::time::sleep(FAST.ping_every * 3 / 2).await;
        answering.store(false, Ordering::SeqCst);
        let silent_from = Instant::now();
        match next_event(&mut events).await {
            SigEvent::Disconnected { reason } => {
                assert!(reason.starts_with("no frame from the relay"), "{reason}")
            }
            other => panic!("expected a disconnect, got {other:?}"),
        }
        let waited = silent_from.elapsed();
        // Its last frame came at most one ping interval before it went silent, so the limit
        // runs out between `dead_after - ping_every` and `dead_after` from here (bounds
        // widened for a loaded machine).
        assert!(
            waited >= FAST.dead_after / 2 && waited < FAST.dead_after * 3,
            "declared dead after {waited:?}"
        );

        // Reconnects after the backoff, on a new socket.
        answering.store(true, Ordering::SeqCst);
        assert!(matches!(
            next_event(&mut events).await,
            SigEvent::Connecting
        ));
        assert!(matches!(
            next_event(&mut events).await,
            SigEvent::Registered { .. }
        ));
        assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
        task.abort();
    }

    #[tokio::test]
    async fn any_relay_frame_counts_as_life() {
        // The relay never answers pings, but pushes another frame now and then.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let registered = r#"{"type":"registered","peer_id":"00"}"#;
            loop {
                if ws.send(Message::Text(registered.into())).await.is_err() {
                    return;
                }
                tokio::time::sleep(FAST.dead_after / 2).await;
            }
        });
        let (mut events, _tx, task) = client(url, FAST);
        let until = Instant::now() + FAST.dead_after * 3;
        while let Ok(event) = tokio::time::timeout_at(until, events.recv()).await {
            assert!(
                !matches!(event, Some(SigEvent::Disconnected { .. }) | None),
                "dropped a relay that was sending frames"
            );
        }
        task.abort();
    }
}
