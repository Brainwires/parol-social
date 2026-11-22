//! The relay WebSocket client: connects, registers by Ed25519 challenge, keeps the socket
//! alive and reconnects with backoff. The answer to the challenge is signed for the relay
//! this client dialed (PNP-001 §10.7), so it is of no use at any other relay. It forwards every relay frame to the app core and
//! sends the frames the core gives it. Signaling frames are never queued here: a frame given
//! while the socket is down is dropped (the core retries at its own level).

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Notify, mpsc};
use tokio_tungstenite::tungstenite::Message;

use parolnet_protocol::relay_auth::{REGISTER_NONCE_LEN, RelayName, register_signable};

use crate::wire::{ClientFrame, ServerFrame};

/// Signs a message with the identity key. The signaling task gives it the register message
/// of PNP-001 §10.7 (label, the relay's nonce, the relay's name), never a bare nonce.
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
/// After a nudge (the network changed) the relay has this long to send anything, a pong to
/// the ping sent at once included, before the socket is taken for dead.
const NUDGE_DEAD_AFTER: Duration = Duration::from_secs(6);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// The reconnect delay: doubles from `BACKOFF_MIN` to `BACKOFF_MAX` while attempts fail and
/// starts over once a socket got registered.
struct Backoff {
    next: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self { next: BACKOFF_MIN }
    }

    /// How long to wait before the next attempt, given whether the socket that just ended
    /// got registered. A registration proves the relay is reachable, however the socket
    /// ended afterwards (a close, an error, the silence limit), so the delay starts over.
    fn delay_after(&mut self, registered: bool) -> Duration {
        if registered {
            self.next = BACKOFF_MIN;
        }
        let delay = self.next;
        self.next = (delay * 2).min(BACKOFF_MAX);
        delay
    }
}

pub struct SigHandle {
    tx: mpsc::UnboundedSender<ClientFrame>,
    nudge: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl SigHandle {
    pub fn send(&self, frame: ClientFrame) {
        let _ = self.tx.send(frame);
    }

    /// The network changed: reconnect now when the socket is down (instead of waiting out
    /// the backoff), and when it looks up, find out quickly whether it still is (a ping at
    /// once, and a short wait for anything from the relay).
    pub fn nudge(&self) {
        self.nudge.notify_one();
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
    let nudge = Arc::new(Notify::new());
    let task = tokio::spawn(run(
        url,
        peer_id,
        public_key_hex,
        signer,
        events,
        rx,
        KEEPALIVE,
        nudge.clone(),
    ));
    SigHandle { tx, nudge, task }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    url: String,
    peer_id: String,
    public_key_hex: String,
    signer: Signer,
    events: mpsc::UnboundedSender<SigEvent>,
    mut outgoing: mpsc::UnboundedReceiver<ClientFrame>,
    keepalive: Keepalive,
    nudge: Arc<Notify>,
) {
    let mut backoff = Backoff::new();
    loop {
        let _ = events.send(SigEvent::Connecting);
        let mut registered = false;
        let reason = match session(
            &url,
            &peer_id,
            &public_key_hex,
            &signer,
            &events,
            &mut outgoing,
            keepalive,
            &nudge,
            &mut registered,
        )
        .await
        {
            Ok(()) => "closed".to_owned(),
            Err(e) => e,
        };
        let delay = backoff.delay_after(registered);
        if events
            .send(SigEvent::Disconnected {
                reason: reason.clone(),
            })
            .is_err()
        {
            return;
        }
        tracing::debug!(%reason, ?delay, "relay socket down; reconnecting");
        // Drop frames given while down: signaling is never queued.
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                // The network is back: try now, and start the backoff over.
                _ = nudge.notified() => {
                    backoff = Backoff::new();
                    break;
                }
                f = outgoing.recv() => if f.is_none() { return },
            }
        }
    }
}

/// One socket's life. `registered` is set as soon as the relay registers the socket, so the
/// caller knows it however the socket ends.
#[allow(clippy::too_many_arguments)]
async fn session(
    url: &str,
    peer_id: &str,
    public_key_hex: &str,
    signer: &Signer,
    events: &mpsc::UnboundedSender<SigEvent>,
    outgoing: &mut mpsc::UnboundedReceiver<ClientFrame>,
    keepalive: Keepalive,
    nudge: &Notify,
    registered: &mut bool,
) -> Result<(), String> {
    crate::install_crypto_provider();
    // The name of the relay this socket goes to, from the URL it is opened with. The
    // challenge answer is signed for it and for no other relay.
    let relay_name = RelayName::from_url(url).map_err(|e| format!("relay URL: {e}"))?;
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
        relay: None,
    }))
    .await
    .map_err(|e| format!("send: {e}"))?;

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
                    None => return Ok(()),
                };
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Close(_) => return Ok(()),
                    _ => continue,
                };
                // Any frame of the relay shows it is alive, not only a pong.
                silence
                    .as_mut()
                    .reset(tokio::time::Instant::now() + keepalive.dead_after);
                let Some(frame) = ServerFrame::parse(&text) else { continue };
                match frame {
                    ServerFrame::Challenge { nonce } => {
                        // A challenge that is not a 32-byte nonce is not answered: the
                        // identity key signs the register message and nothing else here.
                        let Some(nonce_bytes) = hex::decode(&nonce)
                            .ok()
                            .and_then(|b| <[u8; REGISTER_NONCE_LEN]>::try_from(b).ok())
                        else {
                            continue;
                        };
                        let sig = signer(&register_signable(&nonce_bytes, &relay_name, None));
                        sink.send(send(&ClientFrame::Register {
                            peer_id: peer_id.to_owned(),
                            pubkey: Some(public_key_hex.to_owned()),
                            signature: Some(hex::encode(sig)),
                            nonce: Some(nonce),
                            relay: Some(relay_name.as_str().to_owned()),
                        }))
                        .await
                        .map_err(|e| format!("send: {e}"))?;
                    }
                    ServerFrame::Registered { profile, .. } => {
                        *registered = true;
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
                let Some(frame) = frame else { return Ok(()) };
                // Only register / ping may precede registration (PNP-001 §10.6).
                if !*registered && !matches!(frame, ClientFrame::Ping { .. }) {
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
            _ = nudge.notified() => {
                // The network changed under a socket that looks alive: ask, and do not wait
                // the full keepalive for the answer.
                sink.send(send(&ClientFrame::Ping { ts: crate::now_ms() }))
                    .await
                    .map_err(|e| format!("send: {e}"))?;
                let soon = tokio::time::Instant::now()
                    + NUDGE_DEAD_AFTER.min(keepalive.dead_after);
                if soon < silence.deadline() {
                    silence.as_mut().reset(soon);
                }
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
        (url, relay_on(listener, answering))
    }

    fn relay_on(listener: TcpListener, answering: Arc<AtomicBool>) -> Arc<Seen> {
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
        seen
    }

    fn client(
        url: String,
        keepalive: Keepalive,
    ) -> (
        mpsc::UnboundedReceiver<SigEvent>,
        mpsc::UnboundedSender<ClientFrame>,
        tokio::task::JoinHandle<()>,
    ) {
        let (events, tx, task, _) = nudgeable_client(url, keepalive);
        (events, tx, task)
    }

    fn nudgeable_client(
        url: String,
        keepalive: Keepalive,
    ) -> (
        mpsc::UnboundedReceiver<SigEvent>,
        mpsc::UnboundedSender<ClientFrame>,
        tokio::task::JoinHandle<()>,
        Arc<Notify>,
    ) {
        let (events_tx, events) = mpsc::unbounded_channel();
        let (tx, rx) = mpsc::unbounded_channel();
        let signer: Signer = Arc::new(|_| [0u8; 64]);
        let nudge = Arc::new(Notify::new());
        let task = tokio::spawn(run(
            url,
            "00".repeat(32),
            "00".repeat(32),
            signer,
            events_tx,
            rx,
            keepalive,
            nudge.clone(),
        ));
        (events, tx, task, nudge)
    }

    /// A network change does not wait out the reconnect backoff, and a socket that looks
    /// alive is checked at once.
    #[tokio::test]
    async fn a_nudge_reconnects_now_and_checks_a_live_socket() {
        // Nobody listens: attempts fail and the backoff grows (1 s, 2 s, 4 s).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (mut events, _tx, task, nudge) = nudgeable_client(format!("ws://{addr}"), FAST);
        let mut failed = 0;
        while failed < 3 {
            if matches!(next_event(&mut events).await, SigEvent::Disconnected { .. }) {
                failed += 1;
            }
        }
        // The next attempt is 4 s away. The relay comes back and the network says so.
        let answering = Arc::new(AtomicBool::new(true));
        let seen = relay_on(TcpListener::bind(addr).await.unwrap(), answering.clone());
        let nudged = Instant::now();
        nudge.notify_one();
        loop {
            if matches!(next_event(&mut events).await, SigEvent::Registered { .. }) {
                break;
            }
        }
        assert!(
            nudged.elapsed() < Duration::from_secs(2),
            "registered {:?} after the nudge",
            nudged.elapsed()
        );

        // Registered and quiet. A nudge sends a ping at once.
        let before = seen.pings.load(Ordering::SeqCst);
        nudge.notify_one();
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(seen.pings.load(Ordering::SeqCst) > before);
        task.abort();
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

    /// PNP-001 §10.7: the answer to a challenge is the identity key's signature over the
    /// register message, which names the relay the client dialed. A relay that passes on
    /// another relay's nonce gets a signature the other relay refuses.
    #[tokio::test]
    async fn the_challenge_answer_is_signed_for_the_relay_that_was_dialed() {
        use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let nonce = [0x5a_u8; REGISTER_NONCE_LEN];
        let (answer_tx, mut answer_rx) = mpsc::unbounded_channel::<serde_json::Value>();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            // The plain register, then the challenges; every later frame is reported.
            let _ = ws.next().await;
            // Not a 32-byte nonce: must not be signed.
            let _ = ws
                .send(Message::Text(
                    r#"{"type":"challenge","nonce":"abcd"}"#.into(),
                ))
                .await;
            let challenge = format!(r#"{{"type":"challenge","nonce":"{}"}}"#, hex::encode(nonce));
            let _ = ws.send(Message::Text(challenge.into())).await;
            while let Some(Ok(Message::Text(text))) = ws.next().await {
                let _ = answer_tx.send(serde_json::from_str(&text).unwrap());
            }
        });

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let public = key.verifying_key();
        let signer: Signer = Arc::new(move |m| key.sign(m).to_bytes());
        let (events_tx, _events) = mpsc::unbounded_channel();
        let (_tx, rx) = mpsc::unbounded_channel();
        // Dialed with a path and a query: the name is the host and port alone.
        let task = tokio::spawn(run(
            format!("ws://{addr}/ws?probe=1"),
            "00".repeat(32),
            hex::encode(public.to_bytes()),
            signer,
            events_tx,
            rx,
            FAST,
            Arc::new(Notify::new()),
        ));

        let answer = tokio::time::timeout(Duration::from_secs(10), answer_rx.recv())
            .await
            .expect("an answer in time")
            .expect("the relay task is running");
        assert_eq!(answer["type"], "register");
        // The first frame after the challenges answers the 32-byte nonce: the short one
        // was skipped.
        assert_eq!(answer["nonce"], hex::encode(nonce));
        let name = addr.to_string();
        assert_eq!(answer["relay"], name);
        let signature: [u8; 64] = hex::decode(answer["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&signature);
        let relay = RelayName::parse(&name).unwrap();
        public
            .verify(&register_signable(&nonce, &relay, None), &signature)
            .expect("signed over the register message for the dialed relay");
        // Not valid for another relay, and not a signature over the bare nonce.
        let other = RelayName::parse("relay-r.example:443").unwrap();
        assert!(
            public
                .verify(&register_signable(&nonce, &other, None), &signature)
                .is_err()
        );
        assert!(public.verify(&nonce, &signature).is_err());
        task.abort();
    }

    /// A relay URL without a usable relay name is never dialed: there would be nothing to
    /// sign the answer for.
    #[tokio::test]
    async fn a_url_without_a_relay_name_is_refused_before_connecting() {
        let (mut events, _tx, task) = client("ws://user@127.0.0.1:1/ws".to_owned(), FAST);
        assert!(matches!(
            next_event(&mut events).await,
            SigEvent::Connecting
        ));
        match next_event(&mut events).await {
            SigEvent::Disconnected { reason } => {
                assert!(reason.starts_with("relay URL:"), "{reason}")
            }
            other => panic!("expected a disconnect, got {other:?}"),
        }
        task.abort();
    }

    #[test]
    fn backoff_doubles_while_attempts_fail_and_starts_over_after_a_registration() {
        let secs = |b: &mut Backoff, registered| b.delay_after(registered).as_secs();
        let mut backoff = Backoff::new();
        // The relay cannot be reached: 1, 2, 4, ... up to the maximum.
        let failing: Vec<u64> = (0..7).map(|_| secs(&mut backoff, false)).collect();
        assert_eq!(failing, [1, 2, 4, 8, 16, 30, 30]);
        // A socket that got registered: the minimum again, however it ended.
        assert_eq!(secs(&mut backoff, true), 1);
        assert_eq!(secs(&mut backoff, false), 2);
        // A long-lived client whose registered sockets keep ending never drifts upwards.
        for _ in 0..50 {
            assert_eq!(backoff.delay_after(true), BACKOFF_MIN);
        }
    }

    #[tokio::test]
    async fn registered_socket_that_ends_in_an_error_reconnects_at_the_minimum_backoff() {
        // The relay registers every client and then drops the TCP connection without a
        // WebSocket close: the client's read fails.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                    continue;
                };
                let registered = r#"{"type":"registered","peer_id":"00"}"#;
                let _ = ws.next().await;
                let _ = ws.send(Message::Text(registered.into())).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        let (mut events, _tx, task) = client(url, FAST);

        async fn registered_then_failed(events: &mut mpsc::UnboundedReceiver<SigEvent>) {
            assert!(matches!(
                next_event(events).await,
                SigEvent::Registered { .. }
            ));
            match next_event(events).await {
                SigEvent::Disconnected { reason } => {
                    assert_ne!(reason, "closed", "the socket must end in an error")
                }
                other => panic!("expected a disconnect, got {other:?}"),
            }
        }

        // Three sockets in a row get registered and end in an error. Doubling would wait
        // 1 s and then 2 s; a registration resets it, so both waits are the minimum.
        assert!(matches!(
            next_event(&mut events).await,
            SigEvent::Connecting
        ));
        registered_then_failed(&mut events).await;
        for round in 0..2 {
            let down_from = Instant::now();
            assert!(matches!(
                next_event(&mut events).await,
                SigEvent::Connecting
            ));
            let waited = down_from.elapsed();
            assert!(
                waited >= BACKOFF_MIN * 9 / 10 && waited < BACKOFF_MIN * 17 / 10,
                "round {round}: reconnected after {waited:?}"
            );
            registered_then_failed(&mut events).await;
        }
        task.abort();
    }
}
