//! The relay WebSocket client: connects, registers by Ed25519 challenge, keeps the socket
//! alive and reconnects with backoff. It forwards every relay frame to the app core and
//! sends the frames the core gives it. Signaling frames are never queued here: a frame given
//! while the socket is down is dropped (the core retries at its own level).

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Notify, mpsc};
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
/// After a nudge (the network changed) the relay has this long to send anything, a pong to
/// the ping sent at once included, before the socket is taken for dead.
const NUDGE_DEAD_AFTER: Duration = Duration::from_secs(6);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// After a connection to the relay ended, the next one is not opened before this long has
/// passed (PNP-006-MUST-024): no rapid connect / disconnect pattern on the wire.
const RECONNECT_WAIT: Duration = Duration::from_secs(30);

/// The timing of the relay socket.
#[derive(Clone, Copy, Debug)]
struct Timing {
    keepalive: Keepalive,
    /// See [`RECONNECT_WAIT`].
    reconnect_wait: Duration,
}

const TIMING: Timing = Timing {
    keepalive: KEEPALIVE,
    reconnect_wait: RECONNECT_WAIT,
};

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
    stop: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl SigHandle {
    pub fn send(&self, frame: ClientFrame) {
        let _ = self.tx.send(frame);
    }

    /// The network changed: when the socket is down, reconnect without waiting out the
    /// backoff (the wait after a disconnect, PNP-006-MUST-024, still applies), and when it
    /// looks up, find out quickly whether it still is (a ping at once, and a short wait for
    /// anything from the relay).
    pub fn nudge(&self) {
        self.nudge.notify_one();
    }

    /// Close the relay socket properly (the WebSocket close, then TLS `close_notify`,
    /// PNP-006-MUST-026) and end the task. Bounded: an unresponsive relay is not waited for.
    pub async fn stop(&mut self) {
        self.stop.notify_one();
        if tokio::time::timeout(STOP_TIMEOUT, &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
        }
    }
}

/// How long [`SigHandle::stop`] waits for the task to close its socket.
const STOP_TIMEOUT: Duration = Duration::from_secs(4);

pub fn spawn(
    url: String,
    trust_anchors: Vec<Vec<u8>>,
    peer_id: String,
    public_key_hex: String,
    signer: Signer,
    events: mpsc::UnboundedSender<SigEvent>,
) -> SigHandle {
    let (tx, rx) = mpsc::unbounded_channel();
    let nudge = Arc::new(Notify::new());
    let stop = Arc::new(Notify::new());
    let task = tokio::spawn(run(
        Target {
            url,
            trust_anchors,
            peer_id,
            public_key_hex,
            signer,
        },
        events,
        rx,
        TIMING,
        nudge.clone(),
        stop.clone(),
    ));
    SigHandle {
        tx,
        nudge,
        stop,
        task,
    }
}

/// The relay and who we are to it.
struct Target {
    url: String,
    /// Extra TLS trust anchors for the relay's certificate (DER).
    trust_anchors: Vec<Vec<u8>>,
    peer_id: String,
    public_key_hex: String,
    signer: Signer,
}

/// How one socket ended.
enum End {
    /// The socket is gone (closed by the relay, an error, the silence limit).
    Down(String),
    /// We were asked to stop; the socket was closed properly.
    Stopped,
}

async fn run(
    target: Target,
    events: mpsc::UnboundedSender<SigEvent>,
    mut outgoing: mpsc::UnboundedReceiver<ClientFrame>,
    timing: Timing,
    nudge: Arc<Notify>,
    stop: Arc<Notify>,
) {
    let mut backoff = Backoff::new();
    loop {
        let _ = events.send(SigEvent::Connecting);
        let mut registered = false;
        let mut connected = false;
        let end = session(
            &target,
            &events,
            &mut outgoing,
            timing.keepalive,
            &nudge,
            &stop,
            &mut registered,
            &mut connected,
        )
        .await;
        let reason = match end {
            End::Stopped => return,
            End::Down(reason) => reason,
        };
        let ended = tokio::time::Instant::now();
        // A connection that existed is not replaced before `reconnect_wait` has passed,
        // whatever asks for it (PNP-006-MUST-024). An attempt that never connected left
        // nothing on the wire to wait for.
        let earliest = if connected {
            ended + timing.reconnect_wait
        } else {
            ended
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
        let sleep = tokio::time::sleep_until((ended + delay).max(earliest));
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                // The network is back: start the backoff over and try as soon as the wait
                // after a disconnect allows.
                _ = nudge.notified() => {
                    backoff = Backoff::new();
                    sleep.as_mut().reset(earliest);
                }
                _ = stop.notified() => return,
                f = outgoing.recv() => if f.is_none() { return },
            }
        }
    }
}

/// One socket's life. `connected` is set once the connection to the relay exists and
/// `registered` as soon as the relay registers the socket, so the caller knows both however
/// the socket ends.
///
/// The socket is never closed here for its age: it lives until the relay or the network
/// ends it or the app stops (PNP-006-MUST-022 / MUST-023).
#[allow(clippy::too_many_arguments)]
async fn session(
    target: &Target,
    events: &mpsc::UnboundedSender<SigEvent>,
    outgoing: &mut mpsc::UnboundedReceiver<ClientFrame>,
    keepalive: Keepalive,
    nudge: &Notify,
    stop: &Notify,
    registered: &mut bool,
    connected: &mut bool,
) -> End {
    crate::install_crypto_provider();
    let connect = tokio::time::timeout(
        Duration::from_secs(15),
        crate::relay_socket::connect(&target.url, &target.trust_anchors),
    );
    let mut ws = tokio::select! {
        r = connect => match r {
            Err(_) => return End::Down("connect timed out".to_owned()),
            Ok(Err(e)) => return End::Down(e),
            Ok(Ok(ws)) => ws,
        },
        _ = stop.notified() => return End::Stopped,
    };
    *connected = true;
    match serve(
        &mut ws, target, events, outgoing, keepalive, nudge, stop, registered,
    )
    .await
    {
        Ok(true) => {
            crate::relay_socket::close(ws).await;
            End::Stopped
        }
        Ok(false) => End::Down("closed".to_owned()),
        // Dropping the socket tears it down; `run` reconnects after its wait.
        Err(reason) => End::Down(reason),
    }
}

/// Register and carry frames until the socket ends. `Ok(true)`: we were asked to stop and
/// the socket is still open; `Ok(false)`: the relay closed it.
#[allow(clippy::too_many_arguments)]
async fn serve(
    ws: &mut crate::relay_socket::RelaySocket,
    target: &Target,
    events: &mpsc::UnboundedSender<SigEvent>,
    outgoing: &mut mpsc::UnboundedReceiver<ClientFrame>,
    keepalive: Keepalive,
    nudge: &Notify,
    stop: &Notify,
    registered: &mut bool,
) -> Result<bool, String> {
    let (peer_id, public_key_hex, signer) =
        (&target.peer_id, &target.public_key_hex, &target.signer);
    let send = |frame: &ClientFrame| Message::Text(frame.to_json().into());
    ws.send(send(&ClientFrame::Register {
        peer_id: peer_id.to_owned(),
        pubkey: None,
        signature: None,
        nonce: None,
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
            msg = ws.next() => {
                let msg = match msg {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => return Err(format!("read: {e}")),
                    None => return Ok(false),
                };
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Close(_) => return Ok(false),
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
                        ws.send(send(&ClientFrame::Register {
                            peer_id: peer_id.to_owned(),
                            pubkey: Some(public_key_hex.to_owned()),
                            signature: Some(hex::encode(sig)),
                            nonce: Some(nonce),
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
                // The core is gone: close as on a stop.
                let Some(frame) = frame else { return Ok(true) };
                // Only register / ping may precede registration (PNP-001 §10.6).
                if !*registered && !matches!(frame, ClientFrame::Ping { .. }) {
                    tracing::debug!("dropping a frame given before registration");
                    continue;
                }
                ws.send(send(&frame)).await.map_err(|e| format!("send: {e}"))?;
            }
            _ = ping.tick() => {
                ws.send(send(&ClientFrame::Ping { ts: crate::now_ms() }))
                    .await
                    .map_err(|e| format!("send: {e}"))?;
            }
            _ = nudge.notified() => {
                // The network changed under a socket that looks alive: ask, and do not wait
                // the full keepalive for the answer.
                ws.send(send(&ClientFrame::Ping { ts: crate::now_ms() }))
                    .await
                    .map_err(|e| format!("send: {e}"))?;
                let soon = tokio::time::Instant::now()
                    + NUDGE_DEAD_AFTER.min(keepalive.dead_after);
                if soon < silence.deadline() {
                    silence.as_mut().reset(soon);
                }
            }
            _ = stop.notified() => return Ok(true),
            _ = &mut silence => {
                // An unresponsive relay is not owed a proper close.
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
        keepalive: Timing,
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
        timing: Timing,
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
            Target {
                url,
                trust_anchors: Vec::new(),
                peer_id: "00".repeat(32),
                public_key_hex: "00".repeat(32),
                signer,
            },
            events_tx,
            rx,
            timing,
            nudge.clone(),
            Arc::new(Notify::new()),
        ));
        (events, tx, task, nudge)
    }

    /// A network change does not wait out the reconnect backoff (nothing was connected, so
    /// there is no disconnect to wait after), and a socket that looks alive is checked at
    /// once.
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

    const FAST_KEEPALIVE: Keepalive = Keepalive {
        ping_every: Duration::from_millis(100),
        dead_after: Duration::from_millis(400),
    };
    /// Short enough for a test, long enough to tell from "at once".
    const FAST: Timing = Timing {
        keepalive: FAST_KEEPALIVE,
        reconnect_wait: Duration::from_millis(1500),
    };

    #[test]
    fn a_connection_is_not_replaced_within_30_seconds() {
        // PNP-006-MUST-024.
        assert_eq!(TIMING.reconnect_wait, Duration::from_secs(30));
    }

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
        tokio::time::sleep(FAST_KEEPALIVE.dead_after * 4).await;
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
        tokio::time::sleep(FAST_KEEPALIVE.ping_every * 3 / 2).await;
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
            waited >= FAST_KEEPALIVE.dead_after / 2 && waited < FAST_KEEPALIVE.dead_after * 3,
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
                tokio::time::sleep(FAST_KEEPALIVE.dead_after / 2).await;
            }
        });
        let (mut events, _tx, task) = client(url, FAST);
        let until = Instant::now() + FAST_KEEPALIVE.dead_after * 3;
        while let Ok(event) = tokio::time::timeout_at(until, events.recv()).await {
            assert!(
                !matches!(event, Some(SigEvent::Disconnected { .. }) | None),
                "dropped a relay that was sending frames"
            );
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

    /// PNP-006-MUST-024: a socket that existed is replaced no sooner than the reconnect wait
    /// after it ended, however it ended, and a network change does not shorten that.
    #[tokio::test]
    async fn a_socket_that_ended_is_replaced_after_the_reconnect_wait_even_when_nudged() {
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
        let (mut events, _tx, task, nudge) = nudgeable_client(url, FAST);

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

        assert!(matches!(
            next_event(&mut events).await,
            SigEvent::Connecting
        ));
        registered_then_failed(&mut events).await;
        for round in 0..2 {
            let down_from = Instant::now();
            // The second round is nudged at once: the wait still holds.
            if round == 1 {
                nudge.notify_one();
            }
            assert!(matches!(
                next_event(&mut events).await,
                SigEvent::Connecting
            ));
            let waited = down_from.elapsed();
            assert!(
                waited >= FAST.reconnect_wait * 9 / 10 && waited < FAST.reconnect_wait * 2,
                "round {round}: reconnected after {waited:?}"
            );
            registered_then_failed(&mut events).await;
        }
        task.abort();
    }

    /// PNP-006-MUST-026: asked to stop, the client closes the WebSocket properly instead of
    /// dropping the connection.
    #[tokio::test]
    async fn a_stop_closes_the_socket_with_a_close_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let registered = r#"{"type":"registered","peer_id":"00"}"#;
            let _ = ws.send(Message::Text(registered.into())).await;
            let mut close_frame = false;
            while let Some(Ok(msg)) = ws.next().await {
                close_frame |= matches!(msg, Message::Close(_));
            }
            let _ = closed_tx.send(close_frame);
        });
        let (events_tx, mut events) = mpsc::unbounded_channel();
        let signer: Signer = Arc::new(|_| [0u8; 64]);
        let mut handle = spawn(
            url,
            Vec::new(),
            "00".repeat(32),
            "00".repeat(32),
            signer,
            events_tx,
        );
        loop {
            if matches!(next_event(&mut events).await, SigEvent::Registered { .. }) {
                break;
            }
        }
        handle.stop().await;
        assert!(
            closed_rx.await.unwrap(),
            "the socket ended without a close frame"
        );
    }
}
