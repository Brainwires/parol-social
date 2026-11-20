//! Relay operating profile and the abuse controls that bound what one client
//! can make the relay hold or forward.
//!
//! Two profiles exist (see PNP-001 §"Signaling-only relay profile"):
//!
//! * **signaling-only** (the default): the relay only helps peers set up
//!   direct connections — registration, WebRTC SDP / ICE exchange between
//!   two online peers, presence, directory reads and STUN URIs. It accepts no
//!   `message` / `gossip` frames and no onion cells, keeps no mailbox, mints
//!   no tokens and hands out no TURN credentials. No user content ever
//!   transits or is stored on it.
//! * **relay**: the full feature set (mailbox, tokens, onion cells, gossip,
//!   TURN credentials, federation). An operator opts in with
//!   `SIGNALING_ONLY=0`.
//!
//! The connection controls (per-IP and global socket caps, registration
//! deadline, per-connection frame budget, registered PeerIds per IP) and the
//! signaling caps apply to both profiles.

use crate::rate_limit::RateLimiter;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Wire name of the signaling-only profile (`registered.profile`).
pub const PROFILE_SIGNALING_ONLY: &str = "signaling-only";
/// Wire name of the full relay profile (`registered.profile`).
pub const PROFILE_RELAY: &str = "relay";

/// WebSocket message cap on a signaling-only relay.
pub const SIGNALING_MAX_WS_MESSAGE_BYTES: usize = 32 * 1024;
/// WebSocket message cap on a relay-profile relay (a 16 KiB padded envelope
/// is 32 KiB as hex, plus the token and the JSON frame).
pub const RELAY_MAX_WS_MESSAGE_BYTES: usize = 128 * 1024;
/// Largest `payload` of an `rtc_offer` / `rtc_answer` frame.
pub const MAX_SDP_PAYLOAD_BYTES: usize = 16 * 1024;
/// Largest `payload` of an `rtc_ice` frame.
pub const MAX_ICE_PAYLOAD_BYTES: usize = 2 * 1024;
/// Signaling frames one registered sender may send per minute.
pub const SIGNAL_PER_MINUTE: u32 = 60;
/// Signaling frames one registered sender may send per hour.
pub const SIGNAL_PER_HOUR: u32 = 240;
/// Signaling frames per (sender, recipient) pair per 10 minutes.
pub const SIGNAL_PER_PAIR_10MIN: u32 = 64;
/// New WebSockets per client IP per minute.
pub const CONN_PER_MINUTE_PER_IP: u32 = 20;
/// Concurrent WebSockets per client IP.
pub const MAX_CONNS_PER_IP: usize = 8;
/// Concurrent WebSockets across all clients.
pub const MAX_CONNS_GLOBAL: usize = 5000;
/// Seconds a socket may stay open without completing registration.
pub const REGISTER_TIMEOUT_SECS: u64 = 10;
/// PeerIds registered at once from one client IP.
pub const MAX_PEERS_PER_IP: usize = 3;
/// Register frames (challenge requests and answers) one socket may send.
pub const MAX_REGISTER_ATTEMPTS: u32 = 4;
/// PeerIds one socket may watch for presence.
pub const MAX_WATCH_IDS: usize = 256;
/// Frames of any type one socket may send per minute (signaling-only).
pub const SIGNALING_FRAMES_PER_MINUTE: u32 = 120;
/// Frames of any type one socket may send per minute (relay profile; covers
/// cover traffic at one decoy per 500 ms plus real traffic).
pub const RELAY_FRAMES_PER_MINUTE: u32 = 600;
/// Onion circuits one socket may hold (relay profile).
pub const MAX_CIRCUITS_PER_CONN: usize = 64;
/// Token issuance requests per client IP per minute (relay profile).
pub const TOKEN_ISSUE_PER_MINUTE_PER_IP: u32 = 10;
/// Blinded elements accepted in one `/tokens/issue` request.
pub const MAX_TOKENS_PER_ISSUE: usize = 1024;

/// Frame types a signaling-only relay accepts on the client WebSocket.
pub const SIGNALING_FRAME_TYPES: &[&str] = &[
    "register",
    "ping",
    "rtc_offer",
    "rtc_answer",
    "rtc_ice",
    "watch",
];

/// Effective relay configuration, read once at startup.
#[derive(Clone, Debug)]
pub struct RelayPolicy {
    pub signaling_only: bool,
    pub max_ws_message_bytes: usize,
    pub max_sdp_payload_bytes: usize,
    pub max_ice_payload_bytes: usize,
    pub signal_per_minute: u32,
    pub signal_per_hour: u32,
    pub signal_per_pair_10min: u32,
    pub conn_per_minute_per_ip: u32,
    pub max_conns_per_ip: usize,
    pub max_conns_global: usize,
    pub register_timeout: Duration,
    pub max_peers_per_ip: usize,
    pub frames_per_minute: u32,
    /// STUN URIs served by `/turn-credentials` on a signaling-only relay.
    pub stun_uris: Vec<String>,
}

fn parse_bool_default_true(v: Option<String>) -> bool {
    match v {
        None => true,
        Some(s) => !matches!(
            s.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
    }
}

impl RelayPolicy {
    /// Build the policy from process environment variables.
    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok().filter(|s| !s.trim().is_empty()))
    }

    /// Build the policy from a key lookup (tests pass a map).
    ///
    /// `SIGNALING_ONLY` defaults to on; only `0`, `false`, `off` or `no`
    /// selects the relay profile.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let signaling_only = parse_bool_default_true(get("SIGNALING_ONLY"));
        let num = |k: &str, d: u64| -> u64 {
            get(k)
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(d)
        };
        let default_ws = if signaling_only {
            SIGNALING_MAX_WS_MESSAGE_BYTES
        } else {
            RELAY_MAX_WS_MESSAGE_BYTES
        };
        let default_frames = if signaling_only {
            SIGNALING_FRAMES_PER_MINUTE
        } else {
            RELAY_FRAMES_PER_MINUTE
        };
        let stun_uris = get("STUN_URIS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| s.starts_with("stun:") || s.starts_with("stuns:"))
            .collect();
        Self {
            signaling_only,
            max_ws_message_bytes: num("RELAY_MAX_WS_MESSAGE_BYTES", default_ws as u64) as usize,
            max_sdp_payload_bytes: MAX_SDP_PAYLOAD_BYTES,
            max_ice_payload_bytes: MAX_ICE_PAYLOAD_BYTES,
            signal_per_minute: num("RELAY_SIGNAL_PER_MINUTE", SIGNAL_PER_MINUTE as u64) as u32,
            signal_per_hour: num("RELAY_SIGNAL_PER_HOUR", SIGNAL_PER_HOUR as u64) as u32,
            signal_per_pair_10min: num("RELAY_SIGNAL_PER_PAIR_10MIN", SIGNAL_PER_PAIR_10MIN as u64)
                as u32,
            conn_per_minute_per_ip: num("RELAY_CONN_PER_MINUTE", CONN_PER_MINUTE_PER_IP as u64)
                as u32,
            max_conns_per_ip: num("RELAY_MAX_CONNS_PER_IP", MAX_CONNS_PER_IP as u64) as usize,
            max_conns_global: num("RELAY_MAX_CONNS", MAX_CONNS_GLOBAL as u64) as usize,
            register_timeout: Duration::from_secs(num(
                "RELAY_REGISTER_TIMEOUT_SECS",
                REGISTER_TIMEOUT_SECS,
            )),
            max_peers_per_ip: num("RELAY_MAX_PEERS_PER_IP", MAX_PEERS_PER_IP as u64) as usize,
            frames_per_minute: num("RELAY_FRAMES_PER_MINUTE", default_frames as u64) as u32,
            stun_uris,
        }
    }

    /// Wire name of the active profile.
    pub fn profile(&self) -> &'static str {
        if self.signaling_only {
            PROFILE_SIGNALING_ONLY
        } else {
            PROFILE_RELAY
        }
    }

    /// Whether a client frame type is accepted under this profile.
    pub fn frame_type_allowed(&self, msg_type: &str) -> bool {
        !self.signaling_only || SIGNALING_FRAME_TYPES.contains(&msg_type)
    }

    /// Admission check for a client text frame, applied before any
    /// handling: the profile's type whitelist, then registration (an
    /// unregistered socket may send only `register` and `ping`). Returns the
    /// wire error code on refusal.
    pub fn admit_frame(&self, registered: bool, msg_type: &str) -> Result<(), &'static str> {
        if !self.frame_type_allowed(msg_type) {
            return Err("signaling_only");
        }
        if !registered && !matches!(msg_type, "register" | "ping") {
            return Err("not_registered");
        }
        Ok(())
    }

    /// Admission check for a binary frame (onion cell). A signaling-only
    /// relay closes the socket; a relay-profile relay requires
    /// registration.
    pub fn admit_binary(&self, registered: bool) -> BinaryAdmission {
        if self.signaling_only {
            BinaryAdmission::Close
        } else if !registered {
            BinaryAdmission::Refuse("not_registered")
        } else {
            BinaryAdmission::Accept
        }
    }

    /// Full admission for a signaling frame from a registered `sender`:
    /// payload cap, recipient online (never queued), then the rate limits.
    pub fn admit_signal(
        &self,
        limiter: &SignalingLimiter,
        sender: &str,
        recipient: &str,
        recipient_online: bool,
        msg_type: &str,
        payload: &str,
    ) -> Result<(), SignalReject> {
        self.check_signal_payload(msg_type, payload)?;
        if !recipient_online {
            return Err(SignalReject::PeerOffline);
        }
        limiter.check(sender, recipient)
    }

    /// Check a signaling payload against the per-type size cap.
    pub fn check_signal_payload(&self, msg_type: &str, payload: &str) -> Result<(), SignalReject> {
        let cap = match msg_type {
            "rtc_ice" => self.max_ice_payload_bytes,
            _ => self.max_sdp_payload_bytes,
        };
        if payload.len() > cap {
            Err(SignalReject::PayloadTooLarge)
        } else {
            Ok(())
        }
    }
}

/// What to do with a binary frame, see [`RelayPolicy::admit_binary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryAdmission {
    Accept,
    Refuse(&'static str),
    Close,
}

/// Why a signaling frame was refused. `code()` is the wire error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalReject {
    PayloadTooLarge,
    RateLimited,
    PeerOffline,
}

impl SignalReject {
    pub fn code(self) -> &'static str {
        match self {
            SignalReject::PayloadTooLarge => "payload_too_large",
            SignalReject::RateLimited => "rate_limited",
            SignalReject::PeerOffline => "peer_offline",
        }
    }
}

/// Per-sender and per-pair signaling rate limits (PNP-001 signaling-only
/// profile). Keys are hex PeerIds of registered sockets.
pub struct SignalingLimiter {
    per_minute: RateLimiter<String>,
    per_hour: RateLimiter<String>,
    per_pair: RateLimiter<(String, String)>,
}

impl SignalingLimiter {
    pub fn new(policy: &RelayPolicy) -> Self {
        Self {
            per_minute: RateLimiter::new(policy.signal_per_minute, 60),
            per_hour: RateLimiter::new(policy.signal_per_hour, 3600),
            per_pair: RateLimiter::new(policy.signal_per_pair_10min, 600),
        }
    }

    /// Count one signaling frame from `sender` to `recipient`. Returns
    /// `Err(RateLimited)` when any of the three budgets is spent.
    pub fn check(&self, sender: &str, recipient: &str) -> Result<(), SignalReject> {
        let s = sender.to_string();
        // Evaluate all three so a limited sender keeps counting against each
        // window; any one exhausted budget refuses the frame.
        let m = self.per_minute.is_limited(&s);
        let h = self.per_hour.is_limited(&s);
        let p = self.per_pair.is_limited(&(s, recipient.to_string()));
        if m || h || p {
            Err(SignalReject::RateLimited)
        } else {
            Ok(())
        }
    }

    pub fn cleanup(&self) {
        self.per_minute.cleanup();
        self.per_hour.cleanup();
        self.per_pair.cleanup();
    }
}

/// Counting semaphore keyed by client IP with an optional global ceiling.
/// A [`SlotGuard`] releases its slot on drop, so a socket task that ends for
/// any reason (close, error, panic unwind) gives its slot back.
pub struct IpSlots {
    inner: Arc<IpSlotsInner>,
}

struct IpSlotsInner {
    per_ip: std::sync::Mutex<HashMap<IpAddr, usize>>,
    total: AtomicUsize,
    max_per_ip: usize,
    max_total: usize,
}

/// Held for as long as the slot is in use.
pub struct SlotGuard {
    inner: Arc<IpSlotsInner>,
    ip: IpAddr,
}

impl IpSlots {
    /// `max_total == usize::MAX` means no global ceiling.
    pub fn new(max_per_ip: usize, max_total: usize) -> Self {
        Self {
            inner: Arc::new(IpSlotsInner {
                per_ip: std::sync::Mutex::new(HashMap::new()),
                total: AtomicUsize::new(0),
                max_per_ip,
                max_total,
            }),
        }
    }

    /// Take a slot for `ip`, or `None` when the IP or the global cap is full.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<SlotGuard> {
        let mut map = self.inner.per_ip.lock().unwrap();
        let count = map.get(&ip).copied().unwrap_or(0);
        if count >= self.inner.max_per_ip {
            return None;
        }
        if self.inner.total.load(Ordering::SeqCst) >= self.inner.max_total {
            return None;
        }
        map.insert(ip, count + 1);
        self.inner.total.fetch_add(1, Ordering::SeqCst);
        Some(SlotGuard {
            inner: self.inner.clone(),
            ip,
        })
    }

    /// Slots in use for `ip`.
    pub fn in_use(&self, ip: IpAddr) -> usize {
        self.inner
            .per_ip
            .lock()
            .unwrap()
            .get(&ip)
            .copied()
            .unwrap_or(0)
    }

    /// Slots in use across all IPs.
    pub fn total(&self) -> usize {
        self.inner.total.load(Ordering::SeqCst)
    }

    /// Number of distinct IPs holding a slot (map entries are dropped at 0).
    pub fn tracked_ips(&self) -> usize {
        self.inner.per_ip.lock().unwrap().len()
    }
}

impl Clone for IpSlots {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut map = self.inner.per_ip.lock().unwrap();
        if let Some(c) = map.get_mut(&self.ip) {
            *c -= 1;
            if *c == 0 {
                map.remove(&self.ip);
            }
        }
        self.inner.total.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Fixed-window frame budget for one socket. Applies to every frame,
/// registered or not.
pub struct FrameBudget {
    window_start: Instant,
    count: u32,
    max: u32,
    window: Duration,
    warned: bool,
}

/// Outcome of [`FrameBudget::take`].
#[derive(Debug, PartialEq, Eq)]
pub enum Budget {
    /// Frame accepted.
    Ok,
    /// Frame refused; tell the client once per window.
    LimitedNotify,
    /// Frame refused silently (already told this window).
    Limited,
}

impl FrameBudget {
    pub fn new(max_per_minute: u32) -> Self {
        Self::with_window(max_per_minute, Duration::from_secs(60))
    }

    pub fn with_window(max: u32, window: Duration) -> Self {
        Self {
            window_start: Instant::now(),
            count: 0,
            max,
            window,
            warned: false,
        }
    }

    pub fn take(&mut self) -> Budget {
        self.take_at(Instant::now())
    }

    pub fn take_at(&mut self, now: Instant) -> Budget {
        if now.duration_since(self.window_start) >= self.window {
            self.window_start = now;
            self.count = 0;
            self.warned = false;
        }
        self.count = self.count.saturating_add(1);
        if self.count <= self.max {
            Budget::Ok
        } else if !self.warned {
            self.warned = true;
            Budget::LimitedNotify
        } else {
            Budget::Limited
        }
    }
}

/// Presence subscriptions between registered peers. Presence is reported
/// only between **mutual** watchers: W learns about X only if X also watches
/// W, so a stranger cannot use the push to follow someone who never added
/// them.
#[derive(Default)]
pub struct WatchRegistry {
    watches: HashMap<String, HashSet<String>>,
}

impl WatchRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace `watcher`'s watch set with `ids` (invalid ids dropped, capped
    /// at [`MAX_WATCH_IDS`]). Returns the ids in the new set that watch
    /// `watcher` back.
    pub fn set_watch(&mut self, watcher: &str, ids: &[String]) -> Vec<String> {
        let set: HashSet<String> = ids
            .iter()
            .filter(|id| is_peer_id_hex(id) && id.as_str() != watcher)
            .take(MAX_WATCH_IDS)
            .map(|id| id.to_ascii_lowercase())
            .collect();
        let mutual: Vec<String> = set
            .iter()
            .filter(|id| self.watches(id, watcher))
            .cloned()
            .collect();
        if set.is_empty() {
            self.watches.remove(watcher);
        } else {
            self.watches.insert(watcher.to_string(), set);
        }
        mutual
    }

    /// Whether `watcher` watches `target`.
    pub fn watches(&self, watcher: &str, target: &str) -> bool {
        self.watches
            .get(watcher)
            .is_some_and(|s| s.contains(target))
    }

    /// Peers that `peer` watches and that watch `peer` back.
    pub fn mutual_of(&self, peer: &str) -> Vec<String> {
        let Some(set) = self.watches.get(peer) else {
            return Vec::new();
        };
        set.iter()
            .filter(|w| self.watches(w, peer))
            .cloned()
            .collect()
    }

    /// Drop `watcher`'s subscriptions (on disconnect).
    pub fn remove(&mut self, watcher: &str) {
        self.watches.remove(watcher);
    }

    /// Number of peers with a watch set.
    pub fn len(&self) -> usize {
        self.watches.len()
    }

    pub fn is_empty(&self) -> bool {
        self.watches.is_empty()
    }
}

/// `true` for a 64-character hex string (a PeerId).
pub fn is_peer_id_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(pairs: &[(&str, &str)]) -> RelayPolicy {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        RelayPolicy::from_lookup(|k| map.get(k).cloned())
    }

    fn pid(n: u8) -> String {
        format!("{:02x}", n).repeat(32)
    }

    #[test]
    fn signaling_only_is_the_default() {
        let p = policy(&[]);
        assert!(p.signaling_only);
        assert_eq!(p.profile(), PROFILE_SIGNALING_ONLY);
        assert_eq!(p.max_ws_message_bytes, SIGNALING_MAX_WS_MESSAGE_BYTES);
        assert_eq!(p.frames_per_minute, SIGNALING_FRAMES_PER_MINUTE);
        for v in ["1", "true", "yes", "on", "anything"] {
            assert!(policy(&[("SIGNALING_ONLY", v)]).signaling_only, "{v}");
        }
    }

    #[test]
    fn relay_profile_needs_explicit_opt_in() {
        for v in ["0", "false", "FALSE", "off", "no", " 0 "] {
            let p = policy(&[("SIGNALING_ONLY", v)]);
            assert!(!p.signaling_only, "{v}");
            assert_eq!(p.profile(), PROFILE_RELAY);
            assert_eq!(p.max_ws_message_bytes, RELAY_MAX_WS_MESSAGE_BYTES);
        }
    }

    #[test]
    fn section_3_caps_are_the_defaults() {
        let p = policy(&[]);
        assert_eq!(p.max_ws_message_bytes, 32 * 1024);
        assert_eq!(p.max_sdp_payload_bytes, 16 * 1024);
        assert_eq!(p.max_ice_payload_bytes, 2 * 1024);
        assert_eq!(p.signal_per_minute, 60);
        assert_eq!(p.signal_per_hour, 240);
        assert_eq!(p.signal_per_pair_10min, 64);
        assert_eq!(p.conn_per_minute_per_ip, 20);
        assert_eq!(p.max_conns_per_ip, 8);
        assert_eq!(p.max_conns_global, 5000);
        assert_eq!(p.register_timeout, Duration::from_secs(10));
        assert_eq!(p.max_peers_per_ip, 3);
    }

    #[test]
    fn env_overrides_and_stun_filter() {
        let p = policy(&[
            ("RELAY_MAX_CONNS_PER_IP", "2"),
            ("RELAY_REGISTER_TIMEOUT_SECS", "1"),
            ("RELAY_MAX_WS_MESSAGE_BYTES", "bogus"),
            (
                "STUN_URIS",
                "stun:a.example:3478, turn:b.example:3478 ,stuns:c.example:5349,",
            ),
        ]);
        assert_eq!(p.max_conns_per_ip, 2);
        assert_eq!(p.register_timeout, Duration::from_secs(1));
        assert_eq!(p.max_ws_message_bytes, SIGNALING_MAX_WS_MESSAGE_BYTES);
        assert_eq!(
            p.stun_uris,
            vec!["stun:a.example:3478", "stuns:c.example:5349"],
            "TURN URIs are never served from the STUN list"
        );
    }

    #[test]
    fn signaling_only_whitelist() {
        let p = policy(&[]);
        for t in SIGNALING_FRAME_TYPES {
            assert!(p.frame_type_allowed(t));
        }
        for t in ["message", "gossip", "anything", ""] {
            assert!(!p.frame_type_allowed(t), "{t}");
        }
        let relay = policy(&[("SIGNALING_ONLY", "0")]);
        assert!(relay.frame_type_allowed("message"));
        assert!(relay.frame_type_allowed("gossip"));
    }

    #[test]
    fn admission_order() {
        let p = policy(&[]);
        assert_eq!(p.admit_frame(false, "register"), Ok(()));
        assert_eq!(p.admit_frame(false, "ping"), Ok(()));
        assert_eq!(p.admit_frame(false, "rtc_offer"), Err("not_registered"));
        assert_eq!(p.admit_frame(false, "watch"), Err("not_registered"));
        assert_eq!(p.admit_frame(true, "rtc_offer"), Ok(()));
        assert_eq!(p.admit_frame(true, "message"), Err("signaling_only"));
        assert_eq!(p.admit_frame(false, "message"), Err("signaling_only"));
        assert_eq!(p.admit_binary(true), BinaryAdmission::Close);
        let relay = policy(&[("SIGNALING_ONLY", "0")]);
        assert_eq!(relay.admit_frame(false, "message"), Err("not_registered"));
        assert_eq!(relay.admit_frame(true, "message"), Ok(()));
        assert_eq!(
            relay.admit_binary(false),
            BinaryAdmission::Refuse("not_registered")
        );
        assert_eq!(relay.admit_binary(true), BinaryAdmission::Accept);
    }

    #[test]
    fn admit_signal_never_queues() {
        let p = policy(&[]);
        let l = SignalingLimiter::new(&p);
        assert_eq!(
            p.admit_signal(&l, &pid(1), &pid(2), false, "rtc_offer", "x"),
            Err(SignalReject::PeerOffline)
        );
        assert_eq!(
            p.admit_signal(&l, &pid(1), &pid(2), true, "rtc_offer", "x"),
            Ok(())
        );
        assert_eq!(
            p.admit_signal(&l, &pid(1), &pid(2), true, "rtc_ice", &"x".repeat(4096)),
            Err(SignalReject::PayloadTooLarge)
        );
    }

    #[test]
    fn signal_payload_caps() {
        let p = policy(&[]);
        let sdp_ok = "x".repeat(16 * 1024);
        let sdp_big = "x".repeat(16 * 1024 + 1);
        let ice_ok = "x".repeat(2 * 1024);
        let ice_big = "x".repeat(2 * 1024 + 1);
        assert!(p.check_signal_payload("rtc_offer", &sdp_ok).is_ok());
        assert!(p.check_signal_payload("rtc_answer", &sdp_ok).is_ok());
        assert_eq!(
            p.check_signal_payload("rtc_offer", &sdp_big),
            Err(SignalReject::PayloadTooLarge)
        );
        assert!(p.check_signal_payload("rtc_ice", &ice_ok).is_ok());
        assert_eq!(
            p.check_signal_payload("rtc_ice", &ice_big),
            Err(SignalReject::PayloadTooLarge)
        );
        assert_eq!(SignalReject::PayloadTooLarge.code(), "payload_too_large");
        assert_eq!(SignalReject::RateLimited.code(), "rate_limited");
        assert_eq!(SignalReject::PeerOffline.code(), "peer_offline");
    }

    #[test]
    fn signaling_limiter_per_minute() {
        let p = policy(&[]);
        let l = SignalingLimiter::new(&p);
        // Spread over many recipients so the pair cap is not the one hit.
        for i in 0..60u32 {
            let to = pid((i % 50) as u8);
            assert!(l.check(&pid(200), &to).is_ok(), "frame {i}");
        }
        assert_eq!(l.check(&pid(200), &pid(1)), Err(SignalReject::RateLimited));
        // Another sender is unaffected.
        assert!(l.check(&pid(201), &pid(1)).is_ok());
    }

    #[test]
    fn signaling_limiter_per_pair() {
        let p = policy(&[
            ("RELAY_SIGNAL_PER_MINUTE", "1000"),
            ("RELAY_SIGNAL_PER_HOUR", "1000"),
        ]);
        let l = SignalingLimiter::new(&p);
        for _ in 0..64 {
            assert!(l.check(&pid(1), &pid(2)).is_ok());
        }
        assert_eq!(l.check(&pid(1), &pid(2)), Err(SignalReject::RateLimited));
        assert!(
            l.check(&pid(1), &pid(3)).is_ok(),
            "other pairs keep their budget"
        );
    }

    #[test]
    fn signaling_limiter_per_hour() {
        let p = policy(&[
            ("RELAY_SIGNAL_PER_MINUTE", "1000"),
            ("RELAY_SIGNAL_PER_PAIR_10MIN", "1000"),
        ]);
        let l = SignalingLimiter::new(&p);
        for i in 0..240u32 {
            assert!(l.check(&pid(9), &pid((i % 200) as u8)).is_ok());
        }
        assert_eq!(l.check(&pid(9), &pid(1)), Err(SignalReject::RateLimited));
    }

    #[test]
    fn ip_slots_per_ip_and_global() {
        let slots = IpSlots::new(2, 3);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let a1 = slots.try_acquire(a).unwrap();
        let _a2 = slots.try_acquire(a).unwrap();
        assert!(slots.try_acquire(a).is_none(), "per-IP cap");
        let _b1 = slots.try_acquire(b).unwrap();
        assert!(slots.try_acquire(b).is_none(), "global cap");
        assert_eq!(slots.total(), 3);
        drop(a1);
        assert_eq!(slots.in_use(a), 1);
        assert!(slots.try_acquire(b).is_some());
    }

    #[test]
    fn ip_slots_release_all_state() {
        let slots = IpSlots::new(8, usize::MAX);
        let guards: Vec<_> = (0..100u8)
            .map(|i| slots.try_acquire(IpAddr::from([10, 0, 0, i])).unwrap())
            .collect();
        assert_eq!(slots.tracked_ips(), 100);
        drop(guards);
        assert_eq!(slots.total(), 0);
        assert_eq!(slots.tracked_ips(), 0, "no per-IP entries are retained");
    }

    #[test]
    fn frame_budget_notifies_once_per_window() {
        let mut b = FrameBudget::with_window(3, Duration::from_secs(60));
        let t0 = Instant::now();
        assert_eq!(b.take_at(t0), Budget::Ok);
        assert_eq!(b.take_at(t0), Budget::Ok);
        assert_eq!(b.take_at(t0), Budget::Ok);
        assert_eq!(b.take_at(t0), Budget::LimitedNotify);
        assert_eq!(b.take_at(t0), Budget::Limited);
        assert_eq!(b.take_at(t0), Budget::Limited);
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(b.take_at(t1), Budget::Ok);
    }

    #[test]
    fn watch_presence_is_mutual_only() {
        let mut w = WatchRegistry::new();
        let (a, b, c) = (pid(1), pid(2), pid(3));
        // A watches B: not mutual yet.
        assert!(w.set_watch(&a, std::slice::from_ref(&b)).is_empty());
        assert!(w.mutual_of(&b).is_empty());
        // B watches A: now mutual, reported to B at once.
        assert_eq!(w.set_watch(&b, std::slice::from_ref(&a)), vec![a.clone()]);
        assert_eq!(w.mutual_of(&a), vec![b.clone()]);
        assert_eq!(w.mutual_of(&b), vec![a.clone()]);
        // C (a stranger) watching A learns nothing.
        assert!(w.set_watch(&c, std::slice::from_ref(&a)).is_empty());
        assert!(!w.mutual_of(&a).contains(&c));
        // A replaces its set: B is no longer mutual.
        w.set_watch(&a, std::slice::from_ref(&c));
        assert!(w.mutual_of(&b).is_empty());
        assert_eq!(w.mutual_of(&a), vec![c.clone()]);
        w.remove(&a);
        assert!(w.mutual_of(&c).is_empty());
    }

    #[test]
    fn watch_set_is_bounded_and_validated() {
        let mut w = WatchRegistry::new();
        let me = pid(0);
        let mut ids: Vec<String> = (0..1000u32).map(|i| format!("{:064x}", i + 1)).collect();
        ids.push("not-hex".into());
        ids.push(me.clone());
        w.set_watch(&me, &ids);
        assert_eq!(w.watches.get(&me).unwrap().len(), MAX_WATCH_IDS);
        assert!(!w.watches(&me, &me), "self is never watched");
        // Empty set frees the entry.
        w.set_watch(&me, &[]);
        assert!(w.is_empty());
    }

    #[test]
    fn peer_id_hex_shape() {
        assert!(is_peer_id_hex(&pid(7)));
        assert!(!is_peer_id_hex("ab"));
        assert!(!is_peer_id_hex(&"g".repeat(64)));
    }
}
