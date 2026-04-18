//! Federation peer state machine (PNP-008 §5).
//!
//! Pure-data model of per-peer federation link state. No I/O, no networking —
//! callers (the forthcoming `FederationManager`) feed events in and use the
//! exposed timer/eligibility helpers to drive the actual transport.
//!
//! ## Spec mapping
//! - §5 state diagram (INIT → HANDSHAKE → SYNC → ACTIVE → IDLE → BANNED) →
//!   [`PeerState`]
//! - §5.2 MUST-018 (TLS camouflage + PNP-002 before payloads) — structurally
//!   enforced by `can_send_federation_payload()` returning `false` outside
//!   `Sync`/`Active`.
//! - §5.2 MUST-019 (descriptor unverifiable → close) → [`FederationPeer::handshake_failed`]
//! - §5.3 MUST-020 reconnect backoff → [`reconnect_backoff_delay`]
//! - §5.3 MUST-021 failure reset after ≥ 300 s ACTIVE → [`FederationPeer::active_stabilized`]
//! - §5.4 MUST-022 rate limits (100 desc/min, 10 syncs/hr) → [`TokenBucket`]
//! - §4.2 MUST-011 heartbeat cadence / unreachable threshold → [`FederationPeer::tick`]

use parolnet_protocol::address::PeerId;
use parolnet_protocol::federation::{
    HEARTBEAT_UNREACHABLE_SECS, RATE_LIMIT_DESCRIPTORS_PER_MIN, RATE_LIMIT_SYNC_INITS_PER_HOUR,
};
use serde::{Deserialize, Serialize};

/// Minimum ACTIVE dwell time before a successful session resets the failure
/// counter (PNP-008-MUST-021).
pub const STABILIZATION_ACTIVE_SECS: u64 = 300;

/// Default base reconnect delay in seconds (PNP-008-MUST-020:
/// `30 * 2^failures`, bounded).
pub const DEFAULT_RECONNECT_BASE_SECS: u64 = 30;

/// Maximum reconnect delay (PNP-008-MUST-020).
pub const DEFAULT_RECONNECT_MAX_SECS: u64 = 3600;

/// Federation peer lifecycle state (PNP-008 §5 diagram).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerState {
    /// Peer is known but no connection attempt has been made yet.
    Init,
    /// Transport open, TLS+PNP-002 handshake in progress; NO federation
    /// payloads may be exchanged yet (MUST-018).
    Handshake,
    /// Handshake complete; running initial `FederationSync`.
    Sync,
    /// Initial sync complete; exchanging heartbeats and periodic syncs.
    Active,
    /// Not connected; awaiting the MUST-020 reconnect backoff.
    Idle,
    /// Reputation decided to ban this peer (PNP-008-MUST-035 — enforced via
    /// [`crate::MeshError`] flow in the FederationManager; here we record
    /// that the state machine was transitioned into BANNED so other logic
    /// can refuse to re-enter HANDSHAKE during the cooldown).
    Banned,
}

impl PeerState {
    /// Whether this state may carry FederationSync / FederationHeartbeat
    /// payloads (PNP-008-MUST-018).
    ///
    /// `Init`, `Handshake`, `Idle`, `Banned` MUST NOT. `Sync` is allowed
    /// because the initial `FederationSync` is the transition trigger for
    /// `Active`.
    pub fn can_send_federation_payload(self) -> bool {
        matches!(self, Self::Sync | Self::Active)
    }
}

/// Token bucket for the MUST-022 rate-limit caps.
///
/// The bucket refills `capacity` tokens over `period_secs`. Elapsed time is
/// converted to fractional tokens and accumulated on each access — this is
/// what lets us model both fast rates (100/min) and slow rates (10/hr) with
/// a single integer time source. Unconsumed refill-fractions survive across
/// `try_take` calls because `last_refill` is advanced by the whole-second
/// equivalent of tokens minted.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenBucket {
    pub capacity: u32,
    pub period_secs: u64,
    pub tokens: u32,
    pub last_refill: u64,
}

impl TokenBucket {
    pub fn new(capacity: u32, period_secs: u64, now: u64) -> Self {
        Self {
            capacity,
            period_secs,
            tokens: capacity,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: u64) {
        if self.period_secs == 0 || self.capacity == 0 {
            return;
        }
        let elapsed = now.saturating_sub(self.last_refill);
        if elapsed == 0 {
            return;
        }
        // tokens_to_add = floor(elapsed * capacity / period_secs).
        let add = elapsed
            .saturating_mul(self.capacity as u64)
            / self.period_secs;
        if add == 0 {
            return;
        }
        let capped = add.min(self.capacity as u64) as u32;
        self.tokens = self.tokens.saturating_add(capped).min(self.capacity);
        // Advance last_refill by the whole-second equivalent of the tokens
        // we minted so fractional carry isn't lost across calls.
        let consumed_secs = (add.saturating_mul(self.period_secs)) / self.capacity as u64;
        self.last_refill = self.last_refill.saturating_add(consumed_secs);
    }

    /// Attempt to spend one token. Returns `true` on success.
    pub fn try_take(&mut self, now: u64) -> bool {
        self.refill(now);
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Compute the MUST-020 base reconnect delay in seconds.
///
/// `base * 2^failures`, capped at `max`. Caller adds the ±25 % jitter.
pub fn reconnect_backoff_delay(failures: u32, base_secs: u64, max_secs: u64) -> u64 {
    let shift = failures.min(63);
    let raw = base_secs.saturating_mul(1u64 << shift);
    raw.min(max_secs)
}

/// Per-peer federation link state (PNP-008 §5).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationPeer {
    pub peer_id: PeerId,
    pub state: PeerState,
    /// Consecutive connection failures since the last stabilized ACTIVE
    /// session (PNP-008-MUST-021).
    pub failures: u32,
    /// Unix seconds the peer most recently transitioned into ACTIVE.
    pub active_since: Option<u64>,
    /// Unix seconds of the last state transition (for liveness queries).
    pub last_transition: u64,
    /// Unix seconds the peer's last heartbeat arrived.
    pub last_heartbeat_rx: Option<u64>,
    /// Monotonic counter of the last heartbeat we accepted (MUST-010).
    pub last_heartbeat_counter: Option<u64>,
    /// Rate-limit bucket for descriptor deliveries (MUST-022, 100/min).
    pub descriptor_bucket: TokenBucket,
    /// Rate-limit bucket for FederationSync initiations (MUST-022, 10/hr).
    pub sync_init_bucket: TokenBucket,
}

impl FederationPeer {
    /// New peer at `Init` state.
    pub fn new(peer_id: PeerId, now: u64) -> Self {
        Self {
            peer_id,
            state: PeerState::Init,
            failures: 0,
            active_since: None,
            last_transition: now,
            last_heartbeat_rx: None,
            last_heartbeat_counter: None,
            descriptor_bucket: TokenBucket::new(RATE_LIMIT_DESCRIPTORS_PER_MIN, 60, now),
            sync_init_bucket: TokenBucket::new(RATE_LIMIT_SYNC_INITS_PER_HOUR, 3600, now),
        }
    }

    fn transition(&mut self, to: PeerState, now: u64) {
        self.state = to;
        self.last_transition = now;
    }

    /// Begin connection — legal only from `Init` or `Idle`, and never when
    /// `Banned`.
    pub fn connect(&mut self, now: u64) -> Result<(), TransitionError> {
        match self.state {
            PeerState::Init | PeerState::Idle => {
                self.transition(PeerState::Handshake, now);
                Ok(())
            }
            PeerState::Banned => Err(TransitionError::Banned),
            other => Err(TransitionError::IllegalFrom(other)),
        }
    }

    /// Handshake completed successfully → advance to SYNC.
    pub fn handshake_ok(&mut self, now: u64) -> Result<(), TransitionError> {
        if self.state != PeerState::Handshake {
            return Err(TransitionError::IllegalFrom(self.state));
        }
        self.transition(PeerState::Sync, now);
        Ok(())
    }

    /// Handshake failed — MUST-019 requires the transport to be closed; we
    /// fall back to IDLE, increment failures, and let the caller consult
    /// [`Self::reconnect_delay`] for MUST-020 backoff.
    pub fn handshake_failed(&mut self, now: u64) {
        self.failures = self.failures.saturating_add(1);
        self.active_since = None;
        self.transition(PeerState::Idle, now);
    }

    /// Initial `FederationSync` round completed → advance to ACTIVE.
    pub fn sync_complete(&mut self, now: u64) -> Result<(), TransitionError> {
        if self.state != PeerState::Sync {
            return Err(TransitionError::IllegalFrom(self.state));
        }
        self.transition(PeerState::Active, now);
        self.active_since = Some(now);
        Ok(())
    }

    /// Record an accepted heartbeat. Caller has already verified the
    /// signature and monotonicity; this method records the counter.
    pub fn heartbeat_seen(&mut self, counter: u64, now: u64) {
        self.last_heartbeat_rx = Some(now);
        self.last_heartbeat_counter = Some(counter);
    }

    /// Drive time-based transitions. Call periodically from the manager's
    /// ticker. Returns `true` if the state changed.
    ///
    /// Currently implements MUST-011: if ACTIVE and the last heartbeat is
    /// older than `HEARTBEAT_UNREACHABLE_SECS`, transition to IDLE.
    pub fn tick(&mut self, now: u64) -> bool {
        if self.state != PeerState::Active {
            return false;
        }
        if let Some(last) = self.last_heartbeat_rx
            && now.saturating_sub(last) > HEARTBEAT_UNREACHABLE_SECS
        {
            self.failures = self.failures.saturating_add(1);
            self.active_since = None;
            self.transition(PeerState::Idle, now);
            return true;
        }
        // Session has been ACTIVE long enough — reset failures (MUST-021).
        if self.active_stabilized(now) {
            self.failures = 0;
        }
        false
    }

    /// Whether the current ACTIVE session has passed the MUST-021
    /// stabilization threshold (≥ 300 s).
    pub fn active_stabilized(&self, now: u64) -> bool {
        match self.active_since {
            Some(since) => now.saturating_sub(since) >= STABILIZATION_ACTIVE_SECS,
            None => false,
        }
    }

    /// MUST-020 reconnect delay for the current failure count.
    pub fn reconnect_delay(&self) -> u64 {
        reconnect_backoff_delay(
            self.failures,
            DEFAULT_RECONNECT_BASE_SECS,
            DEFAULT_RECONNECT_MAX_SECS,
        )
    }

    /// Wall-clock time at which reconnect becomes eligible, given the peer
    /// is in IDLE. Returns `None` if not applicable.
    pub fn next_reconnect_eligible_at(&self) -> Option<u64> {
        match self.state {
            PeerState::Idle => Some(self.last_transition + self.reconnect_delay()),
            _ => None,
        }
    }

    /// Move to BANNED. Called by the FederationManager when the reputation
    /// subsystem raises the BANNED flag.
    pub fn ban(&mut self, now: u64) {
        self.active_since = None;
        self.transition(PeerState::Banned, now);
    }

    /// Move out of BANNED (back to IDLE) — called by the manager once the
    /// reputation layer has observed the 24 h cooldown passing.
    pub fn unban(&mut self, now: u64) {
        if self.state == PeerState::Banned {
            self.failures = 0;
            self.transition(PeerState::Idle, now);
        }
    }

    /// Attempt to charge one `FederationSync` initiation against the
    /// MUST-022 rate limit. Returns `true` if permitted.
    pub fn charge_sync_init(&mut self, now: u64) -> bool {
        self.sync_init_bucket.try_take(now)
    }

    /// Attempt to charge one descriptor delivery against the MUST-022 rate
    /// limit. Returns `true` if permitted.
    pub fn charge_descriptor_delivery(&mut self, now: u64) -> bool {
        self.descriptor_bucket.try_take(now)
    }
}

/// Errors from illegal state transitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// The attempted transition is not allowed from this state.
    IllegalFrom(PeerState),
    /// Peer is currently BANNED and cannot reconnect.
    Banned,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn state_diagram_happy_path() {
        let mut p = FederationPeer::new(pid(1), 0);
        assert_eq!(p.state, PeerState::Init);
        p.connect(10).unwrap();
        assert_eq!(p.state, PeerState::Handshake);
        p.handshake_ok(20).unwrap();
        assert_eq!(p.state, PeerState::Sync);
        p.sync_complete(30).unwrap();
        assert_eq!(p.state, PeerState::Active);
        assert_eq!(p.active_since, Some(30));
    }

    #[test]
    fn handshake_failed_drops_to_idle_and_bumps_failures() {
        let mut p = FederationPeer::new(pid(1), 0);
        p.connect(1).unwrap();
        p.handshake_failed(5);
        assert_eq!(p.state, PeerState::Idle);
        assert_eq!(p.failures, 1);

        p.connect(10).unwrap();
        p.handshake_failed(12);
        assert_eq!(p.failures, 2);
    }

    #[test]
    fn banned_rejects_connect() {
        let mut p = FederationPeer::new(pid(1), 0);
        p.ban(100);
        assert_eq!(p.state, PeerState::Banned);
        assert_eq!(p.connect(200), Err(TransitionError::Banned));
    }

    #[test]
    fn unban_resets_failures_and_moves_to_idle() {
        let mut p = FederationPeer::new(pid(1), 0);
        p.connect(1).unwrap();
        p.handshake_failed(5);
        assert_eq!(p.failures, 1);
        p.ban(10);
        p.unban(100);
        assert_eq!(p.state, PeerState::Idle);
        assert_eq!(p.failures, 0);
    }

    #[test]
    fn reconnect_backoff_matches_spec_formula() {
        // 30 * 2^failures, capped at 3600.
        assert_eq!(reconnect_backoff_delay(0, 30, 3600), 30);
        assert_eq!(reconnect_backoff_delay(1, 30, 3600), 60);
        assert_eq!(reconnect_backoff_delay(6, 30, 3600), 1920);
        // 30 * 128 = 3840 → capped at 3600.
        assert_eq!(reconnect_backoff_delay(7, 30, 3600), 3600);
        assert_eq!(reconnect_backoff_delay(63, 30, 3600), 3600);
    }

    #[test]
    fn next_reconnect_eligible_at_only_defined_for_idle() {
        let mut p = FederationPeer::new(pid(1), 0);
        assert_eq!(p.next_reconnect_eligible_at(), None); // Init
        p.connect(1).unwrap();
        assert_eq!(p.next_reconnect_eligible_at(), None); // Handshake
        p.handshake_failed(5);
        // Idle at t=5, failures=1 → 60s delay → eligible at 65.
        assert_eq!(p.next_reconnect_eligible_at(), Some(5 + 60));
    }

    #[test]
    fn tick_demotes_active_after_heartbeat_silence() {
        let mut p = FederationPeer::new(pid(1), 0);
        p.connect(1).unwrap();
        p.handshake_ok(2).unwrap();
        p.sync_complete(3).unwrap();
        p.heartbeat_seen(1, 4);
        // Within 180 s — no change.
        assert!(!p.tick(10));
        assert_eq!(p.state, PeerState::Active);
        // > 180 s silence — transition to IDLE.
        assert!(p.tick(4 + HEARTBEAT_UNREACHABLE_SECS + 1));
        assert_eq!(p.state, PeerState::Idle);
        assert_eq!(p.failures, 1);
    }

    #[test]
    fn failure_counter_resets_after_300s_active() {
        let mut p = FederationPeer::new(pid(1), 0);
        // Accumulate failures.
        p.connect(1).unwrap();
        p.handshake_failed(2);
        p.connect(3).unwrap();
        p.handshake_failed(4);
        assert_eq!(p.failures, 2);
        // Establish ACTIVE at t=10.
        p.connect(5).unwrap();
        p.handshake_ok(6).unwrap();
        p.sync_complete(10).unwrap();
        p.heartbeat_seen(1, 11);
        // Before 300 s stabilize — still carries failures.
        p.tick(100);
        assert_eq!(p.failures, 2);
        // After 300 s ACTIVE — failures reset.
        p.heartbeat_seen(2, 11 + STABILIZATION_ACTIVE_SECS);
        p.tick(11 + STABILIZATION_ACTIVE_SECS);
        assert_eq!(p.failures, 0);
    }

    #[test]
    fn federation_payload_gated_by_state() {
        // MUST-018: no FederationSync / Heartbeat before SYNC state.
        assert!(!PeerState::Init.can_send_federation_payload());
        assert!(!PeerState::Handshake.can_send_federation_payload());
        assert!(PeerState::Sync.can_send_federation_payload());
        assert!(PeerState::Active.can_send_federation_payload());
        assert!(!PeerState::Idle.can_send_federation_payload());
        assert!(!PeerState::Banned.can_send_federation_payload());
    }

    #[test]
    fn rate_limit_descriptor_deliveries_100_per_minute() {
        let mut p = FederationPeer::new(pid(1), 0);
        // 100 tokens at t=0.
        for _ in 0..100 {
            assert!(p.charge_descriptor_delivery(0));
        }
        // 101st at t=0 must fail.
        assert!(!p.charge_descriptor_delivery(0));
    }

    #[test]
    fn rate_limit_sync_inits_10_per_hour() {
        let mut p = FederationPeer::new(pid(1), 0);
        for _ in 0..10 {
            assert!(p.charge_sync_init(0));
        }
        assert!(!p.charge_sync_init(0));
    }

    #[test]
    fn rate_limit_refills_over_time() {
        let mut p = FederationPeer::new(pid(1), 0);
        // Drain descriptor bucket.
        for _ in 0..100 {
            p.charge_descriptor_delivery(0);
        }
        assert!(!p.charge_descriptor_delivery(0));
        // 60 s later — full refill at 100/min = 1 token every 0.6 s.
        assert!(p.charge_descriptor_delivery(60));
    }

    #[test]
    fn illegal_transition_from_wrong_state_errors() {
        let mut p = FederationPeer::new(pid(1), 0);
        assert!(matches!(
            p.handshake_ok(1),
            Err(TransitionError::IllegalFrom(PeerState::Init))
        ));
        assert!(matches!(
            p.sync_complete(1),
            Err(TransitionError::IllegalFrom(PeerState::Init))
        ));
    }
}
