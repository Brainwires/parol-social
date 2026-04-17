//! Federation peer reputation (PNP-008 §7).
//!
//! This module is separate from [`crate::directory::RelayHealth`], which tracks
//! per-connection latency and success/failure counters used to weight onion
//! circuit selection. `RelayReputation` models a different signal: the
//! long-running peer-behavior score defined by PNP-008 §7 that governs
//! federation-link admission and drives the SUSPECT/BANNED flag transitions.
//!
//! The two live side-by-side because they have different update cadences,
//! time constants, and decision rules — folding them together would force a
//! single EWMA to serve both fast-moving circuit timings and slow-moving peer
//! trust, neither of which the spec targets directly.
//!
//! ## Spec mapping
//! - §7 struct fields → [`RelayReputation`]
//! - §7.1 MUST-032 EWMA (α=0.9) → [`RelayReputation::record`]
//! - §7.1 MUST-033 event table → [`ObservationEvent`]
//! - §7.2 MUST-034 SUSPECT (score < 0.2 for > 15 min) → [`RelayReputation::evaluate_flags`]
//! - §7.2 MUST-035 BANNED (score < 0.05 OR > 3 invalid sigs / 60 s) → same
//! - §7.2 SHOULD-005 STABLE promotion (7 d ACTIVE + score ≥ 0.8) → [`mark_active_tick`]
//! - §7.3 MUST-036 persistence cadence (≤ 10 min) is a caller responsibility;
//!   this module exposes [`RelayReputation::last_persisted`] and
//!   [`RelayReputation::persist_due`] to let the caller decide.

use serde::{Deserialize, Serialize};

/// EWMA decay α — PNP-008-MUST-032 fixes this at 0.9.
pub const REPUTATION_EWMA_ALPHA: f64 = 0.9;

/// Initial score for a freshly-seen peer — PNP-008 §7.
pub const REPUTATION_INITIAL_SCORE: f64 = 0.5;

/// SUSPECT flag threshold (PNP-008-MUST-034).
pub const SUSPECT_SCORE_THRESHOLD: f64 = 0.2;

/// Minimum consecutive time below `SUSPECT_SCORE_THRESHOLD` before SUSPECT
/// is set (PNP-008-MUST-034, 15 minutes).
pub const SUSPECT_DWELL_SECS: u64 = 15 * 60;

/// BANNED score threshold (PNP-008-MUST-035).
pub const BANNED_SCORE_THRESHOLD: f64 = 0.05;

/// Invalid-signature count within window that triggers BAN
/// (PNP-008-MUST-035).
pub const BANNED_INVALID_SIG_COUNT: usize = 3;

/// Window over which invalid signatures are counted for ban
/// (PNP-008-MUST-035).
pub const BANNED_INVALID_SIG_WINDOW_SECS: u64 = 60;

/// Minimum cooldown before a BANNED peer may be reconnected
/// (PNP-008-MUST-035, 24 hours).
pub const BANNED_COOLDOWN_SECS: u64 = 24 * 3600;

/// Score required to promote a peer to STABLE (PNP-008-SHOULD-005).
pub const STABLE_SCORE_THRESHOLD: f64 = 0.8;

/// Minimum ACTIVE dwell time to promote to STABLE
/// (PNP-008-SHOULD-005, 7 days).
pub const STABLE_ACTIVE_DWELL_SECS: u64 = 7 * 24 * 3600;

/// Maximum interval between reputation persists (PNP-008-MUST-036, 10 min).
pub const REPUTATION_PERSIST_INTERVAL_SECS: u64 = 10 * 60;

/// Peer classification flags (PNP-008 §7.2).
///
/// Represented as a `u32` bitfield so we can persist reputation with plain
/// `serde` without pulling in the `bitflags` crate. SUSPECT and BANNED are
/// mutually informative: BANNED subsumes SUSPECT for routing decisions, but
/// both bits are kept so the exit transition from BANNED (after
/// `BANNED_COOLDOWN_SECS`) can leave the peer in a merely-SUSPECT state
/// rather than immediately pristine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelayFlags(pub u32);

impl RelayFlags {
    /// Peer has been observed stable long enough to be considered for
    /// guard selection (PNP-008-MAY-001).
    pub const GUARD_ELIGIBLE: Self = Self(1 << 0);
    /// Peer has met STABLE criteria (PNP-008-SHOULD-005).
    pub const STABLE: Self = Self(1 << 1);
    /// Peer advertises bridge capability (PNP-008 §4.2 heartbeat flag).
    pub const BRIDGE: Self = Self(1 << 2);
    /// Peer has score below SUSPECT threshold for the dwell window
    /// (PNP-008-MUST-034).
    pub const SUSPECT: Self = Self(1 << 3);
    /// Peer has been banned (PNP-008-MUST-035).
    pub const BANNED: Self = Self(1 << 4);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn contains(&self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn intersects(&self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
}

impl std::ops::BitOr for RelayFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// The spec-defined observation events that drive the EWMA.
///
/// Normalized values come directly from PNP-008-MUST-033 §7.1 table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationEvent {
    /// Successful `FederationSync` round completed with this peer.
    FederationSyncSuccess,
    /// `FederationHeartbeat` received within the 60 s cadence window.
    HeartbeatOnTime,
    /// No heartbeat received for ≥ 180 s (peer unreachable).
    HeartbeatMissed,
    /// Descriptor received from this peer had a valid signature.
    DescriptorSignatureValid,
    /// Descriptor received from this peer had an invalid signature.
    DescriptorSignatureInvalid,
    /// This peer exceeded per-peer rate limits (PNP-008-MUST-022).
    RateLimitExceeded,
    /// This peer replayed a `sync_id` within its 5-minute window
    /// (PNP-008-MUST-006).
    ReplayedWithinWindow,
}

impl ObservationEvent {
    /// Normalized observation value ∈ [0.0, 1.0] per PNP-008-MUST-033.
    pub fn observation(self) -> f64 {
        match self {
            Self::FederationSyncSuccess
            | Self::HeartbeatOnTime
            | Self::DescriptorSignatureValid => 1.0,
            Self::HeartbeatMissed
            | Self::DescriptorSignatureInvalid
            | Self::RateLimitExceeded
            | Self::ReplayedWithinWindow => 0.0,
        }
    }

    /// Whether this event counts an invalid-signature observation for the
    /// rolling ban window (PNP-008-MUST-035).
    pub fn is_invalid_signature(self) -> bool {
        matches!(self, Self::DescriptorSignatureInvalid)
    }

    /// Whether this event updates the `malformed_contrib` counter
    /// (PNP-008-MUST-029).
    pub fn is_malformed(self) -> bool {
        matches!(
            self,
            Self::DescriptorSignatureInvalid | Self::ReplayedWithinWindow
        )
    }
}

/// Per-peer reputation state (PNP-008 §7).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RelayReputation {
    /// EWMA score, bounded to `[0.0, 1.0]`. Initial value: 0.5.
    pub score: f64,
    /// Count of observations contributing 1.0 to the score.
    pub successes: u64,
    /// Count of observations contributing 0.0 to the score.
    pub failures: u64,
    /// Count of malformed events (subset of failures — see
    /// [`ObservationEvent::is_malformed`]).
    pub malformed_contrib: u64,
    /// Current flag set.
    pub flags: RelayFlags,
    /// Unix seconds of the last update.
    pub last_update: u64,
    /// Unix seconds at which `score` first dropped below
    /// `SUSPECT_SCORE_THRESHOLD` in the current streak. `None` when the peer
    /// is at-or-above threshold.
    pub suspect_since: Option<u64>,
    /// Unix seconds of the last BAN event. `None` when never banned.
    pub banned_at: Option<u64>,
    /// Unix seconds at which the peer first entered ACTIVE in the current
    /// streak — drives STABLE promotion (PNP-008-SHOULD-005).
    pub active_since: Option<u64>,
    /// Recent invalid-signature timestamps for the `BANNED_INVALID_SIG_WINDOW`
    /// rolling check. Trimmed lazily on every record() call.
    invalid_sig_ts: Vec<u64>,
    /// Unix seconds of the last persist (PNP-008-MUST-036).
    pub last_persisted: u64,
}

impl Default for RelayReputation {
    fn default() -> Self {
        Self {
            score: REPUTATION_INITIAL_SCORE,
            successes: 0,
            failures: 0,
            malformed_contrib: 0,
            flags: RelayFlags::empty(),
            last_update: 0,
            suspect_since: None,
            banned_at: None,
            active_since: None,
            invalid_sig_ts: Vec::new(),
            last_persisted: 0,
        }
    }
}

impl RelayReputation {
    /// Create a fresh reputation record at `now`.
    pub fn new(now: u64) -> Self {
        Self {
            last_update: now,
            last_persisted: now,
            ..Self::default()
        }
    }

    /// Feed one observation event into the record (PNP-008-MUST-032 +
    /// MUST-033) and re-evaluate the flag state machine (§7.2).
    ///
    /// `now` is Unix seconds; callers must supply a monotonic clock or tick
    /// source — `last_update` is updated unconditionally.
    pub fn record(&mut self, event: ObservationEvent, now: u64) {
        let obs = event.observation();

        // PNP-008-MUST-032: EWMA with α=0.9.
        self.score = (REPUTATION_EWMA_ALPHA * self.score + (1.0 - REPUTATION_EWMA_ALPHA) * obs)
            .clamp(0.0, 1.0);

        if obs >= 0.5 {
            self.successes = self.successes.saturating_add(1);
        } else {
            self.failures = self.failures.saturating_add(1);
        }
        if event.is_malformed() {
            self.malformed_contrib = self.malformed_contrib.saturating_add(1);
        }
        if event.is_invalid_signature() {
            self.push_invalid_signature(now);
        }

        self.last_update = now;
        self.evaluate_flags(now);
    }

    fn push_invalid_signature(&mut self, now: u64) {
        // Trim to the rolling window before pushing.
        let cutoff = now.saturating_sub(BANNED_INVALID_SIG_WINDOW_SECS);
        self.invalid_sig_ts.retain(|t| *t >= cutoff);
        self.invalid_sig_ts.push(now);
    }

    /// Count of invalid signatures within the rolling ban window ending at
    /// `now`.
    pub fn invalid_signatures_in_window(&self, now: u64) -> usize {
        let cutoff = now.saturating_sub(BANNED_INVALID_SIG_WINDOW_SECS);
        self.invalid_sig_ts.iter().filter(|t| **t >= cutoff).count()
    }

    /// Re-evaluate the flag state machine at `now`. Called internally by
    /// [`Self::record`]; expose separately so time-based transitions (e.g.
    /// SUSPECT dwell elapsing with no new events) can be driven by a ticker.
    pub fn evaluate_flags(&mut self, now: u64) {
        // SUSPECT dwell tracking (PNP-008-MUST-034).
        if self.score < SUSPECT_SCORE_THRESHOLD {
            if self.suspect_since.is_none() {
                self.suspect_since = Some(now);
            }
            let entered = self.suspect_since.unwrap();
            if now.saturating_sub(entered) > SUSPECT_DWELL_SECS {
                self.flags.insert(RelayFlags::SUSPECT);
            }
        } else {
            self.suspect_since = None;
            self.flags.remove(RelayFlags::SUSPECT);
        }

        // BAN conditions (PNP-008-MUST-035).
        let too_many_invalid = self.invalid_signatures_in_window(now) > BANNED_INVALID_SIG_COUNT;
        let score_in_ban_band = self.score < BANNED_SCORE_THRESHOLD;
        if too_many_invalid || score_in_ban_band {
            self.flags.insert(RelayFlags::BANNED);
            if self.banned_at.is_none() {
                self.banned_at = Some(now);
            }
        } else if let Some(banned_at) = self.banned_at {
            // Exit BAN only after cooldown has elapsed.
            if now.saturating_sub(banned_at) >= BANNED_COOLDOWN_SECS {
                self.flags.remove(RelayFlags::BANNED);
                self.banned_at = None;
            }
        }
    }

    /// Signal that this peer is currently ACTIVE at `now`. Called by the
    /// federation manager each heartbeat; advances STABLE promotion logic.
    pub fn mark_active_tick(&mut self, now: u64) {
        if self.active_since.is_none() {
            self.active_since = Some(now);
        }
        if let Some(since) = self.active_since {
            if now.saturating_sub(since) >= STABLE_ACTIVE_DWELL_SECS
                && self.score >= STABLE_SCORE_THRESHOLD
            {
                self.flags.insert(RelayFlags::STABLE);
            }
        }
    }

    /// Signal that this peer left ACTIVE (IDLE, HANDSHAKE, BANNED). Resets
    /// the STABLE dwell timer per PNP-008-MUST-021's "failures reset only
    /// after ≥ 300 s ACTIVE" doctrine.
    pub fn mark_active_end(&mut self) {
        self.active_since = None;
        self.flags.remove(RelayFlags::STABLE);
        self.flags.remove(RelayFlags::GUARD_ELIGIBLE);
    }

    /// Whether this peer is currently unsuitable for new circuit selection
    /// (PNP-008-MUST-034 + MUST-035).
    pub fn is_eligible_for_circuits(&self) -> bool {
        !self
            .flags
            .intersects(RelayFlags::SUSPECT | RelayFlags::BANNED)
    }

    /// Whether this peer is currently banned.
    pub fn is_banned(&self) -> bool {
        self.flags.contains(RelayFlags::BANNED)
    }

    /// Whether enough time has elapsed since the last persist that the
    /// caller SHOULD flush state to disk (PNP-008-MUST-036).
    pub fn persist_due(&self, now: u64) -> bool {
        now.saturating_sub(self.last_persisted) >= REPUTATION_PERSIST_INTERVAL_SECS
    }

    /// Mark the current state as persisted — called after the caller has
    /// flushed to durable storage.
    pub fn mark_persisted(&mut self, now: u64) {
        self.last_persisted = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_record_starts_at_spec_defaults() {
        let r = RelayReputation::new(1000);
        assert_eq!(r.score, REPUTATION_INITIAL_SCORE);
        assert_eq!(r.flags, RelayFlags::empty());
        assert_eq!(r.successes, 0);
        assert_eq!(r.failures, 0);
    }

    #[test]
    fn ewma_formula_matches_spec() {
        let mut r = RelayReputation::new(0);
        r.score = 0.5;
        r.record(ObservationEvent::FederationSyncSuccess, 10);
        // 0.9 * 0.5 + 0.1 * 1.0 = 0.55
        assert!((r.score - 0.55).abs() < 1e-9);
        r.record(ObservationEvent::HeartbeatMissed, 20);
        // 0.9 * 0.55 + 0.1 * 0.0 = 0.495
        assert!((r.score - 0.495).abs() < 1e-9);
    }

    #[test]
    fn success_counter_tracks_obs_ge_half() {
        let mut r = RelayReputation::new(0);
        r.record(ObservationEvent::FederationSyncSuccess, 1);
        r.record(ObservationEvent::HeartbeatOnTime, 2);
        r.record(ObservationEvent::HeartbeatMissed, 3);
        assert_eq!(r.successes, 2);
        assert_eq!(r.failures, 1);
    }

    #[test]
    fn malformed_counter_only_increments_for_malformed_events() {
        let mut r = RelayReputation::new(0);
        r.record(ObservationEvent::DescriptorSignatureInvalid, 1);
        r.record(ObservationEvent::ReplayedWithinWindow, 2);
        r.record(ObservationEvent::RateLimitExceeded, 3);
        // RateLimitExceeded is a failure but NOT malformed.
        assert_eq!(r.malformed_contrib, 2);
        assert_eq!(r.failures, 3);
    }

    #[test]
    fn suspect_requires_15_min_below_threshold() {
        let mut r = RelayReputation::new(0);
        // Drive score below 0.2 in one hit — repeated zero observations.
        for t in 0..30 {
            r.record(ObservationEvent::HeartbeatMissed, t);
        }
        assert!(r.score < SUSPECT_SCORE_THRESHOLD);
        // Only 30 s of dwell so far — not SUSPECT yet.
        assert!(!r.flags.contains(RelayFlags::SUSPECT));

        // Advance time past the 15-minute dwell without changing score.
        r.evaluate_flags(30 + SUSPECT_DWELL_SECS + 1);
        assert!(r.flags.contains(RelayFlags::SUSPECT));
    }

    #[test]
    fn suspect_clears_when_score_recovers() {
        let mut r = RelayReputation::new(0);
        for t in 0..30 {
            r.record(ObservationEvent::HeartbeatMissed, t);
        }
        r.evaluate_flags(30 + SUSPECT_DWELL_SECS + 1);
        assert!(r.flags.contains(RelayFlags::SUSPECT));

        // Recover with many successes.
        for t in 0..100 {
            r.record(
                ObservationEvent::FederationSyncSuccess,
                30 + SUSPECT_DWELL_SECS + 2 + t,
            );
        }
        assert!(r.score > SUSPECT_SCORE_THRESHOLD);
        assert!(!r.flags.contains(RelayFlags::SUSPECT));
    }

    #[test]
    fn ban_on_score_below_0_05() {
        let mut r = RelayReputation::new(0);
        for t in 0..100 {
            r.record(ObservationEvent::HeartbeatMissed, t);
        }
        assert!(r.score < BANNED_SCORE_THRESHOLD);
        assert!(r.flags.contains(RelayFlags::BANNED));
        assert!(r.banned_at.is_some());
    }

    #[test]
    fn ban_on_four_invalid_signatures_within_60s() {
        let mut r = RelayReputation::new(0);
        // 4 invalid sigs at t=0,10,20,30 — all within 60 s of each other.
        for t in [0u64, 10, 20, 30] {
            r.record(ObservationEvent::DescriptorSignatureInvalid, t);
        }
        assert_eq!(r.invalid_signatures_in_window(30), 4);
        assert!(r.flags.contains(RelayFlags::BANNED));
    }

    #[test]
    fn three_invalid_sigs_does_not_ban() {
        // MUST-035: "more than 3" means 4+ triggers ban; exactly 3 does not.
        let mut r = RelayReputation::new(0);
        for t in [0u64, 10, 20] {
            r.record(ObservationEvent::DescriptorSignatureInvalid, t);
        }
        assert_eq!(r.invalid_signatures_in_window(20), 3);
        // Score has decayed but is still above 0.05 after only 3 hits
        // starting from 0.5: 0.5 * 0.9^3 ≈ 0.3645.
        assert!(r.score > BANNED_SCORE_THRESHOLD);
        assert!(!r.flags.contains(RelayFlags::BANNED));
    }

    #[test]
    fn invalid_signatures_outside_window_do_not_count() {
        let mut r = RelayReputation::new(0);
        // Two invalid at t=0,10 then another 120 s later — window slides.
        r.record(ObservationEvent::DescriptorSignatureInvalid, 0);
        r.record(ObservationEvent::DescriptorSignatureInvalid, 10);
        assert_eq!(r.invalid_signatures_in_window(10), 2);
        assert_eq!(r.invalid_signatures_in_window(90), 0);
    }

    #[test]
    fn banned_cooldown_is_24_hours() {
        let mut r = RelayReputation::new(0);
        for t in 0..100 {
            r.record(ObservationEvent::HeartbeatMissed, t);
        }
        assert!(r.flags.contains(RelayFlags::BANNED));
        let banned_at = r.banned_at.unwrap();

        // Before cooldown expires, BAN stays even if score recovers.
        for t in 0..100 {
            r.record(
                ObservationEvent::FederationSyncSuccess,
                banned_at + 3600 + t,
            );
        }
        assert!(r.flags.contains(RelayFlags::BANNED));

        // After cooldown, BAN clears.
        r.evaluate_flags(banned_at + BANNED_COOLDOWN_SECS + 1);
        assert!(!r.flags.contains(RelayFlags::BANNED));
        assert!(r.banned_at.is_none());
    }

    #[test]
    fn stable_requires_seven_days_active_and_score_at_least_0_8() {
        let mut r = RelayReputation::new(0);
        // Pump score up.
        for t in 0..200 {
            r.record(ObservationEvent::FederationSyncSuccess, t);
        }
        assert!(r.score >= STABLE_SCORE_THRESHOLD);

        // Tick active for under 7 days → not STABLE yet.
        r.mark_active_tick(201);
        r.mark_active_tick(201 + 3600);
        assert!(!r.flags.contains(RelayFlags::STABLE));

        // Cross the 7-day threshold.
        r.mark_active_tick(201 + STABLE_ACTIVE_DWELL_SECS + 1);
        assert!(r.flags.contains(RelayFlags::STABLE));
    }

    #[test]
    fn stable_clears_on_active_end() {
        let mut r = RelayReputation::new(0);
        for t in 0..200 {
            r.record(ObservationEvent::FederationSyncSuccess, t);
        }
        r.mark_active_tick(201);
        r.mark_active_tick(201 + STABLE_ACTIVE_DWELL_SECS + 1);
        assert!(r.flags.contains(RelayFlags::STABLE));
        r.mark_active_end();
        assert!(!r.flags.contains(RelayFlags::STABLE));
        assert!(r.active_since.is_none());
    }

    #[test]
    fn eligibility_blocked_by_suspect_or_banned() {
        let mut r = RelayReputation::new(0);
        assert!(r.is_eligible_for_circuits());
        r.flags.insert(RelayFlags::SUSPECT);
        assert!(!r.is_eligible_for_circuits());
        r.flags.remove(RelayFlags::SUSPECT);
        r.flags.insert(RelayFlags::BANNED);
        assert!(!r.is_eligible_for_circuits());
    }

    #[test]
    fn persist_cadence_matches_spec() {
        let mut r = RelayReputation::new(0);
        assert!(!r.persist_due(60));
        assert!(r.persist_due(REPUTATION_PERSIST_INTERVAL_SECS));
        r.mark_persisted(REPUTATION_PERSIST_INTERVAL_SECS);
        assert!(!r.persist_due(REPUTATION_PERSIST_INTERVAL_SECS + 1));
    }

    #[test]
    fn serde_roundtrip_preserves_state() {
        let mut r = RelayReputation::new(0);
        for t in 0..10 {
            r.record(ObservationEvent::FederationSyncSuccess, t);
        }
        r.mark_active_tick(11);
        let mut bytes = Vec::new();
        ciborium::into_writer(&r, &mut bytes).unwrap();
        let back: RelayReputation = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back, r);
    }
}
