//! Re-probing contacts the relay called offline (PNP-001 §10.5, client behaviour).
//!
//! The relay pushes presence only between mutual watchers, and keeps at most 256 watched
//! ids. A contact who does not watch us back (yet), one beyond that limit, or one whose
//! presence push we missed is only known to be offline from the `peer_offline` answer to an
//! offer. That verdict goes stale silently, so it is soft: the contact is offered to again
//! with exponential backoff and jitter, whether or not messages wait for it. An offline
//! verdict from a presence push is not handled here: the relay will tell us when it changes.
//!
//! Every probe is an `rtc_offer`, which the relay meters (60 a minute and 240 an hour per
//! sender), so all probes together draw on one token bucket sized well under that.
//!
//! Pure scheduling: the caller passes the time and the jitter, which keeps it testable.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// The relay's hourly cap on signaling frames per sender (PNP-001-MUST-074).
pub const RELAY_SIGNALING_PER_HOUR: u32 = 240;

/// Jitter added to every delay: up to this share of it.
const JITTER: f64 = 0.25;

/// How contacts believed offline are re-probed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectConfig {
    /// The delay before the first probe after a `peer_offline` answer.
    pub first_probe: Duration,
    /// The longest delay between probes of a contact the user is waiting for: messages are
    /// queued for it, or the user asked to connect to it.
    pub max_probe_active: Duration,
    /// The longest delay between probes of any other contact.
    pub max_probe_idle: Duration,
    /// Probes that may go out in a burst (the token bucket's size).
    pub probe_burst: u32,
    /// One more probe is allowed per this interval.
    pub probe_refill: Duration,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        ReconnectConfig {
            first_probe: Duration::from_secs(15),
            max_probe_active: Duration::from_secs(5 * 60),
            max_probe_idle: Duration::from_secs(15 * 60),
            probe_burst: 12,
            probe_refill: Duration::from_secs(60),
        }
    }
}

impl ReconnectConfig {
    /// The delay before probe number `probes_sent` (0 for the first): `first_probe` doubled
    /// each time up to the cap for the contact's kind, plus `jitter` (0.0..1.0) of a quarter.
    pub fn probe_delay(&self, probes_sent: u32, active: bool, jitter: f64) -> Duration {
        let cap = if active {
            self.max_probe_active
        } else {
            self.max_probe_idle
        };
        let base = self
            .first_probe
            .saturating_mul(1u32 << probes_sent.min(20))
            .min(cap.max(self.first_probe));
        base + base.mul_f64(JITTER * jitter.clamp(0.0, 1.0))
    }

    /// The most probes that can go out in any one hour.
    pub fn max_probes_per_hour(&self) -> u32 {
        let refill = self.probe_refill.as_secs_f64().max(0.001);
        self.probe_burst
            .saturating_add((3600.0 / refill).ceil() as u32)
    }
}

/// A token bucket for probes.
#[derive(Debug)]
struct Budget {
    tokens: f64,
    capacity: f64,
    refill: Duration,
    last: Instant,
}

impl Budget {
    fn new(cfg: &ReconnectConfig, now: Instant) -> Budget {
        let capacity = f64::from(cfg.probe_burst.max(1));
        Budget {
            tokens: capacity,
            capacity,
            refill: cfg.probe_refill.max(Duration::from_millis(1)),
            last: now,
        }
    }

    fn fill(&mut self, now: Instant) {
        let gained =
            now.saturating_duration_since(self.last).as_secs_f64() / self.refill.as_secs_f64();
        self.tokens = (self.tokens + gained).min(self.capacity);
        self.last = now;
    }

    fn try_take(&mut self, now: Instant) -> bool {
        self.fill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// When a token will be there (now, if one is).
    fn available_at(&mut self, now: Instant) -> Instant {
        self.fill(now);
        if self.tokens >= 1.0 {
            now
        } else {
            now + self.refill.mul_f64(1.0 - self.tokens)
        }
    }
}

#[derive(Debug)]
struct Entry {
    /// The last `peer_offline` answer or probe.
    last: Instant,
    /// Probes sent since the backoff started.
    probes: u32,
    /// This round's jitter, 0.0..1.0.
    jitter: f64,
}

/// Which soft-offline contacts to probe, and when.
#[derive(Debug)]
pub struct ProbeSchedule {
    cfg: ReconnectConfig,
    entries: HashMap<String, Entry>,
    budget: Budget,
}

impl ProbeSchedule {
    pub fn new(cfg: ReconnectConfig, now: Instant) -> ProbeSchedule {
        ProbeSchedule {
            budget: Budget::new(&cfg, now),
            cfg,
            entries: HashMap::new(),
        }
    }

    /// The relay answered an offer to `peer` with `peer_offline`: start its backoff, or (the
    /// answer to a probe) count the next delay from now.
    pub fn note_offline(&mut self, peer: &str, now: Instant, jitter: f64) {
        match self.entries.get_mut(peer) {
            Some(e) => e.last = now,
            None => {
                self.entries.insert(
                    peer.to_owned(),
                    Entry {
                        last: now,
                        probes: 0,
                        jitter,
                    },
                );
            }
        }
    }

    /// The user asked for `peer` now: its backoff starts over (the caller offers at once).
    pub fn restart(&mut self, peer: &str, now: Instant) {
        if let Some(e) = self.entries.get_mut(peer) {
            e.last = now;
            e.probes = 0;
        }
    }

    /// `peer` is no longer soft-offline (a presence push, an offer or answer from it, an open
    /// channel, or it is no contact any more).
    pub fn clear(&mut self, peer: &str) {
        self.entries.remove(peer);
    }

    pub fn is_scheduled(&self, peer: &str) -> bool {
        self.entries.contains_key(peer)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn due_at(&self, e: &Entry, active: bool) -> Instant {
        e.last + self.cfg.probe_delay(e.probes, active, e.jitter)
    }

    /// The contacts to probe now, at most as many as the budget allows: those the user waits
    /// for first, then the longest overdue. `ready` says a contact can be offered to (no
    /// attempt is under way); `jitter` draws 0.0..1.0 for the next round of each one taken.
    pub fn take_due(
        &mut self,
        now: Instant,
        active: impl Fn(&str) -> bool,
        ready: impl Fn(&str) -> bool,
        mut jitter: impl FnMut() -> f64,
    ) -> Vec<String> {
        let mut due: Vec<(bool, Instant, String)> = self
            .entries
            .iter()
            .filter_map(|(peer, e)| {
                let is_active = active(peer);
                let at = self.due_at(e, is_active);
                (at <= now && ready(peer)).then(|| (!is_active, at, peer.clone()))
            })
            .collect();
        due.sort();
        let mut taken = Vec::new();
        for (_, _, peer) in due {
            if !self.budget.try_take(now) {
                break;
            }
            if let Some(e) = self.entries.get_mut(&peer) {
                e.last = now;
                e.probes = e.probes.saturating_add(1);
                e.jitter = jitter();
            }
            taken.push(peer);
        }
        taken
    }

    /// When [`Self::take_due`] next has something to return: the earliest due time of a
    /// ready contact, not before the budget has a token. `None` with nothing to probe.
    pub fn next_wake(
        &mut self,
        now: Instant,
        active: impl Fn(&str) -> bool,
        ready: impl Fn(&str) -> bool,
    ) -> Option<Instant> {
        let earliest = self
            .entries
            .iter()
            .filter(|(peer, _)| ready(peer))
            .map(|(peer, e)| self.due_at(e, active(peer)))
            .min()?;
        Some(earliest.max(self.budget.available_at(now)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn schedule(now: Instant) -> ProbeSchedule {
        ProbeSchedule::new(ReconnectConfig::default(), now)
    }

    #[test]
    fn delays_double_to_the_cap_of_the_contacts_kind() {
        let cfg = ReconnectConfig::default();
        let active: Vec<u64> = (0..8)
            .map(|n| cfg.probe_delay(n, true, 0.0).as_secs())
            .collect();
        assert_eq!(active, vec![15, 30, 60, 120, 240, 300, 300, 300]);
        let idle: Vec<u64> = (0..8)
            .map(|n| cfg.probe_delay(n, false, 0.0).as_secs())
            .collect();
        assert_eq!(idle, vec![15, 30, 60, 120, 240, 480, 900, 900]);
        // Jitter adds up to a quarter, never subtracts.
        assert_eq!(cfg.probe_delay(0, true, 1.0), secs(15) + secs(15) / 4);
        assert!(cfg.probe_delay(3, false, 0.5) > secs(120));
        assert!(cfg.probe_delay(3, false, 0.5) < secs(150));
        // Huge counts do not overflow.
        assert_eq!(cfg.probe_delay(u32::MAX, false, 0.0), secs(900));
    }

    #[test]
    fn the_default_budget_stays_well_under_the_relays_hourly_cap() {
        let cfg = ReconnectConfig::default();
        assert!(cfg.max_probes_per_hour() <= RELAY_SIGNALING_PER_HOUR / 3);
        // Drive a busy hour: 200 offline contacts, probing as fast as allowed.
        let t0 = Instant::now();
        let mut s = ProbeSchedule::new(cfg.clone(), t0);
        for i in 0..200 {
            s.note_offline(&format!("p{i}"), t0, 0.0);
        }
        let mut sent = 0;
        for step in 0..=3600 {
            let now = t0 + secs(step);
            sent += s.take_due(now, |_| true, |_| true, || 0.0).len();
        }
        assert!(sent as u32 <= cfg.max_probes_per_hour(), "{sent}");
        assert!(sent >= 60, "the budget is used: {sent}");
    }

    #[test]
    fn a_contact_is_probed_with_backoff_whether_or_not_it_is_active() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        s.note_offline("idle", t0, 0.0);
        assert!(
            s.take_due(t0 + secs(14), |_| false, |_| true, || 0.0)
                .is_empty()
        );
        assert_eq!(
            s.take_due(t0 + secs(15), |_| false, |_| true, || 0.0),
            vec!["idle".to_owned()]
        );
        // The relay answers the probe with peer_offline: 30 s from then.
        let t1 = t0 + secs(16);
        s.note_offline("idle", t1, 0.0);
        assert!(
            s.take_due(t1 + secs(29), |_| false, |_| true, || 0.0)
                .is_empty()
        );
        assert_eq!(
            s.take_due(t1 + secs(30), |_| false, |_| true, || 0.0).len(),
            1
        );
        // A probe that got no answer at all still backs off (60 s after it went out).
        let t2 = t1 + secs(30);
        assert!(
            s.take_due(t2 + secs(59), |_| false, |_| true, || 0.0)
                .is_empty()
        );
        assert_eq!(
            s.take_due(t2 + secs(60), |_| false, |_| true, || 0.0).len(),
            1
        );
    }

    #[test]
    fn becoming_active_shortens_a_long_idle_wait() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        s.note_offline("p", t0, 0.0);
        let mut now = t0;
        // Seven probes: the idle delay is at its 15 min cap.
        for n in 0..7 {
            now += ReconnectConfig::default().probe_delay(n, false, 0.0);
            assert_eq!(s.take_due(now, |_| false, |_| true, || 0.0).len(), 1, "{n}");
        }
        let later = now + secs(5 * 60);
        assert!(s.take_due(later, |_| false, |_| true, || 0.0).is_empty());
        // A message is queued for it: the 5 min cap applies to the same wait.
        assert_eq!(s.take_due(later, |_| true, |_| true, || 0.0).len(), 1);
    }

    #[test]
    fn restart_and_clear() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        s.note_offline("p", t0, 0.0);
        let mut now = t0;
        for n in 0..4 {
            now += ReconnectConfig::default().probe_delay(n, true, 0.0);
            assert_eq!(s.take_due(now, |_| true, |_| true, || 0.0).len(), 1);
        }
        // The user presses retry: the next automatic probe is the first delay away again.
        s.restart("p", now);
        assert!(
            s.take_due(now + secs(14), |_| true, |_| true, || 0.0)
                .is_empty()
        );
        assert_eq!(
            s.take_due(now + secs(15), |_| true, |_| true, || 0.0).len(),
            1
        );
        // A presence push or a connection ends the probing.
        s.clear("p");
        assert!(!s.is_scheduled("p"));
        assert!(
            s.take_due(now + secs(3600), |_| true, |_| true, || 0.0)
                .is_empty()
        );
        assert_eq!(s.next_wake(now, |_| true, |_| true), None);
        // Restarting or clearing an unknown peer is a no-op.
        s.restart("nobody", now);
        s.clear("nobody");
        assert!(s.is_empty());
    }

    #[test]
    fn the_budget_serves_waited_for_contacts_first() {
        let t0 = Instant::now();
        let cfg = ReconnectConfig {
            probe_burst: 3,
            ..Default::default()
        };
        let mut s = ProbeSchedule::new(cfg, t0);
        for p in ["idle-a", "idle-b", "wanted-a", "wanted-b", "idle-c"] {
            s.note_offline(p, t0, 0.0);
        }
        let now = t0 + secs(15);
        let taken = s.take_due(now, |p| p.starts_with("wanted"), |_| true, || 0.0);
        assert_eq!(taken.len(), 3);
        assert!(
            taken[..2].iter().all(|p| p.starts_with("wanted")),
            "{taken:?}"
        );
        // No token left: the rest wait for the refill, which next_wake names.
        assert!(s.take_due(now, |_| false, |_| true, || 0.0).is_empty());
        let wake = s.next_wake(now, |_| false, |_| true).unwrap();
        assert_eq!(wake, now + secs(60));
        assert_eq!(s.take_due(wake, |_| false, |_| true, || 0.0).len(), 1);
    }

    #[test]
    fn contacts_with_an_attempt_under_way_are_left_alone() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        s.note_offline("busy", t0, 0.0);
        s.note_offline("free", t0, 0.5);
        let now = t0 + secs(60);
        assert_eq!(
            s.take_due(now, |_| false, |p| p == "free", || 0.0),
            vec!["free".to_owned()]
        );
        // Only "busy" is due now, and it is not ready: nothing to wake for but "free".
        let wake = s.next_wake(now, |_| false, |p| p == "free").unwrap();
        assert_eq!(wake, now + secs(30));
        assert_eq!(s.next_wake(now, |_| false, |_| false), None);
        assert_eq!(s.len(), 2);
    }
}
