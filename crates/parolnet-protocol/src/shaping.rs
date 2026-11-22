//! Traffic shaping decisions (PNP-006): bandwidth modes, send timing, burst smoothing and
//! the choice between real, padding and dummy sends.
//!
//! Everything here is sans-I/O and has no clock of its own: the caller owns the timer and
//! the connection, asks [`SendScheduler::next_delay`] how long to wait and
//! [`SendScheduler::on_slot`] what to send when the wait is over. That keeps one
//! implementation for every sender: circuits (`parolnet-relay`), the native client's direct
//! data channels (`parolnet-app`) and anything compiled to WASM.

use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Duration;

/// Bandwidth modes (PNP-006 §3; `MediaCall` is PNP-007 §8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BandwidthMode {
    /// ~2 KB/s idle, 5% dummy traffic, 2s padding interval.
    Low,
    /// ~8 KB/s idle, 20% dummy traffic, 500ms padding interval. The default
    /// (PNP-006-MUST-003).
    #[default]
    Normal,
    /// ~40 KB/s idle, 40% dummy traffic, 100ms padding interval.
    High,
    /// ~50 cells/s, no burst smoothing, audio-sized padding.
    MediaCall,
}

impl BandwidthMode {
    /// The modes a user chooses between (PNP-006-MUST-001 / MUST-002). `MediaCall` is not
    /// one of them: a call switches its own circuit to it (PNP-007 §8).
    pub const SELECTABLE: [BandwidthMode; 3] = [Self::Low, Self::Normal, Self::High];

    pub fn padding_interval(self) -> Duration {
        match self {
            Self::Low => Duration::from_millis(2000),
            Self::Normal => Duration::from_millis(500),
            Self::High => Duration::from_millis(100),
            Self::MediaCall => Duration::from_millis(20),
        }
    }

    pub fn jitter_max(self) -> Duration {
        match self {
            Self::Low => Duration::from_millis(500),
            Self::Normal => Duration::from_millis(100),
            Self::High => Duration::from_millis(30),
            Self::MediaCall => Duration::from_millis(5),
        }
    }

    pub fn dummy_traffic_percent(self) -> u8 {
        match self {
            Self::Low => 5,
            Self::Normal => 20,
            Self::High => 40,
            Self::MediaCall => 10,
        }
    }

    /// The idle bandwidth of the mode in KB/s (the "Max Bandwidth" column of PNP-006 §3;
    /// PNP-007 §8 for `MediaCall`).
    pub fn idle_bandwidth_kb_per_s(self) -> u32 {
        match self {
            Self::Low => 2,
            Self::Normal => 8,
            Self::High => 40,
            Self::MediaCall => 400,
        }
    }

    /// The mode's name in settings and configuration files.
    pub fn name(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
            Self::MediaCall => "mediacall",
        }
    }

    /// The mode a settings value names (case does not matter).
    pub fn from_name(name: &str) -> Option<BandwidthMode> {
        [Self::Low, Self::Normal, Self::High, Self::MediaCall]
            .into_iter()
            .find(|m| m.name().eq_ignore_ascii_case(name.trim()))
    }

    /// What the user is told about this mode's bandwidth before or when they choose it
    /// (PNP-006-MUST-042). The numbers are the mode's own, so the text cannot drift from
    /// what the scheduler does.
    pub fn bandwidth_warning(self) -> String {
        let interval = self.padding_interval().as_millis();
        let kb = self.idle_bandwidth_kb_per_s();
        let advice = match self {
            Self::Low => "Suited to metered and mobile connections; it hides the least.",
            Self::Normal => "Suited to broadband connections.",
            Self::High => {
                "This uses data all the time and can be costly on a metered connection; it \
                 hides the most."
            }
            Self::MediaCall => "Used only while a call is under way.",
        };
        format!(
            "{} mode: cover traffic uses about {kb} KB/s even when you send nothing, and \
             messages leave at most one every {interval} ms. {advice}",
            self.name().to_ascii_uppercase()
        )
    }
}

/// What goes out at one send opportunity (PNP-006-MUST-010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendChoice<T> {
    /// A queued real message: it takes the slot, and nothing else is sent with it
    /// (PNP-006-MUST-005).
    Real(T),
    /// A plain padding cell (PNP-004 §3.9).
    Padding,
    /// A dummy message: a complete message that goes the whole way like a real one and is
    /// recognised only by its final recipient (PNP-006 §4.3).
    Dummy,
}

/// The queue depth above which the send rate may double (PNP-006-MAY-001).
pub const BURST_QUEUE_DEPTH: usize = 32;
/// How long the doubled rate may last (PNP-006-MAY-001).
pub const BURST_MAX: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Burst {
    /// The doubled rate has not been used since the queue was last short.
    Ready,
    /// Sending at the doubled rate; `left` of the five seconds remain.
    Active { left: Duration },
    /// The five seconds are used up; the base rate applies until the queue is short again.
    Spent,
}

/// The sender's side of PNP-006 §4.1 to §4.4 for one connection: a FIFO queue drained one
/// message per slot, slots one padding interval (plus jitter) apart, and the choice of what
/// an empty slot carries.
///
/// `R` is the random source of the jitter and of the dummy / padding choice. It must be
/// cryptographically secure (PNP-006-MUST-020), which the bound states; [`SendScheduler::new`]
/// uses the operating system's generator.
pub struct SendScheduler<T, R = OsRng> {
    mode: BandwidthMode,
    cover: bool,
    rng: R,
    queue: VecDeque<T>,
    /// How many entries at the head of `queue` are priority messages.
    priority: usize,
    burst: Burst,
    cadence: Option<Cadence>,
}

impl<T> SendScheduler<T, OsRng> {
    /// A scheduler with cover traffic on, drawing from the operating system's CSPRNG.
    pub fn new(mode: BandwidthMode) -> Self {
        Self::with_rng(mode, OsRng)
    }
}

impl<T, R: RngCore + CryptoRng> SendScheduler<T, R> {
    /// A scheduler with cover traffic on that draws its randomness from `rng`.
    pub fn with_rng(mode: BandwidthMode, rng: R) -> Self {
        SendScheduler {
            mode,
            cover: true,
            rng,
            queue: VecDeque::new(),
            priority: 0,
            burst: Burst::Ready,
            cadence: None,
        }
    }

    pub fn mode(&self) -> BandwidthMode {
        self.mode
    }

    /// Change the bandwidth mode; it applies from the next slot.
    pub fn set_mode(&mut self, mode: BandwidthMode) {
        self.mode = mode;
    }

    /// Whether an empty slot carries padding or a dummy (on) or nothing at all (off).
    /// Off is for a link where cover traffic has no meaning: a direct peer-to-peer path
    /// (PNP-006-SHOULD-015).
    pub fn set_cover(&mut self, on: bool) {
        self.cover = on;
    }

    pub fn cover(&self) -> bool {
        self.cover
    }

    /// Shape sends into the request-response cadence of `profile` (PNP-006 §4.6) instead of
    /// the constant padding rate; `None` returns to the constant rate.
    pub fn set_traffic_profile(&mut self, profile: Option<TrafficProfile>) {
        self.cadence = profile.map(|profile| Cadence {
            profile,
            left_in_burst: 0,
        });
    }

    /// Queue a message behind everything already waiting (PNP-006-MUST-008 / MUST-009).
    pub fn push(&mut self, message: T) {
        self.queue.push_back(message);
    }

    /// Queue a priority message (a DESTROY cell, a key exchange message): it goes ahead of
    /// the ordinary messages and behind earlier priority ones (PNP-006-MAY-002).
    pub fn push_priority(&mut self, message: T) {
        self.queue.insert(self.priority, message);
        self.priority += 1;
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Take everything still queued, in the order it would have been sent.
    pub fn drain(&mut self) -> Vec<T> {
        self.priority = 0;
        self.queue.drain(..).collect()
    }

    /// Use the scheduler's random source for something that belongs to the same send (the
    /// bytes of a dummy message).
    pub fn with_rng_mut<O>(&mut self, f: impl FnOnce(&mut R) -> O) -> O {
        f(&mut self.rng)
    }

    /// One jitter value: uniform over `[0, J_max]` of the mode, drawn afresh on every call
    /// (PNP-006-MUST-019 / MUST-021).
    pub fn jitter(&mut self) -> Duration {
        let max = self.mode.jitter_max().as_micros() as u64;
        Duration::from_micros(self.rng.gen_range(0..=max))
    }

    /// How long to wait before the next slot.
    ///
    /// `since_last_send` is the time since this connection last sent anything, `None` when
    /// it never has. The wait is what is left of the padding interval plus a fresh jitter
    /// (PNP-006-MUST-006 / MUST-018): right after a send that is the whole interval, on a
    /// link that has been quiet for longer it is the jitter alone.
    ///
    /// While more than [`BURST_QUEUE_DEPTH`] messages wait, the interval is halved for at
    /// most [`BURST_MAX`] (PNP-006-MAY-001).
    pub fn next_delay(&mut self, since_last_send: Option<Duration>) -> Duration {
        self.next_delay_with_backlog(since_last_send, 0)
    }

    /// As [`next_delay`](Self::next_delay), counting `extra` messages that wait outside this
    /// scheduler's own queue (a caller that keeps its content queue elsewhere).
    pub fn next_delay_with_backlog(
        &mut self,
        since_last_send: Option<Duration>,
        extra: usize,
    ) -> Duration {
        let base = self.base_interval(extra);
        let elapsed = since_last_send.unwrap_or(Duration::MAX);
        base.saturating_sub(elapsed) + self.jitter()
    }

    fn base_interval(&mut self, extra: usize) -> Duration {
        if let Some(cadence) = &mut self.cadence {
            return cadence.next_gap(&mut self.rng);
        }
        let interval = self.mode.padding_interval();
        let depth = self.queue.len() + extra;
        match self.burst {
            Burst::Ready if depth > BURST_QUEUE_DEPTH => {
                self.burst = Burst::Active { left: BURST_MAX };
            }
            Burst::Spent if depth <= BURST_QUEUE_DEPTH => self.burst = Burst::Ready,
            Burst::Active { .. } if depth == 0 => self.burst = Burst::Ready,
            _ => {}
        }
        match self.burst {
            Burst::Active { left } => {
                let half = interval / 2;
                // The worst case of this slot must still fit in what is left of the burst.
                let worst = half + self.mode.jitter_max();
                if left < worst {
                    self.burst = Burst::Spent;
                    interval
                } else {
                    self.burst = Burst::Active { left: left - worst };
                    half
                }
            }
            _ => interval,
        }
    }

    /// What this slot carries. A queued real message always takes it; an empty slot carries
    /// a dummy in the mode's share of cases and padding otherwise (PNP-006-MUST-011), or
    /// nothing when cover traffic is off.
    pub fn on_slot(&mut self) -> Option<SendChoice<T>> {
        if let Some(message) = self.queue.pop_front() {
            self.priority = self.priority.saturating_sub(1);
            return Some(SendChoice::Real(message));
        }
        if !self.cover {
            return None;
        }
        let percent = u32::from(self.mode.dummy_traffic_percent());
        if self.rng.gen_range(0..100u32) < percent {
            Some(SendChoice::Dummy)
        } else {
            Some(SendChoice::Padding)
        }
    }
}

// ── Request-response cadence (PNP-006 §4.6) ───────────────────────

/// A traffic profile: the request-response cadence a connection is shaped into
/// (PNP-006-SHOULD-003). It is data, loaded from a file (CBOR, see
/// [`TrafficProfile::from_cbor`]), so it can change without a software release
/// (PNP-006-SHOULD-004).
///
/// Every range is `[min, max]`, both inclusive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficProfile {
    pub name: String,
    /// Cells in an ordinary burst (an HTTP/2 request and its pushes).
    pub burst_cells: [u32; 2],
    /// The quiet period after a burst, in milliseconds ("reading time").
    pub quiet_ms: [u64; 2],
    /// Cells in a large burst (a page load).
    pub page_load_cells: [u32; 2],
    /// The share of bursts that are page loads, in percent.
    pub page_load_percent: u8,
    /// The gap between two cells of one burst, in milliseconds.
    pub intra_burst_ms: [u64; 2],
}

/// Why a traffic profile was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrafficProfileError {
    #[error("not a CBOR traffic profile: {0}")]
    Decode(String),
    #[error("traffic profile field {0} is not a usable range")]
    Range(&'static str),
}

impl TrafficProfile {
    /// The built-in profile: the numbers of PNP-006 §4.6.
    pub fn browsing() -> TrafficProfile {
        TrafficProfile {
            name: "browsing".into(),
            burst_cells: [2, 8],
            quiet_ms: [1_000, 10_000],
            page_load_cells: [20, 50],
            page_load_percent: 10,
            intra_burst_ms: [5, 40],
        }
    }

    /// Decode a profile file and check its ranges.
    pub fn from_cbor(bytes: &[u8]) -> Result<TrafficProfile, TrafficProfileError> {
        let profile: TrafficProfile =
            ciborium::from_reader(bytes).map_err(|e| TrafficProfileError::Decode(e.to_string()))?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Writing a plain struct to a Vec cannot fail.
        let _ = ciborium::into_writer(self, &mut out);
        out
    }

    pub fn validate(&self) -> Result<(), TrafficProfileError> {
        if self.burst_cells[0] == 0 || self.burst_cells[0] > self.burst_cells[1] {
            return Err(TrafficProfileError::Range("burst_cells"));
        }
        if self.page_load_cells[0] == 0 || self.page_load_cells[0] > self.page_load_cells[1] {
            return Err(TrafficProfileError::Range("page_load_cells"));
        }
        if self.quiet_ms[0] > self.quiet_ms[1] {
            return Err(TrafficProfileError::Range("quiet_ms"));
        }
        if self.intra_burst_ms[0] > self.intra_burst_ms[1] {
            return Err(TrafficProfileError::Range("intra_burst_ms"));
        }
        if self.page_load_percent > 100 {
            return Err(TrafficProfileError::Range("page_load_percent"));
        }
        Ok(())
    }
}

struct Cadence {
    profile: TrafficProfile,
    /// Cells of the current burst that have not been sent yet.
    left_in_burst: u32,
}

impl Cadence {
    /// The gap before the next cell: short inside a burst, a quiet period between bursts.
    fn next_gap<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Duration {
        let p = &self.profile;
        if self.left_in_burst > 0 {
            self.left_in_burst -= 1;
            return Duration::from_millis(rng.gen_range(p.intra_burst_ms[0]..=p.intra_burst_ms[1]));
        }
        let cells = if rng.gen_range(0..100u32) < u32::from(p.page_load_percent) {
            rng.gen_range(p.page_load_cells[0]..=p.page_load_cells[1])
        } else {
            rng.gen_range(p.burst_cells[0]..=p.burst_cells[1])
        };
        // This gap leads to the burst's first cell; the rest follow closely.
        self.left_in_burst = cells - 1;
        Duration::from_millis(rng.gen_range(p.quiet_ms[0]..=p.quiet_ms[1]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_messages_keep_their_own_order() {
        let mut s: SendScheduler<u8> = SendScheduler::new(BandwidthMode::Normal);
        s.push(1);
        s.push_priority(10);
        s.push(2);
        s.push_priority(11);
        let order: Vec<u8> = std::iter::from_fn(|| match s.on_slot() {
            Some(SendChoice::Real(m)) => Some(m),
            _ => None,
        })
        .take(4)
        .collect();
        assert_eq!(order, [10, 11, 1, 2]);
    }

    #[test]
    fn a_quiet_link_waits_for_the_jitter_alone() {
        let mut s: SendScheduler<u8> = SendScheduler::new(BandwidthMode::Normal);
        for _ in 0..100 {
            assert!(s.next_delay(None) <= BandwidthMode::Normal.jitter_max());
            assert!(
                s.next_delay(Some(Duration::from_secs(60))) <= BandwidthMode::Normal.jitter_max()
            );
        }
    }

    #[test]
    fn the_doubled_rate_ends_after_five_seconds() {
        let mut s: SendScheduler<u32> = SendScheduler::new(BandwidthMode::Normal);
        for i in 0..1000 {
            s.push(i);
        }
        let interval = BandwidthMode::Normal.padding_interval();
        let mut fast = Duration::ZERO;
        let mut slow_seen = false;
        for _ in 0..200 {
            let d = s.next_delay(Some(Duration::ZERO));
            s.on_slot();
            if d < interval {
                assert!(
                    !slow_seen,
                    "the doubled rate came back while the queue was long"
                );
                fast += d;
            } else {
                slow_seen = true;
            }
        }
        assert!(slow_seen);
        assert!(fast <= BURST_MAX, "doubled for {fast:?}");
    }

    #[test]
    fn a_bad_traffic_profile_is_refused() {
        let mut p = TrafficProfile::browsing();
        p.burst_cells = [9, 2];
        assert_eq!(
            TrafficProfile::from_cbor(&p.to_cbor()),
            Err(TrafficProfileError::Range("burst_cells"))
        );
        assert!(TrafficProfile::from_cbor(b"junk").is_err());
    }
}
