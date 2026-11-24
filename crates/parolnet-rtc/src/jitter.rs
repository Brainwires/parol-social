//! De-jittering received audio: packets leave in sequence order on the sender's clock.
//!
//! The network delivers RTP packets late by varying amounts and sometimes out of order. A
//! decoder that is fed them as they come plays gaps and scrambled audio. This buffer holds
//! each packet until its playout time: the time it would have arrived over the path's
//! shortest delay, plus a hold that follows how late packets have recently been
//! ([`AudioJitterBuffer::hold`]). On a steady path the hold is a few milliseconds; with 100 ms
//! of jitter it grows to cover it, and shrinks again when the path calms down.
//!
//! Only audio goes through it. Video is reassembled per frame by the receiver's sample
//! builder, which reorders by itself and must still see retransmissions that arrive long
//! after their neighbours.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use rtci::rtp::Packet;

/// Added on top of the measured lateness.
const MARGIN: Duration = Duration::from_millis(5);
/// The hold never exceeds this: later packets are dropped, as a listener prefers a short gap
/// to a conversation half a second behind.
const MAX_HOLD: Duration = Duration::from_millis(400);
/// How far back lateness is remembered.
const WINDOW: Duration = Duration::from_secs(4);
/// The most packets held (two seconds of 20 ms frames, more than `MAX_HOLD` ever needs).
const CAPACITY: usize = 100;

/// One stream's buffer.
#[derive(Debug)]
pub struct AudioJitterBuffer {
    clock_rate: u32,
    /// Extended sequence number → packet.
    held: BTreeMap<u64, Packet>,
    /// The highest extended sequence number seen (for extending the 16-bit ones).
    highest: Option<u64>,
    /// The last sequence number released: older ones are too late.
    released: Option<u64>,
    /// A packet's RTP timestamp and arrival, such that no later packet arrived earlier
    /// relative to its timestamp: the path's shortest delay so far.
    anchor: Option<(u32, Instant)>,
    /// Recent (arrival, lateness) samples.
    lateness: VecDeque<(Instant, Duration)>,
    hold: Duration,
    late_drops: u64,
}

impl AudioJitterBuffer {
    pub fn new(clock_rate: u32) -> Self {
        AudioJitterBuffer {
            clock_rate: clock_rate.max(1),
            held: BTreeMap::new(),
            highest: None,
            released: None,
            anchor: None,
            lateness: VecDeque::new(),
            hold: MARGIN,
            late_drops: 0,
        }
    }

    /// How long packets are held past their earliest possible arrival.
    pub fn hold(&self) -> Duration {
        self.hold
    }

    /// Packets that arrived after their successors had been released.
    pub fn late_drops(&self) -> u64 {
        self.late_drops
    }

    fn extend(&mut self, seq: u16) -> u64 {
        let extended = match self.highest {
            None => u64::from(seq) + (1 << 32),
            Some(highest) => {
                let delta = seq.wrapping_sub(highest as u16) as i16;
                highest.wrapping_add_signed(i64::from(delta))
            }
        };
        if self.highest.is_none_or(|h| extended > h) {
            self.highest = Some(extended);
        }
        extended
    }

    /// When a packet with this timestamp arrives over the shortest delay seen so far.
    fn on_time(&self, timestamp: u32) -> Option<Instant> {
        let (anchor_ts, anchor_at) = self.anchor?;
        let ticks = i64::from(timestamp.wrapping_sub(anchor_ts) as i32);
        let offset =
            Duration::from_secs_f64(ticks.unsigned_abs() as f64 / f64::from(self.clock_rate));
        Some(if ticks >= 0 {
            anchor_at + offset
        } else {
            anchor_at.checked_sub(offset).unwrap_or(anchor_at)
        })
    }

    /// Take a packet that arrived at `now`.
    pub fn push(&mut self, now: Instant, packet: Packet) {
        let seq = self.extend(packet.header.sequence_number);
        let timestamp = packet.header.timestamp;
        let expected = match self.on_time(timestamp) {
            Some(expected) if expected <= now => expected,
            // The first packet, or one earlier than anything before it: the shortest delay
            // is this one's now, and every held packet's time moves with it.
            _ => {
                self.anchor = Some((timestamp, now));
                now
            }
        };
        let late = now.saturating_duration_since(expected);
        self.lateness.push_back((now, late));
        while self
            .lateness
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > WINDOW)
        {
            self.lateness.pop_front();
        }
        let worst = self
            .lateness
            .iter()
            .map(|(_, late)| *late)
            .max()
            .unwrap_or_default();
        let wanted = (worst + MARGIN).min(MAX_HOLD);
        // Up at once (the packets already held are covered too), down slowly: a shorter hold
        // moves every playout time earlier, which is heard as a skip.
        self.hold = if wanted >= self.hold {
            wanted
        } else {
            self.hold - (self.hold - wanted) / 50
        };

        if self.released.is_some_and(|released| seq <= released) {
            self.late_drops += 1;
            return;
        }
        self.held.entry(seq).or_insert(packet);
    }

    fn release_time(&self, packet: &Packet) -> Option<Instant> {
        Some(self.on_time(packet.header.timestamp)? + self.hold)
    }

    /// The next packet whose playout time has come, in sequence order.
    pub fn pop(&mut self, now: Instant) -> Option<Packet> {
        let (&seq, packet) = self.held.first_key_value()?;
        // The next one in sequence leaves at its time; so does one after a gap, whose missing
        // predecessors are given up at that moment. An overfull buffer (a burst after a
        // stall) lets its oldest go at once.
        if self.held.len() <= CAPACITY && self.release_time(packet).is_some_and(|at| at > now) {
            return None;
        }
        let packet = self.held.remove(&seq)?;
        self.released = Some(seq);
        Some(packet)
    }

    /// When [`AudioJitterBuffer::pop`] next has something, if anything is held.
    pub fn next_release(&self) -> Option<Instant> {
        self.held
            .first_key_value()
            .and_then(|(_, packet)| self.release_time(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(seq: u16) -> Packet {
        let mut p = Packet::default();
        p.header.sequence_number = seq;
        p.header.timestamp = 1000u32.wrapping_add(u32::from(seq.wrapping_sub(65_530)) * 960);
        p
    }

    /// Feed packets sent every 20 ms that arrive `delays[i]` after being sent; pop on a 1 ms
    /// clock. Returns (sequence number, release time since the first send) for each.
    fn run(buffer: &mut AudioJitterBuffer, delays: &[Option<u64>]) -> Vec<(u16, u64)> {
        let start = Instant::now();
        let mut arrivals: Vec<(u64, u16)> = delays
            .iter()
            .enumerate()
            .filter_map(|(i, d)| {
                let seq = 65_530u16.wrapping_add(i as u16);
                d.map(|d| (i as u64 * 20 + d, seq))
            })
            .collect();
        arrivals.sort();
        let mut out = Vec::new();
        let end = delays.len() as u64 * 20 + 1000;
        let mut next = 0;
        for ms in 0..end {
            let now = start + Duration::from_millis(ms);
            while next < arrivals.len() && arrivals[next].0 == ms {
                buffer.push(now, packet(arrivals[next].1));
                next += 1;
            }
            while let Some(p) = buffer.pop(now) {
                out.push((p.header.sequence_number, ms));
            }
        }
        out
    }

    #[test]
    fn a_steady_stream_passes_with_only_the_margin() {
        let mut buffer = AudioJitterBuffer::new(48_000);
        // Across the 16-bit wrap of the sequence number.
        let out = run(&mut buffer, &[Some(30); 200]);
        assert_eq!(out.len(), 200);
        for (i, (seq, at)) in out.iter().enumerate() {
            assert_eq!(*seq, 65_530u16.wrapping_add(i as u16));
            assert_eq!(*at, i as u64 * 20 + 30 + 5, "packet {i}");
        }
        assert_eq!(buffer.hold(), MARGIN);
        assert_eq!(buffer.late_drops(), 0);
    }

    #[test]
    fn jitter_and_reordering_come_out_in_order_and_evenly_spaced() {
        // Delays between 30 and 130 ms, in an order that makes packets overtake each other.
        let mut state = 7u64;
        let delays: Vec<Option<u64>> = (0..500)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                Some(30 + (state >> 33) % 101)
            })
            .collect();
        let mut buffer = AudioJitterBuffer::new(48_000);
        let out = run(&mut buffer, &delays);
        // The first second is the buffer learning how late packets get; after it nothing is
        // dropped, everything is in order, and packets leave 20 ms apart.
        let settled: Vec<&(u16, u64)> = out.iter().filter(|(_, at)| *at > 1500).collect();
        assert!(settled.len() >= 400, "{}", settled.len());
        for pair in settled.windows(2) {
            assert_eq!(
                pair[1].0,
                pair[0].0.wrapping_add(1),
                "in order, none missing"
            );
            // 20 ms apart, give or take the hold's slow adjustments.
            let apart = pair[1].1 - pair[0].1;
            assert!((15..=25).contains(&apart), "evenly spaced: {apart} ms");
        }
        assert!(
            buffer.hold() >= Duration::from_millis(95)
                && buffer.hold() <= Duration::from_millis(110),
            "{:?}",
            buffer.hold()
        );
        assert!(buffer.late_drops() <= 10, "{}", buffer.late_drops());
    }

    #[test]
    fn a_lost_packet_is_skipped_at_its_time_and_a_too_late_one_is_dropped() {
        let mut delays = vec![Some(30); 100];
        delays[40] = None; // lost
        delays[60] = Some(30 + 300); // arrives long after its successors left
        let mut buffer = AudioJitterBuffer::new(48_000);
        let out = run(&mut buffer, &delays);
        let seqs: Vec<u16> = out.iter().map(|o| o.0.wrapping_sub(65_530)).collect();
        assert!(!seqs.contains(&40) && !seqs.contains(&60));
        assert_eq!(seqs.len(), 98);
        assert!(seqs.windows(2).all(|w| w[1] > w[0]));
        // The packet after the lost one left at its own time, not later.
        let after = out.iter().find(|o| o.0.wrapping_sub(65_530) == 41).unwrap();
        assert_eq!(after.1, 41 * 20 + 30 + 5);
        assert_eq!(buffer.late_drops(), 1);
        // The late arrival raised the hold; it never exceeds the maximum.
        assert!(buffer.hold() > MARGIN && buffer.hold() <= MAX_HOLD);
    }

    #[test]
    fn the_hold_comes_down_again_when_the_path_calms() {
        let mut delays: Vec<Option<u64>> = (0..100).map(|i| Some(30 + (i * 37) % 90)).collect();
        delays.extend(std::iter::repeat_n(Some(30), 600));
        let mut buffer = AudioJitterBuffer::new(48_000);
        let out = run(&mut buffer, &delays);
        assert!(
            buffer.hold() < Duration::from_millis(20),
            "{:?}",
            buffer.hold()
        );
        assert!(out.len() >= 690);
    }

    #[test]
    fn a_path_that_gets_shorter_moves_the_anchor() {
        // 80 ms at first, then 20 ms: the later packets define "on time".
        let mut delays = vec![Some(80); 50];
        delays.extend(std::iter::repeat_n(Some(20), 300));
        let mut buffer = AudioJitterBuffer::new(48_000);
        let out = run(&mut buffer, &delays);
        let last = out.last().unwrap();
        let sent = u64::from(last.0.wrapping_sub(65_530)) * 20;
        assert!(
            last.1 - sent < 20 + 15,
            "released {} ms after sending",
            last.1 - sent
        );
        // The first packets over the short path overtook the last ones over the long path:
        // those few are given up, once, and the order is kept throughout.
        assert!(
            out.windows(2)
                .all(|w| w[1].0.wrapping_sub(w[0].0) as i16 > 0)
        );
        assert!(out.len() >= 350 - 4, "{}", out.len());
        assert!(buffer.late_drops() <= 4);
    }
}
