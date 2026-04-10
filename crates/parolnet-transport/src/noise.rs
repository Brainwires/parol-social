//! Traffic noise generation (PNP-006).
//!
//! Implements constant-rate padding, burst smoothing, dummy traffic
//! generation, and timing jitter to make traffic patterns
//! indistinguishable from normal HTTPS browsing.

use crate::traits::TrafficShaper;
use std::time::Duration;

/// Bandwidth modes (PNP-006 Section 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BandwidthMode {
    /// ~2 KB/s idle, 5% dummy traffic, 2s padding interval.
    Low,
    /// ~8 KB/s idle, 20% dummy traffic, 500ms padding interval.
    Normal,
    /// ~40 KB/s idle, 40% dummy traffic, 100ms padding interval.
    High,
}

impl BandwidthMode {
    pub fn padding_interval(self) -> Duration {
        match self {
            Self::Low => Duration::from_millis(2000),
            Self::Normal => Duration::from_millis(500),
            Self::High => Duration::from_millis(100),
        }
    }

    pub fn jitter_max(self) -> Duration {
        match self {
            Self::Low => Duration::from_millis(500),
            Self::Normal => Duration::from_millis(100),
            Self::High => Duration::from_millis(30),
        }
    }

    pub fn dummy_traffic_percent(self) -> u8 {
        match self {
            Self::Low => 5,
            Self::Normal => 20,
            Self::High => 40,
        }
    }
}

/// Standard traffic shaper implementing PNP-006 behavioral rules.
pub struct StandardShaper {
    pub mode: BandwidthMode,
}

impl TrafficShaper for StandardShaper {
    fn delay_before_send(&self) -> Duration {
        todo!("Compute delay with jitter")
    }

    fn dummy_traffic_interval(&self) -> Option<Duration> {
        Some(self.mode.padding_interval())
    }

    fn shape(&self, _messages: Vec<Vec<u8>>) -> Vec<(Duration, Vec<u8>)> {
        todo!("Burst smoothing implementation")
    }
}
