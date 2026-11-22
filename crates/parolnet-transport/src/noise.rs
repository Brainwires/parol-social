//! Traffic noise generation (PNP-006).
//!
//! Constant-rate padding, burst smoothing, dummy traffic and timing jitter. The decisions
//! themselves live in [`parolnet_protocol::shaping`] (sans-I/O, shared with the clients);
//! this module is the transport crate's view of them.

use crate::traits::TrafficShaper;
use std::time::Duration;

pub use parolnet_protocol::shaping::{
    BURST_MAX, BURST_QUEUE_DEPTH, BandwidthMode, SendChoice, SendScheduler, TrafficProfile,
    TrafficProfileError,
};

/// Standard traffic shaper implementing PNP-006 behavioral rules.
#[derive(Clone, Copy, Debug, Default)]
pub struct StandardShaper {
    pub mode: BandwidthMode,
}

impl TrafficShaper for StandardShaper {
    fn delay_before_send(&self) -> Duration {
        // The scheduler draws the jitter from the operating system's CSPRNG: predictable
        // jitter would leak timing to a network observer.
        SendScheduler::<()>::new(self.mode).next_delay(Some(Duration::ZERO))
    }

    fn dummy_traffic_interval(&self) -> Option<Duration> {
        Some(self.mode.padding_interval())
    }

    fn shape(&self, messages: Vec<Vec<u8>>) -> Vec<(Duration, Vec<u8>)> {
        let mut scheduler = SendScheduler::new(self.mode);
        for message in messages {
            scheduler.push(message);
        }
        let mut result = Vec::with_capacity(scheduler.len());
        while !scheduler.is_empty() {
            // Each entry's delay counts from the send before it.
            let delay = scheduler.next_delay(Some(Duration::ZERO));
            if let Some(SendChoice::Real(message)) = scheduler.on_slot() {
                result.push((delay, message));
            }
        }
        result
    }
}

/// Read a traffic profile (PNP-006 §4.6) from a CBOR file.
pub fn load_traffic_profile(
    path: &std::path::Path,
) -> Result<TrafficProfile, crate::TransportError> {
    let bytes = std::fs::read(path)?;
    TrafficProfile::from_cbor(&bytes)
        .map_err(|e| crate::TransportError::NotAvailable(e.to_string()))
}
