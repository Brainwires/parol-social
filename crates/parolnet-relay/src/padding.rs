//! Padding between circuit neighbours (PNP-004 Section 5.9).
//!
//! The rate follows the PNP-006 bandwidth mode of the circuit. The mode is negotiated in
//! the handshake extensions (`"pad"`); without one, both sides use NORMAL.

use parolnet_transport::noise::BandwidthMode;
use std::time::Duration;

/// Default padding rate: 1 cell per 500ms (NORMAL mode).
pub const DEFAULT_PADDING_INTERVAL: Duration = Duration::from_millis(500);

/// Inter-cell interval of a bandwidth mode (PNP-004 §5.9 table).
pub fn padding_interval(mode: BandwidthMode) -> Duration {
    mode.padding_interval()
}

/// Wire code of a bandwidth mode in the `"pad"` handshake extension.
pub fn mode_to_wire(mode: BandwidthMode) -> u8 {
    match mode {
        BandwidthMode::Low => 0,
        BandwidthMode::Normal => 1,
        BandwidthMode::High => 2,
        BandwidthMode::MediaCall => 3,
    }
}

/// Bandwidth mode of a `"pad"` wire code.
pub fn mode_from_wire(code: u8) -> Option<BandwidthMode> {
    match code {
        0 => Some(BandwidthMode::Low),
        1 => Some(BandwidthMode::Normal),
        2 => Some(BandwidthMode::High),
        3 => Some(BandwidthMode::MediaCall),
        _ => None,
    }
}
