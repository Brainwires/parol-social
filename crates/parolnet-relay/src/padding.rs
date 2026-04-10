//! Inter-relay padding (PNP-004 Section 5.9).
//!
//! Constant-rate padding between relay pairs to defeat traffic analysis.

use std::time::Duration;

/// Default padding rate: 1 cell per 500ms.
pub const DEFAULT_PADDING_INTERVAL: Duration = Duration::from_millis(500);
