//! In-memory sliding-window rate limiters keyed by IP or peer-id.
//!
//! Pulled out of `main.rs` as part of the #58 refactor. All behavior is
//! byte-identical — only the home of these definitions moved.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Per-IP WebSocket connection rate limiter.
/// Max 10 new connections per minute per IP address.
pub const WS_CONN_RATE_LIMIT: u32 = 10;
pub const WS_CONN_RATE_WINDOW_SECS: u64 = 60;

/// Per-peer message rate limiter.
/// Max 100 messages per minute per connected peer.
pub const MSG_RATE_LIMIT: u32 = 100;
pub const MSG_RATE_WINDOW_SECS: u64 = 60;

/// Per-IP rate limiter for POST /directory/push requests.
/// Max 10 pushes per minute per source IP.
pub const PUSH_RATE_LIMIT: u32 = 10;
pub const PUSH_RATE_WINDOW_SECS: u64 = 60;

/// Per-IP rate limiter for GET /peers/lookup.
pub const LOOKUP_RATE_LIMIT: u32 = 10;
pub const LOOKUP_RATE_WINDOW_SECS: u64 = 1;

/// In-memory rate limiter tracking (window_start, count) per key.
pub struct RateLimiter<K: std::hash::Hash + Eq> {
    limits: std::sync::Mutex<HashMap<K, (std::time::Instant, u32)>>,
    max_count: u32,
    window: Duration,
}

impl<K: std::hash::Hash + Eq + Clone> RateLimiter<K> {
    pub fn new(max_count: u32, window_secs: u64) -> Self {
        Self {
            limits: std::sync::Mutex::new(HashMap::new()),
            max_count,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Check if a key is rate-limited. Increments the counter.
    /// Returns true if the request should be rejected.
    pub fn is_limited(&self, key: &K) -> bool {
        let mut limits = self.limits.lock().unwrap();
        let now = std::time::Instant::now();
        let entry = limits.entry(key.clone()).or_insert((now, 0));

        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 1);
            return false;
        }

        entry.1 += 1;
        entry.1 > self.max_count
    }

    /// Periodically clean up expired entries.
    pub fn cleanup(&self) {
        let mut limits = self.limits.lock().unwrap();
        let now = std::time::Instant::now();
        limits.retain(|_, (start, _)| now.duration_since(*start) < self.window);
    }
}

pub type ConnRateLimiter = Arc<RateLimiter<std::net::IpAddr>>;
pub type MsgRateLimiter = Arc<RateLimiter<String>>;
pub type PushRateLimiter = Arc<RateLimiter<std::net::IpAddr>>;
pub type LookupRateLimiter = Arc<RateLimiter<std::net::IpAddr>>;
