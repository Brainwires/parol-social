//! The wall clock the mesh reads message timestamps against.
//!
//! Gossip `ts` and `exp` are unix seconds. Production uses the system clock; a test
//! that has to cross an expiry, or the 300-second skew bound, supplies its own.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of unix time, in seconds.
#[derive(Clone)]
pub struct Clock(Arc<dyn Fn() -> u64 + Send + Sync>);

impl Clock {
    /// The system clock.
    pub fn system() -> Self {
        Self(Arc::new(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }))
    }

    /// A clock that reads `f`.
    pub fn from_fn(f: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// A clock that starts at `origin_unix` now and then follows tokio's clock, so that
    /// it moves when a paused test runtime advances time.
    pub fn following_tokio(origin_unix: u64) -> Self {
        let origin = tokio::time::Instant::now();
        Self(Arc::new(move || origin_unix + origin.elapsed().as_secs()))
    }

    pub fn now_secs(&self) -> u64 {
        (self.0)()
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::system()
    }
}
