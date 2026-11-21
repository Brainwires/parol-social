//! Abuse bounds (PNP-010 §8).

use crate::{OFFER_BURST, OFFER_REFILL_MS};

/// How many offers one contact may make: a bucket of [`OFFER_BURST`] tokens that regains one
/// every [`OFFER_REFILL_MS`]. One limiter per contact; the caller supplies the clock.
#[derive(Debug, Clone)]
pub struct OfferLimiter {
    tokens: u32,
    /// When the bucket last gained a token (or was full).
    refilled_ms: u64,
}

impl OfferLimiter {
    pub fn new(now_ms: u64) -> OfferLimiter {
        OfferLimiter {
            tokens: OFFER_BURST,
            refilled_ms: now_ms,
        }
    }

    /// Account for one offer arriving now. False: over the limit, decline it.
    pub fn allow(&mut self, now_ms: u64) -> bool {
        let gained = now_ms.saturating_sub(self.refilled_ms) / OFFER_REFILL_MS;
        if gained > 0 {
            self.tokens = self
                .tokens
                .saturating_add(u32::try_from(gained).unwrap_or(u32::MAX))
                .min(OFFER_BURST);
            self.refilled_ms += gained * OFFER_REFILL_MS;
        }
        if self.tokens == OFFER_BURST {
            self.refilled_ms = now_ms;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_then_one_per_interval() {
        let mut l = OfferLimiter::new(1_000);
        for _ in 0..OFFER_BURST {
            assert!(l.allow(1_000));
        }
        assert!(!l.allow(1_000));
        assert!(!l.allow(1_000 + OFFER_REFILL_MS - 1));
        assert!(l.allow(1_000 + OFFER_REFILL_MS));
        assert!(!l.allow(1_000 + OFFER_REFILL_MS));
        // A long quiet time refills the bucket, and no further.
        let later = 1_000 + 1_000 * OFFER_REFILL_MS;
        for _ in 0..OFFER_BURST {
            assert!(l.allow(later));
        }
        assert!(!l.allow(later));
        // A clock that steps back does not panic or refill.
        assert!(!l.allow(0));
    }
}
