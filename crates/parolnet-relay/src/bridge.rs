//! Bridge-mode probe resistance and disclosure controls (PNP-008 §9.1.1 / §9.1.2).
//!
//! Clauses pinned here:
//! - **PNP-008-MUST-085..088** — cover-page constants and no-residual-state policy.
//! - **PNP-008-MUST-089** — in-memory disclosure counter, no cross-restart persistence.
//! - **PNP-008-MUST-090** — scheduled IP audit-log scrubber cadence.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// Cover response latency budget (PNP-008-MUST-087).
pub const COVER_LATENCY_BUDGET_MS: u64 = 250;
/// Cover response minimum body length (PNP-008-MUST-085).
pub const COVER_MIN_BODY_BYTES: usize = 256;
/// HTTP content-type for the cover response (PNP-008-MUST-085).
pub const COVER_CONTENT_TYPE: &str = "text/html; charset=utf-8";
/// Disclosure rolling window (PNP-008-MUST-089).
pub const DISCLOSURE_WINDOW_SECS: u64 = 3600;
/// Disclosure cap per email per hour (PNP-008-MUST-052, reiterated by MUST-089).
pub const DISCLOSURES_PER_EMAIL_PER_HOUR: u32 = 3;
/// Disclosure cap per QR session (PNP-008-MUST-052, reiterated by MUST-089).
pub const DISCLOSURES_PER_QR_SESSION: u32 = 1;
/// IP audit-log retention (PNP-008-MUST-054 / MUST-090).
pub const IP_LOG_MAX_AGE_SECS: u64 = 86_400;
/// IP audit-log scrubber minimum cadence (PNP-008-MUST-090). The scrubber MUST
/// run at least this often, independent of request traffic.
pub const IP_LOG_SCRUBBER_INTERVAL_SECS: u64 = 3_600;

/// Plausible cover-page body served on any connection that does not match the
/// negotiated pluggable transport handshake (PNP-008-MUST-085 / MUST-086).
///
/// The body is ≥ 256 bytes, contains no `ParolNet`, `parolnet`, `federation`,
/// or `bridge` tokens, and reads like a generic tourist landing page a typical
/// reverse proxy might serve for an unconfigured virtual host.
pub const COVER_PAGE_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Welcome</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, sans-serif; max-width: 42rem; margin: 2rem auto; padding: 0 1rem; color: #222; }
    header { border-bottom: 1px solid #ddd; padding-bottom: 0.5rem; }
    p { line-height: 1.5; }
  </style>
</head>
<body>
  <header><h1>Welcome</h1></header>
  <p>This server is configured and ready.</p>
  <p>If you believe you reached this page in error, please check the address and try again.</p>
</body>
</html>
"#;

/// Scope key for the disclosure counter. Email-based disclosures and QR-session
/// disclosures are counted independently so that a single QR session cannot
/// silently raise the email cap (or vice versa).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum DisclosureScope {
    Email(String),
    QrSession(String),
}

impl DisclosureScope {
    fn cap_per_window(&self) -> u32 {
        match self {
            Self::Email(_) => DISCLOSURES_PER_EMAIL_PER_HOUR,
            Self::QrSession(_) => DISCLOSURES_PER_QR_SESSION,
        }
    }
}

/// In-memory disclosure counter (PNP-008-MUST-089).
///
/// Tracks per-scope timestamps within the rolling 60-minute window. Holds no
/// persistent state — a process restart zeroes the counter, which is the whole
/// point: a seized bridge yields no disclosure history.
#[derive(Default)]
pub struct DisclosureLimiter {
    by_scope: HashMap<DisclosureScope, VecDeque<u64>>,
}

impl DisclosureLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a disclosure attempt at time `now_secs`. Returns `true` if the
    /// disclosure is permitted (below the window cap). Rejected attempts
    /// do not advance the counter — the cap is on *successful* disclosures.
    pub fn try_disclose(&mut self, scope: DisclosureScope, now_secs: u64) -> bool {
        let cap = scope.cap_per_window();
        let entry = self.by_scope.entry(scope).or_default();
        let cutoff = now_secs.saturating_sub(DISCLOSURE_WINDOW_SECS);
        while let Some(&front) = entry.front() {
            if front < cutoff {
                entry.pop_front();
            } else {
                break;
            }
        }
        if (entry.len() as u32) >= cap {
            return false;
        }
        entry.push_back(now_secs);
        true
    }

    /// Number of entries currently held (for observability; no persistence).
    pub fn entry_count(&self) -> usize {
        self.by_scope.values().map(|q| q.len()).sum()
    }

    /// Drop empty queues (housekeeping; called from the periodic scrubber).
    pub fn gc(&mut self) {
        self.by_scope.retain(|_, q| !q.is_empty());
    }
}

/// Per-IP rate-limit audit log (PNP-008-MUST-090).
///
/// Maintains each remote IP's first-seen timestamp. A scheduled scrubber drops
/// any entry whose first-seen timestamp is older than
/// [`IP_LOG_MAX_AGE_SECS`]. The scrubber MUST run independently of request
/// traffic; an idle bridge still purges on schedule.
#[derive(Default)]
pub struct IpAuditLog {
    first_seen: HashMap<IpAddr, u64>,
}

impl IpAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a connection from `ip` observed at `now_secs`. The first-seen
    /// timestamp for a previously-unseen IP is `now_secs`; later observations
    /// do not update it (MUST-090 expects the scrubber to evict on age).
    pub fn observe(&mut self, ip: IpAddr, now_secs: u64) {
        self.first_seen.entry(ip).or_insert(now_secs);
    }

    /// Returns whether `ip` is currently tracked.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.first_seen.contains_key(ip)
    }

    /// Purge entries older than [`IP_LOG_MAX_AGE_SECS`]. Returns the number of
    /// entries evicted. Called by the periodic scrubber task.
    pub fn purge(&mut self, now_secs: u64) -> usize {
        let cutoff = now_secs.saturating_sub(IP_LOG_MAX_AGE_SECS);
        let before = self.first_seen.len();
        self.first_seen.retain(|_, first| *first >= cutoff);
        before - self.first_seen.len()
    }

    pub fn len(&self) -> usize {
        self.first_seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.first_seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cover_page_meets_probe_resistance_bounds() {
        // MUST-085: ≥ 256 bytes of HTML.
        assert!(
            COVER_PAGE_HTML.len() >= COVER_MIN_BODY_BYTES,
            "cover page is {} bytes, need ≥ {}",
            COVER_PAGE_HTML.len(),
            COVER_MIN_BODY_BYTES
        );
        // MUST-086: no forbidden tokens.
        for token in ["ParolNet", "parolnet", "federation", "bridge"] {
            assert!(
                !COVER_PAGE_HTML.contains(token),
                "cover page leaks forbidden token {token:?}"
            );
        }
    }

    #[test]
    fn disclosure_counter_enforces_email_cap() {
        let mut lim = DisclosureLimiter::new();
        let scope = DisclosureScope::Email("alice@example.test".into());
        assert!(lim.try_disclose(scope.clone(), 1000));
        assert!(lim.try_disclose(scope.clone(), 1001));
        assert!(lim.try_disclose(scope.clone(), 1002));
        // 4th within the 1-hour window is rejected (cap=3).
        assert!(!lim.try_disclose(scope.clone(), 1003));
    }

    #[test]
    fn disclosure_counter_enforces_qr_cap() {
        let mut lim = DisclosureLimiter::new();
        let scope = DisclosureScope::QrSession("qr-session-42".into());
        assert!(lim.try_disclose(scope.clone(), 1000));
        // 2nd disclosure in the same QR session is rejected (cap=1).
        assert!(!lim.try_disclose(scope.clone(), 1001));
    }

    #[test]
    fn disclosure_counter_rolls_over_hour_window() {
        let mut lim = DisclosureLimiter::new();
        let scope = DisclosureScope::Email("bob@example.test".into());
        for i in 0..3 {
            assert!(lim.try_disclose(scope.clone(), 1000 + i));
        }
        // After the window, old entries are GC'd and the next disclosure passes.
        assert!(lim.try_disclose(scope.clone(), 1000 + DISCLOSURE_WINDOW_SECS + 1));
    }

    #[test]
    fn ip_audit_log_purges_at_24h() {
        let mut log = IpAuditLog::new();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        log.observe(ip, 1000);
        assert!(log.contains(&ip));
        // Exactly at the boundary → still kept.
        assert_eq!(log.purge(1000 + IP_LOG_MAX_AGE_SECS), 0);
        assert!(log.contains(&ip));
        // One second past 24 h → evicted.
        assert_eq!(log.purge(1000 + IP_LOG_MAX_AGE_SECS + 1), 1);
        assert!(!log.contains(&ip));
    }

    #[test]
    fn scrubber_interval_meets_spec() {
        // MUST-090: scrubber runs at least once per hour, independent of traffic.
        assert!(IP_LOG_SCRUBBER_INTERVAL_SECS <= 3_600);
    }
}
