//! Local routing table of known peers and link quality.
//! Also implements peer scoring (PNP-005 Section 5.8).

use parolnet_protocol::address::PeerId;
use std::collections::HashMap;
use std::time::Instant;

/// Default score for new peers.
const DEFAULT_SCORE: i32 = 100;
/// Decay factor: score moves toward DEFAULT_SCORE by this amount per decay tick.
const DECAY_AMOUNT: i32 = 1;
/// Default ban duration in seconds.
const BAN_DURATION_SECS: u64 = 3600;

/// Peer reputation score (PNP-005 Section 5.8).
#[derive(Clone, Debug)]
pub struct PeerScore {
    pub peer_id: PeerId,
    /// Score in range 0-200, initialized to 100.
    pub score: i32,
}

impl PeerScore {
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            score: DEFAULT_SCORE,
        }
    }

    pub fn is_banned(&self) -> bool {
        self.score < 0
    }

    pub fn reward(&mut self) {
        self.score = (self.score + 1).min(200);
    }
    pub fn penalize_invalid(&mut self) {
        self.score -= 10;
    }
    pub fn penalize_expired(&mut self) {
        self.score -= 2;
    }
    pub fn penalize_duplicate(&mut self) {
        self.score -= 1;
    }

    /// Decay score toward the default value.
    pub fn decay(&mut self) {
        if self.score > DEFAULT_SCORE {
            self.score = (self.score - DECAY_AMOUNT).max(DEFAULT_SCORE);
        } else if self.score < DEFAULT_SCORE {
            self.score = (self.score + DECAY_AMOUNT).min(DEFAULT_SCORE);
        }
    }
}

/// Tracks peer scores and ban durations.
pub struct PeerTable {
    scores: HashMap<PeerId, PeerScore>,
    banned_until: HashMap<PeerId, Instant>,
    last_decay: Instant,
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            banned_until: HashMap::new(),
            last_decay: Instant::now(),
        }
    }

    /// Get or create a score entry for a peer.
    pub fn get_or_insert(&mut self, peer_id: PeerId) -> &mut PeerScore {
        self.scores
            .entry(peer_id)
            .or_insert_with(|| PeerScore::new(peer_id))
    }

    /// Check if a peer is currently banned (either by score or explicit ban).
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        // Check explicit ban with expiry
        if let Some(&until) = self.banned_until.get(peer_id)
            && Instant::now() < until
        {
            return true;
        }
        // Check score-based ban
        self.scores
            .get(peer_id)
            .map(|s| s.is_banned())
            .unwrap_or(false)
    }

    /// Explicitly ban a peer for the default duration.
    pub fn ban(&mut self, peer_id: PeerId) {
        let until = Instant::now() + std::time::Duration::from_secs(BAN_DURATION_SECS);
        self.banned_until.insert(peer_id, until);
    }

    /// Decay all scores toward the default. Call periodically.
    pub fn decay_scores(&mut self) {
        for score in self.scores.values_mut() {
            score.decay();
        }
        // Clean up expired bans
        let now = Instant::now();
        self.banned_until.retain(|_, until| *until > now);
        self.last_decay = Instant::now();
    }

    /// Time since last decay was run.
    pub fn time_since_last_decay(&self) -> std::time::Duration {
        self.last_decay.elapsed()
    }
}
