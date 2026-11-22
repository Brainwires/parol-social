//! Local table of known peers: reputation scores and bans (PNP-005 Section 5.8).

use parolnet_protocol::address::PeerId;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::Instant;

/// Default score for new peers (PNP-005-SHOULD-008).
pub const DEFAULT_SCORE: i32 = 100;
/// Highest score.
pub const MAX_SCORE: i32 = 200;
/// Decay: a score moves toward [`DEFAULT_SCORE`] by this much per [`DECAY_PERIOD`].
const DECAY_AMOUNT: i32 = 1;
/// One decay step per hour (PNP-005-SHOULD-010).
pub const DECAY_PERIOD: Duration = Duration::from_secs(3600);
/// A peer whose score fell below zero is refused for this long (PNP-005-SHOULD-009).
pub const BAN_DURATION: Duration = Duration::from_secs(3600);

/// Peer reputation score (PNP-005 Section 5.8).
#[derive(Clone, Debug)]
pub struct PeerScore {
    pub peer_id: PeerId,
    /// At most 200, initialized to 100. Below zero the peer is disconnected.
    pub score: i32,
    /// Up to when decay has been applied.
    decayed_at: Instant,
}

impl PeerScore {
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            score: DEFAULT_SCORE,
            decayed_at: Instant::now(),
        }
    }

    pub fn is_banned(&self) -> bool {
        self.score < 0
    }

    /// A valid, previously unseen message: +1, up to 200.
    pub fn reward(&mut self) {
        self.score = (self.score + 1).min(MAX_SCORE);
    }
    /// An invalid message (bad signature, bad proof-of-work): -10.
    pub fn penalize_invalid(&mut self) {
        self.score -= 10;
    }
    /// An expired message: -2.
    pub fn penalize_expired(&mut self) {
        self.score -= 2;
    }
    /// A duplicate message: -1.
    pub fn penalize_duplicate(&mut self) {
        self.score -= 1;
    }

    /// One decay step toward the default value.
    pub fn decay(&mut self) {
        if self.score > DEFAULT_SCORE {
            self.score = (self.score - DECAY_AMOUNT).max(DEFAULT_SCORE);
        } else if self.score < DEFAULT_SCORE {
            self.score = (self.score + DECAY_AMOUNT).min(DEFAULT_SCORE);
        }
    }

    /// Apply the decay due since it was last applied: one step per whole hour.
    pub fn apply_decay(&mut self, now: Instant) {
        let hours =
            now.saturating_duration_since(self.decayed_at).as_secs() / DECAY_PERIOD.as_secs();
        for _ in 0..hours.min(2 * MAX_SCORE as u64) {
            self.decay();
        }
        self.decayed_at += DECAY_PERIOD * (hours.min(u32::MAX as u64) as u32);
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

    /// Get or create a score entry for a peer, with the decay due applied.
    pub fn get_or_insert(&mut self, peer_id: PeerId) -> &mut PeerScore {
        let score = self
            .scores
            .entry(peer_id)
            .or_insert_with(|| PeerScore::new(peer_id));
        score.apply_decay(Instant::now());
        score
    }

    /// The score of a peer, if it has one, with the decay due applied.
    pub fn get(&mut self, peer_id: &PeerId) -> Option<&PeerScore> {
        let score = self.scores.get_mut(peer_id)?;
        score.apply_decay(Instant::now());
        Some(score)
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

    /// Ban a peer for an hour. Its score starts over, so that the ban, not the score,
    /// decides when it may come back.
    pub fn ban(&mut self, peer_id: PeerId) {
        self.banned_until
            .insert(peer_id, Instant::now() + BAN_DURATION);
        self.scores.remove(&peer_id);
    }

    /// Forget a peer's score if it says nothing (the default value).
    pub fn forget_if_default(&mut self, peer_id: &PeerId) {
        if self
            .scores
            .get(peer_id)
            .is_some_and(|s| s.score == DEFAULT_SCORE)
        {
            self.scores.remove(peer_id);
        }
    }

    /// Decay all scores toward the default by one step and drop bans that ran out.
    pub fn decay_scores(&mut self) {
        for score in self.scores.values_mut() {
            score.decay();
        }
        let now = Instant::now();
        self.banned_until.retain(|_, until| *until > now);
        self.last_decay = Instant::now();
    }

    /// Drop bans that ran out.
    pub fn prune_bans(&mut self) {
        let now = Instant::now();
        self.banned_until.retain(|_, until| *until > now);
    }

    /// Time since last decay was run.
    pub fn time_since_last_decay(&self) -> std::time::Duration {
        self.last_decay.elapsed()
    }
}
