//! The register challenge one client socket has outstanding.
//!
//! A relay proves a client holds the key behind its PeerId by having it sign
//! a nonce. That proves nothing unless the nonce is one this relay issued on
//! this socket, a short time ago, and has not accepted before: a signature
//! over a nonce the client chose can be replayed by anyone who has seen it
//! once. [`RegisterChallenge`] is that memory. It belongs to one socket task,
//! so it needs no lock and costs 32 bytes per socket.

use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/// Bytes in a register challenge nonce.
pub const CHALLENGE_NONCE_LEN: usize = 32;

/// Why a credentialed `register` was refused before its signature was looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    /// The socket has no challenge outstanding: none was asked for, or it was
    /// already answered.
    NoneOutstanding,
    /// The outstanding challenge is older than its lifetime.
    Expired,
    /// The nonce is not the one this socket was given.
    Mismatch,
}

impl ChallengeError {
    /// Text for the `register_failed` error frame.
    pub fn message(self) -> &'static str {
        match self {
            ChallengeError::NoneOutstanding => "no challenge outstanding",
            ChallengeError::Expired => "challenge expired",
            ChallengeError::Mismatch => "nonce is not this socket's challenge",
        }
    }
}

/// At most one outstanding challenge, single use, with a lifetime.
#[derive(Debug)]
pub struct RegisterChallenge {
    ttl: Duration,
    outstanding: Option<([u8; CHALLENGE_NONCE_LEN], Instant)>,
}

impl RegisterChallenge {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            outstanding: None,
        }
    }

    /// The nonce to send in a `challenge` frame.
    ///
    /// While a challenge is outstanding and alive the same nonce is returned
    /// and its lifetime is not extended: a client that sends two plain
    /// `register` frames before it answers (the legacy PWA does) gets one
    /// nonce twice, and its answer to either frame is the answer to both.
    pub fn issue(&mut self, now: Instant) -> [u8; CHALLENGE_NONCE_LEN] {
        if let Some((nonce, issued_at)) = self.outstanding
            && !self.is_expired(issued_at, now)
        {
            return nonce;
        }
        let mut nonce = [0u8; CHALLENGE_NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        self.outstanding = Some((nonce, now));
        nonce
    }

    /// Consume the outstanding challenge against the nonce a client echoed.
    ///
    /// Returns the issued nonce (the bytes the signature must cover) when the
    /// echo matches a live challenge. Whatever the outcome, nothing is
    /// outstanding afterwards: every credentialed `register` spends the
    /// challenge, so a nonce is checked against at most one signature.
    pub fn redeem(
        &mut self,
        echoed: &[u8],
        now: Instant,
    ) -> Result<[u8; CHALLENGE_NONCE_LEN], ChallengeError> {
        let (nonce, issued_at) = self
            .outstanding
            .take()
            .ok_or(ChallengeError::NoneOutstanding)?;
        if self.is_expired(issued_at, now) {
            return Err(ChallengeError::Expired);
        }
        // `ct_eq` on slices is false for unequal lengths.
        if !bool::from(nonce.as_slice().ct_eq(echoed)) {
            return Err(ChallengeError::Mismatch);
        }
        Ok(nonce)
    }

    fn is_expired(&self, issued_at: Instant, now: Instant) -> bool {
        now.saturating_duration_since(issued_at) >= self.ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(60);

    #[test]
    fn accepts_the_issued_nonce_once() {
        let t0 = Instant::now();
        let mut c = RegisterChallenge::new(TTL);
        let nonce = c.issue(t0);
        assert_eq!(c.redeem(&nonce, t0 + Duration::from_secs(1)), Ok(nonce));
    }

    #[test]
    fn refuses_a_replay_of_an_accepted_nonce() {
        let t0 = Instant::now();
        let mut c = RegisterChallenge::new(TTL);
        let nonce = c.issue(t0);
        assert!(c.redeem(&nonce, t0).is_ok());
        assert_eq!(c.redeem(&nonce, t0), Err(ChallengeError::NoneOutstanding));
    }

    #[test]
    fn refuses_a_foreign_nonce_and_spends_the_challenge() {
        let t0 = Instant::now();
        let mut c = RegisterChallenge::new(TTL);
        let nonce = c.issue(t0);
        let mut foreign = nonce;
        foreign[31] ^= 1;
        assert_eq!(c.redeem(&foreign, t0), Err(ChallengeError::Mismatch));
        // The right nonce no longer works either: one answer per challenge.
        assert_eq!(c.redeem(&nonce, t0), Err(ChallengeError::NoneOutstanding));
    }

    #[test]
    fn refuses_a_nonce_of_another_length() {
        let t0 = Instant::now();
        for echoed in [&[][..], &[0u8; 31][..], &[0u8; 33][..]] {
            let mut c = RegisterChallenge::new(TTL);
            c.issue(t0);
            assert_eq!(c.redeem(echoed, t0), Err(ChallengeError::Mismatch));
        }
        // A prefix of the nonce, or the nonce with a byte appended, is not
        // the nonce.
        let mut c = RegisterChallenge::new(TTL);
        let nonce = c.issue(t0);
        assert_eq!(c.redeem(&nonce[..31], t0), Err(ChallengeError::Mismatch));
        let mut c = RegisterChallenge::new(TTL);
        let mut longer = c.issue(t0).to_vec();
        longer.push(0);
        assert_eq!(c.redeem(&longer, t0), Err(ChallengeError::Mismatch));
    }

    #[test]
    fn refuses_an_expired_challenge() {
        let t0 = Instant::now();
        let mut c = RegisterChallenge::new(TTL);
        let nonce = c.issue(t0);
        assert_eq!(c.redeem(&nonce, t0 + TTL), Err(ChallengeError::Expired));
        // Expiry spends it too.
        assert_eq!(c.redeem(&nonce, t0), Err(ChallengeError::NoneOutstanding));

        let mut c = RegisterChallenge::new(TTL);
        let nonce = c.issue(t0);
        let just_inside = t0 + TTL - Duration::from_millis(1);
        assert_eq!(c.redeem(&nonce, just_inside), Ok(nonce));
    }

    #[test]
    fn refuses_credentials_when_no_challenge_was_issued() {
        let mut c = RegisterChallenge::new(TTL);
        assert_eq!(
            c.redeem(&[7u8; CHALLENGE_NONCE_LEN], Instant::now()),
            Err(ChallengeError::NoneOutstanding)
        );
    }

    #[test]
    fn a_repeated_request_gets_the_same_nonce_and_no_longer_life() {
        let t0 = Instant::now();
        let mut c = RegisterChallenge::new(TTL);
        let first = c.issue(t0);
        let again = c.issue(t0 + Duration::from_secs(59));
        assert_eq!(first, again);
        // Still measured from the first issue.
        assert_eq!(c.redeem(&first, t0 + TTL), Err(ChallengeError::Expired));
    }

    #[test]
    fn a_new_request_after_expiry_or_use_gets_a_new_nonce() {
        let t0 = Instant::now();
        let mut c = RegisterChallenge::new(TTL);
        let first = c.issue(t0);
        let second = c.issue(t0 + TTL);
        assert_ne!(first, second);
        assert_eq!(c.redeem(&first, t0 + TTL), Err(ChallengeError::Mismatch));

        let third = c.issue(t0 + TTL);
        assert!(c.redeem(&third, t0 + TTL).is_ok());
        let fourth = c.issue(t0 + TTL);
        assert_ne!(third, fourth);
    }

    #[test]
    fn two_sockets_do_not_share_a_challenge() {
        let t0 = Instant::now();
        let mut a = RegisterChallenge::new(TTL);
        let mut b = RegisterChallenge::new(TTL);
        let nonce_a = a.issue(t0);
        let _nonce_b = b.issue(t0);
        assert_eq!(b.redeem(&nonce_a, t0), Err(ChallengeError::Mismatch));
    }
}
