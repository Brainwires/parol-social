//! The register challenge one client socket has outstanding.
//!
//! A relay proves a client holds the key behind its PeerId by having it sign
//! a nonce. That proves nothing unless the nonce is one this relay issued on
//! this socket, a short time ago, and has not accepted before: a signature
//! over a nonce the client chose can be replayed by anyone who has seen it
//! once. [`RegisterChallenge`] is that memory. It belongs to one socket task,
//! so it needs no lock and costs 32 bytes per socket.
//!
//! A fresh nonce is still not enough. A relay the client connected to can
//! fetch a challenge from another relay, pass it on as its own and present
//! the client's answer there. [`verify_register`] therefore checks the
//! signature over the register message of PNP-001 §10.7, which names the
//! relay the client dialed, and only for a name this relay serves
//! ([`RelayNames`]).

use parolnet_protocol::relay_auth::{RelayName, RelayNameError, register_signable};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/// Bytes in a register challenge nonce.
pub const CHALLENGE_NONCE_LEN: usize = parolnet_protocol::relay_auth::REGISTER_NONCE_LEN;

/// The names under which clients dial this relay (`RELAY_PUBLIC_NAMES`).
///
/// A register answer, and an authenticated `/peers/*` request, is accepted
/// only when it was signed for one of them. With no name configured the
/// relay serves loopback names only (`localhost`, `127.0.0.0/8`, `[::1]`,
/// any port): enough for development and tests on one machine, and useless
/// to anyone who would replay a signature made for another relay, because a
/// client that signed a loopback name was talking to its own machine.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayNames {
    configured: Vec<RelayName>,
}

impl RelayNames {
    /// Parse `RELAY_PUBLIC_NAMES`: comma-separated `host` or `host:port`
    /// entries, a missing port meaning 443. Any malformed entry is an error:
    /// a relay that silently dropped one of its names would refuse every
    /// client that dials it.
    pub fn from_config(value: Option<&str>) -> Result<Self, (String, RelayNameError)> {
        let mut configured = Vec::new();
        for entry in value.unwrap_or_default().split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let name = RelayName::from_config(entry).map_err(|e| (entry.to_owned(), e))?;
            if !configured.contains(&name) {
                configured.push(name);
            }
        }
        Ok(Self { configured })
    }

    /// The configured names; empty when the relay serves loopback names only.
    pub fn configured(&self) -> &[RelayName] {
        &self.configured
    }

    /// Whether a signature made for `name` is one made for this relay.
    pub fn accepts(&self, name: &RelayName) -> bool {
        if self.configured.is_empty() {
            name.is_loopback()
        } else {
            self.configured.contains(name)
        }
    }
}

/// Why a register answer was refused after its nonce was redeemed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    /// `pubkey`, `signature`, `relay` or `relay_key` is not what its field
    /// must hold.
    Malformed(&'static str),
    /// The PeerId is not the SHA-256 of the public key.
    PeerIdMismatch,
    /// The answer was signed for a relay name this relay does not serve.
    WrongRelay,
    /// The client pinned a relay identity key that is not this relay's.
    WrongRelayKey,
    /// The signature does not verify over the register message.
    BadSignature,
}

impl RegisterError {
    /// Text for the `register_failed` error frame.
    pub fn message(&self) -> String {
        match self {
            RegisterError::Malformed(what) => format!("malformed register answer: {what}"),
            RegisterError::PeerIdMismatch => "peer_id does not match pubkey".into(),
            RegisterError::WrongRelay => {
                "the answer is signed for another relay name; this relay does not serve the name the client dialed".into()
            }
            RegisterError::WrongRelayKey => "the pinned relay key is not this relay's key".into(),
            RegisterError::BadSignature => "signature verification failed".into(),
        }
    }
}

/// The credentials of a `register` answer, as they arrive in the frame.
#[derive(Debug, Clone, Copy)]
pub struct RegisterAnswer<'a> {
    /// The PeerId being registered (64 hex characters).
    pub peer_id: &'a str,
    /// The client's Ed25519 public key (hex).
    pub pubkey_hex: &'a str,
    /// The signature over the register message (hex).
    pub signature_hex: &'a str,
    /// The canonical name of the relay the client dialed.
    pub relay: Option<&'a str>,
    /// The relay identity key the client pins (hex), if it pins one.
    pub relay_key_hex: Option<&'a str>,
}

/// Verify a register answer (PNP-001 §10.7): `PeerId = SHA-256(pubkey)`, the
/// answer names a relay this relay is (`names`, and `relay_key` when the
/// client pinned a key), and the signature is the public key's over the
/// register message built from **this relay's** nonce, name and key.
///
/// `nonce` is the challenge this relay issued on this socket, as returned by
/// [`RegisterChallenge::redeem`]; it is never the client's copy. A signature
/// over a nonce the client chose proves nothing: it can be a replay. A
/// signature that does not name the relay proves nothing either: it can have
/// been made for another relay that passed this relay's nonce on.
pub fn verify_register(
    answer: RegisterAnswer<'_>,
    nonce: &[u8; CHALLENGE_NONCE_LEN],
    names: &RelayNames,
    relay_key: &[u8; 32],
) -> Result<(), RegisterError> {
    use ed25519_dalek::Verifier;
    use sha2::{Digest, Sha256};

    let pubkey: [u8; 32] = hex::decode(answer.pubkey_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(RegisterError::Malformed("pubkey must be 32 bytes of hex"))?;
    let signature: [u8; 64] = hex::decode(answer.signature_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(RegisterError::Malformed(
            "signature must be 64 bytes of hex",
        ))?;

    if hex::encode(Sha256::digest(pubkey)) != answer.peer_id {
        return Err(RegisterError::PeerIdMismatch);
    }

    let relay = answer
        .relay
        .ok_or(RegisterError::Malformed("relay is missing"))?;
    let relay = RelayName::parse(relay)
        .map_err(|_| RegisterError::Malformed("relay is not a canonical relay name"))?;
    if !names.accepts(&relay) {
        return Err(RegisterError::WrongRelay);
    }

    let pinned = match answer.relay_key_hex {
        None => None,
        Some(h) => {
            let pinned: [u8; 32] = hex::decode(h).ok().and_then(|b| b.try_into().ok()).ok_or(
                RegisterError::Malformed("relay_key must be 32 bytes of hex"),
            )?;
            if pinned != *relay_key {
                return Err(RegisterError::WrongRelayKey);
            }
            // The message is built from this relay's own key, not the
            // client's copy.
            Some(relay_key)
        }
    };

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey)
        .map_err(|_| RegisterError::Malformed("pubkey is not an Ed25519 key"))?;
    verifying_key
        .verify(
            &register_signable(nonce, &relay, pinned),
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .map_err(|_| RegisterError::BadSignature)
}

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
    use ed25519_dalek::{Signer, SigningKey};

    const TTL: Duration = Duration::from_secs(60);
    const NONCE: [u8; CHALLENGE_NONCE_LEN] = [0x5a; CHALLENGE_NONCE_LEN];
    const RELAY_KEY: [u8; 32] = [0x11; 32];

    struct Client {
        key: SigningKey,
        peer_id: String,
        pubkey_hex: String,
    }

    impl Client {
        fn new(seed: u8) -> Self {
            use sha2::{Digest, Sha256};
            let key = SigningKey::from_bytes(&[seed; 32]);
            let pubkey = key.verifying_key().to_bytes();
            Self {
                peer_id: hex::encode(Sha256::digest(pubkey)),
                pubkey_hex: hex::encode(pubkey),
                key,
            }
        }

        /// The signature hex of an answer for `relay`, optionally pinning a key.
        fn sign(&self, nonce: &[u8; 32], relay: &str, pinned: Option<&[u8; 32]>) -> String {
            let relay = RelayName::parse(relay).unwrap();
            hex::encode(
                self.key
                    .sign(&register_signable(nonce, &relay, pinned))
                    .to_bytes(),
            )
        }

        fn answer<'a>(&'a self, sig: &'a str, relay: &'a str) -> RegisterAnswer<'a> {
            RegisterAnswer {
                peer_id: &self.peer_id,
                pubkey_hex: &self.pubkey_hex,
                signature_hex: sig,
                relay: Some(relay),
                relay_key_hex: None,
            }
        }
    }

    fn names(v: &str) -> RelayNames {
        RelayNames::from_config(Some(v)).unwrap()
    }

    #[test]
    fn relay_names_parse_and_default_to_loopback() {
        let n = names("Parol.Social, relay.example:8443,,parol.social:443");
        assert_eq!(
            n.configured()
                .iter()
                .map(|n| n.as_str())
                .collect::<Vec<_>>(),
            ["parol.social:443", "relay.example:8443"]
        );
        assert!(n.accepts(&RelayName::parse("parol.social:443").unwrap()));
        assert!(!n.accepts(&RelayName::parse("parol.social:80").unwrap()));
        // Configured names replace the loopback default.
        assert!(!n.accepts(&RelayName::parse("127.0.0.1:9000").unwrap()));

        for unset in [None, Some(""), Some(" , ")] {
            let n = RelayNames::from_config(unset).unwrap();
            assert!(n.configured().is_empty());
            assert!(n.accepts(&RelayName::parse("127.0.0.1:9000").unwrap()));
            assert!(n.accepts(&RelayName::parse("localhost:1411").unwrap()));
            assert!(n.accepts(&RelayName::parse("[::1]:9000").unwrap()));
            assert!(!n.accepts(&RelayName::parse("parol.social:443").unwrap()));
        }

        let (entry, _) = RelayNames::from_config(Some("ok.example,wss://bad")).unwrap_err();
        assert_eq!(entry, "wss://bad");
    }

    #[test]
    fn accepts_an_answer_signed_for_this_relay() {
        let c = Client::new(1);
        let sig = c.sign(&NONCE, "relay-r.example:443", None);
        assert_eq!(
            verify_register(
                c.answer(&sig, "relay-r.example:443"),
                &NONCE,
                &names("relay-r.example"),
                &RELAY_KEY
            ),
            Ok(())
        );
    }

    /// The attack this module closes: relay E passes relay R's nonce to a
    /// client that dialed E, and presents the client's answer at R.
    #[test]
    fn refuses_an_answer_signed_for_another_relay() {
        let c = Client::new(1);
        let r = names("relay-r.example");
        let sig_for_e = c.sign(&NONCE, "relay-e.example:443", None);

        // Presented as it was made.
        assert_eq!(
            verify_register(
                c.answer(&sig_for_e, "relay-e.example:443"),
                &NONCE,
                &r,
                &RELAY_KEY
            ),
            Err(RegisterError::WrongRelay)
        );
        // E rewrites the unsigned `relay` field to R's name: the signature
        // is checked over R's name and does not verify.
        assert_eq!(
            verify_register(
                c.answer(&sig_for_e, "relay-r.example:443"),
                &NONCE,
                &r,
                &RELAY_KEY
            ),
            Err(RegisterError::BadSignature)
        );
        // Same host, another port, is another relay.
        let sig_other_port = c.sign(&NONCE, "relay-r.example:8443", None);
        assert_eq!(
            verify_register(
                c.answer(&sig_other_port, "relay-r.example:8443"),
                &NONCE,
                &r,
                &RELAY_KEY
            ),
            Err(RegisterError::WrongRelay)
        );
    }

    #[test]
    fn refuses_a_signature_over_the_bare_nonce() {
        // What clients signed before PNP-001 v0.15.
        let c = Client::new(1);
        let bare = hex::encode(c.key.sign(&NONCE).to_bytes());
        let r = names("relay-r.example");
        assert_eq!(
            verify_register(
                c.answer(&bare, "relay-r.example:443"),
                &NONCE,
                &r,
                &RELAY_KEY
            ),
            Err(RegisterError::BadSignature)
        );
        let mut no_name = c.answer(&bare, "");
        no_name.relay = None;
        assert_eq!(
            verify_register(no_name, &NONCE, &r, &RELAY_KEY),
            Err(RegisterError::Malformed("relay is missing"))
        );
    }

    #[test]
    fn refuses_another_nonce_key_or_peer_id() {
        let c = Client::new(1);
        let r = names("relay-r.example");
        let sig = c.sign(&NONCE, "relay-r.example:443", None);
        let good = c.answer(&sig, "relay-r.example:443");

        let mut other_nonce = NONCE;
        other_nonce[0] ^= 1;
        assert_eq!(
            verify_register(good, &other_nonce, &r, &RELAY_KEY),
            Err(RegisterError::BadSignature)
        );

        let other = Client::new(2);
        let mut wrong_key = good;
        wrong_key.pubkey_hex = &other.pubkey_hex;
        assert_eq!(
            verify_register(wrong_key, &NONCE, &r, &RELAY_KEY),
            Err(RegisterError::PeerIdMismatch)
        );
        let mut wrong_id = good;
        wrong_id.peer_id = &other.peer_id;
        assert_eq!(
            verify_register(wrong_id, &NONCE, &r, &RELAY_KEY),
            Err(RegisterError::PeerIdMismatch)
        );
    }

    #[test]
    fn refuses_names_that_are_not_canonical() {
        let c = Client::new(1);
        let r = names("relay-r.example");
        let sig = c.sign(&NONCE, "relay-r.example:443", None);
        for relay in [
            "relay-r.example",
            "Relay-R.example:443",
            "relay-r.example:0443",
            "wss://relay-r.example:443",
            "",
        ] {
            assert_eq!(
                verify_register(c.answer(&sig, relay), &NONCE, &r, &RELAY_KEY),
                Err(RegisterError::Malformed(
                    "relay is not a canonical relay name"
                )),
                "{relay:?}"
            );
        }
    }

    #[test]
    fn a_pinned_relay_key_must_be_this_relays_key() {
        let c = Client::new(1);
        let r = names("relay-r.example");
        let relay_key_hex = hex::encode(RELAY_KEY);

        let pinned_sig = c.sign(&NONCE, "relay-r.example:443", Some(&RELAY_KEY));
        let mut pinned = c.answer(&pinned_sig, "relay-r.example:443");
        pinned.relay_key_hex = Some(&relay_key_hex);
        assert_eq!(verify_register(pinned, &NONCE, &r, &RELAY_KEY), Ok(()));

        // The client pinned another relay's key (it believes it talks to that
        // relay): refused, whatever name it signed.
        let other_key = [0x22; 32];
        let other_key_hex = hex::encode(other_key);
        let sig_other = c.sign(&NONCE, "relay-r.example:443", Some(&other_key));
        let mut wrong = c.answer(&sig_other, "relay-r.example:443");
        wrong.relay_key_hex = Some(&other_key_hex);
        assert_eq!(
            verify_register(wrong, &NONCE, &r, &RELAY_KEY),
            Err(RegisterError::WrongRelayKey)
        );
        // The forwarding relay swaps the unsigned field for this relay's key:
        // the signature was made over the other key.
        wrong.relay_key_hex = Some(&relay_key_hex);
        assert_eq!(
            verify_register(wrong, &NONCE, &r, &RELAY_KEY),
            Err(RegisterError::BadSignature)
        );
        // Stripping the pin from a pinned answer, or adding one to an
        // unpinned answer, changes the signed message.
        let mut stripped = c.answer(&pinned_sig, "relay-r.example:443");
        stripped.relay_key_hex = None;
        assert_eq!(
            verify_register(stripped, &NONCE, &r, &RELAY_KEY),
            Err(RegisterError::BadSignature)
        );
        let unpinned_sig = c.sign(&NONCE, "relay-r.example:443", None);
        let mut added = c.answer(&unpinned_sig, "relay-r.example:443");
        added.relay_key_hex = Some(&relay_key_hex);
        assert_eq!(
            verify_register(added, &NONCE, &r, &RELAY_KEY),
            Err(RegisterError::BadSignature)
        );
        let mut malformed = c.answer(&pinned_sig, "relay-r.example:443");
        malformed.relay_key_hex = Some("abcd");
        assert_eq!(
            verify_register(malformed, &NONCE, &r, &RELAY_KEY),
            Err(RegisterError::Malformed(
                "relay_key must be 32 bytes of hex"
            ))
        );
    }

    #[test]
    fn an_unconfigured_relay_accepts_loopback_names_only() {
        let c = Client::new(1);
        let unset = RelayNames::default();
        let sig = c.sign(&NONCE, "127.0.0.1:9000", None);
        assert_eq!(
            verify_register(c.answer(&sig, "127.0.0.1:9000"), &NONCE, &unset, &RELAY_KEY),
            Ok(())
        );
        let sig = c.sign(&NONCE, "relay-r.example:443", None);
        assert_eq!(
            verify_register(
                c.answer(&sig, "relay-r.example:443"),
                &NONCE,
                &unset,
                &RELAY_KEY
            ),
            Err(RegisterError::WrongRelay)
        );
    }

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
