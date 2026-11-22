//! Who may ask this relay where a peer is (PNP-008 §10.8).
//!
//! `GET /peers/presence` lists every PeerId connected to the relay and
//! `GET /peers/lookup` says whether one PeerId is online and where. Answered
//! to anyone, they are an oracle for "is this person online right now". A
//! signaling-only relay therefore does not serve them at all, and a
//! relay-profile relay answers only a request that carries a fresh Ed25519
//! signature made for this relay ([`authenticate`]), from
//!
//! * a federation peer whose relay identity key the operator listed in
//!   `FEDERATION_PEER_KEYS` (presence and lookup), or
//! * a peer that is registered on this relay at that moment (lookup only).

use crate::challenge::RelayNames;
use parolnet_protocol::relay_auth::{PeersAuthorization, PeersRequest};

/// Why a `/peers/*` request was refused before it was looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeersAuthError {
    /// No `Authorization` header, or not one of the `PNP-Ed25519` scheme.
    Missing,
    /// The header does not parse.
    Malformed,
    /// Signed for a relay name this relay does not serve.
    WrongRelay,
    /// The timestamp is more than a minute from this relay's clock.
    Stale,
    /// The signature does not verify for this request.
    BadSignature,
}

/// Check the credentials of a `/peers/*` request and return the Ed25519 key
/// that made it. The caller decides whether that key may ask
/// ([`FederationPeers::contains`], or a registered peer for a lookup).
///
/// The signature covers the kind of request, the PeerId looked up, the time
/// and the relay name, so a captured header is of no use for another target,
/// at another relay, or a minute later.
pub fn authenticate(
    authorization: Option<&str>,
    request: PeersRequest,
    names: &RelayNames,
    now_secs: u64,
) -> Result<[u8; 32], PeersAuthError> {
    let header = authorization.ok_or(PeersAuthError::Missing)?;
    if !header.starts_with(parolnet_protocol::relay_auth::PEERS_AUTH_SCHEME) {
        return Err(PeersAuthError::Missing);
    }
    let auth = PeersAuthorization::parse_header(header).ok_or(PeersAuthError::Malformed)?;
    if !names.accepts(&auth.relay) {
        return Err(PeersAuthError::WrongRelay);
    }
    if !auth.is_fresh(now_secs) {
        return Err(PeersAuthError::Stale);
    }
    if !auth.verify(request) {
        return Err(PeersAuthError::BadSignature);
    }
    Ok(auth.key)
}

/// Whether an authenticated caller may be answered (PNP-008-MUST-102).
/// `/peers/presence` lists everyone connected, so only a configured
/// federation peer reads it; `/peers/lookup` is also answered to a peer that
/// is registered on this relay at that moment.
pub fn may_ask(request: PeersRequest, is_federation_peer: bool, is_registered_peer: bool) -> bool {
    match request {
        PeersRequest::Presence => is_federation_peer,
        PeersRequest::Lookup(_) => is_federation_peer || is_registered_peer,
    }
}

/// The relay identity keys of the federation peers that may read this
/// relay's presence (`FEDERATION_PEER_KEYS`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FederationPeers {
    keys: Vec<[u8; 32]>,
}

impl FederationPeers {
    /// Parse `FEDERATION_PEER_KEYS`: comma-separated Ed25519 public keys,
    /// 64 hex characters each (what a relay logs at startup as its
    /// "Relay Ed25519 public key"). A malformed entry is an error, returned
    /// as written.
    pub fn from_config(value: Option<&str>) -> Result<Self, String> {
        let mut keys = Vec::new();
        for entry in value.unwrap_or_default().split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let key: [u8; 32] = hex::decode(entry)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| entry.to_owned())?;
            if ed25519_dalek::VerifyingKey::from_bytes(&key).is_err() {
                return Err(entry.to_owned());
            }
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        Ok(Self { keys })
    }

    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.keys.contains(key)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use parolnet_protocol::address::PeerId;
    use parolnet_protocol::relay_auth::RelayName;

    const NOW: u64 = 1_800_000_000;

    fn names() -> RelayNames {
        RelayNames::from_config(Some("relay-r.example")).unwrap()
    }

    fn header(sk: &SigningKey, request: PeersRequest, ts: u64, relay: &str) -> String {
        PeersAuthorization::sign(
            request,
            sk.verifying_key().to_bytes(),
            ts,
            RelayName::parse(relay).unwrap(),
            |m| sk.sign(m).to_bytes(),
        )
        .to_header()
    }

    #[test]
    fn a_fresh_request_signed_for_this_relay_authenticates_its_key() {
        let sk = SigningKey::from_bytes(&[3; 32]);
        let target = PeersRequest::Lookup(PeerId([0x42; 32]));
        let h = header(&sk, target, NOW, "relay-r.example:443");
        assert_eq!(
            authenticate(Some(&h), target, &names(), NOW + 30),
            Ok(sk.verifying_key().to_bytes())
        );
        let p = header(&sk, PeersRequest::Presence, NOW, "relay-r.example:443");
        assert_eq!(
            authenticate(Some(&p), PeersRequest::Presence, &names(), NOW),
            Ok(sk.verifying_key().to_bytes())
        );
    }

    #[test]
    fn anything_else_is_refused() {
        let sk = SigningKey::from_bytes(&[3; 32]);
        let target = PeersRequest::Lookup(PeerId([0x42; 32]));
        let good = header(&sk, target, NOW, "relay-r.example:443");
        let n = names();

        assert_eq!(
            authenticate(None, target, &n, NOW),
            Err(PeersAuthError::Missing)
        );
        assert_eq!(
            authenticate(Some("Bearer abc"), target, &n, NOW),
            Err(PeersAuthError::Missing)
        );
        assert_eq!(
            authenticate(Some("PNP-Ed25519 nonsense"), target, &n, NOW),
            Err(PeersAuthError::Malformed)
        );
        // A header captured for one target does not ask about another, nor
        // list everyone.
        assert_eq!(
            authenticate(
                Some(&good),
                PeersRequest::Lookup(PeerId([0x43; 32])),
                &n,
                NOW
            ),
            Err(PeersAuthError::BadSignature)
        );
        assert_eq!(
            authenticate(Some(&good), PeersRequest::Presence, &n, NOW),
            Err(PeersAuthError::BadSignature)
        );
        // Nor a minute later, or from the future.
        assert_eq!(
            authenticate(Some(&good), target, &n, NOW + 61),
            Err(PeersAuthError::Stale)
        );
        assert_eq!(
            authenticate(Some(&good), target, &n, NOW - 61),
            Err(PeersAuthError::Stale)
        );
        // A request signed for another relay, forwarded here.
        let for_e = header(&sk, target, NOW, "relay-e.example:443");
        assert_eq!(
            authenticate(Some(&for_e), target, &n, NOW),
            Err(PeersAuthError::WrongRelay)
        );
        // ... with the name rewritten: the signature is over the other name.
        let rewritten = for_e.replace("relay-e.example", "relay-r.example");
        assert_eq!(
            authenticate(Some(&rewritten), target, &n, NOW),
            Err(PeersAuthError::BadSignature)
        );
        // Another key's signature under this key.
        let other = SigningKey::from_bytes(&[4; 32]);
        let forged = good.replace(
            &hex::encode(sk.verifying_key().to_bytes()),
            &hex::encode(other.verifying_key().to_bytes()),
        );
        assert_eq!(
            authenticate(Some(&forged), target, &n, NOW),
            Err(PeersAuthError::BadSignature)
        );
    }

    #[test]
    fn presence_is_for_federation_peers_and_lookup_also_for_registered_peers() {
        let lookup = PeersRequest::Lookup(PeerId([1; 32]));
        assert!(may_ask(PeersRequest::Presence, true, false));
        assert!(!may_ask(PeersRequest::Presence, false, true));
        assert!(!may_ask(PeersRequest::Presence, false, false));
        assert!(may_ask(lookup, true, false));
        assert!(may_ask(lookup, false, true));
        assert!(!may_ask(lookup, false, false));
    }

    #[test]
    fn federation_peer_keys_parse() {
        let a = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
        let b = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
        let cfg = format!(" {} ,{},{}", hex::encode(a), hex::encode(b), hex::encode(a));
        let peers = FederationPeers::from_config(Some(&cfg)).unwrap();
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&a) && peers.contains(&b));
        assert!(!peers.contains(&[0x77; 32]));

        assert!(FederationPeers::from_config(None).unwrap().is_empty());
        assert!(FederationPeers::from_config(Some("")).unwrap().is_empty());
        assert_eq!(
            FederationPeers::from_config(Some("abcd")),
            Err("abcd".to_owned())
        );
        assert!(FederationPeers::from_config(Some(&"zz".repeat(32))).is_err());
    }
}
