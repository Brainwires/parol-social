//! Signatures a client (or a federation peer) makes *for one relay*
//! (PNP-001 §10.7, PNP-008 §10.8).
//!
//! A relay proves who is on the other end of a socket by having them sign a
//! nonce. A signature over the bare nonce says nothing about *which relay*
//! the signer meant: a relay the signer connected to can obtain a nonce from
//! another relay, hand it over as its own challenge and present the answer
//! there. Every message built here therefore carries
//!
//! * a domain-separation label, so the signature cannot be taken for any
//!   other statement made with the same key, and
//! * the **relay name**: the `host:port` the signer dialed, in the canonical
//!   form of [`RelayName`]. A relay accepts a signature only for a name it is
//!   configured to serve.
//!
//! Every field has a fixed length except the name, which is last and
//! length-prefixed, so no two different inputs encode to the same bytes.

use crate::address::PeerId;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Label of a `register` answer (PNP-001-MUST-084).
pub const REGISTER_LABEL: &[u8; 25] = b"PNP-001-relay-register-v1";
/// Label of an authenticated `/peers/*` request (PNP-008-MUST-100).
pub const PEERS_REQUEST_LABEL: &[u8; 24] = b"PNP-008-peers-request-v1";
/// Bytes in a register challenge nonce.
pub const REGISTER_NONCE_LEN: usize = 32;
/// Longest canonical relay name: a 253-byte host, `:` and a 5-digit port.
pub const MAX_RELAY_NAME_LEN: usize = 259;
/// A `/peers/*` request is accepted this many seconds either side of the
/// relay's clock (PNP-008-MUST-101).
pub const PEERS_REQUEST_MAX_SKEW_SECS: u64 = 60;
/// `Authorization` scheme of an authenticated `/peers/*` request.
pub const PEERS_AUTH_SCHEME: &str = "PNP-Ed25519";

/// Why a string is not a relay name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayNameError {
    #[error("relay name is empty")]
    Empty,
    #[error("relay name is too long")]
    TooLong,
    #[error("relay host has a character outside a-z 0-9 . - _")]
    BadHost,
    #[error("relay host is not a valid IPv6 literal")]
    BadIpv6,
    #[error("relay port is not a decimal number from 1 to 65535")]
    BadPort,
    #[error("relay name is not in canonical form")]
    NotCanonical,
    #[error("relay URL scheme is not ws, wss, http or https")]
    BadScheme,
    #[error("relay URL has user information or a malformed authority")]
    BadAuthority,
}

/// The canonical name of a relay: `host:port`.
///
/// * `host` is a DNS name or IPv4 literal in lowercase ASCII (`a-z 0-9 . - _`,
///   internationalised names as A-labels, no trailing dot), or an IPv6
///   literal in square brackets in its shortest lowercase hexadecimal form.
/// * `port` is always present, in decimal without leading zeros. A URL that
///   names no port has its scheme's default: 443 for `wss` / `https`, 80 for
///   `ws` / `http`.
///
/// `wss://Relay.Example/ws` is `relay.example:443`;
/// `ws://127.0.0.1:9000/ws` is `127.0.0.1:9000`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelayName(String);

impl RelayName {
    /// Accept a string only if it already is a canonical relay name.
    pub fn parse(s: &str) -> Result<Self, RelayNameError> {
        let (host, port) = split_host_port(s)?;
        let port = port.ok_or(RelayNameError::BadPort)?;
        let name = Self::from_host_port(host, port)?;
        if name.0 != s {
            return Err(RelayNameError::NotCanonical);
        }
        Ok(name)
    }

    /// Canonicalise a host (as a URL parser reports it) and a port.
    ///
    /// The host is lowercased, one trailing dot is dropped and an IPv6
    /// literal (with or without brackets) is rewritten in its shortest form.
    /// Anything outside the canonical alphabet is refused, never repaired.
    pub fn from_host_port(host: &str, port: u16) -> Result<Self, RelayNameError> {
        if port == 0 {
            return Err(RelayNameError::BadPort);
        }
        if host.is_empty() {
            return Err(RelayNameError::Empty);
        }
        if !host.is_ascii() {
            return Err(RelayNameError::BadHost);
        }
        let host = host.to_ascii_lowercase();
        let canonical_host = if host.starts_with('[') || host.contains(':') {
            let inner = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(&host);
            let addr: std::net::Ipv6Addr = inner.parse().map_err(|_| RelayNameError::BadIpv6)?;
            format!("[{}]", format_ipv6(addr.segments()))
        } else {
            let host = host.strip_suffix('.').unwrap_or(&host);
            if host.is_empty() {
                return Err(RelayNameError::Empty);
            }
            if host.len() > 253 {
                return Err(RelayNameError::TooLong);
            }
            let ok_chars = host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b));
            if !ok_chars || host.starts_with('.') || host.ends_with('.') || host.contains("..") {
                return Err(RelayNameError::BadHost);
            }
            host.to_owned()
        };
        let name = format!("{canonical_host}:{port}");
        if name.len() > MAX_RELAY_NAME_LEN {
            return Err(RelayNameError::TooLong);
        }
        Ok(Self(name))
    }

    /// The name of the relay a `ws`, `wss`, `http` or `https` URL points at.
    ///
    /// Strict on purpose: user information, backslashes, whitespace, percent
    /// escapes and non-ASCII hosts are refused, so there is no URL that this
    /// function and a lenient URL parser read as two different hosts.
    pub fn from_url(url: &str) -> Result<Self, RelayNameError> {
        let (scheme, rest) = url.split_once("://").ok_or(RelayNameError::BadScheme)?;
        let default_port = match scheme.to_ascii_lowercase().as_str() {
            "wss" | "https" => 443,
            "ws" | "http" => 80,
            _ => return Err(RelayNameError::BadScheme),
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty() {
            return Err(RelayNameError::Empty);
        }
        let (host, port) = split_host_port(authority)?;
        Self::from_host_port(host, port.unwrap_or(default_port))
    }

    /// A name from relay configuration: `host` or `host:port`, where a
    /// missing port means 443 (the relay is reached over `wss`).
    pub fn from_config(entry: &str) -> Result<Self, RelayNameError> {
        let (host, port) = split_host_port(entry.trim())?;
        Self::from_host_port(host, port.unwrap_or(443))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the host is `localhost` or a loopback address.
    pub fn is_loopback(&self) -> bool {
        let host = match self.0.rfind(':') {
            Some(i) => &self.0[..i],
            None => return false,
        };
        if host == "localhost" {
            return true;
        }
        if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            return inner
                .parse::<std::net::Ipv6Addr>()
                .is_ok_and(|a| a.is_loopback());
        }
        host.parse::<std::net::Ipv4Addr>()
            .is_ok_and(|a| a.is_loopback())
    }
}

impl std::fmt::Display for RelayName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Split `host`, `host:port`, `[v6]` or `[v6]:port`. The host is returned as
/// written (brackets included); an absent port is `None`.
fn split_host_port(s: &str) -> Result<(&str, Option<u16>), RelayNameError> {
    if s.is_empty() {
        return Err(RelayNameError::Empty);
    }
    if s.bytes()
        .any(|b| b == b'@' || b == b'\\' || b == b'%' || b <= b' ' || b >= 0x7f)
    {
        return Err(RelayNameError::BadAuthority);
    }
    let (host, port) = if s.starts_with('[') {
        let end = s.find(']').ok_or(RelayNameError::BadIpv6)?;
        let (host, rest) = s.split_at(end + 1);
        match rest {
            "" => (host, None),
            _ => (
                host,
                Some(rest.strip_prefix(':').ok_or(RelayNameError::BadAuthority)?),
            ),
        }
    } else {
        match s.split_once(':') {
            None => (s, None),
            Some((host, port)) => (host, Some(port)),
        }
    };
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(RelayNameError::BadPort);
            }
            match p.parse::<u16>() {
                Ok(n) if n != 0 => Some(n),
                _ => return Err(RelayNameError::BadPort),
            }
        }
    };
    Ok((host, port))
}

/// Eight groups as lowercase hexadecimal without leading zeros, with the
/// first longest run of two or more zero groups written `::` (RFC 5952 §4,
/// and what a browser's URL parser prints). An embedded IPv4 address is not
/// written in dotted form.
fn format_ipv6(groups: [u16; 8]) -> String {
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let mut i = 0;
    while i < 8 {
        if groups[i] == 0 {
            let start = i;
            while i < 8 && groups[i] == 0 {
                i += 1;
            }
            if i - start > best_len {
                (best_start, best_len) = (start, i - start);
            }
        } else {
            i += 1;
        }
    }
    let hex = |gs: &[u16]| {
        gs.iter()
            .map(|g| format!("{g:x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    if best_len < 2 {
        return hex(&groups);
    }
    format!(
        "{}::{}",
        hex(&groups[..best_start]),
        hex(&groups[best_start + best_len..])
    )
}

fn push_name(buf: &mut Vec<u8>, relay: &RelayName) {
    let name = relay.as_str().as_bytes();
    // A RelayName is at most MAX_RELAY_NAME_LEN bytes.
    buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
    buf.extend_from_slice(name);
}

/// The bytes a client signs to answer a register challenge (PNP-001 §10.7):
///
/// ```text
/// label      25  "PNP-001-relay-register-v1"
/// nonce      32  the relay's challenge
/// pin         1  0x01 if the client pins the relay's identity key, else 0x00
/// relay_key  32  that Ed25519 key, or 32 zero bytes when pin is 0x00
/// name_len    2  big-endian length of name
/// name        n  the canonical relay name the client dialed
/// ```
pub fn register_signable(
    nonce: &[u8; REGISTER_NONCE_LEN],
    relay: &RelayName,
    pinned_relay_key: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(25 + 32 + 1 + 32 + 2 + relay.as_str().len());
    buf.extend_from_slice(REGISTER_LABEL);
    buf.extend_from_slice(nonce);
    match pinned_relay_key {
        Some(key) => {
            buf.push(0x01);
            buf.extend_from_slice(key);
        }
        None => {
            buf.push(0x00);
            buf.extend_from_slice(&[0u8; 32]);
        }
    }
    push_name(&mut buf, relay);
    buf
}

/// What an authenticated `/peers/*` request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeersRequest {
    /// `GET /peers/presence`.
    Presence,
    /// `GET /peers/lookup?id=<peer>`.
    Lookup(PeerId),
}

/// The bytes signed for an authenticated `/peers/*` request (PNP-008 §10.8):
///
/// ```text
/// label      24  "PNP-008-peers-request-v1"
/// kind        1  0x01 presence, 0x02 lookup
/// timestamp   8  Unix seconds, big-endian
/// target     32  the PeerId looked up; 32 zero bytes for presence
/// name_len    2  big-endian length of name
/// name        n  the canonical relay name the requester dialed
/// ```
pub fn peers_request_signable(request: PeersRequest, timestamp: u64, relay: &RelayName) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + 1 + 8 + 32 + 2 + relay.as_str().len());
    buf.extend_from_slice(PEERS_REQUEST_LABEL);
    match request {
        PeersRequest::Presence => {
            buf.push(0x01);
            buf.extend_from_slice(&timestamp.to_be_bytes());
            buf.extend_from_slice(&[0u8; 32]);
        }
        PeersRequest::Lookup(target) => {
            buf.push(0x02);
            buf.extend_from_slice(&timestamp.to_be_bytes());
            buf.extend_from_slice(&target.0);
        }
    }
    push_name(&mut buf, relay);
    buf
}

/// The credentials of an authenticated `/peers/*` request: the value of its
/// `Authorization` header,
/// `PNP-Ed25519 key=<64 hex>,ts=<decimal>,relay=<name>,sig=<128 hex>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeersAuthorization {
    /// The requester's Ed25519 public key.
    pub key: [u8; 32],
    /// Unix seconds at which the request was signed.
    pub timestamp: u64,
    /// The relay the requester dialed.
    pub relay: RelayName,
    pub signature: [u8; 64],
}

impl PeersAuthorization {
    /// Build the credentials for `request`, signing with `sign`.
    pub fn sign(
        request: PeersRequest,
        key: [u8; 32],
        timestamp: u64,
        relay: RelayName,
        sign: impl FnOnce(&[u8]) -> [u8; 64],
    ) -> Self {
        let signature = sign(&peers_request_signable(request, timestamp, &relay));
        Self {
            key,
            timestamp,
            relay,
            signature,
        }
    }

    /// The `Authorization` header value.
    pub fn to_header(&self) -> String {
        format!(
            "{PEERS_AUTH_SCHEME} key={},ts={},relay={},sig={}",
            hex::encode(self.key),
            self.timestamp,
            self.relay,
            hex::encode(self.signature)
        )
    }

    /// Parse an `Authorization` header value. Each of the four parameters
    /// must appear exactly once; anything else is refused.
    pub fn parse_header(value: &str) -> Option<Self> {
        let params = value.strip_prefix(PEERS_AUTH_SCHEME)?.strip_prefix(' ')?;
        let (mut key, mut ts, mut relay, mut sig) = (None, None, None, None);
        for param in params.split(',') {
            let (name, v) = param.split_once('=')?;
            let slot = match name {
                "key" => &mut key,
                "ts" => &mut ts,
                "relay" => &mut relay,
                "sig" => &mut sig,
                _ => return None,
            };
            if slot.replace(v).is_some() {
                return None;
            }
        }
        let ts = ts?;
        if ts.is_empty() || ts.len() > 20 || !ts.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Self {
            key: hex::decode(key?).ok()?.try_into().ok()?,
            timestamp: ts.parse().ok()?,
            relay: RelayName::parse(relay?).ok()?,
            signature: hex::decode(sig?).ok()?.try_into().ok()?,
        })
    }

    /// Whether `signature` is `key`'s over `request` as addressed to
    /// `self.relay` at `self.timestamp`. The caller still has to check that
    /// the name is its own, that the timestamp is fresh and that `key` is
    /// allowed to ask.
    pub fn verify(&self, request: PeersRequest) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.key) else {
            return false;
        };
        key.verify(
            &peers_request_signable(request, self.timestamp, &self.relay),
            &Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }

    /// Whether the timestamp is within [`PEERS_REQUEST_MAX_SKEW_SECS`] of `now`.
    pub fn is_fresh(&self, now_secs: u64) -> bool {
        now_secs.abs_diff(self.timestamp) <= PEERS_REQUEST_MAX_SKEW_SECS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn name(s: &str) -> RelayName {
        RelayName::parse(s).unwrap()
    }

    #[test]
    fn urls_canonicalise_to_host_and_explicit_port() {
        for (url, want) in [
            ("wss://parol.social/ws", "parol.social:443"),
            ("wss://Parol.Social:443/ws", "parol.social:443"),
            ("wss://parol.social.:8443", "parol.social:8443"),
            ("ws://relay.example/ws", "relay.example:80"),
            ("https://relay.example", "relay.example:443"),
            ("http://1.2.3.4:9000/", "1.2.3.4:9000"),
            ("ws://127.0.0.1:9000/ws?x=1#f", "127.0.0.1:9000"),
            ("ws://[::1]:9000/ws", "[::1]:9000"),
            ("wss://[2001:DB8:0:0:0:0:0:1]/ws", "[2001:db8::1]:443"),
            ("ws://[::ffff:1.2.3.4]:80", "[::ffff:102:304]:80"),
            ("ws://my_relay:9000", "my_relay:9000"),
        ] {
            assert_eq!(RelayName::from_url(url).unwrap().as_str(), want, "{url}");
        }
    }

    #[test]
    fn urls_a_lenient_parser_could_read_differently_are_refused() {
        for url in [
            "wss://relay.example@evil.example/ws",
            "wss://user:pw@relay.example/ws",
            "wss://evil.example\\.relay.example/ws",
            "wss://relay.example\\@evil.example/ws",
            "wss://relay%2eexample/ws",
            "wss://rel\tay.example/ws",
            "wss://relay.example :443/ws",
            "wss://rélay.example/ws",
            "wss://relay..example/ws",
            "wss://.relay.example/ws",
            "wss:///ws",
            "wss://:443/ws",
            "wss://relay.example:0/ws",
            "wss://relay.example:65536/ws",
            "wss://relay.example:44a/ws",
            "wss://relay.example:/ws",
            "wss://[::1/ws",
            "wss://[::1]x/ws",
            "wss://[zz::1]/ws",
            "ftp://relay.example/",
            "relay.example:443",
        ] {
            assert!(RelayName::from_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn parse_accepts_only_the_canonical_spelling() {
        for ok in [
            "parol.social:443",
            "127.0.0.1:9000",
            "[::1]:9000",
            "localhost:1",
        ] {
            assert_eq!(name(ok).as_str(), ok);
        }
        for bad in [
            "",
            "parol.social",
            "Parol.Social:443",
            "parol.social.:443",
            "parol.social:0443",
            "parol.social:0",
            "parol.social:65536",
            "[0:0:0:0:0:0:0:1]:9000",
            "[::1]",
            "::1:9000",
            "a:b:443",
            "parol.social:443 ",
            "parol.social:443\n",
        ] {
            assert!(RelayName::parse(bad).is_err(), "{bad:?}");
        }
        let long = format!("{}:443", "a".repeat(254));
        assert_eq!(RelayName::parse(&long), Err(RelayNameError::TooLong));
        let longest = format!("{}:65535", "a".repeat(253));
        assert_eq!(longest.len(), MAX_RELAY_NAME_LEN);
        assert!(RelayName::parse(&longest).is_ok());
    }

    #[test]
    fn configured_names_default_to_port_443() {
        assert_eq!(
            RelayName::from_config(" Parol.Social ").unwrap(),
            name("parol.social:443")
        );
        assert_eq!(
            RelayName::from_config("relay.example:9000").unwrap(),
            name("relay.example:9000")
        );
        assert_eq!(RelayName::from_config("[::1]").unwrap(), name("[::1]:443"));
        assert!(RelayName::from_config("wss://parol.social").is_err());
        assert!(RelayName::from_config("").is_err());
    }

    #[test]
    fn loopback_names() {
        for n in [
            "localhost:9000",
            "127.0.0.1:1",
            "127.8.9.10:80",
            "[::1]:443",
        ] {
            assert!(name(n).is_loopback(), "{n}");
        }
        for n in [
            "parol.social:443",
            "localhost.example:443",
            "128.0.0.1:80",
            "[::2]:443",
            "10.0.0.1:9000",
        ] {
            assert!(!name(n).is_loopback(), "{n}");
        }
    }

    #[test]
    fn register_signable_layout() {
        let nonce = [0xAB; 32];
        let relay = name("parol.social:443");
        let m = register_signable(&nonce, &relay, None);
        assert_eq!(m.len(), 25 + 32 + 1 + 32 + 2 + 16);
        assert_eq!(&m[..25], b"PNP-001-relay-register-v1");
        assert_eq!(&m[25..57], &nonce);
        assert_eq!(m[57], 0);
        assert_eq!(&m[58..90], &[0u8; 32]);
        assert_eq!(&m[90..92], &[0, 16]);
        assert_eq!(&m[92..], b"parol.social:443");

        let key = [0x07; 32];
        let pinned = register_signable(&nonce, &relay, Some(&key));
        assert_eq!(pinned[57], 1);
        assert_eq!(&pinned[58..90], &key);
        assert_ne!(m, pinned);
        // An unpinned answer is not the answer of a client that pinned the
        // all-zero key.
        assert_ne!(m, register_signable(&nonce, &relay, Some(&[0u8; 32])));
    }

    #[test]
    fn register_signable_differs_per_relay_and_nonce() {
        let nonce = [1u8; 32];
        let a = register_signable(&nonce, &name("relay-a.example:443"), None);
        let b = register_signable(&nonce, &name("relay-b.example:443"), None);
        assert_ne!(a, b);
        let other_port = register_signable(&nonce, &name("relay-a.example:8443"), None);
        assert_ne!(a, other_port);
        assert_ne!(
            a,
            register_signable(&[2u8; 32], &name("relay-a.example:443"), None)
        );
    }

    #[test]
    fn peers_authorization_round_trips_and_binds_every_field() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let relay = name("relay.example:443");
        let target = PeerId([0x42; 32]);
        let auth = PeersAuthorization::sign(
            PeersRequest::Lookup(target),
            sk.verifying_key().to_bytes(),
            1_700_000_000,
            relay.clone(),
            |m| sk.sign(m).to_bytes(),
        );
        let parsed = PeersAuthorization::parse_header(&auth.to_header()).unwrap();
        assert_eq!(parsed, auth);
        assert!(parsed.verify(PeersRequest::Lookup(target)));
        // Another target, another kind, another relay, another time.
        assert!(!parsed.verify(PeersRequest::Lookup(PeerId([0x43; 32]))));
        assert!(!parsed.verify(PeersRequest::Presence));
        let mut other = parsed.clone();
        other.relay = name("other.example:443");
        assert!(!other.verify(PeersRequest::Lookup(target)));
        let mut later = parsed.clone();
        later.timestamp += 1;
        assert!(!later.verify(PeersRequest::Lookup(target)));

        assert!(parsed.is_fresh(1_700_000_000 + 60));
        assert!(parsed.is_fresh(1_700_000_000 - 60));
        assert!(!parsed.is_fresh(1_700_000_000 + 61));
        assert!(!parsed.is_fresh(1_700_000_000 - 61));
    }

    #[test]
    fn malformed_authorization_headers_are_refused() {
        let good = format!(
            "PNP-Ed25519 key={},ts=5,relay=relay.example:443,sig={}",
            "11".repeat(32),
            "22".repeat(64)
        );
        assert!(PeersAuthorization::parse_header(&good).is_some());
        for bad in [
            good.replace("PNP-Ed25519 ", "Bearer "),
            good.replace("PNP-Ed25519 ", "PNP-Ed25519"),
            good.replace("ts=5", "ts=+5"),
            good.replace("ts=5", "ts="),
            good.replace("ts=5", "ts=5,ts=5"),
            good.replace("relay.example:443", "Relay.Example:443"),
            good.replace("relay.example:443", "relay.example"),
            good.replace(",relay=relay.example:443", ""),
            good.replace("key=11", "key=1"),
            format!("{good},extra=1"),
            good.replace("sig=22", "sig=2"),
        ] {
            assert!(PeersAuthorization::parse_header(&bad).is_none(), "{bad}");
        }
    }
}
