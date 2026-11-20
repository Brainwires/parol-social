//! Direct data-channel binding (PNP-001 §10.5.1) and safety numbers (PNP-002 §8.7).
//!
//! On a signaling-only relay the data channel's SDP travels in plaintext through the relay, so
//! a hostile relay could replace both DTLS fingerprints and sit in the middle of the "direct"
//! connection. Each peer therefore sends, inside the end-to-end encrypted session and on the
//! channel itself, a CHANNEL_BINDING (0x14) message naming the DTLS fingerprints of its own
//! local description and of the remote description it applied. The receiver checks them
//! against what it sees: the peer's `local` must be the fingerprints in the remote description
//! it applied, and the peer's `remote` the fingerprints of its own local description. A relay
//! that swapped either fingerprint cannot forge the encrypted message, so the swap shows up as
//! a mismatch and the connection is dropped.
//!
//! The safety number is the out-of-band check of the identities themselves: 60 digits from
//! both PeerIds, the same on both screens (the PWA's `safety-number.js` computes the same).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The binding's format version.
pub const CHANNEL_BINDING_VERSION: u8 = 1;
/// At most this many fingerprints per side (an SDP normally carries one).
pub const MAX_FINGERPRINTS: usize = 8;
/// The longest accepted fingerprint string (`sha-512` with colons is 191 characters).
pub const MAX_FINGERPRINT_LEN: usize = 200;

/// Why a binding was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    #[error("a session description has no DTLS fingerprint")]
    NoFingerprint,
    #[error("malformed channel binding: {0}")]
    Malformed(String),
    #[error("unsupported channel binding version {0}")]
    UnsupportedVersion(u8),
    #[error("the DTLS fingerprints differ from the ones the peer sees")]
    Mismatch,
}

/// The body of a CHANNEL_BINDING (0x14) message: CBOR map `{v, local, remote}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelBinding {
    /// [`CHANNEL_BINDING_VERSION`].
    pub v: u8,
    /// The sender's own DTLS fingerprints (its local description), normalized and sorted.
    pub local: Vec<String>,
    /// The fingerprints in the remote description the sender applied.
    pub remote: Vec<String>,
}

/// One normalized fingerprint: `"<hash function, lower case> <HEX:WITH:COLONS, upper case>"`.
fn normalize(algorithm: &str, value: &str) -> Option<String> {
    let algorithm = algorithm.trim().to_ascii_lowercase();
    let value = value.trim().to_ascii_uppercase();
    let ok_alg = !algorithm.is_empty()
        && algorithm
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let ok_val = !value.is_empty()
        && value
            .split(':')
            .all(|g| g.len() == 2 && g.bytes().all(|b| b.is_ascii_hexdigit()));
    let s = format!("{algorithm} {value}");
    (ok_alg && ok_val && s.len() <= MAX_FINGERPRINT_LEN).then_some(s)
}

/// The DTLS fingerprints (`a=fingerprint:` lines, session or media level) of an SDP,
/// normalized, sorted and without duplicates.
pub fn sdp_fingerprints(sdp: &str) -> Vec<String> {
    let mut out: Vec<String> = sdp
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("a=fingerprint:")?;
            let (alg, value) = rest.trim().split_once(char::is_whitespace)?;
            normalize(alg, value)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn canonical(list: &[String]) -> Result<Vec<String>, BindingError> {
    if list.is_empty() || list.len() > MAX_FINGERPRINTS {
        return Err(BindingError::Malformed(format!(
            "{} fingerprints (1 to {MAX_FINGERPRINTS} expected)",
            list.len()
        )));
    }
    let mut out = Vec::with_capacity(list.len());
    for f in list {
        let (alg, value) = f
            .split_once(' ')
            .ok_or_else(|| BindingError::Malformed("fingerprint without a hash function".into()))?;
        out.push(
            normalize(alg, value)
                .ok_or_else(|| BindingError::Malformed("bad fingerprint".into()))?,
        );
    }
    out.sort();
    out.dedup();
    Ok(out)
}

impl ChannelBinding {
    /// The binding this side sends, from its local description and the remote description it
    /// applied to the data channel's connection.
    pub fn from_sdps(local_sdp: &str, remote_sdp: &str) -> Result<Self, BindingError> {
        let local = sdp_fingerprints(local_sdp);
        let remote = sdp_fingerprints(remote_sdp);
        if local.is_empty() || remote.is_empty() {
            return Err(BindingError::NoFingerprint);
        }
        Ok(ChannelBinding {
            v: CHANNEL_BINDING_VERSION,
            local,
            remote,
        })
    }

    /// CBOR encoding (the message's plaintext).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Serializing a struct of strings into a Vec cannot fail.
        let _ = ciborium::into_writer(self, &mut out);
        out
    }

    /// Decode and validate a peer's binding.
    pub fn decode(bytes: &[u8]) -> Result<Self, BindingError> {
        if bytes.len() > 4096 {
            return Err(BindingError::Malformed("too large".into()));
        }
        let raw: ChannelBinding =
            ciborium::from_reader(bytes).map_err(|e| BindingError::Malformed(e.to_string()))?;
        if raw.v != CHANNEL_BINDING_VERSION {
            return Err(BindingError::UnsupportedVersion(raw.v));
        }
        Ok(ChannelBinding {
            v: raw.v,
            local: canonical(&raw.local)?,
            remote: canonical(&raw.remote)?,
        })
    }

    /// Check a binding received from the peer against this side's view of the connection:
    /// the peer's `local` must equal the fingerprints of the remote description we applied,
    /// and the peer's `remote` the fingerprints of our own local description.
    pub fn verify(&self, our_local_sdp: &str, our_remote_sdp: &str) -> Result<(), BindingError> {
        let ours = ChannelBinding::from_sdps(our_local_sdp, our_remote_sdp)?;
        if self.v != CHANNEL_BINDING_VERSION {
            return Err(BindingError::UnsupportedVersion(self.v));
        }
        let theirs_local = canonical(&self.local)?;
        let theirs_remote = canonical(&self.remote)?;
        if theirs_local == ours.remote && theirs_remote == ours.local {
            Ok(())
        } else {
            Err(BindingError::Mismatch)
        }
    }
}

/// The 60-digit safety number of two PeerIds: SHA-256 over the two ids in ascending byte
/// order, the first 30 bytes as six big-endian 40-bit groups, each modulo 10^10 and written
/// as 10 digits, separated by spaces. Symmetric in its arguments.
pub fn safety_number(a: &[u8; 32], b: &[u8; 32]) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update(lo);
    h.update(hi);
    let digest = h.finalize();
    digest[..30]
        .chunks(5)
        .map(|g| {
            let v = g.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
            format!("{:010}", v % 10_000_000_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "v=0\r\na=fingerprint:sha-256 ab:cd:EF:01\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const B: &str = "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=fingerprint:SHA-256 12:34:56:78\r\n";

    #[test]
    fn fingerprints_are_normalized() {
        assert_eq!(sdp_fingerprints(A), vec!["sha-256 AB:CD:EF:01".to_owned()]);
        assert_eq!(sdp_fingerprints(B), vec!["sha-256 12:34:56:78".to_owned()]);
        assert!(sdp_fingerprints("v=0\r\na=fingerprint:sha-256 zz:11\r\n").is_empty());
        assert!(sdp_fingerprints("v=0\r\n").is_empty());
    }

    #[test]
    fn a_matching_binding_verifies_and_a_swap_does_not() {
        // Alice's local is A, Bob's local is B; each applied the other's description.
        let alice = ChannelBinding::from_sdps(A, B).unwrap();
        let wire = alice.encode();
        let received = ChannelBinding::decode(&wire).unwrap();
        assert_eq!(received.verify(B, A), Ok(()));
        // A relay gave Bob a description with its own fingerprint instead of Alice's.
        let mitm = "v=0\r\na=fingerprint:sha-256 66:66:66:66\r\n";
        assert_eq!(received.verify(B, mitm), Err(BindingError::Mismatch));
        // ... or gave Alice its own instead of Bob's (Alice's binding then names it).
        let alice_fooled = ChannelBinding::from_sdps(A, mitm).unwrap();
        assert_eq!(alice_fooled.verify(B, A), Err(BindingError::Mismatch));
    }

    #[test]
    fn malformed_bindings_are_refused() {
        assert!(matches!(
            ChannelBinding::decode(b"not cbor"),
            Err(BindingError::Malformed(_))
        ));
        let mut b = ChannelBinding::from_sdps(A, B).unwrap();
        b.v = 9;
        assert_eq!(
            ChannelBinding::decode(&b.encode()),
            Err(BindingError::UnsupportedVersion(9))
        );
        let empty = ChannelBinding {
            v: 1,
            local: vec![],
            remote: vec!["sha-256 AB".into()],
        };
        assert!(matches!(
            ChannelBinding::decode(&empty.encode()),
            Err(BindingError::Malformed(_))
        ));
        assert_eq!(
            ChannelBinding::from_sdps("v=0", B),
            Err(BindingError::NoFingerprint)
        );
    }

    #[test]
    fn safety_number_is_symmetric_and_sixty_digits() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let n = safety_number(&a, &b);
        assert_eq!(n, safety_number(&b, &a));
        assert_eq!(n.len(), 65);
        assert_eq!(n.split(' ').count(), 6);
        assert!(
            n.split(' ')
                .all(|g| g.len() == 10 && g.bytes().all(|c| c.is_ascii_digit()))
        );
    }
}
