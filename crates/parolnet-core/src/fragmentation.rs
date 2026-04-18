//! Envelope fragmentation & reassembly (PNP-001 §3.9).
//!
//! Application bodies that would overflow the 16384-byte bucket ceiling are
//! split into multiple single-envelope fragments, each carrying a shared
//! `fragment_id` and a `fragment_seq`. The receiving side buffers fragments
//! keyed by `(sender_peer_id, fragment_id)` and concatenates them in seq
//! order once the final-bit fragment plus every earlier seq has arrived.
//!
//! This module is WASM-compatible and pure data — no tokio, no networking.
//! Time is supplied by the caller; the buffer-eviction tick must be driven
//! externally (typically from the same ticker the session layer already uses).
//!
//! ## Spec mapping
//! - [`FragmentPiece`] corresponds to the §3.3 plaintext map when
//!   `is_fragment = 1`.
//! - [`Fragmenter::split`] produces fragments satisfying MUST-053, MUST-054,
//!   MUST-055, MUST-056.
//! - [`Reassembler::push`] enforces MUST-058 (ordered reassembly), MUST-060
//!   (caps), MUST-061 (duplicate handling), and MUST-062 (metadata
//!   consistency — caller supplies metadata alongside).
//! - [`Reassembler::tick`] enforces MUST-059 (30-second timeout).

use parolnet_protocol::address::PeerId;
use rand_core::RngCore;
use std::collections::{BTreeMap, HashMap};

/// Length of a fragment_id in bytes (PNP-001 §3.9, 128 bits).
pub const FRAGMENT_ID_BYTES: usize = 16;

/// Reassembly timeout measured from the first fragment's arrival
/// (PNP-001-MUST-059).
pub const REASSEMBLY_TIMEOUT_SECS: u64 = 30;

/// Per-sender cap on in-flight partial messages (PNP-001-MUST-060).
pub const MAX_INFLIGHT_PER_SENDER: usize = 8;

/// Per-message cap on fragment count (PNP-001-MUST-060).
pub const MAX_FRAGMENTS_PER_MESSAGE: usize = 256;

/// One fragment of a larger message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FragmentPiece {
    pub fragment_id: [u8; FRAGMENT_ID_BYTES],
    pub fragment_seq: u32,
    pub is_final: bool,
    /// The slice of the original body carried by this fragment.
    pub body: Vec<u8>,
}

/// Splits a byte body into `FragmentPiece`s.
pub struct Fragmenter;

impl Fragmenter {
    /// Split `body` into ordered fragments of at most `max_per_fragment` bytes.
    ///
    /// Returns an empty `Vec` when `body` is empty (nothing to fragment).
    /// Panics if `max_per_fragment == 0`. Returns `Err(FragmentError::TooLarge)`
    /// if splitting `body` at the requested slice size would exceed the
    /// PNP-001-MUST-060 256-fragment cap.
    pub fn split(
        body: &[u8],
        max_per_fragment: usize,
        rng: &mut impl RngCore,
    ) -> Result<Vec<FragmentPiece>, FragmentError> {
        assert!(max_per_fragment > 0, "max_per_fragment must be > 0");
        if body.is_empty() {
            return Ok(Vec::new());
        }
        let num_fragments = body.len().div_ceil(max_per_fragment);
        if num_fragments > MAX_FRAGMENTS_PER_MESSAGE {
            return Err(FragmentError::TooLarge {
                fragments_needed: num_fragments,
                cap: MAX_FRAGMENTS_PER_MESSAGE,
            });
        }
        let mut fragment_id = [0u8; FRAGMENT_ID_BYTES];
        rng.fill_bytes(&mut fragment_id);
        let mut out = Vec::with_capacity(num_fragments);
        for (idx, chunk) in body.chunks(max_per_fragment).enumerate() {
            out.push(FragmentPiece {
                fragment_id,
                fragment_seq: idx as u32,
                is_final: idx + 1 == num_fragments,
                body: chunk.to_vec(),
            });
        }
        Ok(out)
    }
}

/// Outcome of feeding a fragment into [`Reassembler::push`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReassemblyResult {
    /// Fragment buffered; reassembly not yet complete.
    Buffered,
    /// Every fragment has now arrived; reassembled body returned.
    Complete(Vec<u8>),
    /// Fragment with identical (sender, fragment_id, fragment_seq) already
    /// buffered — silently discarded per MUST-061.
    Duplicate,
    /// Fragment rejected because a cap was reached or metadata was invalid.
    Rejected(FragmentError),
}

/// Fragmenter / reassembler failure mode.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FragmentError {
    #[error("MUST-060: sender in-flight cap reached ({0})")]
    InFlightCapReached(usize),
    #[error("MUST-060: fragment seq out of range ({seq} >= {cap})")]
    FragmentSeqOutOfRange { seq: u32, cap: usize },
    #[error("MUST-060: body too large — would need {fragments_needed} fragments (cap {cap})")]
    TooLarge { fragments_needed: usize, cap: usize },
    #[error("fragment_id length invalid: got {0} expected 16")]
    FragmentIdLength(usize),
}

#[derive(Debug)]
struct ReassemblyBuffer {
    fragments: BTreeMap<u32, Vec<u8>>,
    final_seq: Option<u32>,
    /// Unix seconds — arrival of the first fragment in this buffer.
    created_at: u64,
}

impl ReassemblyBuffer {
    fn new(now: u64) -> Self {
        Self {
            fragments: BTreeMap::new(),
            final_seq: None,
            created_at: now,
        }
    }

    fn is_complete(&self) -> bool {
        let Some(final_seq) = self.final_seq else {
            return false;
        };
        // Every seq in 0..=final_seq present.
        (0..=final_seq).all(|s| self.fragments.contains_key(&s))
    }

    fn reassemble(mut self) -> Vec<u8> {
        // BTreeMap iterates in key order — that's our fragment_seq order.
        let mut out = Vec::new();
        for (_seq, slice) in self.fragments.iter_mut() {
            out.append(slice);
        }
        out
    }
}

/// Holds in-flight partial messages per sender.
pub struct Reassembler {
    buffers: HashMap<(PeerId, [u8; FRAGMENT_ID_BYTES]), ReassemblyBuffer>,
    max_inflight_per_sender: usize,
    max_fragments_per_message: usize,
    reassembly_timeout_secs: u64,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Self::with_bounds(
            MAX_INFLIGHT_PER_SENDER,
            MAX_FRAGMENTS_PER_MESSAGE,
            REASSEMBLY_TIMEOUT_SECS,
        )
    }

    pub fn with_bounds(
        max_inflight_per_sender: usize,
        max_fragments_per_message: usize,
        reassembly_timeout_secs: u64,
    ) -> Self {
        Self {
            buffers: HashMap::new(),
            max_inflight_per_sender,
            max_fragments_per_message,
            reassembly_timeout_secs,
        }
    }

    /// Number of in-flight partial messages from `sender`.
    pub fn inflight_for(&self, sender: &PeerId) -> usize {
        self.buffers.keys().filter(|(p, _)| p == sender).count()
    }

    /// Total number of in-flight partial messages across all senders.
    pub fn total_inflight(&self) -> usize {
        self.buffers.len()
    }

    /// Feed a fragment. Returns the reassembled body if this completes a
    /// message.
    pub fn push(
        &mut self,
        sender: PeerId,
        frag: FragmentPiece,
        now: u64,
    ) -> ReassemblyResult {
        if (frag.fragment_seq as usize) >= self.max_fragments_per_message {
            return ReassemblyResult::Rejected(FragmentError::FragmentSeqOutOfRange {
                seq: frag.fragment_seq,
                cap: self.max_fragments_per_message,
            });
        }
        let key = (sender, frag.fragment_id);
        // Reject new-message admission past the per-sender cap. If the buffer
        // already exists we allow the additional fragment.
        if !self.buffers.contains_key(&key)
            && self.inflight_for(&sender) >= self.max_inflight_per_sender
        {
            return ReassemblyResult::Rejected(FragmentError::InFlightCapReached(
                self.max_inflight_per_sender,
            ));
        }
        let buffer = self
            .buffers
            .entry(key)
            .or_insert_with(|| ReassemblyBuffer::new(now));

        // MUST-061: duplicates silently discarded; first-writer wins.
        if buffer.fragments.contains_key(&frag.fragment_seq) {
            return ReassemblyResult::Duplicate;
        }
        buffer.fragments.insert(frag.fragment_seq, frag.body);
        if frag.is_final {
            // Keep the highest final seq seen — spec says exactly one should
            // carry the bit, but defensively we take the max.
            buffer.final_seq = Some(match buffer.final_seq {
                None => frag.fragment_seq,
                Some(prev) => prev.max(frag.fragment_seq),
            });
        }

        if buffer.is_complete() {
            let buffer = self.buffers.remove(&key).unwrap();
            ReassemblyResult::Complete(buffer.reassemble())
        } else {
            ReassemblyResult::Buffered
        }
    }

    /// Evict buffers older than the §3.9 reassembly timeout. Returns the
    /// `(sender, fragment_id)` tuples that were dropped.
    pub fn tick(&mut self, now: u64) -> Vec<(PeerId, [u8; FRAGMENT_ID_BYTES])> {
        let timeout = self.reassembly_timeout_secs;
        let expired: Vec<_> = self
            .buffers
            .iter()
            .filter(|(_, buf)| now.saturating_sub(buf.created_at) > timeout)
            .map(|(key, _)| *key)
            .collect();
        for key in &expired {
            self.buffers.remove(key);
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn peer(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    // -- Fragmenter --------------------------------------------------------

    #[test]
    fn split_empty_body_produces_no_fragments() {
        let out = Fragmenter::split(&[], 10, &mut rng()).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn split_fits_in_one_fragment() {
        let out = Fragmenter::split(&[0xaa; 8], 10, &mut rng()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].fragment_seq, 0);
        assert!(out[0].is_final);
    }

    #[test]
    fn split_many_fragments_have_sequential_seqs() {
        let body = vec![0u8; 100];
        let out = Fragmenter::split(&body, 10, &mut rng()).unwrap();
        assert_eq!(out.len(), 10);
        for (i, f) in out.iter().enumerate() {
            assert_eq!(f.fragment_seq as usize, i);
        }
        // MUST-055: exactly one final.
        assert_eq!(out.iter().filter(|f| f.is_final).count(), 1);
        assert!(out.last().unwrap().is_final);
    }

    #[test]
    fn split_shares_fragment_id_across_message() {
        let body = vec![0u8; 50];
        let out = Fragmenter::split(&body, 10, &mut rng()).unwrap();
        let id = out[0].fragment_id;
        assert!(out.iter().all(|f| f.fragment_id == id));
        assert_eq!(id.len(), FRAGMENT_ID_BYTES);
    }

    #[test]
    fn split_rejects_body_exceeding_fragment_cap() {
        // 256 fragments is the cap; 257 would violate MUST-060.
        let body = vec![0u8; 257];
        let err = Fragmenter::split(&body, 1, &mut rng()).unwrap_err();
        assert!(matches!(err, FragmentError::TooLarge { .. }));
    }

    // -- Reassembler happy path & out-of-order -----------------------------

    #[test]
    fn happy_path_reassembly_matches_spec_vector() {
        let v: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../specs/vectors/PNP-001/fragment_happy_path.json"
        ))
        .unwrap();
        let fid: [u8; 16] = hex::decode(v["fragment_id_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut r = Reassembler::new();
        let sender = peer(1);
        let mut last = ReassemblyResult::Buffered;
        for arr in v["arrivals"].as_array().unwrap() {
            let frag = FragmentPiece {
                fragment_id: fid,
                fragment_seq: arr["fragment_seq"].as_u64().unwrap() as u32,
                is_final: arr["is_final_fragment"].as_bool().unwrap(),
                body: hex::decode(arr["body_hex"].as_str().unwrap()).unwrap(),
            };
            last = r.push(sender, frag, 100);
        }
        let expected = hex::decode(v["expected_reassembled_hex"].as_str().unwrap()).unwrap();
        assert_eq!(last, ReassemblyResult::Complete(expected));
        // Buffer cleared on completion.
        assert_eq!(r.total_inflight(), 0);
    }

    #[test]
    fn out_of_order_reassembly_matches_spec_vector() {
        let v: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../specs/vectors/PNP-001/fragment_out_of_order.json"
        ))
        .unwrap();
        let fid: [u8; 16] = hex::decode(v["fragment_id_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut r = Reassembler::new();
        let sender = peer(2);
        let mut last = ReassemblyResult::Buffered;
        for arr in v["arrivals"].as_array().unwrap() {
            let frag = FragmentPiece {
                fragment_id: fid,
                fragment_seq: arr["fragment_seq"].as_u64().unwrap() as u32,
                is_final: arr["is_final_fragment"].as_bool().unwrap(),
                body: hex::decode(arr["body_hex"].as_str().unwrap()).unwrap(),
            };
            last = r.push(sender, frag, 100);
        }
        let expected = hex::decode(v["expected_reassembled_hex"].as_str().unwrap()).unwrap();
        assert_eq!(last, ReassemblyResult::Complete(expected));
    }

    #[test]
    fn duplicate_fragment_discarded_silently() {
        let v: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../specs/vectors/PNP-001/fragment_duplicate.json"
        ))
        .unwrap();
        let fid: [u8; 16] = hex::decode(v["fragment_id_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut r = Reassembler::new();
        let sender = peer(3);
        let mut outcomes = Vec::new();
        for arr in v["arrivals"].as_array().unwrap() {
            let frag = FragmentPiece {
                fragment_id: fid,
                fragment_seq: arr["fragment_seq"].as_u64().unwrap() as u32,
                is_final: arr["is_final_fragment"].as_bool().unwrap(),
                body: hex::decode(arr["body_hex"].as_str().unwrap()).unwrap(),
            };
            outcomes.push(r.push(sender, frag, 100));
        }
        // First arrival: Buffered. Second (duplicate): Duplicate. Third: Complete.
        assert_eq!(outcomes[0], ReassemblyResult::Buffered);
        assert_eq!(outcomes[1], ReassemblyResult::Duplicate);
        let expected = hex::decode(v["expected_reassembled_hex"].as_str().unwrap()).unwrap();
        assert_eq!(outcomes[2], ReassemblyResult::Complete(expected));
    }

    // -- Timeout -----------------------------------------------------------

    #[test]
    fn buffer_dropped_after_reassembly_timeout() {
        let mut r = Reassembler::new();
        let sender = peer(4);
        let fid = [0xab; 16];
        let frag = FragmentPiece {
            fragment_id: fid,
            fragment_seq: 0,
            is_final: false,
            body: vec![1, 2, 3],
        };
        r.push(sender, frag, 0);
        assert_eq!(r.total_inflight(), 1);
        // Within window — no eviction.
        let evicted = r.tick(REASSEMBLY_TIMEOUT_SECS);
        assert!(evicted.is_empty());
        assert_eq!(r.total_inflight(), 1);
        // Past window — evicted.
        let evicted = r.tick(REASSEMBLY_TIMEOUT_SECS + 1);
        assert_eq!(evicted, vec![(sender, fid)]);
        assert_eq!(r.total_inflight(), 0);
    }

    #[test]
    fn evicted_buffer_does_not_resume() {
        // After timeout eviction, a fragment with the same id MUST NOT
        // resurrect the dropped buffer's older contents.
        let mut r = Reassembler::new();
        let sender = peer(5);
        let fid = [0xcd; 16];
        r.push(
            sender,
            FragmentPiece {
                fragment_id: fid,
                fragment_seq: 0,
                is_final: false,
                body: vec![0x11],
            },
            0,
        );
        r.tick(REASSEMBLY_TIMEOUT_SECS + 10);
        // New fragment under the same id — fresh buffer, old slice is gone.
        r.push(
            sender,
            FragmentPiece {
                fragment_id: fid,
                fragment_seq: 0,
                is_final: false,
                body: vec![0x99],
            },
            100,
        );
        let outcome = r.push(
            sender,
            FragmentPiece {
                fragment_id: fid,
                fragment_seq: 1,
                is_final: true,
                body: vec![0xaa],
            },
            101,
        );
        assert_eq!(outcome, ReassemblyResult::Complete(vec![0x99, 0xaa]));
    }

    // -- Caps --------------------------------------------------------------

    #[test]
    fn in_flight_cap_enforced_per_sender() {
        let mut r = Reassembler::with_bounds(3, MAX_FRAGMENTS_PER_MESSAGE, 30);
        let sender = peer(6);
        // Three distinct fragment_ids → three in-flight buffers.
        for i in 0..3u8 {
            let fid = [i; 16];
            let outcome = r.push(
                sender,
                FragmentPiece {
                    fragment_id: fid,
                    fragment_seq: 0,
                    is_final: false,
                    body: vec![i],
                },
                0,
            );
            assert_eq!(outcome, ReassemblyResult::Buffered);
        }
        // Fourth (new id) must be rejected.
        let outcome = r.push(
            sender,
            FragmentPiece {
                fragment_id: [9u8; 16],
                fragment_seq: 0,
                is_final: false,
                body: vec![9],
            },
            0,
        );
        match outcome {
            ReassemblyResult::Rejected(FragmentError::InFlightCapReached(_)) => {}
            other => panic!("expected InFlightCapReached, got {other:?}"),
        }
        // Additional fragment on an EXISTING buffer still accepted.
        let outcome = r.push(
            sender,
            FragmentPiece {
                fragment_id: [0u8; 16],
                fragment_seq: 1,
                is_final: true,
                body: vec![0x55],
            },
            0,
        );
        assert_eq!(outcome, ReassemblyResult::Complete(vec![0x00, 0x55]));
    }

    #[test]
    fn fragment_seq_beyond_cap_rejected() {
        let mut r = Reassembler::with_bounds(8, 4, 30);
        let outcome = r.push(
            peer(7),
            FragmentPiece {
                fragment_id: [0u8; 16],
                fragment_seq: 5,
                is_final: true,
                body: vec![],
            },
            0,
        );
        match outcome {
            ReassemblyResult::Rejected(FragmentError::FragmentSeqOutOfRange { .. }) => {}
            other => panic!("expected FragmentSeqOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn per_sender_isolation() {
        // MUST-060 cap is per-sender — filling sender A's budget does NOT
        // block sender B.
        let mut r = Reassembler::with_bounds(2, MAX_FRAGMENTS_PER_MESSAGE, 30);
        let a = peer(0xAA);
        let b = peer(0xBB);
        for i in 0..2u8 {
            r.push(
                a,
                FragmentPiece {
                    fragment_id: [i; 16],
                    fragment_seq: 0,
                    is_final: false,
                    body: vec![i],
                },
                0,
            );
        }
        // A is capped.
        match r.push(
            a,
            FragmentPiece {
                fragment_id: [0x77; 16],
                fragment_seq: 0,
                is_final: false,
                body: vec![],
            },
            0,
        ) {
            ReassemblyResult::Rejected(FragmentError::InFlightCapReached(_)) => {}
            other => panic!("expected A capped, got {other:?}"),
        }
        // B still accepted.
        let outcome = r.push(
            b,
            FragmentPiece {
                fragment_id: [0x77; 16],
                fragment_seq: 0,
                is_final: false,
                body: vec![],
            },
            0,
        );
        assert_eq!(outcome, ReassemblyResult::Buffered);
    }

    // -- Constants ---------------------------------------------------------

    #[test]
    fn spec_constants_match_vector_fixture() {
        let v: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../specs/vectors/PNP-001/fragment_constants.json"
        ))
        .unwrap();
        assert_eq!(REASSEMBLY_TIMEOUT_SECS, v["reassembly_timeout_secs"].as_u64().unwrap());
        assert_eq!(
            MAX_INFLIGHT_PER_SENDER as u64,
            v["max_inflight_messages_per_sender"].as_u64().unwrap()
        );
        assert_eq!(
            MAX_FRAGMENTS_PER_MESSAGE as u64,
            v["max_fragments_per_message"].as_u64().unwrap()
        );
        assert_eq!(FRAGMENT_ID_BYTES as u64, v["fragment_id_bytes"].as_u64().unwrap());
    }

    // -- Round trip --------------------------------------------------------

    #[test]
    fn split_then_reassemble_round_trip() {
        let body: Vec<u8> = (0..2048u32).map(|i| (i & 0xff) as u8).collect();
        let frags = Fragmenter::split(&body, 256, &mut rng()).unwrap();
        assert!(frags.len() > 1);

        let mut r = Reassembler::new();
        let sender = peer(0xEE);
        let mut last = ReassemblyResult::Buffered;
        for f in frags {
            last = r.push(sender, f, 0);
        }
        assert_eq!(last, ReassemblyResult::Complete(body));
    }
}
