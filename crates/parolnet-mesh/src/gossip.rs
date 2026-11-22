//! Gossip protocol implementation (PNP-005).

use crate::clock::Clock;
use crate::connection_pool::ConnectionPool;
use crate::{GossipAction, GossipProtocol, MeshError};
use async_trait::async_trait;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parolnet_protocol::address::PeerId;
use parolnet_protocol::envelope::Envelope;
use parolnet_protocol::gossip::{
    GossipEnvelope, GossipPayloadType, MAX_GOSSIP_FRAME, MAX_GOSSIP_PAYLOAD, MAX_MESSAGE_AGE_SECS,
    MAX_TTL, RELAY_DESCRIPTOR_EXPIRY_SECS, RELAY_DESCRIPTOR_TTL, RelayDescriptorGossip,
};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;
use tracing::warn;
use zeroize::Zeroize;

/// Default gossip fanout (number of peers to forward to).
pub const DEFAULT_FANOUT: usize = 3;
/// Default TTL for gossip messages.
pub const DEFAULT_TTL: u8 = 7;
/// Default expiry duration in seconds.
pub const DEFAULT_EXPIRY_SECS: u64 = 86400;
/// Maximum messages per source peer per rate-limit window (PNP-005 Section 6.4).
pub const RATE_LIMIT_MAX_MESSAGES: u32 = 10;
/// Rate-limit window duration in seconds.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Maximum allowed clock skew for future timestamps (seconds).
pub const MAX_FUTURE_SKEW_SECS: u64 = 300;
/// Longest forwarding jitter (PNP-005-MUST-023).
pub const MAX_FORWARD_JITTER: Duration = Duration::from_millis(200);
/// Default proof-of-work difficulty, in leading zero bits (PNP-005 §5.6 item 2).
pub const DEFAULT_POW_DIFFICULTY: u8 = 16;
/// Highest difficulty a node adopts from relay advertisements. Above it, computing the
/// proof for one message takes long enough to be a way of silencing the network.
pub const MAX_ADOPTED_DIFFICULTY: u8 = 24;

/// 1024-bit bloom filter for seen-peer deduplication (PNP-005 Section 3.3).
#[derive(Clone)]
pub struct SeenBloomFilter {
    bits: [u8; 128], // 1024 bits
}

impl Default for SeenBloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl SeenBloomFilter {
    pub fn new() -> Self {
        Self { bits: [0u8; 128] }
    }

    /// The filter of a received envelope. `None` unless it is 128 bytes.
    pub fn from_bytes(seen: &[u8]) -> Option<Self> {
        Some(Self {
            bits: seen.try_into().ok()?,
        })
    }

    /// The 128 bytes that go in the envelope.
    pub fn as_bytes(&self) -> &[u8; 128] {
        &self.bits
    }

    /// Insert a PeerId into the bloom filter using 3 hash functions.
    pub fn insert(&mut self, peer_id: &PeerId) {
        for k in 0u8..3 {
            let idx = self.hash(k, peer_id);
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
    }

    /// Check if a PeerId is probably in the bloom filter.
    pub fn probably_contains(&self, peer_id: &PeerId) -> bool {
        for k in 0u8..3 {
            let idx = self.hash(k, peer_id);
            if self.bits[idx / 8] & (1 << (idx % 8)) == 0 {
                return false;
            }
        }
        true
    }

    /// h_k(PeerId) = SHA-256(k || PeerId) mod 1024
    fn hash(&self, k: u8, peer_id: &PeerId) -> usize {
        let mut hasher = Sha256::new();
        hasher.update([k]);
        hasher.update(peer_id.as_bytes());
        let result = hasher.finalize();
        let val = u16::from_be_bytes([result[0], result[1]]);
        (val as usize) % 1024
    }
}

/// Bits in each of the two deduplication filters. PNP-005-SHOULD-005 asks for 100,000
/// entries at a false-positive rate of at most 0.1%; with both filters consulted, that
/// takes more than the 1,437,760 bits and 7 hash functions §5.5 item 3 suggests (those
/// give 0.13% for one filter). 2^21 bits and 10 hash functions give about 0.006% each.
pub const DEDUP_FILTER_BITS: usize = 1 << 21;
/// Hash functions of the deduplication filter.
pub const DEDUP_HASHES: usize = 10;
/// Entries a deduplication filter is sized for; reaching it rotates early.
pub const DEDUP_CAPACITY: usize = 100_000;
/// The filters rotate this often (PNP-005 §5.5 item 4).
pub const DEDUP_ROTATION: Duration = Duration::from_secs(12 * 3600);

struct Bloom {
    words: Vec<u64>,
    entries: usize,
}

impl Bloom {
    fn new() -> Self {
        Self {
            words: vec![0u64; DEDUP_FILTER_BITS / 64],
            entries: 0,
        }
    }

    fn set(&mut self, indices: &[usize; DEDUP_HASHES]) {
        for &i in indices {
            self.words[i / 64] |= 1 << (i % 64);
        }
        self.entries += 1;
    }

    fn has(&self, indices: &[usize; DEDUP_HASHES]) -> bool {
        indices
            .iter()
            .all(|&i| self.words[i / 64] & (1 << (i % 64)) != 0)
    }
}

struct DedupInner {
    /// Per-node salt: which bits a message ID sets is not predictable from outside.
    salt: [u8; 16],
    current: Bloom,
    previous: Bloom,
    rotated_at: Instant,
}

impl DedupInner {
    fn indices(&self, message_id: &[u8; 32]) -> [usize; DEDUP_HASHES] {
        let mut hasher = Sha256::new();
        hasher.update(self.salt);
        hasher.update(message_id);
        let h = hasher.finalize();
        let h1 = u64::from_be_bytes(h[0..8].try_into().expect("8 bytes"));
        let h2 = u64::from_be_bytes(h[8..16].try_into().expect("8 bytes")) | 1;
        let mut out = [0usize; DEDUP_HASHES];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot =
                (h1.wrapping_add((i as u64).wrapping_mul(h2)) % DEDUP_FILTER_BITS as u64) as usize;
        }
        out
    }

    fn rotate(&mut self) {
        self.previous = std::mem::replace(&mut self.current, Bloom::new());
    }

    /// Rotate as often as 12-hour periods have passed (twice empties both filters).
    fn rotate_if_due(&mut self) {
        let now = Instant::now();
        let mut periods = 0;
        while now.saturating_duration_since(self.rotated_at) >= DEDUP_ROTATION && periods < 2 {
            self.rotate();
            self.rotated_at += DEDUP_ROTATION;
            periods += 1;
        }
        if now.saturating_duration_since(self.rotated_at) >= DEDUP_ROTATION {
            self.rotated_at = now;
        }
    }
}

/// Local deduplication filter for recently seen message IDs (PNP-005 §5.5).
///
/// Two bloom filters, "current" and "previous". Every 12 hours "previous" is discarded,
/// "current" becomes "previous" and a new empty "current" starts; both are consulted.
/// The rotation happens on the filter's own clock, whoever calls it.
pub struct DedupFilter {
    inner: Mutex<DedupInner>,
}

impl Default for DedupFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl DedupFilter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(DedupInner {
                salt: rand::random(),
                current: Bloom::new(),
                previous: Bloom::new(),
                rotated_at: Instant::now(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DedupInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Check if a message ID has been seen recently.
    pub fn is_seen(&self, message_id: &[u8; 32]) -> bool {
        let mut inner = self.lock();
        inner.rotate_if_due();
        let indices = inner.indices(message_id);
        inner.current.has(&indices) || inner.previous.has(&indices)
    }

    /// Mark a message ID as seen.
    /// If the current filter is at capacity, it is rotated first.
    pub fn mark_seen(&self, message_id: [u8; 32]) {
        let mut inner = self.lock();
        inner.rotate_if_due();
        if inner.current.entries >= DEDUP_CAPACITY {
            inner.rotate();
            inner.rotated_at = Instant::now();
        }
        let indices = inner.indices(&message_id);
        inner.current.set(&indices);
    }

    /// Rotate the double buffer: discard previous, promote current.
    pub fn rotate(&self) {
        let mut inner = self.lock();
        inner.rotate();
        inner.rotated_at = Instant::now();
    }

    /// Forget everything (panic wipe).
    pub fn clear(&self) {
        let mut inner = self.lock();
        inner.current = Bloom::new();
        inner.previous = Bloom::new();
    }

    /// Number of IDs marked across both filters.
    pub fn len(&self) -> usize {
        let inner = self.lock();
        inner.current.entries + inner.previous.entries
    }

    /// Whether both filters are empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Proof-of-Work computation (PNP-005 Section 3.4).
pub struct ProofOfWork;

impl ProofOfWork {
    fn challenge(message_id: &[u8; 32], sender: &PeerId, timestamp: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"pgmp-pow-v1");
        hasher.update(message_id);
        hasher.update(sender.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.finalize().into()
    }

    /// Compute a PoW nonce that produces `difficulty` leading zero bits.
    ///
    /// challenge = SHA-256("pgmp-pow-v1" || message_id || sender || timestamp)
    pub fn compute(
        message_id: &[u8; 32],
        sender: &PeerId,
        timestamp: u64,
        difficulty: u8,
    ) -> [u8; 8] {
        let challenge = Self::challenge(message_id, sender, timestamp);

        let mut nonce = [0u8; 8];
        loop {
            let mut h = Sha256::new();
            h.update(challenge);
            h.update(nonce);
            let result = h.finalize();

            if Self::has_leading_zeros(&result, difficulty) {
                return nonce;
            }

            // Increment nonce
            for byte in nonce.iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
        }
    }

    /// Verify a PoW nonce.
    pub fn verify(
        message_id: &[u8; 32],
        sender: &PeerId,
        timestamp: u64,
        nonce: &[u8; 8],
        difficulty: u8,
    ) -> bool {
        let challenge = Self::challenge(message_id, sender, timestamp);

        let mut h = Sha256::new();
        h.update(challenge);
        h.update(nonce);
        let result = h.finalize();

        Self::has_leading_zeros(&result, difficulty)
    }

    /// Check if a hash has at least `n` leading zero bits.
    fn has_leading_zeros(hash: &[u8], n: u8) -> bool {
        let full_bytes = n / 8;
        let remaining_bits = n % 8;

        for byte in hash.iter().take(full_bytes as usize) {
            if *byte != 0 {
                return false;
            }
        }

        if remaining_bits > 0 {
            let mask = 0xFF << (8 - remaining_bits);
            if hash[full_bytes as usize] & mask != 0 {
                return false;
            }
        }

        true
    }
}

/// TTL and lifetime an originator gives a message (PNP-005 §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GossipParams {
    /// Hops the message may travel: 1 to 15.
    pub ttl: u8,
    /// Seconds from origination to expiry: at most 86400.
    pub expiry_secs: u64,
}

impl Default for GossipParams {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_TTL,
            expiry_secs: DEFAULT_EXPIRY_SECS,
        }
    }
}

impl GossipParams {
    /// The defaults of a payload type: TTL 10 and 6 hours for RELAY_DESCRIPTOR
    /// (PNP-005-SHOULD-003), TTL 7 and 24 hours for the rest.
    pub fn for_type(payload_type: u8) -> Self {
        if payload_type == GossipPayloadType::RelayDescriptor as u8 {
            Self {
                ttl: RELAY_DESCRIPTOR_TTL,
                expiry_secs: RELAY_DESCRIPTOR_EXPIRY_SECS,
            }
        } else {
            Self::default()
        }
    }
}

/// Whose name an originated message carries in the cleartext envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The node's identity: `src` is its PeerId. Required for everything but user
    /// messages (PNP-005-MUST-010).
    Identity,
    /// Nobody's: `src` is zero and `src_pubkey` empty (PNP-005 §3.5). User messages
    /// only (PNP-005-MUST-009). The signature is still the node's identity key's.
    Anonymous,
    /// A PeerId made for gossip, not the node's identity (PNP-005-SHOULD-014).
    Pseudonym,
}

/// Most messages a node keeps for set reconciliation.
pub const CACHE_MAX_MESSAGES: usize = 4096;
/// Most bytes of messages a node keeps for set reconciliation.
pub const CACHE_MAX_BYTES: usize = 32 * 1024 * 1024;

struct Cached {
    bytes: Vec<u8>,
    exp: u64,
}

/// Messages this node has and would still pass on, by ID: what a reconnecting peer is
/// synced against (PNP-005 §5.7).
#[derive(Default)]
struct MessageCache {
    messages: HashMap<[u8; 32], Cached>,
    bytes: usize,
}

impl MessageCache {
    fn insert(&mut self, id: [u8; 32], bytes: Vec<u8>, exp: u64) {
        if bytes.len() > CACHE_MAX_BYTES {
            return;
        }
        self.remove(&id);
        while self.messages.len() >= CACHE_MAX_MESSAGES
            || self.bytes + bytes.len() > CACHE_MAX_BYTES
        {
            // The message nearest its expiry goes first.
            let Some(victim) = self
                .messages
                .iter()
                .min_by_key(|(_, m)| m.exp)
                .map(|(id, _)| *id)
            else {
                break;
            };
            self.remove(&victim);
        }
        self.bytes += bytes.len();
        self.messages.insert(id, Cached { bytes, exp });
    }

    fn remove(&mut self, id: &[u8; 32]) {
        if let Some(old) = self.messages.remove(id) {
            self.bytes -= old.bytes.len();
        }
    }

    fn purge(&mut self, now: u64) {
        let dead: Vec<[u8; 32]> = self
            .messages
            .iter()
            .filter(|(_, m)| now >= m.exp)
            .map(|(id, _)| *id)
            .collect();
        for id in dead {
            self.remove(&id);
        }
    }
}

/// What processing a received gossip frame came to.
#[derive(Debug, Clone)]
pub struct Processed {
    pub action: GossipAction,
    /// The envelope as received.
    pub envelope: GossipEnvelope,
    /// The envelope as this node passes it on (TTL down, hops up, itself in `seen`),
    /// when the message was accepted and may still travel.
    pub forward: Option<GossipEnvelope>,
}

/// The PeerId a user message is addressed to: the destination in the cleartext header
/// of the PNP-001 envelope the gossip payload carries.
pub fn user_message_dest(payload: &[u8]) -> Option<PeerId> {
    ciborium::from_reader::<Envelope, _>(payload)
        .ok()
        .map(|e| e.cleartext_header.dest_peer_id)
}

/// Verify the signature of an anonymous envelope with the sender key its recipient took
/// from the decrypted payload (PNP-005-MUST-008). The signature covers the envelope
/// with its zeroed `src` and empty `src_pubkey`.
pub fn verify_anonymous_origin(
    envelope: &GossipEnvelope,
    sender_pubkey: &[u8; 32],
) -> Result<(), MeshError> {
    if !envelope.is_anonymous() {
        return Err(MeshError::ValidationFailed(
            "not an anonymous envelope".into(),
        ));
    }
    verify_signature(envelope, sender_pubkey)
}

fn verify_signature(envelope: &GossipEnvelope, pubkey: &[u8; 32]) -> Result<(), MeshError> {
    let key = VerifyingKey::from_bytes(pubkey).map_err(|_| MeshError::InvalidSignature)?;
    let sig: [u8; 64] = envelope
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| MeshError::InvalidSignature)?;
    // The originator signed its own `ttl`; hops since then have decremented it, so the
    // signature is checked over the originator's value.
    let signable = envelope
        .origin_signable_bytes()
        .ok_or(MeshError::InvalidSignature)?;
    key.verify(&signable, &Signature::from_bytes(&sig))
        .map_err(|_| MeshError::InvalidSignature)
}

pub struct StandardGossip {
    pub our_peer_id: PeerId,
    pub signing_key: ed25519_dalek::SigningKey,
    pub dedup: DedupFilter,
    /// Proof-of-work difficulty in force when no relay advertises one. The floors of
    /// PNP-005 §5.6 (16 bits, 20 for RELAY_DESCRIPTOR) hold whatever this says.
    pub default_difficulty: u8,
    pub pool: Arc<ConnectionPool>,
    /// How user messages are originated: anonymously unless set otherwise.
    pub user_origin: Origin,
    clock: Clock,
    /// Rate limiting per source: (window start, messages in the window).
    rate_limits: Mutex<HashMap<PeerId, (Instant, u32)>>,
    cache: Mutex<MessageCache>,
    /// Difficulty each known relay advertises, with the expiry of the advertisement.
    advertised: Mutex<HashMap<PeerId, (u8, u64)>>,
}

// Note: `ed25519_dalek::SigningKey` implements `ZeroizeOnDrop`, so it
// automatically zeroizes on drop. No manual Drop needed.

impl StandardGossip {
    pub fn new(
        our_peer_id: PeerId,
        signing_key: ed25519_dalek::SigningKey,
        pool: Arc<ConnectionPool>,
    ) -> Self {
        Self::with_clock(our_peer_id, signing_key, pool, Clock::system())
    }

    /// As [`Self::new`], reading time from `clock`.
    pub fn with_clock(
        our_peer_id: PeerId,
        signing_key: ed25519_dalek::SigningKey,
        pool: Arc<ConnectionPool>,
        clock: Clock,
    ) -> Self {
        Self {
            our_peer_id,
            signing_key,
            dedup: DedupFilter::new(),
            default_difficulty: DEFAULT_POW_DIFFICULTY,
            pool,
            user_origin: Origin::Anonymous,
            clock,
            rate_limits: Mutex::new(HashMap::new()),
            cache: Mutex::new(MessageCache::default()),
            advertised: Mutex::new(HashMap::new()),
        }
    }

    /// Check and update the per-source rate limit.
    /// Returns true if the source has exceeded the rate limit.
    fn is_rate_limited(&self, source: &PeerId) -> bool {
        let mut limits = self.rate_limits.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let window = Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
        if limits.len() > 16_384 {
            limits.retain(|_, (start, _)| now.duration_since(*start) < window);
        }

        let entry = limits.entry(*source).or_insert((now, 0));

        // Reset window if expired
        if now.duration_since(entry.0) >= window {
            *entry = (now, 1);
            return false;
        }

        entry.1 += 1;
        entry.1 > RATE_LIMIT_MAX_MESSAGES
    }

    /// The gossip pseudonym of this node: an Ed25519 key derived from the identity key
    /// for this purpose alone (PNP-005-SHOULD-014).
    pub fn pseudonym_key(&self) -> SigningKey {
        let mut seed = [0u8; 32];
        let mut identity = self.signing_key.to_bytes();
        hkdf::Hkdf::<Sha256>::new(None, &identity)
            .expand(b"pgmp-pseudonym-v1", &mut seed)
            .expect("32 bytes is a valid HKDF output length");
        identity.zeroize();
        let key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        key
    }

    /// The PeerId of [`Self::pseudonym_key`].
    pub fn pseudonym_peer_id(&self) -> PeerId {
        PeerId(Sha256::digest(self.pseudonym_key().verifying_key().to_bytes()).into())
    }

    /// The difficulty known relays advertise: the median (PNP-005-SHOULD-006), if any.
    fn adopted_difficulty(&self) -> Option<u8> {
        let now = self.clock.now_secs();
        let mut advertised = self.advertised.lock().unwrap_or_else(|e| e.into_inner());
        advertised.retain(|_, (_, exp)| now < *exp);
        let mut values: Vec<u8> = advertised.values().map(|(d, _)| *d).collect();
        if values.is_empty() {
            return None;
        }
        values.sort_unstable();
        Some(values[values.len() / 2])
    }

    /// Leading zero bits a message of `payload_type` has to show.
    ///
    /// The median difficulty the known relays advertise, or the default without any,
    /// never below the spec's floor for the type (16; 20 for RELAY_DESCRIPTOR,
    /// PNP-005-MUST-036) and never above [`MAX_ADOPTED_DIFFICULTY`].
    pub fn required_difficulty(&self, payload_type: u8) -> u8 {
        let floor = GossipPayloadType::from_u8(payload_type)
            .map(|t| t.pow_difficulty())
            .unwrap_or(DEFAULT_POW_DIFFICULTY);
        self.adopted_difficulty()
            .unwrap_or(self.default_difficulty)
            .min(MAX_ADOPTED_DIFFICULTY)
            .max(floor)
    }

    /// Build, prove and sign a gossip envelope this node originates.
    pub fn build_envelope(
        &self,
        payload_type: u8,
        payload: Vec<u8>,
        params: GossipParams,
        origin: Origin,
    ) -> Result<GossipEnvelope, MeshError> {
        // PNP-005-MUST-025: TTL between 1 and 15. MUST-026: at most 24 hours to live.
        if params.ttl == 0 || params.ttl > MAX_TTL {
            return Err(MeshError::ValidationFailed(format!(
                "originating ttl {} outside 1..={MAX_TTL}",
                params.ttl
            )));
        }
        if params.expiry_secs == 0 || params.expiry_secs > MAX_MESSAGE_AGE_SECS {
            return Err(MeshError::ValidationFailed(format!(
                "expiry {}s outside 1..={MAX_MESSAGE_AGE_SECS}",
                params.expiry_secs
            )));
        }
        if payload.len() > MAX_GOSSIP_PAYLOAD {
            return Err(MeshError::PayloadTooLarge);
        }
        // PNP-005-MUST-009 / MUST-010: only a user message may hide its source.
        let is_user = payload_type == GossipPayloadType::UserMessage as u8;
        if origin != Origin::Identity && !is_user {
            return Err(MeshError::ValidationFailed(
                "only USER_MESSAGE may be anonymous or pseudonymous".into(),
            ));
        }

        let (signer, src, src_pubkey) = match origin {
            Origin::Identity => (
                self.signing_key.clone(),
                self.our_peer_id,
                self.signing_key.verifying_key().to_bytes().to_vec(),
            ),
            // The identity key signs; neither it nor the PeerId is in the envelope.
            Origin::Anonymous => (self.signing_key.clone(), PeerId([0u8; 32]), Vec::new()),
            Origin::Pseudonym => {
                let key = self.pseudonym_key();
                let public = key.verifying_key().to_bytes();
                (key, PeerId(Sha256::digest(public).into()), public.to_vec())
            }
        };

        // id = SHA-256(payload || sender_peer_id || nonce)
        let nonce: [u8; 16] = rand::random();
        let mut id_hasher = Sha256::new();
        id_hasher.update(&payload);
        id_hasher.update(self.our_peer_id.as_bytes());
        id_hasher.update(nonce);
        let message_id: [u8; 32] = id_hasher.finalize().into();

        let ts = self.clock.now_secs();
        let mut bloom = SeenBloomFilter::new();
        bloom.insert(&self.our_peer_id);
        let pow = ProofOfWork::compute(
            &message_id,
            &src,
            ts,
            self.required_difficulty(payload_type),
        );

        let mut envelope = GossipEnvelope {
            v: 1,
            id: message_id.to_vec(),
            src,
            src_pubkey,
            ts,
            exp: ts + params.expiry_secs,
            ttl: params.ttl,
            hops: 0,
            seen: bloom.as_bytes().to_vec(),
            pow: pow.to_vec(),
            sig: vec![0u8; 64],
            payload_type,
            payload,
        };
        envelope.sig = signer.sign(&envelope.signable_bytes()).to_bytes().to_vec();
        Ok(envelope)
    }

    /// Send an envelope this node built to up to F peers. Returns who it went to.
    pub async fn originate(&self, envelope: &GossipEnvelope) -> Result<Vec<PeerId>, MeshError> {
        let message_id = envelope
            .message_id()
            .ok_or_else(|| MeshError::ValidationFailed("invalid message_id length".into()))?;
        let serialized = envelope
            .to_cbor()
            .map_err(|e| MeshError::ValidationFailed(format!("CBOR encode: {e}")))?;
        self.dedup.mark_seen(message_id);
        self.remember(message_id, serialized.clone(), envelope.exp);
        self.note_advertisement(envelope);

        let fanout = self.pool.select_fanout_peers(&[], DEFAULT_FANOUT).await;
        let mut sent = Vec::new();
        for (pid, conn) in &fanout {
            match conn.send(&serialized).await {
                Ok(()) => sent.push(*pid),
                Err(e) => warn!(peer = %pid, error = %e, "failed to send gossip broadcast"),
            }
        }
        Ok(sent)
    }

    /// Originate a message of `payload_type` with the defaults of its type. User
    /// messages go out as [`Self::user_origin`] says; everything else under the node's
    /// identity. Returns the message ID.
    pub async fn publish(&self, payload_type: u8, payload: Vec<u8>) -> Result<[u8; 32], MeshError> {
        let origin = if payload_type == GossipPayloadType::UserMessage as u8 {
            self.user_origin
        } else {
            Origin::Identity
        };
        let envelope = self.build_envelope(
            payload_type,
            payload,
            GossipParams::for_type(payload_type),
            origin,
        )?;
        self.originate(&envelope).await?;
        Ok(envelope.message_id().expect("built with a 32-byte id"))
    }

    fn remember(&self, id: [u8; 32], bytes: Vec<u8>, exp: u64) {
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, bytes, exp);
    }

    /// A relay's RELAY_DESCRIPTOR may advertise a difficulty for the network.
    fn note_advertisement(&self, envelope: &GossipEnvelope) {
        if envelope.payload_type != GossipPayloadType::RelayDescriptor as u8 {
            return;
        }
        if let Ok(wrapper) = RelayDescriptorGossip::from_cbor(&envelope.payload)
            && let Some(difficulty) = wrapper.pow_difficulty
        {
            self.advertised
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(envelope.src, (difficulty, envelope.exp));
        }
    }

    /// IDs of the messages this node holds for reconciliation.
    pub fn cached_ids(&self) -> Vec<[u8; 32]> {
        let now = self.clock.now_secs();
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.purge(now);
        cache.messages.keys().copied().collect()
    }

    /// The wire bytes of a held message.
    pub fn cached(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .messages
            .get(id)
            .map(|m| m.bytes.clone())
    }

    /// Drop held messages that expired.
    pub fn purge_expired(&self) {
        let now = self.clock.now_secs();
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .purge(now);
    }

    /// Forget every held message and every seen ID (panic wipe).
    pub fn wipe(&self) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        for message in cache.messages.values_mut() {
            message.bytes.zeroize();
        }
        *cache = MessageCache::default();
        drop(cache);
        self.dedup.clear();
    }

    async fn penalize(
        &self,
        from: Option<PeerId>,
        f: impl FnOnce(&mut crate::peer_table::PeerScore),
    ) {
        if let Some(from) = from {
            self.pool.update_score(&from, f).await;
        }
    }

    /// Whether an accepted message is handed to the application here: every broadcast
    /// type is, a user message when it is addressed to this node.
    fn is_for_us(&self, envelope: &GossipEnvelope) -> bool {
        match GossipPayloadType::from_u8(envelope.payload_type) {
            Some(GossipPayloadType::UserMessage) => {
                user_message_dest(&envelope.payload) == Some(self.our_peer_id)
            }
            Some(_) => true,
            None => false,
        }
    }

    /// Process a received gossip frame; `from` is the peer it came from (`None` for a
    /// message injected locally). See [`Self::process`].
    pub async fn process_gossip(
        &self,
        from: Option<PeerId>,
        data: &[u8],
    ) -> Result<GossipAction, MeshError> {
        self.process(from, data).await.map(|p| p.action)
    }

    /// Validate a received gossip frame (PNP-005 §5.1, in the order given there) and,
    /// if it passes, forward it (§5.2).
    ///
    /// Invalid messages are discarded without any answer on the wire; the error says
    /// why, for the caller's logs. The peer the message came from is the one whose
    /// score changes (§5.8): it vouched for the message by passing it on, and the
    /// `src` of a message that failed validation is only a claim.
    pub async fn process(&self, from: Option<PeerId>, data: &[u8]) -> Result<Processed, MeshError> {
        if data.len() > MAX_GOSSIP_FRAME {
            self.penalize(from, |s| s.penalize_invalid()).await;
            return Err(MeshError::PayloadTooLarge);
        }
        let envelope = match GossipEnvelope::decode_unvalidated(data) {
            Ok(envelope) => envelope,
            Err(e) => {
                self.penalize(from, |s| s.penalize_invalid()).await;
                return Err(MeshError::ValidationFailed(format!(
                    "gossip CBOR decode: {e}"
                )));
            }
        };

        // 1. Version. Unknown versions are silently discarded (PNP-005-MUST-012).
        if envelope.v != 1 {
            return Err(MeshError::UnsupportedVersion);
        }
        let (Some(message_id), Some(pow_nonce)) = (envelope.message_id(), envelope.pow_nonce())
        else {
            self.penalize(from, |s| s.penalize_invalid()).await;
            return Err(MeshError::ValidationFailed(
                "invalid gossip envelope structure".into(),
            ));
        };
        if envelope.sig.len() != 64 || envelope.seen.len() != 128 {
            self.penalize(from, |s| s.penalize_invalid()).await;
            return Err(MeshError::ValidationFailed(
                "invalid gossip envelope structure".into(),
            ));
        }

        // 2. Expiry (PNP-005-MUST-013), and with it the other bounds on time: a
        //    timestamp more than 300 seconds ahead (MUST-045), an expiry more than 24
        //    hours after origination (MUST-026).
        let now = self.clock.now_secs();
        if envelope.is_expired(now) {
            self.penalize(from, |s| s.penalize_expired()).await;
            return Err(MeshError::MessageExpired);
        }
        if envelope.ts > now + MAX_FUTURE_SKEW_SECS {
            self.penalize(from, |s| s.penalize_invalid()).await;
            return Err(MeshError::FutureTimestamp);
        }
        if envelope.exp > envelope.ts.saturating_add(MAX_MESSAGE_AGE_SECS) {
            self.penalize(from, |s| s.penalize_invalid()).await;
            return Err(MeshError::ValidationFailed(
                "expiry too far from timestamp".into(),
            ));
        }

        // 3. TTL. Zero is still valid: it is not forwarded (PNP-005-MUST-014). A TTL
        //    no originator could have set is not.
        if envelope
            .ttl
            .checked_add(envelope.hops)
            .is_none_or(|origin_ttl| origin_ttl > MAX_TTL)
        {
            self.penalize(from, |s| s.penalize_invalid()).await;
            return Err(MeshError::ValidationFailed("ttl exceeds maximum".into()));
        }

        // 4. Signature (PNP-005-MUST-015). An anonymous envelope carries no key to
        //    check with: for a user message the check is the recipient's, after
        //    decryption (PNP-005-SHOULD-002); for anything else it is not allowed
        //    (PNP-005-MUST-009 / MUST-010).
        if envelope.is_anonymous() {
            if envelope.payload_type != GossipPayloadType::UserMessage as u8 {
                self.penalize(from, |s| s.penalize_invalid()).await;
                return Err(MeshError::InvalidSignature);
            }
        } else {
            let key: Result<[u8; 32], _> = envelope.src_pubkey.as_slice().try_into();
            let valid = match key {
                Ok(key) => {
                    let hash: [u8; 32] = Sha256::digest(key).into();
                    hash == envelope.src.0
                        && envelope.src != PeerId([0u8; 32])
                        && verify_signature(&envelope, &key).is_ok()
                }
                Err(_) => false,
            };
            if !valid {
                // PNP-005-MUST-016: discarded, and the sending peer is penalized.
                self.penalize(from, |s| s.penalize_invalid()).await;
                return Err(MeshError::InvalidSignature);
            }
        }

        // 5. Proof of work (PNP-005-MUST-017 / MUST-035 / MUST-037).
        if !ProofOfWork::verify(
            &message_id,
            &envelope.src,
            envelope.ts,
            &pow_nonce,
            self.required_difficulty(envelope.payload_type),
        ) {
            self.penalize(from, |s| s.penalize_invalid()).await;
            return Err(MeshError::InsufficientPoW);
        }

        // 6. Deduplication (PNP-005-MUST-018).
        if self.dedup.is_seen(&message_id) {
            self.penalize(from, |s| s.penalize_duplicate()).await;
            return Ok(Processed {
                action: GossipAction::Drop,
                envelope,
                forward: None,
            });
        }

        // 7. Payload size (PNP-005-MUST-019).
        if envelope.payload.len() > MAX_GOSSIP_PAYLOAD {
            self.penalize(from, |s| s.penalize_invalid()).await;
            return Err(MeshError::PayloadTooLarge);
        }

        // Rate limit per source PeerId (PNP-005-MUST-046), counted on messages that
        // are valid and new: by now `src` is proven by its signature, and a copy
        // arriving over a second path costs the source nothing. An anonymous envelope
        // has no source PeerId; the peer that delivered it stands in.
        // A message injected locally has no delivering peer either; whoever injects
        // (an exit relay, per circuit) applies its own limit.
        let limited_on = if envelope.is_anonymous() {
            from
        } else {
            Some(envelope.src)
        };
        if limited_on.is_some_and(|source| self.is_rate_limited(&source)) {
            // PNP-005-MUST-047: silently dropped.
            return Ok(Processed {
                action: GossipAction::RateLimited,
                envelope,
                forward: None,
            });
        }

        // Accepted (§5.2 item 1d).
        self.dedup.mark_seen(message_id);
        self.penalize(from, |s| s.reward()).await;
        self.note_advertisement(&envelope);
        let deliver = self.is_for_us(&envelope);

        if envelope.ttl == 0 {
            let action = if deliver {
                GossipAction::Deliver
            } else {
                GossipAction::Drop
            };
            return Ok(Processed {
                action,
                envelope,
                forward: None,
            });
        }

        // §5.2 item 1: our PeerId into `seen`, TTL down, hops up. Nothing else changes:
        // in particular neither the TTL nor the expiry ever grows here (MUST-027/028).
        let received_seen = SeenBloomFilter::from_bytes(&envelope.seen).unwrap_or_default();
        let mut forward = envelope.clone();
        let mut seen = received_seen.clone();
        seen.insert(&self.our_peer_id);
        forward.seen = seen.as_bytes().to_vec();
        forward.ttl -= 1;
        forward.hops = forward.hops.saturating_add(1);
        let serialized = forward
            .to_cbor()
            .map_err(|e| MeshError::ValidationFailed(format!("gossip CBOR encode: {e}")))?;
        self.remember(message_id, serialized.clone(), forward.exp);

        // §5.2 item 2: not back to where it came from, not to peers probably in `seen`.
        let mut excluded: Vec<PeerId> = self
            .pool
            .connected_peers()
            .await
            .into_iter()
            .filter(|pid| received_seen.probably_contains(pid))
            .collect();
        excluded.extend(from);
        let fanout = self
            .pool
            .select_fanout_peers(&excluded, DEFAULT_FANOUT)
            .await;

        // §5.2 item 4: each peer gets the message after its own delay, drawn from the
        // operating system's generator, uniform over 0 to 200 ms.
        let serialized: Arc<[u8]> = serialized.into();
        let mut peers = Vec::with_capacity(fanout.len());
        for (pid, conn) in fanout {
            let jitter = Duration::from_micros(
                rand::rngs::OsRng.gen_range(0..=MAX_FORWARD_JITTER.as_micros() as u64),
            );
            let bytes = serialized.clone();
            peers.push(pid);
            tokio::spawn(async move {
                tokio::time::sleep(jitter).await;
                if let Err(e) = conn.send(&bytes).await {
                    warn!(peer = %pid, error = %e, "failed to forward gossip");
                }
            });
        }

        let action = match (deliver, peers.is_empty()) {
            (true, true) => GossipAction::Deliver,
            (true, false) => GossipAction::DeliverAndForward { peers },
            (false, false) => GossipAction::Forward { peers },
            (false, true) => GossipAction::Drop,
        };
        Ok(Processed {
            action,
            envelope,
            forward: Some(forward),
        })
    }
}

#[async_trait]
impl GossipProtocol for StandardGossip {
    /// Originate a user message carrying `envelope`.
    async fn broadcast(&self, envelope: Envelope) -> Result<(), MeshError> {
        let mut payload = Vec::new();
        ciborium::into_writer(&envelope, &mut payload)
            .map_err(|e| MeshError::ValidationFailed(format!("CBOR encode envelope: {e}")))?;
        self.publish(GossipPayloadType::UserMessage as u8, payload)
            .await
            .map(|_| ())
    }

    async fn on_receive(&self, envelope: Envelope) -> Result<GossipAction, MeshError> {
        // The envelope's encrypted_payload carries the CBOR-encoded GossipEnvelope
        self.process_gossip(None, &envelope.encrypted_payload).await
    }
}
