//! Sender Key protocol for group messaging encryption.
//!
//! Each group member generates a sender key chain and distributes it to other
//! members via pairwise Double Ratchet sessions. This achieves O(1) encrypt
//! per send — the sender encrypts once, and all N-1 members can decrypt.
//!
//! Follows the Signal Sender Keys design:
//! - Each member maintains a symmetric chain key per sender
//! - Messages are signed with Ed25519 for authenticity
//! - Encrypted with ChaCha20-Poly1305 using keys derived via HKDF-SHA-256

use crate::aead::ChaCha20Poly1305Cipher;
use crate::kdf::hkdf_sha256;
use crate::{Aead, CryptoError};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Maximum number of skipped message keys to store.
const MAX_SKIP: u32 = 1000;

/// Maximum number of messages in one sender key chain (PNP-009-MUST-078): a chain carries the
/// indexes `0 ..= MAX_SENDER_CHAIN_LENGTH - 1`, after which its sender rotates (PNP-009 §7.3).
/// Rotation is the sender's own to do and is recommended every 1000 messages, so the limit
/// sits 65 times above that and 65,536 times below the range of the `u32` wire field.
pub const MAX_SENDER_CHAIN_LENGTH: u32 = 1 << 16;

/// Refuse a chain index a message cannot carry (PNP-009-MUST-079 / MUST-080).
fn check_chain_index(chain_index: u32) -> Result<(), CryptoError> {
    if chain_index >= MAX_SENDER_CHAIN_LENGTH {
        return Err(CryptoError::CounterOutOfRange {
            counter: "chain_index",
            value: u64::from(chain_index),
            limit: u64::from(MAX_SENDER_CHAIN_LENGTH - 1),
        });
    }
    Ok(())
}

/// State for one sender in a group's sender key chain.
///
/// The sender holds `signing_key = Some(...)` and can encrypt.
/// Receivers hold `signing_key = None` and can only decrypt/verify.
/// All secret key material is zeroized on drop.
#[derive(Zeroize)]
pub struct SenderKeyState {
    /// Current symmetric chain key.
    chain_key: [u8; 32],
    /// Sender's signing key (Some for our own state, None for received states).
    #[zeroize(skip)]
    signing_key: Option<SigningKey>,
    /// Sender's public key bytes — always set, used for verification and nonce derivation.
    signing_public_key: [u8; 32],
    /// Monotonically increasing message counter.
    chain_index: u32,
    /// Skipped message keys for out-of-order delivery.
    #[zeroize(skip)]
    skipped_keys: HashMap<u32, [u8; 32]>,
}

/// Wire format for a sender-key encrypted message.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SenderKeyMessage {
    /// Chain index at which this message was encrypted.
    pub chain_index: u32,
    /// The encrypted message payload.
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature over (chain_index || ciphertext). 64 bytes.
    pub signature: Vec<u8>,
}

/// Distribution message sent via pairwise Double Ratchet to share sender keys.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SenderKeyDistribution {
    /// PeerId of the sender.
    pub sender_peer_id: [u8; 32],
    /// Current chain key.
    pub chain_key: [u8; 32],
    /// Current chain index.
    pub chain_index: u32,
    /// Sender's Ed25519 public key.
    pub signing_public_key: [u8; 32],
}

impl Default for SenderKeyState {
    fn default() -> Self {
        Self::new()
    }
}

impl SenderKeyState {
    /// Generate a fresh sender key state with a new signing key and random chain key.
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let signing_public_key = signing_key.verifying_key().to_bytes();

        let mut chain_key = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut chain_key);

        Self {
            chain_key,
            signing_key: Some(signing_key),
            signing_public_key,
            chain_index: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Create a receiver-only state from a distribution message.
    ///
    /// The resulting state can decrypt and verify messages but cannot encrypt.
    pub fn from_distribution(dist: &SenderKeyDistribution) -> Result<Self, CryptoError> {
        // A chain that starts at or past its limit can carry no message (PNP-009-MUST-080).
        check_chain_index(dist.chain_index)?;

        // Validate the public key is a valid Ed25519 point
        VerifyingKey::from_bytes(&dist.signing_public_key).map_err(|_| {
            CryptoError::SenderKeyError {
                reason: "invalid signing public key in distribution".into(),
            }
        })?;

        Ok(Self {
            chain_key: dist.chain_key,
            signing_key: None,
            signing_public_key: dist.signing_public_key,
            chain_index: dist.chain_index,
            skipped_keys: HashMap::new(),
        })
    }

    /// Export current state as a distribution message for sharing with group members.
    pub fn create_distribution(&self, sender_peer_id: [u8; 32]) -> SenderKeyDistribution {
        SenderKeyDistribution {
            sender_peer_id,
            chain_key: self.chain_key,
            chain_index: self.chain_index,
            signing_public_key: self.signing_public_key,
        }
    }

    /// Encrypt a message using the sender key chain.
    ///
    /// Only the sender (who holds the signing key) can encrypt.
    /// Returns a `SenderKeyMessage` containing the ciphertext and signature.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<SenderKeyMessage, CryptoError> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or(CryptoError::SenderKeyError {
                reason: "receiver-only state cannot encrypt".into(),
            })?;

        // A chain carries `MAX_SENDER_CHAIN_LENGTH` messages and no more (PNP-009-MUST-078):
        // at the limit the sender rotates (PNP-009 §7.3). Checked before anything is derived.
        if self.chain_index >= MAX_SENDER_CHAIN_LENGTH {
            return Err(CryptoError::SenderKeyChainExhausted {
                limit: MAX_SENDER_CHAIN_LENGTH,
            });
        }
        let next_index =
            self.chain_index
                .checked_add(1)
                .ok_or(CryptoError::SenderKeyChainExhausted {
                    limit: MAX_SENDER_CHAIN_LENGTH,
                })?;

        // Derive the message key on a copy of the chain: the state takes the new chain key
        // and the new index together, once the message exists (PNP-009-MUST-081).
        let mut next_chain_key = Zeroizing::new(self.chain_key);
        let message_key = Zeroizing::new(Self::chain_step(&mut next_chain_key)?);

        // Build nonce: SHA-256(signing_public_key)[0..8] || chain_index.to_be_bytes()
        let nonce = Self::build_nonce(&self.signing_public_key, self.chain_index);

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305Cipher::new(&message_key[..])?;
        let ciphertext = cipher.encrypt(&nonce, plaintext, &[])?;

        // Sign (chain_index || ciphertext)
        let mut signed_data = Vec::with_capacity(4 + ciphertext.len());
        signed_data.extend_from_slice(&self.chain_index.to_be_bytes());
        signed_data.extend_from_slice(&ciphertext);
        let signature = signing_key.sign(&signed_data);

        // Commit.
        let old_index = self.chain_index;
        self.chain_key.copy_from_slice(&next_chain_key[..]);
        self.chain_index = next_index;

        Ok(SenderKeyMessage {
            chain_index: old_index,
            ciphertext,
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Decrypt a sender key message.
    ///
    /// Handles out-of-order delivery by storing skipped message keys. All-or-nothing: when
    /// this returns `Err` the state, skipped keys included, is exactly what it was before
    /// the call.
    pub fn decrypt(&mut self, msg: &SenderKeyMessage) -> Result<Vec<u8>, CryptoError> {
        // An index past the limit is refused before anything else is done with the message
        // (PNP-009-MUST-079): no sender produces one (`encrypt` stops at the limit).
        check_chain_index(msg.chain_index)?;

        // Verify Ed25519 signature
        let verifying_key = VerifyingKey::from_bytes(&self.signing_public_key).map_err(|_| {
            CryptoError::SenderKeyError {
                reason: "invalid signing public key".into(),
            }
        })?;

        let mut signed_data = Vec::with_capacity(4 + msg.ciphertext.len());
        signed_data.extend_from_slice(&msg.chain_index.to_be_bytes());
        signed_data.extend_from_slice(&msg.ciphertext);

        let sig_bytes: [u8; 64] =
            msg.signature
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::SenderKeyError {
                    reason: "invalid signature length".into(),
                })?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        let nonce = Self::build_nonce(&self.signing_public_key, msg.chain_index);

        // All-or-nothing from here: the signature proves who sent the message, not that it
        // decrypts under the chain this state holds (a sender can sign anything). Nothing
        // below is written back before the AEAD tag has verified.
        if msg.chain_index < self.chain_index {
            // A stored key is consumed only by a message that authenticates under it.
            let mk = self
                .skipped_keys
                .get(&msg.chain_index)
                .ok_or(CryptoError::MessageKeyExhausted)?;
            let plaintext =
                ChaCha20Poly1305Cipher::new(mk)?.decrypt(&nonce, &msg.ciphertext, &[])?;
            if let Some(mut used) = self.skipped_keys.remove(&msg.chain_index) {
                used.zeroize();
            }
            return Ok(plaintext);
        }

        // The index this message leaves the chain at: at most `MAX_SENDER_CHAIN_LENGTH`
        // after the check above. The addition is checked anyway.
        let next_index = msg
            .chain_index
            .checked_add(1)
            .ok_or(CryptoError::CounterOutOfRange {
                counter: "chain_index",
                value: u64::from(msg.chain_index),
                limit: u64::from(MAX_SENDER_CHAIN_LENGTH - 1),
            })?;

        // Ratchet a copy of the chain forward, collecting the keys of the skipped messages.
        let skip_count = msg.chain_index.saturating_sub(self.chain_index);
        let skip_len = usize::try_from(skip_count).unwrap_or(usize::MAX);
        if skip_count > MAX_SKIP
            || self.skipped_keys.len().saturating_add(skip_len)
                > usize::try_from(MAX_SKIP).unwrap_or(usize::MAX)
        {
            return Err(CryptoError::SenderKeyError {
                reason: "too many skipped message keys".into(),
            });
        }
        let mut chain_key = Zeroizing::new(self.chain_key);
        let mut new_skipped = Zeroizing::new(Vec::with_capacity(skip_len));
        for _ in 0..skip_count {
            let mut mk = Self::chain_step(&mut chain_key)?;
            new_skipped.push(mk);
            mk.zeroize();
        }
        let message_key = Zeroizing::new(Self::chain_step(&mut chain_key)?);

        let plaintext =
            ChaCha20Poly1305Cipher::new(&message_key[..])?.decrypt(&nonce, &msg.ciphertext, &[])?;

        // Commit. The copies above zeroize themselves when they drop.
        for (idx, mk) in (self.chain_index..msg.chain_index).zip(new_skipped.iter()) {
            self.skipped_keys.insert(idx, *mk);
        }
        self.chain_key = *chain_key;
        self.chain_index = next_index;

        Ok(plaintext)
    }

    /// One symmetric ratchet step: returns the message key and advances `chain_key`.
    fn chain_step(chain_key: &mut [u8; 32]) -> Result<[u8; 32], CryptoError> {
        let mk_bytes = hkdf_sha256(chain_key, &[0x01], b"ParolNet_sender_key_v1", 32)?;
        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&mk_bytes);

        let ck_bytes = hkdf_sha256(chain_key, &[0x02], b"ParolNet_sender_chain_v1", 32)?;
        chain_key.copy_from_slice(&ck_bytes);

        Ok(message_key)
    }

    /// Rotate the sender key (PNP-009 §7.2): a new random chain key (MUST-028), a new
    /// Ed25519 signing key pair (MUST-029) and the index back at 0 (MUST-030).
    ///
    /// Used on member removal, suspected compromise and periodically. After rotation a new
    /// distribution message (`create_distribution`, which carries the new verification key)
    /// must be sent to all group members. The old signing key zeroizes as it is dropped
    /// here; a receiver-only state has none and gains none.
    pub fn rotate(&mut self) {
        use rand::RngCore;
        OsRng.fill_bytes(&mut self.chain_key);
        self.chain_index = 0;
        if self.signing_key.is_some() {
            let signing_key = SigningKey::generate(&mut OsRng);
            self.signing_public_key = signing_key.verifying_key().to_bytes();
            self.signing_key = Some(signing_key);
        }
        // Clear skipped keys from old chain — they are no longer valid
        for value in self.skipped_keys.values_mut() {
            value.zeroize();
        }
        self.skipped_keys.clear();
    }

    /// Test hook: put the chain at `chain_index` without sending that many messages, so the
    /// limit (`MAX_SENDER_CHAIN_LENGTH`) can be reached in a test. The chain key is not
    /// moved: a receiver built from [`Self::create_distribution`] afterwards is in step.
    /// Compiled only for this crate's tests and under the `test-hooks` feature, which no
    /// production crate enables.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_chain_index_for_test(&mut self, chain_index: u32) {
        self.chain_index = chain_index;
    }

    /// Build a 12-byte nonce from the signing public key and chain index.
    ///
    /// Nonce = SHA-256(signing_public_key)[0..8] || chain_index.to_be_bytes()
    /// This guarantees uniqueness: different senders have different public keys,
    /// and within a sender's chain the index is monotonic.
    fn build_nonce(signing_public_key: &[u8; 32], chain_index: u32) -> [u8; 12] {
        let hash = Sha256::digest(signing_public_key);
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&hash[..8]);
        nonce[8..12].copy_from_slice(&chain_index.to_be_bytes());
        nonce
    }
}

/// Manual `Drop` to zeroize key material that `#[zeroize(skip)]` excludes:
/// - `skipped_keys`: HashMap values contain message keys (secret material).
/// - `signing_key`: `SigningKey` handles its own zeroization.
impl Drop for SenderKeyState {
    fn drop(&mut self) {
        // Zeroize the derive-Zeroize fields (chain_key, etc.)
        self.zeroize();

        // Zeroize all skipped message keys (HashMap is #[zeroize(skip)])
        for value in self.skipped_keys.values_mut() {
            value.zeroize();
        }
        self.skipped_keys.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sender_key_encrypt_decrypt() {
        let mut sender = SenderKeyState::new();
        let peer_id = [0x42u8; 32];
        let dist = sender.create_distribution(peer_id);

        let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

        let msg = sender.encrypt(b"hello group").unwrap();
        let plaintext = receiver.decrypt(&msg).unwrap();
        assert_eq!(plaintext, b"hello group");
    }

    #[test]
    fn test_sender_key_out_of_order() {
        let mut sender = SenderKeyState::new();
        let peer_id = [0x42u8; 32];
        let dist = sender.create_distribution(peer_id);
        let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

        let msg1 = sender.encrypt(b"msg1").unwrap();
        let msg2 = sender.encrypt(b"msg2").unwrap();
        let msg3 = sender.encrypt(b"msg3").unwrap();

        // Decrypt out of order: 3, 1, 2
        let pt3 = receiver.decrypt(&msg3).unwrap();
        assert_eq!(pt3, b"msg3");

        let pt1 = receiver.decrypt(&msg1).unwrap();
        assert_eq!(pt1, b"msg1");

        let pt2 = receiver.decrypt(&msg2).unwrap();
        assert_eq!(pt2, b"msg2");
    }

    #[test]
    fn test_sender_key_tampered_ciphertext() {
        let mut sender = SenderKeyState::new();
        let peer_id = [0x42u8; 32];
        let dist = sender.create_distribution(peer_id);
        let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

        let mut msg = sender.encrypt(b"secret data").unwrap();
        // Tamper with ciphertext
        if !msg.ciphertext.is_empty() {
            msg.ciphertext[0] ^= 0xFF;
        }

        // Should fail — signature won't match tampered ciphertext
        assert!(receiver.decrypt(&msg).is_err());
    }

    #[test]
    fn test_sender_key_tampered_signature() {
        let mut sender = SenderKeyState::new();
        let peer_id = [0x42u8; 32];
        let dist = sender.create_distribution(peer_id);
        let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

        let mut msg = sender.encrypt(b"secret data").unwrap();
        // Tamper with signature
        msg.signature[0] ^= 0xFF;

        assert!(receiver.decrypt(&msg).is_err());
    }

    #[test]
    fn test_sender_key_rotation() {
        let mut sender = SenderKeyState::new();
        let peer_id = [0x42u8; 32];
        let dist = sender.create_distribution(peer_id);
        let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

        // Send a message before rotation
        let msg1 = sender.encrypt(b"before rotation").unwrap();

        // Rotate sender keys
        sender.rotate();

        // Distribute new keys
        let new_dist = sender.create_distribution(peer_id);
        let mut receiver2 = SenderKeyState::from_distribution(&new_dist).unwrap();

        // New messages use new chain
        let msg2 = sender.encrypt(b"after rotation").unwrap();
        let pt2 = receiver2.decrypt(&msg2).unwrap();
        assert_eq!(pt2, b"after rotation");

        // Old receiver can still decrypt old message
        let pt1 = receiver.decrypt(&msg1).unwrap();
        assert_eq!(pt1, b"before rotation");
    }

    #[test]
    fn test_receiver_cannot_encrypt() {
        let sender = SenderKeyState::new();
        let peer_id = [0x42u8; 32];
        let dist = sender.create_distribution(peer_id);
        let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

        let result = receiver.encrypt(b"should fail");
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::SenderKeyError { reason } => {
                assert!(reason.contains("receiver-only"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// PNP-009-MUST-029: rotation replaces the signing key pair, and the new distribution
    /// carries the new verification key.
    #[test]
    fn rotation_replaces_the_signing_key() {
        let mut sender = SenderKeyState::new();
        let old_dist = sender.create_distribution([0x42; 32]);
        let old_secret = sender.signing_key.as_ref().unwrap().to_bytes();
        let mut old_receiver = SenderKeyState::from_distribution(&old_dist).unwrap();

        sender.rotate();

        let new_dist = sender.create_distribution([0x42; 32]);
        assert_ne!(new_dist.signing_public_key, old_dist.signing_public_key);
        assert_ne!(sender.signing_key.as_ref().unwrap().to_bytes(), old_secret);
        assert_eq!(
            sender
                .signing_key
                .as_ref()
                .unwrap()
                .verifying_key()
                .to_bytes(),
            new_dist.signing_public_key
        );

        // The new chain verifies under the new key, and not under the old one.
        let msg = sender.encrypt(b"after").unwrap();
        assert!(matches!(
            old_receiver.decrypt(&msg),
            Err(CryptoError::SignatureVerificationFailed)
        ));
        let mut new_receiver = SenderKeyState::from_distribution(&new_dist).unwrap();
        assert_eq!(new_receiver.decrypt(&msg).unwrap(), b"after");

        // Whoever holds the old signing key cannot sign for the new chain.
        let old_key = SigningKey::from_bytes(&old_secret);
        let mut forged = sender.encrypt(b"next").unwrap();
        let mut signed = forged.chain_index.to_be_bytes().to_vec();
        signed.extend_from_slice(&forged.ciphertext);
        forged.signature = old_key.sign(&signed).to_bytes().to_vec();
        assert!(matches!(
            new_receiver.decrypt(&forged),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    /// The chain index is a `u32` and the low four bytes of the nonce: at its limit the
    /// chain refuses to encrypt and to accept, in place of wrapping.
    #[test]
    fn chain_index_does_not_wrap() {
        let mut sender = SenderKeyState::new();
        sender.chain_index = MAX_SENDER_CHAIN_LENGTH - 1;
        let mut receiver =
            SenderKeyState::from_distribution(&sender.create_distribution([0x42; 32])).unwrap();

        // The last usable index.
        let last = sender.encrypt(b"last").unwrap();
        assert_eq!(last.chain_index, MAX_SENDER_CHAIN_LENGTH - 1);
        assert_eq!(sender.chain_index, MAX_SENDER_CHAIN_LENGTH);

        // At the limit: an error, and the state is untouched.
        let chain_key = sender.chain_key;
        assert!(sender.encrypt(b"one too many").is_err());
        assert_eq!(sender.chain_index, MAX_SENDER_CHAIN_LENGTH);
        assert_eq!(sender.chain_key, chain_key);

        // A sender that ignores the limit: the receiver refuses the index, unchanged.
        let mut step = receiver.chain_key;
        SenderKeyState::chain_step(&mut step).unwrap();
        let key_at_max = SenderKeyState::chain_step(&mut step).unwrap();
        let nonce =
            SenderKeyState::build_nonce(&sender.signing_public_key, MAX_SENDER_CHAIN_LENGTH);
        let ciphertext = ChaCha20Poly1305Cipher::new(&key_at_max)
            .unwrap()
            .encrypt(&nonce, b"wrapped", &[])
            .unwrap();
        let mut signed = MAX_SENDER_CHAIN_LENGTH.to_be_bytes().to_vec();
        signed.extend_from_slice(&ciphertext);
        let at_max = SenderKeyMessage {
            chain_index: MAX_SENDER_CHAIN_LENGTH,
            signature: sender
                .signing_key
                .as_ref()
                .unwrap()
                .sign(&signed)
                .to_bytes()
                .to_vec(),
            ciphertext,
        };
        assert_rejected_unchanged(&mut receiver, &at_max);

        // The genuine last message still decrypts.
        assert_eq!(receiver.decrypt(&last).unwrap(), b"last");
        assert_eq!(receiver.chain_index, MAX_SENDER_CHAIN_LENGTH);
    }

    // ── Atomic decrypt ──────────────────────────────────────────────────
    //
    // A message that passes the signature check but not the AEAD check (signed by the same
    // sender for another chain) changes nothing.

    #[allow(clippy::type_complexity)]
    fn snapshot(s: &SenderKeyState) -> (Vec<u8>, u32, Vec<(u32, [u8; 32])>) {
        let mut skipped: Vec<_> = s.skipped_keys.iter().map(|(n, k)| (*n, *k)).collect();
        skipped.sort();
        (s.chain_key.to_vec(), s.chain_index, skipped)
    }

    fn assert_rejected_unchanged(s: &mut SenderKeyState, msg: &SenderKeyMessage) {
        let before = snapshot(s);
        assert!(s.decrypt(msg).is_err());
        assert!(
            snapshot(s) == before,
            "a failed decrypt changed the sender key state (index {})",
            msg.chain_index
        );
    }

    /// A receiver of the sender's first chain, six messages of that chain, and eight
    /// validly signed messages of another chain under the same signing key.
    fn receiver_with_messages_of_two_chains()
    -> (SenderKeyState, Vec<SenderKeyMessage>, Vec<SenderKeyMessage>) {
        let mut sender = SenderKeyState::new();
        let receiver =
            SenderKeyState::from_distribution(&sender.create_distribution([0x42; 32])).unwrap();
        let genuine = (0..6u8).map(|i| sender.encrypt(&[i]).unwrap()).collect();
        // Another chain under the same signing key: `rotate` replaces the key, so build it.
        let mut sender = SenderKeyState {
            chain_key: [0x77; 32],
            signing_key: sender.signing_key.clone(),
            signing_public_key: sender.signing_public_key,
            chain_index: 0,
            skipped_keys: HashMap::new(),
        };
        let other = (0..8u8).map(|i| sender.encrypt(&[i]).unwrap()).collect();
        (receiver, genuine, other)
    }

    #[test]
    fn failed_decrypt_keeps_the_skipped_key() {
        let (mut receiver, genuine, other) = receiver_with_messages_of_two_chains();
        // The third arrives first: the keys of the first two are stored as skipped.
        assert_eq!(receiver.decrypt(&genuine[2]).unwrap(), [2]);
        assert_eq!(receiver.skipped_keys.len(), 2);

        assert_rejected_unchanged(&mut receiver, &other[0]);
        assert_rejected_unchanged(&mut receiver, &other[1]);
        assert_eq!(receiver.skipped_keys.len(), 2);

        assert_eq!(receiver.decrypt(&genuine[0]).unwrap(), [0]);
        assert_eq!(receiver.decrypt(&genuine[1]).unwrap(), [1]);
        // Used once, then gone.
        assert!(receiver.skipped_keys.is_empty());
        assert_rejected_unchanged(&mut receiver, &genuine[0]);
    }

    #[test]
    fn failed_decrypt_does_not_advance_the_chain() {
        let (mut receiver, genuine, other) = receiver_with_messages_of_two_chains();
        assert_eq!(receiver.decrypt(&genuine[0]).unwrap(), [0]);

        // The next index, and indexes ahead of the chain (which ask for skipped keys).
        assert_rejected_unchanged(&mut receiver, &other[1]);
        assert_rejected_unchanged(&mut receiver, &other[5]);
        assert_rejected_unchanged(&mut receiver, &other[7]);
        assert!(receiver.skipped_keys.is_empty());
        assert_eq!(receiver.chain_index, 1);

        // In order, out of order, and late: the genuine chain is intact.
        assert_eq!(receiver.decrypt(&genuine[1]).unwrap(), [1]);
        assert_eq!(receiver.decrypt(&genuine[5]).unwrap(), [5]);
        assert_rejected_unchanged(&mut receiver, &other[3]);
        assert_eq!(receiver.decrypt(&genuine[3]).unwrap(), [3]);
        assert_eq!(receiver.decrypt(&genuine[2]).unwrap(), [2]);
        assert_eq!(receiver.decrypt(&genuine[4]).unwrap(), [4]);
        assert!(receiver.skipped_keys.is_empty());
    }

    #[test]
    fn rejected_before_the_aead_check_changes_nothing() {
        let (mut receiver, genuine, _) = receiver_with_messages_of_two_chains();
        assert_eq!(receiver.decrypt(&genuine[2]).unwrap(), [2]);

        // Bad signature, on a stored skipped key's index and ahead of the chain.
        for i in [0, 4] {
            let mut forged = genuine[i].clone();
            forged.signature[0] ^= 0x01;
            assert_rejected_unchanged(&mut receiver, &forged);
            let mut forged = genuine[i].clone();
            forged.ciphertext[0] ^= 0x01;
            assert_rejected_unchanged(&mut receiver, &forged);
        }
        // Replay of a consumed message.
        assert_rejected_unchanged(&mut receiver, &genuine[2]);

        // Past the skip limit.
        let mut sender = SenderKeyState::new();
        let mut far =
            SenderKeyState::from_distribution(&sender.create_distribution([0x42; 32])).unwrap();
        let mut last = None;
        for _ in 0..=MAX_SKIP + 1 {
            last = Some(sender.encrypt(b"x").unwrap());
        }
        assert_rejected_unchanged(&mut far, &last.unwrap());
        assert!(far.skipped_keys.is_empty());

        assert_eq!(receiver.decrypt(&genuine[0]).unwrap(), [0]);
        assert_eq!(receiver.decrypt(&genuine[4]).unwrap(), [4]);
    }
}
