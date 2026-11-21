//! Double Ratchet protocol implementation.
//!
//! Provides forward secrecy and future secrecy for ongoing message encryption.
//! Initialized from the shared secret produced by X3DH (PNP-002).
//!
//! Each message uses a unique key derived through the ratchet chain.

use crate::aead::ChaCha20Poly1305Cipher;
use crate::kdf::hkdf_sha256;
use crate::{Aead, CryptoError, RatchetHeader, RatchetSession};
use rand::rngs::OsRng;
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Maximum number of skipped message keys to store.
const MAX_SKIP: u32 = 1000;

/// State for an active Double Ratchet session.
#[derive(Zeroize)]
pub struct DoubleRatchetSession {
    /// Root key — ratcheted on each DH ratchet step.
    root_key: [u8; 32],
    /// Current sending chain key.
    send_chain_key: Option<[u8; 32]>,
    /// Current receiving chain key.
    recv_chain_key: Option<[u8; 32]>,
    /// Our current DH ratchet private key.
    #[zeroize(skip)]
    dh_self: Option<StaticSecret>,
    /// Their current DH ratchet public key.
    #[zeroize(skip)]
    dh_remote: Option<PublicKey>,
    /// Message number in current sending chain.
    send_n: u32,
    /// Message number in current receiving chain.
    recv_n: u32,
    /// Number of messages in previous sending chain.
    previous_send_n: u32,
    /// Skipped message keys: (ratchet_pubkey, message_number) -> message_key
    #[zeroize(skip)]
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl DoubleRatchetSession {
    /// Initialize as the initiator (Alice) after X3DH.
    ///
    /// Alice sends the first message, so she:
    /// - Uses SK as the root key
    /// - Generates her first DH ratchet keypair
    /// - Performs a DH ratchet with Bob's ratchet public key
    pub fn initialize_initiator(
        shared_secret: [u8; 32],
        remote_ratchet_key: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        let dh_self = StaticSecret::random_from_rng(OsRng);
        let dh_remote = PublicKey::from(*remote_ratchet_key);

        // Perform initial DH ratchet
        let dh_output = dh_self.diffie_hellman(&dh_remote);
        let kdf_out = hkdf_sha256(
            &shared_secret,
            dh_output.as_bytes(),
            b"ParolNet_ratchet_v1",
            64,
        )?;

        let mut root_key = [0u8; 32];
        let mut send_chain_key = [0u8; 32];
        root_key.copy_from_slice(&kdf_out[..32]);
        send_chain_key.copy_from_slice(&kdf_out[32..64]);

        Ok(Self {
            root_key,
            send_chain_key: Some(send_chain_key),
            recv_chain_key: None,
            dh_self: Some(dh_self),
            dh_remote: Some(dh_remote),
            send_n: 0,
            recv_n: 0,
            previous_send_n: 0,
            skipped_keys: HashMap::new(),
        })
    }

    /// Initialize as the responder (Bob) after X3DH.
    ///
    /// Bob waits for Alice's first message, which will contain her ratchet key.
    pub fn initialize_responder(
        shared_secret: [u8; 32],
        our_ratchet_secret: StaticSecret,
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            root_key: shared_secret,
            send_chain_key: None,
            recv_chain_key: None,
            dh_self: Some(our_ratchet_secret),
            dh_remote: None,
            send_n: 0,
            recv_n: 0,
            previous_send_n: 0,
            skipped_keys: HashMap::new(),
        })
    }

    /// Get our current ratchet public key.
    pub fn our_ratchet_public_key(&self) -> Option<[u8; 32]> {
        self.dh_self
            .as_ref()
            .map(|s| *PublicKey::from(s).as_bytes())
    }

    /// Export session state as bytes for persistence.
    ///
    /// Format: version(1) || root_key(32) || send_ck_flag(1) [|| send_ck(32)]
    ///   || recv_ck_flag(1) [|| recv_ck(32)] || dh_self_flag(1) [|| dh_self(32)]
    ///   || dh_remote_flag(1) [|| dh_remote(32)] || send_n(4) || recv_n(4)
    ///   || previous_send_n(4) || skipped_count(4)
    ///   || [ratchet_key(32) || msg_num(4) || msg_key(32)]...
    pub fn export_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(200);
        out.push(0x01); // version
        out.extend_from_slice(&self.root_key);

        // Optional fields: flag byte then 32 bytes if present
        if let Some(ref ck) = self.send_chain_key {
            out.push(1);
            out.extend_from_slice(ck);
        } else {
            out.push(0);
        }

        if let Some(ref ck) = self.recv_chain_key {
            out.push(1);
            out.extend_from_slice(ck);
        } else {
            out.push(0);
        }

        if let Some(ref secret) = self.dh_self {
            out.push(1);
            out.extend_from_slice(&secret.to_bytes());
        } else {
            out.push(0);
        }

        if let Some(ref pk) = self.dh_remote {
            out.push(1);
            out.extend_from_slice(pk.as_bytes());
        } else {
            out.push(0);
        }

        out.extend_from_slice(&self.send_n.to_be_bytes());
        out.extend_from_slice(&self.recv_n.to_be_bytes());
        out.extend_from_slice(&self.previous_send_n.to_be_bytes());

        let count = self.skipped_keys.len() as u32;
        out.extend_from_slice(&count.to_be_bytes());
        for ((rk, n), mk) in &self.skipped_keys {
            out.extend_from_slice(rk);
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(mk);
        }

        out
    }

    /// Import session state from bytes produced by `export_bytes`.
    pub fn import_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        let err = || CryptoError::RatchetError {
            reason: "invalid session export data".into(),
        };

        if data.is_empty() || data[0] != 0x01 {
            return Err(err());
        }

        let mut pos = 1;

        // Helper to read exactly 32 bytes
        let read_32 = |pos: &mut usize| -> Result<[u8; 32], CryptoError> {
            if *pos + 32 > data.len() {
                return Err(err());
            }
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&data[*pos..*pos + 32]);
            *pos += 32;
            Ok(buf)
        };

        let read_4 = |pos: &mut usize| -> Result<u32, CryptoError> {
            if *pos + 4 > data.len() {
                return Err(err());
            }
            let val = u32::from_be_bytes(data[*pos..*pos + 4].try_into().map_err(|_| err())?);
            *pos += 4;
            Ok(val)
        };

        let read_flag = |pos: &mut usize| -> Result<bool, CryptoError> {
            if *pos >= data.len() {
                return Err(err());
            }
            let flag = data[*pos] != 0;
            *pos += 1;
            Ok(flag)
        };

        let root_key = read_32(&mut pos)?;

        let send_chain_key = if read_flag(&mut pos)? {
            Some(read_32(&mut pos)?)
        } else {
            None
        };

        let recv_chain_key = if read_flag(&mut pos)? {
            Some(read_32(&mut pos)?)
        } else {
            None
        };

        let dh_self = if read_flag(&mut pos)? {
            Some(StaticSecret::from(read_32(&mut pos)?))
        } else {
            None
        };

        let dh_remote = if read_flag(&mut pos)? {
            Some(PublicKey::from(read_32(&mut pos)?))
        } else {
            None
        };

        let send_n = read_4(&mut pos)?;
        let recv_n = read_4(&mut pos)?;
        let previous_send_n = read_4(&mut pos)?;

        let skip_count = read_4(&mut pos)? as usize;
        if skip_count > MAX_SKIP as usize {
            return Err(err());
        }

        let mut skipped_keys = HashMap::with_capacity(skip_count);
        for _ in 0..skip_count {
            let rk = read_32(&mut pos)?;
            let n = read_4(&mut pos)?;
            let mk = read_32(&mut pos)?;
            skipped_keys.insert((rk, n), mk);
        }

        Ok(Self {
            root_key,
            send_chain_key,
            recv_chain_key,
            dh_self,
            dh_remote,
            send_n,
            recv_n,
            previous_send_n,
            skipped_keys,
        })
    }

    /// Derive the next message key from a chain key (symmetric ratchet step).
    fn chain_ratchet(chain_key: &mut [u8; 32]) -> Result<[u8; 32], CryptoError> {
        // Message key = HMAC-SHA256(chain_key, 0x01)
        let mk_bytes = hkdf_sha256(chain_key, &[0x01], b"ParolNet_msg_key", 32)?;
        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&mk_bytes);

        // New chain key = HMAC-SHA256(chain_key, 0x02)
        let ck_bytes = hkdf_sha256(chain_key, &[0x02], b"ParolNet_chain_key", 32)?;
        chain_key.copy_from_slice(&ck_bytes);

        Ok(message_key)
    }

    /// Construct a 12-byte nonce from the ratchet public key and message_number.
    ///
    /// Uses 8 bytes from the ratchet key (unique per chain) plus the message
    /// number to guarantee nonce uniqueness: different chains have different
    /// ratchet keys, and within a chain the message number is monotonic.
    fn build_nonce(ratchet_key: &[u8; 32], message_number: u32) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&ratchet_key[..8]);
        nonce[8..12].copy_from_slice(&message_number.to_be_bytes());
        nonce
    }
}

/// The state one received message may change, worked on apart from the session.
///
/// `decrypt` runs the DH ratchet step, the skipped-key derivation and the chain step on this
/// copy and writes it back with [`ReceiveAttempt::commit`] only once the AEAD tag has
/// verified (PNP-002-MUST-041). A message that does not authenticate drops the attempt, which
/// zeroizes every key in it, and the session keeps the state it had. The session's stored
/// skipped keys are never copied: the keys this message makes the receiver skip wait in
/// `new_skipped`, and the session's own DH secret is only read.
#[derive(Zeroize, ZeroizeOnDrop)]
struct ReceiveAttempt {
    root_key: [u8; 32],
    send_chain_key: Option<[u8; 32]>,
    recv_chain_key: Option<[u8; 32]>,
    /// The sending ratchet key generated by a DH ratchet step; `None` without one.
    new_dh_self: Option<StaticSecret>,
    /// Public.
    #[zeroize(skip)]
    dh_remote: Option<PublicKey>,
    send_n: u32,
    recv_n: u32,
    previous_send_n: u32,
    /// How many skipped keys the session already stores (for the `MAX_SKIP` limit).
    stored_skipped: usize,
    /// Skipped keys derived for this message: (ratchet_pubkey, message_number, message_key).
    new_skipped: Vec<([u8; 32], u32, [u8; 32])>,
}

impl ReceiveAttempt {
    fn begin(session: &DoubleRatchetSession) -> Self {
        Self {
            root_key: session.root_key,
            send_chain_key: session.send_chain_key,
            recv_chain_key: session.recv_chain_key,
            new_dh_self: None,
            dh_remote: session.dh_remote,
            send_n: session.send_n,
            recv_n: session.recv_n,
            previous_send_n: session.previous_send_n,
            stored_skipped: session.skipped_keys.len(),
            new_skipped: Vec::new(),
        }
    }

    /// Perform a DH ratchet step when receiving a new ratchet public key.
    ///
    /// `dh_self` is the session's current ratchet secret.
    fn dh_ratchet(
        &mut self,
        dh_self: Option<&StaticSecret>,
        new_remote_key: &[u8; 32],
    ) -> Result<(), CryptoError> {
        let dh_remote = PublicKey::from(*new_remote_key);

        // Derive receiving chain key from current DH
        if let Some(dh_self) = dh_self {
            let dh_output = dh_self.diffie_hellman(&dh_remote);
            let kdf_out = hkdf_sha256(
                &self.root_key,
                dh_output.as_bytes(),
                b"ParolNet_ratchet_v1",
                64,
            )?;
            self.root_key.copy_from_slice(&kdf_out[..32]);
            let mut recv_ck = [0u8; 32];
            recv_ck.copy_from_slice(&kdf_out[32..64]);
            self.recv_chain_key = Some(recv_ck);
            recv_ck.zeroize();
        }

        self.dh_remote = Some(dh_remote);

        // Generate new DH keypair for sending
        let new_dh_self = StaticSecret::random_from_rng(OsRng);
        let dh_output = new_dh_self.diffie_hellman(&dh_remote);
        let kdf_out = hkdf_sha256(
            &self.root_key,
            dh_output.as_bytes(),
            b"ParolNet_ratchet_v1",
            64,
        )?;
        self.root_key.copy_from_slice(&kdf_out[..32]);
        let mut send_ck = [0u8; 32];
        send_ck.copy_from_slice(&kdf_out[32..64]);
        self.send_chain_key = Some(send_ck);
        send_ck.zeroize();
        self.new_dh_self = Some(new_dh_self);
        self.previous_send_n = self.send_n;
        self.send_n = 0;
        self.recv_n = 0;

        Ok(())
    }

    /// Skip message keys for out-of-order delivery.
    fn skip_message_keys(&mut self, remote_key: &[u8; 32], until: u32) -> Result<(), CryptoError> {
        if let Some(ref mut ck) = self.recv_chain_key {
            while self.recv_n < until {
                if self.stored_skipped + self.new_skipped.len() >= MAX_SKIP as usize {
                    return Err(CryptoError::RatchetError {
                        reason: "too many skipped message keys".into(),
                    });
                }
                let mut mk = DoubleRatchetSession::chain_ratchet(ck)?;
                self.new_skipped.push((*remote_key, self.recv_n, mk));
                mk.zeroize();
                self.recv_n += 1;
            }
        }
        Ok(())
    }

    /// Write the attempt back to the session. Called only after the AEAD tag verified.
    ///
    /// Dropping `self` afterwards zeroizes this copy; the session's previous ratchet secret
    /// zeroizes itself when it is replaced.
    fn commit(mut self, session: &mut DoubleRatchetSession) {
        session.root_key = self.root_key;
        session.send_chain_key = self.send_chain_key;
        session.recv_chain_key = self.recv_chain_key;
        if let Some(new_dh_self) = self.new_dh_self.take() {
            session.dh_self = Some(new_dh_self);
        }
        session.dh_remote = self.dh_remote;
        session.send_n = self.send_n;
        session.recv_n = self.recv_n;
        session.previous_send_n = self.previous_send_n;
        for (ratchet_key, n, mk) in &self.new_skipped {
            session.skipped_keys.insert((*ratchet_key, *n), *mk);
        }
    }
}

/// Manual `Drop` to zeroize key material that `#[zeroize(skip)]` excludes:
/// - `skipped_keys`: HashMap values contain message keys (secret material).
/// - `dh_remote`: `PublicKey` does not implement `Zeroize`; we manually wipe its bytes.
/// - `dh_self`: `StaticSecret` implements `ZeroizeOnDrop` natively, so the skip is safe.
impl Drop for DoubleRatchetSession {
    fn drop(&mut self) {
        // Zeroize the derive-Zeroize fields (root_key, chain keys, etc.)
        self.zeroize();

        // Zeroize all skipped message keys (HashMap is #[zeroize(skip)])
        for value in self.skipped_keys.values_mut() {
            value.zeroize();
        }
        self.skipped_keys.clear();

        // Zeroize the remote public key bytes via unsafe cast
        // (PublicKey does not implement Zeroize)
        if let Some(ref mut pk) = self.dh_remote {
            let bytes: &mut [u8; 32] = unsafe { &mut *(pk as *mut PublicKey as *mut [u8; 32]) };
            bytes.zeroize();
        }
    }
}

/// Build the AEAD additional-authenticated-data for the Double Ratchet
/// session AEAD (PNP-001-MUST-007).
///
/// The ratchet public key is bound for nonce-derivation integrity, and the
/// optional `extra_aad` (typically the serialized cleartext envelope header)
/// is concatenated after it so wire-level header tampering is detected by
/// the AEAD tag. Concatenation is unambiguous here because the ratchet-key
/// prefix is always exactly 32 bytes.
fn build_aad(ratchet_key: &[u8; 32], extra_aad: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + extra_aad.len());
    aad.extend_from_slice(ratchet_key);
    aad.extend_from_slice(extra_aad);
    aad
}

impl RatchetSession for DoubleRatchetSession {
    fn encrypt(
        &mut self,
        plaintext: &[u8],
        extra_aad: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>), CryptoError> {
        let send_ck = self
            .send_chain_key
            .as_mut()
            .ok_or(CryptoError::RatchetError {
                reason: "no sending chain key established".into(),
            })?;

        let message_key = Self::chain_ratchet(send_ck)?;

        let ratchet_pub = self
            .our_ratchet_public_key()
            .ok_or(CryptoError::RatchetError {
                reason: "no DH ratchet key".into(),
            })?;

        let header = RatchetHeader {
            ratchet_key: ratchet_pub,
            previous_chain_length: self.previous_send_n,
            message_number: self.send_n,
        };

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305Cipher::new(&message_key)?;
        let nonce = Self::build_nonce(&ratchet_pub, self.send_n);
        let aad = build_aad(&header.ratchet_key, extra_aad);
        let ciphertext = cipher.encrypt(&nonce, plaintext, &aad)?;

        self.send_n += 1;

        Ok((header, ciphertext))
    }

    /// Decrypt one message. All-or-nothing (PNP-002-MUST-041): when this returns `Err` the
    /// session, skipped keys included, is exactly what it was before the call.
    fn decrypt(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
        extra_aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = Self::build_nonce(&header.ratchet_key, header.message_number);
        let aad = build_aad(&header.ratchet_key, extra_aad);

        // Check for skipped message key. It is consumed only by a message that authenticates.
        let skipped_id = (header.ratchet_key, header.message_number);
        if let Some(mk) = self.skipped_keys.get(&skipped_id) {
            let plaintext = ChaCha20Poly1305Cipher::new(mk)?.decrypt(&nonce, ciphertext, &aad)?;
            if let Some(mut used) = self.skipped_keys.remove(&skipped_id) {
                used.zeroize();
            }
            return Ok(plaintext);
        }

        // Everything below runs on a copy; `self` changes only in `commit`.
        let mut attempt = ReceiveAttempt::begin(self);

        // Check if we need a DH ratchet step
        let need_dh_ratchet = self
            .dh_remote
            .as_ref()
            .map(|r| *r.as_bytes() != header.ratchet_key)
            .unwrap_or(true);

        if need_dh_ratchet {
            // Skip any remaining messages in the current receiving chain
            if let (Some(remote), Some(_)) = (self.dh_remote.as_ref(), self.recv_chain_key) {
                attempt.skip_message_keys(remote.as_bytes(), header.previous_chain_length)?;
            }
            attempt.dh_ratchet(self.dh_self.as_ref(), &header.ratchet_key)?;
        }

        // Skip to the correct message number
        attempt.skip_message_keys(&header.ratchet_key, header.message_number)?;

        // Derive the message key
        let recv_ck = attempt
            .recv_chain_key
            .as_mut()
            .ok_or(CryptoError::RatchetError {
                reason: "no receiving chain key".into(),
            })?;
        let message_key = Zeroizing::new(Self::chain_ratchet(recv_ck)?);
        attempt.recv_n += 1;

        // Decrypt, and only then commit
        let plaintext =
            ChaCha20Poly1305Cipher::new(&message_key[..])?.decrypt(&nonce, ciphertext, &aad)?;
        attempt.commit(self);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_session_pair() -> (DoubleRatchetSession, DoubleRatchetSession) {
        let shared_secret = [0x42u8; 32];

        // Bob generates his initial ratchet keypair
        let bob_ratchet = StaticSecret::random_from_rng(OsRng);
        let bob_ratchet_pub = *PublicKey::from(&bob_ratchet).as_bytes();

        let alice =
            DoubleRatchetSession::initialize_initiator(shared_secret, &bob_ratchet_pub).unwrap();
        let bob = DoubleRatchetSession::initialize_responder(shared_secret, bob_ratchet).unwrap();

        (alice, bob)
    }

    #[test]
    fn test_alice_sends_bob_decrypts() {
        let (mut alice, mut bob) = setup_session_pair();

        let (header, ct) = alice.encrypt(b"hello bob", &[]).unwrap();
        let pt = bob.decrypt(&header, &ct, &[]).unwrap();
        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn test_bidirectional() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice -> Bob
        let (h1, ct1) = alice.encrypt(b"hello", &[]).unwrap();
        let pt1 = bob.decrypt(&h1, &ct1, &[]).unwrap();
        assert_eq!(pt1, b"hello");

        // Bob -> Alice
        let (h2, ct2) = bob.encrypt(b"hi alice", &[]).unwrap();
        let pt2 = alice.decrypt(&h2, &ct2, &[]).unwrap();
        assert_eq!(pt2, b"hi alice");

        // Alice -> Bob again (new ratchet step)
        let (h3, ct3) = alice.encrypt(b"how are you?", &[]).unwrap();
        let pt3 = bob.decrypt(&h3, &ct3, &[]).unwrap();
        assert_eq!(pt3, b"how are you?");
    }

    #[test]
    fn test_multiple_messages_same_direction() {
        let (mut alice, mut bob) = setup_session_pair();

        let (h1, ct1) = alice.encrypt(b"msg1", &[]).unwrap();
        let (h2, ct2) = alice.encrypt(b"msg2", &[]).unwrap();
        let (h3, ct3) = alice.encrypt(b"msg3", &[]).unwrap();

        // Decrypt in order
        assert_eq!(bob.decrypt(&h1, &ct1, &[]).unwrap(), b"msg1");
        assert_eq!(bob.decrypt(&h2, &ct2, &[]).unwrap(), b"msg2");
        assert_eq!(bob.decrypt(&h3, &ct3, &[]).unwrap(), b"msg3");
    }

    #[test]
    fn test_out_of_order_delivery() {
        let (mut alice, mut bob) = setup_session_pair();

        let (h1, ct1) = alice.encrypt(b"msg1", &[]).unwrap();
        let (h2, ct2) = alice.encrypt(b"msg2", &[]).unwrap();
        let (h3, ct3) = alice.encrypt(b"msg3", &[]).unwrap();

        // Deliver out of order: 3, 1, 2
        assert_eq!(bob.decrypt(&h3, &ct3, &[]).unwrap(), b"msg3");
        assert_eq!(bob.decrypt(&h1, &ct1, &[]).unwrap(), b"msg1");
        assert_eq!(bob.decrypt(&h2, &ct2, &[]).unwrap(), b"msg2");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (mut alice, mut bob) = setup_session_pair();

        let (header, mut ct) = alice.encrypt(b"secret", &[]).unwrap();
        ct[0] ^= 0xFF; // tamper
        assert!(bob.decrypt(&header, &ct, &[]).is_err());
    }

    #[test]
    fn test_different_keys_produce_different_ciphertexts() {
        let (mut alice1, _) = setup_session_pair();
        let (mut alice2, _) = setup_session_pair();

        let (_, ct1) = alice1.encrypt(b"same message", &[]).unwrap();
        let (_, ct2) = alice2.encrypt(b"same message", &[]).unwrap();
        assert_ne!(ct1, ct2); // different session keys
    }

    #[test]
    fn test_export_import_roundtrip() {
        let (mut alice, mut bob) = setup_session_pair();

        // Exchange some messages to advance ratchet state
        let (h1, ct1) = alice.encrypt(b"hello", &[]).unwrap();
        bob.decrypt(&h1, &ct1, &[]).unwrap();
        let (h2, ct2) = bob.encrypt(b"world", &[]).unwrap();
        alice.decrypt(&h2, &ct2, &[]).unwrap();

        // Export Alice's session
        let exported = alice.export_bytes();

        // Import into new session
        let mut alice2 = DoubleRatchetSession::import_bytes(&exported).unwrap();

        // Alice2 should be able to send and Bob should decrypt
        let (h3, ct3) = alice2.encrypt(b"after restore", &[]).unwrap();
        let pt3 = bob.decrypt(&h3, &ct3, &[]).unwrap();
        assert_eq!(pt3, b"after restore");
    }

    #[test]
    fn test_export_import_with_skipped_keys() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice sends 3 messages
        let (h1, ct1) = alice.encrypt(b"msg1", &[]).unwrap();
        let (h2, ct2) = alice.encrypt(b"msg2", &[]).unwrap();
        let (h3, ct3) = alice.encrypt(b"msg3", &[]).unwrap();

        // Bob receives msg3 first (skips 1 and 2)
        bob.decrypt(&h3, &ct3, &[]).unwrap();

        // Export Bob with skipped keys
        let exported = bob.export_bytes();
        let mut bob2 = DoubleRatchetSession::import_bytes(&exported).unwrap();

        // Bob2 should still decrypt skipped messages
        assert_eq!(bob2.decrypt(&h1, &ct1, &[]).unwrap(), b"msg1");
        assert_eq!(bob2.decrypt(&h2, &ct2, &[]).unwrap(), b"msg2");
    }

    #[test]
    fn test_import_invalid_data() {
        assert!(DoubleRatchetSession::import_bytes(&[]).is_err());
        assert!(DoubleRatchetSession::import_bytes(&[0x02]).is_err()); // wrong version
        assert!(DoubleRatchetSession::import_bytes(&[0x01]).is_err()); // truncated
    }

    // ── Atomic decrypt (PNP-002-MUST-041) ──────────────────────────────
    //
    // A decrypt that fails leaves the session exactly as it was.

    /// Every field of the session, skipped keys in a fixed order.
    fn snapshot(s: &DoubleRatchetSession) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&s.root_key);
        for ck in [&s.send_chain_key, &s.recv_chain_key] {
            out.push(ck.is_some() as u8);
            out.extend_from_slice(&ck.unwrap_or_default());
        }
        out.push(s.dh_self.is_some() as u8);
        out.extend_from_slice(&s.dh_self.as_ref().map(|k| k.to_bytes()).unwrap_or_default());
        out.push(s.dh_remote.is_some() as u8);
        out.extend_from_slice(&s.dh_remote.map(|k| *k.as_bytes()).unwrap_or_default());
        for n in [s.send_n, s.recv_n, s.previous_send_n] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        let mut skipped: Vec<_> = s.skipped_keys.iter().collect();
        skipped.sort();
        for ((rk, n), mk) in skipped {
            out.extend_from_slice(rk);
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(mk);
        }
        out
    }

    /// Feed a message that must not decrypt and check nothing moved.
    fn assert_rejected_unchanged(
        s: &mut DoubleRatchetSession,
        header: &RatchetHeader,
        ct: &[u8],
        aad: &[u8],
    ) {
        let before = snapshot(s);
        let exported = s.export_bytes();
        assert!(s.decrypt(header, ct, aad).is_err());
        assert!(
            snapshot(s) == before,
            "a failed decrypt changed the session (header {header:?})"
        );
        assert_eq!(s.export_bytes(), exported);
    }

    /// Both directions still work, including across a DH ratchet step each way.
    fn assert_conversation_continues(
        alice: &mut DoubleRatchetSession,
        bob: &mut DoubleRatchetSession,
    ) {
        for round in 0..3u8 {
            let (h, ct) = alice.encrypt(&[b'a', round], b"aad").unwrap();
            assert_eq!(bob.decrypt(&h, &ct, b"aad").unwrap(), [b'a', round]);
            let (h, ct) = bob.encrypt(&[b'b', round], b"aad").unwrap();
            assert_eq!(alice.decrypt(&h, &ct, b"aad").unwrap(), [b'b', round]);
        }
    }

    /// A pair that has talked in both directions (so both have every chain).
    fn established_pair() -> (DoubleRatchetSession, DoubleRatchetSession) {
        let (mut alice, mut bob) = setup_session_pair();
        assert_conversation_continues(&mut alice, &mut bob);
        (alice, bob)
    }

    #[test]
    fn failed_decrypt_random_ciphertext_under_current_header() {
        let (mut alice, mut bob) = established_pair();
        let (h, ct) = alice.encrypt(b"genuine", b"aad").unwrap();
        let (h2, ct2) = alice.encrypt(b"genuine 2", b"aad").unwrap();

        let garbage = vec![0xA5u8; ct.len()];
        assert_rejected_unchanged(&mut bob, &h, &garbage, b"aad");
        // The genuine ciphertext under other associated data (an envelope of another session).
        assert_rejected_unchanged(&mut bob, &h, &ct, b"other");
        // Too short to carry a tag.
        assert_rejected_unchanged(&mut bob, &h, &[1, 2, 3], b"aad");

        assert_eq!(bob.decrypt(&h, &ct, b"aad").unwrap(), b"genuine");
        assert_eq!(bob.decrypt(&h2, &ct2, b"aad").unwrap(), b"genuine 2");
        assert_conversation_continues(&mut alice, &mut bob);
    }

    #[test]
    fn failed_decrypt_fresh_responder_session() {
        // Bob has received nothing yet: no remote key, no chains.
        let (mut alice, mut bob) = setup_session_pair();
        let (h, ct) = alice.encrypt(b"first", &[]).unwrap();

        let mut forged = h.clone();
        forged.ratchet_key = [0x77; 32];
        assert_rejected_unchanged(&mut bob, &forged, &ct, &[]);
        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert_rejected_unchanged(&mut bob, &h, &tampered, &[]);

        assert_eq!(bob.decrypt(&h, &ct, &[]).unwrap(), b"first");
        assert_conversation_continues(&mut alice, &mut bob);
    }

    #[test]
    fn failed_decrypt_new_random_ratchet_key() {
        let (mut alice, mut bob) = established_pair();
        let (h, ct) = alice.encrypt(b"genuine", b"aad").unwrap();

        for (key, pn, n) in [
            ([0x99u8; 32], 0u32, 0u32),
            ([0x5Au8; 32], 2, 0),
            ([0x01u8; 32], 700, 3),
            ([0x02u8; 32], 5000, 0),
            ([0x03u8; 32], 0, 5000),
            ([0x04u8; 32], u32::MAX, u32::MAX),
        ] {
            let forged = RatchetHeader {
                ratchet_key: key,
                previous_chain_length: pn,
                message_number: n,
            };
            assert_rejected_unchanged(&mut bob, &forged, &ct, b"aad");
            assert_rejected_unchanged(&mut alice, &forged, &ct, b"aad");
        }

        assert_eq!(bob.decrypt(&h, &ct, b"aad").unwrap(), b"genuine");
        assert_conversation_continues(&mut alice, &mut bob);
    }

    #[test]
    fn failed_decrypt_huge_message_number() {
        let (mut alice, mut bob) = established_pair();
        let (h, ct) = alice.encrypt(b"genuine", b"aad").unwrap();
        let skipped_before = bob.skipped_keys.len();

        // Within the skip limit (repeated, so the limit would be passed if any were stored),
        // at it, and beyond it.
        for n in [
            h.message_number + 1,
            h.message_number + 600,
            h.message_number + 600,
            h.message_number + MAX_SKIP - 1,
            h.message_number + MAX_SKIP,
            h.message_number + MAX_SKIP + 1,
            5000,
            u32::MAX,
        ] {
            let mut forged = h.clone();
            forged.message_number = n;
            assert_rejected_unchanged(&mut bob, &forged, &ct, b"aad");
            assert_eq!(bob.skipped_keys.len(), skipped_before);
        }

        assert_eq!(bob.decrypt(&h, &ct, b"aad").unwrap(), b"genuine");
        assert_conversation_continues(&mut alice, &mut bob);
    }

    #[test]
    fn failed_decrypt_replay_of_consumed_message() {
        let (mut alice, mut bob) = established_pair();
        let (h1, ct1) = alice.encrypt(b"one", b"aad").unwrap();
        let (h2, ct2) = alice.encrypt(b"two", b"aad").unwrap();
        let (h3, ct3) = alice.encrypt(b"three", b"aad").unwrap();

        assert_eq!(bob.decrypt(&h1, &ct1, b"aad").unwrap(), b"one");
        assert_rejected_unchanged(&mut bob, &h1, &ct1, b"aad");
        assert_rejected_unchanged(&mut bob, &h1, &ct1, b"aad");

        // Out of order, then replays of both the skipped-key message and the in-order one.
        assert_eq!(bob.decrypt(&h3, &ct3, b"aad").unwrap(), b"three");
        assert_rejected_unchanged(&mut bob, &h3, &ct3, b"aad");
        assert_eq!(bob.decrypt(&h2, &ct2, b"aad").unwrap(), b"two");
        assert_rejected_unchanged(&mut bob, &h2, &ct2, b"aad");

        // A replay from the previous receiving chain, after a DH ratchet step.
        assert_conversation_continues(&mut alice, &mut bob);
        assert_rejected_unchanged(&mut bob, &h1, &ct1, b"aad");
        assert_conversation_continues(&mut alice, &mut bob);
    }

    #[test]
    fn failed_decrypt_keeps_the_skipped_key() {
        let (mut alice, mut bob) = established_pair();
        let (h1, ct1) = alice.encrypt(b"one", b"aad").unwrap();
        let (h2, ct2) = alice.encrypt(b"two", b"aad").unwrap();
        let (h3, ct3) = alice.encrypt(b"three", b"aad").unwrap();

        // Bob gets the third first: the keys of the first two are stored as skipped.
        assert_eq!(bob.decrypt(&h3, &ct3, b"aad").unwrap(), b"three");
        assert_eq!(bob.skipped_keys.len(), 2);

        let mut tampered = ct1.clone();
        *tampered.last_mut().unwrap() ^= 0x80;
        assert_rejected_unchanged(&mut bob, &h1, &tampered, b"aad");
        assert_rejected_unchanged(&mut bob, &h2, &ct2, b"wrong aad");
        assert_eq!(bob.skipped_keys.len(), 2);

        assert_eq!(bob.decrypt(&h1, &ct1, b"aad").unwrap(), b"one");
        assert_eq!(bob.decrypt(&h2, &ct2, b"aad").unwrap(), b"two");
        // Used once, then gone.
        assert!(bob.skipped_keys.is_empty());
        assert_rejected_unchanged(&mut bob, &h1, &ct1, b"aad");
        assert_conversation_continues(&mut alice, &mut bob);
    }

    #[test]
    fn failed_decrypt_keeps_skipped_keys_of_the_previous_chain() {
        let (mut alice, mut bob) = established_pair();
        let (h, ct) = alice.encrypt(b"a", b"aad").unwrap();
        bob.decrypt(&h, &ct, b"aad").unwrap();
        let (h_old, ct_old) = alice.encrypt(b"late", b"aad").unwrap();
        let (_, _) = alice.encrypt(b"never delivered", b"aad").unwrap();
        // A full round trip moves Alice to a new sending chain.
        let (h, ct) = bob.encrypt(b"b", b"aad").unwrap();
        alice.decrypt(&h, &ct, b"aad").unwrap();
        let (h_new, ct_new) = alice.encrypt(b"new chain", b"aad").unwrap();
        assert_ne!(h_new.ratchet_key, h_old.ratchet_key);

        // Forgeries against the new-chain header: Bob must not step his DH ratchet for them.
        let mut tampered = ct_new.clone();
        tampered[0] ^= 1;
        assert_rejected_unchanged(&mut bob, &h_new, &tampered, b"aad");
        let mut forged = h_new.clone();
        forged.previous_chain_length = 900;
        assert_rejected_unchanged(&mut bob, &forged, &tampered, b"aad");

        assert_eq!(bob.decrypt(&h_new, &ct_new, b"aad").unwrap(), b"new chain");
        // The late message of the previous chain is now behind a skipped key.
        let mut tampered = ct_old.clone();
        tampered[0] ^= 1;
        assert_rejected_unchanged(&mut bob, &h_old, &tampered, b"aad");
        assert_eq!(bob.decrypt(&h_old, &ct_old, b"aad").unwrap(), b"late");
        assert_conversation_continues(&mut alice, &mut bob);
    }

    #[test]
    fn skip_limit_still_enforced() {
        let (mut alice, mut bob) = established_pair();
        let mut last = None;
        for _ in 0..=MAX_SKIP + 1 {
            last = Some(alice.encrypt(b"x", &[]).unwrap());
        }
        let (h, ct) = last.unwrap();
        // A genuine message more than MAX_SKIP ahead is refused, and stores nothing.
        assert_rejected_unchanged(&mut bob, &h, &ct, &[]);
        assert!(bob.skipped_keys.is_empty());
    }

    /// Garbage and genuine messages interleaved, both directions, any delivery order.
    #[test]
    fn interleaved_garbage_never_disturbs_genuine_traffic() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        struct Flight {
            header: RatchetHeader,
            ct: Vec<u8>,
            pt: Vec<u8>,
        }

        fn garbage(rng: &mut StdRng, known: &[&Flight]) -> (RatchetHeader, Vec<u8>, Vec<u8>) {
            // Mostly small counters (cheap to reject), now and then far past the skip limit.
            let counter = |rng: &mut StdRng| {
                if rng.gen_ratio(1, 12) {
                    rng.r#gen::<u32>()
                } else {
                    rng.gen_range(0..40)
                }
            };
            let random_header = |rng: &mut StdRng| RatchetHeader {
                ratchet_key: rng.r#gen(),
                previous_chain_length: counter(rng),
                message_number: counter(rng),
            };
            let mut random_ct = vec![0u8; rng.gen_range(0..80)];
            rng.fill(&mut random_ct[..]);
            if known.is_empty() {
                return (random_header(rng), random_ct, b"aad".to_vec());
            }
            let base = known[rng.gen_range(0..known.len())];
            let mut header = base.header.clone();
            let mut ct = base.ct.clone();
            let mut aad = b"aad".to_vec();
            match rng.gen_range(0..6) {
                0 => return (random_header(rng), random_ct, aad),
                1 => {
                    let i = rng.gen_range(0..ct.len());
                    ct[i] ^= 1 << rng.gen_range(0..8);
                }
                2 => {
                    header.message_number =
                        header.message_number.wrapping_add(1 + counter(rng) / 2);
                }
                3 => header.ratchet_key = rng.r#gen(),
                4 => {
                    header.ratchet_key = rng.r#gen();
                    header.previous_chain_length = counter(rng);
                }
                _ => aad = b"other".to_vec(),
            }
            (header, ct, aad)
        }

        for seed in 0..8u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let (mut alice, mut bob) = setup_session_pair();
            // In flight to Bob / to Alice, and what each has already consumed.
            let mut flights: [Vec<Flight>; 2] = [Vec::new(), Vec::new()];
            let mut consumed: [Vec<Flight>; 2] = [Vec::new(), Vec::new()];
            let mut counter = 0u32;

            for step in 0..500 {
                let draining = step >= 420;
                let to_bob = rng.gen_bool(0.5);
                let dir = if to_bob { 0 } else { 1 };
                let (sender, receiver) = if to_bob {
                    (&mut alice, &mut bob)
                } else {
                    (&mut bob, &mut alice)
                };
                match rng.gen_range(0..10) {
                    0..=3 if !draining => {
                        counter += 1;
                        let pt = counter.to_be_bytes().to_vec();
                        // Bob cannot send before he has received anything.
                        if let Ok((header, ct)) = sender.encrypt(&pt, b"aad") {
                            flights[dir].push(Flight { header, ct, pt });
                        }
                    }
                    4..=6 => {
                        let known: Vec<&Flight> =
                            flights[dir].iter().chain(consumed[dir].iter()).collect();
                        let (header, ct, aad) = garbage(&mut rng, &known);
                        assert_rejected_unchanged(receiver, &header, &ct, &aad);
                    }
                    _ => {
                        if flights[dir].is_empty() {
                            continue;
                        }
                        // Any in-flight message: out-of-order delivery included.
                        let i = rng.gen_range(0..flights[dir].len());
                        let f = flights[dir].swap_remove(i);
                        assert_eq!(
                            receiver.decrypt(&f.header, &f.ct, b"aad").unwrap(),
                            f.pt,
                            "seed {seed} step {step}"
                        );
                        // And a replay of it right away.
                        assert_rejected_unchanged(receiver, &f.header, &f.ct, b"aad");
                        consumed[dir].push(f);
                    }
                }
            }
            for (dir, receiver) in [(0, &mut bob), (1, &mut alice)] {
                while let Some(f) = flights[dir].pop() {
                    assert_eq!(receiver.decrypt(&f.header, &f.ct, b"aad").unwrap(), f.pt);
                }
            }
            assert_conversation_continues(&mut alice, &mut bob);
        }
    }
}
