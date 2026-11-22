//! The record stream (PNP-010 §6): how a file is cut into records, the key of one attempt
//! and the STREAM nonces.

use chacha20poly1305::aead::{AeadInPlace as _, KeyInit as _};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

use crate::{CHUNK_SIZE, FileKey, TAG_SIZE, TransferError, TransferId};

/// Domain separation of the per-attempt record key.
const RECORD_KEY_INFO: &[u8] = b"PNP-010 record key v1";

/// How many records carry a file of `size` bytes: `ceil(size / CHUNK_SIZE)`, and one (empty)
/// record for an empty file. Saturates for sizes no offer may have.
pub fn record_count(size: u64) -> u32 {
    let count = size.div_ceil(CHUNK_SIZE as u64).max(1);
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// Plaintext length of record `index` of a file of `size` bytes: [`CHUNK_SIZE`] for every
/// record but the last, the remainder for the last. `None` when the file has no such record.
pub fn record_len(size: u64, index: u32) -> Option<usize> {
    let count = record_count(size);
    if index >= count {
        return None;
    }
    if index + 1 < count {
        return Some(CHUNK_SIZE);
    }
    Some((size - u64::from(index) * CHUNK_SIZE as u64) as usize)
}

/// The cipher of one attempt on one channel. Its key is wiped when it is dropped.
pub(crate) struct AttemptCipher(ChaCha20Poly1305);

impl AttemptCipher {
    /// `HKDF-SHA-256(salt = sender salt || receiver nonce, ikm = file key,
    /// info = "PNP-010 record key v1" || id || next)`: both ends contribute, so the records
    /// of one attempt verify in no other, and the same record index is never sealed twice
    /// under one key.
    pub(crate) fn derive(
        key: &FileKey,
        id: &TransferId,
        next: u32,
        salt: &[u8; 16],
        nonce: &[u8; 16],
    ) -> AttemptCipher {
        let mut hk_salt = [0u8; 32];
        hk_salt[..16].copy_from_slice(salt);
        hk_salt[16..].copy_from_slice(nonce);
        let mut info = Vec::with_capacity(RECORD_KEY_INFO.len() + 20);
        info.extend_from_slice(RECORD_KEY_INFO);
        info.extend_from_slice(&id.0);
        info.extend_from_slice(&next.to_be_bytes());
        let mut okm = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&hk_salt), key.as_bytes())
            .expand(&info, &mut okm)
            .expect("32 bytes is a valid HKDF-SHA-256 output length");
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&okm));
        okm.zeroize();
        AttemptCipher(cipher)
    }

    /// Seal `chunk` as record `index` into `out` (ciphertext, then the tag).
    pub(crate) fn seal(&self, index: u32, last: bool, chunk: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(chunk);
        let tag = self
            .0
            .encrypt_in_place_detached(&nonce(index, last), &[], &mut out[start..])
            .expect("a record is far below the ChaCha20-Poly1305 message limit");
        out.extend_from_slice(&tag);
    }

    /// Open record `index`. On any failure nothing of the plaintext is returned.
    pub(crate) fn open(
        &self,
        index: u32,
        last: bool,
        sealed: &[u8],
    ) -> Result<Vec<u8>, TransferError> {
        let split = sealed
            .len()
            .checked_sub(TAG_SIZE)
            .ok_or(TransferError::Record)?;
        let (ciphertext, tag) = sealed.split_at(split);
        let mut plain = ciphertext.to_vec();
        match self.0.decrypt_in_place_detached(
            &nonce(index, last),
            &[],
            &mut plain,
            Tag::from_slice(tag),
        ) {
            Ok(()) => Ok(plain),
            Err(_) => {
                plain.zeroize();
                Err(TransferError::Record)
            }
        }
    }
}

/// The STREAM nonce: seven zero bytes, the record index (big-endian) and the last-record
/// flag. The key is per attempt, so the prefix carries nothing.
fn nonce(index: u32, last: bool) -> Nonce {
    let mut n = [0u8; 12];
    n[7..11].copy_from_slice(&index.to_be_bytes());
    n[11] = u8::from(last);
    Nonce::from(n)
}

/// SHA-256 of a file read in pieces: what the sender puts in the offer.
#[derive(Clone, Default)]
pub struct FileHasher {
    hasher: Sha256,
    len: u64,
}

impl FileHasher {
    pub fn new() -> FileHasher {
        FileHasher::default()
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.len += bytes.len() as u64;
    }

    /// Bytes hashed so far.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_cut_into_records() {
        let c = CHUNK_SIZE as u64;
        assert_eq!(CHUNK_SIZE, 65_519);
        assert_eq!(record_count(0), 1);
        assert_eq!(record_len(0, 0), Some(0));
        assert_eq!(record_len(0, 1), None);
        assert_eq!(record_count(1), 1);
        assert_eq!(record_len(1, 0), Some(1));
        assert_eq!(record_count(c), 1);
        assert_eq!(record_len(c, 0), Some(CHUNK_SIZE));
        assert_eq!(record_count(c + 1), 2);
        assert_eq!(record_len(c + 1, 0), Some(CHUNK_SIZE));
        assert_eq!(record_len(c + 1, 1), Some(1));
        assert_eq!(record_len(c + 1, 2), None);
        assert_eq!(record_count(crate::MAX_FILE_SIZE), 16_781_570);
        assert_eq!(record_count(u64::MAX), u32::MAX);
    }

    #[test]
    fn a_record_opens_only_at_its_own_position_and_attempt() {
        let key = FileKey::from_bytes([1; 32]);
        let id = TransferId([2; 16]);
        let cipher = AttemptCipher::derive(&key, &id, 0, &[3; 16], &[4; 16]);
        let mut sealed = Vec::new();
        cipher.seal(5, false, b"hello", &mut sealed);
        assert_eq!(sealed.len(), 5 + TAG_SIZE);
        assert_eq!(cipher.open(5, false, &sealed).unwrap(), b"hello");
        // Another index, or the last-record flag.
        assert!(cipher.open(4, false, &sealed).is_err());
        assert!(cipher.open(5, true, &sealed).is_err());
        // Another salt, nonce, start, id or file key.
        for other in [
            AttemptCipher::derive(&key, &id, 0, &[9; 16], &[4; 16]),
            AttemptCipher::derive(&key, &id, 0, &[3; 16], &[9; 16]),
            AttemptCipher::derive(&key, &id, 1, &[3; 16], &[4; 16]),
            AttemptCipher::derive(&key, &TransferId([9; 16]), 0, &[3; 16], &[4; 16]),
            AttemptCipher::derive(&FileKey::from_bytes([9; 32]), &id, 0, &[3; 16], &[4; 16]),
        ] {
            assert!(other.open(5, false, &sealed).is_err());
        }
        // A flipped bit anywhere.
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(cipher.open(5, false, &bad).is_err());
        }
        assert!(cipher.open(5, false, &sealed[..TAG_SIZE - 1]).is_err());
    }
}
