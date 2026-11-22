//! Passphrase bootstrap (PNP-003 §3.2, §5.2, §5.3): for when a QR code cannot be scanned.
//!
//! The issuer generates a passphrase ([`generate`]) and tells the other peer its
//! [`PassphrasePayload`] (identity key and passphrase) out of band: read aloud, or over a
//! channel both already trust. Nothing in this crate or its callers sends a passphrase or a
//! payload anywhere: the only things derived from it that leave the device are the
//! BootstrapHandshake proof and the `bs_hint`, both one-way functions of the Bootstrap Secret.
//!
//! The passphrase is stretched once ([`StretchedPassphrase::stretch`], Argon2id), which erases
//! it; the Bootstrap Secret is then derived for the pair of identity keys.

use crate::CoreError;
use parolnet_crypto::kdf::{argon2id, hkdf_sha256_fixed};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

/// The fewest words a passphrase may have (PNP-003-MUST-013, -MUST-041): 66 bits.
pub const MIN_WORDS: usize = 6;
/// The length of a generated passphrase unless asked otherwise (PNP-003-MUST-018): 88 bits.
pub const DEFAULT_WORDS: usize = 8;
/// The most words accepted (a bound on what is stretched, well beyond any real passphrase).
pub const MAX_WORDS: usize = 24;
/// Entropy of one word drawn uniformly from the 2048-word list.
pub const BITS_PER_WORD: u32 = 11;

/// Argon2id parameters of §5.2 step 3: `t=3, m=65536 KiB, p=4`, salt `"ParolNet"`.
pub const ARGON2_PASSES: u32 = 3;
pub const ARGON2_MEMORY_KIB: u32 = 65536;
pub const ARGON2_LANES: u32 = 4;
pub const ARGON2_SALT: &[u8] = b"ParolNet";
const HKDF_SALT: &[u8] = b"ParolNet_passphrase_v1";

/// The BIP-39 English wordlist: 2048 words, sorted.
pub fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| include_str!("bip39-english.txt").lines().collect())
}

fn is_word(word: &str) -> bool {
    wordlist().binary_search(&word).is_ok()
}

/// A freshly generated passphrase and what to tell the user about it.
pub struct GeneratedPassphrase {
    /// The words, separated by single blanks. Erased when dropped.
    pub phrase: Zeroizing<String>,
    /// How many words.
    pub words: usize,
    /// Its entropy in bits, to be shown to the user (PNP-003-MUST-019).
    pub entropy_bits: u32,
}

/// Generate a passphrase of the default length: 8 words drawn uniformly at random from the
/// BIP-39 English wordlist (PNP-003-MUST-017, -MUST-018).
pub fn generate() -> GeneratedPassphrase {
    generate_with(DEFAULT_WORDS, &mut rand::rngs::OsRng).expect("the default length is valid")
}

/// Generate a passphrase of `words` words (at least [`MIN_WORDS`]) with `rng`.
pub fn generate_with(
    words: usize,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<GeneratedPassphrase, CoreError> {
    use rand::Rng as _;
    if !(MIN_WORDS..=MAX_WORDS).contains(&words) {
        return Err(CoreError::BootstrapFailed(format!(
            "a passphrase has {MIN_WORDS} to {MAX_WORDS} words"
        )));
    }
    let list = wordlist();
    let mut phrase = Zeroizing::new(String::new());
    for i in 0..words {
        if i > 0 {
            phrase.push(' ');
        }
        // `gen_range` is uniform over the range (it rejects, it does not reduce modulo).
        phrase.push_str(list[rng.gen_range(0..list.len())]);
    }
    Ok(GeneratedPassphrase {
        phrase,
        words,
        entropy_bits: entropy_bits(words),
    })
}

/// Entropy in bits of a passphrase of `words` words drawn uniformly from the wordlist.
pub fn entropy_bits(words: usize) -> u32 {
    words as u32 * BITS_PER_WORD
}

/// The words of a passphrase as typed: case and spacing do not matter. Refuses fewer than
/// [`MIN_WORDS`] words (PNP-003-MUST-013, -MUST-041) and any word not on the wordlist.
fn normalize(phrase: &str) -> Result<Zeroizing<String>, CoreError> {
    let mut lower = Zeroizing::new(phrase.to_lowercase());
    let mut out = Zeroizing::new(String::with_capacity(lower.len()));
    let mut count = 0usize;
    for word in lower.split_whitespace() {
        if !is_word(word) {
            return Err(CoreError::BootstrapFailed(
                "the passphrase has a word that is not on the wordlist".into(),
            ));
        }
        if count > 0 {
            out.push(' ');
        }
        out.push_str(word);
        count += 1;
    }
    lower.zeroize();
    if count < MIN_WORDS {
        return Err(CoreError::BootstrapFailed(format!(
            "a passphrase needs at least {MIN_WORDS} words, this one has {count}"
        )));
    }
    if count > MAX_WORDS {
        return Err(CoreError::BootstrapFailed(format!(
            "a passphrase has at most {MAX_WORDS} words"
        )));
    }
    Ok(out)
}

/// How many words `phrase` has, if it is an acceptable passphrase.
pub fn validate(phrase: &str) -> Result<usize, CoreError> {
    Ok(normalize(phrase)?.split(' ').count())
}

/// A passphrase after Argon2id: what a peer keeps between learning the passphrase and
/// knowing the other peer's identity key. Erased when dropped.
pub struct StretchedPassphrase(Zeroizing<[u8; 32]>);

impl StretchedPassphrase {
    /// Stretch `phrase` (`Argon2id(passphrase, salt="ParolNet", t=3, m=65536, p=4)`) and
    /// erase it: the caller's buffer is overwritten with zeros and emptied before this
    /// returns, whether or not the passphrase was acceptable (PNP-003-MUST-016, -MUST-049).
    pub fn stretch(phrase: &mut String) -> Result<StretchedPassphrase, CoreError> {
        let normalized = normalize(phrase);
        phrase.zeroize();
        let normalized = normalized?;
        let out = argon2id(
            normalized.as_bytes(),
            ARGON2_SALT,
            ARGON2_MEMORY_KIB,
            ARGON2_PASSES,
            ARGON2_LANES,
            32,
        )
        .map_err(|e| CoreError::BootstrapFailed(format!("Argon2id: {e}")))?;
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&out);
        Ok(StretchedPassphrase(key))
    }

    /// The Bootstrap Secret for two identity keys (§5.2 step 3):
    /// `HKDF-SHA-256(salt="ParolNet_passphrase_v1", ikm=<stretched>, info=sorted_concat(IKs))`.
    pub fn bootstrap_secret(
        &self,
        our_ik: &[u8; 32],
        their_ik: &[u8; 32],
    ) -> Result<[u8; 32], CoreError> {
        let mut info = [0u8; 64];
        let (first, second) = if our_ik < their_ik {
            (our_ik, their_ik)
        } else {
            (their_ik, our_ik)
        };
        info[..32].copy_from_slice(first);
        info[32..].copy_from_slice(second);
        hkdf_sha256_fixed::<32>(HKDF_SALT, &self.0[..], &info)
            .map_err(|e| CoreError::BootstrapFailed(format!("HKDF: {e}")))
    }
}

/// Derive the Bootstrap Secret from a passphrase in one step, erasing the passphrase
/// (PNP-003-MUST-015, -MUST-016).
pub fn derive_bootstrap_secret(
    phrase: &mut String,
    our_ik: &[u8; 32],
    their_ik: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    StretchedPassphrase::stretch(phrase)?.bootstrap_secret(our_ik, their_ik)
}

/// What the issuer of a passphrase tells the other peer out of band (PNP-003 §3.2).
#[derive(Clone, Serialize, Deserialize)]
pub struct PassphrasePayload {
    /// Protocol version: 0x01 (PNP-003-MUST-003).
    pub v: u8,
    /// The issuer's Ed25519 identity public key.
    #[serde(with = "serde_bytes")]
    pub ik: Vec<u8>,
    /// The passphrase.
    pub phrase: String,
}

impl Drop for PassphrasePayload {
    fn drop(&mut self) {
        self.phrase.zeroize();
    }
}

impl PassphrasePayload {
    /// The payload for `identity_key` and `phrase` (which must be an acceptable passphrase).
    pub fn new(identity_key: &[u8; 32], phrase: &str) -> Result<PassphrasePayload, CoreError> {
        let normalized = normalize(phrase)?;
        Ok(PassphrasePayload {
            v: 1,
            ik: identity_key.to_vec(),
            phrase: normalized.as_str().to_owned(),
        })
    }

    /// CBOR bytes of the payload.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let mut buf = Zeroizing::new(Vec::new());
        ciborium::into_writer(self, &mut *buf)
            .map_err(|e| CoreError::BootstrapFailed(format!("CBOR encode: {e}")))?;
        Ok(buf)
    }

    /// Parse and validate CBOR bytes: version 0x01, a 32-byte key, an acceptable passphrase.
    pub fn decode(data: &[u8]) -> Result<PassphrasePayload, CoreError> {
        let mut payload: PassphrasePayload = ciborium::from_reader(data)
            .map_err(|e| CoreError::BootstrapFailed(format!("CBOR decode: {e}")))?;
        if payload.v != 1 {
            return Err(CoreError::BootstrapFailed(format!(
                "unsupported version: {}",
                payload.v
            )));
        }
        if payload.ik.len() != 32 {
            return Err(CoreError::BootstrapFailed(
                "identity key must be 32 bytes".into(),
            ));
        }
        let normalized = normalize(&payload.phrase)?;
        payload.phrase.zeroize();
        payload.phrase = normalized.as_str().to_owned();
        Ok(payload)
    }

    /// The payload as one line of text to pass on (base45 of the CBOR, as a QR payload).
    pub fn to_text(&self) -> Result<Zeroizing<String>, CoreError> {
        Ok(Zeroizing::new(super::base45::encode(&self.encode()?)))
    }

    /// Parse [`PassphrasePayload::to_text`]'s output.
    pub fn from_text(text: &str) -> Result<PassphrasePayload, CoreError> {
        let cbor = Zeroizing::new(super::decode_qr_text(text)?);
        PassphrasePayload::decode(&cbor)
    }

    /// The issuer's identity key.
    pub fn identity_key(&self) -> [u8; 32] {
        let mut ik = [0u8; 32];
        ik.copy_from_slice(&self.ik);
        ik
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_the_bip39_english_list() {
        use sha2::{Digest, Sha256};
        let list = wordlist();
        assert_eq!(list.len(), 2048);
        assert_eq!(list[0], "abandon");
        assert_eq!(list[2047], "zoo");
        assert!(
            list.windows(2).all(|w| w[0] < w[1]),
            "sorted, no duplicates"
        );
        // The published file (bitcoin/bips, bip-0039/english.txt).
        assert_eq!(
            hex::encode(Sha256::digest(include_bytes!("bip39-english.txt"))),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    #[test]
    fn normalizes_case_and_spacing() {
        let typed = "  Abandon ability\table  ABOUT above absent ";
        assert_eq!(
            normalize(typed).unwrap().as_str(),
            "abandon ability able about above absent"
        );
        assert_eq!(validate(typed).unwrap(), 6);
    }
}
