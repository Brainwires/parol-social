use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AEAD encryption failed")]
    EncryptionFailed,

    #[error("AEAD decryption failed: invalid ciphertext or authentication tag")]
    DecryptionFailed,

    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    #[error("key derivation failed")]
    KdfFailed,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid pre-key bundle: {reason}")]
    InvalidPreKeyBundle { reason: String },

    #[error("X3DH key agreement failed: {reason}")]
    KeyAgreementFailed { reason: String },

    #[error("Double Ratchet error: {reason}")]
    RatchetError { reason: String },

    #[error("message from unknown ratchet chain")]
    UnknownChain,

    #[error("message key exhausted or already used")]
    MessageKeyExhausted,

    #[error("sender key error: {reason}")]
    SenderKeyError { reason: String },

    /// The Double Ratchet sending chain has produced its last message
    /// (PNP-002-MUST-045). Nothing was encrypted and the session is unchanged. The chain is
    /// replaced when a message with a new ratchet key arrives from the peer; until then the
    /// session cannot send, and a new handshake is the only other way on.
    #[error(
        "sending chain exhausted: {limit} messages sent without a new ratchet key from the peer"
    )]
    SendChainExhausted { limit: u32 },

    /// The sender key chain has produced its last message (PNP-009-MUST-078). Nothing was
    /// encrypted and the state is unchanged: rotate the sender key and distribute the new one.
    #[error("sender key chain exhausted after {limit} messages: rotate the sender key")]
    SenderKeyChainExhausted { limit: u32 },

    /// A counter received from a peer, or read from stored state, is past the limit its
    /// specification sets (PNP-002-MUST-046, PNP-009-MUST-079 / MUST-080). Nothing was changed.
    #[error("{counter} {value} is past the limit of {limit}")]
    CounterOutOfRange {
        counter: &'static str,
        value: u64,
        limit: u64,
    },

    #[error("not implemented: {feature}")]
    NotImplemented { feature: String },
}
