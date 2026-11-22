use thiserror::Error;

#[derive(Debug, Error)]
pub enum MeshError {
    #[error("peer discovery failed: {0}")]
    DiscoveryFailed(String),

    #[error("gossip validation failed: {0}")]
    ValidationFailed(String),

    #[error("store-and-forward error: {0}")]
    StorageError(String),

    #[error("sync error: {0}")]
    SyncError(String),

    #[error("peer banned: score below threshold")]
    PeerBanned,

    #[error("proof-of-work insufficient")]
    InsufficientPoW,

    #[error("message expired")]
    MessageExpired,

    #[error("TTL exhausted")]
    TtlExhausted,

    #[error("peer connection limit reached")]
    PeerLimitReached,

    #[error("unsupported gossip version")]
    UnsupportedVersion,

    #[error("gossip signature invalid")]
    InvalidSignature,

    #[error("gossip payload too large")]
    PayloadTooLarge,

    #[error("gossip timestamp too far in the future")]
    FutureTimestamp,
}
