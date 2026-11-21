//! # parolnet-store
//!
//! Encrypted native persistence for ParolNet clients: one SQLite database, encrypted page by
//! page with SQLCipher, holding the identity secret, contacts, Double Ratchet sessions, chat
//! history, the sender-side queue and settings.
//!
//! - **The database key** is 256 random bits made on first run and held by a
//!   [`KeyProvider`]: the OS keychain (`KeychainKeyProvider`, cargo feature `keychain`), an
//!   owner-only key file next to the database ([`FileKeyProvider`], for machines without a
//!   keychain; it does **not** protect a copied or seized disk) or memory
//!   ([`MemoryKeyProvider`], tests). The provider a store was created with is recorded in
//!   `store.json`; opening it with another kind is refused
//!   ([`StoreError::KeyProviderMismatch`]), so a store never moves silently from the keychain
//!   to a file.
//! - **Schema**: a version table and forward migrations ([`Database::schema_version`]).
//! - **Writes** are incremental ([`Op`]) and transactional, in WAL mode with
//!   `synchronous=FULL`. [`Writer`] owns the database on a dedicated thread so an async
//!   caller never waits for a commit.
//! - **Legacy import**: a plaintext data directory from M1 slices 1-2 (`identity.key`,
//!   `state.json`) is imported on first open, verified, and the plaintext files are
//!   overwritten and removed.
//! - **Wipe**: [`Database::wipe`] / [`wipe`] delete the database files and remove the key
//!   from its provider ("delete all data on this device").
//!
//! ## What is and is not protected
//!
//! SQLCipher encrypts every page (AES-256-CBC with a per-page HMAC-SHA512), the WAL
//! included, so without the key the files reveal only their size. `store.json` is plaintext
//! and says only which key provider was used and the key's random id. With the keychain
//! provider the key is as safe as the user's login keychain; an attacker running as the
//! logged-in user can still ask the keychain for it.
//!
//! SQLCipher's cipher comes from a C library (CommonCrypto on Apple systems, a statically
//! linked OpenSSL libcrypto elsewhere). That is storage encryption on this device, not the
//! end-to-end layer: every E2EE primitive stays pure Rust in `parolnet-crypto`.
//!
//! Nothing in this crate logs key material, record contents or peer ids.

mod db;
mod fsutil;
mod key;
mod legacy;
mod model;
mod schema;
mod writer;

pub use db::{DB_FILE, Database, META_FILE, wipe};
pub use key::{FileKeyProvider, KEY_FILE, KeyError, KeyProvider, MemoryKeyProvider, StoreKey};
#[cfg(feature = "keychain")]
pub use key::{KEYCHAIN_SERVICE, KeychainKeyProvider};
pub use legacy::{LEGACY_IDENTITY_FILE, LEGACY_STATE_FILE};
pub use model::{
    ContactRecord, DeliveryState, Direction, MessageRecord, Op, QueuedRecord, SessionRecord,
};
pub use schema::SCHEMA_VERSION;
pub use writer::Writer;

/// Errors of the encrypted store. None of them carries key material or record contents.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("key provider: {0}")]
    Key(#[from] KeyError),
    /// The key the provider returned does not open this database (or the file is not a
    /// database at all).
    #[error("the storage key does not open this database")]
    WrongKey,
    /// The database exists but its key is gone from the provider.
    #[error("the storage key is missing from the {provider} key provider")]
    KeyMissing { provider: String },
    /// The store was created with one kind of key provider and opened with another.
    #[error(
        "this store keeps its key in the {created_with} key provider; refusing to open it with the {configured} provider"
    )]
    KeyProviderMismatch {
        created_with: String,
        configured: String,
    },
    /// `store.json` is missing or unreadable next to an existing database.
    #[error("store metadata: {0}")]
    Metadata(String),
    /// The database was written by a newer version of the app.
    #[error("database schema {found} is newer than this build supports ({supported})")]
    SchemaTooNew { found: u32, supported: u32 },
    /// Another process (or another instance in this one) has the store open.
    #[error("the store is in use by another instance")]
    Busy,
    /// An identity is already stored and a different one was offered.
    #[error("a different identity is already stored")]
    IdentityExists,
    /// A plaintext data directory could not be imported; its files were left in place.
    #[error("legacy data: {0}")]
    Legacy(String),
    #[error("corrupt record in {0}")]
    Corrupt(&'static str),
    /// The writer thread is gone.
    #[error("the store writer has stopped")]
    Stopped,
    /// An earlier write on the writer thread failed.
    #[error("an earlier write failed: {0}")]
    WriteFailed(String),
}
