//! The database key and where it is kept.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rand::RngCore as _;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::fsutil;

/// The key file's name in the data directory ([`FileKeyProvider`]).
pub const KEY_FILE: &str = "store.key";

/// The 256-bit database key. Zeroized on drop; `Debug` prints nothing of it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StoreKey([u8; 32]);

impl StoreKey {
    /// A fresh random key from the OS generator.
    pub fn generate() -> StoreKey {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let key = StoreKey(bytes);
        bytes.zeroize();
        key
    }

    pub fn from_bytes(bytes: [u8; 32]) -> StoreKey {
        StoreKey(bytes)
    }

    /// `None` unless `bytes` is exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<StoreKey> {
        let mut raw: [u8; 32] = bytes.try_into().ok()?;
        let key = StoreKey(raw);
        raw.zeroize();
        Some(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoreKey(..)")
    }
}

/// A key provider failed. The text never contains key material.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The provider cannot be reached (no keychain service, locked keychain, access denied).
    #[error("key storage is unavailable: {0}")]
    Unavailable(String),
    /// What the provider holds is not a 32-byte key.
    #[error("the stored key is malformed")]
    Malformed,
    #[error("{0}")]
    Other(String),
}

/// Where the database key lives.
///
/// `key_id` is the store's random id (from `store.json`): providers that hold keys for
/// several stores (the keychain) name the entry after it.
pub trait KeyProvider: Send + Sync + fmt::Debug {
    /// A stable name for this kind of provider, recorded in the store's metadata:
    /// `"keychain"`, `"file"`, `"memory"`.
    fn kind(&self) -> &'static str;
    /// The key, or `None` when the provider holds none under this id.
    fn load(&self, key_id: &str) -> Result<Option<StoreKey>, KeyError>;
    /// Keep the key (replacing any earlier one under this id).
    fn store(&self, key_id: &str, key: &StoreKey) -> Result<(), KeyError>;
    /// Forget the key. Deleting a key that is not there succeeds.
    fn delete(&self, key_id: &str) -> Result<(), KeyError>;
}

/// Keeps the key in memory: tests, and stores that should not outlive the process. Clones
/// share the key.
#[derive(Clone, Default)]
pub struct MemoryKeyProvider {
    key: Arc<Mutex<Option<StoreKey>>>,
}

impl MemoryKeyProvider {
    pub fn new() -> MemoryKeyProvider {
        MemoryKeyProvider::default()
    }

    /// A provider that already holds `key`.
    pub fn with_key(key: StoreKey) -> MemoryKeyProvider {
        MemoryKeyProvider {
            key: Arc::new(Mutex::new(Some(key))),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Option<StoreKey>> {
        self.key.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl fmt::Debug for MemoryKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryKeyProvider")
    }
}

impl KeyProvider for MemoryKeyProvider {
    fn kind(&self) -> &'static str {
        "memory"
    }

    fn load(&self, _key_id: &str) -> Result<Option<StoreKey>, KeyError> {
        Ok(self.slot().clone())
    }

    fn store(&self, _key_id: &str, key: &StoreKey) -> Result<(), KeyError> {
        *self.slot() = Some(key.clone());
        Ok(())
    }

    fn delete(&self, _key_id: &str) -> Result<(), KeyError> {
        *self.slot() = None;
        Ok(())
    }
}

/// Keeps the key in an owner-only file (`store.key`) in the data directory.
///
/// **Weaker than the keychain**: the key sits next to the database it opens, so this
/// protects nothing once the directory is copied or the disk is seized; it only keeps the
/// database opaque to tools that see the database file alone. It exists for machines
/// without a keychain service (headless Linux, CI, the interop bot). On Windows the file
/// gets no extra ACL beyond what the directory inherits.
#[derive(Clone)]
pub struct FileKeyProvider {
    path: PathBuf,
}

impl FileKeyProvider {
    /// The provider for the store in `data_dir`.
    pub fn in_dir(data_dir: &Path) -> FileKeyProvider {
        FileKeyProvider {
            path: data_dir.join(KEY_FILE),
        }
    }
}

impl fmt::Debug for FileKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileKeyProvider")
    }
}

impl KeyProvider for FileKeyProvider {
    fn kind(&self) -> &'static str {
        "file"
    }

    fn load(&self, _key_id: &str) -> Result<Option<StoreKey>, KeyError> {
        let text = match std::fs::read(&self.path) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let trimmed = text.trim_ascii();
        if trimmed.len() != 64 {
            return Err(KeyError::Malformed);
        }
        let mut raw = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(trimmed, raw.as_mut_slice()).map_err(|_| KeyError::Malformed)?;
        Ok(Some(StoreKey::from_bytes(*raw)))
    }

    fn store(&self, _key_id: &str, key: &StoreKey) -> Result<(), KeyError> {
        let mut text = Zeroizing::new(vec![0u8; 64]);
        hex::encode_to_slice(key.as_bytes(), text.as_mut_slice())
            .map_err(|_| KeyError::Malformed)?;
        if let Some(dir) = self.path.parent() {
            fsutil::create_private_dir(dir)?;
        }
        fsutil::write_private_atomic(&self.path, &text)?;
        Ok(())
    }

    fn delete(&self, _key_id: &str) -> Result<(), KeyError> {
        fsutil::secure_remove(&self.path)?;
        Ok(())
    }
}

/// The keychain service name entries are filed under.
#[cfg(feature = "keychain")]
pub const KEYCHAIN_SERVICE: &str = "social.parol.ParolNet";

/// Keeps the key in the OS keychain: the macOS login keychain, the Windows Credential
/// Manager, or the Secret Service (GNOME Keyring, KWallet) on Linux and the BSDs.
///
/// The entry is `service` / `store-key-<key id>`, so several data directories each have
/// their own. The first access can prompt the user (macOS asks before an app it has not
/// seen reads a keychain item; a locked Secret Service collection asks to be unlocked).
/// When there is no keychain service at all the provider reports
/// [`KeyError::Unavailable`]; nothing falls back to a file on its own.
#[cfg(feature = "keychain")]
#[derive(Clone)]
pub struct KeychainKeyProvider {
    service: String,
}

#[cfg(feature = "keychain")]
impl KeychainKeyProvider {
    /// The provider under [`KEYCHAIN_SERVICE`].
    pub fn new() -> KeychainKeyProvider {
        KeychainKeyProvider::with_service(KEYCHAIN_SERVICE)
    }

    /// The provider under another service name (a differently branded build).
    pub fn with_service(service: impl Into<String>) -> KeychainKeyProvider {
        KeychainKeyProvider {
            service: service.into(),
        }
    }

    fn entry(&self, key_id: &str) -> Result<keyring::Entry, KeyError> {
        keyring::Entry::new(&self.service, &format!("store-key-{key_id}")).map_err(keychain_error)
    }
}

#[cfg(feature = "keychain")]
impl Default for KeychainKeyProvider {
    fn default() -> KeychainKeyProvider {
        KeychainKeyProvider::new()
    }
}

#[cfg(feature = "keychain")]
impl fmt::Debug for KeychainKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeychainKeyProvider")
            .field("service", &self.service)
            .finish()
    }
}

#[cfg(feature = "keychain")]
impl KeyProvider for KeychainKeyProvider {
    fn kind(&self) -> &'static str {
        "keychain"
    }

    fn load(&self, key_id: &str) -> Result<Option<StoreKey>, KeyError> {
        match self.entry(key_id)?.get_secret() {
            Ok(secret) => {
                let secret = Zeroizing::new(secret);
                StoreKey::from_slice(&secret)
                    .map(Some)
                    .ok_or(KeyError::Malformed)
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(keychain_error(e)),
        }
    }

    fn store(&self, key_id: &str, key: &StoreKey) -> Result<(), KeyError> {
        self.entry(key_id)?
            .set_secret(key.as_bytes())
            .map_err(keychain_error)
    }

    fn delete(&self, key_id: &str) -> Result<(), KeyError> {
        match self.entry(key_id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(keychain_error(e)),
        }
    }
}

/// Map a keyring error without its payload: some variants carry the stored bytes.
#[cfg(feature = "keychain")]
fn keychain_error(e: keyring::Error) -> KeyError {
    use keyring::Error as E;
    match e {
        E::NoStorageAccess(inner) => KeyError::Unavailable(format!("no access: {inner}")),
        E::PlatformFailure(inner) => KeyError::Unavailable(inner.to_string()),
        E::NoDefaultStore => KeyError::Unavailable("this system has no keychain service".into()),
        E::BadEncoding(mut bytes) | E::BadDataFormat(mut bytes, _) => {
            bytes.zeroize();
            KeyError::Malformed
        }
        E::NoEntry => KeyError::Other("no such keychain entry".into()),
        E::TooLong(what, limit) => KeyError::Other(format!("{what} is longer than {limit}")),
        E::Invalid(what, why) => KeyError::Other(format!("invalid {what}: {why}")),
        E::Ambiguous(_) => KeyError::Other("more than one matching keychain entry".into()),
        E::BadStoreFormat(why) => KeyError::Other(format!("keychain store format: {why}")),
        E::NotSupportedByStore(why) => KeyError::Other(format!("not supported: {why}")),
        _ => KeyError::Other("keychain error".into()),
    }
}
