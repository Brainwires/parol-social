//! Persistence for the Privacy Pass VOPRF authority keys.
//!
//! Mirrors [`crate::identity`]: load-or-init from a mode-0600 file under
//! `/data`, atomic write via tmp+rename, parent directory locked down to
//! 0700. The file stores up to two epoch keys (`current`, `prior`) as CBOR
//! — the same on-wire format used by the Privacy Pass issuance endpoint for
//! its own scalars, so the format is familiar and unambiguous.
//!
//! Why this exists: before persistence, a mid-epoch restart of the relay
//! generated a fresh VOPRF secret under the same (wall-clock-derived)
//! epoch_id. Clients' in-pool tokens looked valid but the new authority
//! silently rejected them per PNP-001-MUST-050. Persisting the key lets the
//! relay resume issuance under the same secret without any client-visible
//! protocol change; epoch rotation at boundaries (MUST-051) still fires.

use parolnet_relay::tokens::PersistedEpochKey;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Default on-disk location; matches the `VOLUME /data` directive in the
/// production Dockerfile and sits alongside `relay.key`.
pub const DEFAULT_AUTHORITY_KEY_FILE: &str = "/data/relay-authority.cbor";

/// Env var pointing at the persisted authority-key file.
pub const AUTHORITY_KEY_FILE_ENV: &str = "RELAY_AUTHORITY_KEY_FILE";

/// Tells callers which path was taken, for logging parity with `identity.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityKeySource {
    /// No existing file: caller will generate + persist via the `on_rotate` hook.
    FreshGenerated,
    /// Loaded from an existing file.
    ExistingFile,
}

/// Resolve the authority-key file path from env (fallback to the default).
pub fn key_file_path() -> PathBuf {
    std::env::var(AUTHORITY_KEY_FILE_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_AUTHORITY_KEY_FILE))
}

/// Load the persisted authority-key list if the file exists. Returns an
/// empty vec when the file is absent — callers pair that with
/// `TokenAuthority::from_persisted`, which falls back to `::new`.
///
/// Fatal errors on malformed CBOR or unreadable file, mirroring
/// `identity::load_or_generate_relay_identity`'s strictness.
pub fn load_or_empty(path: &Path) -> io::Result<(Vec<PersistedEpochKey>, AuthorityKeySource)> {
    if !path.exists() {
        return Ok((Vec::new(), AuthorityKeySource::FreshGenerated));
    }
    let bytes = fs::read(path)?;
    let keys: Vec<PersistedEpochKey> = ciborium::from_reader(bytes.as_slice()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed authority key file {}: {e}", path.display(),),
        )
    })?;
    Ok((keys, AuthorityKeySource::ExistingFile))
}

/// Atomically replace the authority-key file with a fresh snapshot. Creates
/// parent directories with mode 0700 if missing; the file itself is mode 0600.
///
/// Write-to-tmp-then-rename keeps the rotation hook safe under crashes: if
/// the process dies between serialize and fsync, the old file is still
/// readable — the worst case is that we start up with a one-epoch-stale
/// key set, which `from_persisted` handles via its rotate-on-load path.
pub fn persist(path: &Path, keys: &[PersistedEpochKey]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)?;
            set_dir_mode_0700(parent)?;
        }
    }

    let mut buf = Vec::with_capacity(128);
    ciborium::into_writer(&keys, &mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode keys: {e}")))?;

    let tmp_path = match path.file_name() {
        Some(name) => {
            let mut tmp_name = name.to_os_string();
            tmp_name.push(".tmp");
            path.with_file_name(tmp_name)
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "key file has no name",
            ));
        }
    };

    // Clear any stale tmp file from a previous crashed write.
    if tmp_path.exists() {
        fs::remove_file(&tmp_path)?;
    }

    write_tmp_0600(&tmp_path, &buf)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn write_tmp_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
    }
}

#[cfg(unix)]
fn set_dir_mode_0700(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_path: &Path) -> io::Result<()> {
    Ok(())
}
