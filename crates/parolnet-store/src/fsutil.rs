//! Small file helpers: owner-only atomic writes and best-effort secure removal.

use std::fs;
use std::io::{self, Seek as _, SeekFrom, Write as _};
use std::path::Path;

/// Create the directory (and parents) and restrict it to its owner on Unix.
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Write through a temporary file and rename, with owner-only permissions on Unix.
pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_parent(path);
    Ok(())
}

/// Restrict an existing file to its owner on Unix (the database files SQLite creates).
pub(crate) fn restrict_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Overwrite a file with zeros, sync, then unlink it. A missing file is not an error.
///
/// Best effort: on copy-on-write filesystems and flash storage the old blocks may survive
/// until the device reuses them. It still keeps the plaintext out of the directory, out of
/// backups made afterwards and away from simple undelete tools.
pub(crate) fn secure_remove(path: &Path) -> io::Result<()> {
    let mut file = match fs::OpenOptions::new().write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut left = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let zeros = [0u8; 4096];
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..n])?;
        left -= n as u64;
    }
    file.sync_all()?;
    drop(file);
    fs::remove_file(path)?;
    sync_parent(path);
    Ok(())
}

/// Remove a file; a missing file is not an error.
pub(crate) fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Make a rename / unlink durable (Unix; a no-op elsewhere).
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    if let Some(dir) = path.parent()
        && let Ok(d) = fs::File::open(dir)
    {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}
