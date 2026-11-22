//! Private files: keys, secrets and saved state. Everything secret is
//! owner-only; a secret file readable by others is refused, not used.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use nostr_sdk::prelude::{Keys, ToBech32};

/// Read a file that must be private to its owner; `None` if it does not
/// exist. Permissions are read from the open handle, so the file that is
/// checked is the file that is read.
pub fn read_private_bytes(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let shown = path.display();
    match fs::File::open(path) {
        Ok(mut file) => {
            let mode = file.metadata().map_err(|e| format!("{shown}: {e}"))?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(format!("{shown} is readable by other users; run: chmod 600 {shown}"));
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(|e| format!("{shown}: {e}"))?;
            Ok(Some(bytes))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{shown}: {e}")),
    }
}

/// The same for a text file.
pub fn read_private(path: &Path) -> Result<Option<String>, String> {
    match read_private_bytes(path)? {
        Some(bytes) => String::from_utf8(bytes).map(Some).map_err(|_| format!("{} is not text", path.display())),
        None => Ok(None),
    }
}

/// A secret that must exist, as text. A binary file (an LND macaroon) is
/// given as hex, the form its HTTP header takes.
pub fn read_secret_text(path: &Path) -> Result<String, String> {
    match read_private_bytes(path)? {
        Some(bytes) => match std::str::from_utf8(&bytes) {
            Ok(text) if text.trim().is_empty() => Err(format!("{} is empty", path.display())),
            Ok(text) => Ok(text.trim().to_string()),
            Err(_) => Ok(hex::encode(bytes)),
        },
        None => Err(format!("{} does not exist", path.display())),
    }
}

/// Write `content` to `path` atomically (temporary file, sync, rename), owner-only.
pub fn write_private(path: &Path, content: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let write = || -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    };
    write().map_err(|e| format!("{}: {e}", path.display()))
}

/// Load a Nostr identity from `path`, creating it on first start.
pub fn load_or_create_keys(path: &Path) -> Result<Keys, String> {
    if let Some(text) = read_private(path)? {
        return Keys::parse(text.trim()).map_err(|_| format!("{} does not hold a nostr secret key", path.display()));
    }
    let keys = Keys::generate();
    let nsec = keys.secret_key().to_bech32().expect("a valid secret key always encodes as bech32");
    write_private(path, &format!("{nsec}\n"))?;
    Ok(keys)
}

/// Create a directory if needed and make it private to the owner.
pub fn open_dir(dir: &Path) -> Result<(), String> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .and_then(|()| fs::set_permissions(dir, fs::Permissions::from_mode(0o700)))
        .map_err(|e| format!("{}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_created_private_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/node.key");
        open_dir(path.parent().unwrap()).unwrap();
        let a = load_or_create_keys(&path).unwrap();
        let b = load_or_create_keys(&path).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_create_keys(&path).unwrap_err().contains("chmod 600"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        write_private(&path, "not a key").unwrap();
        assert!(load_or_create_keys(&path).unwrap_err().contains("does not hold"));
    }

    #[test]
    fn secrets_must_exist_and_hold_something() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("macaroon");
        assert!(read_secret_text(&path).unwrap_err().contains("does not exist"));
        write_private(&path, "  \n").unwrap();
        assert!(read_secret_text(&path).unwrap_err().contains("is empty"));
        write_private(&path, " abc \n").unwrap();
        assert_eq!(read_secret_text(&path).unwrap(), "abc");
        fs::write(&path, [0x02, 0xff, 0x00]).unwrap();
        assert_eq!(read_secret_text(&path).unwrap(), "02ff00");
        assert!(read_private(&path).unwrap_err().contains("is not text"));
        // A directory cannot be read as a file.
        assert!(read_private(dir.path()).is_err());
        // Nor written in a missing directory, nor created under a file.
        assert!(write_private(&dir.path().join("nope/x"), "a").is_err());
        assert!(open_dir(&path.join("x")).is_err());
    }

    #[test]
    fn unreadable_files_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locked");
        write_private(&path, "x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        // Root can read anything; everyone else gets an error naming the file.
        if let Err(e) = read_private(&path) {
            assert!(e.contains("locked"));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
