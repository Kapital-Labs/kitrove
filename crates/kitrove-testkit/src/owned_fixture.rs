//! Managed fixture files must have the same owner as production-created authority.

use std::io::Write as _;
use std::path::Path;

/// Creates a new fixture file with the current user's ownership and durable contents.
pub fn create(path: &Path, bytes: &[u8]) {
    #[cfg(unix)]
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .unwrap();
    #[cfg(windows)]
    let mut file = {
        // Elevated CI otherwise assigns Administrators ownership, unlike production.
        let parent = cap_std::fs::Dir::open_ambient_dir(
            path.parent().unwrap(),
            cap_std::ambient_authority(),
        )
        .unwrap();
        kitrove_windows_security::create_owned_file(&parent, path.file_name().unwrap()).unwrap()
    };
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[cfg(test)]
mod tests {
    #[test]
    fn creates_contents_and_refuses_to_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority");
        super::create(&path, b"original");
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        assert!(std::panic::catch_unwind(|| super::create(&path, b"replacement")).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
    }
}
