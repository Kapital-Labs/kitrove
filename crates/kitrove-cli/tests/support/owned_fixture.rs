//! Managed fixture files must have the same owner as production-created authority.

use std::io::Write as _;
use std::path::Path;

pub(crate) fn create(path: &Path, bytes: &[u8]) {
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
