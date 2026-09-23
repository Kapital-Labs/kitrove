//! Fresh staging for already verified release artifacts, with native permissions.
use std::path::Path;

const NAME: &str = "verified-local-artifacts";

pub(crate) fn create(parent: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let parent = cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())
            .map_err(|error| format!("cannot open release staging parent: {error}"))?;
        kitrove_windows_security::create_private_directory(&parent, std::ffi::OsStr::new(NAME))
            .map(|_| ())
            .map_err(|error| format!("cannot create private release staging: {error:?}"))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(parent.join(NAME))
            .map_err(|error| format!("cannot create private release staging: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn staging_refuses_symlinks_without_touching_their_targets() {
        let root = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(target.path(), root.path().join(NAME)).unwrap();
        assert!(create(root.path()).is_err());
        assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
    }

    #[test]
    fn staging_is_private_writable_and_never_reuses_a_destination() {
        let root = tempfile::tempdir().unwrap();
        create(root.path()).unwrap();
        let directory = root.path().join(NAME);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        #[cfg(windows)]
        {
            let parent =
                cap_std::fs::Dir::open_ambient_dir(root.path(), cap_std::ambient_authority())
                    .unwrap();
            let private = kitrove_windows_security::open_private_directory(
                &parent,
                std::ffi::OsStr::new(NAME),
            )
            .unwrap();
            kitrove_windows_security::inspect_private_directory(&private).unwrap();
        }
        std::fs::write(directory.join("sentinel"), b"retained").unwrap();
        assert!(create(root.path()).is_err());
        assert_eq!(
            std::fs::read(directory.join("sentinel")).unwrap(),
            b"retained"
        );
        let file_root = tempfile::tempdir().unwrap();
        std::fs::write(file_root.path().join(NAME), b"file").unwrap();
        assert!(create(file_root.path()).is_err());
        assert_eq!(std::fs::read(file_root.path().join(NAME)).unwrap(), b"file");
    }
}
