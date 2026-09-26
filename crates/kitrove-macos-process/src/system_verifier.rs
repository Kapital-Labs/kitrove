//! Retained, read-only selection of the one native system verifier.
use super::ProcessRefused;
use std::fs::{File, Metadata};
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use rustix::fs::{CWD, Mode, OFlags, openat};

const COMPONENTS: [&str; 4] = ["/", "usr", "bin", "codesign"];
const MAX_VERIFIER_BYTES: u64 = 16 * 1024 * 1024;

/// Retains the root-controlled verifier and every directory used to select it.
/// This is filesystem evidence, not an Apple signature or helper identity check.
/// Callers must revalidate around use. It does not defend against privileged OS
/// replacement and grants no installer readiness or process launch authority.
pub struct SystemVerifier {
    objects: Vec<RetainedObject>,
}

struct RetainedObject {
    file: File,
    identity: Identity,
}

#[derive(Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<&Metadata> for Identity {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.nlink(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

impl SystemVerifier {
    pub fn open() -> Result<Self, ProcessRefused> {
        let mut objects: Vec<RetainedObject> = Vec::with_capacity(COMPONENTS.len());
        for (index, component) in COMPONENTS.iter().enumerate() {
            let directory = index + 1 != COMPONENTS.len();
            let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
            let flags = if directory {
                flags | OFlags::DIRECTORY
            } else {
                flags
            };
            let fd = match objects.last() {
                Some(parent) => openat(&parent.file, *component, flags, Mode::empty()),
                None => openat(CWD, *component, flags, Mode::empty()),
            }
            .map_err(|_| ProcessRefused)?;
            let file = File::from(fd);
            let identity = inspect(&file, directory)?;
            objects.push(RetainedObject { file, identity });
        }
        Ok(Self { objects })
    }

    /// Fixed system path only; no ambient PATH lookup or caller override.
    pub fn path(&self) -> &'static Path {
        Path::new("/usr/bin/codesign")
    }

    pub fn revalidate(&self) -> Result<(), ProcessRefused> {
        let current = Self::open()?;
        for (index, (retained, selected)) in self.objects.iter().zip(&current.objects).enumerate() {
            if inspect(&retained.file, index + 1 != COMPONENTS.len())? != retained.identity
                || selected.identity != retained.identity
            {
                return Err(ProcessRefused);
            }
        }
        Ok(())
    }
}

fn inspect(file: &File, directory: bool) -> Result<Identity, ProcessRefused> {
    let metadata = file.metadata().map_err(|_| ProcessRefused)?;
    validate_metadata(&metadata, directory)?;
    // Use the reviewed handle-bound ACL reader and its canonical empty predicate.
    // A system verifier needs no user ACL grants, unlike user-state ancestry.
    if !calcifer_macos_acl::read_acl(file.as_fd())
        .map_err(|_| ProcessRefused)?
        .is_empty()
    {
        return Err(ProcessRefused);
    }
    let after = file.metadata().map_err(|_| ProcessRefused)?;
    let identity = Identity::from(&metadata);
    if Identity::from(&after) != identity {
        return Err(ProcessRefused);
    }
    Ok(identity)
}

fn validate_metadata(metadata: &Metadata, directory: bool) -> Result<(), ProcessRefused> {
    validate_shape(metadata.uid(), metadata.mode(), metadata.len(), directory)
}

fn validate_shape(uid: u32, mode: u32, size: u64, directory: bool) -> Result<(), ProcessRefused> {
    let expected = if directory {
        libc::S_IFDIR
    } else {
        libc::S_IFREG
    };
    if uid != 0
        || mode & u32::from(libc::S_IFMT) != u32::from(expected)
        || mode & 0o6022 != 0
        || mode & 0o111 == 0
        || (!directory && (size == 0 || size > MAX_VERIFIER_BYTES))
    {
        return Err(ProcessRefused);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_policy_rejects_user_ownership_writable_and_special_objects() {
        let regular = u32::from(libc::S_IFREG) | 0o755;
        assert!(validate_shape(0, regular, 1, false).is_ok());
        assert!(validate_shape(501, regular, 1, false).is_err());
        for mode in [
            regular | 0o022,
            regular | 0o4000,
            u32::from(libc::S_IFREG) | 0o644,
            u32::from(libc::S_IFLNK) | 0o755,
            u32::from(libc::S_IFIFO) | 0o755,
        ] {
            assert!(validate_shape(0, mode, 1, false).is_err());
        }
        assert!(validate_shape(0, regular, 0, false).is_err());
        assert!(validate_shape(0, regular, MAX_VERIFIER_BYTES + 1, false).is_err());
        assert!(validate_shape(0, u32::from(libc::S_IFDIR) | 0o1777, 1, true).is_err());
        assert!(validate_shape(0, u32::from(libc::S_IFDIR) | 0o755, 1, true).is_ok());
        assert!(validate_shape(0, regular, 1, true).is_err());
    }

    #[test]
    fn retains_and_revalidates_fixed_system_verifier_without_execution() {
        let verifier = SystemVerifier::open().unwrap();
        assert_eq!(verifier.path(), Path::new("/usr/bin/codesign"));
        assert_eq!(verifier.objects.len(), COMPONENTS.len());
        verifier.revalidate().unwrap();
    }

    #[test]
    fn revalidation_requires_every_retained_identity_to_match() {
        for index in 0..COMPONENTS.len() {
            let mut verifier = SystemVerifier::open().unwrap();
            // Alter only test-owned evidence, never a system file or its permissions.
            verifier.objects[index].identity.inode ^= 1;
            assert!(verifier.revalidate().is_err());
        }
    }
}
