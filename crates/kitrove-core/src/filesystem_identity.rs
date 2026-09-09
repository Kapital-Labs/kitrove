use cap_fs_ext::MetadataExt;

/// Identity available from the shared metadata API.
///
/// This is lossless on Unix. It is suitable only for transient comparisons on Windows because the
/// shared inode field cannot represent ReFS's complete 128-bit file identifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct MetadataIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

impl MetadataIdentity {
    pub(crate) fn from_metadata(metadata: &impl MetadataExt) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}
