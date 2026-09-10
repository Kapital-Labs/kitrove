#![forbid(unsafe_code)]
//! Helpers for building synthetic, credential-free harness fixtures.

mod harness;
pub mod owned_fixture;
mod policy_contract;
mod process_sentinel;

use std::path::{Path, PathBuf};

use kitrove_model::{EnvironmentManifest, LocalState, Lockfile};

pub use harness::{FilesystemSnapshot, FixtureBuilder, HarnessFixture, SnapshotEntry};
pub use policy_contract::{
    LocatorExpectation, LocatorProbe, NativeRootExpectation, PolicyContractCase,
    PolicyContractFailures, ReceiptAnchorExpectation, assert_policy_contract, test_engine,
};
pub use process_sentinel::{ProcessSentinel, SentinelEvent, sentinel_marker};

/// Creates a test directory beneath a trusted user-owned ancestor on Unix.
pub fn trusted_tempdir(prefix: &str) -> tempfile::TempDir {
    #[cfg(unix)]
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(std::env::var_os("HOME").expect("test user directory"))
        .expect("trusted test directory");
    #[cfg(windows)]
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("test directory");
    directory
}

/// Initializes an exact lifecycle-coordinated authority for integration tests.
pub fn initialize_empty_authority_fixture(
    environment_root: &Path,
    state_root: &Path,
    manifest: &EnvironmentManifest,
    state: &LocalState,
) -> Result<(), String> {
    kitrove_core::preflight_empty_authority_initialization(
        environment_root,
        state_root,
        manifest,
        state,
    )
    .map_err(|error| error.to_string())?;
    let (authority, guard) = kitrove_state_lifecycle::StateAuthority::initialize_absent(state_root)
        .map_err(|error| error.to_string())?;
    let access = authority
        .exclusive_access(&guard)
        .map_err(|error| error.to_string())?;
    kitrove_core::initialize_empty_authority(environment_root, &access, manifest, state)
        .map_err(|error| error.to_string())
}

/// Installs a deterministic extended ACL on a macOS test fixture.
#[cfg(target_os = "macos")]
pub fn install_macos_extended_acl(path: &Path) {
    let status = std::process::Command::new("/bin/chmod")
        .arg("+a")
        .arg("everyone allow add_file,delete_child")
        .arg(path)
        .status()
        .expect("macOS ACL fixture command must launch");
    assert!(status.success(), "macOS ACL fixture command must succeed");
}

/// A checked-in, credential-free Agent Skills fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentSkillFixture {
    /// A standards-only skill with a documentation reference.
    StandardBasic,
    /// A skill that preserves Claude Code native frontmatter fields.
    ClaudeExtended,
    /// A skill tree containing a harmless executable file.
    ScriptBearing,
}

impl AgentSkillFixture {
    /// Returns the checked-in fixture directory.
    #[must_use]
    pub fn directory(self) -> PathBuf {
        let name = match self {
            Self::StandardBasic => "standard-basic",
            Self::ClaudeExtended => "claude-extended",
            Self::ScriptBearing => "script-bearing",
        };

        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("agent-skills")
            .join(name)
    }
}

/// Loads the checked-in credential-free portable manifest fixture.
#[must_use]
pub fn portable_manifest() -> EnvironmentManifest {
    EnvironmentManifest::from_toml(include_str!("../fixtures/portable/kitrove.toml"))
        .expect("checked-in portable manifest fixture must stay valid")
}

/// Loads the checked-in deterministic lockfile fixture.
#[must_use]
pub fn portable_lockfile() -> Lockfile {
    Lockfile::from_json(include_str!("../fixtures/portable/kitrove.lock.json"))
        .expect("checked-in lockfile fixture must stay valid")
}

/// A synthetic harness home rooted inside a test-owned directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticHome {
    root: PathBuf,
}

impl SyntheticHome {
    /// Creates a handle for a test-owned root.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the fixture root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns a child path without touching the filesystem.
    #[must_use]
    pub fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.root.join(relative)
    }
}
