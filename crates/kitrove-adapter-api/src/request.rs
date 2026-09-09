use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::path::{Path, PathBuf};

use kitrove_agent_skills::CaptureLimits;
use kitrove_model::{HarnessId, HarnessScope};
use serde::{Deserialize, Serialize};

use crate::{EvidenceRef, NativeRootKey, VerifiedVersionEvidence};

/// User/project scope selection for one scan request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSelection {
    User,
    Project,
    All,
}

/// Validated repository boundary used by project-root policies.
#[derive(Clone, Eq, PartialEq)]
pub enum ProjectBoundary {
    Repository {
        root: PathBuf,
    },
    NoRepository,
    /// Repository discovery stopped at an unsafe marker.
    ///
    /// Consumers may inspect the working directory, but must not infer authority
    /// from or search through any shared ancestor.
    UnsafeStop,
}

impl Debug for ProjectBoundary {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Repository { .. } => formatter.write_str("Repository { root: <redacted> }"),
            Self::NoRepository => formatter.write_str("NoRepository"),
            Self::UnsafeStop => formatter.write_str("UnsafeStop"),
        }
    }
}

/// A caller-selected local root with no policy-owned provenance.
#[derive(Clone, Eq, PartialEq)]
pub struct ExplicitRoot {
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub path: PathBuf,
}

impl Debug for ExplicitRoot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExplicitRoot")
            .field("harness", &self.harness)
            .field("scope", &self.scope)
            .field("path", &RedactedPath)
            .finish()
    }
}

impl ExplicitRoot {
    #[must_use]
    pub fn new(harness: HarnessId, scope: HarnessScope, path: PathBuf) -> Self {
        Self {
            harness,
            scope,
            path,
        }
    }
}

/// A caller-supplied path selecting a closed native-root descriptor.
#[derive(Clone, Eq, PartialEq)]
pub struct SuppliedNativeRoot {
    harness: HarnessId,
    scope: HarnessScope,
    source_key: NativeRootKey,
    path: PathBuf,
}

impl Debug for SuppliedNativeRoot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SuppliedNativeRoot")
            .field("harness", &self.harness)
            .field("scope", &self.scope)
            .field("source_key", &self.source_key)
            .field("path", &RedactedPath)
            .finish()
    }
}

impl SuppliedNativeRoot {
    #[must_use]
    pub fn new(
        harness: HarnessId,
        scope: HarnessScope,
        source_key: NativeRootKey,
        path: PathBuf,
    ) -> Self {
        Self {
            harness,
            scope,
            source_key,
            path,
        }
    }

    #[must_use]
    pub fn harness(&self) -> &HarnessId {
        &self.harness
    }

    #[must_use]
    pub const fn scope(&self) -> HarnessScope {
        self.scope
    }

    #[must_use]
    pub fn source_key(&self) -> &NativeRootKey {
        &self.source_key
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Local key for a transient project-trust observation.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProjectTrustKey {
    pub harness: HarnessId,
    pub project_anchor: PathBuf,
}

impl Debug for ProjectTrustKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectTrustKey")
            .field("harness", &self.harness)
            .field("project_anchor", &RedactedPath)
            .finish()
    }
}

/// Typed local evidence about whether a harness trusts one project boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectTrustObservation {
    Trusted { evidence: EvidenceRef },
    Declined { evidence: EvidenceRef },
    Unknown,
}

/// Bounded, caller-owned environment manifest input.
#[derive(Clone, Eq, PartialEq)]
pub struct EnvironmentInput<'a> {
    pub source_path: PathBuf,
    pub toml_bytes: &'a [u8],
}

impl Debug for EnvironmentInput<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentInput")
            .field("source_path", &RedactedPath)
            .field("toml_bytes", &self.toml_bytes.len())
            .finish()
    }
}

/// Bounded, caller-owned local-state input or a redacted unsafe-read outcome.
#[derive(Clone, Eq, PartialEq)]
pub enum LocalStateInput<'a> {
    /// Bytes captured from a bounded, no-follow regular-file read.
    Bytes {
        source_path: PathBuf,
        json_bytes: &'a [u8],
    },
    /// A local-state path existed or was expected but could not be read safely.
    ///
    /// The authored path is deliberately omitted so diagnostics cannot disclose it.
    Unsafe,
}

impl Debug for LocalStateInput<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes { json_bytes, .. } => formatter
                .debug_struct("Bytes")
                .field("source_path", &RedactedPath)
                .field("json_bytes", &json_bytes.len())
                .finish(),
            Self::Unsafe => formatter.write_str("Unsafe"),
        }
    }
}

/// Request-wide discovery, reporting, and capture limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanLimits {
    pub max_input_bytes: u64,
    pub max_roots: usize,
    pub max_discovery_entries: usize,
    pub max_candidates: usize,
    pub max_discovery_depth: usize,
    pub max_receipts: usize,
    pub max_findings: usize,
    pub max_report_entries: usize,
    pub max_capture_files: usize,
    pub max_capture_bytes: u64,
    pub capture: CaptureLimits,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 32 * 1024 * 1024,
            max_roots: 256,
            max_discovery_entries: 65_536,
            max_candidates: 4_096,
            max_discovery_depth: 64,
            max_receipts: 4_096,
            max_findings: 32_768,
            max_report_entries: 8_192,
            max_capture_files: 16_384,
            max_capture_bytes: 256 * 1024 * 1024,
            capture: CaptureLimits::default(),
        }
    }
}

/// Complete read-only scan request.
#[derive(Clone, Eq, PartialEq)]
pub struct ScanRequest<'a> {
    /// Available user home. Absence must remain distinct from the working directory.
    pub home: Option<PathBuf>,
    pub working_directory: PathBuf,
    pub project_boundary: ProjectBoundary,
    pub harnesses: BTreeSet<HarnessId>,
    pub scopes: ScopeSelection,
    pub explicit_roots: Vec<ExplicitRoot>,
    pub supplied_native_roots: Vec<SuppliedNativeRoot>,
    pub versions: BTreeMap<HarnessId, VerifiedVersionEvidence>,
    pub project_trust: BTreeMap<ProjectTrustKey, ProjectTrustObservation>,
    pub environment: Option<EnvironmentInput<'a>>,
    pub local_state: Option<LocalStateInput<'a>>,
    pub limits: ScanLimits,
}

impl Debug for ScanRequest<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScanRequest")
            .field("home", &self.home.as_ref().map(|_| RedactedPath))
            .field("working_directory", &RedactedPath)
            .field("project_boundary", &self.project_boundary)
            .field("harnesses", &self.harnesses)
            .field("scopes", &self.scopes)
            .field("explicit_roots", &self.explicit_roots.len())
            .field("supplied_native_roots", &self.supplied_native_roots.len())
            .field("versions", &self.versions.keys().collect::<Vec<_>>())
            .field("project_trust", &self.project_trust.len())
            .field("environment", &self.environment)
            .field("local_state", &self.local_state)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Borrowed request context supplied to one harness policy.
#[derive(Clone, Copy)]
pub struct RootContext<'a> {
    /// Available user home. Policies must suppress implicit home-derived roots when absent.
    pub home: Option<&'a Path>,
    pub working_directory: &'a Path,
    pub project_boundary: &'a ProjectBoundary,
    pub scopes: ScopeSelection,
    pub explicit_roots: &'a [ExplicitRoot],
    pub supplied_native_roots: &'a [SuppliedNativeRoot],
    pub project_trust: &'a BTreeMap<ProjectTrustKey, ProjectTrustObservation>,
    pub limits: &'a ScanLimits,
}

impl Debug for RootContext<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootContext")
            .field("home", &self.home.map(|_| RedactedPath))
            .field("working_directory", &RedactedPath)
            .field("project_boundary", &self.project_boundary)
            .field("scopes", &self.scopes)
            .field("explicit_roots", &self.explicit_roots.len())
            .field("supplied_native_roots", &self.supplied_native_roots.len())
            .field("project_trust", &self.project_trust.len())
            .field("limits", &self.limits)
            .finish()
    }
}

struct RedactedPath;

impl Debug for RedactedPath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}
