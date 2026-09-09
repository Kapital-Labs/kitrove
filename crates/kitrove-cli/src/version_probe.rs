use kitrove_adapter_api::VerifiedVersionEvidence;
use kitrove_model::{ContentHash, HarnessId};
use kitrove_version_probe::{
    VerifiedOpenCodeV2Version, VerifiedPiVersion, VersionProbeKind, classify_version_probe_binary,
    probe_opencode_v2_version, probe_pi_version,
};
use serde_json::json;

use crate::args::{CliError, VersionProbeArgs};
use crate::portable::CompletedCommand;

pub(crate) fn run_version_probe(arguments: VersionProbeArgs) -> Result<CompletedCommand, CliError> {
    let result = probe_harness_version(&arguments.harness, &arguments.binary)?;
    let observed = result.evidence().observed().as_str();
    let policy_line = result.evidence().policy_line().as_str();
    let evidence = result.evidence().evidence().as_str();
    let output = if arguments.json {
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "harness": arguments.harness.as_str(),
            "observed": observed,
            "policy_line": policy_line,
            "evidence": evidence,
            "executable_hash": result.executable_hash().as_str(),
        }))
        .map(|text| format!("{text}\n"))
        .map_err(|_| {
            CliError::new(
                "version.output_failed",
                "the version probe result could not be rendered",
            )
        })?
    } else {
        format!(
            "harness version probe\nharness: {}\nobserved: {observed}\npolicy: {policy_line}\nevidence: {evidence}\nexecutable: {}\n",
            arguments.harness.as_str(),
            result.executable_hash()
        )
    };
    Ok(CompletedCommand { output, status: 0 })
}

pub(crate) fn probe_pi_version_cli(
    binary: &std::path::Path,
) -> Result<VerifiedPiVersion, CliError> {
    probe_pi_version(binary).map_err(|error| CliError::new(error.code(), error.message()))
}

#[derive(Debug, Default)]
pub(crate) struct MaterializationVersionProbes {
    pi: Option<VerifiedPiVersion>,
    opencode_v2: Option<VerifiedOpenCodeV2Version>,
}

impl MaterializationVersionProbes {
    pub(crate) fn acquire(
        binaries: &[std::path::PathBuf],
        needs_pi: bool,
        needs_opencode_v2: bool,
    ) -> Result<Self, CliError> {
        let selected = classify_materialization_binaries(binaries)?;
        reject_unused_probe(selected.pi, needs_pi)?;
        reject_unused_probe(selected.opencode_v2, needs_opencode_v2)?;
        require_probe(selected.pi, needs_pi)?;
        require_probe(selected.opencode_v2, needs_opencode_v2)?;

        Ok(Self {
            pi: selected.pi.map(probe_pi_version_cli).transpose()?,
            opencode_v2: selected
                .opencode_v2
                .map(probe_opencode_v2_version)
                .transpose()
                .map_err(probe_error)?,
        })
    }

    pub(crate) const fn pi(&self) -> Option<&VerifiedPiVersion> {
        self.pi.as_ref()
    }

    pub(crate) const fn opencode_v2(&self) -> Option<&VerifiedOpenCodeV2Version> {
        self.opencode_v2.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ClassifiedVersionBinaries<'a> {
    pi: Option<&'a std::path::Path>,
    opencode_v2: Option<&'a std::path::Path>,
}

fn classify_materialization_binaries(
    binaries: &[std::path::PathBuf],
) -> Result<ClassifiedVersionBinaries<'_>, CliError> {
    let mut selected = ClassifiedVersionBinaries::default();
    for binary in binaries {
        let slot = match classify_version_probe_binary(binary) {
            Some(VersionProbeKind::Pi) => &mut selected.pi,
            Some(VersionProbeKind::OpenCodeV2) => &mut selected.opencode_v2,
            _ => {
                return Err(CliError::new(
                    "version.probe_binary_name_invalid",
                    "the explicit version probe binary does not match a reviewed harness",
                ));
            }
        };
        if slot.replace(binary.as_path()).is_some() {
            return Err(CliError::new(
                "version.probe_duplicate",
                "only one explicit version probe binary may be supplied per harness",
            ));
        }
    }
    Ok(selected)
}

fn reject_unused_probe(binary: Option<&std::path::Path>, required: bool) -> Result<(), CliError> {
    if binary.is_some() && !required {
        return Err(CliError::new(
            "version.probe_unused",
            "--version-binary was supplied for a harness without a gated selected asset",
        ));
    }
    Ok(())
}

fn require_probe(binary: Option<&std::path::Path>, required: bool) -> Result<(), CliError> {
    if binary.is_none() && required {
        return Err(CliError::new(
            "apply.harness_version_unverified",
            "materialization requires exact verified harness version evidence",
        ));
    }
    Ok(())
}

fn probe_harness_version(
    harness: &HarnessId,
    binary: &std::path::Path,
) -> Result<VersionProbeResult, CliError> {
    match harness {
        HarnessId::Pi => probe_pi_version_cli(binary).map(VersionProbeResult::Pi),
        HarnessId::OpenCode => probe_opencode_v2_version(binary)
            .map(VersionProbeResult::OpenCodeV2)
            .map_err(probe_error),
        _ => Err(CliError::new(
            "version.probe_harness_unsupported",
            "the selected harness has no reviewed version probe",
        )),
    }
}

fn probe_error(error: kitrove_version_probe::ProbeError) -> CliError {
    CliError::new(error.code(), error.message())
}

#[derive(Debug)]
enum VersionProbeResult {
    Pi(VerifiedPiVersion),
    OpenCodeV2(VerifiedOpenCodeV2Version),
}

impl VersionProbeResult {
    fn evidence(&self) -> &VerifiedVersionEvidence {
        match self {
            Self::Pi(result) => result.evidence(),
            Self::OpenCodeV2(result) => result.evidence(),
        }
    }

    fn executable_hash(&self) -> &ContentHash {
        match self {
            Self::Pi(result) => result.executable_hash(),
            Self::OpenCodeV2(result) => result.executable_hash(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_reviewed_harnesses_have_probes() {
        let missing = std::path::Path::new("/definitely/missing/pi");
        assert_ne!(
            probe_harness_version(&HarnessId::Pi, missing)
                .unwrap_err()
                .code,
            "version.probe_harness_unsupported"
        );
        let missing = std::path::Path::new("/definitely/missing/opencode2");
        assert_ne!(
            probe_harness_version(&HarnessId::OpenCode, missing)
                .unwrap_err()
                .code,
            "version.probe_harness_unsupported"
        );
        assert_eq!(
            probe_harness_version(&HarnessId::Claude, missing)
                .unwrap_err()
                .code,
            "version.probe_harness_unsupported"
        );
    }

    #[test]
    fn materialization_probe_classification_rejects_duplicates_and_unused_paths() {
        let pi = if cfg!(windows) {
            std::path::PathBuf::from(r"C:\tools\pi.exe")
        } else {
            std::path::PathBuf::from("/tools/pi")
        };
        assert_eq!(
            MaterializationVersionProbes::acquire(&[pi.clone(), pi], true, false)
                .unwrap_err()
                .code,
            "version.probe_duplicate"
        );
        assert_eq!(
            MaterializationVersionProbes::acquire(
                &[std::path::PathBuf::from(if cfg!(windows) {
                    r"C:\tools\opencode2.exe"
                } else {
                    "/tools/opencode2"
                })],
                false,
                false,
            )
            .unwrap_err()
            .code,
            "version.probe_unused"
        );
        assert_eq!(
            MaterializationVersionProbes::acquire(&[], false, true)
                .unwrap_err()
                .code,
            "apply.harness_version_unverified"
        );
    }

    #[cfg(unix)]
    #[test]
    fn materialization_can_acquire_pi_and_opencode_evidence_together() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let pi = root.path().join("pi");
        let opencode = root.path().join("opencode2");
        fs::write(&pi, "#!/bin/sh\nprintf '0.83.0\\n'\n").unwrap();
        fs::write(
            &opencode,
            "#!/bin/sh\nprintf 'opencode2 v0.0.0-beta-18387\\n'\n",
        )
        .unwrap();
        fs::set_permissions(&pi, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&opencode, fs::Permissions::from_mode(0o700)).unwrap();

        let probes = MaterializationVersionProbes::acquire(&[pi, opencode], true, true).unwrap();
        assert_eq!(
            probes.pi().unwrap().evidence().policy_line().as_str(),
            "pi_latest"
        );
        assert_eq!(
            probes
                .opencode_v2()
                .unwrap()
                .evidence()
                .policy_line()
                .as_str(),
            "open_code_v2"
        );
    }
}
