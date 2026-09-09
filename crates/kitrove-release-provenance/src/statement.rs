use serde::Deserialize;
use sigstore_types::{Bundle, SignatureContent};

use crate::{AttestationPolicy, ReleaseAttestationError};

const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";
const GITHUB_WORKFLOW_BUILD_TYPE: &str = "https://actions.github.io/buildtypes/workflow/v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InTotoStatement {
    #[serde(rename = "_type")]
    statement_type: String,
    subject: Vec<StatementSubject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: SlsaPredicate,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatementSubject {
    name: String,
    digest: StatementDigest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatementDigest {
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SlsaPredicate {
    build_definition: BuildDefinition,
    run_details: RunDetails,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BuildDefinition {
    build_type: String,
    external_parameters: ExternalParameters,
    internal_parameters: InternalParameters,
    resolved_dependencies: Vec<ResolvedDependency>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalParameters {
    workflow: WorkflowParameters,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowParameters {
    r#ref: String,
    repository: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InternalParameters {
    github: GithubParameters,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GithubParameters {
    event_name: String,
    repository_id: String,
    repository_owner_id: String,
    runner_environment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedDependency {
    uri: String,
    digest: GitCommitDigest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GitCommitDigest {
    git_commit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RunDetails {
    builder: Builder,
    metadata: RunMetadata,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Builder {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RunMetadata {
    invocation_id: String,
}

pub(super) fn validate(
    bundle: &Bundle,
    archive_name: &str,
    archive_sha256: [u8; 32],
    policy: &AttestationPolicy<'_>,
    certificate_run_invocation: &str,
) -> Result<(), ReleaseAttestationError> {
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return Err(ReleaseAttestationError::UnsupportedBundle);
    };
    if envelope.payload_type != IN_TOTO_PAYLOAD_TYPE {
        return Err(ReleaseAttestationError::InvalidStatement);
    }
    let statement: InTotoStatement = serde_json::from_slice(envelope.payload.as_bytes())
        .map_err(|_| ReleaseAttestationError::InvalidStatement)?;
    if statement.statement_type != IN_TOTO_STATEMENT_V1
        || statement.predicate_type != SLSA_PROVENANCE_V1
    {
        return Err(ReleaseAttestationError::InvalidStatement);
    }
    let [subject] = statement.subject.as_slice() else {
        return Err(ReleaseAttestationError::SubjectMismatch);
    };
    if subject.name != archive_name || subject.digest.sha256 != encode_lower_hex(&archive_sha256) {
        return Err(ReleaseAttestationError::SubjectMismatch);
    }
    validate_predicate(&statement.predicate, policy, certificate_run_invocation)
}

fn validate_predicate(
    predicate: &SlsaPredicate,
    policy: &AttestationPolicy<'_>,
    certificate_run_invocation: &str,
) -> Result<(), ReleaseAttestationError> {
    let definition = &predicate.build_definition;
    let workflow = &definition.external_parameters.workflow;
    let github = &definition.internal_parameters.github;
    let [dependency] = definition.resolved_dependencies.as_slice() else {
        return Err(ReleaseAttestationError::InvalidStatement);
    };
    let expected_dependency_uri = format!("git+{}@{}", policy.repository_uri, policy.source_ref);
    if definition.build_type != GITHUB_WORKFLOW_BUILD_TYPE
        || workflow.r#ref != policy.source_ref
        || workflow.repository != policy.repository_uri
        || workflow.path != policy.workflow_path
        || github.event_name != policy.build_trigger
        || github.repository_id != policy.repository_id
        || github.repository_owner_id != policy.owner_id
        || github.runner_environment != policy.runner_environment
        || dependency.uri != expected_dependency_uri
        || dependency.digest.git_commit != policy.source_commit
        || predicate.run_details.builder.id != policy.signer_identity
        || predicate.run_details.metadata.invocation_id != certificate_run_invocation
    {
        return Err(ReleaseAttestationError::InvalidStatement);
    }
    Ok(())
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}
