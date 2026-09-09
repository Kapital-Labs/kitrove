#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

mod release_archive;

const REVIEWED_CARGO_LOCK_BLAKE3: &str =
    "7333ae2ee43a577234785bd8afdc36fb0d1a51784f382da2bdff7e1e1c749b92";
const REVIEWED_SIGSTORE_REKOR_TREE_BLAKE3: &str =
    "898ca8f9c61bd79c3ef16bcc22650249eb4f32872540d281660f07b1c828c355";
const REVIEWED_SIGSTORE_TSA_TREE_BLAKE3: &str =
    "c48b716039e6942cf81eba8cf3558d7fe6d08facf5353ca5de99b03072cfc8db";
const REVIEWED_RELEASE_WORKFLOW_BLAKE3: &str =
    "9c0336026d3fa747e1f58f19b49f3e6f42602e8c9a8ba652efe1887aaf8b49db";
const REVIEWED_DIST_CONFIG_BLAKE3: &str =
    "f8abff8da26c1cf018af5379c6dc49282879dcd72d3655d1d183b9ee050bb216";
const REVIEWED_RELEASE_POLICY_BLAKE3: &str =
    "80e65cadb0b1c57dca2a791e0fe145571b22254e7c56c0b195d03b8841b670cd";
const REVIEWED_APPLICATION_COMPATIBILITY_BLAKE3: &str =
    "9e27d66b38ee4555c61480132e7fd3cc28ce472af7c34fdb92cb559a2528824a";
const RELEASE_ACTION_PINS: [(&str, &str); 4] = [
    ("actions/attest", "1e69f48acb82d1966a394da916b4c1698aa569d6"),
    (
        "actions/checkout",
        "d23441a48e516b6c34aea4fa41551a30e30af803",
    ),
    (
        "actions/download-artifact",
        "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    ),
    (
        "actions/upload-artifact",
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    ),
];

fn main() -> ExitCode {
    let command = env::args().nth(1).unwrap_or_else(|| "help".to_owned());
    let root = repository_root();

    let result = match command.as_str() {
        "ci" => run_ci(&root),
        "governance" => check_governance(&root),
        "licenses" => check_dependency_licenses(&root),
        "repository" => check_repository(&root),
        "prepare-application-release" => release_archive::prepare(env::args_os().skip(2).collect()),
        "prepare-platform-release" => {
            release_archive::prepare_platform_signed(env::args_os().skip(2).collect())
        }
        "verify-application-release" => release_archive::verify(env::args_os().skip(2).collect()),
        "verify-application-release-bundle" => {
            release_archive::verify_bundle(env::args_os().skip(2).collect())
        }
        "harden-powershell-installer" => {
            release_archive::harden_powershell(env::args_os().skip(2).collect())
        }
        "all" => {
            eprintln!("note: `cargo xtask all` is retained as an alias for `cargo xtask ci`");
            run_ci(&root)
        }
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(format!(
            "unknown xtask command {other:?}\n\nAvailable commands:\n  ci\n  governance\n  licenses\n  repository\n  prepare-platform-release <archive> <target> <tag> <compatibility-file> <dist-manifest>\n  prepare-application-release <archive> <target> <tag> <compatibility-file> <dist-manifest>\n  verify-application-release <archive> <target> <tag>\n  verify-application-release-bundle <archive> <target> <tag> <dist-manifest>\n  harden-powershell-installer <installer> <archive> <target>\n  help"
        )),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask failed: {message}");
            ExitCode::FAILURE
        }
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live directly under the repository root")
        .to_path_buf()
}

fn run_ci(root: &Path) -> Result<(), String> {
    run_cargo(root, "formatting", &["fmt", "--all", "--check"])?;
    run_cargo(
        root,
        "Clippy",
        &[
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run_cargo(
        root,
        "tests",
        &["test", "--locked", "--workspace", "--all-features"],
    )?;
    run_release_archive_tests(root)?;

    println!("==> Checking governance");
    check_governance(root)?;

    println!("==> Checking dependency licenses");
    check_dependency_licenses(root)?;

    println!("==> Checking repository structure and hygiene");
    check_repository(root)?;

    println!("all CI checks passed");
    Ok(())
}

fn run_release_archive_tests(root: &Path) -> Result<(), String> {
    let python = find_python()?;
    let rendered = "python -m unittest discover -s scripts -p test_*.py";
    println!("==> Running release archive security tests: {rendered}");
    let status = Command::new(python)
        .args([
            "-m",
            "unittest",
            "discover",
            "-s",
            "scripts",
            "-p",
            "test_*.py",
        ])
        .current_dir(root)
        .status()
        .map_err(|error| format!("cannot run {rendered}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{rendered} failed with status {status}"))
    }
}

fn find_python() -> Result<OsString, String> {
    if let Some(configured) = env::var_os("PYTHON") {
        return Ok(configured);
    }
    for candidate in ["python3", "python"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return Ok(OsString::from(candidate));
        }
    }
    Err("Python 3 is required for release archive security tests".to_owned())
}

fn run_cargo(root: &Path, label: &str, args: &[&str]) -> Result<(), String> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let rendered = format!("cargo {}", args.join(" "));

    println!("==> Running {label}: {rendered}");

    let status = Command::new(cargo)
        .args(args)
        .current_dir(root)
        .status()
        .map_err(|error| format!("cannot run {rendered}: {error}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("{rendered} failed with status {status}"))
    }
}

fn check_governance(root: &Path) -> Result<(), String> {
    let public_required = [
        ".editorconfig",
        ".gitattributes",
        ".gitignore",
        "README.md",
        "LICENSE.md",
        "LICENSE-APACHE",
        "LICENSE-MIT",
        "THIRD_PARTY_NOTICES.md",
        "NORTH_STAR.md",
        "DEVELOPMENT_RULES.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "docs/01-PRODUCT-SPEC.md",
        "docs/02-ARCHITECTURE.md",
        "docs/04-THREAT-MODEL.md",
        "docs/ADAPTER_GUIDE.md",
        "docs/DEPENDENCY_LICENSE_POLICY.md",
        "docs/REVIEW_PROCESS.md",
        "docs/architecture/INVARIANTS.md",
        "docs/adr/README.md",
        ".github/pull_request_template.md",
        ".github/workflows/release.yml",
        "dist-workspace.toml",
        "docs/RELEASES.md",
        "release/application-compatibility.json",
        "release/kitrove-release.json",
    ];

    for relative in public_required {
        require_file(root, relative)?;
    }

    let private_required = [
        "WHY_KITROVE.md",
        "AGENTS.md",
        "CLAUDE.md",
        "docs/COMPETITIVE_POSITIONING.md",
        "docs/DEVELOPMENT_CONTEXT.md",
        "docs/DECISION_LOG.md",
    ];
    let private_count = private_required
        .iter()
        .filter(|relative| root.join(relative).is_file())
        .count();
    let private_context = private_context_present(private_count, private_required.len())?;

    let north_star = read(root, "NORTH_STAR.md")?;
    for number in 1..=10 {
        require_token(&north_star, &format!("NS-{number:02}"), "NORTH_STAR.md")?;
    }

    let invariants = read(root, "docs/architecture/INVARIANTS.md")?;
    for number in 1..=12 {
        require_token(
            &invariants,
            &format!("INV-{number:02}"),
            "docs/architecture/INVARIANTS.md",
        )?;
    }

    let adr_index = read(root, "docs/adr/README.md")?;
    for number in 1..=10 {
        require_token(&adr_index, &format!("{number:04}"), "docs/adr/README.md")?;
    }

    if private_context {
        let agent_instructions = read(root, "AGENTS.md")?;
        for token in [
            "NORTH_STAR.md",
            "NS-*",
            "round-trip",
            "silent loss",
            "DEVELOPMENT_CONTEXT.md",
        ] {
            require_token(&agent_instructions, token, "AGENTS.md")?;
        }
    }

    check_compiled_tier_one_sources(root)?;
    check_git_dependency_boundary(root)?;
    check_release_configuration(root)?;

    println!("governance checks passed");
    Ok(())
}

fn check_release_configuration(root: &Path) -> Result<(), String> {
    let policy = read(root, "release/release-policy.json")?;
    let observed_policy_digest = blake3::hash(policy.as_bytes()).to_hex().to_string();
    if observed_policy_digest != REVIEWED_RELEASE_POLICY_BLAKE3 {
        return Err(format!(
            "release policy differs from the exact reviewed catalog (observed {observed_policy_digest})"
        ));
    }
    let compatibility = read(root, "release/application-compatibility.json")?;
    let observed_compatibility_digest = blake3::hash(compatibility.as_bytes()).to_hex().to_string();
    if observed_compatibility_digest != REVIEWED_APPLICATION_COMPATIBILITY_BLAKE3 {
        return Err(format!(
            "application compatibility catalog differs from the reviewed rollback authority (observed {observed_compatibility_digest})"
        ));
    }
    if read(root, "release/kitrove-release.json")? != "{}\n" {
        return Err("release manifest placeholder must remain exact empty JSON".to_owned());
    }
    let config = read(root, "dist-workspace.toml")?;
    check_dist_configuration(&config)?;
    let observed_config_digest = blake3::hash(config.as_bytes()).to_hex().to_string();
    if observed_config_digest != REVIEWED_DIST_CONFIG_BLAKE3 {
        return Err(format!(
            "dist configuration differs from the exact security-reviewed configuration (observed {observed_config_digest})"
        ));
    }
    check_dist_package_metadata(root)?;

    let workflow = read(root, ".github/workflows/release.yml")?;
    require_token(
        &workflow,
        "workflow autogenerated by dist",
        ".github/workflows/release.yml",
    )?;
    if !release_trigger_is_tag_push_only(&workflow) {
        return Err(
            "release workflow trigger must contain only semantic-version tag pushes".to_owned(),
        );
    }
    for token in [
        "permissions:\n  \"contents\": \"read\"",
        "\"contents\": \"write\"",
        "sha256sum --check --strict",
        "Get-FileHash -Algorithm SHA256",
        "shasum -a 256 --check",
        "release tag must exactly match v<kitrove-cli package version>",
        "needs.build-global-artifacts.result == 'success'",
        "needs.build-local-artifacts.result == 'success'",
        "Attest global release controls",
        "Attest the exact application archive",
        "application archive attestation requires exactly one target",
        "subject-path: ${{ steps.verified-local.outputs.staged_path }}",
        "subject-path: ${{ steps.verified-local.outputs.installer_staged_path }}",
        "verified-global-artifacts/kitrove-cli-installer.sh",
        "verified-global-artifacts/kitrove-cli-installer.ps1",
        "verified-global-artifacts/kitrove-installer-installer.sh",
        "verified-global-artifacts/kitrove-installer-installer.ps1",
        "verified-global-artifacts/source.tar.gz.sha256",
        "environment: release",
        "release_args=(\"$RELEASE_TAG\" --draft --target \"$RELEASE_COMMIT\"",
        "gh release create \"${release_args[@]}\" verified-artifacts/*",
        "gh release edit \"$RELEASE_TAG\" --draft=false",
        "python3 scripts/verify_release_archives.py target/distrib",
        "--stage verified-artifacts",
        "--stage verified-global-artifacts",
        "--release-tag \"$RELEASE_TAG\"",
        "cargo xtask harden-powershell-installer",
        "cargo xtask prepare-platform-release",
        "python3 scripts/hosted_apple_signing.py",
        "xcrun swiftc scripts/hosted_apple_import.swift",
        "NOTARY_PASSWORD: ${{ secrets.KITROVE_GITHUB_NOTARIZATION }}",
        "cargo xtask verify-application-release",
        "release/application-compatibility.json",
        "verified-artifacts/*",
        "aa343b2ff78ec2981f17a65140250c5ad6062c74072163f68c5c2686d94763a7",
        "6243464a8389e006b9256ee548bc795638f1a17113c1b6669c0e05ce89fd05c5",
        "eb52f9fae0d0506774e9f1801c1168f87fa2c87a45e2d64d3ae7c89401929946",
        "26e845cabff12a92911ce960af73a86c8f9b2b2d9072b01dfe5b662acf044fa3",
    ] {
        require_token(&workflow, token, ".github/workflows/release.yml")?;
    }
    if workflow.matches("\"contents\": \"write\"").count() != 1 {
        return Err("release workflow must grant contents write exactly once".to_owned());
    }
    if workflow.contains("subject-path: \"target/distrib/*${{ join(matrix.targets, ', ') }}*\"") {
        return Err("application archives must not share a multi-subject attestation".to_owned());
    }
    if workflow.matches("GH_TOKEN:").count() != 1 {
        return Err("release workflow must expose GH_TOKEN only to the host job".to_owned());
    }
    check_release_attestation_permissions(&workflow)?;
    if workflow
        .matches("python3 scripts/verify_release_archives.py")
        .count()
        != 4
    {
        return Err(
            "release workflow must verify archives before scratch upload and publication"
                .to_owned(),
        );
    }
    let host_job = bounded_workflow_job(&workflow, "host", "announce")?;
    for token in ["\"contents\": \"write\"", "GH_TOKEN:"] {
        require_token(host_job, token, "release workflow host job")?;
    }
    if workflow.contains("cargo-dist-installer.sh") || workflow.contains("matrix.install_dist.run")
    {
        return Err("release workflow must install cargo-dist from verified archives".to_owned());
    }
    check_release_actions(&workflow)?;
    let observed_workflow_digest = blake3::hash(workflow.as_bytes()).to_hex().to_string();
    if observed_workflow_digest != REVIEWED_RELEASE_WORKFLOW_BLAKE3 {
        return Err(format!(
            "release workflow differs from the exact security-reviewed workflow (observed {observed_workflow_digest})"
        ));
    }
    Ok(())
}

fn bounded_workflow_job<'a>(
    workflow: &'a str,
    job: &str,
    next_job: &str,
) -> Result<&'a str, String> {
    workflow
        .split_once(&format!("\n  {job}:\n"))
        .and_then(|(_, jobs)| jobs.split_once(&format!("\n  {next_job}:\n")))
        .map(|(body, _)| body)
        .ok_or_else(|| format!("release workflow is missing a bounded {job} job"))
}

fn check_release_attestation_permissions(workflow: &str) -> Result<(), String> {
    let permission_tokens = ["\"attestations\": \"write\"", "\"id-token\": \"write\""];
    for job in [
        bounded_workflow_job(workflow, "build-local-artifacts", "build-global-artifacts")?,
        bounded_workflow_job(workflow, "build-global-artifacts", "host")?,
    ] {
        for token in permission_tokens {
            if job.matches(token).count() != 1 {
                return Err(
                    "each artifact build job must receive one attestation and identity-token grant"
                        .to_owned(),
                );
            }
        }
    }
    for token in permission_tokens {
        if workflow.matches(token).count() != 2 {
            return Err(
                "release workflow must confine attestation authority to artifact build jobs"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn check_release_actions(workflow: &str) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for action in workflow.lines().filter_map(|line| {
        line.trim()
            .strip_prefix("- uses: ")
            .or_else(|| line.trim().strip_prefix("uses: "))
    }) {
        let Some((name, revision)) = action.rsplit_once('@') else {
            return Err(format!("release workflow action is unpinned: {action}"));
        };
        let Some((_, expected_revision)) = RELEASE_ACTION_PINS
            .iter()
            .find(|(expected_name, _)| *expected_name == name)
        else {
            return Err(format!("release workflow uses unreviewed action {name:?}"));
        };
        if revision != *expected_revision {
            return Err(format!(
                "release workflow action {name:?} must use reviewed commit {expected_revision}"
            ));
        }
        seen.insert(name);
    }
    for (name, _) in RELEASE_ACTION_PINS {
        if !seen.contains(name) {
            return Err(format!(
                "release workflow is missing reviewed action {name:?}"
            ));
        }
    }
    Ok(())
}

fn check_dist_configuration(source: &str) -> Result<(), String> {
    let document = source
        .parse::<toml::Table>()
        .map_err(|error| format!("dist-workspace.toml is invalid TOML: {error}"))?;
    let dist = document
        .get("dist")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "dist-workspace.toml is missing [dist]".to_owned())?;

    for (key, expected) in [
        ("cargo-dist-version", "0.32.0"),
        ("pr-run-mode", "skip"),
        ("checksum", "sha256"),
    ] {
        if dist.get(key).and_then(toml::Value::as_str) != Some(expected) {
            return Err(format!(
                "dist-workspace.toml [dist].{key} must equal {expected:?}"
            ));
        }
    }
    let includes = dist
        .get("include")
        .and_then(toml::Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .map(toml::Value::as_str)
                .collect::<Option<Vec<_>>>()
        });
    if includes.as_deref() != Some(&["release/kitrove-release.json"][..]) {
        return Err(
            "dist-workspace.toml [dist].include must contain only the release manifest placeholder"
                .to_owned(),
        );
    }
    if dist.get("ci").and_then(toml::Value::as_str) != Some("github") {
        return Err("dist-workspace.toml [dist].ci must equal \"github\"".to_owned());
    }
    let release_targets = kitrove_release_policy::APPLICATION_ARCHIVES
        .iter()
        .map(|spec| spec.target())
        .collect::<Vec<_>>();
    for (key, expected) in [
        ("installers", &["shell", "powershell"][..]),
        ("packages", &["kitrove-cli", "kitrove-installer"][..]),
        ("targets", release_targets.as_slice()),
    ] {
        let observed = dist
            .get(key)
            .and_then(toml::Value::as_array)
            .and_then(|values| {
                values
                    .iter()
                    .map(toml::Value::as_str)
                    .collect::<Option<Vec<_>>>()
            });
        if observed.as_deref() != Some(expected) {
            return Err(format!(
                "dist-workspace.toml [dist].{key} must equal {expected:?}"
            ));
        }
    }
    for key in ["precise-builds", "github-attestations"] {
        if dist.get(key).and_then(toml::Value::as_bool) != Some(true) {
            return Err(format!("dist-workspace.toml [dist].{key} must be true"));
        }
    }
    if dist.get("install-updater").and_then(toml::Value::as_bool) != Some(false) {
        return Err("dist-workspace.toml [dist].install-updater must be false".to_owned());
    }
    if dist.get("install-path").and_then(toml::Value::as_str) != Some("CARGO_HOME") {
        return Err("dist-workspace.toml [dist].install-path must equal \"CARGO_HOME\"".to_owned());
    }
    if dist.contains_key("binaries") {
        return Err(
            "product binary selections must be package-local, not workspace-wide".to_owned(),
        );
    }
    let custom_runners = dist
        .get("github-custom-runners")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "dist-workspace.toml is missing [dist.github-custom-runners]".to_owned())?;
    if custom_runners.len() != 1
        || custom_runners
            .get("aarch64-apple-darwin")
            .and_then(toml::Value::as_str)
            != Some("macos-15")
    {
        return Err("dist-workspace.toml must bind aarch64-apple-darwin to macos-15".to_owned());
    }
    let configured_actions = dist
        .get("github-action-commits")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "dist-workspace.toml is missing [dist.github-action-commits]".to_owned())?;
    if configured_actions.len() != RELEASE_ACTION_PINS.len() {
        return Err("dist-workspace.toml must contain the exact reviewed action set".to_owned());
    }
    for (name, revision) in RELEASE_ACTION_PINS {
        if configured_actions.get(name).and_then(toml::Value::as_str) != Some(revision) {
            return Err(format!(
                "dist-workspace.toml action {name:?} must use reviewed commit {revision}"
            ));
        }
    }
    let allowed_dirty = dist
        .get("allow-dirty")
        .and_then(toml::Value::as_array)
        .and_then(|values| values.first())
        .and_then(toml::Value::as_str);
    if allowed_dirty != Some("ci")
        || dist
            .get("allow-dirty")
            .and_then(toml::Value::as_array)
            .is_none_or(|values| values.len() != 1)
    {
        return Err("dist-workspace.toml [dist].allow-dirty must equal [\"ci\"]".to_owned());
    }
    Ok(())
}

fn check_dist_package_metadata(root: &Path) -> Result<(), String> {
    let workspace_source = read(root, "Cargo.toml")?;
    let document = workspace_source
        .parse::<toml::Table>()
        .map_err(|error| format!("Cargo.toml is invalid TOML: {error}"))?;
    let workspace = document
        .get("workspace")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "Cargo.toml is missing [workspace]".to_owned())?;
    if workspace
        .get("metadata")
        .and_then(toml::Value::as_table)
        .is_some_and(|metadata| metadata.contains_key("dist"))
    {
        return Err("Cargo.toml must not contain [workspace.metadata.dist]".to_owned());
    }
    reject_alternate_dist_configuration(&root.join("dist.toml"), "dist.toml")?;

    let metadata = load_cargo_metadata(root, true, "effective release packages")?;
    for (manifest_path, distributable) in effective_dist_manifests(&metadata, root)? {
        let location = manifest_path.display().to_string();
        let package_root = manifest_path
            .parent()
            .ok_or_else(|| format!("workspace manifest has no parent: {location}"))?;
        reject_alternate_dist_configuration(
            &package_root.join("dist.toml"),
            &format!("{}/dist.toml", package_root.display()),
        )?;
        let source = fs::read_to_string(&manifest_path)
            .map_err(|error| format!("cannot read {location}: {error}"))?;
        check_dist_package_configuration(&source, distributable, &location)?;
    }
    Ok(())
}

fn reject_alternate_dist_configuration(path: &Path, location: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!(
            "{location} is unsupported; release configuration must remain in dist-workspace.toml"
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect {location}: {error}")),
    }
}

fn effective_dist_manifests(
    metadata: &serde_json::Value,
    root: &Path,
) -> Result<Vec<(PathBuf, bool)>, String> {
    let workspace_members = metadata
        .get("workspace_members")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Cargo metadata has no workspace_members array".to_owned())?
        .iter()
        .map(|member| {
            member
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "Cargo metadata contains a non-string workspace member".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Cargo metadata has no packages array".to_owned())?;
    let expected_packages = ["kitrove-cli", "kitrove-installer"];
    let mut manifests = Vec::with_capacity(workspace_members.len());
    let mut found_packages = BTreeSet::new();
    for package in packages {
        let id = metadata_string(package, "id")?;
        if !workspace_members.contains(id) {
            continue;
        }
        let name = metadata_string(package, "name")?;
        let manifest_path = PathBuf::from(metadata_string(package, "manifest_path")?);
        if !manifest_path.starts_with(root) {
            return Err(format!(
                "workspace manifest is outside the repository: {}",
                manifest_path.display()
            ));
        }
        let distributable = expected_packages.contains(&name)
            && manifest_path == root.join(format!("crates/{name}/Cargo.toml"));
        if distributable {
            found_packages.insert(name);
        }
        manifests.push((manifest_path, distributable));
    }
    if manifests.len() != workspace_members.len() {
        return Err("Cargo metadata does not describe every effective workspace member".to_owned());
    }
    if found_packages.len() != expected_packages.len() {
        return Err(
            "Cargo metadata must contain the exact application and installer packages".to_owned(),
        );
    }
    Ok(manifests)
}

fn check_dist_package_configuration(
    source: &str,
    distributable: bool,
    location: &str,
) -> Result<(), String> {
    let document = source
        .parse::<toml::Table>()
        .map_err(|error| format!("{location} is invalid TOML: {error}"))?;
    let dist = document
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("metadata"))
        .and_then(toml::Value::as_table)
        .and_then(|metadata| metadata.get("dist"));
    if !distributable {
        return if dist.is_none() {
            Ok(())
        } else {
            Err(format!(
                "{location} must not contain package-local dist configuration"
            ))
        };
    }
    let dist = dist.and_then(toml::Value::as_table).ok_or_else(|| {
        format!("{location} must contain dist = true and exact product binary selections")
    })?;
    if dist.len() != 2 || dist.get("dist").and_then(toml::Value::as_bool) != Some(true) {
        return Err(format!(
            "{location} must contain only dist = true and exact product binary selections"
        ));
    }
    let binary = match document
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
    {
        Some("kitrove-cli") => "kitrove",
        Some("kitrove-installer") => "kitrove-installer",
        _ => return Err(format!("{location} is not a distributable product")),
    };
    let binaries = dist
        .get("binaries")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| format!("{location} must select its exact product binary"))?;
    let targets = kitrove_release_policy::APPLICATION_ARCHIVES;
    if binaries.len() != targets.len()
        || targets.iter().any(|spec| {
            binaries
                .get(spec.target())
                .and_then(toml::Value::as_array)
                .is_none_or(|values| values.len() != 1 || values[0].as_str() != Some(binary))
        })
    {
        return Err(format!(
            "{location} must select only {binary} for every release target"
        ));
    }
    Ok(())
}

fn release_trigger_is_tag_push_only(workflow: &str) -> bool {
    let normalized = workflow.replace("\r\n", "\n");
    let Some((_, after_on)) = normalized.split_once("\non:\n") else {
        return false;
    };
    let Some((trigger, _)) = after_on.split_once("\njobs:\n") else {
        return false;
    };
    trigger.trim_end() == "  push:\n    tags:\n      - '**[0-9]+.[0-9]+.[0-9]+*'"
}

fn check_dependency_licenses(root: &Path) -> Result<(), String> {
    check_reviewed_third_party_tree(
        &root.join("third_party/sigstore-rekor"),
        REVIEWED_SIGSTORE_REKOR_TREE_BLAKE3,
    )?;
    check_reviewed_third_party_tree(
        &root.join("third_party/sigstore-tsa"),
        REVIEWED_SIGSTORE_TSA_TREE_BLAKE3,
    )?;
    let lock_bytes = fs::read(root.join("Cargo.lock"))
        .map_err(|error| format!("cannot read Cargo.lock: {error}"))?;
    let observed_lock_digest = blake3::hash(&lock_bytes).to_hex().to_string();
    if observed_lock_digest != REVIEWED_CARGO_LOCK_BLAKE3 {
        return Err(format!(
            "Cargo.lock has not received dependency identity and license review; observed BLAKE3 {observed_lock_digest}"
        ));
    }

    let metadata = load_cargo_metadata(root, false, "locked dependency licenses")?;
    check_offline_release_provenance_graph(&metadata, root)?;
    let workspace_members = metadata
        .get("workspace_members")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Cargo metadata has no workspace_members array".to_owned())?
        .iter()
        .map(|member| {
            member
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "Cargo metadata contains a non-string workspace member".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Cargo metadata has no packages array".to_owned())?;

    let mut inventory = Vec::new();
    for package in packages {
        let id = metadata_string(package, "id")?;
        let name = metadata_string(package, "name")?;
        let version = metadata_string(package, "version")?;
        let license = package
            .get("license")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!("package {name} {version} has no declared license expression")
            })?;

        if workspace_members.contains(id) {
            if license != "MIT OR Apache-2.0" {
                return Err(format!(
                    "workspace package {name} {version} declares {license:?}, expected \"MIT OR Apache-2.0\""
                ));
            }
        } else {
            if !license_expression_allowed(license) {
                return Err(format!(
                    "third-party package {name} {version} has unreviewed license expression {license:?}"
                ));
            }
            inventory.push((name.to_owned(), version.to_owned(), license.to_owned()));
        }
    }

    inventory.sort();
    println!("package\tversion\tlicense");
    for (name, version, license) in &inventory {
        println!("{name}\t{version}\t{license}");
    }
    println!(
        "dependency license checks passed ({} third-party packages inspected)",
        inventory.len()
    );
    Ok(())
}

fn check_offline_release_provenance_graph(
    metadata: &serde_json::Value,
    root: &Path,
) -> Result<(), String> {
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Cargo metadata has no packages array".to_owned())?;
    let package_names = packages
        .iter()
        .map(|package| {
            Ok((
                metadata_string(package, "id")?,
                metadata_string(package, "name")?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let workspace_members = metadata
        .get("workspace_members")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Cargo metadata has no workspace_members array".to_owned())?;
    let expected_manifest = root.join("crates/kitrove-release-provenance/Cargo.toml");
    let mut release_provenance_ids = packages.iter().filter_map(|package| {
        let id = package.get("id")?.as_str()?;
        let name = package.get("name")?.as_str()?;
        let manifest = package.get("manifest_path")?.as_str()?;
        (name == "kitrove-release-provenance"
            && Path::new(manifest) == expected_manifest
            && workspace_members
                .iter()
                .any(|member| member.as_str() == Some(id)))
        .then_some(id)
    });
    let release_provenance_id = release_provenance_ids.next().ok_or_else(|| {
        "Cargo metadata has no exact workspace release-provenance package".to_owned()
    })?;
    if release_provenance_ids.next().is_some() {
        return Err(
            "Cargo metadata has multiple exact workspace release-provenance packages".to_owned(),
        );
    }
    let nodes = metadata
        .pointer("/resolve/nodes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Cargo metadata has no resolved dependency nodes".to_owned())?;
    let node_by_id = nodes
        .iter()
        .map(|node| Ok((metadata_string(node, "id")?, node)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;

    let mut pending = vec![release_provenance_id];
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let name = package_names
            .get(id)
            .ok_or_else(|| format!("resolved package {id} has no package metadata"))?;
        if matches!(
            *name,
            "reqwest" | "hyper" | "hyper-util" | "ureq" | "isahc" | "surf" | "curl"
        ) {
            return Err(format!(
                "offline release provenance unexpectedly reaches network client package {name}"
            ));
        }
        let node = node_by_id
            .get(id)
            .ok_or_else(|| format!("resolved package {id} has no dependency node"))?;
        if matches!(*name, "sigstore-rekor" | "sigstore-tsa") {
            let features = node
                .get("features")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| format!("{name} node has no feature array"))?;
            if !features.is_empty() {
                return Err(format!(
                    "offline {name} must have no enabled features, observed {features:?}"
                ));
            }
            let package = packages
                .iter()
                .find(|package| package.get("id").and_then(serde_json::Value::as_str) == Some(id))
                .ok_or_else(|| format!("{name} has no package metadata"))?;
            let expected_manifest = root.join(format!("third_party/{name}/Cargo.toml"));
            if Path::new(metadata_string(package, "manifest_path")?) != expected_manifest {
                return Err(format!(
                    "offline {name} must resolve to the reviewed third_party patch"
                ));
            }
        }
        let dependencies = node
            .get("deps")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("resolved package {id} has no dependency list"))?;
        for dependency in dependencies {
            pending.push(metadata_string(dependency, "pkg")?);
        }
    }
    Ok(())
}

fn check_reviewed_third_party_tree(root: &Path, expected_digest: &str) -> Result<(), String> {
    let mut files = Vec::new();
    collect_reviewed_tree_files(root, root, &mut files)?;
    let files = files
        .into_iter()
        .map(|path| reviewed_tree_relative_name(&path).map(|name| (name, path)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-reviewed-third-party-tree-v1\0");
    for (name, relative) in files {
        let relative_bytes = name.as_bytes();
        let content = fs::read(root.join(&relative)).map_err(|error| {
            format!(
                "cannot read reviewed tree file {}: {error}",
                relative.display()
            )
        })?;
        hasher.update(&(relative_bytes.len() as u64).to_le_bytes());
        hasher.update(relative_bytes);
        hasher.update(&(content.len() as u64).to_le_bytes());
        hasher.update(&content);
    }
    let observed = hasher.finalize().to_hex().to_string();
    if observed != expected_digest {
        return Err(format!(
            "reviewed third-party tree {} changed; observed BLAKE3 {observed}",
            root.display()
        ));
    }
    Ok(())
}

// Hash a host-independent path spelling, without normalizing the file's bytes.
// Reject Unix backslash filenames rather than aliasing a Windows separator.
fn reviewed_tree_relative_name(path: &Path) -> Result<String, String> {
    let parts = path
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => name
                .to_str()
                .filter(|name| !name.contains('\\'))
                .ok_or_else(|| "reviewed tree name is not portable UTF-8".to_owned()),
            _ => Err("reviewed tree name must be relative normal components".to_owned()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parts.is_empty() {
        return Err("reviewed tree name is empty".to_owned());
    }
    Ok(parts.join("/"))
}

fn collect_reviewed_tree_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "cannot inspect reviewed tree {}: {error}",
            directory.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "cannot inspect reviewed tree entry in {}: {error}",
                directory.display()
            )
        })?;
        let path = entry.path();
        if directory == root && entry.file_name() == "target" {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "cannot inspect reviewed tree path {}: {error}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "reviewed tree contains a symbolic link: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            collect_reviewed_tree_files(root, &path, files)?;
        } else if metadata.is_file() {
            files.push(
                path.strip_prefix(root)
                    .map_err(|_| format!("reviewed tree path escaped root: {}", path.display()))?
                    .to_owned(),
            );
        } else {
            return Err(format!(
                "reviewed tree contains a special file: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn load_cargo_metadata(
    root: &Path,
    no_dependencies: bool,
    purpose: &str,
) -> Result<serde_json::Value, String> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command.args(["metadata", "--locked", "--format-version", "1"]);
    if no_dependencies {
        command.arg("--no-deps");
    }
    let output = command
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot inspect {purpose}: {error}"))?;
    if !output.status.success() {
        return Err(format!("cargo metadata failed while inspecting {purpose}"));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Cargo metadata for {purpose} is not valid JSON: {error}"))
}

fn metadata_string<'a>(package: &'a serde_json::Value, field: &str) -> Result<&'a str, String> {
    package
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("Cargo metadata package has no string {field:?} field"))
}

fn license_expression_allowed(expression: &str) -> bool {
    matches!(
        expression,
        "(MIT OR Apache-2.0) AND Unicode-3.0"
            | "Apache-2.0"
            | "Apache-2.0 AND ISC"
            | "ISC AND (Apache-2.0 OR ISC)"
            | "ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0)"
            | "Apache-2.0 OR BSL-1.0"
            | "Apache-2.0 OR ISC OR MIT"
            | "Apache-2.0 OR MIT"
            | "Apache-2.0 WITH LLVM-exception"
            | "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT"
            | "BSD-2-Clause OR Apache-2.0 OR MIT"
            | "BSD-3-Clause"
            | "CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception"
            | "CC0-1.0 OR MIT-0 OR Apache-2.0"
            | "CDLA-Permissive-2.0"
            | "ISC"
            | "MIT"
            | "MIT OR Apache-2.0"
            | "MIT OR Apache-2.0 OR BSD-1-Clause"
            | "MIT OR Apache-2.0 OR LGPL-2.1-or-later"
            | "MIT OR Apache-2.0 OR Zlib"
            | "MIT/Apache-2.0"
            | "Unicode-3.0"
            | "Unlicense OR MIT"
            | "Zlib"
            | "Zlib OR Apache-2.0 OR MIT"
    )
}

fn private_context_present(present: usize, required: usize) -> Result<bool, String> {
    match present {
        0 => Ok(false),
        count if count == required => Ok(true),
        _ => Err(
            "private continuity files must be either completely present or completely absent"
                .to_owned(),
        ),
    }
}

fn check_compiled_tier_one_sources(root: &Path) -> Result<(), String> {
    let crates = root.join("crates");
    let mut files = Vec::new();
    collect_files(&crates, &mut files)?;
    let testkit = crates.join("kitrove-testkit");
    let mut external_test_modules = BTreeSet::new();

    for path in &files {
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs")
            || !path
                .components()
                .any(|component| component.as_os_str() == "src")
        {
            continue;
        }
        let source = fs::read_to_string(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        external_test_modules.extend(cfg_test_path_modules(path, &source));
    }

    for path in files {
        if path.starts_with(&testkit)
            || external_test_modules.contains(&path)
            || path.extension().and_then(|extension| extension.to_str()) != Some("rs")
            || !path
                .components()
                .any(|component| component.as_os_str() == "src")
        {
            continue;
        }
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let relative = path.strip_prefix(root).unwrap_or(&path);
        check_production_source(relative, &source)?;
    }
    Ok(())
}

fn cfg_test_path_modules(source_path: &Path, source: &str) -> Vec<PathBuf> {
    let lines = source.lines().map(str::trim).collect::<Vec<_>>();
    let mut modules = Vec::new();

    for declaration in lines.windows(3) {
        if declaration[0] != "#[cfg(test)]"
            || declaration[2]
                .strip_prefix("mod ")
                .and_then(|module| module.strip_suffix(';'))
                .is_none()
        {
            continue;
        }
        let Some(relative) = declaration[1]
            .strip_prefix("#[path = \"")
            .and_then(|path| path.strip_suffix("\"]"))
        else {
            continue;
        };
        let relative = Path::new(relative);
        if relative.components().count() != 1 {
            continue;
        }
        if let Some(parent) = source_path.parent() {
            modules.push(parent.join(relative));
        }
    }

    modules
}

fn check_production_source(path: &Path, source: &str) -> Result<(), String> {
    // Tests may prepare hostile fixtures. The compiled product portion ends before the
    // conventional trailing test module; production crates keep those modules last.
    let source = source.replace("\r\n", "\n");
    let test_module = [
        "#[cfg(test)]\nmod tests",
        "#[cfg(test)]\npub(crate) mod tests",
    ]
    .into_iter()
    .filter_map(|marker| source.find(marker))
    .min();
    let production = test_module.map_or(source.as_str(), |index| &source[..index]);
    let forbidden = [
        ("std::process::Command", "process launch"),
        ("process::Command", "process launch"),
        ("Command::new(", "process launch"),
        ("tokio::process", "process launch"),
        ("std::process::exit(", "process termination"),
        ("std::net::", "network access"),
        ("TcpStream", "network access"),
        ("TcpListener", "network access"),
        ("UdpSocket", "network access"),
        ("reqwest", "network access"),
        ("ureq::", "network access"),
        ("hyper::", "network access"),
        ("std::fs::write", "filesystem mutation"),
        ("fs::write(", "filesystem mutation"),
        ("File::create(", "filesystem mutation"),
        ("create_dir(", "filesystem mutation"),
        ("create_dir_all(", "filesystem mutation"),
        ("remove_file(", "filesystem mutation"),
        ("remove_dir(", "filesystem mutation"),
        ("remove_dir_all(", "filesystem mutation"),
        ("rename(", "filesystem mutation"),
        ("set_permissions(", "filesystem mutation"),
        (".write(true)", "filesystem mutation"),
        (".append(true)", "filesystem mutation"),
        (".truncate(true)", "filesystem mutation"),
        (".create(true)", "filesystem mutation"),
        ("write_all(", "filesystem mutation"),
        ("SetEntriesInAclW(", "filesystem mutation"),
        ("SetSecurityInfo(", "filesystem mutation"),
    ];

    let filesystem_mutation_allowed = [
        "crates/kitrove-core/src/object_mutation.rs",
        "crates/kitrove-core/src/quarantine_cleanup/batch.rs",
        "crates/kitrove-windows-security/src/lib.rs",
        "crates/kitrove-installer/src/unix_staging.rs",
        "crates/kitrove-installer/src/windows_staging.rs",
        "crates/kitrove-installer/src/unix_install.rs",
        "crates/kitrove-installer/src/windows_install.rs",
        "crates/kitrove-installer/src/unix_recovery.rs",
        "crates/kitrove-state-lifecycle/src/lib.rs",
    ]
    .into_iter()
    .any(|allowed| path == Path::new(allowed));
    let network_allowed = path == Path::new("crates/kitrove-core/src/git_sync_backend.rs")
        || path == Path::new("crates/kitrove-core/src/ssh_git_transport.rs");
    let process_launch_allowed = path == Path::new("crates/kitrove-version-probe/src/lib.rs");
    if let Some((token, category)) = forbidden.into_iter().find(|(token, category)| {
        production.contains(token)
            && !(*category == "filesystem mutation" && filesystem_mutation_allowed)
            && !(*category == "network access" && network_allowed)
            && !(*category == "process launch" && process_launch_allowed)
    }) {
        return Err(format!(
            "compiled tier-one source {} contains forbidden {category} API token {token:?}",
            path.display()
        ));
    }
    Ok(())
}

fn check_git_dependency_boundary(root: &Path) -> Result<(), String> {
    let manifest = read(root, "Cargo.toml")?;
    for token in [
        "ureq = { version = \"=3.4.0\", default-features = false, features = [\"rustls\"] }",
        "rustls = { version = \"=0.23.32\", default-features = false, features = [\"ring\", \"logging\", \"std\", \"tls12\"] }",
        "webpki-roots = \"=1.0.9\"",
        "url = \"=2.5.8\"",
        "gix-hash = { version = \"=0.26.2\", default-features = false, features = [\"sha1\"] }",
        "gix-object = { version = \"=0.64.1\", default-features = false }",
        "gix-pack = { version = \"=0.74.2\", default-features = false, features = [\"sha1\"] }",
        "gix-packetline = { version = \"=0.22.2\", default-features = false, features = [\"blocking-io\"] }",
        "gix-zlib = { version = \"=0.1.0\", default-features = false }",
        "data-encoding = \"=2.11.1\"",
        "calcifer-macos-acl = \"=0.1.0\"",
        "hmac = \"=0.13.0\"",
        "rpassword = \"=7.5.4\"",
        "russh = { version = \"=0.62.0\", default-features = false, features = [\"ring\"] }",
        "tokio = { version = \"=1.53.1\", default-features = false, features = [\"io-util\", \"net\", \"rt\", \"sync\", \"time\"] }",
        "sha1 = \"=0.11.0\"",
        "zeroize = \"=1.9.0\"",
        "windows-sys = \"=0.61.2\"",
    ] {
        require_token(&manifest, token, "Cargo.toml")?;
    }

    let core_manifest = read(root, "crates/kitrove-core/Cargo.toml")?;
    require_token(
        &core_manifest,
        "[target.'cfg(target_os = \"macos\")'.dependencies]\ncalcifer-macos-acl.workspace = true",
        "crates/kitrove-core/Cargo.toml",
    )?;
    require_token(
        &core_manifest,
        "[target.'cfg(windows)'.dependencies]\nkitrove-windows-security.workspace = true",
        "crates/kitrove-core/Cargo.toml",
    )?;

    let lock = read(root, "Cargo.lock")?;
    for (name, version) in [
        ("calcifer-macos-acl", "0.1.0"),
        ("gix-zlib", "0.1.0"),
        ("aes", "0.9.2"),
        ("russh", "0.62.0"),
        ("russh-cryptovec", "0.62.0"),
        ("rpassword", "7.5.4"),
        ("rtoolbox", "0.0.6"),
        ("zlib-rs", "0.6.7"),
        ("idna_adapter", "1.2.1"),
        ("icu_collections", "2.1.1"),
        ("icu_locale_core", "2.1.1"),
        ("icu_normalizer", "2.1.1"),
        ("icu_normalizer_data", "2.1.1"),
        ("icu_properties", "2.1.2"),
        ("icu_properties_data", "2.1.2"),
        ("icu_provider", "2.1.1"),
        ("windows-sys", "0.61.2"),
    ] {
        require_token(
            &lock,
            &format!("name = \"{name}\"\nversion = \"{version}\""),
            "Cargo.lock",
        )?;
    }

    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .args(["tree", "--locked", "-e", "features"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot inspect locked dependency features: {error}"))?;
    if !output.status.success() {
        return Err("cargo tree --locked -e features failed".to_owned());
    }
    let graph = String::from_utf8(output.stdout)
        .map_err(|_| "dependency feature graph is not UTF-8".to_owned())?;
    for prohibited in [
        "git2 ",
        "libgit2-sys ",
        "gix-protocol ",
        "gix-transport ",
        "gix-credentials ",
        "gix-command ",
        "native-tls ",
        "rustls-native-certs ",
        "rustls-platform-verifier ",
        "openssl-probe ",
        "flate2 ",
        "brotli ",
        "cookie feature",
        "proxy feature",
    ] {
        if graph.contains(prohibited) {
            return Err(format!(
                "locked Git dependency graph contains prohibited token {prohibited:?}"
            ));
        }
    }
    for required in [
        "gix-zlib v0.1.0",
        "aes v0.9.2",
        "russh v0.62.0",
        "russh-cryptovec v0.62.0",
        "rpassword v7.5.4",
        "rtoolbox v0.0.6",
        "zlib-rs v0.6.7",
        "webpki-roots v1.0.9",
    ] {
        if !graph.contains(required) {
            return Err(format!(
                "locked Git dependency graph is missing required token {required:?}"
            ));
        }
    }
    Ok(())
}

fn check_repository(root: &Path) -> Result<(), String> {
    let prohibited_names = [
        ".env",
        "auth.json",
        ".credentials.json",
        "credentials.json",
        "id_rsa",
        "id_ed25519",
    ];

    let mut files = Vec::new();
    collect_files(root, &mut files)?;

    for path in &files {
        if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
            if prohibited_names.contains(&name) {
                return Err(format!(
                    "prohibited credential-like file is present: {}",
                    path.display()
                ));
            }
        }

        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "repository scaffold contains a symlink: {}",
                path.display()
            ));
        }
    }

    println!("repository checks passed ({} files inspected)", files.len());
    Ok(())
}

fn collect_files(current: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(current)
        .map_err(|error| format!("cannot read {}: {error}", current.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot read directory entry: {error}"))?;
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");

        if matches!(name, ".git" | "target") {
            continue;
        }

        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_files(&path, files)?;
        } else if file_type.is_file() || file_type.is_symlink() {
            files.push(path);
        }
    }
    Ok(())
}

fn require_file(root: &Path, relative: &str) -> Result<(), String> {
    let path = root.join(relative);
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("required governance file is missing: {relative}"))
    }
}

fn read(root: &Path, relative: &str) -> Result<String, String> {
    fs::read_to_string(root.join(relative))
        .map_err(|error| format!("cannot read {relative}: {error}"))
}

fn require_token(content: &str, token: &str, location: &str) -> Result<(), String> {
    if content.contains(token) {
        Ok(())
    } else {
        Err(format!("{location} is missing required token {token:?}"))
    }
}

fn print_help() {
    println!(
        "Kitrove repository automation\n\nUsage:\n  cargo xtask <COMMAND>\n\nCommands:\n  ci                                    Run every required local and CI validation\n  governance                            Validate North Stars, invariants, ADRs, and context files\n  licenses                              Validate and print the locked dependency license inventory\n  repository                            Validate repository structure and private-repo hygiene\n  prepare-platform-release <archive> <target> <tag> <compatibility-file> <dist-manifest>\n  prepare-application-release           Bind metadata and refresh cargo-dist checksum authority\n  verify-application-release            Verify one archive's metadata and checksum\n  verify-application-release-bundle     Verify archive, sidecar, and cargo-dist authority\n  harden-powershell-installer           Add mandatory archive digest verification to PowerShell\n  help                                  Print this help\n\nContributor shortcut:\n  cargo ci"
    );
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        REVIEWED_APPLICATION_COMPATIBILITY_BLAKE3, REVIEWED_DIST_CONFIG_BLAKE3,
        REVIEWED_RELEASE_POLICY_BLAKE3, REVIEWED_RELEASE_WORKFLOW_BLAKE3,
        REVIEWED_SIGSTORE_REKOR_TREE_BLAKE3, REVIEWED_SIGSTORE_TSA_TREE_BLAKE3,
        cfg_test_path_modules, check_dist_configuration, check_dist_package_configuration,
        check_production_source, check_release_actions, check_release_attestation_permissions,
        check_reviewed_third_party_tree, effective_dist_manifests, license_expression_allowed,
        private_context_present, release_trigger_is_tag_push_only,
    };

    #[test]
    fn governance_accepts_public_or_complete_private_context_only() {
        assert!(!private_context_present(0, 6).unwrap());
        assert!(private_context_present(6, 6).unwrap());
        assert!(private_context_present(1, 6).is_err());
        assert!(private_context_present(5, 6).is_err());
    }

    #[test]
    fn release_configuration_uses_active_toml_values() {
        let valid = r#"
[dist]
cargo-dist-version = "0.32.0"
pr-run-mode = "skip"
ci = "github"
installers = ["shell", "powershell"]
targets = ["aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"]
precise-builds = true
packages = ["kitrove-cli", "kitrove-installer"]
include = ["release/kitrove-release.json"]
install-path = "CARGO_HOME"
install-updater = false
checksum = "sha256"
github-attestations = true
allow-dirty = ["ci"]

[dist.github-custom-runners]
aarch64-apple-darwin = "macos-15"

[dist.github-action-commits]
"actions/attest" = "1e69f48acb82d1966a394da916b4c1698aa569d6"
"actions/checkout" = "d23441a48e516b6c34aea4fa41551a30e30af803"
"actions/download-artifact" = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
"actions/upload-artifact" = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
"#;
        check_dist_configuration(valid).expect("exact active settings are accepted");

        for invalid in [
            valid.replace(
                "pr-run-mode = \"skip\"",
                "# pr-run-mode = \"skip\"\npr-run-mode = \"upload\"",
            ),
            valid.replace("checksum = \"sha256\"", "checksum = \"sha512\""),
            valid.replace("github-attestations = true", "github-attestations = false"),
            valid.replace("install-updater = false", "install-updater = true"),
            valid.replace(
                "installers = [\"shell\", \"powershell\"]",
                "installers = [\"shell\", \"powershell\", 1]",
            ),
            valid.replace(
                "packages = [\"kitrove-cli\", \"kitrove-installer\"]",
                "packages = [\"kitrove-cli\", \"xtask\"]",
            ),
            format!("{valid}\n[dist.binaries]\nx86_64-pc-windows-msvc = [\"kitrove\"]\n"),
        ] {
            check_dist_configuration(&invalid)
                .expect_err("comments and unsafe active overrides must fail closed");
        }
    }

    #[test]
    fn release_actions_use_only_reviewed_repositories_and_commits() {
        let valid = include_str!("../../.github/workflows/release.yml");
        check_release_actions(valid).expect("checked-in workflow uses the reviewed action set");

        for invalid in [
            valid.replace(
                "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
                "attacker/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
            ),
            valid.replace(
                "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
                "actions/attest@1111111111111111111111111111111111111111",
            ),
        ] {
            check_release_actions(&invalid)
                .expect_err("unknown actions and unreviewed commits must fail closed");
        }
    }

    #[test]
    fn release_attestation_authority_is_confined_to_artifact_builds() {
        let valid = include_str!("../../.github/workflows/release.yml");
        check_release_attestation_permissions(valid)
            .expect("both artifact build jobs have exact attestation authority");

        let grant = concat!(
            "    permissions:\n",
            "      \"attestations\": \"write\"\n",
            "      \"contents\": \"read\"\n",
            "      \"id-token\": \"write\"\n",
        );
        let relocated = valid
            .replacen(grant, "    permissions:\n      \"contents\": \"read\"\n", 1)
            .replacen(
                "  plan:\n",
                concat!(
                    "  plan:\n",
                    "    permissions:\n",
                    "      \"attestations\": \"write\"\n",
                    "      \"id-token\": \"write\"\n",
                ),
                1,
            );
        check_release_attestation_permissions(&relocated)
            .expect_err("attestation authority cannot move to a non-build job");
    }

    #[test]
    fn package_local_dist_configuration_cannot_override_release_policy() {
        let valid = r#"
[package]
name = "kitrove-cli"

[package.metadata.dist]
dist = true
[package.metadata.dist.binaries]
aarch64-apple-darwin = ["kitrove"]
x86_64-apple-darwin = ["kitrove"]
x86_64-unknown-linux-gnu = ["kitrove"]
x86_64-pc-windows-msvc = ["kitrove"]
"#;
        check_dist_package_configuration(valid, true, "cli/Cargo.toml")
            .expect("the exact product binary map is accepted");
        let installer = valid
            .replace("name = \"kitrove-cli\"", "name = \"kitrove-installer\"")
            .replace("[\"kitrove\"]", "[\"kitrove-installer\"]");
        check_dist_package_configuration(&installer, true, "installer/Cargo.toml")
            .expect("installer packaging selects only its own executable");
        check_dist_package_configuration(
            &installer.replace("[\"kitrove-installer\"]", "[\"kitrove\"]"),
            true,
            "installer/Cargo.toml",
        )
        .expect_err("a product cannot package the other product's executable");

        for invalid in [
            valid.replace("dist = true", "dist = false"),
            valid.replace("[\"kitrove\"]", "[\"kitrove\", \"kitrove-installer\"]"),
            valid.replace("x86_64-pc-windows-msvc = [\"kitrove\"]", ""),
            format!(
                "{valid}\n[package.metadata.dist.binaries]\naarch64-apple-darwin = [\"fixture\"]\n"
            ),
            valid.replace(
                "dist = true",
                "dist = true\nfeatures = [\"windows-test-fixture\"]",
            ),
        ] {
            check_dist_package_configuration(&invalid, true, "cli/Cargo.toml")
                .expect_err("package-local dist overrides must fail closed");
        }
        check_dist_package_configuration(valid, false, "other/Cargo.toml")
            .expect_err("non-distributable packages cannot add dist metadata");
        check_dist_package_configuration(
            "[package]\nname = \"other\"\n",
            false,
            "other/Cargo.toml",
        )
        .expect("ordinary packages need no dist metadata");
    }

    #[test]
    fn effective_release_members_include_root_and_implicit_packages() {
        let root = Path::new("/repo");
        let metadata = serde_json::json!({
            "workspace_members": ["root-id", "cli-id", "installer-id", "implicit-id"],
            "packages": [
                {
                    "id": "root-id",
                    "name": "root-package",
                    "manifest_path": "/repo/Cargo.toml"
                },
                {
                    "id": "cli-id",
                    "name": "kitrove-cli",
                    "manifest_path": "/repo/crates/kitrove-cli/Cargo.toml"
                },
                {
                    "id": "installer-id",
                    "name": "kitrove-installer",
                    "manifest_path": "/repo/crates/kitrove-installer/Cargo.toml"
                },
                {
                    "id": "implicit-id",
                    "name": "implicit-package",
                    "manifest_path": "/repo/crates/implicit/Cargo.toml"
                }
            ]
        });
        let manifests = effective_dist_manifests(&metadata, root).unwrap();
        assert_eq!(manifests.len(), 4);
        assert_eq!(
            manifests
                .iter()
                .filter(|(_, distributable)| *distributable)
                .count(),
            2
        );
        assert!(manifests.contains(&(root.join("Cargo.toml"), false)));
        assert!(manifests.contains(&(root.join("crates/implicit/Cargo.toml"), false)));
        assert!(manifests.contains(&(root.join("crates/kitrove-cli/Cargo.toml"), true)));
        assert!(manifests.contains(&(root.join("crates/kitrove-installer/Cargo.toml"), true)));

        let incomplete = serde_json::json!({
            "workspace_members": ["cli-id", "implicit-id"],
            "packages": [{
                "id": "cli-id",
                "name": "kitrove-cli",
                "manifest_path": "/repo/crates/kitrove-cli/Cargo.toml"
            }]
        });
        effective_dist_manifests(&incomplete, root)
            .expect_err("every effective workspace member must be described and validated");
    }

    #[test]
    fn release_behavior_files_are_bound_to_reviewed_content() {
        let mut changed = Vec::new();
        for (name, content, expected) in [
            (
                "dist-workspace.toml",
                include_str!("../../dist-workspace.toml"),
                REVIEWED_DIST_CONFIG_BLAKE3,
            ),
            (
                ".github/workflows/release.yml",
                include_str!("../../.github/workflows/release.yml"),
                REVIEWED_RELEASE_WORKFLOW_BLAKE3,
            ),
            (
                "release/release-policy.json",
                include_str!("../../release/release-policy.json"),
                REVIEWED_RELEASE_POLICY_BLAKE3,
            ),
            (
                "release/application-compatibility.json",
                include_str!("../../release/application-compatibility.json"),
                REVIEWED_APPLICATION_COMPATIBILITY_BLAKE3,
            ),
        ] {
            let observed = blake3::hash(content.as_bytes()).to_hex();
            if observed.as_str() != expected {
                changed.push(format!("{name}: observed {observed}, reviewed {expected}"));
            }
            assert_ne!(
                blake3::hash(format!("{content}\n# unreviewed").as_bytes())
                    .to_hex()
                    .as_str(),
                expected,
                "any release behavior change requires explicit review"
            );
        }
        assert!(
            changed.is_empty(),
            "unreviewed release behavior:\n{}",
            changed.join("\n")
        );
    }

    #[test]
    fn release_trigger_accepts_only_version_tag_pushes() {
        let valid = "name: Release\non:\n  push:\n    tags:\n      - '**[0-9]+.[0-9]+.[0-9]+*'\njobs:\n  plan: {}\n";
        assert!(release_trigger_is_tag_push_only(valid));

        for extra in [
            "    branches: [main]\n",
            "  schedule:\n    - cron: '0 0 * * *'\n",
            "  workflow_dispatch: {}\n",
            "  pull_request_target: {}\n",
        ] {
            let invalid = valid.replace("\njobs:\n", &format!("\n{extra}jobs:\n"));
            assert!(!release_trigger_is_tag_push_only(&invalid));
        }
    }

    #[test]
    fn dependency_license_policy_is_explicit_and_fail_closed() {
        assert!(license_expression_allowed("MIT OR Apache-2.0"));
        assert!(license_expression_allowed(
            "MIT OR Apache-2.0 OR BSD-1-Clause"
        ));
        assert!(license_expression_allowed("Apache-2.0 WITH LLVM-exception"));
        assert!(license_expression_allowed(
            "BSD-2-Clause OR Apache-2.0 OR MIT"
        ));
        assert!(!license_expression_allowed("GPL-3.0-only"));
        assert!(!license_expression_allowed(""));
    }

    #[test]
    fn reviewed_dependency_graph_is_bound_to_the_exact_lockfile() {
        let observed = blake3::hash(include_bytes!("../../Cargo.lock"))
            .to_hex()
            .to_string();
        assert_eq!(
            observed,
            super::REVIEWED_CARGO_LOCK_BLAKE3,
            "the exact locked graph requires fresh dependency identity and license review"
        );
    }

    #[test]
    fn vendored_sigstore_verification_trees_are_bound_to_exact_inventories() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        for (relative, digest) in [
            (
                "third_party/sigstore-rekor",
                REVIEWED_SIGSTORE_REKOR_TREE_BLAKE3,
            ),
            (
                "third_party/sigstore-tsa",
                REVIEWED_SIGSTORE_TSA_TREE_BLAKE3,
            ),
        ] {
            let path = root.join(relative);
            check_reviewed_third_party_tree(&path, digest)
                .expect("vendored verifier source must match the reviewed tree");
            check_reviewed_third_party_tree(&path, "unreviewed")
                .expect_err("any different reviewed digest must fail closed");
        }
    }

    #[test]
    fn reviewed_tree_names_use_portable_separators_without_aliases() {
        assert_eq!(
            super::reviewed_tree_relative_name(&Path::new("src").join("body.rs")).unwrap(),
            "src/body.rs"
        );
        for invalid in [
            Path::new(""),
            Path::new("../body.rs"),
            Path::new("/body.rs"),
        ] {
            assert!(super::reviewed_tree_relative_name(invalid).is_err());
        }
        #[cfg(unix)]
        assert!(super::reviewed_tree_relative_name(Path::new("src\\body.rs")).is_err());
    }

    #[test]
    fn production_source_governance_rejects_side_effect_apis() {
        for source in [
            "std::process::Command::new(\"sh\");",
            "std::net::TcpStream::connect(\"127.0.0.1:1\");",
            "std::fs::write(\"result\", b\"changed\");",
            "std::fs::File::create(\"result\");",
            "options.write(true);",
            "writer.write_all(b\"changed\");",
        ] {
            let error = check_production_source(Path::new("fixture.rs"), source)
                .expect_err("compiled production source must reject side-effect APIs");
            assert!(error.contains("fixture.rs"));
        }
    }

    #[test]
    fn production_source_governance_allows_read_only_apis_and_test_modules() {
        let source = r#"
let bytes = std::fs::read("input")?;
let mut options = cap_std::fs::OpenOptions::new();
options.read(true);

#[cfg(test)]
mod tests {
    fn fixture() {
        std::fs::write("fixture", b"body").unwrap();
        std::process::Command::new("mkfifo");
    }
}
"#;

        check_production_source(Path::new("fixture.rs"), source)
            .expect("read-only production code and test-only setup are permitted");

        let crate_visible_tests = source.replace("mod tests", "pub(crate) mod tests");
        check_production_source(Path::new("fixture.rs"), &crate_visible_tests)
            .expect("crate-visible test helpers remain test-only setup");
    }

    #[test]
    fn production_governance_recognizes_only_local_explicit_cfg_test_modules() {
        let source = r#"
#[cfg(test)]
#[path = "transaction_tests.rs"]
mod tests;

#[path = "production.rs"]
mod production;

#[cfg(test)]
#[path = "../escaped.rs"]
mod escaped;

#[cfg(test)]
#[path = "inline.rs"]
mod inline {}
"#;

        assert_eq!(
            cfg_test_path_modules(Path::new("crate/src/transaction.rs"), source),
            vec![Path::new("crate/src/transaction_tests.rs").to_path_buf()]
        );
    }

    #[test]
    fn production_governance_limits_filesystem_mutation_to_reviewed_modules() {
        let filesystem_write = "std::fs::write(\"object\", b\"body\");";
        for reviewed in [
            "crates/kitrove-core/src/object_mutation.rs",
            "crates/kitrove-core/src/quarantine_cleanup/batch.rs",
            "crates/kitrove-installer/src/unix_staging.rs",
            "crates/kitrove-installer/src/windows_staging.rs",
            "crates/kitrove-installer/src/unix_install.rs",
            "crates/kitrove-installer/src/unix_recovery.rs",
        ] {
            check_production_source(Path::new(reviewed), filesystem_write)
                .expect("only an exact reviewed mutation module owns filesystem writes");
        }
        check_production_source(
            Path::new("crates/kitrove-core/src/object_mutations.rs"),
            filesystem_write,
        )
        .expect_err("similarly named modules receive no mutation authority");
        check_production_source(
            Path::new("crates/kitrove-installer/src/windows_stagings.rs"),
            filesystem_write,
        )
        .expect_err("similarly named installer modules receive no mutation authority");
        check_production_source(
            Path::new("crates/kitrove-core/src/quarantine_cleanup/batches.rs"),
            filesystem_write,
        )
        .expect_err("similarly named cleanup modules receive no mutation authority");
        check_production_source(
            Path::new("crates/kitrove-core/src/object_mutation.rs"),
            "std::process::Command::new(\"sh\");",
        )
        .expect_err("object mutation authority never grants process execution");
    }

    #[test]
    fn production_governance_limits_network_authority_to_reviewed_transports() {
        let network = "ureq::Agent::new_with_defaults();";
        check_production_source(
            Path::new("crates/kitrove-core/src/git_sync_backend.rs"),
            network,
        )
        .expect("the reviewed Git backend owns network access");
        check_production_source(
            Path::new("crates/kitrove-core/src/git_sync_backends.rs"),
            network,
        )
        .expect_err("similarly named modules receive no network authority");
        check_production_source(
            Path::new("crates/kitrove-core/src/ssh_git_transport.rs"),
            "TcpStream::connect(\"example.invalid:22\");",
        )
        .expect("the reviewed SSH transport owns network access");
        check_production_source(
            Path::new("crates/kitrove-core/src/ssh_git_transports.rs"),
            "TcpStream::connect(\"example.invalid:22\");",
        )
        .expect_err("similarly named SSH modules receive no network authority");
        check_production_source(
            Path::new("crates/kitrove-core/src/git_sync_backend.rs"),
            "std::process::Command::new(\"git\");",
        )
        .expect_err("network authority never grants process execution");
    }

    #[test]
    fn production_governance_limits_process_authority_to_version_probe_boundary() {
        let launch = "std::process::Command::new(\"pi\");";
        check_production_source(Path::new("crates/kitrove-version-probe/src/lib.rs"), launch)
            .expect("the reviewed version probe boundary owns bounded process launch");
        check_production_source(
            Path::new("crates/kitrove-version-probe/src/probe.rs"),
            launch,
        )
        .expect_err("adjacent version probe modules receive no process authority");
        check_production_source(Path::new("crates/kitrove-cli/src/version_probe.rs"), launch)
            .expect_err("the CLI composition layer receives no process authority");
    }
}
