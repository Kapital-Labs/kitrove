//! Guided orchestration. All mutations delegate to existing reviewed boundaries.
use std::collections::BTreeSet;
use std::io::{self, BufRead, IsTerminal as _, Write};
use std::path::PathBuf;

use kitrove_adapter_api::ScopeSelection;
use kitrove_agent_skills::CaptureLimits;
use kitrove_core::{
    FilesystemSyncBackend, PolicyRegistry, SshGitSyncBackend, SyncBackend, SyncBackendRead,
    commit_collection_import, plan_collection_import,
};
use kitrove_model::{AssetId, ContentHash, HarnessId, HarnessScope, MachineId, SyncLimits};

use crate::args::{
    AdoptArgs, CliError, EnvironmentArgs, GitCredentialSource, InitArgs, MaterializeArgs, ScanArgs,
    SyncArgs, SyncRemoteArgs, tier_one_harnesses,
};
use crate::portable::{load_manifest, run_adopt, run_status};
use crate::scan::{resolve_required_environment_root, resolve_required_state_root, scan_report};
use crate::scan_display::{name, safe, selectable};

struct Dialog<R, W> {
    input: R,
    output: W,
}

impl<R: BufRead, W: Write> Dialog<R, W> {
    fn report(&mut self, text: &str) -> Result<(), CliError> {
        for line in text.lines() {
            self.say(&safe(line))?;
        }
        Ok(())
    }

    fn confirm_plan(&mut self, plan: &str) -> Result<bool, CliError> {
        self.summary(plan)?;
        self.confirm("Proceed with this plan?")
    }

    fn summary(&mut self, encoded: &str) -> Result<(), CliError> {
        let value: serde_json::Value = serde_json::from_str(encoded).map_err(|_| io_error())?;
        self.say(&human_summary(&value, 0))
    }

    fn say(&mut self, message: &str) -> Result<(), CliError> {
        writeln!(self.output, "{message}").map_err(|_| io_error())
    }

    fn ask(&mut self, message: &str) -> Result<String, CliError> {
        self.say(message)?;
        self.output.flush().map_err(|_| io_error())?;
        let mut bytes = Vec::new();
        // Bound input without reading an unlimited line, and never accept EOF as consent.
        loop {
            let available = self.input.fill_buf().map_err(|_| io_error())?;
            if available.is_empty() {
                return Err(cancelled());
            }
            let count = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |n| n + 1);
            if bytes.len() + count > 8192 {
                return Err(CliError::new(
                    "setup.input_limit",
                    "input line is too long; completed steps are retained",
                ));
            }
            bytes.extend_from_slice(&available[..count]);
            self.input.consume(count);
            if bytes.last() == Some(&b'\n') {
                break;
            }
        }
        let value = String::from_utf8(bytes).map_err(|_| io_error())?;
        let value = value.trim();
        if value == "q" {
            return Err(cancelled());
        }
        if value.chars().any(char::is_control) {
            return Err(io_error());
        }
        Ok(value.to_owned())
    }

    fn confirm(&mut self, message: &str) -> Result<bool, CliError> {
        Ok(self.ask(&format!(
            "{message}\nType yes to confirm; Enter skips; q stops."
        ))? == "yes")
    }

    fn choose(&mut self, message: &str, labels: &[String]) -> Result<Vec<usize>, CliError> {
        self.say(message)?;
        for (index, label) in labels.iter().enumerate() {
            self.say(&format!("  {}. {}", index + 1, safe(label)))?;
        }
        loop {
            let response =
                self.ask("Select numbers separated by commas, all, or Enter to skip (q stops):")?;
            match selection(&response, labels.len()) {
                Some(indices) => return Ok(indices),
                None => self.say("Choose only numbers shown above. Nothing has changed.")?,
            }
        }
    }
}

fn selection(value: &str, length: usize) -> Option<Vec<usize>> {
    if value.is_empty() {
        return Some(Vec::new());
    }
    if value == "all" {
        return Some((0..length).collect());
    }
    let mut chosen = BTreeSet::new();
    for part in value.split(',') {
        let number = part.trim().parse::<usize>().ok()?;
        if number == 0 || number > length {
            return None;
        }
        chosen.insert(number - 1);
    }
    Some(chosen.into_iter().collect())
}

pub(crate) fn entry(environment: Option<PathBuf>, configure: bool) -> u8 {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        eprintln!(
            "Guided setup needs an interactive terminal. For scripts use init --environment PATH --machine-id NAME, scan --json, adopt, plan and apply."
        );
        return 2;
    }
    let mut dialog = Dialog {
        input: io::stdin().lock(),
        output: io::stdout(),
    };
    let result = crate::registry::try_tier_one_registry()
        .map_err(|_| io_error())
        .and_then(|registry| run(&mut dialog, environment, configure, &registry));
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!(
                "error[{}]: {error}\nPreviously confirmed steps are retained. No later step ran.",
                error.code
            );
            1
        }
    }
}

fn default_collection() -> Result<PathBuf, CliError> {
    // This is a displayed suggestion, never filesystem authority until confirmed.
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .ok_or_else(io_error)?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err(io_error());
    }
    Ok(home.join("Kitrove"))
}

fn run<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    environment: Option<PathBuf>,
    configure: bool,
    registry: &PolicyRegistry,
) -> Result<(), CliError> {
    dialog.say("Kitrove setup\nCredentials, trust and deployment receipts stay on this computer.\nEach change has its own confirmation. Type q at any prompt to stop.")?;
    let start = if configure {
        String::new()
    } else {
        loop {
            let choice = dialog.ask("How would you like to start?\n  1. Set up my first computer\n  2. Connect a second computer to the whole collection\n  3. Import specific items on a second computer\n  4. Combine this computer's skills with an existing collection\n  5. Inspect this computer without changing anything\nChoose 1-5:")?;
            if matches!(choice.as_str(), "1" | "2" | "3" | "4" | "5") {
                break choice;
            }
            dialog.say("Choose a number from 1 to 5.")?;
        }
    };
    if start == "5" {
        let report = scan_report(
            ScanArgs {
                harnesses: tier_one_harnesses(),
                scope: ScopeSelection::User,
                project_root: None,
                roots: Vec::new(),
                environment: None,
                json: false,
                verbose: false,
            },
            registry,
        )?;
        return dialog.say(&crate::scan_display::render(&report));
    }
    let root = if configure {
        let suggested = match environment {
            Some(root) => resolve_required_environment_root(Some(&root))?,
            None => match resolve_required_environment_root(None) {
                Ok(root) => root,
                Err(error) if error.code == "cli.environment_missing" => default_collection()?,
                Err(error) => return Err(error),
            },
        };
        let response = dialog.ask(&format!(
            "Existing collection path [{}]:",
            safe(&suggested.display().to_string())
        ))?;
        resolve_required_environment_root(Some(&if response.is_empty() {
            suggested
        } else {
            PathBuf::from(response)
        }))?
    } else {
        let suggestion = default_collection()?;
        let response = dialog.ask(&format!(
            "Where should your portable collection live? [{}]",
            safe(&suggestion.display().to_string())
        ))?;
        let root = if response.is_empty() {
            suggestion
        } else {
            PathBuf::from(response)
        };
        let root = if root.is_absolute() {
            root
        } else {
            std::env::current_dir().map_err(|_| io_error())?.join(root)
        };
        let machine = dialog.ask("Name this computer (for example mac-mini):")?;
        let machine = MachineId::parse(machine).map_err(|_| {
            CliError::new(
                "setup.machine_invalid",
                "choose a valid machine name using lowercase letters, digits and hyphens",
            )
        })?;
        let local = resolve_required_state_root()?;
        if !dialog.confirm(&format!("Create an empty collection at {}\nLocal-only state at {}\nExisting agent files will not be changed.", safe(&root.display().to_string()), safe(&local.display().to_string())))? { return Ok(()); }
        let completed = crate::init::run_init(
            InitArgs {
                machine_id: Some(machine),
                project_root: None,
                environment: Some(root.clone()),
                json: false,
            },
            registry,
        )?;
        dialog.report(&completed.output)?;
        root
    };
    let status = run_status(EnvironmentArgs {
        environment: Some(root.clone()),
        json: false,
    })?;
    if status.status != 0 {
        dialog.report(&status.output)?;
        return Err(CliError::new(
            "setup.collection_attention",
            "collection needs attention; use status before continuing",
        ));
    }
    match start.as_str() {
        "1" => collect(dialog, &root, registry)?,
        "2" => synchronize(dialog, &root)?,
        "3" => import(dialog, &root)?,
        "4" => {
            dialog.say("First connect this empty collection to the existing one. Then select local skills to add, and review publishing those additions. Existing agent files remain untouched.")?;
            let backend = remote(dialog)?;
            if synchronize_with(dialog, &root, backend.clone())? {
                collect(dialog, &root, registry)?;
                synchronize_with(dialog, &root, backend)?;
            }
        }
        _ => {}
    }
    loop {
        dialog.say("\nWhat would you like to do?\n  1. Collect skills from this computer\n  2. Connect / sync the whole collection (bidirectional)\n  3. Import specific items from another collection (one-time)\n  4. Apply selected items to tools on this computer\n  5. Finish\nFor an empty second-computer collection, connect with 2 before collecting local additions. Selective import can combine items without establishing ongoing sync. Conflicts stop without choosing a winner.")?;
        match dialog.ask("Choose 1-5 [5]:")?.as_str() {
            "1" => collect(dialog, &root, registry)?,
            "2" => synchronize(dialog, &root)?,
            "3" => import(dialog, &root)?,
            "4" => apply(dialog, &root)?,
            "" | "5" => break,
            _ => dialog.say("Choose a number from 1 to 5.")?,
        }
    }
    dialog.say(&format!("\nSetup finished. Collection: {}\nNothing runs in the background. Revisit with kitrove configure --environment PATH.\nOn another computer, install Kitrove, run kitrove init, then choose connect or selective import.\nNo credentials, trust decisions or harness installations are cloned.", safe(&root.display().to_string())))
}

fn collect<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    registry: &PolicyRegistry,
) -> Result<(), CliError> {
    let report = scan_report(
        ScanArgs {
            harnesses: tier_one_harnesses(),
            scope: ScopeSelection::User,
            project_root: None,
            roots: Vec::new(),
            environment: Some(root.to_owned()),
            json: false,
            verbose: false,
        },
        registry,
    )?;
    dialog.say(&crate::scan_display::render(&report))?;
    let candidates: Vec<_> = report.entries.iter().filter(|e| selectable(e)).collect();
    let labels: Vec<_> = candidates
        .iter()
        .map(|e| format!("{} ({}, {:?})", name(e), e.harness.as_str(), e.scope))
        .collect();
    'skills: for index in dialog.choose(
        "Select skills to collect. Originals remain unchanged.",
        &labels,
    )? {
        let entry = candidates[index];
        let id = loop {
            let response = dialog.ask(&format!(
                "Collection name for {} [{}] (type - to skip this skill):",
                safe(name(entry)),
                safe(name(entry))
            ))?;
            if response == "-" {
                continue 'skills;
            }
            let id = match AssetId::parse(if response.is_empty() {
                name(entry).to_owned()
            } else {
                response
            }) {
                Ok(id) => id,
                Err(_) => {
                    dialog.say("Choose a valid item name using letters, digits and hyphens.")?;
                    continue;
                }
            };
            let current = load_manifest(root)?;
            if current.assets.contains_key(&id) || current.packs.contains_key(&id) {
                dialog.say("That collection name is already in use. Choose a different name to keep both, or - to skip. Nothing is overwritten.")?;
                continue;
            }
            break id;
        };
        let args = AdoptArgs {
            observation_id: entry
                .observation_id
                .as_ref()
                .expect("selectable")
                .as_str()
                .to_owned(),
            asset_id: Some(id),
            update_asset_id: None,
            expected_prior: None,
            binding: None,
            harnesses: BTreeSet::from([entry.harness.clone()]),
            scope: ScopeSelection::User,
            project_root: None,
            roots: Vec::new(),
            environment: Some(root.to_owned()),
            json: true,
        };
        let mut prompt_error = None;
        let result = run_adopt(args, registry, |plan| match dialog.confirm_plan(plan) {
            Ok(yes) => yes,
            Err(error) => {
                prompt_error = Some(error);
                false
            }
        });
        if let Some(error) = prompt_error {
            return Err(error);
        }
        match result {
            Ok(done) => dialog.summary(&done.output)?,
            Err(error) if error.code == "adoption.confirmation_required" => {
                dialog.say("Skipped this skill.")?
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn remote<R: BufRead, W: Write>(dialog: &mut Dialog<R, W>) -> Result<SyncRemoteArgs, CliError> {
    dialog.say("Use an existing Kitrove sync backend, not an arbitrary Git checkout.\n1. Filesystem/shared directory\n2. HTTPS Git\n3. SSH Git\nCredentials are handled by the existing Git provider, never stored in the collection.")?;
    match dialog.ask("Backend 1-3:")?.as_str() {
        "1" => Ok(SyncRemoteArgs::Filesystem(PathBuf::from(
            dialog.ask("Existing backend directory:")?,
        ))),
        "2" => Ok(SyncRemoteArgs::Git {
            url: dialog.ask("HTTPS URL without embedded credentials:")?,
            credentials: GitCredentialSource::Terminal,
        }),
        "3" => Ok(SyncRemoteArgs::Ssh {
            url: dialog.ask("SSH URL:")?,
            known_hosts: PathBuf::from(dialog.ask("Known-hosts file path:")?),
        }),
        _ => Err(CliError::new(
            "setup.backend_invalid",
            "choose a supported backend",
        )),
    }
}

fn synchronize<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
) -> Result<(), CliError> {
    let remote = remote(dialog)?;
    synchronize_with(dialog, root, remote).map(|_| ())
}

fn synchronize_with<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    remote: SyncRemoteArgs,
) -> Result<bool, CliError> {
    dialog.say("Full sync combines portable collections with shared history and can publish local items to the remote. It does not apply anything to agent tools. Unrelated nonempty collections and same-item conflicts block. No background sync is enabled.")?;
    let planned = crate::sync::run_sync_plan(SyncArgs {
        remote: remote.clone(),
        environment: Some(root.to_owned()),
        confirm: None,
        json: true,
    })?;
    if planned.status != 0 {
        dialog.report(&planned.output)?;
        return Ok(false);
    }
    let value: serde_json::Value = serde_json::from_str(&planned.output).map_err(|_| io_error())?;
    let digest = ContentHash::parse(value["plan_digest"].as_str().ok_or_else(io_error)?)
        .map_err(|_| io_error())?;
    dialog.summary(&planned.output)?;
    let summary = format!(
        "Sync action: {}\nUpload objects: {}\nDownload objects: {}\nConfirm bidirectional synchronization?",
        value["disposition"], value["upload_objects"], value["download_objects"]
    );
    if !dialog.confirm(&summary)? {
        return Ok(false);
    }
    let result = crate::sync::run_sync_apply(SyncArgs {
        remote,
        environment: Some(root.to_owned()),
        confirm: Some(digest),
        json: false,
    })?;
    dialog.report(&result.output)?;
    Ok(result.status == 0)
}

fn import<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
) -> Result<(), CliError> {
    dialog.say("Selective import is a one-time copy, not ongoing selective sync. The remote is not modified. Differing local identities refuse the import.")?;
    match remote(dialog)? {
        SyncRemoteArgs::Filesystem(path) => import_backend(
            dialog,
            root,
            FilesystemSyncBackend::open(&path).map_err(crate::sync::backend_error)?,
        ),
        SyncRemoteArgs::Git { url, credentials } => import_backend(
            dialog,
            root,
            crate::sync::open_git_backend(&url, credentials)?,
        ),
        SyncRemoteArgs::Ssh { url, known_hosts } => import_backend(
            dialog,
            root,
            SshGitSyncBackend::open(&url, known_hosts).map_err(crate::sync::backend_error)?,
        ),
    }
}

fn import_backend<R: BufRead, W: Write, B: SyncBackend>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    backend: B,
) -> Result<(), CliError> {
    let limits = SyncLimits::default();
    let mut read = backend
        .begin_read(limits)
        .map_err(crate::sync::backend_error)?;
    let history = read
        .inspect_history(limits)
        .map_err(crate::sync::backend_error)?;
    let head = history.snapshots().first().ok_or_else(|| {
        CliError::new(
            "setup.remote_empty",
            "remote has no published collection yet",
        )
    })?;
    let manifest = head.snapshot().manifest();
    let items: Vec<_> = manifest
        .assets
        .keys()
        .chain(manifest.packs.keys())
        .cloned()
        .collect();
    let labels: Vec<_> = items
        .iter()
        .map(|id| {
            format!(
                "{} ({})",
                id.as_str(),
                if manifest.packs.contains_key(id) {
                    "pack, includes members"
                } else {
                    "asset"
                }
            )
        })
        .collect();
    let selected: BTreeSet<_> = dialog
        .choose("Choose remote items:", &labels)?
        .into_iter()
        .map(|i| items[i].clone())
        .collect();
    if selected.is_empty() {
        return Ok(());
    }
    let current = load_manifest(root)?;
    let plan = plan_collection_import(&current, &history, &selected)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let mut objects = Vec::new();
    for descriptor in plan.required_objects() {
        let object = read
            .fetch_object(descriptor, limits)
            .map_err(crate::sync::backend_error)?;
        if object.descriptor() != descriptor {
            return Err(io_error());
        }
        objects.push(object);
    }
    if read
        .inspect_history(limits)
        .map_err(crate::sync::backend_error)?
        != history
    {
        return Err(CliError::new(
            "setup.remote_changed",
            "remote changed during import planning; inspect again",
        ));
    }
    drop(read);
    for (id, asset) in &plan.proposed_manifest().assets {
        if current.assets.get(id) != Some(asset) {
            dialog.say(&format!(
                "  {}: {:?}; {:?}; {} native variants",
                id.as_str(),
                asset.kind,
                asset.content_class,
                asset.native_variants.len()
            ))?;
            for (target, fidelity) in &asset.compatibility {
                dialog.say(&format!(
                    "    {}: {:?}",
                    target.as_str(),
                    fidelity.fidelity()
                ))?;
            }
        }
    }
    let chosen = selected
        .iter()
        .map(AssetId::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if !dialog.confirm(&format!("Import {chosen} and required pack members ({} verified objects)?\nNative content and provenance remain intact. Nothing is applied or trusted for execution.", objects.len()))? { return Ok(()); }
    commit_collection_import(&plan, &objects, root, CaptureLimits::default())
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    dialog.say("Selected items imported. Choose Apply separately when ready.")
}

fn apply<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
) -> Result<(), CliError> {
    let manifest = load_manifest(root)?;
    let items: Vec<_> = manifest
        .assets
        .keys()
        .chain(manifest.packs.keys())
        .cloned()
        .collect();
    let labels: Vec<_> = items.iter().map(|id| id.as_str().to_owned()).collect();
    let selected = dialog.choose("Choose collection items to apply:", &labels)?;
    if selected.is_empty() {
        return Ok(());
    }
    let harnesses = [
        HarnessId::Claude,
        HarnessId::Codex,
        HarnessId::Pi,
        HarnessId::OpenCode,
    ];
    let labels = harnesses
        .iter()
        .map(|h| h.as_str().to_owned())
        .collect::<Vec<_>>();
    let targets: BTreeSet<_> = dialog
        .choose("Choose destination tools (user scope):", &labels)?
        .into_iter()
        .map(|i| harnesses[i].clone())
        .collect();
    if targets.is_empty() {
        return Ok(());
    }
    let mut binaries = Vec::new();
    for target in &targets {
        if matches!(target, HarnessId::Pi | HarnessId::OpenCode) {
            dialog.say("This tool requires explicit version evidence. Planning may run the selected local executable's bounded version probe; no upstream code or dependencies are installed.")?;
            let path = dialog.ask(&format!(
                "Absolute trusted {} executable path (Enter cancels application):",
                target.as_str()
            ))?;
            if path.is_empty() {
                return Ok(());
            }
            binaries.push(PathBuf::from(path));
        }
    }
    let mut args = MaterializeArgs {
        profile: None,
        assets: BTreeSet::new(),
        packs: BTreeSet::new(),
        targets,
        scope: HarnessScope::User,
        project_root: None,
        version_binaries: binaries,
        environment: Some(root.to_owned()),
        json: true,
    };
    for i in selected {
        if manifest.packs.contains_key(&items[i]) {
            args.packs.insert(items[i].clone());
        } else {
            args.assets.insert(items[i].clone());
        }
    }
    let mut prompt_error = None;
    let result = crate::materialize::run_apply(args, |plan| match dialog.confirm_plan(plan) {
        Ok(yes) => yes,
        Err(error) => {
            prompt_error = Some(error);
            false
        }
    });
    if let Some(error) = prompt_error {
        return Err(error);
    }
    match result {
        Ok(done) => dialog.summary(&done.output),
        Err(error) if error.code == "apply.confirmation_required" => {
            dialog.say("Application skipped.")
        }
        Err(error) => Err(error),
    }
}

fn human_summary(value: &serde_json::Value, indent: usize) -> String {
    let padding = " ".repeat(indent);
    match value {
        serde_json::Value::Object(fields) => fields
            .iter()
            .filter(|(key, _)| {
                !matches!(
                    key.as_str(),
                    "schema_version"
                        | "plan_digest"
                        | "batch_digest"
                        | "observation_id"
                        | "asset_revision"
                        | "rendered_hash"
                )
            })
            .map(|(key, value)| {
                let label = safe(&key.replace('_', " "));
                if value.is_object() || value.is_array() {
                    format!("{padding}{label}:\n{}", human_summary(value, indent + 2))
                } else {
                    format!("{padding}{label}: {}\n", human_summary(value, 0).trim_end())
                }
            })
            .collect(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| human_summary(item, indent))
            .collect(),
        serde_json::Value::String(text) => format!("{padding}{}\n", safe(text)),
        _ => format!("{padding}{value}\n"),
    }
}

fn cancelled() -> CliError {
    CliError::new(
        "setup.cancelled",
        "setup stopped; previously confirmed steps are retained",
    )
}
fn io_error() -> CliError {
    CliError::new(
        "setup.input_output",
        "setup could not safely read input or write output",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only the Rust test executable contains this scripted entry. Shipping setup
    // still requires a terminal; tests isolate environment variables in a child.
    #[test]
    #[ignore = "invoked by isolated parent fixtures"]
    fn scripted_child() {
        let input = std::env::var("KITROVE_TEST_SETUP_INPUT").unwrap();
        let configure = std::env::var("KITROVE_TEST_CONFIGURE").unwrap() == "true";
        let environment = std::env::var_os("KITROVE_TEST_COLLECTION").map(PathBuf::from);
        let mut dialog = Dialog {
            input: io::Cursor::new(input),
            output: Vec::new(),
        };
        let result = run(
            &mut dialog,
            environment,
            configure,
            &crate::tier_one_registry(),
        );
        println!("{}", String::from_utf8(dialog.output).unwrap());
        let expected = std::env::var("KITROVE_TEST_EXPECT_ERROR").unwrap_or_default();
        if expected.is_empty() {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err().code, expected);
        }
    }

    fn machine(root: &std::path::Path, name: &str) -> PathBuf {
        let path = root.join(name);
        std::fs::create_dir_all(path.join("home/.claude/skills")).unwrap();
        std::fs::create_dir_all(path.join("working")).unwrap();
        path
    }

    fn skill(machine: &std::path::Path, name: &str, body: &str) {
        let directory = machine.join("home/.claude/skills").join(name);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: A test skill.\n---\n{body}\n"),
        )
        .unwrap();
    }

    fn script(machine: &std::path::Path, input: &str, configure: bool, expected: &str) -> String {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "setup::tests::scripted_child",
                "--ignored",
                "--nocapture",
            ])
            .current_dir(machine.join("working"))
            .env("HOME", machine.join("home"))
            .env("USERPROFILE", machine.join("home"))
            .env("LOCALAPPDATA", machine.join("local"))
            .env("KITROVE_STATE_HOME", machine.join("state"))
            .env_remove("KITROVE_ENV")
            .env_remove("XDG_DATA_HOME")
            .env("KITROVE_TEST_SETUP_INPUT", input)
            .env("KITROVE_TEST_CONFIGURE", configure.to_string())
            .env("KITROVE_TEST_COLLECTION", machine.join("collection"))
            .env("KITROVE_TEST_EXPECT_ERROR", expected)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn manifest(machine: &std::path::Path) -> kitrove_model::EnvironmentManifest {
        load_manifest(&machine.join("collection")).unwrap()
    }

    #[test]
    fn first_second_and_selective_computers_preserve_native_content_and_local_identity() {
        let tmp = kitrove_testkit::trusted_tempdir(".setup-machines-");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let a = machine(&root, "a");
        let b = machine(&root, "b");
        let c = machine(&root, "c");
        let remote = root.join("remote");
        std::fs::create_dir(&remote).unwrap();
        skill(&a, "alpha", "Preserve alpha instructions.");
        skill(&a, "beta", "Preserve beta instructions.");
        let original = std::fs::read(a.join("home/.claude/skills/alpha/SKILL.md")).unwrap();
        let input = format!(
            "1\n{}\nmachine-a\nyes\n1,2\n\nyes\n\nyes\n2\n1\n{}\nyes\n5\n",
            a.join("collection").display(),
            remote.display()
        );
        script(&a, &input, false, "");
        assert_eq!(manifest(&a).assets.len(), 2);
        assert_eq!(
            std::fs::read(a.join("home/.claude/skills/alpha/SKILL.md")).unwrap(),
            original
        );
        let input = format!(
            "2\n{}\nmachine-b\nyes\n1\n{}\nyes\n5\n",
            b.join("collection").display(),
            remote.display()
        );
        script(&b, &input, false, "");
        assert_eq!(manifest(&a), manifest(&b));
        assert!(
            !b.join("home/.agents/skills/alpha").exists(),
            "sync must not apply"
        );
        let input = format!(
            "3\n{}\nmachine-c\nyes\n1\n{}\n1\nyes\n5\n",
            c.join("collection").display(),
            remote.display()
        );
        script(&c, &input, false, "");
        let imported = manifest(&c);
        assert_eq!(imported.assets.len(), 1);
        assert_eq!(
            imported.assets.values().next(),
            manifest(&a).assets.values().next()
        );
        let local = std::fs::read_to_string(c.join("state/state.json")).unwrap();
        assert!(local.contains("machine-c"));
        assert!(!local.contains("machine-a"));
        script(&c, "\n4\n1\n2\n\n5\n", true, "");
        assert!(!c.join("home/.agents/skills/alpha").exists());
        // Configure applies only the selected item, using receipt-backed normal APIs.
        script(&c, "\n4\n1\n2\nyes\n5\n", true, "");
        assert!(c.join("home/.agents/skills/alpha/SKILL.md").is_file());
        assert!(!c.join("home/.agents/skills/beta").exists());
        // A second computer can start with its own independent skill, then merge.
        let d = machine(&root, "d");
        skill(
            &d,
            "gamma",
            "Keep this computer's independent instructions.",
        );
        script(
            &d,
            &format!(
                "4\n{}\nmachine-d\nyes\n1\n{}\nyes\n1\n\nyes\nyes\n5\n",
                d.join("collection").display(),
                remote.display()
            ),
            false,
            "",
        );
        assert_eq!(manifest(&d).assets.len(), 3);
        script(
            &a,
            &format!("\n2\n1\n{}\nyes\n5\n", remote.display()),
            true,
            "",
        );
        assert_eq!(manifest(&a), manifest(&d));
        assert!(!a.join("home/.claude/skills/gamma").exists());
    }

    #[test]
    fn cancellation_and_inspection_do_not_initialize() {
        let tmp = kitrove_testkit::trusted_tempdir(".setup-cancel-");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let a = machine(&root, "a");
        script(&a, "5\n", false, "");
        assert!(!a.join("state").exists());
        assert!(!a.join("collection").exists());
        script(
            &a,
            &format!("1\n{}\nmachine-a\n", a.join("collection").display()),
            false,
            "setup.cancelled",
        );
        assert!(!a.join("state").exists());
        assert!(!a.join("collection").exists());
        script(
            &a,
            &format!("1\n{}\nmachine-a\n\n", a.join("collection").display()),
            false,
            "",
        );
        assert!(!a.join("state").exists());
    }

    #[test]
    fn default_collection_inside_home_can_apply_to_the_same_home() {
        let tmp = kitrove_testkit::trusted_tempdir(".setup-default-");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let a = machine(&root, "a");
        skill(&a, "example", "Default-home fixture instructions.");
        script(&a, "1\n\na\nyes\n1\n\nyes\n4\n1\n2\nyes\n5\n", false, "");
        assert!(a.join("home/Kitrove/kitrove.toml").is_file());
        assert!(a.join("home/.agents/skills/example/SKILL.md").is_file());
    }

    #[test]
    fn selective_import_cancellation_and_collisions_preserve_both_collections() {
        let tmp = kitrove_testkit::trusted_tempdir(".setup-refusals-");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let a = machine(&root, "a");
        let b = machine(&root, "b");
        let remote = root.join("remote");
        std::fs::create_dir(&remote).unwrap();
        skill(&a, "alpha", "Remote content");
        skill(&b, "alpha", "Different local content");
        script(
            &a,
            &format!(
                "1\n{}\na\nyes\n1\n\nyes\n2\n1\n{}\nyes\n5\n",
                a.join("collection").display(),
                remote.display()
            ),
            false,
            "",
        );
        script(
            &b,
            &format!("1\n{}\nb\nyes\n\n5\n", b.join("collection").display()),
            false,
            "",
        );
        let before = manifest(&b);
        script(&b, "\n1\n1\n\n\n5\n", true, "");
        assert_eq!(manifest(&b), before);
        script(
            &b,
            &format!("\n3\n1\n{}\nall\n\n5\n", remote.display()),
            true,
            "",
        );
        assert_eq!(manifest(&b), before);
        script(&b, "\n1\n1\n\nyes\n5\n", true, "");
        let local = manifest(&b);
        let source = manifest(&a);
        script(
            &b,
            &format!("\n3\n1\n{}\nall\n", remote.display()),
            true,
            "collection.identity_conflict",
        );
        assert_eq!(manifest(&b), local);
        assert_eq!(manifest(&a), source);
        // Full sync also refuses to choose a winner, and returns to the menu.
        let output = script(&b, &format!("\n2\n1\n{}\n5\n", remote.display()), true, "");
        assert!(output.contains("blocked"));
        assert_eq!(manifest(&b), local);
    }
    #[test]
    fn selections_are_bounded_and_explicit() {
        assert_eq!(selection("", 3), Some(vec![]));
        assert_eq!(selection("all", 3), Some(vec![0, 1, 2]));
        assert_eq!(selection("3,1,1", 3), Some(vec![0, 2]));
        for invalid in ["0", "4", "-1", "1,", "yes"] {
            assert_eq!(selection(invalid, 3), None);
        }
    }
    #[test]
    fn eof_cancel_and_controls_never_confirm() {
        for input in ["", "yes", "q\n", "yes\u{1b}\n"] {
            let mut dialog = Dialog {
                input: io::Cursor::new(input),
                output: Vec::new(),
            };
            assert!(dialog.confirm("change?").is_err());
        }
        let mut dialog = Dialog {
            input: io::Cursor::new("\n"),
            output: Vec::new(),
        };
        assert!(!dialog.confirm("change?").unwrap());
    }

    #[test]
    fn summaries_escape_untrusted_lines_and_input_is_bounded() {
        let summary = human_summary(
            &serde_json::json!({
                "path": "skill\nProceed with this plan?\u{1b}[2J",
                "disposition": "blocked",
                "reasons": ["unmanaged destination"],
                "plan_digest": "not user-facing"
            }),
            0,
        );
        assert!(summary.contains("\\nProceed"));
        assert!(!summary.contains('\u{1b}'));
        assert!(summary.contains("blocked"));
        assert!(summary.contains("unmanaged destination"));
        assert!(!summary.contains("not user-facing"));
        let mut dialog = Dialog {
            input: io::Cursor::new(format!("{}\n", "x".repeat(8192))),
            output: Vec::new(),
        };
        assert_eq!(dialog.ask("input").unwrap_err().code, "setup.input_limit");
    }
}
