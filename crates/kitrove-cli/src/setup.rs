//! Guided orchestration. All mutations delegate to existing reviewed boundaries.
use std::collections::BTreeSet;
use std::io::{self, BufRead, IsTerminal as _, Write};
use std::path::PathBuf;

use kitrove_adapter_api::ScopeSelection;
use kitrove_agent_skills::CaptureLimits;
use kitrove_core::{
    FilesystemSyncBackend, GitRemoteUrl, PolicyRegistry, SshGitRemoteUrl, SshGitSyncBackend,
    SyncBackend, SyncBackendRead, commit_collection_import, plan_collection_import,
};
use kitrove_model::{AssetId, ContentHash, HarnessId, HarnessScope, MachineId, SyncLimits};

use crate::args::{
    AdoptArgs, CliError, EnvironmentArgs, GitCredentialSource, InitArgs, MaterializeArgs, ScanArgs,
    SyncArgs, SyncRemoteArgs, tier_one_harnesses,
};
use crate::portable::{load_manifest, run_adopt, run_status};
use crate::scan::{resolve_required_environment_root, resolve_required_state_root, scan_report};
use crate::scan_display::{name, safe, selectable};

mod collection;
mod collection_selection;
mod initialization;
mod inventory;
mod menu_input;
mod presentation;

pub(crate) use inventory::browse_scan;

trait PromptInput {
    fn with_reader<T>(&mut self, read: impl FnOnce(&mut dyn BufRead) -> T) -> T;
}

impl<R: BufRead> PromptInput for R {
    fn with_reader<T>(&mut self, read: impl FnOnce(&mut dyn BufRead) -> T) -> T {
        read(self)
    }
}

struct TerminalInput(io::Stdin);

impl PromptInput for TerminalInput {
    fn with_reader<T>(&mut self, read: impl FnOnce(&mut dyn BufRead) -> T) -> T {
        // An operation can prompt for Git credentials after this setup prompt.
        read(&mut self.0.lock())
    }
}

struct Dialog<R, W> {
    input: R,
    output: W,
    color: bool,
    single_key: bool,
}

impl Dialog<TerminalInput, io::Stdout> {
    fn terminal() -> Self {
        Self {
            input: TerminalInput(io::stdin()),
            output: io::stdout(),
            color: presentation::detect(io::stdout().is_terminal()),
            single_key: true,
        }
    }
}

impl<R: PromptInput, W: Write> Dialog<R, W> {
    fn menu(&mut self, message: &str, default_finish: bool) -> Result<String, CliError> {
        self.decision(
            &format!("{message}\nPress 1-5 (no Enter needed); q stops."),
            b"12345",
            default_finish,
        )
    }

    fn decision(
        &mut self,
        message: &str,
        keys: &[u8],
        accept_enter: bool,
    ) -> Result<String, CliError> {
        if !self.single_key {
            return self.ask(message);
        }
        // A key queued before this question is not consent for its new preview.
        menu_input::discard_pending().map_err(|_| io_error())?;
        presentation::prompt(&mut self.output, self.color, message).map_err(|_| io_error())?;
        self.output.flush().map_err(|_| io_error())?;
        let mut mode = menu_input::Mode::enter().map_err(|_| io_error())?;
        let answer = self
            .input
            .with_reader(|reader| menu_input::read(reader, keys, accept_enter));
        let discarded = menu_input::discard_pending();
        // Restore before any next prompt, output or operation, including cancellation.
        mode.restore().map_err(|_| io_error())?;
        discarded.map_err(|_| io_error())?;
        writeln!(self.output, "{}", answer.as_deref().unwrap_or_default())
            .map_err(|_| io_error())?;
        answer
    }

    fn report(&mut self, text: &str) -> Result<(), CliError> {
        let text = text.lines().map(safe).collect::<Vec<_>>().join("\n");
        presentation::block(&mut self.output, self.color, "Command output", &text)
            .map_err(|_| io_error())
    }

    fn confirm_plan(&mut self, plan: &str) -> Result<bool, CliError> {
        self.summary(plan)?;
        self.confirm("Proceed with this plan?")
    }

    fn summary(&mut self, encoded: &str) -> Result<(), CliError> {
        let value: serde_json::Value = serde_json::from_str(encoded).map_err(|_| io_error())?;
        presentation::block(
            &mut self.output,
            self.color,
            "Preview (no changes yet)",
            &human_summary(&value, 0),
        )
        .map_err(|_| io_error())
    }

    fn outcome(&mut self, encoded: &str) -> Result<(), CliError> {
        let value: serde_json::Value = serde_json::from_str(encoded).map_err(|_| io_error())?;
        presentation::block(
            &mut self.output,
            self.color,
            "Result",
            &human_summary(&value, 0),
        )
        .map_err(|_| io_error())
    }

    fn heading(&mut self, message: &str) -> Result<(), CliError> {
        writeln!(self.output).map_err(|_| io_error())?;
        presentation::styled(
            &mut self.output,
            self.color,
            presentation::Tone::Heading,
            message,
        )
        .map_err(|_| io_error())?;
        writeln!(self.output).map_err(|_| io_error())
    }

    fn hint(&mut self, message: &str) -> Result<(), CliError> {
        presentation::styled(
            &mut self.output,
            self.color,
            presentation::Tone::Hint,
            message,
        )
        .map_err(|_| io_error())?;
        writeln!(self.output).map_err(|_| io_error())
    }

    fn success(&mut self, message: &str) -> Result<(), CliError> {
        presentation::notice(
            &mut self.output,
            self.color,
            presentation::Tone::Success,
            "Completed",
            message,
        )
        .map_err(|_| io_error())
    }

    fn warning(&mut self, message: &str) -> Result<(), CliError> {
        presentation::notice(
            &mut self.output,
            self.color,
            presentation::Tone::Warning,
            "Warning",
            message,
        )
        .map_err(|_| io_error())
    }

    fn detail(&mut self, message: &str) -> Result<(), CliError> {
        for line in message.lines() {
            writeln!(self.output, "  | {line}").map_err(|_| io_error())?;
        }
        Ok(())
    }

    fn say(&mut self, message: &str) -> Result<(), CliError> {
        writeln!(self.output, "{message}").map_err(|_| io_error())
    }

    fn ask(&mut self, message: &str) -> Result<String, CliError> {
        presentation::prompt(&mut self.output, self.color, message).map_err(|_| io_error())?;
        self.output.flush().map_err(|_| io_error())?;
        let single_key = self.single_key;
        let bytes = self.input.with_reader(|input| {
            let mut bytes = Vec::new();
            // Bound input without reading an unlimited line, and never accept EOF as consent.
            loop {
                let available = input.fill_buf().map_err(|_| io_error())?;
                if available.is_empty() {
                    return Err(cancelled());
                }
                let count = available
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(available.len(), |n| n + 1);
                let consumed = if single_key && available.get(count - 1) == Some(&b'\n') {
                    // Pasted later answers are not consent for an unseen preview.
                    available.len()
                } else {
                    count
                };
                if bytes.len() + count > 8192 {
                    return Err(CliError::new(
                        "setup.input_limit",
                        "input line is too long; completed steps are retained",
                    ));
                }
                bytes.extend_from_slice(&available[..count]);
                input.consume(consumed);
                if bytes.last() == Some(&b'\n') {
                    break;
                }
            }
            Ok(bytes)
        })?;
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
        loop {
            match self
                .ask(&format!(
                    "{message}\ny/yes confirms; n or Enter skips; q stops."
                ))?
                .to_ascii_lowercase()
                .as_str()
            {
                "y" | "yes" => return Ok(true),
                "" | "n" | "no" => return Ok(false),
                _ => self.say("Choose y to confirm or n to skip. Nothing has changed.")?,
            }
        }
    }

    fn choose(&mut self, message: &str, labels: &[String]) -> Result<Vec<usize>, CliError> {
        let mut prompt = message.to_owned();
        for (index, label) in labels.iter().enumerate() {
            prompt.push_str(&format!("\n{}. {}", index + 1, safe(label)));
        }
        prompt
            .push_str("\nSelect 1,4,7; all; all,-3,-8 (all except); or n/Enter to skip (q stops):");
        loop {
            let response = self.ask(&prompt)?;
            match selection(&response, labels.len()) {
                Some(indices) => return Ok(indices),
                None => self.say("Choose only numbers shown above. Nothing has changed.")?,
            }
        }
    }
}

fn selection(value: &str, length: usize) -> Option<Vec<usize>> {
    if value.is_empty() || value == "n" {
        return Some(Vec::new());
    }
    let mut parts = value.split(',').map(str::trim).peekable();
    let exclude = parts
        .peek()
        .is_some_and(|part| *part == "all" || part.starts_with('-'));
    if parts.peek() == Some(&"all") {
        parts.next();
        if parts.peek().is_none() {
            return Some((0..length).collect());
        }
    }
    let mut chosen = BTreeSet::new();
    for part in parts {
        let digits = if exclude {
            part.strip_prefix('-')?
        } else {
            part
        };
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let number = digits.parse::<usize>().ok()?;
        if number == 0 || number > length {
            return None;
        }
        chosen.insert(number - 1);
    }
    Some(if exclude {
        (0..length)
            .filter(|index| !chosen.contains(index))
            .collect()
    } else {
        chosen.into_iter().collect()
    })
}

pub(crate) fn entry(environment: Option<PathBuf>, configure: bool) -> u8 {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        eprintln!(
            "Guided setup needs an interactive terminal. For scripts use init --environment PATH --machine-id NAME, scan --json, adopt, plan and apply."
        );
        return 2;
    }
    let mut dialog = Dialog::terminal();
    let result = crate::registry::try_tier_one_registry()
        .map_err(|_| io_error())
        .and_then(|registry| run(&mut dialog, environment, configure, &registry));
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = presentation::notice(
                &mut io::stderr().lock(),
                presentation::detect(io::stderr().is_terminal()),
                presentation::Tone::Error,
                "Error",
                &format!(
                    "error[{}]: {error}\nPreviously confirmed steps are retained. No later step ran.",
                    error.code
                ),
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

fn run<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    environment: Option<PathBuf>,
    configure: bool,
    registry: &PolicyRegistry,
) -> Result<(), CliError> {
    dialog.heading("Kitrove setup")?;
    dialog.hint("Credentials, trust and deployment receipts stay on this computer.\nPreview skills together or review individually. Apply and sync are separate approvals.\nType q at any prompt to stop.")?;
    let mut start = if configure {
        String::new()
    } else {
        loop {
            let choice = dialog.menu("How would you like to start?\n  1. Set up my first computer\n  2. Connect a second computer to the whole collection\n  3. Import specific items on a second computer\n  4. Combine this computer's skills with an existing collection\n  5. Inspect this computer without changing anything\nChoose 1-5:", false)?;
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
        return dialog.report(&crate::scan_display::render(&report));
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
        let Some((root, resumed)) = initialization::select(dialog, registry)? else {
            return Ok(());
        };
        if resumed {
            // Resume reaches the ordinary menu, not the selected new-machine action.
            start.clear();
        }
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
        "2" => synchronize(dialog, &root, false)?,
        "3" => import(dialog, &root)?,
        "4" => {
            dialog.say("First connect this empty collection to the existing one. Then select local skills to add, and review publishing those additions. Existing agent files remain untouched.")?;
            if let Some(backend) = remote(dialog, false)?
                && synchronize_with(dialog, &root, backend.clone())?
            {
                collect(dialog, &root, registry)?;
                synchronize_with(dialog, &root, backend)?;
            }
        }
        _ => {}
    }
    loop {
        match dialog.menu("What would you like to do?\n1. Add skills from this computer\n2. Choose skills to add to your AI tools\n3. Share this collection with another computer\n4. Copy selected items from another collection\n5. Finish for now\nChoose 1-5 [5]:", true)?.as_str() {
            "1" => collect(dialog, &root, registry)?,
            "2" => apply(dialog, &root)?,
            "3" => synchronize(dialog, &root, true)?,
            "4" => import(dialog, &root)?,
            "" | "5" => break,
            _ => dialog.say("Choose a number from 1 to 5.")?,
        }
    }
    dialog.success(&format!(
        "Setup finished. Collection: {}",
        safe(&root.display().to_string())
    ))?;
    dialog.hint("Nothing runs in the background. Revisit with kitrove configure --environment PATH.\nNo credentials, trust decisions or harness installations are cloned.")
}

fn collect<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    registry: &PolicyRegistry,
) -> Result<(), CliError> {
    collection::collect(dialog, root, registry)
}

fn remote<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    offer_new_repository: bool,
) -> Result<Option<SyncRemoteArgs>, CliError> {
    dialog.hint(
        "Use a folder or Git repository reserved for Kitrove. Credentials stay on this computer.",
    )?;
    loop {
        match dialog.decision("Where is the shared collection stored?\n1. Shared folder or drive\n2. Git repository\nn. Not now\nChoose 1-2 [n]:", b"12n", true)?.as_str() {
            "" | "n" => return Ok(None),
            "1" => return Ok(Some(SyncRemoteArgs::Filesystem(PathBuf::from(dialog.ask("Shared Kitrove folder path:")?)))),
            "2" => return git_remote(dialog, offer_new_repository),
            _ => dialog.warning("Choose 1, 2 or n. Nothing has changed.")?,
        }
    }
}

fn git_remote<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    offer_new_repository: bool,
) -> Result<Option<SyncRemoteArgs>, CliError> {
    dialog.hint("Paste an HTTPS or ssh:// clone URL without a password or token.")?;
    let prompt = if offer_new_repository {
        "Git repository URL:\n  c   Create a private repository\n  n   Not now (or Enter)\n  q   Quit"
    } else {
        dialog.hint("The repository must already exist for this operation.")?;
        "Git repository URL:\n  n   Not now (or Enter)\n  q   Quit"
    };
    loop {
        let mut url = dialog.ask(prompt)?;
        if matches!(url.as_str(), "" | "n") {
            return Ok(None);
        }
        if url == "c" && offer_new_repository {
            dialog.say("Create an empty private repository on your Git host:\n  1. Open your host's new repository page. For GitHub, use https://github.com/new?visibility=private.\n  2. Select Private. Leave the template, README, .gitignore and license unset.\n  3. Copy the HTTPS or ssh:// clone URL and paste it below.")?;
            continue;
        }
        // Recognize path spellings here, not whether this host can open them.
        if url.starts_with(['/', '\\'])
            || ["./", "../", "~/"]
                .into_iter()
                .any(|prefix| url.starts_with(prefix))
            || (url.as_bytes().get(1) == Some(&b':') && url.as_bytes()[0].is_ascii_alphabetic())
        {
            dialog.warning(
                "Paste a remote repository URL, not a local checkout path. Nothing has changed.",
            )?;
            continue;
        }
        if !url.contains("://") {
            if url
                .split_once(':')
                .is_some_and(|(authority, _)| authority.contains('@') && !authority.contains('/'))
            {
                dialog.warning("Use the ssh:// URL form, not the colon-separated Git address. For example: ssh://git@host/owner/repository.git. Nothing has changed.")?;
                continue;
            }
            let scheme = loop {
                match dialog.decision("How should Kitrove connect?\n1. HTTPS\n2. SSH\nn. Not now\nChoose 1-2 [n]:", b"12n", true)?.as_str() {
                    "" | "n" => return Ok(None),
                    "1" => break "https",
                    "2" => break "ssh",
                    _ => dialog.warning("Choose 1, 2 or n. Nothing has changed.")?,
                }
            };
            url = format!("{scheme}://{url}");
        }
        if GitRemoteUrl::parse(&url).is_ok() {
            dialog.hint(
                "HTTPS selected. The connection may ask for your Git username and access token.",
            )?;
            return Ok(Some(SyncRemoteArgs::Git {
                url,
                credentials: GitCredentialSource::Terminal,
            }));
        }
        if SshGitRemoteUrl::parse(&url).is_ok() {
            dialog.hint("SSH selected. Use an existing known-hosts file with this server's verified key. Kitrove will not add host keys or start an SSH agent.")?;
            loop {
                let path = dialog.ask("Known-hosts file path (Enter/n skips):")?;
                if matches!(path.as_str(), "" | "n") {
                    return Ok(None);
                }
                let known_hosts = PathBuf::from(path);
                if known_hosts.is_absolute() {
                    return Ok(Some(SyncRemoteArgs::Ssh { url, known_hosts }));
                }
                dialog.warning("Use an absolute path to an existing known-hosts file, or n to skip. Nothing has changed.")?;
            }
        }
        dialog.warning("That URL is not supported. Use an HTTPS or ssh:// repository URL without passwords, tokens, query strings or fragments. Nothing has changed.")?;
    }
}

fn synchronize<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    offer_new_repository: bool,
) -> Result<(), CliError> {
    match remote(dialog, offer_new_repository)? {
        Some(remote) => synchronize_with(dialog, root, remote).map(|_| ()),
        None => Ok(()),
    }
}

fn synchronize_with<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    remote: SyncRemoteArgs,
) -> Result<bool, CliError> {
    dialog.hint("Sharing sends and receives collection changes between computers. It does not add skills to your AI tools.\nReview the upload/download plan before approving. Unrelated collections or conflicting items stop without choosing a winner. Nothing runs in the background.")?;
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

fn import<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
) -> Result<(), CliError> {
    dialog.say("Selective import is a one-time copy, not ongoing selective sync. The remote is not modified. Differing local identities refuse the import.")?;
    match remote(dialog, false)? {
        None => Ok(()),
        Some(SyncRemoteArgs::Filesystem(path)) => import_backend(
            dialog,
            root,
            FilesystemSyncBackend::open(&path).map_err(crate::sync::backend_error)?,
        ),
        Some(SyncRemoteArgs::Git { url, credentials }) => import_backend(
            dialog,
            root,
            crate::sync::open_git_backend(&url, credentials)?,
        ),
        Some(SyncRemoteArgs::Ssh { url, known_hosts }) => import_backend(
            dialog,
            root,
            SshGitSyncBackend::open(&url, known_hosts).map_err(crate::sync::backend_error)?,
        ),
    }
}

fn import_backend<R: PromptInput, W: Write, B: SyncBackend>(
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
    dialog.success(
        "Selected items imported. Choose skills to add to your AI tools separately when ready.",
    )
}

fn apply<R: PromptInput, W: Write>(
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
    dialog.hint("This adds selected collection items to tools on this computer. It does not run them or share them with another computer.")?;
    let selected = dialog.choose("Which saved items would you like to add?", &labels)?;
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
        .choose(
            "Which AI tools should receive these items on this computer?",
            &labels,
        )?
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
        Ok(done) => dialog.outcome(&done.output),
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
#[path = "setup_quick_tests.rs"]
mod quick_tests;

#[cfg(test)]
#[path = "setup_existing_tests.rs"]
mod existing_tests;

#[cfg(test)]
#[path = "setup_presentation_tests.rs"]
mod presentation_tests;

#[cfg(test)]
#[path = "setup_duplicate_tests.rs"]
mod duplicate_tests;

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
            color: false,
            single_key: false,
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

    pub(super) fn machine(root: &std::path::Path, name: &str) -> PathBuf {
        let path = root.join(name);
        std::fs::create_dir_all(path.join("home/.claude/skills")).unwrap();
        std::fs::create_dir_all(path.join("working")).unwrap();
        path
    }

    pub(super) fn skill(machine: &std::path::Path, name: &str, body: &str) {
        let directory = machine.join("home/.claude/skills").join(name);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: A test skill.\n---\n{body}\n"),
        )
        .unwrap();
    }

    pub(super) fn script(
        machine: &std::path::Path,
        input: &str,
        configure: bool,
        expected: &str,
    ) -> String {
        script_target(
            machine,
            input,
            configure,
            expected,
            "setup::tests::scripted_child",
        )
    }

    pub(super) fn script_target(
        machine: &std::path::Path,
        input: &str,
        configure: bool,
        expected: &str,
        target: &str,
    ) -> String {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", target, "--ignored", "--nocapture"])
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
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("running 1 test"),
            "child selector must execute exactly one fixture: {target}"
        );
        stdout
    }

    pub(super) fn manifest(machine: &std::path::Path) -> kitrove_model::EnvironmentManifest {
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
            "1\n{}\nmachine-a\nyes\n1,2\nyes\n3\n1\n{}\nyes\n5\n",
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
        script(&c, "\n2\n1\n2\n\n5\n", true, "");
        assert!(!c.join("home/.agents/skills/alpha").exists());
        // Configure applies only the selected item, using receipt-backed normal APIs.
        script(&c, "\n2\n1\n2\nyes\n5\n", true, "");
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
                "4\n{}\nmachine-d\nyes\n1\n{}\nyes\n1\nyes\nyes\n5\n",
                d.join("collection").display(),
                remote.display()
            ),
            false,
            "",
        );
        assert_eq!(manifest(&d).assets.len(), 3);
        script(
            &a,
            &format!("\n3\n1\n{}\nyes\n5\n", remote.display()),
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
        script(&a, "1\n\na\nyes\n1\nyes\n2\n1\n2\nyes\n5\n", false, "");
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
                "1\n{}\na\nyes\n1\nyes\n3\n1\n{}\nyes\n5\n",
                a.join("collection").display(),
                remote.display()
            ),
            false,
            "",
        );
        script(
            &b,
            &format!("1\n{}\nb\nyes\nn\n5\n", b.join("collection").display()),
            false,
            "",
        );
        let before = manifest(&b);
        script(&b, "\n1\n1\nn\n5\n", true, "");
        assert_eq!(manifest(&b), before);
        script(
            &b,
            &format!("\n4\n1\n{}\nall\n\n5\n", remote.display()),
            true,
            "",
        );
        assert_eq!(manifest(&b), before);
        script(&b, "\n1\n1\nyes\n5\n", true, "");
        let local = manifest(&b);
        let source = manifest(&a);
        script(
            &b,
            &format!("\n4\n1\n{}\nall\n", remote.display()),
            true,
            "collection.identity_conflict",
        );
        assert_eq!(manifest(&b), local);
        assert_eq!(manifest(&a), source);
        // Full sync also refuses to choose a winner, and returns to the menu.
        let output = script(&b, &format!("\n3\n1\n{}\n5\n", remote.display()), true, "");
        assert!(output.contains("blocked"));
        assert_eq!(manifest(&b), local);
    }
    #[test]
    fn selections_are_bounded_and_explicit() {
        assert_eq!(selection("", 3), Some(vec![]));
        assert_eq!(selection("all", 3), Some(vec![0, 1, 2]));
        assert_eq!(selection("3,1,1", 3), Some(vec![0, 2]));
        for invalid in ["0", "4", "--1", "1,", "yes"] {
            assert_eq!(selection(invalid, 3), None);
        }
    }
    #[test]
    fn eof_cancel_and_controls_never_confirm() {
        for input in ["", "yes", "q\n", "yes\u{1b}\n"] {
            let mut dialog = Dialog {
                input: io::Cursor::new(input),
                output: Vec::new(),
                color: false,
                single_key: false,
            };
            assert!(dialog.confirm("change?").is_err());
        }
        let mut dialog = Dialog {
            input: io::Cursor::new("\n"),
            output: Vec::new(),
            color: false,
            single_key: false,
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
            color: false,
            single_key: false,
        };
        assert_eq!(dialog.ask("input").unwrap_err().code, "setup.input_limit");
    }
}
