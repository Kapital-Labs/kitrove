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

mod application;
mod application_preview;
mod application_readiness;
mod collection;
mod collection_selection;
mod collection_status;
mod initialization;
mod inventory;
mod menu_input;
mod navigation;
mod presentation;
mod storage;

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
    terminal_input: bool,
}

impl Dialog<TerminalInput, io::Stdout> {
    fn terminal() -> Self {
        Self {
            input: TerminalInput(io::stdin()),
            output: io::stdout(),
            color: presentation::detect(io::stdout().is_terminal()),
            terminal_input: true,
        }
    }
}

impl<R: PromptInput, W: Write> Dialog<R, W> {
    fn decision(&mut self, message: &str) -> Result<String, CliError> {
        self.menu_answer(message, false)
    }

    fn menu_answer(&mut self, message: &str, quit_option: bool) -> Result<String, CliError> {
        // Start each decision with fresh terminal input. A line queued while
        // the previous screen was active cannot approve this one.
        if self.terminal_input {
            menu_input::discard_pending().map_err(|_| io_error())?;
        }
        self.read_answer(message, quit_option)
    }

    fn report(&mut self, text: &str) -> Result<(), CliError> {
        let text = text.lines().map(safe).collect::<Vec<_>>().join("\n");
        presentation::block(&mut self.output, self.color, "Command output", &text)
            .map_err(|_| io_error())
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
        self.read_answer(message, false)
    }

    fn read_answer(&mut self, message: &str, quit_option: bool) -> Result<String, CliError> {
        presentation::prompt(&mut self.output, self.color, message).map_err(|_| io_error())?;
        self.output.flush().map_err(|_| io_error())?;
        let terminal_input = self.terminal_input;
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
                let consumed = if terminal_input && available.get(count - 1) == Some(&b'\n') {
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
        if value == "q" && !quit_option {
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
                .decision(&format!(
                    "{message}\n[y] Continue\n[n] Skip [default]\nEnter submits."
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
        prompt.push_str("\n1,4,7      Select numbers\nall,-3     All except these\nEnter/n    Skip\nq          Quit");
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

fn existing_collection<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    environment: Option<PathBuf>,
) -> Result<PathBuf, CliError> {
    if let Some(root) = environment.as_deref() {
        return resolve_required_environment_root(Some(root));
    }
    let suggested = match resolve_required_environment_root(None) {
        Ok(root) => root,
        Err(error) if error.code == "cli.environment_missing" => default_collection()?,
        Err(error) => return Err(error),
    };
    let response = dialog.ask(&format!(
        "Existing collection path [{}]:",
        safe(&suggested.display().to_string())
    ))?;
    resolve_required_environment_root(Some(&if response.is_empty() {
        suggested
    } else {
        PathBuf::from(response)
    }))
}

fn check_collection<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
) -> Result<(), CliError> {
    let status = run_status(EnvironmentArgs {
        environment: Some(root.to_owned()),
        json: false,
    })?;
    if status.status != 0 {
        dialog.report(&status.output)?;
        return Err(CliError::new(
            "setup.collection_attention",
            "collection needs attention; use status before continuing",
        ));
    }
    Ok(())
}

pub(crate) fn launch() -> u8 {
    let mut dialog = Dialog::terminal();
    let task = navigation::choose(
        &mut dialog,
        "What would you like to do?",
        &[
            (b'1', "Find or collect skills"),
            (b'2', "Add saved skills or packs to a tool"),
            (b'3', "Share a collection between computers"),
            (b'4', "Check collection storage"),
            (b'5', "Set up Kitrove"),
            (b'q', "Quit"),
        ],
        0,
    );
    match task {
        Ok(b'1') => {
            let selection = ScanArgs {
                harnesses: tier_one_harnesses(),
                scope: ScopeSelection::User,
                project_root: None,
                roots: Vec::new(),
                environment: None,
                json: false,
                verbose: false,
            };
            let result = crate::registry::try_tier_one_registry()
                .map_err(|_| io_error())
                .and_then(|registry| crate::scan::run_scan(selection, &registry));
            match result {
                Ok(status) => status,
                Err(error) => report_result(Err(error)),
            }
        }
        Ok(b'2') => apply_entry(None),
        Ok(b'3') => report_result(share(&mut dialog)),
        Ok(b'4') => match storage::inspect(&mut dialog, None) {
            Ok(status) => status,
            Err(error) => report_result(Err(error)),
        },
        Ok(b'5') => entry(None, false),
        Ok(_) => 0,
        Err(error) => report_result(Err(error)),
    }
}

fn share(dialog: &mut Dialog<impl PromptInput, impl Write>) -> Result<(), CliError> {
    let choice = navigation::choose(
        dialog,
        "How would you like to share?",
        &[
            (b'1', "Keep both collections in sync"),
            (b'2', "Copy selected items once"),
            (b'n', "Back"),
        ],
        2,
    )?;
    if choice == b'n' {
        return Ok(());
    }
    let root = existing_collection(dialog, None)?;
    check_collection(dialog, &root)?;
    match choice {
        b'1' => synchronize(dialog, &root, true),
        _ => import(dialog, &root),
    }
}

pub(crate) fn apply_entry(environment: Option<PathBuf>) -> u8 {
    let mut dialog = Dialog::terminal();
    let result = (|| {
        dialog.heading("Add skills or packs to a tool")?;
        let root = existing_collection(&mut dialog, environment)?;
        check_collection(&mut dialog, &root)?;
        application::apply(&mut dialog, &root, &[])
    })();
    report_result(result)
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
    report_result(result)
}

fn report_result(result: Result<(), CliError>) -> u8 {
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
    dialog.hint("Kitrove previews changes before asking you to approve. Press q to quit.")?;
    let start = if configure {
        b'0'
    } else {
        navigation::choose(
            dialog,
            "How would you like to start?",
            &[
                (b'1', "Set up my first computer"),
                (b'2', "Sync with a collection on another computer"),
                (b'3', "Copy selected items from another collection"),
                (b'4', "Combine skills with an existing collection"),
                (b'5', "Find skills on this computer"),
                (b'q', "Quit"),
            ],
            5,
        )?
    };
    if start == b'q' {
        return Ok(());
    }
    if start == b'5' {
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
    let mut start = start;
    let root = if configure {
        existing_collection(dialog, environment)?
    } else {
        let Some((root, resumed)) = initialization::select(dialog, registry)? else {
            return Ok(());
        };
        if resumed {
            // Resume reaches the ordinary menu, not the selected new-machine action.
            start = b'0';
        }
        root
    };
    check_collection(dialog, &root)?;
    let mut just_collected = Vec::new();
    match start {
        b'1' => just_collected = collect(dialog, &root, registry)?,
        b'2' => synchronize(dialog, &root, false)?,
        b'3' => import(dialog, &root)?,
        b'4' => {
            dialog.say("First connect this empty collection to the existing one. Then select local skills to add, and review publishing those additions. Existing agent files remain untouched.")?;
            if let Some(backend) = remote(dialog, false)?
                && synchronize_with(dialog, &root, backend.clone())?
            {
                just_collected = collect(dialog, &root, registry)?;
                synchronize_with(dialog, &root, backend)?;
            }
        }
        _ => {}
    }
    loop {
        if !just_collected.is_empty() {
            application::offer(dialog, &root, &just_collected)?;
            just_collected.clear();
        }
        let choice = navigation::choose(
            dialog,
            "What would you like to do?",
            &[
                (b'1', "Collect skills from this computer"),
                (b'2', "Add saved skills or packs to a tool"),
                (b'3', "Sync this collection with another computer"),
                (b'4', "Copy selected items from another collection"),
                (b'5', "Finish for now"),
            ],
            4,
        )?;
        match choice {
            b'1' => just_collected = collect(dialog, &root, registry)?,
            b'2' => application::apply(dialog, &root, &[])?,
            b'3' => synchronize(dialog, &root, true)?,
            b'4' => import(dialog, &root)?,
            _ => break,
        }
    }
    dialog.success(&format!(
        "Setup finished. Collection: {}",
        safe(&root.display().to_string())
    ))?;
    dialog.hint("Reopen this menu with kitrove configure.")
}

fn collect<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    registry: &PolicyRegistry,
) -> Result<Vec<AssetId>, CliError> {
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
        match dialog.decision("Where is the shared collection stored?\n1. Shared folder or drive\n2. Git repository\nn. Not now\nChoose 1-2 [n]:")?.as_str() {
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
                match dialog.decision("How should Kitrove connect?\n1. HTTPS\n2. SSH\nn. Not now\nChoose 1-2 [n]:")?.as_str() {
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
    dialog.hint(
        "Sync is two-way. Review what this computer will send and receive before approving.",
    )?;
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
    dialog.hint(
        "Sync changes the collection. To add skills to a tool afterward, run kitrove apply.",
    )?;
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
    dialog.say("This copies selected items once. Changes are saved to this collection only.")?;
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
    dialog.success("Selected items imported. Add skills or packs to a tool separately when ready.")
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
            terminal_input: false,
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
            "1\n{}\nmachine-a\nyes\n1,2\nyes\nn\n3\n1\n{}\nyes\n5\n",
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
        script(&c, "2\n2\n1\ns\n1\n\n5\n", true, "");
        assert!(!c.join("home/.agents/skills/alpha").exists());
        // Configure applies only the selected item, using receipt-backed normal APIs.
        script(&c, "2\n2\n1\ns\n1\nyes\n5\n", true, "");
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
                "4\n{}\nmachine-d\nyes\n1\n{}\nyes\n1\nyes\nyes\nn\n5\n",
                d.join("collection").display(),
                remote.display()
            ),
            false,
            "",
        );
        assert_eq!(manifest(&d).assets.len(), 3);
        script(
            &a,
            &format!("3\n1\n{}\nyes\n5\n", remote.display()),
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
        script(
            &a,
            "1\n\na\nyes\n1\nyes\na\n2\n1\ns\n1\nyes\n5\n",
            false,
            "",
        );
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
                "1\n{}\na\nyes\n1\nyes\nn\n3\n1\n{}\nyes\n5\n",
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
        script(&b, "1\n1\nn\n5\n", true, "");
        assert_eq!(manifest(&b), before);
        script(
            &b,
            &format!("4\n1\n{}\nall\n\n5\n", remote.display()),
            true,
            "",
        );
        assert_eq!(manifest(&b), before);
        script(&b, "1\n1\nyes\nn\n5\n", true, "");
        let local = manifest(&b);
        let source = manifest(&a);
        script(
            &b,
            &format!("4\n1\n{}\nall\n", remote.display()),
            true,
            "collection.identity_conflict",
        );
        assert_eq!(manifest(&b), local);
        assert_eq!(manifest(&a), source);
        // Full sync also refuses to choose a winner, and returns to the menu.
        let output = script(&b, &format!("3\n1\n{}\n5\n", remote.display()), true, "");
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
                terminal_input: false,
            };
            assert!(dialog.confirm("change?").is_err());
        }
        let mut dialog = Dialog {
            input: io::Cursor::new("\n"),
            output: Vec::new(),
            color: false,
            terminal_input: false,
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
            terminal_input: false,
        };
        assert_eq!(dialog.ask("input").unwrap_err().code, "setup.input_limit");
    }
}

#[cfg(test)]
#[path = "setup_application_tests.rs"]
mod application_tests;
#[cfg(test)]
#[path = "setup_collection_status_tests.rs"]
mod collection_status_tests;
