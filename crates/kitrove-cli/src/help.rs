//! Human help is selected only by exact, fixed command paths.
use std::ffi::OsString;

pub(crate) const INDEX: &str = "Kitrove | Carry your AI tool skills between tools and computers

Start here
  kitrove init         Set up your first or another computer
  kitrove configure    Open the menu for an existing collection
  kitrove scan         See skills on this computer
  kitrove apply        Add saved skills or packs to a tool
  kitrove doctor       Check collection and private storage

Other commands
  Collect and place    adopt, plan, remove
  Share and organize   sync, pack
  Review and repair    trust, status, recover, lock, versions
  About Kitrove        about, north-star, invariants, --version

Use kitrove <command> --help for details, or kitrove help --all.
";

struct Topic {
    path: &'static str,
    text: &'static str,
}

macro_rules! topic {
    ($path:literal, $title:literal, $($line:literal),+ $(,)?) => {
        Topic { path: $path, text: concat!($title, "\n\n", $($line, "\n"),+) }
    };
}

const TOPICS: &[Topic] = &[
    topic!(
        "init",
        "Set up Kitrove",
        "  kitrove init                         Open guided setup",
        "  kitrove init [--environment PATH] [--machine-id ID]",
        "               [--project-root PATH] [--json]",
        "",
        "With options, create an empty collection and private state after a scan."
    ),
    topic!(
        "configure",
        "Manage an existing collection",
        "  kitrove configure [--environment PATH]",
        "",
        "Collect skills, add them to a tool, sync, or copy selected items."
    ),
    topic!(
        "scan",
        "Find skills on this computer",
        "  kitrove scan [--harness TOOL] [--scope user|project|all]",
        "               [--root TOOL:SCOPE:PATH] [--project-root PATH]",
        "               [--environment PATH] [--verbose | --json]",
        "",
        "Browse results without writes. Collecting requires a separate preview.",
        "Tools: claude, codex, pi, opencode. Repeat --harness or --root as needed.",
        "Use --verbose for all findings. Exit 3 indicates that findings were reported."
    ),
    topic!(
        "adopt",
        "Collect one skill",
        "  kitrove adopt NAME --harness TOOL",
        "  kitrove adopt OBSERVATION [scan selection] [--environment PATH] [--id ID]",
        "  kitrove adopt OBSERVATION [same selection] --plan --json",
        "  kitrove adopt OBSERVATION [same selection] --confirm DIGEST --json",
        "",
        "The name must be unique. Use scan --help for discovery filters.",
        "To update, add --update ID and --expected-prior HASH to both steps.",
        "For MCP, --binding NAME maps a native environment reference.",
        "Approval covers this adoption only. Script trust is a separate step."
    ),
    topic!(
        "apply",
        "Add saved skills or packs to a tool",
        "  kitrove apply [--environment PATH]      Choose a tool and preview items",
        "  kitrove apply --asset ID --target TOOL  Preview one saved skill",
        "  kitrove apply --pack ID --target TOOL   Preview a saved pack",
        "",
        "For scripts, run kitrove plan [selection] --json first.",
        "Repeat the selection with apply --confirm BATCH_DIGEST [--json].",
        "Run kitrove plan --help for all selectors. Script trust is separate."
    ),
    topic!(
        "plan",
        "Preview adding skills or packs",
        "  kitrove plan [--profile ID | --asset ID | --pack ID] [--target TOOL]",
        "               [--scope user|project] [--project-root PATH]",
        "               [--environment PATH] [--version-binary PATH] [--json]",
        "",
        "Repeat --asset, --pack, --target or --version-binary as needed.",
        "Automation applies the full batch_digest returned by --json."
    ),
    topic!(
        "remove",
        "Remove a Kitrove-managed copy from a tool",
        "  kitrove remove --asset ID --target TOOL [--scope user|project]",
        "                 [--project-root PATH] [--environment PATH]",
        "                 [--plan | --confirm BATCH_DIGEST] [--json]",
        "",
        "Your saved skill stays in the collection. Only a copy with a matching",
        "Kitrove receipt is eligible. Preview with --plan --json for automation."
    ),
    topic!(
        "sync",
        "Sync a collection between computers",
        "  kitrove sync plan --filesystem PATH",
        "  kitrove sync apply --filesystem PATH --confirm DIGEST",
        "",
        "Use configure for the guided sync flow or for a one-time copy.",
        "Git options are listed in kitrove sync plan --help."
    ),
    topic!(
        "sync plan",
        "Preview which changes sync would send or receive",
        "  kitrove sync plan (--filesystem PATH | --git HTTPS_URL | --ssh SSH_URL)",
        "                    [--environment PATH] [--json]",
        "",
        "SSH requires --known-hosts PATH. For HTTPS automation,",
        "--git-env-credentials reads KITROVE_GIT_USERNAME and KITROVE_GIT_TOKEN."
    ),
    topic!(
        "sync apply",
        "Apply a reviewed two-way sync",
        "  kitrove sync apply [same selection as sync plan] --confirm DIGEST [--json]",
        "",
        "Run kitrove sync plan --help for folder and Git connection options."
    ),
    topic!(
        "pack",
        "Browse and manage saved packs",
        "  kitrove pack list [--environment PATH] [--json]",
        "  kitrove pack inspect --pack <pack-id> [--environment PATH] [--json]",
        "  kitrove pack discover REMOTE",
        "  kitrove pack adopt --pack <pack-id> REMOTE",
        "  kitrove pack create --pack <pack-id> --member ID...",
        "  kitrove pack update --pack <pack-id> --expected-prior HASH --member ID...",
        "  kitrove pack rollback --pack <pack-id> --expected-prior HASH --to HASH REMOTE",
        "  kitrove pack remove --pack <pack-id> --expected-prior HASH",
        "",
        "Use kitrove apply to add a saved pack to a tool.",
        "Run kitrove pack <operation> --help for options and approval."
    ),
    topic!(
        "pack list",
        "List saved packs",
        "  kitrove pack list [--environment PATH] [--json]"
    ),
    topic!(
        "pack inspect",
        "Show a pack and its contents",
        "  kitrove pack inspect --pack ID [--environment PATH] [--json]"
    ),
    topic!(
        "pack discover",
        "List packs available from a collection",
        "  kitrove pack discover (--filesystem PATH | --git HTTPS_URL | --ssh SSH_URL)",
        "                        [--json]",
        "",
        "SSH requires --known-hosts PATH. HTTPS supports --git-env-credentials."
    ),
    topic!(
        "pack adopt",
        "Copy one pack and its contents into your collection",
        "  kitrove pack adopt --pack ID (--filesystem PATH | --git HTTPS_URL | --ssh SSH_URL)",
        "                     [--environment PATH] [--plan | --confirm DIGEST | --yes]",
        "                     [--json]",
        "",
        "See pack discover --help for connection options. Preview before approval."
    ),
    topic!(
        "pack create",
        "Create a pack from saved items",
        "  kitrove pack create --pack ID --member ID... [--authored]",
        "                      [--environment PATH] [--plan | --confirm DIGEST] [--json]",
        "",
        "Use --authored for members with different sources. Otherwise members",
        "must share one distribution source. Repeat --member to add more items."
    ),
    topic!(
        "pack update",
        "Change the members of an existing pack",
        "  kitrove pack update --pack ID --expected-prior HASH --member ID...",
        "                      [--environment PATH] [--plan | --confirm DIGEST] [--json]",
        "",
        "Reuse the same selection to confirm. The pack keeps its creation mode."
    ),
    topic!(
        "pack rollback",
        "Restore a pack revision from collection history",
        "  kitrove pack rollback --pack ID --expected-prior HASH --to HASH",
        "                        (--filesystem PATH | --git HTTPS_URL | --ssh SSH_URL)",
        "                        [--environment PATH] [--plan | --confirm DIGEST | --yes]",
        "                        [--json]",
        "",
        "See pack discover --help for connection options."
    ),
    topic!(
        "pack remove",
        "Remove a pack and its unshared managed copies",
        "  kitrove pack remove --pack ID --expected-prior HASH",
        "                      [--environment PATH] [--plan | --confirm BATCH_DIGEST] [--json]"
    ),
    topic!(
        "trust",
        "Review script trust on this computer",
        "  kitrove trust audit [--asset ID] [--environment PATH] [--json]",
        "  kitrove trust plan --asset ID --decision trusted|denied [--json]",
        "  kitrove trust apply [same selection] --confirm DIGEST [--json]",
        "",
        "Trust applies to the reviewed bytes on this computer. It does not add skills."
    ),
    topic!(
        "trust audit",
        "List local trust decisions",
        "  kitrove trust audit [--asset ID] [--environment PATH] [--json]"
    ),
    topic!(
        "trust plan",
        "Preview granting or denying trust to exact script contents",
        "  kitrove trust plan --asset ID --decision trusted|denied",
        "                     [--environment PATH] [--json]"
    ),
    topic!(
        "trust apply",
        "Record a reviewed local trust decision",
        "  kitrove trust apply --asset ID --decision trusted|denied --confirm DIGEST",
        "                      [--environment PATH] [--json]"
    ),
    topic!(
        "status",
        "Check the collection manifest, lock and saved objects",
        "  kitrove status [--environment PATH] [--json]",
        "",
        "For storage permissions and retained files, run kitrove doctor."
    ),
    Topic {
        path: "doctor",
        text: crate::args::DOCTOR_HELP,
    },
    Topic {
        path: "recover",
        text: crate::recover::HELP,
    },
    topic!(
        "recover plan",
        "Preview preserving retained files on macOS",
        "  kitrove recover plan --root collection|private-state [--environment PATH] [--json]",
        "",
        "This checks storage without changing files. Start with kitrove doctor."
    ),
    topic!(
        "recover preserve",
        "Preserve retained files on macOS after review",
        "  kitrove recover preserve --root collection|private-state --confirm DIGEST",
        "                           [--environment PATH] [--json]",
        "",
        "Run recover plan for the same root and collection first."
    ),
    topic!(
        "lock",
        "Regenerate the collection lock from its manifest",
        "  kitrove lock [--environment PATH] [--json]"
    ),
    topic!(
        "versions",
        "Check tool version evidence",
        "  kitrove versions probe --harness pi|opencode --binary ABSOLUTE_PATH [--json]"
    ),
    topic!(
        "versions probe",
        "Run a bounded version check with an explicit tool binary",
        "  kitrove versions probe --harness pi|opencode --binary ABSOLUTE_PATH [--json]"
    ),
    topic!("about", "Show the product and version", "  kitrove about"),
    topic!(
        "north-star",
        "Read the product goals",
        "  kitrove north-star"
    ),
    topic!(
        "invariants",
        "Read the architectural guarantees",
        "  kitrove invariants"
    ),
];

fn find(arguments: &[OsString]) -> Option<&'static Topic> {
    TOPICS.iter().find(|topic| {
        topic
            .path
            .split_ascii_whitespace()
            .map(std::ffi::OsStr::new)
            .eq(arguments.iter().map(OsString::as_os_str))
    })
}

pub(crate) fn requested(arguments: &[OsString]) -> Option<&'static str> {
    match arguments {
        [help, path @ ..] if help == "help" => find(path).map(|topic| topic.text),
        [path @ .., flag] if flag == "--help" || flag == "-h" => find(path).map(|topic| topic.text),
        _ => None,
    }
}

pub(crate) fn error_hint(arguments: &[OsString]) -> String {
    let path = [2, 1]
        .into_iter()
        .filter_map(|count| arguments.get(..count))
        .find_map(find);
    match path {
        Some(topic) => format!("Run kitrove {} --help.", topic.path),
        None => "Run kitrove --help.".to_owned(),
    }
}

pub(crate) fn reference() -> String {
    use std::fmt::Write as _;
    let mut reference = INDEX.to_owned();
    reference.push_str("\nAutomation: use --json for results when supported. Put --json-errors\n                        before the command for structured errors on stderr.\n");
    for topic in TOPICS {
        writeln!(reference, "\nkitrove {}\n{}", topic.path, topic.text)
            .expect("writing to a string cannot fail");
    }
    reference
}
