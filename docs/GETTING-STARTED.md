# Set up Kitrove

Kitrove collects skills from your agent tools and lets you apply compatible
capabilities elsewhere. It does not install those tools or copy their accounts.

## Install the latest preview

These instructions describe a fresh installation of **RC5.22**. On an Apple Silicon Mac with
[Homebrew](https://brew.sh/) already installed:

```sh
brew install --cask kapital-labs/tap/kitrove
kitrove --version
```

The package is named `kitrove`; the installed version still identifies itself as
`0.1.0-rc.5.22`. This is an evaluation preview, not stable support. Use a new isolated
collection and empty destinations with synthetic or disposable capabilities.
Homebrew checks the pinned archive checksum; you trust Homebrew and the reviewed
[tap](https://github.com/Kapital-Labs/homebrew-tap) to select the package. It does
not initialize Kitrove, scan skills, or grant execution trust during installation.
Leave quarantine and Gatekeeper enabled.

For Linux x86-64 and Windows x86-64, use the exact
[RC5.22 downloads](https://github.com/Kapital-Labs/kitrove/releases/tag/v0.1.0-rc.5.22)
and follow the [verification guide](INSTALLER.md) with an independently trusted
or reviewed-source-built verifier **before execution**. A checksum alone is not
provenance. Intel Macs are unsupported in this preview.

## Upgrade with Homebrew

If you already installed the `kitrove` cask from the Kapital Labs tap, update
the tap before upgrading the executable:

```sh
brew update
brew upgrade --cask kapital-labs/tap/kitrove
kitrove --version
```

`brew update` refreshes package information. Without it, Homebrew can report
that the latest version is installed while its local copy of the tap is behind.
The Kitrove upgrade replaces the Homebrew-managed executable and preserves your
collection and local state. For the older
`kitrove-rc` or `kitrove-rc@5.5` casks, see [Existing installations](#existing-installations).

Use `kitrove --help` to find a command. For usage, run the command with
`--help` (for example, `kitrove apply --help`).

## Start on your first computer

The guided screens below describe the CLI in this source tree. If you installed
RC5.22, use its [versioned setup guide](https://github.com/Kapital-Labs/kitrove/blob/v0.1.0-rc.5.22/docs/GETTING-STARTED.md).

To browse tasks, run `kitrove` in a terminal. For initial setup, run this in a terminal:

```sh
kitrove init
```

Choose **Set up my first computer**. The walkthrough asks where to keep your
portable collection, suggests `~/Kitrove`, and asks for a name for this computer.
Before creating anything it shows both the collection and machine-local state
locations. On macOS the default local state location is
`~/Library/Application Support/kitrove`.

Kitrove then scans your user-level skills and summarizes the sources.
Enter previews eligible skills. Type `v` to browse numbered copies, `/name` to
filter, and `next` to page. Use `1,4,7` to choose specific copies or
`all,-3,-8` to exclude copies 3 and 8. Numbers belong to this scan.
The same directory can appear through multiple tools; review source tools and
scopes, not just names. Ambiguous names do not silently pick a source.

If repeated names leave nothing ready to collect, choose a numbered source tool
to preview its copies with your exclusions still applied. You can also type
`from codex`, `from claude`, `from pi` or `from opencode`. For example,
`from codex,-13,-20` excludes those original inventory numbers. This choice
applies to the current scan. Existing collection names and duplicates within one
tool still need an explicit choice or individual review.

The preview shows skipped-item counts by reason. Press `d` for all details.
Ready plans still show complete source, fidelity and loss details. An empty
preview offers no adoption approval or zero-item success. Enter or `s` chooses
again using the same scan; `s` also works after a nonempty preview.

Review the preview's fidelity and loss warnings. Type `y` and press Enter to
save the ready set. Enter alone skips the save. Use `r` for individual review,
where `y` then Enter saves the current skill. Original source files stay in place.

Bulk adoption is sequential, not atomic. A stale source, changed collection,
pending recovery or failed commit stops later items; completed items remain and
are reported. See the [quick collection flow](SETUP-QUICK-ADOPTION.md) for omitted
items, naming conflicts and exact confirmation semantics.

After saving skills, choose a tool to preview adding them. Kitrove offers to
preview ready skills from what you just saved. It also lets you check the
whole collection or select specific skills and packs. Run `kitrove apply`
to return directly. Review the destinations and type `y` then Enter to
approve the exact preview. The [tool-first guide](ADD-TO-TOOLS.md) explains
shared folders and advanced items.

Ordinary skills do not need an executable path. Selected Pi extensions and
OpenCode advanced items can require an explicit trusted executable for the
existing bounded version probe. Script-containing skills have a separate exact local review before placement.
Native extensions retain their existing explicit trust workflow. Setup installs no prerequisites.

Enter submits the current choice or text. In a supported terminal, arrow
keys and shortcuts can highlight a menu choice before you submit.
A key left over from an earlier prompt cannot approve a later preview.
Saving skills, adding them to a tool, and syncing each require their own
approval. Press Ctrl+C to leave; earlier confirmed steps remain completed.

Skills with eligible text helper scripts can be collected as data. Before adding
one to a tool, review its exact stored bundle and approve that version locally.
Kitrove does not run helpers or install dependencies. Compiled payloads and native
lifecycle directives remain unsupported. See [script-containing skills](ADD-TO-TOOLS.md#script-containing-skills).

On a repeated collection scan, exact native matches are already collected. Return
to setup and use option 2 to add saved skills to a tool; individual review skips
those exact matches instead of asking you to rename them. Changed or unverified
copies still require explicit review.

## Revisit setup

```sh
kitrove configure
```

The walkthrough asks for your existing collection. The menu separates these goals:

1. **Collect skills from this computer** copies selected skills into your collection.
2. **Add saved skills or packs to a tool** previews adding a selection locally.
3. **Sync this collection with another computer** reviews bidirectional sync.
4. **Copy selected items from another collection** performs a one-time import.
5. **Finish for now** leaves setup.

Questions and the input marker are cyan in recognized interactive terminals;
command results and no-write previews are labeled and indented. `NO_COLOR` or an
unrecognized terminal keeps plain text, with the same labels and approvals.
To select a non-default collection explicitly:

```sh
kitrove configure --environment /absolute/path/to/collection
```

For explicit commands outside your collection directory, supply `--environment`
or set `KITROVE_ENV` yourself. Setup does not edit your shell profile. Backend
locations are requested per operation rather than saved with credentials.

## Prepare a collection for another computer

In Configure, choose **Sync this collection with another computer**. Select an
existing filesystem/shared directory or **Git repository**. Paste the repository
URL: `https://...` selects HTTPS and `ssh://...` selects
SSH. A URL without its scheme asks which connection to use. SSH also asks for an
absolute path to an existing known-hosts file; it does not learn host keys or start
an agent.
This must be a Kitrove snapshot backend, not merely a checkout
containing skill files. An empty existing backend can receive the first approved
publication. Create and authorize any remote repository separately: setup does not create
one, inspect the current project's remotes or import Git/SSH configuration.

When the Git prompt offers **Create a private repository**, type `c` for
instructions, create the empty private repository on your Git host, and paste
its clone URL. Leave the template, README, license and `.gitignore` unset. If
HTTPS asks for credentials, enter your Git username and a repository access
token. Token input is hidden, and an empty answer cancels authentication.

Review what will change locally and remotely before confirming. Full sync is
bidirectional: it may publish local additions, not just download. Credentials use
the existing operation-local provider and do not enter your collection. Do not
paste credentials into URLs.

## Set up a second computer

Install Kitrove and run `kitrove init` there. Choose either:

- **Connect a second computer to the whole collection:** initialize new local
  identity, read the selected backend, and review full synchronization. Existing
  agent files are untouched until you separately choose Apply.
- **Import specific items:** choose individual assets or packs. Pack selections
  include their required members. This imports only that selection and preserves
  unrelated local items. It is a one-time import, not an ongoing selective sync
  subscription; it does not modify the remote.
- **Combine this computer's skills with an existing collection:** first connect
  the empty collection to establish shared history, then select local skills to
  add and review publishing those additions. Existing agent files are untouched.

After connecting, you can also collect skills through Configure and then run full sync. Independent changes are
reconciled by Kitrove's existing semantic planner. Different content under the same
identity is not silently replaced: a conflict stops that operation for review.
There is no automatic conflict-winner or keep-both rewrite in this release.
Two independently populated collections without a retained shared base cannot
full-sync automatically. Use selective import to combine chosen items locally;
it does not establish shared sync history. Do not delete local state to force a
connection.

Full collection transfer does not clone credentials, trust decisions, local
bindings, machine paths, deployment receipts, or installed agent tools. Each
computer chooses its own destinations. The walkthrough does not claim cross-tool
equivalence or supported remote-content behavior solely because an import passed.

## Inspect without changing anything

```sh
kitrove scan
kitrove scan --harness claude --scope user
```

In a terminal, scan starts with a compact summary. Use Up/Down and Enter on
supported Mac/Linux terminals, or press a displayed shortcut. Native Windows,
narrow and unrecognized terminals use shortcuts and a marked Enter default.

- Choose **View scan issues** (`i`) to identify folders that could not be read.
  A folder error is not a skill. The inventory may be incomplete, so zero listed
  skills does not prove that the unavailable folder is empty.
- Choose **Scan again** (`r`) to scan again with the same filters, including
  explicit source roots and the project boundary. Nothing retries automatically.
- Choose **Add skills to collection** (`a`) for a separate collection selection,
  fresh preview and approval. Browsing alone does not collect or apply anything.
- Press `d` for diagnostics or `q` to quit. Enter selects the marked action;
  browsing a group defaults to Back, and an empty scan defaults to Quit.

Browsing changes no files. Available source skills still need a separate adoption
plan for your collection. Redirected output remains a read-only text report;
JSON and verbose reports retain their established contracts.

You can leave existing links in place when the scan skips them. Review metadata,
size and credential-related findings locally.

For diagnostics or automation:

```sh
kitrove scan --verbose
kitrove scan --json
```

For exact non-interactive materialization approvals, see
[the agent workflow](AGENT-WORKFLOW.md).

To adopt one uniquely named skill without the walkthrough:

```sh
kitrove adopt humanizer --harness claude --scope user
```

Ambiguous names require a narrower scope/source or an exact observation ID from
the verbose report. Selection still binds fresh captured content and a confirmed
plan. Scripted initialization keeps its explicit form:

```sh
kitrove init --environment /absolute/path/to/collection --machine-id my-machine
```

Bare `init` and `configure` refuse non-terminal input instead of pretending setup
completed. JSON scan and existing explicit operations remain available to scripts.

## If adding items fails

Run a read-only collection and storage check:

```sh
kitrove doctor --environment /absolute/path/to/your/collection
```

Doctor makes no changes or repairs. See the [diagnostic guide](DOCTOR.md) for
what the report checks and how to share its redacted JSON.

## Existing installations

Already initialized this collection and computer? Use the existing-setup menu:

```sh
kitrove configure --environment /absolute/path/to/your/collection
```

RC5.7 adds explicit existing-setup continuation in `init`, after validating the
collection and local state. Do not delete either to rerun initialization. The
previous RC5.6 first-computer path refuses existing setup; use `configure` above
with that older binary. RC5.7 asks before continuing a valid existing setup and
does not delete or recreate either the collection or local state. Incomplete,
unsafe or in-use state stops for inspection rather than implicit repair.

The RC5.7 setup UI also separates cyan questions/input markers from labeled
command output and previews, with plain text when `NO_COLOR` is set or the terminal
is not recognized. Its second menu choice is “Choose skills to add to your AI
tools”; sharing and one-time copying have their own choices. RC5.6 still has the
older menu labels/numbers. Do not use RC5.7 menu numbers with that binary.

The fresh-install instructions do not migrate an older collection. RC5.22 has no
rollback-compatible predecessor; RC4.2 cannot read authored-pack collections.
Keep older collections and local state separate. Binary rollback is not data
rollback.

The retained Homebrew casks `kitrove-rc` (RC4.2) and `kitrove-rc@5.5` (RC5.5) are
not automatically renamed or replaced by `kitrove`. The new cask refuses both
installed tokens and an occupied executable path. Check ownership and recovery
needs before changing an existing installation; do not force an overwrite, delete
state, or use `--zap` to bypass a conflict. Never point `kitrove-installer` at a
Homebrew-managed binary. Normal cask removal preserves Kitrove collections and
local state; use the token that actually owns your installed binary.

The older APT/DNF package channels remain RC4.2, not an RC5.22 install or upgrade
path. See the [Linux package guide](LINUX-INSTALL.md) for their exact scope.
