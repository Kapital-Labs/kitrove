# Set up Kitrove

Kitrove collects skills from your agent tools and lets you apply compatible
capabilities elsewhere. It does not install those tools or copy their accounts.

## Install the latest preview

These instructions start with a fresh installation of the latest reviewed
preview, currently **RC5.6**. On an Apple Silicon Mac with
[Homebrew](https://brew.sh/) already installed:

```sh
brew install --cask kapital-labs/tap/kitrove
kitrove --version
```

The package is named `kitrove`; the installed version still identifies itself as
`0.1.0-rc.5.6`. This is an evaluation preview, not stable support. Use a new isolated
collection and empty destinations with synthetic or disposable capabilities.
Homebrew checks the pinned archive checksum; you trust Homebrew and the reviewed
[tap](https://github.com/Kapital-Labs/homebrew-tap) to select the package. It does
not initialize Kitrove, scan skills, or grant execution trust during installation.
Leave quarantine and Gatekeeper enabled.

For Linux x86-64 and Windows x86-64, use the exact
[RC5.6 downloads](https://github.com/Kapital-Labs/kitrove/releases/tag/v0.1.0-rc.5.6)
and follow the [verification guide](INSTALLER.md) with an independently trusted
or reviewed-source-built verifier **before execution**. A checksum alone is not
provenance. Intel Macs are unsupported in this preview.

## Start on your first computer

After installing, run this in a terminal:

```sh
kitrove init
```

Choose **Set up my first computer**. The walkthrough asks where to keep your
portable collection, suggests `~/Kitrove`, and asks for a name for this computer.
Before creating anything it shows both the collection and machine-local state
locations. On macOS the default local state location is
`~/Library/Application Support/kitrove`.

Kitrove then scans your user-level skills and shows the first 20 numbered entries.
Enter previews the recommended eligible set without writing it. Use `v` to see
the full inventory, `1,4,7` to choose only those entries, or `all,-3,-8` (also
`-3,-8`) for everything except entries 3 and 8. Numbers belong to this scan.
The same directory can appear through multiple tools; review source tools and
scopes, not just names. Ambiguous names do not silently pick a source.

Review the preview's fidelity and loss warnings. `y` or `yes` approves only the
displayed ready set; Enter does not approve bulk writes. Use `r` for individual
review: Enter/y accepts the current shown plan, n skips, and r renames before a
new preview. `n` at selection skips collection. Original source files stay in place.

Bulk adoption is sequential, not atomic. A stale source, changed collection,
pending recovery or failed commit stops later items; completed items remain and
are reported. See the [quick collection flow](SETUP-QUICK-ADOPTION.md) for omitted
items, naming conflicts and exact confirmation semantics.

Use **Apply selected items** to select destinations. This is a separate plan and
confirmation. Fidelity results explain what transfers; an unmanaged destination
conflict is refused, not overwritten. Pi and OpenCode may require the absolute
path of an independently trusted local binary for the existing bounded version
probe. Executable capabilities still require separate local trust; setup does
not grant trust or install prerequisites.

`q` stops at any prompt. Other write confirmations still skip on Enter; individual
adoption review is the explicit exception described above. Previously confirmed steps
remain completed if you stop later. Setup is not a single transaction covering
all earlier choices, and nothing starts running in the background.

## Revisit setup

```sh
kitrove configure
```

The walkthrough asks for your existing collection. You can collect more skills,
synchronize, selectively import, or apply a different selection. To select a
non-default collection explicitly:

```sh
kitrove configure --environment /absolute/path/to/collection
```

For explicit commands outside your collection directory, supply `--environment`
or set `KITROVE_ENV` yourself. Setup does not edit your shell profile. Backend
locations are requested per operation rather than saved with credentials.

## Prepare a collection for another computer

In Configure, choose **Connect / sync the whole collection**. Select an existing
filesystem/shared directory, HTTPS Git remote, or SSH Git remote with an explicit
known-hosts file. This must be a Kitrove snapshot backend, not merely a checkout
containing skill files. An empty existing backend can receive the first approved
publication. Create and authorize any remote repository separately.

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

The default report lists skills and groups repeated warnings. Linked or special
entries skipped by current policy are not an instruction to delete existing
links. Metadata, size and credential-related findings need local review.

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

## Existing installations

Already initialized this collection and computer? Use the existing-setup menu:

```sh
kitrove configure --environment /absolute/path/to/your/collection
```

RC5.7 adds explicit existing-setup continuation in `init`, after validating the
collection and local state. Do not delete either to rerun initialization. The
previous RC5.6 first-computer path refuses existing setup; use `configure` above
with that binary. RC5.7 publication and package-channel availability are verified
separately; this source guide is not a claim that Homebrew has already updated.

The RC5.7 setup UI also separates cyan questions/input markers from labeled
command output and previews, with plain text when `NO_COLOR` is set or the terminal
is not recognized. Its second menu choice is “Choose skills to add to your AI
tools”; sharing and one-time copying have their own choices. RC5.6 still has the
older menu labels/numbers. Do not use RC5.7 menu numbers with that binary.

The fresh-install instructions do not migrate an older collection. RC5.6 has no
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

The older APT/DNF package channels remain RC4.2, not an RC5.6 install or upgrade
path. See the [Linux package guide](LINUX-INSTALL.md) for their exact scope.
