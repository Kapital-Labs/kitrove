# Set up Kitrove

Kitrove collects skills from your agent tools and lets you apply compatible
capabilities elsewhere. It does not install those tools or copy their accounts.

## Start on your first computer

After installing the release candidate, run this in a terminal:

```sh
kitrove init
```

Choose **Set up my first computer**. The walkthrough asks where to keep your
portable collection, suggests `~/Kitrove`, and asks for a name for this computer.
Before creating anything it shows both the collection and machine-local state
locations. On macOS the default local state location is
`~/Library/Application Support/kitrove`.

Kitrove then scans your user-level skills. Select the numbers beside skills you
want, or `all`. Names, source tools and scopes are shown; there is no observation
ID to copy. The same directory can be visible to multiple tools, so review the
source tool before choosing. Each adoption has its own preview and confirmation.
The source files remain in place.

Use **Apply selected items** to select destinations. This is a separate plan and
confirmation. Fidelity results explain what transfers; an unmanaged destination
conflict is refused, not overwritten. Pi and OpenCode may require the absolute
path of an independently trusted local binary for the existing bounded version
probe. Executable capabilities still require separate local trust; setup does
not grant trust or install prerequisites.

`q` stops at any prompt. Enter skips a confirmation. Previously confirmed steps
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
