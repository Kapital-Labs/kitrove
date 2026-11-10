# ADR-0047: Guided setup preserves explicit authority

- **Status:** Accepted for implementation by maintainer request, 2026-10-13
- **North Star:** NS-01 through NS-10, no weakening

## Decision

Bare interactive `init` and `configure` orchestrate the existing bounded scan,
initialization, adoption, distribution, synchronization and materialization APIs.
Explicit scripted initialization remains available. A walkthrough requires a
terminal; EOF, cancellation and invalid input never count as confirmation.
No operation runs an upstream script or installs a prerequisite.

The first-computer path selects a collection directory and local machine identity,
shows both portable and local paths, confirms initialization, scans without writes,
selects skills by readable names and scopes, explicitly approves adoption, and separately
plans and confirms destination application. A later `configure` can revisit these
operations. Completed steps are retained on cancellation and reported honestly;
the entire walkthrough is not a new all-or-nothing transaction.

Second-computer setup accepts an explicit existing Kitrove filesystem or Git
backend, not an arbitrary checkout. Full synchronization uses the existing
three-way planner and exact confirmation digest. The combine path first connects
an empty collection to establish a real base, then explicitly adopts local skills
and previews their synchronization. Unrelated populated histories remain blocked.
Conflicting identities block;
the walkthrough cannot choose a winner or rename provenance implicitly.

Selective import extends ADR-0035's verified head graft to selected individual
assets and pack closures. It retains exact component provenance/native variants,
required symbolic bindings and immutable descriptors, excludes unrelated remote
records, rejects differing local identity collisions, and uses the same manifest
transaction and object validation. It does not create a synchronization base or
an ongoing selective subscription. Full sync is explicitly bidirectional and may
publish; selective import is a one-time read-only-remote operation.

Human scan output groups findings and omits internal hashes by default. JSON and
verbose reports retain diagnostics. Name selection is exact, bounded and
unambiguous across the selected harness/scope, resolves to an observation ID, and
then uses normal fresh capture/confirmation. Presentation escapes terminal control
characters in untrusted names and paths. Readable does not mean trusted, portable
does not mean equivalent on every target, and missing observations do not mean a
tool is absent.

## Boundaries and validation

### Git storage choice amendment (2026-11-06)

Storage selection offers a shared folder or one Git repository choice. State
plainly that the repository must already exist (it may be empty); setup does not
create repositories or interpret a local checkout as a Kitrove backend. Infer
HTTPS/SSH only from the supplied URL, using the existing canonical core parsers.
If the scheme is omitted, ask for the transport before constructing and validating
the URL. Non-URL guidance recognizes slash-rooted, drive and UNC spellings on all
platforms rather than using host-specific absolute-path semantics. This does not
admit those spellings as URLs or alter the actual known-hosts path check.
Never guess from the current project, read ambient Git/SSH configuration,
run a helper, follow redirects, or choose credentials from the transport choice.
SSH still requires an explicitly selected absolute known-hosts path, with existing
read-only host verification and agent-only authentication unchanged. Selection
performs no backend/account/network/credential access. Enter/n can leave selection;
q/EOF stops. Publication still requires the separate exact sync-plan confirmation.
Remote repository creation and checkout-remote discovery are not introduced.
No portable/local schema, fidelity, provenance, receipt, trust or sync semantics
change. This UX is unreleased until a separately authorized binary includes it.

### Git creation guidance and terminal input amendment

The Git URL prompt offers a guide to creating an empty private repository on
the user's Git host. The user creates it there, then pastes its clone URL back
into the same prompt. Kitrove does not open a browser, invoke a provider API,
grant permissions, discover repository settings or approve a sync plan.
Guided input holds the standard input lock only while reading a single prompt.
An HTTPS authentication challenge can therefore read the username and hidden
token after the Git URL prompt returns.

### Existing-setup routing amendment (2026-11-04)

After selecting a collection path, guided `init` checks for existing collection
control files or local state before asking for a machine name or creation approval.
Presence is only a routing hint, not ownership or permission to mutate. A valid
portable status, bounded no-follow local-state decode and existing shared lifecycle
lock are required before offering continuation. Missing, invalid, redirected or
in-use authority stops with inspection guidance, never implicit repair/deletion.

An explicit `y`/`yes` continues at the ordinary configuration menu. It does not
repeat the selected first/second-computer action, scan for collection, adopt,
apply, synchronize, create another machine identity or change existing authority.
Enter/`n` skips and `q`/EOF cancels. Normal fresh initialization and every later
operation still enforce their original preconditions; the routing observation
does not freeze authority or bypass fresh mutation checks. Scripted `init` and
`configure` retain their contracts. This is not data migration or new compatibility
support, and remains unreleased until included in a separately approved binary.

### Presentation amendment (2026-11-04)

Questions and input markers have their own spacing and fixed prompt style.
Command output and previews remain labeled and indented, including every line of
escaped untrusted output. Optional ANSI styles supplement textual labels; they
never carry authority or replace loss/omission details. Only a recognized terminal
may receive color, with `NO_COLOR` (even empty), missing/unknown TERM and dumb
terminals disabling it. Redirected output and JSON automation gain no ANSI codes.
Styles are fixed, reset before input, and never derived from capability content.

Goal-based navigation keeps adding saved items to local tools separate from
sharing a collection and from one-time copying. The setup menu's second choice
is “Choose skills to add to your AI tools.” Sharing still discloses upload and
download scope and requires the exact existing sync plan approval. Storage
selection can return “Not now” before opening a backend or invoking a credential
provider. Previously confirmed setup steps remain; skipping does not undo them.
No `Enter`, `y`, EOF, cancellation, trust, mutation, remote or receipt authority
changes. These UI changes remain unreleased until separately published.

Portable/local schemas, asset identity, fidelity derivation, trust decisions and
receipt ownership remain unchanged. Remote import grants no execution authority.
Credentials, machine IDs, local paths, trust and receipts never synchronize.
No implicit conflict resolution, unmanaged overwrite, symlink following, shell
profile edits or background sync is introduced. Secrets are not requested by the
wizard; Git credentials use the existing operation-local provider.

### Ordinary home-directory application layout

Native terminal testing exposed an existing overly broad root-overlap refusal:
user-scope application anchors at the home directory, which normally contains
both the collection and machine-local state. A dedicated application coordinator
now admits this layout, not a global relaxation of transaction locking.

Environment and state remain distinct and non-nested. A distinct target root
cannot be inside either authority root. Every root's `.kitrove` control namespace
must be disjoint from every other control namespace. Exact filesystem identities
are still unique, revalidated and locked in the same global identity order.
General transaction coordinators retain their original non-nesting rule.

Before application and recovery, planned destination paths are checked against
the complete machine-state root, nested collection authority, and every selected
control namespace. Directory ancestors are resolved without following links;
destination leaves are not followed. The established project case where the
collection itself is the target remains supported. Cleanup still visits only
the same explicitly locked, bounded control namespaces. No lock is omitted and
no recursive cleanup of a home directory is introduced.

The journal format is unchanged. Tests cover ordinary defaults, prepared/target/
state interruption recovery, protected-path refusals, existing nested-target
refusal and lock ordering. Finish any pending RC4 transaction before attempting
a binary rollback; RC3 retains the prior home-layout refusal.

Tests must cover terminal/EOF refusal, cancellation before each write boundary,
names/ambiguity/stale observations, grouped findings and JSON compatibility,
first-machine setup, subsequent configuration, isolated two-machine full sync and
selective import, conflicting identities, corrupt/missing/stale remote objects,
unchanged native variants and unrelated local content, and secret/local-state
exclusion. RC4 publication requires full local CI/MSRV, reviewed exact-head checks,
green main, normal protected signing and independent artifact authentication.

## Guided selection amendment (2026-11-02)

Maintainer-approved setup UX may preview a recommended set and accept one `y`
for that exact displayed, ordered set of first skill adoptions. Enter selects
recommendations at selection time; the separate approval gesture is amended on
November6 below. `all,-3,-8` (or `-3,-8`)
excludes numbered observations; `1,4,7` selects only those observations. Numbers
are bound to the displayed scan, never a later scan's ordering. Invalid or
mixed inclusion/exclusion input reprompts without mutation. Full inventory is
available on request rather than printed twice by default.

Recommendations omit invalid/occupied names, every same-name ambiguity, and
blocked plans. Do not privilege a harness, collapse distinct native sources,
invent names or overwrite existing assets. Show omissions and per-target fidelity
with loss reasons. Users can switch to individual review and explicitly rename
an item; Enter approves that currently displayed single adoption plan.
`n` skips and `q`/EOF stops. Other write confirmations retain skip-on-Enter;
`y` and `yes` are explicit equivalents, never session-wide approval.

Plan the bulk sequence against successive proposed manifests, retain only its
exact per-item approval digests, and invoke the existing freshly replanned
`Confirm` adoption boundary for each commit. A stale source, manifest, digest,
pending recovery, or commit failure stops later items; report prior completed
items honestly. This is not an atomic batch or automatic recovery. No new domain
API, portable schema, trust grant, receipt, synchronization, or Apply authority
is introduced. Original source files/native variants and local-only boundaries
remain unchanged. The UX is unreleased until a separately authorized binary
release includes it; current RC5.5 documentation must not claim it is installed.

### Explicit source selection and empty-preview amendment (2026-11-05)

Repeated names can arise from overlapping discovery policies or distinct local
copies. Neither name nor portable-content equality proves interchangeable native
identity. Do not deduplicate, merge native variants, privilege a harness, infer
ownership, update an occupied name or invent a new name automatically.

Guided collection accepts `from TOOL` to explicitly restrict this scan's selected
observations to one displayed tool. Optional exclusions, such as
`from codex,-3,-8`, retain the original inventory numbering. This is a one-time
selection, not a canonical-source preference or saved authority. Remaining
same-name ambiguity within that tool still refuses bulk adoption. Every ready
plan retains its source, full target fidelity/loss report, exact digest and fresh
commit checks. Excluded sources remain unchanged and are not claimed equivalent.

Omission/exclusion output defaults to a bounded sample plus counts/reasons;
`d` displays all skipped-item details before any approval. Ready plans are never
truncated. An empty preview offers choose-again, individual review, details, skip
or stop, never adoption approval or an "Adopted 0" success. Choose-again reuses
the same observed inventory; later mutations still require normal fresh planning.
No schema, identity, preservation, fidelity, receipt, trust, Apply or sync behavior
changes. These setup improvements remain unreleased until separately published.

### Guided empty-preview source choice (2026-11-09)

When an empty collection preview includes same-name observations across tools,
offer numbered choices for the tools in that selection. Each choice narrows only
the current selected original inventory indices and produces a new complete
preview; it never restores excluded observations, rescans, adopts, or saves a
preferred/canonical tool. Enter/s chooses different skills, not a default tool.
Individual review, full skipped details, skip and cancellation remain available.
Invalid keys and EOF cannot select a source or approve adoption.

Show omission/exclusion reason counts by default, with every skipped item still
available through d. Report occupied collection names separately from ambiguous
source copies, without claiming that an occupied name proves prior adoption or
equal content. Full ready-item source/fidelity/loss output is unchanged. Remaining
ambiguity within one tool still needs an exact numbered observation or individual
review; no native sources are merged and no occupied asset is overwritten.
The existing exact per-item approval, fresh capture, trust, recovery, Apply and
sync boundaries are unchanged. This presentation-only improvement is not in an
installed binary until a separately authorized release includes it.

### Immediate navigation and explicit adoption decisions (2026-11-06)

Maintainer-approved initial and subsequent five-option menus accept a single
`1` through `5` without Enter. Enter retains the subsequent-menu finish default;
the initial menu has no default. `q`, Escape, Ctrl-C, Ctrl-D and EOF stop without
authorizing an action. Unsupported keys do not select an option.

Following the complete displayed nonempty adoption preview, Enter or a single
`y` explicitly confirms only that exact ordered set. This supersedes the earlier
bulk skip-on-Enter UI, not its fresh per-item digest, source, state or recovery
checks. `n`, `s`, `r`, `d` and `q` act immediately to skip, choose again, review
individually, inspect skipped details or quit. The individual adoption preview
likewise accepts Enter/y, n, r or q immediately for its already established
single-plan decisions. EOF, invalid input and cancellation never mean Enter.
An empty preview still uses Enter/s to choose again and offers no adoption.

Display a short question with aligned choice lines and a distinct input marker,
not a semicolon-delimited help paragraph. Source filters, multi-item selection,
names and paths retain bounded line input. Initialization, trust, Apply, sync
and other confirmations retain their original defaults and approval boundaries.

Each real terminal decision requires a fresh response: discard already queued
terminal input before showing the next question and drain read-ahead after an
accepted key or text line. A reflex Enter after r/y or pasted later responses
must not become approval for a different or not-yet-displayed preview. This
type-ahead barrier does not authorize script automation; non-TTY setup still
refuses, and scripted test dialogs retain their explicit line protocol.

Temporarily change only input-terminal mode, retaining the same input buffer and
restoring its prior mode before any next prompt or operation, including errors
and cancellation. Restoration failure stops setup. The retained Windows handle
and Unix termios snapshot change no trust, filesystem permissions or portable
state. Scripted test dialogs keep line input; production still refuses non-TTY
setup. No new registry package, release or version is authorized by this UI
change. It remains unreleased until separately published.
