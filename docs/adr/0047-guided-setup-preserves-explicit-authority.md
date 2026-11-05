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
recommendations but does not approve bulk writes. `all,-3,-8` (or `-3,-8`)
excludes numbered observations; `1,4,7` selects only those observations. Numbers
are bound to the displayed scan, never a later scan's ordering. Invalid or
mixed inclusion/exclusion input reprompts without mutation. Full inventory is
available on request rather than printed twice by default.

Recommendations omit invalid/occupied names, every same-name ambiguity, and
blocked plans. Do not privilege a harness, collapse distinct native sources,
invent names or overwrite existing assets. Show omissions and per-target fidelity
with loss reasons. Users can switch to individual review and explicitly rename
an item; Enter approves only that currently displayed single adoption plan.
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
