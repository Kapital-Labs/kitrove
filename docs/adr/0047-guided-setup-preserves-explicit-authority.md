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
selects skills by readable names and scopes, confirms each adoption, and separately
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
