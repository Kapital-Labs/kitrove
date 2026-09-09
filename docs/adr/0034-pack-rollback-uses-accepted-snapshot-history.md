# ADR-0034: Pack Rollback Uses Accepted Snapshot History

- **Status:** Accepted
- **Date:** 2026-08-31
- **North Star invariants:** NS-01, NS-03, NS-05, NS-06

## Context

An exact pack revision binds its source declaration, source revision, exact source hash, direct
member revisions, derived compatibility, content class, and bindings. The current manifest and lock
retain only current desired-state authority. They cannot reconstruct an older pack or an older member
revision after an update.

`pack update` already accepts a caller-selected member set. Reusing that interface under a rollback
name would create new desired state rather than restore known prior authority. Persisting mutable
history inside the pack would also make desired state machine-dependent and conflict with ADR-0023.

The sync backends already retain bounded immutable snapshot history, and the machine-local sync base
store retains verified immutable generations and their object envelopes. Those are the appropriate
sources of prior evidence.

## Decision

Pack rollback restores one exact prior pack revision from a complete, previously accepted portable
snapshot. It never derives prior state from current files, a caller-supplied member list, or an
unverified manifest.

The workflow has four authority boundaries:

1. History inspection follows only the selected remote's bounded, verified ancestry. A retained
   machine-local generation is eligible only when its record, canonical manifest, snapshot digest,
   backend revision, and complete immutable object catalog all verify.
2. The caller selects the pack, exact current revision, and exact historical pack revision. Selection
   fails closed when the revision is absent, ambiguous across the inspected ancestry, not older than
   current accepted authority, or outside the configured history budget.
3. Planning grafts the selected historical pack's exact transitive component closure into current
   authority. Unrelated current records remain current. Any shared component change re-derives and
   reports every affected aggregate; a missing historical object, identity collision, cycle, invalid
   derived record, or unsafe executable transition refuses the plan.
4. Confirmation binds the current manifest revision, selected historical snapshot identity, target
   pack revisions, complete proposed manifest and lock, required immutable objects, and affected
   aggregates. Commit uses the existing crash-recoverable portable mutation transaction. Local
   projections change only through a separately confirmed atomic pack application; rollback does not
   infer destination ownership or silently overwrite drift.

The initial CLI is explicit:

```text
kitrove pack rollback --pack <pack-id> --expected-prior <current-pack-hash> \
  --to <historical-pack-hash> [remote selection] [--yes]
```

`--to` names a pack revision, not a backend commit. Output also identifies the selected snapshot in
content-redacted form so the user can distinguish equivalent pack revisions reached through different
environment histories.

`pack remove` remains the local deactivation operation. It releases exact machine-local claims and
unshared projections while preserving portable pack authority; a second `pack disable` command would
duplicate those semantics and is not planned.

## Consequences

- Rollback works across machines after synchronization because its authority is portable snapshot
  history rather than one machine's mutable command log.
- A rollback cannot be promised before history and every required immutable object have been fetched
  and verified.
- Current unrelated environment changes survive a selective pack rollback, while shared changes are
  visible as affected aggregate revisions instead of hidden side effects.
- Portable rollback and local re-application are separate confirmations until one reviewed composite
  transaction can preserve both authority domains atomically.

## Validation

- Current-revision mismatch, unknown/ambiguous/non-ancestor target, history-budget exhaustion,
  malformed snapshot, incomplete object catalog, missing closure member, cycle, shared-member impact,
  and executable-policy bypass are non-mutating refusals.
- The plan digest changes with the selected snapshot, either pack revision, closure, object catalog,
  current manifest revision, proposed manifest/lock, or affected aggregates.
- Interruption tests cover every journal phase and retain all immutable prior objects.
- Stable and Rust 1.85 tests cover filesystem, Git HTTPS, and Git SSH history providers before the CLI
  is accepted.

## Rejected alternatives

- **Alias rollback to `pack update`:** constructs desired state without proving that it ever existed.
- **Store history in each pack:** mixes machine history into synchronized desired-state identity.
- **Read an arbitrary manifest path:** gives unverified local input lifecycle authority.
- **Shell out to ambient Git:** bypasses Kitrove's bounded transport, history, and credential policy.
- **Restore the whole historical environment:** discards unrelated current work when only one
  lifecycle object was selected.
