# ADR-0063: Profile validation is stack-safe

- **Status:** Accepted for implementation; validation pending
- **Date:** 2026-10-23
- **North Star:** NS-03, NS-05, NS-07, NS-09, NS-10
- **Invariants:** INV-03, INV-07, INV-08, INV-12

## Context

Profile inheritance is a flat, single-parent graph in the portable manifest.
Cycle validation recursively follows parents without a depth bound. An isolated
1,040,001-byte manifest with a 20,000-profile acyclic chain makes the read-only
CLI status command abort with stack overflow before ordinary validation returns.
The later profile resolver is already iterative. This is an availability defect,
not evidence of data loss or permission to mutate an environment.

## Decision

Validate profile cycles iteratively, retaining completed-node memoization and a
per-walk set. Each profile has at most one outgoing parent edge, so an explicit
walk can preserve the existing valid/invalid distinction without native stack
growth proportional to chain depth. A repeated node in the current walk retains
the existing manifest.profile_cycle error. Unknown parents and mismatched profile
identities retain their existing earlier validation errors.

Do not add a new profile-depth policy or schema version merely to repair the
implementation. Existing byte and sync-record intake limits still apply. Valid
deep chains remain valid; cycle rejection must not depend on traversal ordering
or whether part of the parent chain was visited previously.

## Scope and alternatives

A recursive depth cap would reject previously valid manifests and introduce a
new product limit. A larger thread stack would only move the failure boundary.
Neither is needed for this single-parent graph. Discovery/adoption, native bytes,
fidelity, provenance, receipts, trust, sync/conflict rules and mutation authority
are unchanged. This introduces no execution, transport or release operation.

## Validation

Run deep acyclic and cyclic parser cases in isolated test subprocesses so stack
overflow becomes an ordinary failing parent test. Cover shared completed ancestry,
self-cycles, missing parents and existing shallow profile-resolution behavior.
Observe the deep regression fail before changing production code. Full stable,
Rust1.88, source review, exact hosted checks and exact green main remain required.
