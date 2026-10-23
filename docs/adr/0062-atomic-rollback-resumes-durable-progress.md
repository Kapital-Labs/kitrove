# ADR-0062: Atomic rollback resumes durable progress

- **Status:** Accepted for implementation; validation pending
- **Date:** 2026-10-23
- **North Star:** NS-03, NS-05, NS-06, NS-07, NS-09, NS-10
- **Invariants:** INV-03, INV-05, INV-06, INV-07, INV-08, INV-11, INV-12

## Context

Receipt-backed atomic batches persist rollback progress before destructive
operations. Recovery currently always enters RollingBack again, which the strict
journal transition validator rejects if recovery itself was interrupted there.
A real local fixture with durable production journal transitions reproduces
failure on retry while the old local state and target remain intact. This is a
recovery availability defect, not evidence of a data-loss incident.

## Decision

Recovery resumes existing RollingBack progress instead of repeating its entry
transition. A terminal RolledBack journal resumes only verified artifact cleanup.
Participant recovery likewise recognizes persisted removal/restoration boundaries
and already-rolled-back participants. It never loosens the valid journal graph
or changes digest-bound authority to accommodate a retry.

Before removing a target or restoring a backup, use the existing exact identity,
retained-root and no-follow boundaries. Changed or unmanaged destination content
must not be overwritten. Completed participants need no repeated target mutation;
terminal cleanup removes only exact journal-owned artifacts and leaves later
user changes to destinations untouched. Local state remains the already-verified
old state throughout rollback.

## Scope and safety

Discovery, adoption, portable/native object formats and preservation, fidelity,
provenance, receipts, synchronization and conflict rules are unchanged. No trust
or secret authority becomes portable. No automatic migration, execution,
provider operation or release is introduced. This corrects the existing failure
recovery contract; malformed journals, changed control authority and unsafe
paths still fail closed.

## Validation

Tests must fail before each corresponding production correction. Cover durable
phase entry, RemovePending before/after removal, RestorePending before/after
restoration, already-rolled-back participants and terminal cleanup; include
install, restore, managed update, removal and no-op dispositions and mixed
reverse-order batches. Refuse changed target/backup/control authority without
overwriting user data. Full stable/Rust 1.88 validation, independent source review,
exact hosted checks and green merged main precede completion or later releases.
