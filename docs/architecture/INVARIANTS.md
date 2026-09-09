# Architectural Invariants

This file translates the North Star into implementation constraints. `cargo xtask governance` verifies the identifiers remain present.

## INV-01 — Harness neutrality

No harness-specific representation may be the canonical domain model. Adapters convert between observed native resources and Kitrove assets.

## INV-02 — Bidirectional adapter boundary

Every tier-one adapter is designed for both inspection and materialization, even when one direction is initially unsupported. Unsupported operations return structured results rather than being absent conceptually.

## INV-03 — Portable/native coexistence

An asset may hold portable content and zero or more native variants simultaneously. Applying to one target cannot erase another target's native variant.

## INV-04 — Mandatory fidelity

Every planned target result includes a fidelity category and reasons. No adapter operation returns bare success for a lossy transformation.

## INV-05 — Immutable captured sources

Adoption and external-source resolution retain an immutable captured snapshot identified by content hash before transformation.

## INV-06 — Proven ownership

Destructive destination changes require a matching receipt, explicit managed marker, or user-approved reconciliation.

## INV-07 — Portable/local type separation

Portable schemas cannot reference types that contain resolved secrets, machine authentication state, trust decisions, deployment receipts, or transient paths.

## INV-08 — Transactional mutation

Adopt, apply, sync, upgrade, and rollback stage changes and expose recoverable failure states.

## INV-09 — Backend separation

Sync backends transport portable state. Source resolvers retrieve assets. Harness adapters interpret harnesses. No layer silently assumes another layer's responsibility.

## INV-10 — Version-aware evidence

Adapter behavior is tied to tested harness versions or an explicit unknown-version policy.

## INV-11 — Deterministic plans

Equivalent desired state and observed state produce equivalent plans, excluding timestamps and non-semantic presentation fields.

## INV-12 — No implicit execution

Fetching, scanning, resolving, and planning do not execute capability-provided code. Scan also launches no harness binary; active diagnostics use a separate reviewed command.
