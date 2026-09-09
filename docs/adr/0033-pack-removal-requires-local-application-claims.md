# ADR-0033: Pack removal requires machine-local application claims

- Status: Accepted for Phase 4 implementation
- Date: 2026-08-31
- North Star: NS-02, NS-05, NS-07, NS-09, NS-10

## Context

A deployment receipt proves that Kitrove owns one rendered destination, but it intentionally does
not say why the destination was requested. The same receipt can result from an explicit asset,
profile, or pack application. Removing every receipt whose asset is currently a pack member would
therefore erase capabilities that the user also requested independently. Current portable pack
membership is also insufficient historical authority because a pack may be updated after it was
applied.

## Decision

Kitrove records pack application ownership in machine-local `state.json`. One claim binds an exact
pack revision, scope, normalized target anchor, selected target set, and the receipt IDs that the
application owns. Its key is a versioned BLAKE3 identity over the stable application context; the
pack revision and receipt set are mutable exact evidence within that context.

Claims follow conservative reference semantics:

1. A newly materialized receipt selected through one or more packs is owned by every selecting pack.
2. A receipt already owned by another pack may be co-owned by a newly applied pack.
3. A pre-existing receipt with no pack owner is treated as independently or historically owned and
   is not claimed by a later pack application.
4. An explicit-asset or profile application removes overlapping receipt ownership from every pack
   claim. Direct intent therefore takes precedence whether it occurs before, during, or after a pack
   application.
5. Empty claims are removed. Claims and deployment receipts are committed in the same atomic batch
   state transition and participate in the confirmed digest, stale-state check, rollback, and crash
   recovery.
6. Pack removal may delete a receipt only when the selected claim owns it, no retained claim owns it,
   and current receipt authority still exactly matches. Missing, malformed, legacy, stale, or
   ambiguous ownership fails closed instead of inferring deletion authority.
7. Removal confirms the historical revision recorded by the local claim. A later portable pack
   update does not rewrite or strand that installed evidence; current manifest authority is still
   required to validate every affected asset and transaction.

Claims are local. They are never synchronized, placed in the portable manifest or lock, or treated
as evidence that another machine installed the same pack.

## Consequences

Pack removal can be coherent and reference-aware without embedding lifecycle provenance in every
receipt or inventing reference counts. Multiple packs can share one physical projection, and direct
application remains an explicit retention mechanism. Existing local-state JSON remains readable
through a default-empty claim map, but receipts created before this decision cannot be removed as a
pack unless a later confirmed application establishes unambiguous ownership.

When logical instruction regions or MCP entries share one physical document, removal coalesces all
selected receipt transitions into one guarded document mutation. Exclusively owned logical content
is removed while content retained by another pack remains receipt-backed; the whole-document hash
authority of retained MCP entries advances with that same atomic transition.

Executable extension removal validates current manifest/object/policy authority and exact installed
receipt bytes, but does not require the object to remain trusted: revoking execution trust must not
strand an already installed projection. Its removal and rollback use the same layout-aware guarded
journal authority as extension installation and update.

Changing the pack revision, scope, anchor, targets, receipt set, claim identity, or precedence rules
changes confirmed authority and must be covered by deterministic identity, stale-plan, recovery, and
non-mutation tests.
