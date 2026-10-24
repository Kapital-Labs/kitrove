# ADR-0064: Instruction insertion respects the region ceiling

- **Status:** Accepted for implementation; validation pending
- **Date:** 2026-10-24
- **North Star:** NS-05, NS-09, NS-10
- **Invariants:** INV-06, INV-08, INV-11

## Context

Managed instruction documents are co-owned with the user. Their parser enforces
an existing request-local maximum region count (256 by default). The pure updater
validates its input with that limit, but can append one more distinct region.
Both single and coalesced core planners then approve output that the same parser
refuses on later observation. The isolated reproduction did not commit a target
write or demonstrate data loss.

## Decision

Before rendering or allocating an insertion result, refuse a new managed region
when the parsed document already contains the maximum permitted count. Reuse the
existing closed `instruction.region_limit` error. Do not raise the ceiling,
truncate regions, remove another asset, or alter bytes outside the selected
managed region. Updating an existing region at the ceiling remains allowed.
Zero means no new regions may be inserted. Existing malformed or over-limit
documents continue to fail their input validation unchanged.

The shared pure renderer enforces this boundary for both single and coalesced
planning before any transaction or receipt mutation is possible. Existing core
error mappings remain unchanged; no new public schema or error code is needed.

## Unchanged boundaries

Discovery and adoption, portable/native representation, fidelity, exact source
preservation, provenance, receipt ownership, local-state schemas, trust and
sync/conflict semantics are unchanged. No credential, process, transport or
release authority is introduced. This is existing-limit enforcement, not a new
instruction-count policy or an authorization to repair an already invalid file.

## Validation

Observe renderer and both real planner regressions fail before production edits.
Cover zero, one and default ceilings; below-ceiling insertion; same-region
updates at the ceiling; successful reparse; and exact preservation of human and
other-region bytes. Refused planning must leave target bytes and local receipt
state unchanged. Run full stable/Rust1.88 validation, source review, fresh exact
public checks and exact green latest main before merge. Existing releases and
failed release tags remain immutable; this repair does not authorize publication.
