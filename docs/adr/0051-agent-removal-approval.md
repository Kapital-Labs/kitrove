# ADR-0051: Agent removal approves complete receipt-backed batches

- Status: Proposed implementation, pending validation
- North Star: NS-05, NS-07, NS-09, NS-10
- Invariants: INV-06, INV-07, INV-08, INV-11

## Decision

Add mutually exclusive `--plan` and `--confirm <batch_digest>` modes to direct
`remove` and `pack remove`. Preview is read-only and never runs recovery or reads
stdin. Explicit approval must match the complete batch, including retained
co-owners and changed local claims, not an individual receipt or pack revision.
Pack removal still requires its exact historical application revision.

Retain interactive behavior. Agent-approved operations refuse pending or invalid
batch recovery before planning and commitment; the existing core coordinator
also checks all relevant recovery authorities under its locks. Rebuild the plan
before committing and retain exact receipt, local-state and destination checks.
Modified or unmanaged content remains protected. Portable assets are not deleted.

Share the explicit approval-mode type with pack authoring. Extract removal
orchestration and argument parsing rather than enlarging large existing modules.
No new transaction engine, ownership rule, executable trust or MCP service.

## Validation

Test preview nonmutation with closed stdin, exact confirmed removal, mismatched
and stale approval, modified destinations, pending journal preservation, pack
ownership retention and strict flags. Retain existing interactive tests; full
CI/MSRV and exact public checks remain required before merge.
