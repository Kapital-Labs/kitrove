# ADR-0050: Agent pack authoring requires exact plans and refuses recovery

- Status: Proposed implementation, pending validation
- North Star: NS-04, NS-05, NS-07, NS-09, NS-10
- Invariants: INV-06, INV-07, INV-08, INV-11, INV-12

## Decision

Add mutually exclusive `--plan` and `--confirm <digest>` to `pack create`
and `pack update`. Neither flag changes the existing interactive default.
Preview emits the existing plan without prompting or mutating; confirmation
compares the exact typed planner digest without reading stdin. Update still
requires the exact prior pack revision. Whole proposed manifest authority,
affected parent aggregates and member identities remain covered by the planner.

The unattended commit path must refuse every pending portable journal under
the environment lock before cleanup, recovery or mutation. A CLI-only precheck
is insufficient because a journal can appear between planning and commitment.
Existing interactive commits retain their recovery behavior. Both paths reuse
the same transaction and stale-manifest checks.

No digest grants user authorization, executable trust, destination ownership or
permission to transfer credentials. Pack authoring changes portable desired
state, not installed projections. Import, adoption and removal remain separate
increments, and no MCP service is introduced.

## Validation

Cover read-only preview with closed stdin, valid exact approval, wrong/stale
approval, changed member selection and parent aggregates, strict incompatible
flags, pending/malformed journal preservation, and interactive compatibility.
Run full CI/MSRV, review and exact public checks before merge.
