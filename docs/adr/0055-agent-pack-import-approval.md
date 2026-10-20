# ADR-0055: Pack import approval preserves verified authority

- Status: Proposed implementation, pending validation
- North Star: NS-04, NS-05, NS-07, NS-09, NS-10

## Decision

Add mutually exclusive `--plan` and `--confirm <digest>` to `pack adopt` and
`pack rollback`. Neither reads stdin; both conflict with legacy `--yes`.
Keep ordinary interactive and legacy confirmation behavior unchanged.

Preview performs existing bounded remote reads and object verification without
committing collection or native authority. Backends may use temporary or cache
storage. Approval covers the existing typed plan, verified history selection,
and exact object closure; it is not authentication or executable trust.

Approved commits refuse pending recovery under the existing environment lock
before cleanup. Preserve history rereads, object verification, exact-prior
rollback and local authority revalidation. Never consume approval to recover
an earlier transaction.

## Validation

Require closed-stdin preview/confirmation, stale authority, strict flag conflicts,
pending journals, object verification and legacy confirmation regressions.
Full stable/MSRV validation and exact public checks precede merge.
