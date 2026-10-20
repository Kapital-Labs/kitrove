# ADR-0049: Agent materialization approval uses exact batch authority

- Status: Proposed implementation, pending review
- North Star: NS-04, NS-05, NS-07, NS-09, NS-10; no weakening
- Invariants: INV-04, INV-06, INV-07, INV-08, INV-11, INV-12

## Decision

Expose `apply --confirm <batch-digest>` as the non-interactive counterpart of
`plan --json`. The existing `batch_digest`, not a single item's `plan_digest`,
authorizes the complete atomic batch, including selected pack ownership.
The CLI compares typed core digests; presentation text is never approval authority.
No `--yes` bypass is added.

The command builds the current plan, compares its exact batch digest, rebuilds
and checks it again, and uses the existing commit coordinator and locked
preconditions. It does not consume stdin or prompt. Stale approval is an error.
The existing interactive apply path remains compatible.

Unattended apply refuses pending or invalid batch recovery before planning and
again before commitment; a supplied digest cannot authorize an earlier journal.
An operator must handle recovery through the existing workflow, inspect the
outcome, and generate a fresh plan. Planning remains non-mutating.

No portable schema, native variant, fidelity, adapter, trust or receipt semantics
change. Credentials, local paths and trust do not become portable. A digest is
not an authentication token: the calling agent still needs user authorization
and local filesystem access. Explicit version probes retain their existing
consent and executable-bound rules.

## Validation

Cover missing/malformed/repeated confirmation, confirmation rejected on `plan`,
closed-stdin successful apply, single-item digest rejection, stale approval,
pending recovery refusal without mutation, unmanaged target refusal, and
unchanged interactive behavior. Full CI, Rust 1.85 and exact public checks remain
required before merge.

## Scope

This first increment covers materialization. Adoption, removal and pack
authoring approval interfaces remain follow-up work. Sync and trust already
provide explicit digest-confirmed operations. An MCP server is not introduced.
