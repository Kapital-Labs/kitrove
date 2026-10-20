# ADR-0052: Adoption approval refuses implicit recovery

- Status: Proposed implementation, pending validation
- North Star: NS-05, NS-07, NS-09, NS-10
- Invariants: INV-06, INV-07, INV-08, INV-11

## Decision

Add mutually exclusive `adopt --plan` and `adopt --confirm <digest>`, including
exact-prior updates. Preview returns the existing redacted typed plan without
recovery, writes or stdin. Approval matches the typed plan digest; it does not
authenticate a user or grant executable trust. Existing interactive behavior
remains available.

The approved core entry points refuse pending recovery under the existing locks,
before cleanup, while retaining source rereads, exact manifest/prior checks,
object verification and transactional commits. Native-extension preservation must
obey the same rule even though it uses the portable sync coordinator. Never
interpret a confirmation digest as permission to finish an older transaction.

Keep native content, symbolic bindings and machine-local receipt authority within
their existing boundaries. No credentials, trust grants or new capability kinds.

## Validation

Exercise closed-stdin preview and exact approval, stale source/manifest/prior,
strict flags, pending valid and invalid journals, and ordinary interactive
regressions. Full CI/MSRV and exact public checks precede merge. The real-machine
agent acceptance remains a separate milestone gate.
