# Doctor retained-cleanup failure reasons

This applies ADR-0078 without changing the storage or cleanup policy. NS-04 and
NS-10 benefit from naming the failed invariant; NS-07 and NS-09 require redacted
observations and preservation of all existing mutation approvals and guards.

The original doctor discarded all unsafe retained-cleanup failures into one
code. A normal directory mode listing cannot identify a mismatched recorded
identity, linked entry or unexpected pending batch contents. Preserve the first
failure at its existing validation site, not through a second speculative scan.
The existing inspector remains the single traversal for cleanup and doctor.
Detailed errors carry the existing coarse outcome plus closed reason/location
labels and an optional bounded top-level listing ordinal. Mutation callers map
back to their original errors. Check order, no-follow handles, complete native
identity checks, cleanup reservations and budget charging remain unchanged.

Private directory predicates retain a closed reason on their existing error.
Their public codes/messages, equality, formatting and failure behavior remain
unchanged. Native protection refusal is reported at its actual level of evidence;
it does not invent a specific Windows ACL defect or expose principals. If no
narrower observation is available, doctor says the boundary is unverified.

The normal human report states the reason, so identifying the invariant does not
require another shell command. JSON schema 2 retains existing fields and adds
optional diagnostic detail only for failed cleanup observations. Ordinals refer
to this bounded sorted listing, never a filename, durable ID or deletion command.
Reports still stop at the first failure in each root and disclose no paths,
private names, identities, principals, body data, environment values or raw errors.

Tests use disposable fixtures for name/kind/identity/hardlink/pending/conflicting
batch/descendant-link/mode/ACL failures, deterministic replacement during open,
unchanged coarse outcomes and budgets, and human/JSON parity with canaries.
Native Windows identity and hardlink cases also check the detailed result. File
snapshots assert unchanged bytes, modes, identities, link counts, timestamps and
native ACLs where available. Existing cleanup/transaction tests remain required.

No stored schema, dependency, tool adapter, portable fidelity, receipt, trust,
sync, permission scope, version, tag, signing or publication change is included.
No retained-state repair is attempted. These observations do not establish the
cause of a historical apply refusal on another computer. Reverting this source
restores generic doctor reporting; no state migration or cleanup is required.

Validation results are recorded separately; this note does not assert unrun
checks passed or constitute exhaustive independent repository review.
