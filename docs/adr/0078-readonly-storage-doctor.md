# ADR-0078: Read-only local storage doctor

- **Status:** Accepted for source implementation; validation pending
- **North Star:** NS-01, NS-04, NS-07, NS-08, NS-09, NS-10
- **Related:** ADR-0037, ADR-0038, ADR-0076; local materialization and recovery

## Context

A portable status report verifies collection authority but does not inspect every
private-state, control or retained-cleanup boundary used by application. A support
script that only lists modes can miss native ACL policy and persisted identity
checks. Requiring a transferred script also makes diagnosis harder on another
computer. Generic storage errors alone cannot establish a historical cause.

## Decision

Provide `kitrove doctor --environment <collection> [--json]`, with the existing
setup default collection for bare invocation. The command is a local read-only
observation, not a preflight grant or repair operation.

A core reporting facade reuses existing no-follow root capabilities, nonrepairing
private-boundary inspection, native ACL checks and bounded quarantine inspection.
Any extracted predicate remains shared with the existing writer rather than
introducing a second filesystem policy. Use one inspection-only production budget
across the selected roots; it grants no cleanup or mutation authority.

Observe existing lock and fixed recovery-marker metadata without acquiring locks,
creating controls or reading recovery bodies. Report missing optional controls as
missing. Reuse bounded portable manifest/lock/object integrity primitives without
changing `status` or its JSON contract. Project-target diagnostics remain outside
the initial CLI surface.

The versioned CLI result has fixed roles, stages, statuses and reason codes, with
optional bounded counts. It includes the public CLI version and explicitly marks
`inspection: unlocked` and `mutation_access: not_tested`. No path, principal,
environment value, skill identifier, file body, trust decision, persisted inode
identity or raw operating-system error enters the report. Public report types
expose observations, never capability handles or write authorization.

Human output summarizes observations and relevant next actions. Ordinary findings
use status3; reported observations without findings use status0. Invalid arguments
and unexpected command failures retain ordinary CLI handling. Inspect-mode
refusals are not predictions that an approved mutation could never normalize a
private mode. Neither successful metadata nor a visible lock proves lock
availability, operating-system write access, a coherent multi-root snapshot or
the cause of a past failure.

The command must not initialize, create/acquire locks, normalize permissions,
recover, reserve mutation authority, delete quarantine, probe writes, synchronize,
execute collected content, launch another program or contact a provider. No
`--fix` path exists. Existing apply ownership, stale-plan, fidelity, trust and
recovery guards remain authoritative. Grok gains no tool or output schema from
this CLI command.

## Validation and consequences

Use disposable synthetic fixtures to prove unchanged names, bytes, modes,
identities and native ACLs for passing and refused inspections. Cover absent roots
and controls, held locks without acquisition, link-like objects, hardlinks,
malformed or changed retained identities, recovery-marker metadata, shared limits
and native private-boundary refusals. Canary paths, identifiers, principals and
bodies must remain absent from human and JSON reports.

Preserve existing apply and status error/JSON contracts. Validate source with the
normal stable/MSRV and native platform checks before publication. This decision
adds no dependency, persistence format, permission scope, account access, signing
activation, version, tag, release or channel authority.

A report can narrow current storage failures. It cannot turn unobserved historical
conditions into a verified root cause, and it does not justify deleting or changing
retained state without a separate evidence-backed repair.
