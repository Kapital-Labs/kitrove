# ADR-0072: Interactive inventory can enter explicit collection

- **Status:** Accepted for implementation by maintainer request, 2026-11-16
- **North Star:** NS-01, NS-02, NS-03, NS-04, NS-05, NS-06, NS-07, NS-09, NS-10
- **Related:** ADR-0012, ADR-0047, ADR-0052

## Decision

The interactive CLI inventory can hand off to the existing guided collection
flow when the user selects **Add to collection**. This supersedes the assumption
that every interactive scan session ends after read-only browsing. It does not
change the read-only adapter observation engine or the JSON, verbose and
non-terminal scan contracts.

The handoff retains the exact captured report and its harness, scope, project
boundary and explicit roots. The user selects a destination collection. Existing
collection status and local authority must validate, or initialization requires
its own machine identity and confirmation through the existing initialization
flow. Choosing Add is not initialization or adoption approval.

Existing selection, full ready-plan source/fidelity/loss display and exact digest
confirmation remain mandatory. Fresh commit recaptures using the original scan
selection and the chosen destination, and refuses changed sources, state, pending
recovery or invalid authority. No default all-harness or user-only rescan can
replace the observations the user just browsed. Collection never implies Apply,
sync, execution, executable trust or remote access. Previously confirmed steps
remain on later cancellation or failure; the CLI must not claim no files changed
after leaving browsing for collection.

## Readiness and presentation

A scan candidate is **Ready to preview**, not proven ready to add. The collection
planner separately checks occupied names and blockers. Matching names are skipped
without claiming content equality or prior successful adoption. The default
summary shows the selected count, ready count, occupied names and bounded named
blocker explanations. Full skipped and excluded details remain available on
request. No trust or loss reason may be hidden for a ready plan.

## Validation and limits

Synthetic terminal tests cover direct navigation, existing/new collections,
separate initialization/adoption approvals, harness/project/explicit-root capture
selection, skip/cancel, stale-source refusal, terminal restoration and honest
completion. Existing full-machine scan snapshots, process sentinels, JSON/verbose
contracts and digest/lifecycle tests remain required. No schema, provenance,
receipt, sync, dependency, version, release, migration or stable-support change is
introduced. Publication requires a separately authorized release.
