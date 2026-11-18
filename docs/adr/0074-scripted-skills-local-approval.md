# ADR-0074: Collect text helpers as data; approve exact bundles locally before placement

- **Status:** Accepted for implementation by maintainer, 2026-11-17
- **North Star:** NS-01, NS-02, NS-03, NS-04, NS-05, NS-06, NS-07, NS-09, NS-10
- **Related:** ADR-0073

## Decision

A skill may retain text helper scripts as inert, hash-verified collection objects. It remains Executable, including when its helper has ordinary file mode. Credential guards, capture limits, link refusal and source fidelity remain mandatory. Compiled payloads, nontext helpers, executable principal documents and native lifecycle/install/plugin directives remain ineligible. No interpreter, dependency, collected code or provider is executed by collection or placement.

Placement requires a separate exact-bundle machine-local decision keyed by the complete asset revision, covering portable and every native variant. Existing journaled trust transitions, private state, locks, fresh manifest/object verification and stale-plan refusal govern that decision. Approval does not sync. A changed bundle needs fresh approval. Tool permissions and runtime availability remain the tool's responsibility; representation fidelity is not execution permission.

Unix placement preserves recorded regular/executable mode classes. Platforms unable to preserve executable mode refuse before writing. Existing receipt-backed removal remains available after denial, but denial does not remove deployed files or revoke a running tool's permissions. Executable pack rollback remains outside this unit.

## Validation conditions

Synthetic bundles exercise inert collection, approval/denial/update invalidation, imported data without transferred trust, all four destinations, modes, credential/binary refusal, stale-state refusal, journal recovery and safe removal. No real user collection, skill, installed executable or sync mutation. Full stable/Rust1.89, source and authority review, exact public checks and green main precede commit/merge/publication claims.
