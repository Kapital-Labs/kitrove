# Development Rules

1. **Governance precedes implementation.** Foundational behavior changes through ADRs, not incidental shortcuts.
2. **Every change names its North Star impact.** Pull requests identify affected `NS-*` invariants.
3. **No silent loss.** Unpreserved semantics return `Partial`, `Unsupported`, or `Blocked` with structured reasons.
4. **Round-trip is a core quality property.** Inspectable and materializable capabilities require semantic round-trip or explicit-loss tests.
5. **Managed ownership is proven.** Removal and overwrite require receipts or another reviewed ownership mechanism.
6. **Portable and local state remain separate.** Machine identity, trust decisions, receipts, caches, bindings, and authentication observations remain local.
7. **Security-sensitive actions require plans.** Remote executable content follows `fetch -> inspect -> plan -> trust -> apply`.
8. **Scope is reviewed, not accumulated.** A feature belongs only when it helps capabilities be discovered, adopted, preserved, understood, versioned, adapted, synchronized, or reproduced.
9. **Evidence drives adapters.** Harness behavior requires official documentation, a versioned fixture, or reproducible observation.
10. **Private does not mean careless.** Never commit credentials, proprietary work assets, conversation logs, or personal authentication state.
