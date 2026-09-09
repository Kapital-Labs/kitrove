# Contributing to Kitrove

Kitrove is currently a private public-alpha release candidate, dual-licensed under MIT or Apache-2.0. The eventual public repository will accept contributions after its reporting channels are active. Until then, participation is by invitation. Optimize for correctness of the product model rather than feature count.

Before opening a change, read `NORTH_STAR.md`, `DEVELOPMENT_RULES.md`, and the relevant architecture decisions, then determine whether the proposal requires a new ADR.

Every pull request must include:

- purpose and user outcome
- affected `NS-*` invariants
- architecture impact
- security and privacy impact
- fidelity and loss behavior
- tests added or intentionally deferred
- documentation updates
- rollback or migration considerations

Before requesting review, run the canonical repository validation from the workspace root:

```bash
cargo ci
```

This is the same validation contract used by GitHub Actions. It includes formatting checks, Clippy with warnings denied, all workspace tests and features, governance validation, dependency-license policy, and repository hygiene checks.

Review order:

1. Product boundary
2. Data-loss and fidelity behavior
3. Security and ownership
4. Synchronization semantics
5. Domain design
6. Harness-specific correctness
7. Code quality and performance

A clean implementation of the wrong product model must not be merged.

Never attach real harness state, credentials, private skills, absolute machine paths, or proprietary capability content to an issue or pull request. Build reproductions from the synthetic fixture helpers. Report security issues through the private process in `SECURITY.md`, not in a public issue.

Harness-policy changes also follow [`docs/ADAPTER_GUIDE.md`](docs/ADAPTER_GUIDE.md). User-visible behavior and breaking persistence changes require a changelog entry and, when they alter an accepted architecture decision, a new or superseding ADR. Unless explicitly stated otherwise, intentionally submitted contributions are licensed under the project's dual MIT OR Apache-2.0 terms.
