# Kitrove

> **Public-alpha release candidate in a private staging repository**
> Kitrove is the provisionally approved public name, subject to formal trademark and domain clearance. The fresh `Kapital-Labs/kitrove` repository exists, but source publication and signed releases remain gated.

Kitrove is a Rust-first, local-first portability layer for a developer's durable agent environment. It discovers, adopts, versions, preserves, adapts, and synchronizes agent capabilities across harnesses and computers while keeping credentials, authentication, and machine-private state local.

## The product thesis

Most adjacent tools begin with a central configuration and deploy it outward. Kitrove is built around a different lifecycle:

```text
harness -> scan -> adopt -> preserve -> adapt -> synchronize -> round-trip
```

A useful capability acquired in Claude Code should be adoptable into portable state, retain any Claude-native behavior, adapt honestly for Codex, Pi, and OpenCode, and follow the developer to another computer.

## Current status

Gates C through F and Gate G work units G1-G4 have completed implementation review. The current CLI supports safe environment initialization, read-only discovery, explicit first and update adoption, recoverable atomic multi-target materialization, filesystem and bounded HTTPS/SSH Git synchronization, first-class pack identity, exact Pi native-extension preservation, machine-local exact-content executable trust, explicit executable-bound Pi version probing, saved-trust project extension materialization, and atomic application of broader portable capabilities. Release acceptance still requires the exact candidate revision to pass the documented stable, Rust 1.85, architecture, security, test-evidence, and native-platform checks.

This is not a public release. The source is dual-licensed under MIT or Apache-2.0. Approval of the historical 272-file public snapshot does not cover the current source; a refreshed exact-snapshot review remains required. Packaging and offline installer workflows are implemented, while formal naming clearance, signed release acceptance and public repository security setup remain open.

### Implemented support matrix

| Capability | Model and core | Current CLI | Released product |
| --- | --- | --- | --- |
| Environment bootstrap | Empty manifest, derived lock, and machine-local authority are validated independently | `init` scans first, then creates complete authority without adopting capabilities | Not released |
| Claude Code, Codex, Pi, and OpenCode skill discovery | Implemented with compiled, evidence-backed policies | `scan` inventory and classified scan | Not released |
| Portable skill, prompt-command, and Pi extension adoption and updates | Implemented with exact native preservation, risk classification, and transactional state | `adopt` supports first adoption and exact-prior updates, including inert prompt commands and native Pi extensions | Not released |
| Receipt-backed materialization | Implemented with fidelity results, plan digests, coalesced shared documents, and crash recovery | `plan` and confirmed `apply` commit selected targets and machine state as one recoverable atomic batch | Not released |
| Cross-machine continuity | Filesystem and bounded smart-HTTPS/SSH Git backends implemented | `sync plan` and confirmed `sync apply`; SSH uses explicit known-host authority and agent authentication, while HTTPS accepts an explicit environment credential provider | Not released; Pageant, Git helpers, and stored credentials remain unsupported |
| Executable native preservation | Exact Pi extension capture plus machine-local content-hash trust is implemented | Machine-local exact-content trust plus explicit executable-bound Pi evidence authorize exact user and saved-trust project targets on Unix and Windows | Not released; Kitrove never executes extensions or changes Pi trust |
| Packs | Bounded aggregate resolution, verified distribution adoption, application claims, selective historical grafting, and crash-recoverable mutation are implemented | `pack discover`, `adopt`, `list`, `inspect`, `create`, `apply`, `update`, `remove`, and verified `rollback` support skills, prompt commands, instructions, agents, MCP declarations, and—on supported platforms—authorized user/project Pi extensions | Not released; arbitrary repository resolution remains open |
| Commands, instructions, agents, and MCP declarations | Standing instructions, inert prompt commands, subagents, and narrow remote-HTTPS MCP declarations have receipt-backed local lifecycles with symbolic bearer bindings and shared-document ownership | `scan`, confirmed adoption and supported exact-prior updates, coalesced `plan`/`apply`, and exact local or pack removal support the implemented capability/target pairs while retaining portable authority | Not yet a complete alpha workflow |
| Installation and distribution | Separate application/installer archives, exact offline provenance, guarded installation/replacement, recovery, and retained history are implemented | The separate `kitrove-installer` exposes install/upgrade/rollback, recovery/history, and read-only attestation-bundle selection; build from reviewed source until release acceptance | No supported public package or signed binaries; fresh public repository is empty |

## Alpha boundary

The current implementation deliberately does not provide:

- a supported installer, crates.io package, signed binary release, or stability guarantee;
- automatic trust, extension execution, dependency installation, or package management;
- automatic conflict resolution, arbitrary historical restoration, or application-data rollback (verified pack-history rollback and compatible application-binary rollback are implemented);
- arbitrary Git refs, ambient credential stores, Pageant, Git helpers, redirects, or proxies;
- dynamic third-party adapters, a registry, background watcher, TUI, or desktop UI.

Only documented tier-one skill layouts are materialized across Claude Code, Codex, Pi, and OpenCode. Native executable preservation and local materialization are limited to documented Pi user and saved-trust project extension layouts with exact local content and version authority. Unsupported or lossy paths remain explicit fidelity results rather than silent approximation.
Verified executable-bound `opencode2` evidence enables the accepted OpenCode V2 policies;
unknown versions remain conservative. See [INSTALLER.md](docs/INSTALLER.md) for the
offline installer contract and remaining first-download trust gates.

## Build and inspect the candidate

Rust 1.85 or newer is required on macOS, Linux, and Windows. Kitrove carries an audited syntax-only
patch for the locked `russh -> pageant 0.2` dependency, which declares Rust 1.85 support but used
newer syntax. Exact native Windows validation covers the complete CLI dependency graph, and
operating-system-sensitive source changes repeat that check automatically.
Until a signed release exists, build only from a reviewed source revision:

```bash
cargo build --locked --release -p kitrove-cli
./target/release/kitrove help
```

Read-only discovery works before an environment is initialized:

```bash
./target/release/kitrove scan --json
```

Create empty portable authority and private machine-local state after that read-only inventory:

```bash
./target/release/kitrove init --machine-id my-machine
```

Authority-changing workflows separate planning from confirmation. `kitrove lock` is the narrow exception: it immediately rebuilds deterministic derived lock state from the already-authoritative manifest and does not change portable authority. Run `kitrove help` for the exact current command contract; product-spec examples may describe later work that is not implemented yet.

## Start here

Every contributor and coding agent must read:

1. [`NORTH_STAR.md`](NORTH_STAR.md)
2. [`docs/01-PRODUCT-SPEC.md`](docs/01-PRODUCT-SPEC.md)
3. [`docs/02-ARCHITECTURE.md`](docs/02-ARCHITECTURE.md)
4. [`docs/04-THREAT-MODEL.md`](docs/04-THREAT-MODEL.md)
5. [`DEVELOPMENT_RULES.md`](DEVELOPMENT_RULES.md)
6. [`docs/ADAPTER_GUIDE.md`](docs/ADAPTER_GUIDE.md) for harness-policy work
7. Relevant [architecture decision records](docs/adr/README.md)

## Tier-one targets

Harnesses:

- Claude Code
- Codex
- Pi
- OpenCode

Platforms:

- macOS
- Linux
- Windows

WSL is treated as a separate Linux machine profile rather than being implicitly merged with Windows.

## Non-goals

Kitrove is not a general dotfiles manager, system package manager, harness installer, runtime manager, password manager, credential synchronizer, model proxy, chat-history synchronizer, or agent runtime.

It may detect missing prerequisites and explain them. It does not own their installation.

## Repository layout

```text
crates/                     Rust workspace
  kitrove-model/            Domain types and invariants
  kitrove-adapter-api/      Harness adapter contract
  kitrove-core/             Planning and reconciliation
  kitrove-cli/              CLI entrypoint
  adapters/                 Tier-one harness boundaries
  kitrove-testkit/          Synthetic test helpers
xtask/                      Rust-native repository automation
docs/                       Product, architecture, security, and reviews
fixtures/                   Synthetic harness homes
examples/                   Non-normative examples
.github/                    Review templates and CI
```

## Private-to-public strategy

This repository is the private release-staging history. The empty public destination is
`Kapital-Labs/kitrove`; only the newly approved source snapshot may be copied into it
as clean initial commits after architecture, security, dependency, provenance, naming,
and history review. Do not publish this repository's private history. See
[`docs/PUBLIC_SOURCE_MANIFEST.md`](docs/PUBLIC_SOURCE_MANIFEST.md).

## Development checks

Run the complete validation contract before opening or updating a pull request:

```bash
cargo ci
```

`cargo ci` is a repository-local Cargo alias backed by the Rust `xtask` crate. It runs formatting checks, Clippy with warnings denied, the full workspace test suite, governance validation, dependency-license policy, and repository hygiene checks. Pull requests run this canonical check on Ubuntu. Pushes to `main` and manually dispatched acceptance runs execute the complete Ubuntu, macOS, Windows, Rust 1.85, public-Git, and advisory matrix. Documentation-only changes are excluded from the expensive build matrix, while the separate pinned secret scan still covers every change. Newer runs cancel superseded work on the same ref.

Focused commands remain available during development:

```bash
cargo fmt --all
cargo test --workspace --all-features
cargo xtask governance
cargo xtask licenses
cargo xtask repository
cargo xtask --help
```

No external task runner is required.

## License

Kitrove is dual-licensed under the [Apache License 2.0](LICENSE-APACHE) or the [MIT License](LICENSE-MIT), at your option. See [`LICENSE.md`](LICENSE.md) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
