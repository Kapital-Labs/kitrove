# Changelog

Notable changes to Kitrove are recorded here.

## Unreleased

## 0.1.0-rc.1.2

Replacement for the unpublished RC1.1 build. Earlier failed tags remain unchanged.

### Fixed

- Release staging uses native private-directory permissions on Windows instead of Unix chmod.

Public-artifact and clean-machine acceptance remain pending. No earlier version
is declared rollback-compatible.

## 0.1.0-rc.1.1

Unpublished: Windows staging failed after signing, before publication.

Replacement for the unpublished RC1 build. The failed RC1 tag is unchanged.

### Fixed

- Release builds use Bash consistently, including Windows, so the version tag is passed correctly.
- Planning-only manifests no longer override archive paths in build manifests.

Public-artifact and clean-machine acceptance remain pending. No earlier version
is declared rollback-compatible.

## 0.1.0-rc.1

Unpublished: the release workflow failed before publication.

First release candidate, not a stable release. Public-artifact acquisition and
two-version installer lifecycle acceptance are still pending. Clean-machine Mac
online/offline first launch has not been established. No earlier application
version is declared rollback-compatible.

### Release preparation

- Separate CLI and installer archives for Apple Silicon, Intel Mac, x86-64 Linux
  and x86-64 Windows, with production provenance verification.
- Mac signed, notarized, stapled installer images and a reviewed-source native
  consumer verifier that authenticates artifacts before mounting.
- Ordinary-user installation, upgrade, recovery and rollback interfaces with
  retained prior-version evidence; candidate acceptance remains required.

### Added

- Product North Star and governance model
- Initial product, architecture, threat-model, and implementation planning documents
- Rust workspace scaffold and tier-one adapter boundaries
- Governance checks and review templates
- Gate B domain model with strict portable manifest, deterministic lockfile, and machine-local state contracts
- Qualified BLAKE3 hashes, portable path validation, explicit fidelity evidence, and pack/profile graph validation
- Credential-free portable and lockfile fixtures exercised through public persistence APIs
- Read-only four-harness discovery with deterministic six-state classification
- Explicit first and exact-prior update adoption with immutable portable and native objects
- Receipt-backed install, no-op, restore, and managed-update materialization
- Portable agent observation, six-state receipt classification, adoption, exact-prior update, and
  atomic apply/remove recovery for Claude, Codex, and OpenCode
- Strict portable remote-MCP name, HTTPS endpoint, symbolic bearer-binding, content identity, and
  storage primitives plus compiled Claude, Codex, OpenCode V2, and unsupported Pi target policies
- Component-aware filesystem and bounded HTTPS Git synchronization with conservative conflicts
- First-class pack identity and a deterministic Gstack-scale stress corpus
- Exact Pi native-extension preservation without parsing or execution
- Machine-local exact-content executable trust, redacted audit, and recoverable Pi user-extension materialization
- Safe `init` bootstrap with a read-only four-harness inventory and complete manifest, lock, and private local-state authority
- Repeatable asset and target selection with explicitly sequential multi-item materialization
- End-to-end first and exact-prior update adoption for native Pi extensions in non-empty catalogs
- Dual MIT OR Apache-2.0 project licensing with fail-closed locked dependency-license validation and release notices
- Tag-only four-platform release packaging with SHA-256 checksums, shell and PowerShell installers,
  commit-pinned GitHub Actions, and public-release provenance attestations

### Security

- Fail-closed path, link, reparse-point, special-file, stale-input, journal-tamper, and crash-recovery coverage
- Cross-machine tests proving receipts, trust, credentials, and machine identity remain local
- Stable, Rust 1.85, Ubuntu, macOS, Windows, public Git-over-TLS, and locked dependency-advisory validation
- Cross-transaction recovery interlocks, replacement-root capability checks, credential-shaped content refusal, path redaction, and continuous checksum-pinned secret scanning
- Shared credential-shape detection across skill capture, authored capability adoption,
  materialization, rendering, and MCP validation
