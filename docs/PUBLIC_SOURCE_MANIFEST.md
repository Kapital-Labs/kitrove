# Public Source Manifest

**Status:** The 2026-08-28 baseline, the independent-review amendment, and the resulting exact 272-file candidate snapshot were explicitly approved by the copyright holder. Later source changes are outside that historical snapshot and require a refreshed exact file-list and content review. Repository creation, visibility changes, package publication, and release signing still require their stated approvals.

The public project must be created as a fresh repository. This manifest defines the proposed source snapshot so private development history and coordination artifacts are not published accidentally.

## Include

- Rust workspace source, locked dependencies, and release verification tooling: `Cargo.toml`,
  `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`, `dist-workspace.toml`, `.cargo/`,
  `crates/`, `xtask/`, `scripts/`, and the reviewed `release/` policy/manifest files.
- Audited compatibility-patched dependency source and retained upstream license material:
  `third_party/`.
- Synthetic tests and evidence-labeled fixtures: `fixtures/`, `examples/`, and `schemas/`.
- Public product, safety, and license contract: `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `NORTH_STAR.md`, `DEVELOPMENT_RULES.md`, `LICENSE.md`, `LICENSE-APACHE`, `LICENSE-MIT`, and `THIRD_PARTY_NOTICES.md`.
- Public technical documentation: `docs/01-PRODUCT-SPEC.md`, `docs/02-ARCHITECTURE.md`, `docs/03-HARNESS-CAPABILITY-MATRIX.md`, `docs/04-THREAT-MODEL.md`, `docs/ROADMAP.md`, `docs/ADAPTER_GUIDE.md`, `docs/DEPENDENCY_LICENSE_POLICY.md`, `docs/PUBLIC_SOURCE_MANIFEST.md`, `docs/REVIEW_PROCESS.md`, `docs/architecture/`, `docs/adr/`, and `docs/research/`.
- Public operational documentation: `docs/QUARANTINE-RECOVERY.md`, `docs/RELEASES.md`,
  `docs/INSTALLER.md`, and `docs/RELEASE-SIGNING.md`.
- Public repository configuration: `.editorconfig`, `.gitattributes`, `.gitignore`, `.github/CODEOWNERS`, issue and pull-request templates, Dependabot configuration, reviewed CI/release workflows, and their reviewed `.github/scripts/` helpers.

The added distribution configuration, release policy files, installer guide and workflow
helpers above are proposed corrections to the include set, not retroactive public-source
approval. A private 633-file candidate from implementation `bf3267f` was materialized
without Git history and passed a fresh Gitleaks 8.30.1 scan on 2026-09-07. It still needs
complete refreshed content/provenance review and exact-list approval; any later changes,
including final public repository identity pins, require a newly bound snapshot.

The signing guide is also proposed for inclusion because the public release guide
links to it. Signing rehearsal records remain private and are not part of this
include set. Public documentation must summarize their evidence and limitations
without linking to excluded local files. The guide's inclusion does not authorize
signing, source publication or production activation.

## Exclude

- the private Git history, branches, tags, pull requests, Actions history, and repository settings;
- private coordination and implementation history: `BOOTSTRAP_GITHUB.md`, `AGENTS.md`, `CLAUDE.md`, `WHY_KITROVE.md`, `docs/COMPETITIVE_POSITIONING.md`, `docs/INITIAL_BACKLOG.md`, `docs/05-MVP-IMPLEMENTATION-PLAN.md`, `docs/DEVELOPMENT_CONTEXT.md`, `docs/DECISION_LOG.md`, `docs/PROJECT_PLAN.md`, `docs/PUBLIC_RELEASE_CHECKLIST.md`, `docs/handoffs/`, `docs/review/`, and `docs/superpowers/`;
- build output, caches, local environments, credentials, editor state, generated signing material, and machine-specific configuration; and
- any file added after approval until it receives the same source, provenance, path, identity, and secret review.

## Snapshot procedure

1. Resolve every unchecked source, license, security, naming, and release item in the private release checklist.
2. Materialize only the approved include set into a new temporary directory; do not clone or filter the private history.
3. Run repository hygiene, credential-canary, path/identity, dependency advisory, and dependency-license checks against the materialized tree.
4. Inspect every generated package/archive file list before signing.
5. Create the public repository with clean initial commits only after explicit user authorization.
6. Enable private vulnerability reporting, branch protection, required CI, dependency alerts, and code/secret scanning before announcing the repository.

The copyright holder must approve this manifest and each final materialized file list. The recorded 272-file candidate received that approval; later changes do not inherit it. Snapshot approval does not itself authorize repository creation, visibility changes, package publication, or release signing.
