# Release license packaging implementation plan

> **For agentic workers:** Execute inline using the executing-plans skill; no delegation is authorized.

**Goal:** Include the existing policy's third-party notices, complete locked inventory and license text in both release products before signing.

**Architecture:** Deterministic checked-in documents are reproduced from authenticated crate archives and tracked supplements. Rust/Python enforce one exact expanded companion catalog. CI and credential-free builds reject stale documents; signing, attestations and DMG authority remain unchanged.

**Tech stack:** Existing Rust xtask, standard-library Python, pinned cargo-dist 0.32.

**Spec:** ADR-0066 and docs/DEPENDENCY_LICENSE_POLICY.md.

## Global constraints

- Rust 1.88; no lockfile, dependency or permission changes.
- No retries, retags, signing activation or release in this repair PR.
- Preserve old assets, source/failure evidence and unrelated worktrees.
- All NS-07/NS-09 and INV-07/INV-12 boundaries remain; no capability semantics change.

### Task 1: Closed archive contract

Files: release/release-policy.json, crates/kitrove-release-policy/src/{lib,entry_policy}.rs,
scripts/verify_release_archives.py, scripts/test_verify_release_archives.py, shared corpus fixtures.

- [ ] Add a regression constructing TAR and ZIP for both products with each required notice omitted/empty; assert validation refuses. Run against baseline and retain the expected failures.
- [ ] Add exactly the three ADR-0066 names to both catalogs and fixture builders. Reject empty required materials. Do not alter limits or other refusal paths.
- [ ] Regenerate corpus through scripts/generate_release_archive_corpus.py; run all archive tests and correspondence checks, retaining negatives.

### Task 2: Reproducible review materials

Files: xtask/src/main.rs, scripts/release_notices.py, scripts/test_release_notices.py,
release/license-supplements/*, release/THIRD_PARTY_LICENSE_{INVENTORY,LICENSES}.txt.

Interfaces: `cargo xtask license-inputs` emits JSON {metadata, lock_packages, inventory};
`python scripts/release_notices.py --write|--check` consumes that trusted local command,
verifies archive checksums and outputs/compares the two named documents.

- [ ] Test exact inventory identity, sorted deterministic deduplication, changed crate hashes, missing materials and malformed/stale supplements before implementing each behavior.
- [ ] Refactor existing license validation to return the same complete inventory without changing its command output; expose reviewed metadata/locked checksums as JSON.
- [ ] Implement bounded regular-file reads, checksum-before-decode, no extraction/execution/network, per-package coverage and source-pinned supplements for archives missing license text.
- [ ] Generate/check outputs twice; retain input identities and reviewed supplement sources. Never substitute SPDX identifiers for missing required text.

### Task 3: Build gates and final verification

Files: dist-workspace.toml, .github/workflows/release.yml, xtask/src/main.rs,
scripts/test_release_build_workflow.py, policy/notices documentation and ADR index.

- [ ] Add a workflow regression asserting reproducibility check precedes dist build/signing, and that both product archives select the three materials.
- [ ] Include the exact three paths in dist config; add the same --check gate to canonical CI and credential-free release build.
- [ ] Verify real unsigned CLI/installer archive members and bytes without executing downloaded products, then source-review all changes.
- [ ] Run full stable then Rust 1.88 cargo ci serially; freeze the tree before committing. No commit on partial/failing validation.
- [ ] Commit/push explicit public PR, require exact PR/latest-main checks before guarded merge, exact postmerge green, then archive and clean only owned merged worktrees with no active consumers.

Self-review: scope covers both products/formats, generator provenance, license text omissions, strict refusal and publication gates. This repair does not select a new release version or establish production artifact acceptance.
