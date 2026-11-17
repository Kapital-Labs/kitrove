# Tool-first collection and installation implementation plan

> Execute inline using the executing-plans workflow. No delegation: maintainer scope preserves the existing no-new-subagent constraint.

**Goal:** Make collection status understandable and install selected collection items into Claude, Codex, Pi and OpenCode through one tool-first journey.

**Architecture:** CLI orchestration and presentation only; all observations, portable/native loading, destination planning, version probing and writes stay behind existing reviewed core boundaries. New setup modules own tool selection/preview and source grouping/status. Collection-to-tool handoff selects only newly adopted IDs; every apply still requires its own exact refreshed plan confirmation.

**Tech Stack:** Rust 1.89+, existing model/core/adapters, child-isolated tests and real terminal fixtures. No dependencies.

**Spec:** Maintainer request November 17 and ADR-0073.

## Global constraints

- Work in an isolated worktree; stacked on unmerged PR140 b11e8d35. Do not modify its public branch or retry unchanged hosted CI.
- Never read/write the maintainer's real collection, tool roots, installed binary or sync; all behavior tests use disposable homes/state/targets.
- No release, version, tag, signing, deployment or package-channel changes.
- Preserve no-follow reads, native loss, trust, ownership, transaction, stale-plan and recovery gates. No settings/account probing or automatic executable discovery/launch.
- Tool paths come from existing target policy, not duplicate hard-coded destination authority. Shared roots are observations, not proof that a tool loaded a skill.

## Task 1: Tool-first installation

Files: create setup/application.rs and setup/application_preview.rs, wire setup.rs, create setup_application_tests.rs.

- [x] Add isolated journey tests first: `for tool in ["1", "2", "3", "4"]` selects tools before saved items; skill-only Pi/OpenCode never request a binary. Assert actual destination files and receipts only after explicit apply approval.
- [x] Run focused tests and retain expected failures.
- [x] Implement `application::apply(dialog, root, suggested: &[AssetId]) -> Result<(), CliError>`. Select tools, then user/project scope and explicit project path, then labeled assets/packs. Preserve multi-tool selection and exclusions.
- [x] Resolve selected pack contents through existing model resolution; request Pi version only for extensions and OpenCode V2 only for instruction/command/agent/MCP, matching core. No probe for skills.
- [x] Use `materialize::run_plan` for individual readiness and the existing `run_apply` for final whole-batch plan/revalidation/commit. Show readable actions/destinations and all loss/effect details before confirmation; details remain available. Blocked items are visible, never silently dropped.
- [x] Verify global/project targets, unmanaged conflict, no-op, stale source/authority, cancellation and non-skill version gating. Test hostile names/output escaping.

## Task 2: Collection status and grouped sources

Files: setup/collection_status.rs, collection_selection.rs, collection.rs, setup_collection_status_tests.rs.

- [x] Add failing tests for exact same native source, changed same-name source, other-tool copy, corrupt stored object, duplicates and exclusions.
- [x] Implement status comparison only after validated manifest-authorized native object load. Compare captured exact source hash to stored native identity; missing/other-tool evidence is explicitly not compared, never equal. Status cannot authorize update/trust or suppress a blocker.
- [x] Group initial display by skill name with original numbered source copies under it. Keep original indices and tool/source differences; no automatic winner or native merge. Bound default output; full inventory remains available.
- [x] Show matching/different/not-compared status separately from ready and blocked. Retain explicit rename/review and all prior source selection semantics.

## Task 3: Collection-to-tool next step

Files: setup.rs, setup/collection.rs, setup/inventory.rs, existing scripted/PTY fixtures.

- [x] Test that successful collection offers the new IDs to the application journey; skipping does not write receipts or destinations. A blocked/empty/skipped collection offers no false success.
- [x] Return adopted IDs from the collection helper and preserve them across individual and bulk selection. Offer the next step without a new collection/path prompt; do not apply or sync automatically.
- [x] Update fixtures for the intentional next-step prompt and retain real single-key pending-input protections.

## Task 4: Documentation, review and validation

- [x] Record the four-tool matrix from primary docs, exact discovery/destination limits, duplicate behavior and version/trust gates. Update getting-started/quick adoption and threat-model/review record.
- [ ] Run focused setup/materialization/terminal tests, then full stable and Rust1.89 `cargo ci` serially on the same frozen source. Preserve failed/superseded logs.
- [ ] Complete product, architecture, security and full-diff/source review; audit/license/notices/governance/Gitleaks checks before committing. No independent-agent review claim.
- [ ] Commit and open a separately reviewed public stacked PR after full pass. Do not merge ahead of PR140 or bypass missing Mac CI. Archive exact source/evidence; retain unmerged worktree.
