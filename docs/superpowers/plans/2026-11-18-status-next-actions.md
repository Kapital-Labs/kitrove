# Status and Next Actions Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Explain collection and destination readiness with consistent labels and one obvious next action, without changing what can be collected or applied.

**Architecture:** Begin in the existing setup presentation boundary. Keep source comparison, plan readiness and runtime loading as separate evidence. A small pure advisory decision maps existing states to a suggested action; the existing menu and planners perform any separately confirmed operation.

**Tech Stack:** Existing Rust CLI/testkit, no dependency or persisted field.

**Spec:** `docs/PRODUCT-PRIORITIES.md`, `setup/collection_status.rs`, `setup/application_readiness.rs`.

## Global Constraints

- Preserve NS-01/02/03/04/05/07/09/10, exact native-content comparison, trust, ownership and fresh plan gates.
- No scan count becomes an adoption count; scan observes sources while collection planning evaluates a selected collection.
- No JSON schema, default write, automatic trust, source selection or shared-root ownership change in this first increment.
- Unknown comparison stays unverified. A matching name never means equal bytes or owned destination.
- Worktree, full stable/Rust1.89, manual source review and exact public checks before guarded merge.

### Task 1: Pure vocabulary and next-action decision

**Files:** Modify `crates/kitrove-cli/src/setup/collection_status.rs`; create `crates/kitrove-cli/src/setup/next_action.rs`; register it in `setup.rs`; extend `setup_collection_status_tests.rs`.

**Interfaces:** Introduce private `CollectionRelation::{Uncollected, Exact, Changed, Unverified}` and `NextAction::{PreviewCollection, ReviewSource, ChooseTool}`. `collection_next_action(relation: CollectionRelation, blocked: bool) -> NextAction` is advisory and receives no writer, transaction or trust authority.

- [ ] Add a failing pure test with these exact expectations:

```rust
assert_eq!(collection_next_action(CollectionRelation::Exact, false), NextAction::ChooseTool);
assert_eq!(collection_next_action(CollectionRelation::Changed, false), NextAction::ReviewSource);
assert_eq!(collection_next_action(CollectionRelation::Unverified, false), NextAction::ReviewSource);
assert_eq!(collection_next_action(CollectionRelation::Uncollected, true), NextAction::ReviewSource);
assert_eq!(collection_next_action(CollectionRelation::Uncollected, false), NextAction::PreviewCollection);
```

- [ ] Implement that match table. Derive `Exact` only from the existing exact native source/object comparison. Keep the current comparison function available to its existing callers while migrating their labels.
- [ ] Run `cargo test --locked -p kitrove-cli collection_status`; confirm unknown evidence never reaches `ChooseTool` as a claim of completed placement.

### Task 2: One summary and a real next action

**Files:** Modify `setup/collection.rs`, `setup/collection_selection.rs`, `setup/navigation.rs`, `setup/application_readiness.rs`; extend `setup_quick_tests.rs`, `setup_application_tests.rs` and `setup_presentation_tests.rs`.

**Interfaces:** Use `NextAction` from Task1 for display/selection only. Continue invoking the existing application picker and `materialize::run_plan`; do not create a summarized-plan confirmation path.

- [ ] Add a transcript fixture with 15 selected source skills: 12 exact already-collected items and 3 script-review refusals. Assert `0 ready to collect`, `12 already collected`, and `3 need review` are distinct counts. The suggested next action must not ask to rename the 12 exact items.
- [ ] Add a second fixture with one newly collectable item and a destination managed copy. Assert destination `no_op` remains "Already current (managed)" and `managed_update` remains an explicit proposed change.
- [ ] Show short sections for these counts and one selected next action. Explanations live below the result, not inside a multi-clause input line. Keep detailed skipped rows on demand.
- [ ] Offer "Add collected skills to a tool" when applicable, routing to the existing tool-first picker. Enter may select that navigation action; it cannot apply, collect a new set or approve scripts.
- [ ] Test empty selection, EOF, queued keys, invalid input, shared Claude/OpenCode source copies, blocked trust and unknown plan shapes. Compare collection/state/source snapshots before and after navigation.
- [ ] Run `cargo test --locked -p kitrove-cli setup`; retain RC5.18's signed-artifact no-op proof as baseline rather than rerunning it without a changed behavior.

### Task 3: Evidence and user comprehension

**Files:** Update `docs/GETTING-STARTED.md`, `docs/ADD-TO-TOOLS.md`; create `docs/acceptance/first-placement.md`.

- [ ] Document one disposable journey using existing commands: scan, collect, select a pack/tool, inspect the complete plan, separately approve, then run again after collecting another skill.
- [ ] Record observed/selected/ready/blocked counts and the user's chosen next action. Measure elapsed time and retries only with consent; no background telemetry.
- [ ] Complete canonical validation and complete diff review before commit. Release notes may claim clearer navigation after acceptance; they must not claim runtime loading, recovery support or a changed collection schema.

## Deferred boundary

A general per-tool `status` report needs its own output schema and explicit
target/root inputs. Do not silently expand current `status --json`, which reports
portable integrity. Do not add an ambient scan to make these labels appear richer.
