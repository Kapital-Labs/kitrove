# Drift and Exact-Prior Update Review Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Explain changes in one ordinary skill's collection source and managed tool copy before offering the existing exact-prior update workflow.

**Architecture:** A read-only advisory model combines accepted native observations, existing collection hashes and validated receipt evidence. The review view proposes an existing core plan; it cannot authorize overwrite, merge or grant trust. Begin with explicit local sources, not automatic upstream fetching.

**Tech Stack:** Existing Rust core `update.rs`, CLI adoption orchestration and synthetic testkit. No new persistence, merge engine, backend or dependency.

**Spec:** `docs/PRODUCT-PRIORITIES.md`, ADR-0023, `crates/kitrove-core/src/update.rs`.

## Global Constraints

- NS-02/03/04/05/06/07/09/10; explicit roots or valid managed-modified receipt authority remain mandatory.
- No name-only attribution, automatic winner, background scan, remote fetch, new Git authentication, trust grant or implicit sync.
- Preserve native fields, exact prior revision and complete fidelity/blocked reporting. A summary is not a replacement approval digest.
- Scope first implementation to an ordinary skill and one explicitly selected tool/user destination. Other capability kinds retain existing behavior.
- Share reviewed vocabulary with the status plan. Keep runtime-loaded evidence separate from file/receipt evidence.

### Task 1: Read-only relation classification

**Files:** Create `crates/kitrove-cli/src/setup/drift_review.rs`; register in `setup.rs`; create `setup_drift_review_tests.rs`. Read existing `core/update.rs`, `core/materialization.rs`, `model/local.rs` and `setup/collection_status.rs` before implementation.

**Interfaces:** Private `DriftRelation::{Current, CollectionChanged, ManagedCopyChanged, BothChanged, Unmanaged, Unknown}`, `ReceiptEvidence::{Absent, Valid, Invalid}`, and pure `classify_drift(collection_changed: Option<bool>, managed_copy_changed: Option<bool>, receipt: ReceiptEvidence) -> DriftRelation`. Its caller supplies a known existing selected destination; an absent destination is reported separately as not placed. The first comparison is the selected asset's `content_hash` against the valid receipt's `source_hash`, not the aggregate environment revision. The second compares observed normalized content against the receipt's `rendered_hash`. A changed asset revision does not by itself prove changed target bytes; show the current core plan's disposition separately. Missing evidence stays `None`; invalid receipt evidence is not proof of an unmanaged file.

- [ ] Add a failing match-table test:

```rust
assert_eq!(classify_drift(Some(false), Some(false), ReceiptEvidence::Valid), DriftRelation::Current);
assert_eq!(classify_drift(Some(true), Some(false), ReceiptEvidence::Valid), DriftRelation::CollectionChanged);
assert_eq!(classify_drift(Some(false), Some(true), ReceiptEvidence::Valid), DriftRelation::ManagedCopyChanged);
assert_eq!(classify_drift(Some(true), Some(true), ReceiptEvidence::Valid), DriftRelation::BothChanged);
assert_eq!(classify_drift(None, None, ReceiptEvidence::Absent), DriftRelation::Unmanaged);
assert_eq!(classify_drift(Some(false), Some(false), ReceiptEvidence::Invalid), DriftRelation::Unknown);
assert_eq!(classify_drift(None, Some(false), ReceiptEvidence::Valid), DriftRelation::Unknown);
```

- [ ] Implement the pure classification without a filesystem writer or receipt constructor. `BothChanged` describes conflicting evidence; it does not choose a winner or automatically invoke semantic merge.
- [ ] Add fixtures for changed bytes, renamed source, ambiguous receipts, stale collection revision, unverified shared source and tampered native object. An unrelated collection addition must leave the selected unchanged asset current, preserving RC5.18's regression. Unknown or invalid evidence never becomes `Current`.
- [ ] Run `cargo test --locked -p kitrove-cli drift_review`.

### Task 2: Human review and existing update-plan handoff

**Files:** Modify `crates/kitrove-cli/src/setup/collection.rs`, `setup/collection_selection.rs` and `portable/adoption.rs` only at the orchestration boundary; extend `setup_collection_status_tests.rs`, `setup_application_tests.rs` and `crates/kitrove-cli/tests/portable_workflow.rs`.

**Interfaces:** A review selection carries existing `AssetId`, exact current content hash and accepted `ObservationId` into the current `run_adopt`/update path. Use `UpdateSourceAuthority::{ManagedModified, ExplicitRoot}` from the core; do not invent another authority category.

- [ ] Write a transcript that identifies which side changed and offers "Preview collecting this update", "Preview updating the tool copy", or "Leave unchanged" only when existing authority supports that action.
- [ ] Keep any displayed diff local and opt-in, with bounded output and known credential exclusions. Bot/cloud summaries remain IDs/counts/codes, never automatic skill-body export.
- [ ] Recompute the complete existing update plan after selection and obtain its separate exact confirmation. A changed source, receipt, journal or prior revision must refuse that confirmation and stop later items.
- [ ] Test stale preview, explicit-root substitution, unmanaged destination, denied scripts, unknown native fields and overlapping pack ownership. Compare all unselected source/destination bytes and receipts before/after.
- [ ] Run targeted core update tests plus the CLI workflow. Do not widen source selection or relax exact-prior checks to simplify a transcript.

### Task 3: Acceptance and documentation

**Files:** Update `docs/GETTING-STARTED.md`, `docs/AGENT-WORKFLOW.md`, `docs/ADD-TO-TOOLS.md`; create `docs/acceptance/drift-review.md`.

- [ ] Record a disposable sequence: collect, place, edit one managed copy, inspect drift, separately preview/approve collecting that exact update, then preview the other tool. Preserve a native-only field or report its unsupported transfer explicitly.
- [ ] Add a second sequence with edits on both sides and require a visible refusal rather than a guessed winner. Leave sync conflict handling with the existing engine.
- [ ] Complete manual source review, full stable/Rust1.89 and exact public checks before merge. Public wording may describe only the accepted ordinary-skill/version/platform scope; upstream remote update automation remains separate work.
