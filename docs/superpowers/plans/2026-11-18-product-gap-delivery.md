# Product Gap Delivery Plan

> **For agentic workers:** Use superpowers:executing-plans to implement each linked plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Keep work inline unless the maintainer separately requests agent delegation.

**Goal:** Make the collect, place and update journey understandable and establish the evidence needed for broader preview and eventual stable support.

**Architecture:** Four independently reviewable workstreams retain the existing planners, transaction coordinator, receipts, trust and recovery. UX changes consume advisory evidence; acceptance work records observations without creating authority. Upgrade support is a separate decision after artifact and persistence review.

**Tech Stack:** Existing Rust 1.89 workspace, synthetic testkit, signed preview artifacts, dated tool fixtures and documentation. No new dependency is assumed.

**Spec:** `docs/PRODUCT-PRIORITIES.md`, NS-01 through NS-10.

## Global Constraints

- Planning is authorized here; these plans do not implement new collection, destination, migration or sync behavior.
- Leave the maintainer's installed executable, real collections, trust and sync untouched.
- No publication, new release/tag/signing, paid account, provider call, runtime install or personal-tool launch follows from a plan.
- Preserve exact-prior plans, explicit writes, managed ownership, partial fidelity and recovery refusals.
- Cross-tool file presence is not evidence that a receiving tool loaded the content.
- No automatic secret transfer, helpers, trust inheritance, conflict winner or background sync.
- Worktrees, full stable/Rust1.89, complete source review and exact public checks apply to implementation changes. Use separate PRs by acceptance boundary, not one rewrite.

## Sequence and ownership

| Order | Workstream | First independently useful result | Depends on |
| --- | --- | --- | --- |
| 1 | [Status and next actions](2026-11-18-status-next-actions.md) | A user understands why a scanned item is already collected, blocked or ready, and reaches the existing tool-first flow | Current CLI evidence only |
| 2 | [Tool-loading acceptance](2026-11-18-tool-loading-acceptance.md) | One bounded OpenCode journey distinguishes placement from observed loading; the same record works for all four tools | Reviewed artifact and an approved isolated tool runtime |
| 3 | [Upgrade and recovery](2026-11-18-upgrade-recovery-evidence.md) | A source/artifact report establishes whether a named candidate version pair is eligible for a support decision | Persistence audit; no compatibility catalog change before approval |
| 4 | [Drift and update review](2026-11-18-drift-update-review.md) | Read-only review of one ordinary skill explains collection and managed-copy differences before exact-prior update | Existing ownership/update APIs; shared vocabulary from 1 |

Start 1 while preparing 2's procedure and 3's source inventory. Workstream 4 can
be specified independently, then uses 1's reviewed labels. The Grok connector is
separate: it consumes existing plans and does not implement these product gaps.

## Review and release gates

- [ ] Review the first status/next-action change independently of a new general status command or persistence schema.
- [ ] Record one opt-in user's disposable first-placement and repeat-run journey, including hesitation and refusal comprehension. Do not enable telemetry.
- [ ] Run the reviewed tool-loading procedure only on approved isolated runtimes. Publish `unverified` when a tool cannot supply evidence without an account or unsupported invocation.
- [ ] Review the candidate version-pair evidence and approve the support statement before any predecessor/catalog or migration behavior change.
- [ ] Ship drift review first as inspection. A later update button must use the existing exact-prior preview and confirmation.
- [ ] Refresh the launch claims ledger against the exact accepted artifact. A source test, Bot demo or completed plan never grants stable support or release authority.

## Decisions that remain explicit

The first supported upgrade pair, live-tool runtime/account access, public cohort
recruitment, any new migration operation and final launch copy remain maintainer
decisions. Preparation can proceed without repeatedly requesting them. Ask only
when an approved implementation or test reaches the actual boundary, with its
reviewable procedure and expected data effects ready.
