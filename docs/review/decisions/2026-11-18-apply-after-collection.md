# Apply after collecting more skills

Status: implementation and manual source/caller review prepared; full stable and
Rust 1.89 validation and exact public checks remain conditions of commit/merge.

## Reproduction and cause

The maintainer's transcript collected two script-containing skills successfully,
then reported bounded recovery authority errors for ordinary saved skills and a
compatibility refusal after selecting all. No placement followed that refusal.
The actual personal collection/state was not opened or changed for diagnosis.

A synthetic real setup journey reproduces the same ordinary-skill error: collect,
apply, collect an unrelated skill, then apply the first skill again. Collecting
changes the manifest revision. The skill planner incorrectly called an otherwise
unchanged owned target ManagedUpdate because its receipt named the earlier
collection revision. The journal correctly refuses equal old/new replacement
hashes. This is a planner classification bug, not evidence of a destination write
or data loss. The journal guard stays unchanged.

## Repair and authority

When source hash, rendered hash and adapter version still match an exact present
receipt-backed target, a collection-only revision is NoOp for target content.
The fresh plan and existing atomic coordinator bind the new manifest/state and
refresh its receipt after normal confirmation. Missing, modified, unsafe,
unmanaged or differently owned targets retain their existing guards. Source or
adapter changes are not made equivalent by this revision-only repair. No journal
schema, receipt schema, trust policy, fidelity category, dependency or sync change.

Partial fidelity is separately a real blocker. The guided flow still enters the
authoritative apply/recovery path; only an actual compatibility refusal offers
another selection using a fresh manifest and the same chosen tools/scope. Nothing
is silently excluded, and every subsequent plan still needs its own approval.
Recovery, stale-plan, ownership and other transaction errors still propagate.
Script approval remains separate and exact; no helper is executed or trust synced.

Descriptions normalize whitespace and retain readable quotes, letters/numbers
and a closed punctuation set. Other control/format characters remain escaped;
output stays bounded. Canonical JSON and source bytes are unchanged.

## Evidence and limits

External opencode-apply-guidance-20261118 evidence retains the real-journey
red-before-green, planner regression and all-four-tool bytes/mtime checks,
compatibility selection red-before-green, recovery guard and separate script
review checks, terminal-control display checks and all superseded fixture errors.
Initial test execution lacked the existing trusted-directory write permission;
the corrected isolated run reproduced the product error. A later unrelated core
test build ran out of disk; only rebuildable owned incremental caches were
removed after their validators ended. Logs/source/fixtures remained intact.

No installed executable, real skill collection/local state/trust/sync, tool
settings, account, VM, signing, tag, release or channel action. Manual review is
not an independent-agent or exhaustive repository/security sign-off. These
filesystem tests do not prove a live tool loaded a skill.
