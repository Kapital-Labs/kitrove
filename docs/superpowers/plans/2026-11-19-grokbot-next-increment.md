# Grok Bot next increment: reproducible synthetic setup

Status: proposal, November 19, 2026. This plan adds no runtime behavior and does
not authorize execution, a provider connection or publication.

## Evidence and current boundary

The reviewed baseline is public main
`49ba42071582b4374b580fbc9510f332837d6188`. Its four Python modules implement a
source-only MCP stdio prototype with three tools: `list_packs`, `inspect_pack`
and `preview_pack`. They invoke existing CLI inspection and planning commands.
The server is not part of the signed RC5.18 executable. A source fix in the
current batch follow-up does not update that installed executable or its pinned
pilot copy.

The maintainer-retained bundle
`grokbot-readonly-pilot-20261118-953nb6gb` records the completed trial:

| Evidence | Supported conclusion | Limit |
| --- | --- | --- |
| `LIVE-NATIVE-PROOF.json` | Linux x86_64, Python3.13.5; ten successful read calls, repeated previews for four targets, write/path overrides refused, fixture unchanged | Native protocol proof on a synthetic fixture |
| `LIVE-GROK-RESULTS.json` | App displayed Connected and three tools; selected-connector conversation returned list, inspect and OpenCode preview results | Observed catalog and conversation, without an independent provider transport trace |
| `LIVE-TRIAL-RESULTS.md`, `COMPLETE.json` | Temporary connector removed; source/CLI/fixture unchanged; trust, receipts and pack applications empty | No real collection, placement, receiving-tool loading or new release |

Earlier README, contract and operator status text predates that trial. Its lack
of live acceptance is historical, not evidence that another trial is needed.
ADR-0077 still defines the implementation boundary; the later one-off trial did
not authorize continuing account access or distribution.

The initial `/tmp` seed failed the unchanged Rust private-state ancestor rule.
A fresh fixture beneath a checked home ancestor chain passed. The operator guide
now distinguishes that CLI rule from the wrapper's sticky-ancestor allowance.
No guard, existing permission or failed fixture should change to make setup pass.

## Effect of the batch and CLI UX work

Complete the batch-storage diagnosis and clearer CLI next steps first. The Grok server
has no apply endpoint and does not run the batch transaction. Its previews use
closed `planned` result schemas and selected-pack checks, so preserve those JSON
contracts when changing transaction internals or human-facing CLI text. Existing
recovery refusals and unknown-result termination must remain intact; do not add
write errors to the allowlist merely because batch errors now have better text.

After integration, run the existing focused Grok Python suites against the exact
combined source. This checks the wrapper's contracts; it does not prove that a
new CLI artifact or provider environment works. No additional account trial is
needed to review the current batch/UX change.

## Smallest useful next unit

Prepare one reviewable operator handoff for reproducing the existing synthetic
source setup, with the current three tools and configuration unchanged. This
reduces the gap between checked-in source and a usable setup without starting a
new provider or mutation program.

- [ ] Reconcile dated status in the integration docs with the retained trial,
  preserving its limits and removal evidence. Keep the RC5.18 artifact distinct
  from any later source candidate.
- [ ] Specify a minimal source bundle inventory: four modules, inert sample,
  applicable licenses and instructions. Pin an exact commit and complete file
  hashes. Record the independently verified CLI artifact identity separately;
  never substitute the user's installed executable or silently select latest.
- [ ] Write a complete local setup procedure that checks POSIX APIs, Python
  identity, canonical ancestry, permissions and absent collection/state before
  fixture seeding. List each existing CLI seed write and its explicit disposable
  paths. Do not add a setup helper, installer, dependency or automatic trust.
- [ ] Define an offline acceptance record with source/CLI hashes, platform,
  supported protocol, exact three-tool catalog, expected closed results,
  refused write/path arguments and before/after fixture comparison. Keep raw
  private output outside public fixtures. Execution of a fresh fixture is a
  separately authorized step after this procedure is reviewed.
- [ ] Review the handoff and focused contract results before choosing whether
  to package or publish it. A source bundle proposal is not a released feature,
  Bot import file, native Grok skill adapter or installed connector.

Exit criterion: a second operator can review exact inputs, fixture effects,
expected results and cleanup before executing anything. No new live trial or
public distribution is required to finish this unit.

## Later decisions remain separate

| Later increment | Evidence and decision required first |
| --- | --- |
| Public source distribution or Bot template | Reviewed inventory, provenance, maintenance/version policy and explicit publication decision; no credentials or account state in the package |
| Real-collection read-only connection | A separate design for supported content and existing state, explicit data minimization/transfer scope, execution location and account sharing. Do not remove the synthetic marker or recovery refusal to enable it |
| Receiving-tool discovery | Follow the tool-loading acceptance plan with a pinned isolated runtime; a planned install count and a Connected MCP catalog establish neither file placement nor skill discovery |
| Mutation tools | Separate authenticated exact-operation approval, expiry/replay and stale-plan design using the existing transaction coordinator; batch correctness alone grants no Bot write authority |

Status/next actions, tool loading, upgrade/recovery and drift/update remain
implementation or acceptance plans except where the current follow-up supplies
its own reviewed evidence. Do not describe this Grok handoff as completing them.

## Reviewed references

- [Tool contract](../../integrations/grokbot/TOOL-CONTRACT.md),
  [operator guide](../../integrations/grokbot/OPERATOR.md),
  [ADR-0077](../../adr/0077-synthetic-readonly-agent-command-pilot.md).
- [Status and next actions](2026-11-18-status-next-actions.md),
  [tool-loading acceptance](2026-11-18-tool-loading-acceptance.md),
  [product-gap sequence](2026-11-18-product-gap-delivery.md).
- Source: `scripts/grokbot_projection.py`, `scripts/grokbot_readonly.py`,
  `scripts/grokbot_process.py`; private-state ancestor predicate:
  `crates/kitrove-state-lifecycle/src/lib.rs`, `require_trusted_ancestor` and
  `create_absent_root_nofollow`.
