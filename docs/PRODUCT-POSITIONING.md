# Product positioning

Reviewed November 18, 2026 (America/Chicago). Release baseline: RC5.18.
This document connects the [product invariants](../NORTH_STAR.md) to current
evidence. It does not approve a launch, a new adapter or a release.

## Who we serve first

Developers who have accumulated skills in Claude Code, Codex, Pi or OpenCode and
want to reuse selected items in another supported tool or on another computer.
Start with a single person's collection. Team administration is a later product
decision; it should not complicate that first useful workflow.

## The promise

**Collect the agent capabilities you want to keep, preview their use in another
tool, and manage changes without silently dropping tool-specific content.**

For a short introduction: Kitrove manages a developer-owned collection of agent
capabilities across supported tools and computers. It preserves source content,
reports target compatibility, and keeps credentials and execution trust local.
The [release claims](launch/CLAIMS.md) qualify this statement for RC5.18.

The useful demonstration is concrete: collect a skill, preview another tool's
destination, approve placement, edit a managed copy, and review how to bring that
edit back. A file existing in two folders does not establish that both tools loaded
it or behaved the same way. Tool settings, native fields and local trust matter.

## Why choose it

Kitrove's product bet combines discovery of existing capabilities, retained native
variants, explicit fidelity, receipt-backed ownership and asset-level continuity.
The source and bounded synthetic acceptance support those mechanisms. We still
need independent user and live-tool acceptance to establish their practical value.

The competitive test is whether a user can complete this workflow with less
re-authoring and less uncertainty than with a tool they already use. More adapters,
a lockfile, Rust or a Bot interface do not establish that advantage on their own.

## When another approach fits

| Your immediate job | Consider first | Why |
| --- | --- | --- |
| Find and install a published skill | [Vercel skills](https://github.com/vercel-labs/skills) | Discovery and installation across its documented targets. |
| Declare one repeatable setup from known sources | [Kasetto](https://kasetto.dev/docs) | Broad configuration-driven asset distribution and lock handling. |
| Maintain a neutral settings source with import and review | [Kanon](https://github.com/kelos-dev/kanon) | Existing-settings import and a source-to-native configuration workflow. |
| Distribute a centrally managed coding-tool configuration | [agentctl](https://github.com/liangquanzhou/agentctl) | Its documented configuration, skills and subagent workflows. |
| Isolate dependency-resolved project environments | [agentenv](https://github.com/7emotions/agentenv) | Its documented environment and activation model. |
| Reuse a skill that your tools already discover in a shared folder | The shared folder | Another managed copy may add no value for this job. |

These are documentation-based fit assessments, not comparative runtime results.
The [dated landscape review](research/2026-11-18-landscape.md) records commit pins,
historical comparisons and unresolved questions. Credit each project's work;
do not describe competitors as unsafe or incapable without a tested, scoped case.

## What changed in our understanding

The original four labels in NORTH_STAR were useful orientation, not sufficient
competitive evidence. Kanon documents reverse import; agentctl documents planning
and rollback; agentenv documents locked transactional activation. Those features
already appear in the recovered September baseline. Our earlier labels understated
overlap; that is distinct from a new competitor feature.

Kasetto's reviewed README changed since that baseline and now describes subagents,
plugin enablement and auditing. Vercel skills also warrants an explicit place in
the comparison. A shared skill format reduces the value of basic file copying.
The retained-content and change-management workflow must earn the distinction.

## Product priorities

1. **First useful placement.** A user can explain what they collected, what is
   already available, and what will change before adding a skill to another tool.
   Measure time and failed attempts in a disposable journey; do not collect
   telemetry or call local observations user research without consent.
2. **Lifecycle clarity.** Show the collection revision, placed copies, ownership,
   local edits, upstream changes and sync conflicts as different states. Explain
   the next safe action. Prioritize drift/review and recovery guidance over another
   broad installer or registry.
3. **Upgrade and recovery confidence.** Binary replacement is not collection
   migration. Prove the supported version pair, interrupted operations and recovery
   before promising an upgrade path or stable support.
4. **Compatibility evidence.** Keep tool-version fixtures and a public support
   matrix current. Separate file placement from a tool actually loading a skill;
   preserve unknown or partial results rather than inventing conversions.
5. **Agent usability.** Use the same plans and ownership rules through the
   [Grok Bot pilot](integrations/grokbot/README.md). A conversational front end
   should explain state, not create a second mutation or approval engine.

Useful follow-ons include a small reviewed starter pack, source-update previews,
license/provenance display, environment health diagnostics and a redacted support
bundle. Each needs a contract and acceptance evidence. A generic marketplace,
automatic script/runtime installation, unattended sync and an enterprise policy
server are not prerequisites for the first user cohort.

## How we keep the story current

Before an announcement or a major scope change, the maintainer reviews the
landscape pins and the release claims ledger. Re-run the same small comparison
scenario when a candidate appears equivalent: import an existing skill, retain a
native-only field, place compatible content, edit it, inspect a conflict, and
remove only owned content. Compare results and user effort; do not infer missing
features from README silence.

Treat broad overlap as a reason to reassess whether contributing to another
project would serve users better. Preserve the existing kill criteria in the
[product specification](01-PRODUCT-SPEC.md). Only the maintainer can approve a
changed product direction. Historical research and release evidence remain
available when the summary changes.
