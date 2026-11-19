# Agent capability landscape

Reviewed November 18, 2026 (America/Chicago). Documentation comparison; no competing
tool was installed or executed. Source snapshots and hashes remain in the local
research evidence. Links below pin the public source used for this review.

## Baseline and method

Kitrove's [initial reviewed source](https://github.com/Kapital-Labs/kitrove/blob/bb472b254e94b061f36c4773cc892cf054b056b8/NORTH_STAR.md)
recorded Kanon, agentctl, agentenv and Kasetto in four short labels. It did not
record repository identities or competitor version pins. We recovered public
projects matching those descriptions; agentctl and agentenv have namesakes, so
these owner-qualified identities must accompany future comparisons.

For each project we compared the closest available default-branch commit before
the end of September 9 Chicago with the current default branch. September 9 is
the recorded Kitrove source baseline, not a proven date of the original research.
A README change proves a documentation change, not when a feature first shipped.
An unchanged README does not prove unchanged runtime behavior.
Commit dates and the recovered default-branch history approximate this baseline;
they do not prove what every release or branch offered on that historical date.

| Project | September baseline | Current reviewed source | Observation |
| --- | --- | --- | --- |
| kelos-dev/kanon | [d5881210](https://github.com/kelos-dev/kanon/blob/d588121036fd47f4f76be197d05f38ec0cd1e389/README.md) | [d37d7e64](https://github.com/kelos-dev/kanon/blob/d37d7e64e7658a8ae3f914e91ace9c028a174989/README.md) | README bytes match; implementation head advanced. |
| liangquanzhou/agentctl | [006d5c3b](https://github.com/liangquanzhou/agentctl/blob/006d5c3b3c604e938fef93f65a0ccca1d75a7d6c/README.md) | Same commit | This default-branch snapshot did not advance. |
| 7emotions/agentenv | [5c6a7949](https://github.com/7emotions/agentenv/blob/5c6a7949092ee2a45e433fcd63c438d0e28a967a/README.md) | Same commit | This default-branch snapshot did not advance. |
| pivoshenko/kasetto | [8ee03075](https://github.com/pivoshenko/kasetto/blob/8ee03075c33a74e2cd35dccb1f7fec1c54db7541/README.md) | [687d7111](https://github.com/pivoshenko/kasetto/blob/687d7111932e14bcca3c70e773e27d5d152a8aa4/README.md) | README now includes subagents, plugin enablement and an audit command. |
| vercel-labs/skills | [80feb488](https://github.com/vercel-labs/skills/blob/80feb48868972d518436f26711509bc78595b5cb/README.md) | [57217cf8](https://github.com/vercel-labs/skills/blob/57217cf86ba38148a57af9e90d14a4c049558330/README.md) | Broader command/lock documentation; include this project in the comparison. |

## Current overlap and the question to test

**Kanon:** the reviewed README documents import of existing settings, a review UI,
provider pins and Git-backed distribution. Calling it a one-way generator would
misrepresent that record. Compare native-field preservation and reverse edits
through a concrete fixture before claiming a Kitrove advantage.
[Pinned README](https://github.com/kelos-dev/kanon/blob/d37d7e64e7658a8ae3f914e91ace9c028a174989/README.md)

**agentctl:** the reviewed README covers multiple asset kinds, per-tool skills,
planning, application, verification and rollback. Compare the authority for
ownership, changed local content and removal; do not treat rollback as unique to
Kitrove. This is liangquanzhou/agentctl, not an agent router or a fleet daemon.
[Pinned README](https://github.com/liangquanzhou/agentctl/blob/006d5c3b3c604e938fef93f65a0ccca1d75a7d6c/README.md)

**agentenv:** the reviewed README describes dependency resolution, a content store,
lockfiles and transactional activation across its adapters. These are substantial
overlaps that already existed in the baseline. Compare adoption from an existing
tool and later native edits rather than claiming unique reproducibility or
transactions. This is 7emotions/agentenv, not an agent-training VM project.
[Pinned README](https://github.com/7emotions/agentenv/blob/5c6a7949092ee2a45e433fcd63c438d0e28a967a/README.md)

**Kasetto:** its current source presents broad declarative distribution with local
sources, pins, secrets integration and more asset types than the older summary
suggests. Its published sync contract distinguishes replacement of skill trees
from additive MCP handling and tracked cleanup. Compare semantic reverse-edit
and conflict workflows; do not claim it has no ownership or lock semantics.
[Pinned README](https://github.com/pivoshenko/kasetto/blob/687d7111932e14bcca3c70e773e27d5d152a8aa4/README.md),
[sync contract](https://kasetto.dev/docs/how-sync-works)

**Vercel skills:** its current source documents skill discovery, installation,
updates and locked project restoration, including experimental commands. The
September README already described more than downloading files. Compare the
broader capability lifecycle and native preservation without calling the tool a
simple copier. Retain its experimental qualifications in any public comparison.
[Pinned README](https://github.com/vercel-labs/skills/blob/57217cf86ba38148a57af9e90d14a4c049558330/README.md),
[command reference](https://github.com/vercel-labs/skills/blob/57217cf86ba38148a57af9e90d14a4c049558330/docs/commands.md)

The [Agent Skills specification](https://agentskills.io/specification) supplies a
shared directory and metadata format. Shared formats and shared discovery paths
reduce the need for another copy of a basic skill. They do not establish identical
tool interpretation, local permission, ownership or bidirectional change handling.
That last statement is an architectural inference, not a benchmark result.

Grok Bot adds a conversational product surface: Bots, reusable skills, templates
and custom connectors. Its documented skill library is not evidence of a native
filesystem adapter contract. The [pilot plan](../integrations/grokbot/README.md)
separates those two integration jobs.

## Assessment

The market is crowded enough that "multi-tool skills with a lockfile" is an
insufficient pitch. The more defensible Kitrove focus is the complete managed
collection workflow: capture existing capabilities, preserve native content,
explain fidelity, track owned placements and review changes across machines.
The current preview and bounded synthetic acceptance support parts of that
workflow; they do not establish superiority over these projects.

Before stronger comparative claims, run an agreed fixture against named versions
of the closest alternatives. Publish the procedure and both successes and limits.
Credit tools that fit a simpler job. Reassess the product if the same workflow is
equally clear elsewhere; do not add a Bot or more adapters to hide that result.
