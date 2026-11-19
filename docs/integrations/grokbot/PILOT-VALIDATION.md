# Source prototype acceptance

November 18, 2026 (America/Chicago). Local Apple Silicon Mac acceptance only;
no live Grok account, connection, template or provider transfer was used.

## Actual protocol and artifact

The stdio server used an independently verified public RC5.18 CLI, source
`ab95ab79d5e3271320ca1e5563f4ae7b0a6baac8`, executable SHA256
`3579f5cc2885d613ce272c87d40d70de5dc251b45e2996340dab8bee6e1ee34e`.
The server itself is source-prototype work, not a feature shipped in that CLI.

A new private fixture was seeded through five existing CLI operations: initialize,
preview/confirm collection, and preview/confirm an authored pack. The sample is
ordinary inert text. Its native source was retained away from the target roots.
These seed operations changed only that fixture; they were not server tools.

A separate protocol client then performed initialization, three-tool discovery,
pack listing, inspection and repeated previews for Claude, Codex, Pi and OpenCode.
All ten successful tool calls returned the expected closed summaries; each target
planned one install and its repeated result matched. The client also proved that
an `apply` tool and a model-provided root override were refused before execution.

The entire fixture's paths, modes, file bytes and modification times matched
before and after. No destination placement, receipt, trust or sync change occurred.
The server had no children at the idle handoff, closed with exit0 and empty stderr,
and emitted no private destination paths, skill bodies, source metadata or digests.
Its module hashes were bound to the accepted source during the proof.

## Boundary regressions

Focused tests cover duplicate/nonfinite/deep JSON, unknown commands/fields,
incorrect target/schema/phase, changed pack authority, privacy projection,
unsupported platforms, executable replacement, unsafe fixture paths, retained
recovery evidence, output flood, timeout, denied/uncertain cleanup and descendants.
They exercise actual stdio initialization, active-request cancellation, EOF,
handled termination and strict refusal of unknown child output. A group cannot
be signaled after the direct ownership anchor has been reaped.

Initial failing regressions and superseded logs are retained in maintainer
evidence. The artifact driver also corrected two fixture mistakes before its
accepted run: precreated initialization directories and an unsupported native
parent-process query. Those corrections did not change Kitrove production code.

## What this does not establish

This is not live Grok interoperability, Linux native-artifact acceptance, Windows
service support, a security audit, a new release, receiving-tool execution or an
OS sandbox against the operator and other code with equivalent access. It does
not authorize uploading source/data or connecting a computer. The installed copy,
personal collections, credentials, trust and sync were excluded throughout.

Use the [operator guide](OPERATOR.md) and [contract](TOOL-CONTRACT.md) for exact
limits. Product-gap work is separately [planned](../../superpowers/plans/2026-11-18-product-gap-delivery.md),
not implemented by this prototype.
