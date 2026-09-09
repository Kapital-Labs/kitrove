# ADR-0029: Managed instruction removal is receipt-backed projection mutation

- **Status:** Accepted for Phase 3 implementation
- **Date:** 2026-08-30
- **North Star:** NS-02, NS-05, NS-07, NS-09, NS-10

## Context

Standing instructions live inside co-owned Markdown files. Removing a deployed instruction must not
delete the portable asset, infer ownership from matching bytes, erase another consumer's shared
region, or overwrite human edits outside Kitrove's markers. A previously active profile also cannot
remain recorded as fully applied after one of its projections is deliberately removed.

## Decision

`kitrove remove --asset <id> --target <harness>` removes one logical managed instruction region from
one selected scope. The selected target identifies the physical receipt; when that receipt is shared,
the operation names and removes the complete exact consumer set because those consumers own one
physical region together.

Removal authority is:

- one structurally valid managed-region receipt for the exact asset, scope, destination, and target;
- the exact receipt consumer set resolved through current compiled target policies to one physical
  document;
- a strictly parsed current region whose exact hash equals the receipt's rendered hash; and
- an unchanged complete document and local-state file from confirmation through locked commit.

The receipt's historical source revision and adapter versions remain evidence, not current-policy
preconditions. Requiring them to equal the current portable asset or adapter would strand a safely
owned older projection after an upgrade. Current policies must still resolve every recorded consumer
to the same receipt destination.

Planning uses the pure bounded managed-region remover. It preserves all bytes outside the exact
marker range and does not delete an empty resulting file or guess that adjacent whitespace belongs to
Kitrove. The shared atomic apply coordinator stages the resulting document and receipt deletion,
revalidates all authority under its existing locks, and commits or recovers them together. Successful
removal clears `machine.active_profile`, because the machine no longer exactly realizes that profile.

The portable instruction, immutable objects, manifest entry, packs, and profile definitions remain
unchanged. A later apply can restore the projection from portable authority.

## Consequences

- Human changes outside the region survive byte-for-byte when they precede planning; any later
  document change invalidates the confirmed plan.
- A missing, modified, ambiguous, unmanaged, or differently located region fails closed without
  changing the document or receipt state.
- Selecting one consumer of a shared region does not silently leave misleading partial ownership.
- Removal does not propagate as portable or synchronization deletion.
- Skill, extension, command, agent, MCP, pack, and portable-asset deletion remain separate future
  workflows.
