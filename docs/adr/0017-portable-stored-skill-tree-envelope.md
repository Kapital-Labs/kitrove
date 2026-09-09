# ADR-0017: Portable stored skill-tree envelope

**Status:** Accepted  
**Date:** 2026-08-24  
**Drivers:** NS-01, NS-03, NS-05, NS-07, NS-10; INV-03, INV-05, INV-07, INV-11, INV-12

## Context

The versioned Agent Skill tree identity includes each file's regular or executable mode. Filesystem mode bits are not a portable persistence format: Windows cannot reproduce Unix executable bits, repository checkouts may normalize them, and reading host mode during status would make one stored object hash differently across machines.

Kitrove also cannot place its metadata inside the authored tree. An origin may already contain the same reserved-looking filename, and treating storage metadata as capability content would change later materialization.

## Decision

Every stored Agent Skill tree uses an envelope root with two children:

- `metadata.json`: strict JSON schema version `1` containing the complete ordered map of portable payload paths to `regular` or `executable` mode;
- `payload/`: the authored file paths and exact bytes. Host filesystem mode is not authoritative.

Verification captures the complete envelope without following links or reparse points, refuses any entry outside those two namespaces, requires the metadata and payload path sets to match exactly, reconstructs the canonical modes from metadata, and recomputes `kitrove-skill-tree-v1` over paths, declared modes, and bytes.

Version-1 metadata is bounded to four MiB. Construction refuses an object whose ordered path/mode map would exceed that bound, and verification gives envelope metadata the same explicit allowance in addition to the captured payload limits.

Portable skill content uses that reconstructed tree hash directly as `PortableContent.object_hash`. ADR-0016 origin-native metadata embeds the same versioned tree metadata alongside layout, original document name, and adapter-native identity; its `payload/` follows this envelope decision.

The envelope metadata is not capability content and is never materialized into a harness destination. Payload bytes remain untrusted and are never executed during staging, verification, status, or recovery.

## Consequences

- Stored tree identity remains stable across macOS, Linux, and Windows.
- Executable classification and mode evidence survive a host that cannot express Unix modes.
- Extra, missing, duplicate, linked, special, or mismatched payload entries invalidate the object.
- Path/mode metadata cannot grow without a fixed refusal boundary.
- Storage format and content identity remain separate: changing JSON whitespace alone does not change the reconstructed tree identity, while changing a declared mode does.
- Any future envelope schema change requires an explicit version transition.
