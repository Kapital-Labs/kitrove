# ADR-0016: Versioned origin-native skill object

**Status:** Accepted  
**Date:** 2026-08-24  
**Drivers:** NS-03, NS-05, NS-07, NS-10; INV-03, INV-05, INV-07, INV-11, INV-12

## Context

An Agent Skill tree hash covers portable paths, modes, and bytes, but it deliberately does not cover the source layout, original principal-document name, or adapter-native identity. Those fields distinguish a directory package from a standalone source and preserve origin-native behavior even when two sources have the same portable projection. Reusing the tree hash as `NativeVariant.object_hash` would therefore collapse evidence that Kitrove promises to retain.

Native metadata also needs a strict storage boundary. It must not be mixed into the exact captured tree because a source may already contain the same reserved-looking filename, and materializing metadata as authored content would be incorrect.

## Decision

Kitrove stores an origin-native Agent Skill object as two independent parts under its referenced object root:

- `metadata.json`: strict JSON containing schema version `1`, source layout, original document name, adapter-native identity, and the ADR-0017 ordered payload path/mode map;
- `payload/`: the exact captured paths and bytes. Canonical regular/executable modes come from metadata rather than host filesystem mode.

`NativeVariant.format` is `kitrove-native-skill-object/v1`. Its `object_hash` is the qualified BLAKE3 result of this frame:

1. ASCII domain separator `kitrove-native-skill-object-v1` followed by NUL;
2. one layout byte (`0` directory, `1` standalone);
3. original document name as a u64 big-endian byte length and UTF-8 bytes;
4. adapter-native identity with the same string framing; and
5. the qualified `kitrove-skill-tree-v1` payload hash with the same string framing.

The reconstructed payload tree hash already commits to every path, declared mode, and byte. The native-object frame commits to the remaining native identity without duplicating the payload bytes. Stored metadata is parsed strictly, rejects unknown fields and unsupported versions, and must reproduce the referenced native-object hash after the payload is captured independently.

Portable skill objects remain direct `kitrove-skill-tree-v1` trees and use their tree hash. Exact-source observation identity, portable tree identity, native object identity, complete asset revision identity, and rendered destination identity remain distinct.

Adoption must refuse an adapter-native identity that violates the portable-state secret policy before writing this metadata. Diagnostic and `Debug` output report only structural presence and hashes, never the native identity or captured bytes.

## Consequences

- Directory and standalone origins cannot collapse merely because their payload or portable projection matches.
- Original document names and adapter-native identities survive portable storage explicitly.
- Status can verify metadata and payload independently, then recompute one native-object identity.
- Object-store code reserves no filename inside authored payload content.
- Any future envelope change requires a new format and hash-frame version.
