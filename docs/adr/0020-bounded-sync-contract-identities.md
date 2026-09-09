# ADR-0020: Synchronization contracts use bounded versioned identities

- **Status:** Accepted for Gate D D1 implementation
- **Date:** 2026-08-25
- **North Star invariants:** NS-03, NS-05, NS-06, NS-07, NS-10

## Context

Gate D needs portable snapshot descriptors, a machine-local retained base, backend revision evidence, and structured semantic conflicts before any backend authority is introduced. Raw strings, unbounded collections, or diagnostics containing remote identities would make those contracts unsafe to persist or expose.

## Decision

Synchronization contracts are pure data types in `kitrove-model`; they perform no filesystem, network, process, adapter, or clock access.

`SnapshotDigest` is `snapshot:blake3:<64 lowercase hexadecimal digits>`. `RemoteKey` is `remote:blake3:<64 lowercase hexadecimal digits>` and is derived elsewhere from a versioned backend-kind and normalized-remote-identity frame. Opaque `RemoteRevision` evidence is non-empty printable ASCII bounded to 1024 bytes. Its `Debug` representation is structural and never prints the value.

An `ObjectDescriptor` contains only a typed portable/native object kind, portable root, qualified object hash, and encoded byte length. Descriptors are canonically ordered. `SyncLimits` is an immutable, non-zero refusing budget covering snapshot/control documents, manifest, lock, object count, individual and aggregate object bytes, conflicts, and semantic components.

A version-1 local base record binds its remote key, snapshot digest, manifest revision, opaque backend revision, and exact sorted object descriptors. Strict parsing rejects unknown fields and applies the caller's refusing limits before the record becomes usable. Base and conflict `Debug` representations contain only structural counts and categories.

Conflicts use a closed stable code and typed subject. They retain only validated identifiers required to locate a semantic component; messages are compiled from the code. Rendering must apply the existing credential-shape redaction boundary before displaying even validated identifiers.

## Consequences

- Backend implementations cannot redefine identity, limits, or conflict codes.
- Local synchronization evidence is bounded and redacted independently of backend choice.
- Snapshot envelope hashing, semantic merge, and backend implementations remain later D1/D2 units layered on these contracts.
- A future need for binary or non-ASCII backend revisions requires an explicit versioned contract change.

## Validation

- Fixed parser vectors reject wrong prefixes, length, uppercase, controls, and oversized revisions.
- Zero or internally inconsistent limits are rejected.
- Base parsing rejects unknown fields, descriptor overflows, duplicate roots, and aggregate overflow.
- Debug and errors omit remote revisions, remote identities, authored paths, and canary values.
- Stable/Rust-1.85 canonical CI passes on Linux, macOS, and Windows.

## Supersession

This ADR is superseded only by a reviewed synchronization schema version that preserves the portable/local and redaction boundaries.
