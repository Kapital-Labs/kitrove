# ADR-0004: Content Addressing with BLAKE3

- **Status:** Accepted
- **Date:** 2026-08-22
- **North Star invariants:** NS-05, NS-06

## Context

Adoption, provenance, locking, trust, rollback, and synchronization require fast stable content identity.

## Decision

Use BLAKE3 content hashes for captured objects and normalized content. Canonical hashing rules must be specified per object type.

## Consequences

Hash canonicalization becomes part of the compatibility contract and must avoid platform-specific path or line-ending drift.

## Validation

Golden hashes must match across macOS, Linux, and Windows CI for identical logical fixtures.
