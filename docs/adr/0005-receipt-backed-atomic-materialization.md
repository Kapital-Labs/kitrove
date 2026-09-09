# ADR-0005: Receipt-Backed Atomic Materialization

- **Status:** Accepted
- **Date:** 2026-08-22
- **North Star invariants:** NS-05, NS-09

## Context

Harness directories are often shared with user-authored and generated files. Blind copying or deletion risks data loss, while symlinks are unreliable across platforms.

## Decision

Render into staging, validate, apply through the safest available atomic operation, and record deployment receipts. Copy is the default materialization mode; links are optional optimizations later.

## Consequences

Local state and recovery logic are required. Kitrove gains evidence for drift, safe removal, and rollback.

## Validation

Tests cover interrupted writes, stale receipts, user-replaced destinations, and Windows rename behavior.
