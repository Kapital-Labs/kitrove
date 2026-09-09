# ADR-0006: Git Is a Sync Backend, Not the Product

- **Status:** Accepted
- **Date:** 2026-08-22
- **North Star invariants:** NS-06

## Context

Git provides useful history and transport but raw Git workflows are the pain users are trying to avoid, and some users prefer directory synchronization.

## Decision

Kitrove exposes synchronization semantics through a backend interface. Git is the default backend and a filesystem backend is also supported. Users should not need routine add/commit/pull/rebase/push operations.

## Consequences

Kitrove must own semantic reconciliation and clear conflict UX rather than delegating everything to Git.

## Validation

The two-machine acceptance flow completes without raw Git commands.
