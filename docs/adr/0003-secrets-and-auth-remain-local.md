# ADR-0003: Secrets and Authentication Remain Local

- **Status:** Accepted
- **Date:** 2026-08-22
- **North Star invariants:** NS-07

## Context

Users need different accounts, API keys, and providers across personal and work computers. Embedding a vault would create security and ecosystem coupling.

## Decision

Portable state may declare logical bindings but never contains resolved secret values or harness authentication state. Machine-local configuration resolves bindings through modular local mechanisms.

## Consequences

Some target configurations cannot be fully materialized until local bindings exist. Those results are `Blocked`, not sync failures or reasons to store the secret.

## Validation

Synthetic secret canaries must never appear in environment files, lockfiles, sync transport, logs, or JSON output.
