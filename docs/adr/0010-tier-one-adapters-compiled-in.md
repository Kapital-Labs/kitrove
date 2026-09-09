# ADR-0010: Tier-One Adapters Are Compiled In

- **Status:** Accepted
- **Date:** 2026-08-22
- **North Star invariants:** NS-01, NS-02

## Context

A plugin ABI before the domain and security model stabilize would increase complexity and reduce confidence in the four launch harnesses.

## Decision

Claude Code, Codex, Pi, and OpenCode adapters are workspace crates compiled into the initial binary. A community extension mechanism is deferred. WASM Components are the preferred future direction for complex third-party adapters.

## Consequences

The core release cadence initially carries tier-one adapter updates. Internal adapter contracts must still be clean and testable.

## Validation

All four adapters implement the same API and run against synthetic fixtures in CI.
