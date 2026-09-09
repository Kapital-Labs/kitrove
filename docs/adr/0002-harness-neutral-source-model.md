# ADR-0002: Harness-Neutral Source Model

- **Status:** Accepted
- **Date:** 2026-08-22
- **North Star invariants:** NS-01, NS-02

## Context

Making Claude Code, Codex, Pi, or OpenCode the source of truth would structurally make other harnesses export targets and undermine bidirectional adoption.

## Decision

Kitrove's canonical domain model is harness-neutral. Every tier-one adapter has an inspection direction and a materialization direction. Origin harness is provenance, not authority.

## Consequences

The domain model must be independently designed and adoption may preserve native content when portable extraction is incomplete.

## Validation

The initial vertical slice must adopt the same valid skill from each tier-one harness into equivalent portable semantics.
