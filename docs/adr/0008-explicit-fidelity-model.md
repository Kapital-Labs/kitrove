# ADR-0008: Explicit Categorical Fidelity

- **Status:** Accepted
- **Date:** 2026-08-22
- **North Star invariants:** NS-04, NS-10

## Context

"Installed" does not mean equivalent. Numeric compatibility percentages would imply precision before a defensible weighting model exists.

## Decision

Every asset-target result uses `Native`, `Portable`, `Adapted`, `Partial`, `Unsupported`, or `Blocked`, plus structured reasons and evidence. No percentage score is exposed initially.

## Consequences

Adapters must enumerate omissions and blocked requirements. CLI and machine output can aggregate categories but cannot erase reasons.

## Validation

Golden tests verify known omissions produce the correct non-success category.

## Gate F amendment

ADR-0026 replaces the original binding-only blocked-requirement vector with tagged `binding { name }` and `executable_trust` requirements. The portable value names missing local authority but never carries a resolved binding or trust decision.
