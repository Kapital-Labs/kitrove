# ADR-0001: Portable Core Plus Native Variants

- **Status:** Accepted
- **Date:** 2026-08-22
- **North Star invariants:** NS-03, NS-10

## Context

Harnesses expose overlapping but non-identical capability systems. A single normalized schema would either omit native behavior or grow into a disguised union of every harness.

## Decision

An asset may contain a portable core and independent native variants for zero or more harnesses. Materialization combines the portable representation, any reviewed adaptation, and the target's native variant. Unsupported native variants remain stored.

## Consequences

The model is more complex and adapters must reason about composition. In return, Kitrove can preserve behavior and report honest target fidelity instead of flattening everything.

## Validation

Round-trip tests must prove a portable edit never removes an unrelated native variant and a native edit never rewrites portable content implicitly.
