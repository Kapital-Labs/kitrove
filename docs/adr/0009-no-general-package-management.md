# ADR-0009: No General Package Management

- **Status:** Accepted
- **Date:** 2026-08-22
- **North Star invariants:** NS-08

## Context

Cross-platform installation of runtimes, harnesses, Docker, and OS packages is a broad and mature problem that would overwhelm capability portability.

## Decision

Kitrove detects prerequisites and may invoke a harness's reviewed native capability lifecycle, but does not install general system software or runtimes.

## Consequences

Some plans are `Blocked` until users satisfy prerequisites externally.

## Validation

Feature review rejects additions whose primary purpose is workstation or runtime provisioning.
