# Kitrove North Star

This document contains the durable product invariants. Product plans, code, adapters, deadlines, and convenience do not override them silently.

Any proposal that weakens an invariant requires an ADR that names the affected invariant, explains the tradeoff, and receives explicit maintainer approval.

## Mission

> **Kitrove makes agent capabilities portable and bidirectional across harnesses and machines without silently losing native behavior or moving identity.**

## Product invariants

### NS-01 — Capabilities belong to the developer

The durable unit is the developer's capability environment, not a harness directory. Claude Code, Codex, Pi, and OpenCode are runtimes and contributors to that environment.

### NS-02 — Portability is bidirectional

Supported harnesses must be able to consume managed capabilities and contribute discoverable local capabilities back through an explicit `scan -> adopt` workflow. A one-way manifest renderer is not enough.

### NS-03 — Portable does not mean lowest common denominator

Every asset may contain a portable core plus harness-native variants. Native behavior that cannot travel must be preserved, not erased or silently normalized away.

### NS-04 — Fidelity is explicit

Every asset-target result must be classifiable as `Native`, `Portable`, `Adapted`, `Partial`, `Unsupported`, or `Blocked`. Kitrove must never report undifferentiated success when behavior was omitted.

### NS-05 — Assets and packs are first-class

A managed capability has stable identity, provenance, revision, content hash, trust classification, target compatibility, and deployment receipts. A multi-capability pack remains one lifecycle object.

### NS-06 — Synchronization is a product workflow

Users synchronize environments with Kitrove semantics, not by manually reconciling harness directories. Git may be a backend, but manual Git operations are not the intended user experience.

### NS-07 — Identity and secrets remain local

Harness authentication, OAuth state, API keys, tokens, cookies, and decrypted secret values are never part of portable state. Portable state may declare symbolic binding requirements; each machine resolves them locally.

### NS-08 — No package-management creep

Kitrove manages agent capability assets. It does not become a general installer for operating-system packages, language runtimes, Docker, harness binaries, or unrelated tools. It may detect and report prerequisites.

### NS-09 — Safety precedes convenience

Remote executable content is inspected, classified, and trusted before execution. Kitrove does not automatically run arbitrary upstream installers or lifecycle scripts.

### NS-10 — Partial support is acceptable; silent loss is not

A capability may be unsupported on a target. The correct response is preservation plus a clear report, not a lossy transformation disguised as success.

## Architectural test

Every major feature must answer:

1. How is the capability discovered or introduced?
2. What is portable?
3. What remains native?
4. What provenance and trust data are retained?
5. What fidelity does each target receive?
6. Can the result round-trip without silent loss?
7. What stays local to the machine?
8. How does it behave during synchronization and conflict?

## Product distinction

```text
Kanon      compiles agent configuration
agentctl   deploys agent configuration
agentenv   reproduces project capabilities
Kasetto    declares agent environments

Kitrove    makes agent capabilities portable and bidirectional
```

## Reassessment questions

At every phase gate, ask:

1. Are we still solving capability portability rather than configuration distribution?
2. Can capabilities move both into and out of Kitrove without silent loss?
3. Is the result materially better than extending an existing OSS tool?

If any answer becomes "no," stop and reassess before expanding implementation.
