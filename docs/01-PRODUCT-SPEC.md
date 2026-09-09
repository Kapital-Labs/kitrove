# Product Specification

**Status:** Accepted for private design review  
**Working name:** Kitrove

## Product statement

Kitrove is an open-source, Rust-first portability and synchronization layer for a developer's durable agent environment. It discovers, adopts, versions, preserves, adapts, and synchronizes capabilities across AI coding harnesses and computers while keeping credentials, authentication, and machine-private state local.

> **Build your agent environment in any harness. Carry it, without silent loss, to every other supported harness and machine.**

## User problem

Developers accumulate skills, instructions, agents, commands, hooks, MCP declarations, plugins, extensions, and packs across multiple harnesses and computers. Current continuity usually depends on manual copying, symlinks, dotfiles, one-way configuration managers, or hand-maintained equivalents. Those approaches fail when capabilities originate inside a harness, include native behavior, diverge across computers, or require different local identities.

## Primary users

A developer who:

- uses two or more agentic coding harnesses
- works across two or more computers or operating systems
- acquires or authors reusable skills and workflow packs
- wants local-first and self-hostable behavior
- requires explicit security boundaries and reproducibility

A later secondary user is a small team sharing a baseline with personal overlays. Team policy is not an MVP requirement.

## Jobs to be done

1. **Adopt something useful.** Discover a capability inside a harness and bring it under management without re-authoring it.
2. **Use it elsewhere.** Materialize compatible behavior on another harness or machine with an honest fidelity report.
3. **Preserve unique behavior.** Retain native components even when another target cannot represent them.
4. **Keep identity local.** Reuse capabilities while accounts, API keys, and secret providers differ per machine.
5. **Understand drift.** Explain canonical, local-deployment, upstream, and synchronization drift at the asset level.
6. **Manage a pack as one object.** Upgrade, audit, synchronize, remove, and roll back a multi-capability pack coherently.

## Core concepts

### Environment

The desired portable capability inventory plus source resolution, profiles, and selected targets.

### Asset

A first-class capability object with stable identity, source, revision, content hash, trust metadata, portable content, native variants, compatibility, and receipts.

### Pack

An aggregate asset containing multiple related capabilities and possibly native implementations for several harnesses.

### Portable core

Content represented independently of one harness or through a shared standard.

### Native variant

Harness-specific content preserved alongside the portable core.

### Fidelity

One of `Native`, `Portable`, `Adapted`, `Partial`, `Unsupported`, or `Blocked`, plus structured reasons.

### Receipt

Evidence that Kitrove materialized a particular asset into a destination at a specific content and adapter version.

### Binding

A symbolic local requirement such as `github_mcp_token`. Portable state names it; each machine resolves it locally.

## Core workflows

### Initialize

```bash
kitrove init
```

Creates an environment and machine-local identity, detects harnesses, and reports existing capabilities without adopting or mutating them implicitly.

### Scan

```bash
kitrove scan
```

Read-only inspection works before environment initialization. In inventory mode it reports valid candidates as unmanaged and failures as unknown. With manifest and local receipt evidence, it classifies managed unchanged, managed modified, unmanaged capability, missing managed capability, conflicting duplicate, and unknown content. It does not launch harness binaries, initialize state, or repair receipts.

### Adopt

```bash
kitrove adopt claude:skill/frontend-design
```

Captures the original source, extracts portable content, preserves native behavior, classifies trust, computes compatibility, and proposes an atomic environment update.

### Add

```bash
kitrove add git:https://example.com/org/pack
```

Fetches without executing, inventories the source, shows trust and target plans, then records a locked asset after approval.

### Plan and apply

```bash
kitrove plan
kitrove apply
```

Plans and materializes desired state with staging, validation, ownership receipts, and safe writes.

### Synchronize

```bash
kitrove sync
```

Fetches portable state, reconciles asset-level changes, surfaces semantic conflicts, applies accepted results locally, validates, and publishes through the selected backend.

### Inspect compatibility

```bash
kitrove compatibility gstack
```

Shows permanent per-target fidelity and reasons for partial, unsupported, or blocked results.

### Upgrade and rollback

```bash
kitrove upgrade gstack
kitrove rollback gstack
```

Operate on a lifecycle object rather than anonymous generated files.

## Core features

- version-evidence-aware harness discovery without active scan probes
- read-only scanning
- bidirectional adoption from every tier-one harness
- portable core plus native variants
- structured fidelity reporting
- provenance and deterministic lockfile
- receipt-backed atomic materialization
- Git and filesystem synchronization backends
- asset-level drift and conflict handling
- machine-local secret bindings
- content trust classification
- pack lifecycle management

## Add-on features

Deferred until the core model is proven:

- community WASM adapter SDK
- declarative simple adapters
- capability registry and search
- OCI pack distribution
- WebDAV and S3-compatible sync backends
- team baseline plus personal overlays
- organization policy
- signed provenance
- background watcher
- TUI or desktop UI
- named snapshots
- sanitized environment export
- public compatibility database

## Non-goals

Kitrove does not own operating-system packages, language runtimes, harness installation, Docker, general dotfiles, model billing, request proxying, chat history, OAuth credential movement, workstation bootstrap, or secret storage.

An adapter may invoke a harness's own native capability lifecycle only when planned and trusted. This does not authorize general package management.

## Tier-one scope

Harnesses: Claude Code, Codex, Pi, OpenCode.

Platforms: macOS arm64/x86_64, Linux arm64/x86_64, Windows x86_64. WSL is a distinct Linux machine profile.

MVP capability types: skills and instructions. The skills slice accepts directory packages and policy-supported standalone Markdown while retaining original layout evidence. Claude command files remain related native `Command` capabilities rather than Agent Skills. Commands and basic MCP declarations are conditional. Executable plugins, extensions, and complex hooks are deferred until native-variant and trust architecture are proven.

## Product quality requirements

- zero silent-loss paths
- deterministic locked application
- no implicit remote execution
- transactional recovery for adopt/apply/sync/upgrade/rollback
- inspectable portable/local boundaries
- Windows-safe semantics without required symlinks
- actionable failures rather than ambiguous success

## MVP acceptance scenario

1. Create or install a valid skill in Claude Code on computer A.
2. `scan` discovers it without mutation.
3. `adopt` records portable content and origin metadata.
4. `plan` reports all four target outcomes.
5. `apply` materializes it into enabled compatible harnesses.
6. `sync` publishes portable state without credentials.
7. Computer B synchronizes and receives it.
8. Computer B edits the portable skill.
9. `scan` identifies local deployment drift.
10. The user adopts the change.
11. It synchronizes back to computer A.
12. Native variants remain unchanged.
13. No raw Git command is required.

## Kill criteria

Stop, fold into another project, or redesign if adoption requires substantial re-authoring; native behavior cannot be preserved; round-trip is unreliable; the experience is not materially better than Kasetto plus manual edits; adapter maintenance is unsustainable; another OSS project implements equivalent semantics; or security would require owning credentials or executing untrusted installers by default.
