# Harness capability matrix

**Status:** C2 evidence and policy baseline, extended through Phase 5 version and project-trust boundaries
**Last reviewed:** 2026-09-02

Harness behavior needs official documentation, a versioned fixture, or a reproducible observation. Production scan runs no harness command and reports `VersionObservation::Unknown` unless a typed caller supplies verified evidence.

## C2 Agent Skills discovery inputs

| Harness policy | User or global roots | Project roots | Native root tiers | Production scan version |
|---|---|---|---|---|
| Claude current | `~/.claude/skills`; caller-supplied enterprise, bundled, plugin, or additional-directory sources | parent and nested `.claude/skills` | User, Project, Admin, System, Explicit | `Unknown` |
| Codex current | `~/.agents/skills`, `/etc/codex/skills`, bundled source | ancestor `.agents/skills` through repository root | User, Project, Admin, System | `Unknown` |
| Pi Latest | `~/.pi/agent/skills`, `~/.agents/skills` | `.pi/skills`, ancestor `.agents/skills`, subject to trust evidence | User, Project, Compatibility, Explicit | `Unknown` |
| OpenCode current or unknown | `~/.config/opencode/skills`, `~/.claude/skills`, `~/.agents/skills` | matching native and compatibility roots through worktree root | User, Project, Compatibility, Explicit | `Unknown` |
| OpenCode V2 with verified evidence | same filesystem roots, a typed built-in provider, and caller-supplied local directories | same project roots through project root | User, Project, System, Compatibility, Explicit | caller evidence |

`HarnessScope` remains `User | Project`. `RootTier` is transient and records `User | Project | Admin | System | Compatibility | Explicit`. A root has both values. Root tier never enters portable or receipt identity.

Codex C2 observation covers repository, user, admin, and system tiers. If no safe bundled system provider exists, the report includes `scan.root_unresolved` for system tier and launches no Codex process.

Pi project trust is a typed transient input keyed by Pi and the validated project anchor. Production scan does not inspect Pi trust state; absent evidence produces `pi.project_trust_unknown`, while declined evidence produces `pi.project_trust_declined`. Both retain the candidate and its ownership classification.

## Skill source layouts

| Harness policy | Directory | Standalone Markdown | Boundary |
|---|---|---|---|
| Claude current | supported | unsupported for Agent Skills | `.claude/commands/*.md` is a related `Command`, not a skill layout |
| Codex current | supported | unsupported | official package form is a directory with `SKILL.md` |
| Pi Latest native `.pi` roots | supported at any depth | supported at the source root | valid skill frontmatter and non-empty description |
| Pi Latest `.agents` compatibility roots | supported at any depth | host ignores direct root files; C2 reports the unsupported layout; grouping-folder files are supported | root-specific discovery rule |
| OpenCode current | supported as direct `<name>/SKILL.md` | unsupported | strict current name and directory rule |
| OpenCode V2 | supported at any depth | supported at source root | verified V2 policy line required |
| OpenCode unknown | conservative current directory form | visible as unsupported | unknown does not select V2 |

ADR-0014 exact identity contains layout, original document name, paths, modes, and bytes. Portable projection maps the principal document to `SKILL.md`. Portable hashes may match across layouts; exact hashes do not.

Pi explicit sources may be a local directory or one standalone file because its documented settings and CLI accept both. OpenCode V2 explicit sources are local directories. C2 fetches neither package nor HTTP sources.

## Native identity and duplicates

| Harness policy | Native identity | Container/name policy | Same-name policy |
|---|---|---|---|
| Claude current | directory name, plus qualified path for nested clashes | name and description are optional; projection uses a standard-valid directory ID and an authored description or valid first-paragraph fallback, with adaptation evidence | documented source winner; nested qualified candidates coexist; retain shadows |
| Codex current | standard directory skill identity | strict | coexist, never merge |
| Pi Latest | declared frontmatter name | mismatch accepted by host with loss evidence | first-found-wins is documented, but total source order is not; C2 reports ambiguity without order evidence |
| OpenCode current | matching frontmatter and directory name | strict | no documented winner; C2 reports ambiguity |
| OpenCode V2 | exact case-sensitive document basename or `SKILL.md` parent-directory ID | name and description may be absent; portable projection needs a standard-valid path ID and a description | later source wins in documented order; retain shadows |
| OpenCode unknown | current conservative identity | strict | ambiguity; V2 precedence not applied |

C2 preserves every candidate. Documented winners attach `scan.candidate_shadowed`; coexistence keeps independent entries; unresolved effective duplicates become `ConflictingDuplicate` in classified mode.

## High-level research matrix

| Capability | Claude Code | Codex | Pi | OpenCode |
|---|---|---|---|---|
| Durable instructions | researched for Phase 3 | researched for Phase 3 | researched for Phase 3 | researched for Phase 3 |
| Agent Skills Directory | current policy | current policy | Latest policy | current, unknown, and V2 policies |
| Agent Skills Standalone | unsupported | unsupported | Latest root-specific policy | verified V2 policy only |
| Related command Markdown | legacy native `Command`; skills recommended | removed from current releases; skills recommended | first-class prompt templates | first-class Markdown and config commands |
| Agents or subagents | outside C2 | outside C2 | outside C2 | outside C2 |
| Hooks or lifecycle | exact evidence and classification | exact evidence and classification | exact evidence and classification | exact evidence and classification |
| MCP declarations | scan/adopt/update/apply/remove implemented | scan/adopt/update/apply/remove implemented | unsupported: no built-in registry | V2 full local lifecycle implemented when version-authorized |
| Native packaging | caller-supplied plugin root | caller-supplied system root | caller-supplied local root | caller-supplied local root; no HTTP fetch |
| Executable extension | classified, never run | classified, never run | classified, never run | classified, never run |

A documented native capability does not imply schema or semantic parity. C2 inventories Agent Skills, retains related findings, and makes no executable lifecycle claim.

## Scan and ownership matrix

| Inputs | Valid candidate | Failed candidate | Duplicate ambiguity | Receipt-backed states |
|---|---|---|---|---|
| no initialized environment | `Unmanaged` | `Unknown` | candidates stay `Unmanaged` with finding | unavailable |
| manifest and valid local receipt view | one of six states | `Unknown` | `ConflictingDuplicate` | unchanged, modified, or missing through exact target identity |
| invalid receipt record | unaffected siblings continue | affected association is `Unknown` | unaffected groups continue | invalid receipt proves no ownership |
| invalid top-level local state | inventory retained with report finding | `Unknown` where ownership may exist | duplicate evidence retained | ownership claims disabled |

C2 adds receipt scope and read-only receipt identity/shape validation. For Agent Skills, receipt source identity is the complete manifest asset revision's `Asset.content_hash`, distinct from the portable object's hash; rendered identity is the layout-aware exact-source hash of the installed target. Scan derives a receipted target's layout from its safe filesystem kind, independent of current version-policy acceptance. It creates, repairs, updates, or removes no receipt.

Discovery and capture are request-bounded. Aggregate file-attempt and byte budgets apply across candidates and overlapping roots in addition to each candidate's capture limits.

## Official sources reviewed

### Claude Code

- https://code.claude.com/docs/en/skills

### Codex

- https://developers.openai.com/codex/skills
- https://agentskills.io/specification

### Pi

- https://pi.dev/docs/latest/skills

### OpenCode

- https://opencode.ai/docs/skills
- https://opencode.ai/v2/docs/skills

## Phase 3 standing-instruction evidence

This section records the official behavior used to design the first Phase 3 capability. It does not
expand the C2 Agent Skills scanner or authorize writes by itself.

The compiled user/project target policies, capability declarations, and receipt-bound single-document
observer/classifier are implemented. Scan-engine integration, adoption, and mutation remain the next
Phase 3 slices.

| Harness policy | User target | Project target | Native discovery and precedence relevant to projection |
|---|---|---|---|
| Claude current | `~/.claude/CLAUDE.md` | repository-root `CLAUDE.md` | managed policy, user, project, then local; ancestor files layer root-to-working-directory; subdirectory files load on demand; `CLAUDE.local.md`, auto memory, imports, and `.claude/rules/` have distinct semantics |
| Codex current | `$CODEX_HOME/AGENTS.md`, normally `~/.codex/AGENTS.md` | repository-root `AGENTS.md` | one file per directory, preferring `AGENTS.override.md`; project files layer root-to-working-directory; custom fallback names and nested overrides are native configuration |
| Pi Latest | `~/.pi/agent/AGENTS.md` | repository-root `AGENTS.md` | `AGENTS.override.md` replaces `AGENTS.md` or `CLAUDE.md` within one directory; context files from ancestors still layer; context files load independently of project-resource trust |
| OpenCode current | `~/.config/opencode/AGENTS.md` | repository-root `AGENTS.md` | current documentation selects the first local `AGENTS.md`/`CLAUDE.md` and then global fallback by category |
| OpenCode V2 with verified evidence | `$XDG_CONFIG_HOME/opencode/AGENTS.md` | repository-root `AGENTS.md` | every `AGENTS.md` from the location upward is combined; nested files may load on access; V1 `CLAUDE.md` fallback and remote/config instruction resolution do not apply |
| OpenCode unknown | no writable target | no writable target | current and V2 discovery differ materially, so unknown version fails closed for instruction materialization |

The portable intersection is an authored Markdown instruction body with `User` or repository-root
`Project` scope. Kitrove does not claim that native precedence is portable. It reports native ordering,
override, conditional-loading, import, and fallback behavior as fidelity evidence.

The following are deliberately separate capabilities or native variants, not standing instructions:

- Claude auto memory, `CLAUDE.local.md`, managed policy, imported external files, and path-scoped
  `.claude/rules/`;
- Codex `AGENTS.override.md` and custom fallback filenames;
- Pi `SYSTEM.md`, `APPEND_SYSTEM.md`, and override files;
- OpenCode config-driven local, glob, URL, dynamic, or session instruction sources.

Project `AGENTS.md` is a shared physical target for Codex, Pi, and OpenCode. Phase 3 must coalesce
identical projections to that target. It must never create one duplicate block per harness merely to
fit a harness-shaped receipt.

### Official instruction sources reviewed

- https://code.claude.com/docs/en/memory
- https://developers.openai.com/codex/guides/agents-md
- https://pi.dev/docs/latest/usage
- https://pi.dev/docs/latest/security
- https://opencode.ai/docs/rules/
- https://opencode.ai/v2/docs/instructions

## Phase 3 prompt-command evidence

This boundary is implemented by ADR-0030 and
`docs/superpowers/specs/2026-08-30-phase3-commands-prompts.md`. Compiled target policies and the
receipt-backed plan/apply/remove lifecycle now authorizes Claude legacy and Pi targets. Removal is an
exact whole-file transaction that clears only matching local receipt authority and retains the
portable asset. OpenCode still fails closed until production can supply trustworthy V2 evidence;
Codex remains unsupported.

| Harness policy | Standard Markdown roots | Portable target decision |
|---|---|---|
| Claude current | `~/.claude/commands/**/*.md`, project `.claude/commands/**/*.md` | Legacy compatibility target for direct-child commands, with explicit deprecation fidelity; subdirectories do not namespace invocation and skills take precedence on name collision. |
| Codex current | none | Unsupported. Custom prompts were removed; Kitrove does not silently convert a command asset to a skill. |
| Pi Latest | direct `*.md` children of `~/.pi/agent/prompts` and project `.pi/prompts` | Portable for the inert common subset; standard discovery is non-recursive and project templates require project trust. |
| OpenCode current/V2 | `~/.config/opencode/commands/**/*.md`, project `.opencode/commands/**/*.md` | Portable for direct-child inert commands; nested command namespaces and JSON/JSONC commands remain native in v1. |

The v1 portable intersection is one direct-child, single-segment UTF-8 Markdown command with an
optional bounded description and either no argument placeholder or one normalized all-arguments
placeholder. Shell interpolation is executable.
Positional/range arguments, implicit argument appending, file inclusion, model/agent/tool metadata,
configured sources, packages, plugins, built-ins, and remote definitions remain native, blocked, or
unsupported as specified by the design.

### Official prompt-command sources reviewed

- https://code.claude.com/docs/en/slash-commands
- https://code.claude.com/docs/en/agent-sdk/slash-commands
- https://github.com/openai/codex/issues/15941
- https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/prompt-templates.md
- https://opencode.ai/v2/docs/commands

## Phase 3 MCP evidence

ADR-0032 and `docs/superpowers/specs/2026-08-30-phase3-mcp-declarations.md` accept a narrow portable
Streamable HTTP declaration. The design does not expand C2 skill inspection or authorize network or
process activity.

| Harness policy | User/project native shape | Portable target decision |
|---|---|---|
| Claude current | `mcpServers.<name>` in `~/.claude.json` or project `.mcp.json` | HTTPS Streamable HTTP plus optional environment-backed bearer reference; local/project approval state remains local. |
| Codex current | `[mcp_servers.<name>]` in user/project `config.toml` | HTTPS Streamable HTTP plus optional `bearer_token_env_var`; OAuth and tool policy remain native. |
| Pi Latest | no built-in MCP setting | Unsupported; extension-provided integrations are executable native capabilities. |
| OpenCode V2 | `mcp.servers.<name>` in user/project JSON/JSONC | HTTPS remote entry plus optional environment-backed bearer reference; bearer entries disable OAuth while ambient OAuth remains target-local fidelity for credential-free entries. |

Local stdio, SSE, plaintext HTTP, arbitrary headers, OAuth, tool policy, timeouts, managed/plugin
sources, and generated authentication state remain native, blocked, or unsupported. MCP entries are
agent-active and live inside shared configuration documents, so implementation requires exact logical
entry receipts and atomic preservation of unrelated document content.

The implemented lifecycle performs bounded read-only classification, exact first/update adoption,
deterministic multi-entry coalescing, confirmed atomic plan/apply, exact receipt-backed removal, and
crash recovery. Planning reports that a later harness load may connect to the declared endpoint;
Kitrove itself never connects during these workflows.

### Official MCP sources reviewed

- https://code.claude.com/docs/en/mcp
- https://developers.openai.com/codex/mcp/
- https://developers.openai.com/codex/config-reference/
- https://opencode.ai/v2/docs/mcp-servers/
- https://opencode.ai/v2/docs/config/
- https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/settings.md

## Required adapter evidence

For each policy line, record root scope and tier, traversal boundary, source layouts, native identity, container/name behavior, duplicate resolution, shadow behavior, trust or permission prerequisites, reload behavior, authentication and generated-state exclusions, symlink behavior, target layout, and tested fixture provenance.

Unknown version rules must name the conservative intersection they use. Explicit Pi and OpenCode V2
diagnostic probes remain outside scan and bind accepted evidence to the exact local executable.
Windows Pi project scope additionally requires handle-bound saved-project trust-store ownership and
DACL evidence.

## Fidelity questions

For each capability mapping:

- Can the target consume the original layout and content unchanged?
- Can it consume the portable projection through another layout without semantic loss?
- Which native names, fields, supporting files, or lifecycle events lack an equivalent?
- Does Kitrove retain the origin layout and exact bytes?
- Can the transformation round-trip?
- Which official source, fixture, or observation supports the result?

## Implementation priority

1. C2 Agent Skills observation through both generic layouts where policy permits them.
2. C3 adoption with origin-layout evidence and four-target fidelity.
3. C4 target-layout rendering and scoped receipts.
4. Standing instructions.
5. Commands, prompt templates, and agents.
6. Basic MCP declarations.
7. Hooks, plugins, extensions, and packs after trust architecture.
