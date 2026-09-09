# OpenCode adapter research

**Status:** C2 policy and production V2 executable evidence implemented

**Evidence last reviewed:** 2026-08-31

## Official sources

- https://opencode.ai/docs/skills
- https://opencode.ai/v2/docs/skills
- https://opencode.ai/v2/docs
- https://opencode.ai/v2/docs/migrate-v1

## Version evidence and policy boundary

Production `kitrove scan` does not invoke `opencode --version` or another OpenCode process. It reports `VersionObservation::Unknown`. A typed library caller or versioned fixture may select `OpenCodeCurrent` or `OpenCodeV2` with verified evidence.

The V2 page does not publish a numeric release cutover. Instead, OpenCode publishes V2 as the
separate `opencode2` executable and documents side-by-side installation with V1's `opencode`.
`kitrove versions probe --harness opencode --binary <absolute-opencode2-path>` therefore verifies
the dedicated executable name, exact `opencode2 v<semver>` output, bounded process behavior, and
the executable's BLAKE3 identity. It does not infer V2 from an `opencode` version string. Ordinary
unknown observation still uses the common current directory form and reports V2-only standalone
files or nested forms as unsupported.

Explicit V2 evidence is accepted only for a selected version-gated OpenCode instruction, command,
agent, or MCP asset. It selects the V2 policy for those entries and any portable skills in the same
atomic batch. Skill-only materialization retains the conservative current-policy fallback because
the current and V2 portable skill destinations and formats are identical. The complete local probe
observation replaces static policy evidence in each resulting plan digest, so a
different executable invalidates confirmation even when it reports the same semantic version.
Receipt-backed removal uses the already-owned destination and compiled compatible removal policy;
it does not execute OpenCode again.

## Built-in filesystem sources

| Source family | User path | Project path | Scope and tier |
|---|---|---|---|
| OpenCode native | `~/.config/opencode/skills` | `.opencode/skills` | User/User or Project/Project |
| Claude compatibility | `~/.claude/skills` | `.claude/skills` | User/Compatibility or Project/Compatibility |
| Agent compatibility | `~/.agents/skills` | `.agents/skills` | User/Compatibility or Project/Compatibility |

Project discovery walks from the working directory to the Git worktree or project root and includes matching sources at each level.

The V2 precedence list also names built-in skills. Verified V2 uses user scope and system tier for that source. A typed caller may supply a bounded native root; otherwise C2 reports the unresolved V2 system tier. Current and unknown profiles do not import a V2-only built-in-source assumption.

OpenCode V2 also accepts local directories and HTTP catalogs through config. C2 scans a local directory after a caller supplies it as `RootTier::Explicit`. It does not parse remote catalogs, fetch HTTP, update cache, or mutate config.

Authentication, provider config, sessions, permissions, agents, caches, logs, and unrelated generated state stay outside skill-source capture. C2 observes filesystem candidates without claiming that the selected OpenCode agent permits them.

## Layout and identity boundary

| Policy profile | Directory | Standalone Markdown | Native ID | Name validation |
|---|---|---|---|---|
| Current | one direct `<name>/SKILL.md` package per source | unsupported | frontmatter `name` | 1-64 lowercase kebab case and matching directory |
| V2 | `SKILL.md` at any depth | root-level `*.md` | exact case-sensitive path-derived ID | frontmatter `name` is optional display text; V2 does not enforce standard ID or description limits |
| Unknown | current common direct directory form | unsupported and visible | current conservative ID | current conservative validation |

V2 Standalone has no neighboring supporting-file list. Generic capture reads the one authored Markdown file and no siblings. Directory capture preserves supporting files. Exact identity retains layout, document name, modes, paths, and bytes. Portable projection can match across layouts.

A current mismatch fails with `skill.directory_name_mismatch`. V2 accepts a path ID that differs from display name and records portable-loss evidence when a standard projection needs a different name. V2 also accepts missing frontmatter, name, or description. C2 keeps that native candidate; portable projection is unavailable unless the path ID passes standard name validation and a description exists. C2 never fabricates a description.

V2 derives the ID from the discovered document's basename or containing directory, not its full nested path: `<source>/release.md`, `<source>/release/SKILL.md`, and `<source>/teams/release/SKILL.md` all produce `release`. A root-level `SKILL.md` produces the literal ID `SKILL`. IDs retain case.

## Duplicate and precedence policy

The current page tells users to keep names unique across locations but does not document a winner. C2 returns ambiguity and `ConflictingDuplicate` in classified mode.

V2 keys skills by path-derived ID and states that the later source wins. Its low-to-high precedence order is:

1. built-in skills;
2. Claude compatibility sources, global then farthest ancestor to current directory;
3. agent compatibility sources, global then farthest ancestor to current directory;
4. global OpenCode source;
5. project OpenCode sources, project root to current directory;
6. explicit config sources in config priority and array order.

C2 preserves the winner and every shadowed candidate. Shadowed entries include `scan.candidate_shadowed` and the winning observation ID. Unknown profile does not borrow V2 precedence.

## Capability inventory

### Agent Skills

C2 supports current directory packages plus verified V2 directory and standalone forms. Current unknown frontmatter fields remain exact native evidence. V2 `slash` and `metadata.opencode/*` fields remain native evidence. Known script or execution semantics remain `Executable`; scan runs none of them.

### Commands

OpenCode has a separate command system. C2 does not treat its command Markdown as ADR-0014 Standalone Agent Skills.

### Instructions, agents, plugins, tools, hooks, and MCP

C2 makes no support claim for these capability kinds. Permissions can affect native availability, but C2 does not turn local permission state into portable fidelity.

Phase 3 research confirms Markdown agents under user `~/.config/opencode/agents/` and project
`.opencode/agents/`. The file body is the prompt, the file stem is identity, and `mode` distinguishes
primary, subagent, and all behavior. Model, tool, and permission fields remain native controls.
ADR-0031 accepts only explicit `mode: subagent`, description, and body into portable v1.

Phase 3 MCP research uses the current V2 contract: named entries live below `mcp.servers`, local
entries start argv-style stdio commands, and remote entries use absolute Streamable HTTP URLs.
Servers connect unless disabled, while remote OAuth is active unless explicitly disabled. ADR-0032
therefore accepts only credential-free HTTPS remote entries and optional environment-backed bearer
headers; bearer entries explicitly refuse OAuth, while credential-free entries retain ambient OAuth
as target-local fidelity. Current/unknown shapes remain unsupported until their exact policy is
compiled rather than inferred from V2.

## C2 policy contract

- Filesystem roots use the scope and tier table above.
- Verified V2 reports its built-in source through a typed native root or an unresolved system-tier finding.
- A caller may add a local explicit root; C2 never fetches an HTTP catalog.
- `Unknown` uses current direct directory rules.
- Verified V2 enables root-level standalone, nested `SKILL.md`, path IDs, and documented precedence.
- Current and unknown duplicate names remain ambiguous.
- V2 shadows retain every candidate.
- Unsupported layout candidates remain visible.
- Inspection performs no write, process spawn, network request, cache update, or symlink follow.

## Fixture contract

- all six filesystem user and project source families;
- supplied and unresolved V2 built-in system sources;
- ancestor traversal through worktree root;
- current direct directory acceptance and strict mismatch;
- current standalone and nested-layout rejection with visible findings;
- V2 root standalone and nested directory acceptance;
- equal portable identity across layouts with distinct exact identity;
- V2 path ID, display-name mismatch, and case sensitivity;
- current ambiguity and V2 later-source shadow order;
- local explicit root and rejected HTTP source;
- permission evidence as local finding, not portable state;
- executable content, symlink refusal, process/network sentinels, and filesystem equality.

## Evidence log

| Date | Policy line | Observation | Source |
|---|---|---|---|
| 2026-08-23 | Current docs | Current OpenCode requires one directory per skill with `SKILL.md` and searches native plus compatibility roots. | https://opencode.ai/docs/skills |
| 2026-08-23 | Current docs | Current names must match their directory; the page defines no duplicate winner. | https://opencode.ai/docs/skills |
| 2026-08-23 | V2 docs | V2 accepts root-level Markdown and `SKILL.md` at any depth. | https://opencode.ai/v2/docs/skills |
| 2026-08-30 | Current docs | Markdown agents use user/project agent directories and the file name as agent identity. | https://opencode.ai/docs/agents/ |
| 2026-08-30 | Current docs | Agent mode can be primary, subagent, or all; omitted mode is not safely equivalent to subagent-only v1. | https://opencode.ai/docs/agents/ |
| 2026-08-23 | V2 docs | V2 derives exact case-sensitive IDs from paths and treats frontmatter name as display text. | https://opencode.ai/v2/docs/skills |
| 2026-08-23 | V2 docs | V2 defines a six-step later-source-wins order and distinguishes supporting files for directory sources. | https://opencode.ai/v2/docs/skills |
| 2026-08-23 | C2 decision | Unknown version does not select V2, and scan launches no OpenCode process. | docs/adr/0012-versioned-read-only-adapter-observation.md |
| 2026-08-30 | V2 docs | MCP entries live under `mcp.servers`; local entries start commands and remote entries use Streamable HTTP. | https://opencode.ai/v2/docs/mcp-servers/ |
| 2026-08-30 | V2 docs | Servers connect unless disabled, and remote OAuth is attempted unless explicitly disabled. | https://opencode.ai/v2/docs/mcp-servers/ |
| 2026-08-30 | V2 docs | Global and project configuration accept JSON or JSONC at documented direct and `.opencode` locations with defined merge precedence. | https://opencode.ai/v2/docs/config/ |
| 2026-08-31 | V2 docs | V2 installs and runs as `opencode2` beside V1's `opencode`; binary identity, not a guessed numeric threshold, selects the V2 probe contract. | https://opencode.ai/v2/docs |
| 2026-08-31 | V2 migration docs | V1 and V2 are explicitly side-by-side and the V2 beta remains changeable, so Kitrove retains exact ephemeral evidence and fail-closed policy selection. | https://opencode.ai/v2/docs/migrate-v1 |
