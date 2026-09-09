# Claude Code adapter research

**Status:** C2 policy design approved; implementation remains incomplete

**Evidence last reviewed:** 2026-08-23

## Official source

- https://code.claude.com/docs/en/skills

## Version evidence

Production `kitrove scan` does not invoke `claude --version` or another Claude process. It reports `VersionObservation::Unknown`. A library caller or versioned fixture may supply typed verified evidence.

The current skills page contains behavior notes for named Claude versions, but it does not define one numeric range for the complete root, layout, and duplicate policy. C2 therefore uses a conservative current-docs read-only profile for `Unknown`. Future active version probing belongs to a separate diagnostic command.

## Filesystem, scope, and tier

| Native source | Path | Scope | Root tier | C2 discovery |
|---|---|---|---|---|
| Enterprise skills | path selected through managed settings | User | Admin | caller-supplied `SuppliedNativeRoot` |
| Personal skills | `~/.claude/skills/<name>/SKILL.md` | User | User | static root |
| Project skills | `.claude/skills/<name>/SKILL.md` from the working directory through repository root | Project | Project | ancestor roots |
| Nested project skills | nested `.claude/skills/<name>/SKILL.md` below the working directory | Project | Project | bounded unusual-root hook |
| Plugin skills | `<plugin>/skills/<name>/SKILL.md` or plugin-root `SKILL.md` | depends on plugin enablement | Explicit | caller-supplied root in C2 |
| Additional-directory skills | `<added-directory>/.claude/skills/<name>/SKILL.md` | caller-selected | Explicit | caller-supplied root in C2 |
| Bundled skills | packaged with Claude Code | User | System | caller-supplied typed native root |
| Custom commands | `.claude/commands/<name>.md` | User or Project | native command source | related `Command`, not an Agent Skill |

Parent traversal stops at the repository root. Claude makes a nested root available after it reads or edits in that subtree. Kitrove has no session-access history, so its bounded hook inventories potential nested roots and attaches `claude.nested_activation_context_unknown`.

Scan reads no authentication, managed settings, session, history, cache, or plugin state. A caller may supply a verified enterprise, plugin, additional-directory, or bundled source through the typed local API. Kitrove does not sign in, reload, enable a plugin, or derive roots by launching Claude.

## Skill layout and identity

- Supported Agent Skill layout: `Directory`.
- Principal document: `SKILL.md`.
- Supporting files: documented beside the principal document, including references and scripts.
- Native invocation ID for personal and project skills: directory name.
- Frontmatter `name` for personal and project skills: optional display label, not invocation ID.
- Frontmatter `description`: recommended rather than required; when absent, Claude uses the first Markdown paragraph.
- Projection policy: use the directory ID when it passes standard validation. Use an authored standard description or the unmodified first paragraph when it is non-empty and within the standard limit. Retain a differing display name or body-derived description as adaptation evidence. Leave projection unavailable when no standard name or description can be formed without truncation or invention.
- Symlink policy: Claude may follow a skill-directory symlink. Kitrove reports `capture.symlink` and reads no target.

Claude documents custom command files and skill directories as related invocation forms. A skill wins when a skill and command share a name. C2 does not use this relationship as evidence that `.claude/commands/*.md` is a standalone Agent Skill layout. It records command presence under `AssetKind::Command` when the adapter observes that root.

## Duplicate and precedence policy

Current docs define:

- enterprise over personal over project;
- any of those sources over a same-name bundled skill;
- plugin skills under a plugin namespace;
- a skill over a same-name command;
- nested same-name project skills retained through directory-qualified names.

C2 keeps every candidate. A documented winner adds `scan.candidate_shadowed` to the lower-precedence candidate. Nested candidates use their qualified native identity and coexist. Enterprise, bundled, plugin, and additional-directory sources enter C2 only through caller-supplied typed roots; scan does not infer their absence from the default filesystem roots.

The current page does not define a total same-name order between an additional-directory source and the standard enterprise, personal, project, or bundled levels. C2 reports such an unqualified collision as ambiguous unless verified fixture evidence supplies an order. It does not substitute request or traversal order.

## Capability inventory

### Agent Skills

C2 supports directory observation through the shared engine. It preserves Claude-only frontmatter, dynamic shell injection syntax, invocation fields, exact bytes, file modes, and supporting files as native evidence. Known execution fields or scripts retain `Executable` classification. Scan runs none of them.

### Commands

Current `.claude/commands/*.md` files remain a related native command capability. They are outside the C2 Agent Skills adoption path. Future command support must use `AssetKind::Command` and its own fidelity rules.

### Instructions, agents, hooks, plugins, and MCP

C2 makes no support claim for these capability kinds. Native fields or supporting files that reference them remain exact evidence and can force `Partial`, `Unsupported`, or executable findings in later milestones.

Phase 3 research confirms that current custom subagents are Markdown files under user
`~/.claude/agents/` or project `.claude/agents/` directories. `name` and `description` are required,
the body is the system prompt, and optional fields can alter tools, permissions, models, MCP, hooks,
skills, memory, background execution, and worktree isolation. ADR-0031 therefore admits only the
required inert subset into portable v1 and treats every optional execution-affecting field as native
blocking evidence.

Phase 3 MCP research confirms three scopes: local and user entries in `~/.claude.json`, and shared
project entries in repository-root `.mcp.json`. Entries may start stdio programs or connect through
HTTP/SSE; project entries require separate machine-local approval, and local definitions take
precedence over project, user, plugin, and connector definitions of the same name. ADR-0032 accepts
only credential-free HTTPS Streamable HTTP plus an optional environment-backed bearer reference.
Kitrove never copies approval or OAuth state and never connects while inspecting or materializing.

## C2 policy contract

- Roots use user or project scope and the tiers above.
- Layout set is `{Directory}`.
- `Unknown` version selects the current read-only directory profile.
- The nested-root hook stays under the supplied project boundary and shared limits.
- Duplicate resolution uses the source rules above and retains shadows.
- Inspection performs no write, process spawn, network request, or symlink follow.
- Unsupported standalone Markdown in a skills root remains visible as `scan.layout_unsupported`.
- Command Markdown never enters skill capture.

## Fixture contract

- user, ancestor, project-root, and nested directory skills;
- personal over project shadowing;
- nested same-name qualification;
- skill over related command without command-to-skill coercion;
- name/display mismatch;
- missing description with valid and over-limit first-paragraph fallbacks;
- enterprise, bundled, plugin, and additional-directory roots supplied through typed inputs;
- additional-directory same-ID ambiguity;
- symlink refusal;
- executable native field and script;
- unknown-version informational finding;
- before-and-after filesystem equality and process-spawn sentinel.

## Evidence log

| Date | Policy line | Observation | Source |
|---|---|---|---|
| 2026-08-23 | Current docs | Enterprise, personal, project, plugin, additional-directory, bundled, nested, and command sources have distinct path and activation rules. | https://code.claude.com/docs/en/skills |
| 2026-08-23 | Current docs | Enterprise, personal, project, bundled, plugin, command, and nested clashes use documented winner or coexistence rules. | https://code.claude.com/docs/en/skills |
| 2026-08-23 | Current docs | Personal and project invocation names come from directories; frontmatter `name` supplies a display label. | https://code.claude.com/docs/en/skills |
| 2026-08-23 | Current docs | Frontmatter fields are optional, and a missing description falls back to the first Markdown paragraph. | https://code.claude.com/docs/en/skills |
| 2026-08-23 | C2 decision | Scan runs no Claude command and returns unknown version without caller evidence. | docs/adr/0012-versioned-read-only-adapter-observation.md |
| 2026-08-30 | Current docs | User and project subagents are recursively discovered Markdown files; logical identity comes from required `name` frontmatter. | https://code.claude.com/docs/en/sub-agents |
| 2026-08-30 | Current docs | Only `name` and `description` are required; the body is the system prompt and optional fields can change runtime authority. | https://code.claude.com/docs/en/sub-agents |
| 2026-08-30 | Current docs | MCP local, project, and user scopes have distinct storage, approval, and precedence behavior. | https://code.claude.com/docs/en/mcp |
| 2026-08-30 | Current docs | MCP HTTP, SSE, and stdio entries may interpolate environment variables; plugin and managed sources have separate authority. | https://code.claude.com/docs/en/mcp |
