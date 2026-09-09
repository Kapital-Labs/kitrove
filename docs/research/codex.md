# Codex adapter research

**Status:** C2 policy design approved; implementation remains incomplete

**Evidence last reviewed:** 2026-08-23

## Official sources

- https://developers.openai.com/codex/skills
- https://agentskills.io/specification

## Version evidence

Production `kitrove scan` does not invoke `codex --version` or another Codex process. It reports `VersionObservation::Unknown`. A library caller or versioned fixture may supply typed verified evidence. The current skills page does not publish a numeric range for its full discovery contract, so C2 uses the documented current directory profile for read-only unknown-version inventory.

## Filesystem, scope, and tier

| Native source | Path | Scope | Root tier | C2 discovery |
|---|---|---|---|---|
| Repository | `.agents/skills` in the working directory and every ancestor through repository root | Project | Project | ancestor roots |
| User | `$HOME/.agents/skills` | User | User | static root |
| Admin | `/etc/codex/skills` | User | Admin | static root |
| System | skills bundled with Codex | User | System | typed native root or visible unresolved-tier finding |

C2 evaluates all four tiers. The official page documents bundled system skills but no portable filesystem path for them. Scan accepts a typed native root from its caller. Without one, it emits `scan.root_unresolved` for `RootTier::System`. It never launches Codex or infers absence.

Codex config, credentials, session state, logs, caches, and ChatGPT account data are outside candidate roots. `~/.codex/config.toml` can disable a skill, but C2 does not parse local enablement as portable content or use it to hide a filesystem candidate.

## Skill layout and identity

- Supported layout: `Directory`.
- Principal document: `SKILL.md`.
- Supporting files: optional `scripts/`, `references/`, `assets/`, and `agents/openai.yaml` content.
- Required document fields: `name` and `description` under the open Agent Skills contract.
- Container/name policy: strict standard directory identity. The Codex page says skills follow the open Agent Skills standard, and that standard requires `name` to match the parent directory. A mismatch yields `Unknown` with `skill.directory_name_mismatch`.
- Symlink policy: native Codex behavior does not weaken Kitrove's no-follow boundary. A symlinked source stays visible as `Unknown` and Kitrove reads no target.

The official page calls unbundled packages "standalone skills" in product prose and then defines a skill as a directory with `SKILL.md`. It provides no evidence for a flat Markdown source. ADR-0014 `Standalone` remains disabled for Codex current and unknown profiles.

## Duplicate policy

The current page states that Codex does not merge same-name skills and may show both in selectors. C2 uses `DuplicateDecision::Coexist`. It keeps each repository, user, admin, or system candidate under its observation identity. It does not invent a winner or classify documented coexistence as a conflict.

If two candidates collide under an identity that the documented selector cannot distinguish, the policy returns ambiguity with evidence. Byte equality never merges them.

## Capability inventory

### Agent Skills

C2 observes directory packages across all four tiers. Shared capture preserves `agents/openai.yaml`, scripts, references, assets, exact bytes, and modes. Optional interface or dependency metadata remains native evidence. Script content remains `Executable`; scan runs none of it.

### Instructions, agents, commands, hooks, plugins, and MCP

C2 makes no support claim for these capability kinds. An `agents/openai.yaml` file is supporting native skill metadata, not a separately adopted Agent asset in C2.

Phase 3 research confirms a separate custom-agent registry under user `~/.codex/agents/` and project
`.codex/agents/`. Each standalone TOML file requires `name`, `description`, and
`developer_instructions`; normal session configuration such as model, reasoning effort, sandbox,
MCP, and skills may also be present. ADR-0031 accepts only the three required fields into portable v1.

Phase 3 MCP research confirms user `~/.codex/config.toml` and trusted project `.codex/config.toml`
tables under `mcp_servers`. Codex supports stdio commands and Streamable HTTP URLs plus environment,
OAuth, tool-policy, timeout, required, and enablement controls. ADR-0032 accepts only credential-free
HTTPS Streamable HTTP and an optional `bearer_token_env_var`; OAuth credentials, static headers,
tool policy, and local commands remain machine-local or native blocking evidence.

## C2 policy contract

- Root descriptors cover project, user, and admin.
- The unusual-root hook accepts a typed native system root.
- Layout set is `{Directory}`.
- `Unknown` version selects conservative current directory rules.
- Same-name candidates coexist and remain unmerged.
- Unsupported flat Markdown remains visible as `scan.layout_unsupported`.
- Inspection performs no write, process spawn, network request, or symlink follow.

## Fixture contract

- working-directory, ancestor, and repository-root sources;
- user and admin sources;
- supplied and unresolved bundled system sources;
- all four tiers in one report;
- same-name coexistence across tiers;
- strict container/name mismatch;
- unsupported standalone Markdown;
- optional supporting directories and executable classification;
- symlink refusal;
- unknown-version informational finding;
- before-and-after filesystem equality and process-spawn sentinel.

## Evidence log

| Date | Policy line | Observation | Source |
|---|---|---|---|
| 2026-08-23 | Current docs | Codex reads repository, user, admin, and bundled system skill sources. | https://developers.openai.com/codex/skills |
| 2026-08-23 | Current docs | Repository discovery walks from the working directory through repository root. | https://developers.openai.com/codex/skills |
| 2026-08-23 | Current docs | Same-name skills are not merged and can coexist in selectors. | https://developers.openai.com/codex/skills |
| 2026-08-23 | Current docs | A local skill package is a directory with `SKILL.md`; no flat Markdown layout is documented. | https://developers.openai.com/codex/skills |
| 2026-08-23 | Open standard | The required standard name matches the parent directory. | https://agentskills.io/specification |
| 2026-08-23 | C2 decision | Scan runs no Codex command and reports an unresolved system tier when no safe provider exists. | docs/adr/0012-versioned-read-only-adapter-observation.md |
| 2026-08-30 | Current docs | Custom agents are standalone user/project TOML files with required name, description, and developer instructions. | https://developers.openai.com/codex/subagents |
| 2026-08-30 | Current docs | Custom agent files can inherit or override session model, sandbox, MCP, and skill configuration. | https://developers.openai.com/codex/subagents |
| 2026-08-30 | Current docs | MCP servers are user or trusted-project `config.toml` tables using stdio or Streamable HTTP. | https://developers.openai.com/codex/mcp/ |
| 2026-08-30 | Current docs | MCP authentication, tool policy, enablement, required behavior, and timeouts are independent native controls. | https://developers.openai.com/codex/config-reference/ |
