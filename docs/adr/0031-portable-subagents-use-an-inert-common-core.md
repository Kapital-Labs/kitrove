# ADR-0031: Portable subagents use an inert common core

- **Status:** Accepted for Phase 3 implementation
- **Date:** 2026-08-30
- **North Star:** NS-01, NS-02, NS-03, NS-04, NS-05, NS-07, NS-09, NS-10

## Context

Claude Code, Codex, and OpenCode each support reusable custom agents, but their native definitions
also carry model selection, tool and permission policy, MCP access, hooks, skills, memory, isolation,
and execution-mode controls. Those fields can change authority or execution and do not share one
stable cross-harness meaning. Pi exposes subagents only through an optional example extension that
spawns another Pi process; its agent directory is not a built-in capability contract.

All three built-in registries can represent a narrower authored component: a stable name, a human
description, and system instructions for a subagent. Claude stores that component as Markdown with
YAML frontmatter, OpenCode stores it as Markdown with YAML frontmatter and an explicit `subagent`
mode, and Codex stores it as TOML. Treating the complete native files as interchangeable would erase
privilege and runtime differences. Treating the common instructions as standing instructions or a
skill would erase the user's chosen capability kind.

## Decision

Kitrove represents the common component as `AssetKind::Agent` in a versioned portable envelope.
Version 1 contains only:

- a lowercase, single-segment name using letters and single hyphen separators;
- a bounded non-empty description; and
- bounded UTF-8 system instructions normalized to one final line feed.

Version 1 is subagent-only. Claude renders `name` and `description` frontmatter plus the instruction
body. OpenCode renders `description`, `mode: subagent`, and the instruction body, using the file name
as native identity. Codex renders `name`, `description`, and `developer_instructions` in canonical
TOML. User and project scopes use each harness's documented standard directories.

Adoption accepts only native definitions whose execution-affecting optional fields are absent and
whose exact instructions pass the existing credential and content-risk checks. Model, reasoning or
effort, tools, permissions, skills, hooks, memory, background behavior, isolation, inline or named
MCP servers, display metadata, primary/all mode, and harness-specific request configuration remain
native evidence and block the v1 portable projection. Kitrove does not infer equivalent privileges
from similarly named fields.

The portable component is `AgentActive`. Kitrove never invokes an agent, starts a model, loads a
skill, connects an MCP server, or executes a hook while scanning, adopting, planning, or applying.
Materialization uses whole-file receipts and the existing atomic transaction and recovery contracts.
Pi remains unsupported until a built-in or explicitly trusted executable-extension contract can
authorize its optional subagent implementation.

## Consequences

- Authored subagent instructions can round-trip across Claude, OpenCode, and Codex without carrying
  target-specific privilege configuration.
- Native agents with model, permission, tool, MCP, hook, memory, or isolation settings remain visible
  but cannot be silently weakened or widened.
- Primary agents and agent teams are not reinterpreted as subagents.
- Pi agent files are not written into a directory that has no built-in runtime meaning.
- A future portable privilege or orchestration schema requires a new format version and explicit
  semantic fixtures; it cannot reinterpret v1.

## Evidence

- Claude Code custom subagents: https://code.claude.com/docs/en/sub-agents
- Codex custom agents: https://developers.openai.com/codex/subagents
- OpenCode agents: https://opencode.ai/docs/agents/
- Pi optional subagent extension example:
  https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent/examples/extensions/subagent
