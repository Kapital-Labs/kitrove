# ADR-0032: Portable MCP v1 is remote HTTPS with local authentication bindings

- **Status:** Accepted for Phase 3 implementation
- **Date:** 2026-08-30
- **North Star:** NS-01, NS-02, NS-03, NS-04, NS-05, NS-07, NS-09, NS-10

## Context

Claude Code, Codex, and OpenCode can all configure MCP servers, but their native documents, scopes,
authentication, enablement, tool policy, and local-process fields differ. A local stdio declaration
starts a process. A remote declaration causes a future harness session to connect to a network
service and may grant that service's tools to an agent. OAuth credentials and approval decisions are
machine-local authority. Pi does not document a built-in MCP registry.

Treating complete native MCP entries as portable would either copy secrets and local authority or
erase execution-affecting fields. Treating an MCP entry as inert data would understate the authority
it gains when the target harness next loads its configuration.

## Decision

Kitrove represents the first portable MCP component as `AssetKind::McpServer` in a versioned
`kitrove.mcp-server.v1` envelope. Version 1 contains:

- a conservative cross-harness server name;
- one absolute Streamable HTTP endpoint using `https`, with a DNS host and no user information,
  query, fragment, or embedded credential material; and
- an optional bearer-token `BindingName` whose machine-local resolver must be an environment
  variable.

The portable object never stores a token, static authorization header, OAuth credential, client
secret, cookie, or resolved binding value. Applying an authenticated entry writes only the target
harness's environment-variable reference. Missing or non-environment binding authority blocks the
plan. OAuth discovery and stored login state remain target-local behavior and must be reported as
fidelity evidence; v1 does not promise that bearer authentication is the target's exclusive fallback.

MCP assets are `AgentActive`. Their exact digest-confirmed apply may author an enabled remote entry,
but Kitrove itself never starts a harness, connects to the endpoint, performs OAuth, enumerates tools,
or invokes a tool during scan, adoption, planning, apply, or recovery. The plan reports that the
target harness can connect on a later load.

Native stdio, SSE, plaintext HTTP, localhost/private-network exceptions, arbitrary headers, OAuth
configuration, tool allow/deny and approval policy, timeouts, required/startup behavior, project
approval state, plugin/managed sources, and target-specific display or code-mode fields remain exact
native evidence and block the v1 portable projection. A future stdio format must use exact executable
trust and a machine-local command binding; it cannot reinterpret v1.

MCP entries live inside shared JSON, JSONC, or TOML configuration documents. Receipts therefore own
one exact logical server entry, not the whole file. Mutation must parse the native document with a
bounded, format-aware editor, preserve unrelated keys, reject duplicate or ambiguous keys, stage one
whole-document replacement atomically, and bind the receipt to both the logical entry and the
resulting document identity. Removal deletes only an unchanged receipt-backed entry and never the
surrounding document.

Claude, Codex, and OpenCode user and project targets are eligible only where a compiled adapter policy
defines the exact native document and entry path. Unknown harness versions fail closed when document
shape or precedence differs. Pi is observable only as unsupported evidence until an official built-in
registry exists.

## Consequences

- A credential-free remote MCP endpoint can move across the three built-in target harnesses.
- Bearer authentication remains portable as a symbolic requirement while its environment variable
  name and value remain machine-local.
- Applying a declaration is explicitly agent-active and digest-confirmed; read-only operations have
  no network or process side effects.
- Local stdio servers and richer native policy are preserved without silently gaining or losing
  authority.
- Structured shared-document mutation becomes a reusable transaction primitive, but only after its
  ownership and preservation invariants are proven.

## Evidence

- Claude Code MCP: https://code.claude.com/docs/en/mcp
- Codex MCP: https://developers.openai.com/codex/mcp/
- Codex configuration reference: https://developers.openai.com/codex/config-reference/
- OpenCode V2 MCP servers: https://opencode.ai/v2/docs/mcp-servers/
- OpenCode V2 configuration: https://opencode.ai/v2/docs/config/
- Pi settings: https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/settings.md
