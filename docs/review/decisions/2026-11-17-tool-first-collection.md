# Tool-first collection review

Status: implementation and manual source review complete; full validation is a
condition of commit, with exact results recorded in the PR and external evidence.

## Product

Maintainer authorized remaining collection improvements and a tool-first local
installation flow for all four supported tools, starting with OpenCode.
No tool installer, credential provider, automatic sync or cloud configuration
was added. Installed copy, real collection and sync remain untouched.

## Architecture

Setup modules only select, compare and present. Existing core planning, object
loading, adapter paths, receipts, trust, transaction/recovery and refreshed exact
confirmation govern actual changes. A shared kind/target rule is used by both
materialization and the UI for required version probes. Pack leaves use the
existing bounded resolver. Collected IDs are actual successful commits, not
inferred by comparing mutable manifests. Scan hands off to a separately approved
installation phase; ordinary browsing/verbose/JSON remain read-only.

## Security and error handling

No implicit executable discovery/launch, account/config probing, tool installation,
trust grant or ownership acquisition. Missing comparison evidence is explicitly
unverified. A source grouping never selects or merges a native source silently.
Descriptions use verified portable objects and escaped bounded display text;
full objects are still checked by planning. Discovery warnings grant no authority
and cannot prove a runtime load. Unmanaged conflicts stop the selection; stale
plan/commit failures propagate. Full fidelity reasons and MCP connection effects
remain visible before confirmation; full canonical plan details are available.
Descriptions/fidelity remain bound to the selected manifest snapshot; a changed
collection refuses before confirmation, and the existing final batch refresh
refuses changes after confirmation. Structured preview preserves removals, native
entry names and MCP connection effects even with pagination. The actual
input/terminal boundary retains pending-key discard and cancellation.

## Four-tool evidence

Primary docs reviewed November17: Claude personal/project `.claude/skills`,
Codex shared `.agents/skills`, Pi native `.pi/agent/skills` / `.pi/skills` plus
shared compatibility, OpenCode `.config/opencode/skills` / `.opencode/skills`
plus Claude/shared compatibility. See ADD-TO-TOOLS.md for links and limits.
Upstream policies/settings can alter runtime loading. No live-tool acceptance
or exhaustive adapter revalidation claim is made by filesystem journey tests.

## Evidence and limits

Red-before-green and all corrected fixture failures retained in external
`tool-first-ux-20261117-2vzcmkfn` evidence. Full stable/Rust1.89/source review,
notices/licenses/audit/Gitleaks/public exact checks remain required before
commit/merge as applicable. This is manual review, not independent-agent review.
Stacked on unmerged PR140; no merge or release authority is inferred from it.
No schema, persisted receipt, dependency, lock, version, catalog, workflow,
signing or channel changes. Other readiness monitoring stays paused.
