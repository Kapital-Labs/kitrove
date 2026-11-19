# Grok Bot Read-Only Pilot Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Keep execution inline; no new agents are needed.

**Goal:** Implement a local, synthetic-data MCP command server that lists and inspects authored packs and previews ordinary skills through the existing CLI.

**Architecture:** A small standard-library Python server owns newline-framed JSON-RPC, strict result projection and a bounded POSIX child lifetime. Operator configuration fixes a private disposable root and verified CLI hash. The model receives three read-only tools and cannot select paths, launch commands, grant trust or request writes.

**Tech Stack:** Python 3.11+, POSIX `waitid(..., WNOWAIT)`, selectors, existing RC5.18 CLI; no new dependency, registry edge or application command.

**Spec:** `docs/integrations/grokbot/TOOL-CONTRACT.md`, ADR-0077.

## Global Constraints

- No installed-copy, personal collection, sync, provider connection or cloud transfer.
- No new release/version/tag/signing/activation, account, credential or permission changes.
- Only synthetic data in a private operator-owned root; the server is not an OS sandbox against its owner or another process with equivalent filesystem access.
- POSIX pilot only. Windows refuses before launch until a reviewed Job Object boundary exists.
- Three tools: `list_packs`, `inspect_pack`, `preview_pack`; ordinary skills and authored packs only.
- Fixed limits: 16 KiB input frame, 256 KiB combined child output, 10-second child runtime, bounded terminal group cleanup, 128 requests per session.
- Keep CLI source/error schemas closed. Return IDs, counts, target, dispositions and recognized refusal codes; never forward bodies, private paths, arbitrary stderr or grants.
- Full stable/Rust1.89 and complete review precede commits. Plan task boundaries do not authorize intermediate unchecked commits.

---

### Task 1: Closed schemas and privacy projection

**Files:** Create `scripts/grokbot_codec.py`, `scripts/grokbot_projection.py`; test `scripts/test_grokbot_readonly.py`.

**Interfaces:** `PilotError(code: str, *, cli_code: str | None = None, fatal: bool = False)`; `decode(bytes) -> dict`; `arguments(name: str, values: dict) -> list[str]`; `project(name: str, values: dict, response: dict) -> dict`.

- [ ] Write tests that reject duplicate keys, nonfinite JSON, unknown arguments, path-like IDs and write-tool names.
- [ ] Run `python3 -m unittest discover -s scripts -p test_grokbot_readonly.py`; require a genuine failure before implementation.
- [ ] Implement exact argument arrays for pack list/inspect and `plan --pack ... --target ... --scope user`, with no shell or model-controlled environment.
- [ ] Project pack/member counts and planned-action counts. Reject unknown schemas, targets, phases, dispositions, non-skill components, mismatched selected packs and unrecognized error envelopes.
- [ ] Test that injected descriptions, private destination paths, raw errors and unknown fields never enter a successful MCP result.

### Task 2: Configured, bounded CLI lifetime

**Files:** Create `scripts/grokbot_process.py`; test `scripts/test_grokbot_process.py`.

**Interfaces:** `PilotConfig.load(path: str) -> PilotConfig`; `run_cli(config, arguments: list[str], cancelled: Callable[[], bool]) -> tuple[int, bytes, bytes]`.

- [ ] Test refused configuration modes, symlinks, missing fixture markers, non-POSIX capability and changed executable hashes before any command launch.
- [ ] Require a private root with fixed `bin/kitrove`, `collection`, `home`, `state` and `.git` directories. Validate operator ownership, regular files and no symlinks; pin executable identity/hash before and after each operation.
- [ ] Launch with closed stdin, a fixed minimal environment, a new owned session and bounded nonblocking pipe reads.
- [ ] Keep the direct child unreaped using `waitid` with `WNOWAIT` until all group signals have completed. Never signal a numeric group after reaping its leader. Verify disappearance after reaping; uncertainty is fatal.
- [ ] Prove timeout, output flood, descendants holding pipes, denied cleanup and cancellation stop the whole trusted group. Preserve only closed error codes.

### Task 3: MCP transport and lifecycle

**Files:** Create `scripts/grokbot_readonly.py`; extend `scripts/test_grokbot_readonly.py`.

**Interfaces:** `Session.dispatch(message: dict) -> dict | None`; `serve(config, input_fd: int, output_fd: int) -> int`. The runner remains injectable in unit tests only, never via protocol/configuration input.

- [ ] Test initialize/initialized ordering, protocol negotiation, ping, three-tool discovery and unknown-method/unknown-field refusal.
- [ ] Implement bounded UTF-8 newline JSON-RPC frames. Do not emit nonprotocol stdout or raw exception text. Keep frame assembly and output delivery deadlines bounded.
- [ ] Poll the input during a CLI operation: EOF or cancellation of its active request stops the owned group; queue only a bounded number of other frames.
- [ ] Test duplicate request IDs, oversized/partial frames, input injection, request cancellation and shutdown without lingering owned children.

### Task 4: Real-artifact proof and operator guide

**Files:** Update `docs/integrations/grokbot/README.md`, `TOOL-CONTRACT.md`; create `OPERATOR.md`; record ADR-0077 and threat-model boundary.

- [ ] Seed a fresh disposable fixture using independently verified signed RC5.18 bytes and the public inert sample. Do not repurpose the prior fixture or personal state.
- [ ] Drive initialize, discovery, inspection and all four previews through the actual stdio server. Verify matching repeated plans and source/collection/state/destination snapshots before and after.
- [ ] Demonstrate refused writes, malformed frames and operational errors with closed results and no provider action.
- [ ] Document exact operator command, schema, platform and transport limits. Command connectors run on the provider's computer; local filesystem access or transfer remains a separate decision.
- [ ] Complete full diff review, focused tests, full stable/MSRV, staged/commit secret scans and exact public PR checks. Keep the change stacked on PR150 and unmerged for review; no release or live connector installation.
