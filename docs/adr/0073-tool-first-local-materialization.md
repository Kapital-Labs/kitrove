# ADR-0073: Tool-first local materialization and explicit collection status

- **Status:** Accepted for implementation by maintainer request, 2026-11-17
- **North Star:** NS-01, NS-02, NS-03, NS-04, NS-05, NS-06, NS-07, NS-09, NS-10
- **Related:** ADR-0047, ADR-0072

## Decision

Guided setup chooses destination tools and scope before saved items. Claude, Codex, Pi and OpenCode use the same interaction with existing adapter policies governing actual paths, fidelity, native ownership, trust and version requirements. Ordinary skill installation does not require an executable probe; Pi extensions and gated OpenCode V2 assets still do. No executable is discovered or launched implicitly.

Collection presents same-name copies as a group without picking a winner or merging native variants. An existing name is not evidence of equality: only a validated stored native object compared with the captured exact source identity can support a matching-content observation. Other-tool variants, missing or unreadable evidence remain explicitly unverified. Comparison is advisory and grants no update, trust or ownership authority.

After collection the user can explicitly enter tool installation with newly collected IDs suggested. Installation has a separate preview and confirmation; sync is independent. Read-only inventory browsing and machine-readable commands retain their contracts. No tool, dependency or credential is installed by this flow.

## Conditions

Disposable-home tests cover all four tools, both destination scopes, duplicate and missing evidence, stale plan refusal, unmanaged conflicts and cancellation. Full stable/Rust1.89/source review precedes commit; exact public checks and green latest main precede merge. No installed-copy, real collection or sync changes are authorized by implementation testing. No live-tool loading claim follows from filesystem installation alone.
