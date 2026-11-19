# Release and launch claims ledger

Reviewed November 18, 2026 (America/Chicago). Baseline is the immutable
[RC5.18 release](https://github.com/Kapital-Labs/kitrove/releases/tag/v0.1.0-rc.5.18)
at source `ab95ab79d5e3271320ca1e5563f4ae7b0a6baac8`. Recheck before publication.

| Claim | Evidence | Qualification to retain |
| --- | --- | --- |
| Public RC5.18 downloads exist | [Protected release run 44422645113](https://github.com/Kapital-Labs/kitrove/actions/runs/44422645113), release inventory | Evaluation preview; not stable support. |
| Homebrew selects RC5.18 | [Tap PR19](https://github.com/Kapital-Labs/homebrew-tap/pull/19), exact merged tap `94aaa756d14d9f3224f399ffbf8b516f65465619` | Apple Silicon cask; Homebrew manages the executable, not Kitrove state. |
| The matching website is deployed | [Pages run 44426490934](https://github.com/Kapital-Labs/kitrove/actions/runs/44426490934), maintainer live byte verification | The release page and docs remain the current download authority. |
| Preview supports Apple Silicon macOS, x86-64 Linux and x86-64 Windows archives | [Versioned release policy](https://github.com/Kapital-Labs/kitrove/blob/v0.1.0-rc.5.18/release/release-policy.json) | Intel Mac and Linux ARM archive support are not current release claims. |
| You can collect and plan skills for Claude Code, Codex, Pi and OpenCode | [Versioned tool guide](https://github.com/Kapital-Labs/kitrove/blob/v0.1.0-rc.5.18/docs/ADD-TO-TOOLS.md) | Compatibility depends on content, scope and tool/version evidence. File placement does not prove tool execution. |
| Kitrove retains native content and reports fidelity | [North Star](https://github.com/Kapital-Labs/kitrove/blob/v0.1.0-rc.5.18/NORTH_STAR.md), versioned tool guide | Partial or unsupported content can block a selected plan. Do not promise that every plugin or native directive converts. |
| Script-containing skills have a local review boundary | Versioned tool guide and [RC5.18 notes](https://github.com/Kapital-Labs/kitrove/blob/v0.1.0-rc.5.18/release/notes/v0.1.0-rc.5.18.md) | Eligible text helpers are inert data until separate local approval for placement. Kitrove does not run helpers or install runtimes. |
| The unchanged managed-file failure after collection changes is repaired | [PR148](https://github.com/Kapital-Labs/kitrove/pull/148), [four-tool regression](https://github.com/Kapital-Labs/kitrove/blob/v0.1.0-rc.5.18/crates/kitrove-cli/src/setup_application_tests.rs) | Maintainer also checked actual signed RC5.18 bytes/mtime in synthetic destinations; this is not a claim that anyone's existing collection was migrated or repaired. |
| Agent-facing CLI previews and exact confirmations exist | [Versioned agent workflow](https://github.com/Kapital-Labs/kitrove/blob/v0.1.0-rc.5.18/docs/AGENT-WORKFLOW.md) | Digest freshness is not human authorization. Recovery, trust and unknown errors still require review. |
| Cross-machine continuity is a product workflow | [Agent acceptance and limitations](https://github.com/Kapital-Labs/kitrove/blob/v0.1.0-rc.5.18/docs/AGENT-WORKFLOW.md), [roadmap](https://github.com/Kapital-Labs/kitrove/blob/v0.1.0-rc.5.18/docs/ROADMAP.md) | Existing bounded Mac/Linux synthetic filesystem acceptance is not current-artifact acceptance of every transport, capability or concurrent user. |

Maintainer verification of RC5.18 covered 21 public files, 14 exact-source
attestations, notice bytes in six archives and the native ARM installer image.
The protected run passed once with normal configured reviewer approvals; temporary
signing activation was removed. This is release provenance and bounded acceptance,
not an independent third-party security audit or a promise that every workflow works.

## Claims to withhold

- Stable, seamless migration, rollback-safe collection upgrades or an RC4.2 upgrade
  path; no rollback-compatible predecessor is declared for RC5.18.
- Clean-Mac offline first launch, every live harness or helper runtime, every
  capability type, or complete production-artifact two-machine acceptance.
- Available S3/GCS/Azure sync, a hosted Kitrove account, automatic secret migration,
  a marketplace or arbitrary public Git repository installation.
- Shipped Grok Bot integration, a published Kitrove Bot template, or a verified
  native Grok skill import/export adapter.
- Unique lockfiles, unique cross-tool support, unique rollback, superiority to a
  named competitor, or claims that a competing tool has no feature because its
  README did not mention one.

The architecture specification contains design examples, including `add`,
`compatibility`, `upgrade` and `rollback` forms. That specification is not the
released command reference. Use the versioned agent/setup/installer docs and the
actual CLI for examples. APT/RPM channels remain the separate RC4.2 distribution;
do not advertise their commands as installing RC5.18.

No legal-compliance, exhaustive security or vulnerability-free claim follows from
the license inventory or audit. The existing chrono maintenance warning remains
visible; the release checks found zero known vulnerabilities at their checkpoint.
