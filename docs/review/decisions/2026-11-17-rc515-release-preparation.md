# RC5.15 preparation review

This preview carries merged PR140/141 scan-to-collection and tool-first UX across
Claude Code, Codex, Pi and OpenCode. Preparation changes release metadata and
current documentation; no application, signing, workflow or authority logic.

Cargo.lock changes only 27 workspace versions. Registry versions, checksums,
edges/features and all other fields remain identical. Previous compatibility
entries are unchanged; RC5.15 appends an empty rollback-predecessor list. Exact
reviewed lock/catalog fingerprints change accordingly. All three notice materials
and the release policy, workflow, dist configuration and signing helper stay
byte-identical. No migration, stable, Intel or package-channel support is added.

Fresh normal cargo audit reports zero known vulnerabilities and one existing
informational unmaintained chrono0.4.45/RUSTSEC-2026-0543 warning through the
Windows SSH graph. No ignore/deny setting is changed and no dependency is
silently upgraded. The release operator must bind that reviewed informational
record and refuse any additional warning or vulnerability, while normal public
audit gates run unchanged. This is not a security-clean or exhaustive review claim.

The separately approved metadata-only renewal is merged as PR142 at
880c180ac996435edbf91cb07a8e33834ff2a56c, with unchanged RC4.2 package/key/index
bytes and a reviewed seven-day timestamp/signature window. Its live signatures,
freshness and native APT/DNF refreshes remain required before this version commit
or publication. No expiry bypass or workflow-path workaround is used.
The metadata-only renewal keeps the existing RC5.14 pages unchanged. Matching
RC5.15 website publication follows the standing request for latest-version docs,
only after independent release/Homebrew verification and exact green main.
Homebrew promotion waits for independently verified RC5.15 public artifacts.
Installed executable, actual collections/state and sync remain untouched.

Full stable/Rust1.89 canonical checks, website tests, complete manual source review,
Gitleaks/fresh audit, pinned unsigned plan/package smokes and exact public PR/main
gates precede the one protected publication attempt. Green source and unsigned
smokes do not establish production artifact or clean-machine acceptance.
