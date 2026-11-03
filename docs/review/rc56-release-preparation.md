# RC5.6 quick adoption preview preparation

The maintainer asked to take the approved guided-setup change through release.
Prepare the next incremental preview 0.1.0-rc.5.6 through existing protected gates.
Apple Silicon macOS, x86-64 Linux and Windows only; all old tags/assets immutable.
No APT/RPM/WinGet update, migration, stable support or personal-state mutation.

PR110 supplies the reviewed CLI-only shortcut flow. This preparation changes no
runtime behavior. Version metadata changes exactly27 workspace Cargo.lock versions;
every other lock byte/registry identity/checksum/edge/feature is unchanged. Catalog
schema and all old entries are unchanged, appending only RC5.6 with empty rollback
predecessors. The current-version synthetic diagnostic expectation, changelog,
versioned notes and quick-flow availability copy follow that version. Installation
instructions and live Homebrew remain pinned RC5.5 until the new artifacts verify.

Reviewed lock BLAKE3 87899e74f7dd73cdc9db4be8815cfd8215aa68fb82db59358dcf46832c36d2e0;
compatibility 1367cb64c5e816509ea48cc8de1c0fb031ed2138a974299accb0b508603b5a46.
Only those reviewed fingerprints refresh; original mismatch refusals are retained.
No publication policy, dist configuration, workflow permission, native signing,
provider retry, lifecycle deadline, process ownership or notice-source change.
The closed inventory remains21 files/14 direct attested subjects/six binary archives.

NS-01/02/03/04/05/07/09/10 and INV-03/04/05/07/08/11/12 remain intact: explicit
source identity, preservation and loss reporting; fresh exact adoption authority;
separate Apply/sync/trust; local credentials and receipts. Selection numbers bind
one retained scan, not names across tools. Bulk approval is ordered/sequential, not
atomic, and stops on stale inputs or failed commit. No core/schema/platform/trust
change is added by release metadata; existing ADR0047/0066/0067/0068-0070 apply.

Baseline xtask suite132 passed/one ignored. Initial --lib selector refused because
xtask is a binary; corrected explicit --bin suite ran, not a zero-test claim.
Metadata comparison used existing Python3.14 after default Python lacked tomllib;
no dependency install or lock resolution. Manual full-diff/caller review, not an
independent-agent or exhaustive repository assurance. Require full stable and
Rust1.88 cargo ci, fresh audit/notices/licenses/governance/secret scans, pinned
dist0.32 plan, unsigned ARM bundle/version/help/JSON smokes before commit. Require
fresh exact RequiredCI and full platform tests, green prior and exact merged main
before one new tag/protected signing attempt. No blind rerun of unexplained
parallel version-probe failures and no assertion/timeout weakening.

Temporary signing activation must be removed on every terminal outcome. Public
acceptance requires all21 assets/14 exact-source attestations/six notice payloads
and native ARM image verification. Source tests and unsigned smokes do not prove
production artifact, clean-Mac/offline-first-launch/live-harness/Intel execution.
