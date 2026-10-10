# Homebrew RC package preparation

Date: 2026-10-09. Source base: `4212327d45097c1826e64a0a8f6e556c40bffc7f`.

## Scope

Local Apple Silicon Mac cask candidate, not a published tap or supported bootstrap
announcement. [ADR-0046](../adr/0046-homebrew-is-a-separate-distribution-authority.md)
remains proposed. The package links the unchanged signed RC3 CLI archive, not the
separate installer. No production Rust, release workflow or released artifact
changes are included.

## Observed checks

- Two static regression checks pass: exact reviewed declarative package text and
  closed package-directory inventory. They run in the existing Python discovery
  step of `cargo ci`, not a new hosted workflow.
- Homebrew 6.0.22 on the existing Apple Silicon Mac parses the candidate as version
  `0.1.0-rc.3`, the exact public release URL and archive checksum, one `binary`
  artifact, arm64/Mac dependencies, skipped livecheck and no installation hooks.
- `brew style` reports one file inspected with no offenses. `brew audit --cask
  --strict` exits successfully through a temporary local-only tap pointing to
  the owned worktree. No public tap was created. The temporary tap link was
  removed afterward; package sources remain in the worktree.
- Fresh GitHub attestation verification passes against the retained archive and
  bundle, pinned to `Kapital-Labs/kitrove`, the production release workflow,
  `refs/tags/v0.1.0-rc.3`, exact source and signer commit, with self-hosted runners
  denied. Current archive SHA-256 matches the cask. This is provenance verification,
  not a new native installation or first-execution test.

Durable maintainer evidence: `homebrew-rc-parsed-cask-20261009.json` and
`homebrew-rc-provenance-20261009.json`. Full local CI and MSRV results are recorded
separately in `homebrew-rc-local-ci-20261009.log` and
`homebrew-rc-msrv-20261009.log`. Both completed successfully before the code commit.

## Review findings and limits

The cask has no shell hooks, probes, profile edits, installer invocation or user-data
removal rules. Static tests freeze that surface rather than pretending to sandbox
arbitrary Ruby. Cask changes still require review, native tests and a trusted tap.
Homebrew's generic autobump metadata is not an update policy for our tap; no
autobump workflow is enabled, and livecheck is explicitly skipped.

Modern Homebrew rejects direct-path cask audit/info, so the local tap is necessary
for those checks. Style checking installed Homebrew's development Ruby dependencies;
its automatically enabled developer mode was turned off afterward. No Kitrove
package was installed, linked or executed, and operator state was not selected.

## Isolated native acceptance

On the existing arm64 Mac, macOS 26.6/build 25G72, a separate Homebrew worktree at
`08e85c4e42f5d8f1ea17c36cb59cf61c2ccb26c3` provided a private, non-default prefix.
No Kitrove binary was installed in the operator's `/opt/homebrew` prefix. The tap
was local-only and pointed to the reviewed package source. Auto-update/analytics
were disabled; archive cache and logs used the private evidence directory.

1. An occupied `bin/kitrove` regular-file canary caused normal cask installation
   to exit 1 without overwriting it. Its exact authored contents were unchanged.
   The test then moved that owned canary to a retained evidence leaf.
2. Normal installation into the now-empty name succeeded. The downloaded archive
   matched the independently authenticated SHA-256. The linked executable matched
   `0dad5b176d6502c207ce317f636cfe38afd494f50e9707696a86803981bcc034`.
3. The independently source-built installer freshly authenticated the archive
   and selected bundle under the shared production policy. Native strict signature
   verification with the reviewed Apple Developer ID/team requirement passed.
   Signature display showed hardened runtime and a secure timestamp.
4. `spctl --assess --type execute` exited 3 because the valid code is not an app.
   This failed diagnostic is preserved, not reported as a pass. Apple's
   [guidance for other code](https://developer.apple.com/forums/thread/130560)
   specifies `codesign -vvvv -R=notarized --check-notarization`; that check passed.
   No security setting or quarantine attribute was removed to make it pass.
5. With quarantine still present, explicit `--version` and `--help` both exited 0.
   Version output was `kitrove 0.1.0-rc.3`, and the executable digest stayed exact.
   This executed the independently authenticated downloaded CLI, not a downloaded
   installer. No discovery, initialization or state-mutating command ran.
6. Normal cask uninstall exited 0, removed its binary link and cask directory,
   and preserved all three fixture canaries: conflict, synthetic state and harness.
   The now-clean disposable Homebrew worktree was removed without force. Logs,
   downloaded archive, verification bundle and canaries remain outside that tree.

Evidence directory: `homebrew-native-SZzhVS`. It retains `conflict-install.log`,
`install.log`, `codesign-verify.log`, `gatekeeper.log`, `notarization-check.log`,
`verified-application.bundle.json`, quarantine before/after records, `version.log`,
`help.log`, installed digest/metadata, `uninstall.log` and final canary hashes.
Source-built verifier SHA-256:
`3e263e134905b6b02083057fd39da1daefba8b686995fb4a45c19be75dc96777`.

This is warm-host, non-default-prefix package acceptance with small synthetic
canaries. It does not prove a clean-machine first launch, a public tap checkout,
standard-prefix migration, existing Kitrove state compatibility or Brew upgrade.

Outstanding: approved tap repository creation/protection/publication and actual
public-command verification on the intended ordinary-user Homebrew installation.
Future upgrade acceptance is separate from first-install acceptance. Clean-Mac
online/offline first launch, Intel Mac, Windows and two-machine product acceptance
remain open. A warm-Mac cask test cannot substitute for those gates.
