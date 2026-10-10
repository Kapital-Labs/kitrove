# Homebrew prerelease package staging

This is the reviewed source for a proposed official tap, **not a published tap**.
See [ADR-0046](../../docs/adr/0046-homebrew-is-a-separate-distribution-authority.md).
Do not add an install command to the main README or release page yet.

Local style/audit, full CI/MSRV and isolated warm-Mac installation, conflict
refusal, authenticated version/help and removal passed. See the scoped
[acceptance record](../../docs/review/homebrew-rc-package.md). These checks do not
publish the tap or establish clean-machine/offline acceptance.

The initial cask is Apple Silicon macOS only. It installs the CLI directly, without
Rust, a separate Kitrove installer, or automatic initialization. Homebrew owns the
executable; your Kitrove state and harness files remain outside package ownership.
The package intentionally uses an explicit `-rc` name rather than a stable name.

## Pinned candidate

| Field | Value |
|---|---|
| Public repository | `Kapital-Labs/kitrove` |
| Tag | `v0.1.0-rc.3` |
| Source commit | `4212327d45097c1826e64a0a8f6e556c40bffc7f` |
| Release workflow run | `37640833426` |
| Archive | `kitrove-cli-aarch64-apple-darwin.tar.xz` |
| Archive SHA-256 | `49229e4d6c0eee3f7f711c42b50274a24a29dfa90768b1cedbed21e16b44b28e` |
| Executable SHA-256 | `0dad5b176d6502c207ce317f636cfe38afd494f50e9707696a86803981bcc034` |

These pins record the RC3 verification checkpoint, not permission to execute
unverified current files. The cask checksum binds the archive; maintainers must
authenticate release provenance and native signatures before every publication.

## Review and promotion checklist

1. Reverify exact public tag/commit and successful protected release run. Use the
   existing independently trusted release verifier and exact production policy
   in `release/release-policy.json`. Verify the archive's retained bytes, full
   inventory/manifest, executable digest and native signing identity. Preserve
   bundles and logs. Do not substitute a downloaded self-verifier.
2. Run the package regression tests through `cargo ci`, plus Homebrew parsing,
   style and audit on the intended Mac. Static checks alone do not install it.
3. Exercise native installation/removal and occupied-link refusal in a disposable
   Homebrew environment with isolated Kitrove state and harness canaries. Keep
   quarantine enabled and compare exact executable bytes/signature before running
   version/help. Never use `--force`, `--no-quarantine` or Gatekeeper bypasses.
4. Record warm versus clean-machine evidence honestly. A warm Mac cannot close
   clean-machine offline first launch. Test future upgrades separately; do not
   claim the custom installer's state preflight or rollback guarantees for Brew.
5. Obtain approval for the new distribution contract and creation/publication of
   `Kapital-Labs/homebrew-tap`. Configure protected review before the first package
   update. Copy only reviewed `Casks/kitrove-rc.rb` to the tap with its evidence
   reference, inspect the exact resulting diff, and verify the public tap revision.
6. Only then publish the actual fully qualified command and supported scope. The
   proposed command is `brew install --cask kapital-labs/tap/kitrove-rc`; it is not
   available from this staging directory. Uninstall must preserve user data.

No release assets are rebuilt, re-signed, replaced or republished by this work.
No new hosted signing job or automatic tap-publishing workflow is introduced.

## Local checks

```sh
python3 -m unittest discover -s scripts -p test_homebrew_package.py
HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 brew style release/homebrew/Casks/kitrove-rc.rb
```

The test freezes this deliberately small cask rather than evaluating arbitrary
Ruby as a security policy. Changing a release pin or adding any executable hook
requires a corresponding reviewed test change. Homebrew itself remains the DSL
parser. Check the [Cask cookbook](https://docs.brew.sh/Cask-Cookbook) and
[tap guide](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap) for the package
manager's behavior; third-party tap trust is not GitHub release attestation.
