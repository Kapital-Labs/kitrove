# Release acceptance

Kitrove is in Phase 6, before public alpha. Implementation, rehearsal evidence and
supported-release acceptance are separate gates. Passing one does not imply the
others. This record supersedes older pending-signing statements, not accepted ADRs.

## Historical signing checkpoint

Source: `1267b8438276d70fd3f083cfa9e4a8576a31178b`.

- [Main CI](https://github.com/Kapital-Labs/kitrove/actions/runs/35115547142)
  passed on Linux, macOS and Windows, including Rust 1.85 and the dependency audit.
- [Secret scan](https://github.com/Kapital-Labs/kitrove/actions/runs/35115547478)
  passed on the same revision.
- [Product signing rehearsal](https://github.com/Kapital-Labs/kitrove/actions/runs/35118722213)
  passed for the CLI and installer on Apple Silicon, Intel Mac and Windows.
  Signing, Apple notarization, credential cleanup and final archive checks passed.
- The six signed archives and their build manifests were preserved from the three
  evidence artifacts; all adjacent archive checksums matched locally.
- Temporary rehearsal activation was removed. No release was published and
  production activation remains disabled.

The rehearsal used `v0.0.0` and a manual workflow. Its evidence is not an attestation
from the production tag workflow. Do not relax the installer verifier to accept it.
Linux needs no native code signer, but still needs authenticated release artifacts
and native installer acceptance. The release catalog currently covers x86-64 Linux,
not the broader product specification's Linux arm64 ambition.

## Execution order

### 1. Trusted first acquisition

Establish an independently trusted starting verifier before executing a downloaded
installer. The reviewed-source-built installer remains the development route; it
is not a convenient binary bootstrap and cannot authenticate its own first download.

The implementation must reuse ADR-0041's installer-specific authentication and
bounded archive inspection, not add another signature or archive parser. Retain
exact authenticated bytes through private, no-follow, no-overwrite staging. Keep
installer authority distinct from application replacement and rollback authority.
No automatic launch, PATH modification, elevation, package installation or latest
version discovery belongs in this step.

Private authenticated installer-data staging is implemented on Unix and Windows.
[PR #33 validation](https://github.com/Kapital-Labs/kitrove/actions/runs/36036868392)
passed the native Windows suite and an explicitly unelevated retained-payload test;
merged main validation also passed in
[run 36040431645](https://github.com/Kapital-Labs/kitrove/actions/runs/36040431645).
This is data staging only: native-signature-gated executable publication, reopening
and a consumer bootstrap command remain unimplemented.

The Mac retained-payload library now provides bounded native signature inspection
using an independently trusted source-built self helper. It derives the candidate
from authenticated installer bytes, checks retained file identity and bytes around
inspection, and leaves the payload non-executable. The pinned RC2 arm64 fixture
passed the authentic case and rejected changed CMS/code on the existing Mac through
the real helper dispatch. This is not executable publication, downloaded-installer
bootstrap, Windows signature acceptance or clean-machine/offline launch evidence.
The operator-only test is explicitly selected with
`cargo test -p kitrove-installer --test public_installer_payload -- --run-native-acceptance`
and requires `KITROVE_TEST_INSTALLER_ARCHIVE` and `KITROVE_TEST_INSTALLER_BUNDLE` to
point to the pinned RC2 arm64 archive and its selected production attestation bundle.
Ordinary test runs skip this external-artifact acceptance exercise.

Before advertising the binary path, prove:

- independent selection of tag, full source commit, target and expected checksum;
- exact repository IDs, release workflow, source ref and source digest verification;
- rejection of wrong product/target, corrupt archives, invalid or ambiguous bundles,
  redirected paths, occupied destinations and changed bytes without overwriting them;
- native signature verification on Mac and Windows, supplementary to provenance;
- use from a fresh ordinary-user account without a preinstalled Kitrove binary.

The maintainer selected a signed, notarized, stapled DMG on 2026-09-16;
[ADR-0043](adr/0043-stapled-mac-installer-container.md) records the direction.
The `stage-installer-dmg` operator command now prepares the exact private payload
through existing archive validation. It has been exercised with both preserved Mac
installer archives from rehearsal `35118722213`, without executing either binary.
The separate `prepare-installer-dmg` command now implements native image creation,
signing/notarization/stapling and mounted-payload verification. Its local unsigned
native image test passed without executing the payload. Local signed preparation
also passed for both Mac payload targets; the
[native rehearsal record](review/installer-dmg-native-rehearsal.md) lists exact
digests and limits of that evidence. The disabled production workflow now includes
DMG preparation, credential-free native reverification, individual attestations and
the expanded exact checksum/publication set. Hosted Mac-only rehearsal
[`35224395532`](https://github.com/Kapital-Labs/kitrove/actions/runs/35224395532)
passed both architectures at `5d7d0b37fca4c923508a5d8f20600122e7b01044`, including
native image preparation and final evidence verification. Both evidence inventories
and all file digests were verified locally; temporary authorization was removed.
The shared library now authenticates opaque container snapshots using the fixed
production provenance policy. The read-only `verify-installer-container` command
connects that library to retained local input validation. Neither checkpoint mounts
or executes images. Container bundle selection reuses the exact-one-match JSONL
selector through `select-installer-container-bundle`. The reviewed-source operator
command below connects authentication to the shared native verification path:

```sh
cargo xtask verify-downloaded-installer-dmg <image> <image-bundle> <installer-archive> <installer-bundle> <target> <tag> <commit>
```

Both artifacts must pass the fixed production provenance policy before native
verification or read-only mounting. The command compares the exact payload and
detaches without executing or installing it. It does not use signing credentials.
Production-artifact results are recorded below; native verification alone does not
establish clean-machine online/offline execution. The maintainer has no clean Mac
available; the signing host is not a substitute for that evidence.
A notarized archive
of standalone executables does not prove offline first-launch acceptance. A stapled
container design must specify its contents, authentication, quarantine behavior,
extraction/staging and clean-machine online/offline tests. Adding a container also
changes the exact release inventory and requires an ADR and shared-policy tests.
Do not bypass quarantine or disable Gatekeeper to make a test pass.
Use Apple's [notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
and [distribution packaging guidance](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution)
for the container design; stapling support alone is not clean-machine acceptance.

### 2. Prepare lifecycle acceptance without release credentials

Use the existing installer commands and recovery machinery in isolated, private
test destinations, never the operator's real installation or harness state.
Keep the separately trusted installer and prior rollback material available.
Synthetic tests may prove failure handling but must be labeled synthetic; they do
not establish native signing, real provenance or public-download acceptance.

Prepare a compatibility-reviewed pair of distinct candidate versions. Record their
exact source commits and compatibility metadata before building. Do not relabel a
signed archive or invent production attestations for a manual rehearsal.

#### Approved candidate pair

The maintainer approved preparing, signing and publishing `v0.1.0-rc.1` for A and
`v0.1.0-rc.2` for B on 2026-09-23, sequentially after verification. This is not
stable-release approval. RC1 failed before publication; its tag remains unchanged.
RC1.1 also failed before publication, during Windows artifact staging after signing;
its tag remains unchanged. RC1.2 completed all platform jobs but failed shared
source-archive validation before publication. Its tag also remains unchanged.
The replacement A is `v0.1.0-rc.1.3`, including the reviewed source-family fix.
Its workspace version and compatibility catalog declare `0.1.0-rc.1.3` with no
predecessor. A was published by
[run 35941035846](https://github.com/Kapital-Labs/kitrove/actions/runs/35941035846)
from `31b4657a8742756f26aa0596e2c57a4f357c8295`. All 27 public assets were acquired;
the exact inventory/checksums passed and all 17 directly attested files passed
independent, pinned GitHub attestation verification. Temporary signing activation
was removed afterward.

A's bundled installer rejects the production release-environment certificate
identity. [ADR-0044](adr/0044-release-environment-provenance.md) records the correction
merged at `3c469d5b8b86489bb44327db19abf0a651758baf`; its main CI passed in
[run 35955613847](https://github.com/Kapital-Labs/kitrove/actions/runs/35955613847).
The corrected, independently reviewed source verifier authenticated both Mac DMGs
and their installer archives before native signature/staple checks and read-only
exact-payload verification. Neither embedded installer was executed.

Using that corrected source installer, A's authenticated arm64 CLI passed preflight,
first install, installed digest/version checks, retirement into history and read-only
history inspection in a private, empty-state sandbox on the existing arm64 Mac
(macOS 26.6, ordinary user). No actual user installation or configured state was
touched. This is not clean-machine/offline evidence, Intel execution, or evidence
for Windows/Linux installation, application-state preservation or credential canaries.

B was published as `v0.1.0-rc.2` with the verifier correction by
[run 35966127917](https://github.com/Kapital-Labs/kitrove/actions/runs/35966127917)
from `11f2d7b7daa1115e23d95121a6f7c923153b3190`, after exact-head PR and main checks
passed. All four platform builds and global artifact validation passed. The release
is a prerelease, not a stable release; temporary signing activation was removed.
All 27 public assets were downloaded and passed the shared inventory/checksum checks;
all 17 directly attested files passed independently pinned GitHub verification.

Review of changes since A found only provenance verification, tests and documentation before candidate
metadata updates: no application-state or lifecycle format changed. The catalog
therefore declares A rollback-compatible.

Both B Mac images and installer archives passed corrected-source provenance and
native signature/staple/read-only payload verification on the existing arm64 Mac.
No embedded installer was executed. The same independently trusted source installer
then upgraded the isolated, empty-state A installation to B and rolled it back to A.
Both preflights passed without mutation; both transactions committed and were
retained in history. Explicit version checks reported B then A, and rollback restored
A's exact original executable SHA-256. No actual user installation or state was used.

| Observed executable | SHA-256 |
|---|---|
| A, before upgrade and after rollback | `766afbe0279cf6a1f623a8a69bb122cfdcb3206f26a7b7c1acceff749e905e7e` |
| B, after upgrade | `54ac690c5ae5b0bcc480f4925b0f7ef5fe4e9b777a6b9390ca0ead593715bed2` |

This proves the real-artifact happy path on the existing arm64 Mac, using a reviewed
source installer. It does not prove downloaded-installer bootstrap, clean-machine
online/offline launch, Intel execution, Windows/Linux lifecycle behavior, application
data or canary preservation, or real-artifact interruption recovery. Those acceptance
gates remain open; no stable platform support is asserted.

Prepare each version in its own reviewed worktree/PR. Update the
shared workspace version, locked workspace package records and compatibility
catalog together, and review the resulting lock/catalog guard digests. A declares
no rollback predecessor. B explicitly declares `0.1.0-rc.1.3` as compatible only
after review confirms no intervening incompatible state-format change. Do not
change state formats merely to exercise replacement. Both packages inherit the
workspace version; the release workflow requires the tag to match it exactly.

Record each final merged commit in the acceptance evidence before tagging; the
current implementation commit is not a substitute for either future versioned
commit. Require its main checks to pass. Publish A first, verify its complete
inventory and acquisition path, then proceed to B. Do not launch two signing
matrices together or retry successful signing jobs. If A fails authentication or
native validation, stop before B and preserve the evidence.

Prepare one private evidence record per target with these fields left explicitly
pending until observed:

- A/B tag, full source commit, workflow/run ID and artifact/bundle digests;
- independently trusted verifier source/build and exact invocation;
- OS, architecture, ordinary-user context, quarantine and clean-machine conditions;
- fresh destination and selected test state roots, containing synthetic data only;
- first install, A-to-B upgrade, B-to-A rollback and guarded recovery results;
- expected and actual digests/versions, exit status, preserved failure evidence;
- unmanaged-file and credential-canary checks, plus remaining unsupported behavior.

Use the existing commands in [INSTALLER.md](INSTALLER.md), not a second replacement
script. Keep A, B and the independently trusted installer available throughout.
Synthetic interruption tests are supplemental; never claim a real-artifact
interruption result without actually observing one. Windows uses its documented
two-move gap. Mac online/offline first launch remains pending until a clean machine
is available. No clean-machine claim may be inferred from hosted signing or the
new credential-free DMG verifier.

### 3. Approve the release-candidate pair and verify the consumer path

Real production provenance requires the protected tag workflow, which currently
publishes a release. Obtain explicit approval for the candidate versions, production
activation and publication before using it. If a nonpublishing tag build is desired,
review that workflow change first; never silently weaken provenance expectations.
Thus real two-version acceptance follows controlled candidate publication, and must
precede stable support. It cannot be a prerequisite for the first-ever candidate.

For each of Apple Silicon, Intel Mac, x86-64 Linux and x86-64 Windows, retain an
acceptance record covering:

| Scenario | Required evidence |
|---|---|
| Fresh acquisition | Exact archive/bundle pins; independent verifier and native signature results |
| First install | Empty owned destination; successful installed digest/version; unmanaged files unchanged |
| Upgrade A to B | Verified prior kit retained before mutation; compatibility accepted; B digest/version |
| Failed upgrade | Prior restored or explicit recoverable state; both releases and evidence preserved |
| Interrupted upgrade | Fresh-process recovery at durable boundaries; second interruption recoverable |
| Rollback B to A | Fresh authentication and compatibility; A digest/version; application data preserved |
| Refusal | Wrong pins, changed state, occupied names and tampering rejected without unauthorized writes |

Record OS/architecture, ordinary-user context, source/workflow/run IDs, artifact
digests, commands, exit status and observed outcome. Do not put private state or
credentials in public evidence. Windows's documented two-move availability gap is
not atomic exchange. Binary rollback does not roll back application data.

### 4. Release candidate review and bounded alpha

Verify the complete release inventory and provenance, not just the six signed
rehearsal archives. Include Linux, source, installers and checksum controls under
the existing exact inventory policy. Test documented download instructions and
private vulnerability reporting. State supported versions and platform limitations.

Run the product specification's two-machine round trip with synthetic capabilities
and a bounded harness/capability matrix. Record expected unsupported/partial results
as such, verify native preservation, and check no credential canaries are exported.
Close known release-blocking findings before declaring stable production support.

## Cost and approval boundaries

Use local focused tests and canonical validation before one reviewed push per unit.
Keep signing and release jobs manual or tag-only, never ordinary pull-request jobs.
Run a native acceptance matrix only when platform behavior or the release candidate
requires it; reuse recorded evidence only for the exact unchanged artifacts.
Do not rerun expensive signing just for documentation updates.

The maintainer authorized production activation, signing, tags and publication for
this sequential candidate pair. Protected environment gates remain in force. Stable
publication, expanded cloud permissions and purchases are not authorized by that
approval. The completed signing rehearsal monitor is paused.

## Invariant impact

NS-07/NS-09 and INV-06/INV-07/INV-08/INV-12 remain unchanged: local credentials stay
local, executable trust precedes use, writes require ownership and recovery is
explicit. This plan does not change discovery/adoption, portable or native
representation, fidelity, capability receipts, synchronization or conflict behavior.
