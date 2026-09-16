# Release acceptance

Kitrove is in Phase 6, before public alpha. Implementation, rehearsal evidence and
supported-release acceptance are separate gates. Passing one does not imply the
others. This record supersedes older pending-signing statements, not accepted ADRs.

## Accepted checkpoint

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

Before advertising the binary path, prove:

- independent selection of tag, full source commit, target and expected checksum;
- exact repository IDs, release workflow, source ref and source digest verification;
- rejection of wrong product/target, corrupt archives, invalid or ambiguous bundles,
  redirected paths, occupied destinations and changed bytes without overwriting them;
- native signature verification on Mac and Windows, supplementary to provenance;
- use from a fresh ordinary-user account without a preinstalled Kitrove binary.

The maintainer selected a signed, notarized, stapled DMG on 2026-09-16;
[ADR-0043](adr/0043-stapled-mac-installer-container.md) records the direction.
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

Production activation, tags, publication, expanded cloud permissions and purchases
remain separate approval gates. The completed signing monitor is paused.

## Invariant impact

NS-07/NS-09 and INV-06/INV-07/INV-08/INV-12 remain unchanged: local credentials stay
local, executable trust precedes use, writes require ownership and recovery is
explicit. This plan does not change discovery/adoption, portable or native
representation, fidelity, capability receipts, synchronization or conflict behavior.
