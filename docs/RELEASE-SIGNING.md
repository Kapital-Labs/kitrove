# Platform release signing

Status: local Apple Silicon notarization and scoped native Windows signing passed;
production hosted activation remains gated.
See ADR-0042. No signing service runs during ordinary CI.

## Ordering and boundaries

Use pinned cargo-dist 0.32.0 to build local artifacts and retain its actual JSON
build manifest. For each application and installer archive, run:

```text
cargo xtask prepare-platform-release <archive> <target> <tag> release/application-compatibility.json <dist-build-manifest>
cargo xtask verify-application-release-bundle <archive> <target> <tag> <dist-build-manifest>
```

Preparation validates the archive, checksum and cargo-dist authority before copying
only the executable to an isolated temporary directory. It signs that copy with
native tools and verifies the result. macOS additionally requires Apple's notary
service to accept a ZIP of those signed bytes. The existing bounded archive machinery
then binds the manifest to the signed executable digest, rebuilds the archive,
updates its checksum and cargo-dist authority, and reverifies the handoff.
Signing/notarization failure leaves the original archive untouched. A later output
write failure can leave inconsistent build outputs: discard that build and rebuild.
This is build preparation, not an installer recovery transaction.

Only afterward generate global installers, checksums and attestations. Never sign
executable bytes after preparing the final archive. PowerShell hardening must precede
script signing; PowerShell script signing is not implemented in this slice. Those
scripts remain convenience controls, not the supported authenticated bootstrap.

`prepare-application-release` is the explicitly **unsigned development** path and
must not be substituted into the release workflow. Linux requires no native signer
but still requires checksums and GitHub provenance. Neither command executes Kitrove
or installs it. Signing timestamps preclude identical signed bytes across signing runs.

## macOS operator setup

The reviewed identity is `Developer ID Application: Kapital Labs LLC (98RZ36ES7A)`.
Keep its private key in Keychain; no export is needed locally. Use notarytool's secure
interactive prompt to save credentials. Never put passwords in source or arguments.

```sh
export KITROVE_NOTARY_PROFILE=kitrove-notary
```

For a separately provisioned temporary hosted Keychain, also set
`KITROVE_SIGNING_KEYCHAIN` to its absolute regular file path. The same path is
passed explicitly to codesign and notarytool. Omit this setting for the existing
local setup. Hosted provisioning keeps the default unchanged, temporarily appends
the new store to the search list, and restores that list during cleanup. Codesign
requires this membership even when an explicit Keychain is selected.
Apple's codesign still uses the system search list for certificate-chain building,
not for choosing a different signing identity. The runner must provide the normal
Apple certificate chain separately; this option does not install chain certificates.
Empty, relative, missing, directory and symlink settings are errors, not fallback.
This option selects an existing store; it does not create, unlock or import one.

Preparation requires macOS, system codesign/ditto/xcrun, an unlocked usable identity
and the configured profile. It verifies the Developer ID chain and exact team,
hardened runtime and secure timestamp. The notary wait is bounded to 20 minutes;
a timeout may leave a pending Apple submission. Diagnose locally with notarytool
history/log and the same Keychain profile. Only `Accepted` allows preparation.
Provider output is intentionally not echoed by the tool.

Standalone executables cannot carry stapled notarization tickets. This TAR path
does not claim offline first-launch Gatekeeper acceptance. An offline-stapleable
container needs a separate packaging decision and acceptance evidence.

## Windows operator setup

Enrollment requires approval, organization validation and a **Public Trust**
certificate profile. These prerequisites are complete for Kitrove's reviewed
publisher; the scoped rehearsal is recorded below.
Test profiles are not acceptable for public distribution. Follow Microsoft's
[SignTool instructions](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations).
Provision reviewed Windows SDK SignTool, the compatible Artifact Signing DLL and
its .NET prerequisites. This tool does not download/install/update them. Record
approved versions and digests before hosted activation. Use provider-managed keys.

Set these machine-local environment values before preparing the Windows archive:

| Variable | Required value |
|---|---|
| `KITROVE_SIGNTOOL` | Absolute path to reviewed `signtool.exe` |
| `KITROVE_AZURE_SIGNING_DLIB` | Absolute path to reviewed provider DLL |
| `KITROVE_AZURE_SIGNING_METADATA` | Absolute path to provider metadata JSON naming endpoint, account and certificate profile |
| `KITROVE_WINDOWS_PUBLISHER` | Exact reviewed certificate Subject from the validated Kapital Labs publisher profile |

Do not guess the publisher subject or copy it from an arbitrary downloaded binary.
Provider metadata is public configuration, not a place for tokens. Authentication
is provisioned separately. Signing uses SHA-256 and Microsoft's RFC3161 timestamp
service, then requires SignTool Authenticode verification, a valid embedded signature,
a timestamp certificate and exact publisher match through Windows PowerShell.
Missing prerequisites or any failed check stop preparation. Signing does not guarantee immediate
SmartScreen reputation or warning-free launch.

## Completed rehearsals and remaining acceptance

Both Apple Silicon products were locally signed and notarized on 2026-09-08.
Both Windows products passed native signing, exact publisher, timestamp and final
archive checks in
[run 34306851788](https://github.com/brandon-kaplan/kitrove/actions/runs/34306851788);
the detailed Apple and Windows evidence records remain in the private development
repository and are not distributed with this source snapshot.
These are private `v0.0.0` rehearsals, not public releases or installer execution
acceptance. Temporary Windows federation, its profile role and activation variable
were removed. Windows production credential provisioning remains incomplete.

The operator approved Apple credential custody in the protected `release`
environment of `Kapital-Labs/kitrove`. The encrypted identity and its password,
Apple ID/team and dedicated notarization password are stored as environment
secrets. The notarization secret is named `KITROVE_GITHUB_NOTARIZATION`.
Read-only hosted credential check
[34365796564](https://github.com/Kapital-Labs/kitrove/actions/runs/34365796564)
passed the exact certificate, expiry, key-pair and notarization-login checks.
Temporary branch permission and exact-SHA activation were removed afterward.
Only that isolated workflow was published, not the product source or Git history.
Subsequent native hosted rehearsal
[34378308650](https://github.com/Kapital-Labs/kitrove/actions/runs/34378308650)
signed a tiny test executable, verified its exact team/runtime/timestamp, received
Accepted Apple notarization, restored the search list and removed the temporary
store. Its temporary GitHub access was removed. This is infrastructure evidence,
not acceptance of actual Kitrove release archives or offline Gatekeeper behavior.

## Hosted Apple archive integration

The disabled production workflow compiles the native import helper and xtask before
exposing Apple credentials. `scripts/hosted_apple_signing.py` manages one temporary
store for both products and delegates actual signing/archive binding to the existing
prebuilt xtask. It never implements a second signer or executes the product binaries.
Credential environment variables are removed before children; secrets travel only
through stdin or a no-echo native prompt, not arguments or logs. The Swift helper
uses Apple's legacy file-Keychain APIs (which emit deprecation warnings) because
native codesign requires this store type. No additional package is installed.

The wrapper restores the exact prior search list and attempts store deletion even
if restoration fails. Both failures stop release preparation. Abrupt runner
cancellation relies on ephemeral runner destruction; this is not a self-hosted
workflow. Signed archive verification, staging and attestations follow cleanup.
The actual two-product hosted handoff and both Mac architectures still require
native release acceptance. Test fixtures are not product release evidence.

Still required: Intel Mac signing evidence; real hosted archive acceptance;
offline Gatekeeper container/bootstrap acceptance; signed PowerShell convenience
scripts if distributed as signed scripts; public-source approval and exact hosted
provenance; and real two-version install, upgrade, failed-upgrade recovery and
rollback acceptance. Do not infer any of these from successful code signing.

## Hosted activation — not complete

The release workflow uses signing-required preparation. Its cheap initial gate also
requires repository variable `KITROVE_HOSTED_SIGNING_READY=true` before expensive
validation/builds. **Do not set it yet.** It is an activation acknowledgement, not
signing evidence or an unsigned bypass.

First separately approve and implement ephemeral hosted credential/tool provisioning,
restrict signing to the protected `release` environment and reviewed source, clean
up provisioned material even on failure, and demonstrate a native release rehearsal.
For Azure prefer GitHub OIDC scoped to the exact repository/environment and a
least-privilege certificate-profile signer role. Hosted access to an Apple key needs
a separate explicit decision, now recorded above; Apple provisioning is integrated
but production activation and actual archive acceptance remain gated. Do not use a developer workstation as an unattended
public-repository runner. The public-source and publication approval gates remain.
