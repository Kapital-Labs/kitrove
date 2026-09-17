# ADR-0043: A stapled Mac installer container supplements release archives

Status: Accepted; local signed preparation passed, native consumer acceptance pending

## Context

The maintainer selected a signed, notarized, stapled DMG for Mac downloads on
2026-09-16. The CLI and installer executables already pass hosted signing and
notarization on both Mac architectures. Their TAR archives cannot carry a stapled
ticket. Successful signing is not evidence of offline first launch.

## Decision

Add an architecture-specific installer DMG without replacing the existing typed
application and installer archives. The container is a bootstrap artifact, never
application replacement or rollback authority. The ordinary-user installation
transaction remains in the existing installer. Do not introduce a privileged PKG,
installation script, application self-updater or a second archive/signature parser.

Build the container only from the exact prepared installer archive and its retained
build-manifest/checksum authority. Reuse the bounded Rust archive and manifest
validation to obtain the installer bytes. Do not extract arbitrary archive paths
using a shell command. Stage in a fresh private directory and retain/revalidate
input identity through preparation. The payload must be a closed, tested inventory;
it must include the exact signed installer and its original installer archive so
the consumer can independently bind the executable to its archive provenance.
No executable is launched during packaging or signing.

Use Apple's native image, signing, notarization and stapling tools. Reuse the
existing exact Developer ID/team, Keychain selection, redacted errors and cleanup
boundary. Require accepted notarization, staple validation, container signature
verification and payload identity checks before computing the final image checksum.
Never mutate the final image after checksum/provenance generation. Failure cannot
produce a releasable unsigned or unstapled fallback.

Before release integration, specify and test exact image names, payload inventory,
size bounds, no-overwrite publication and retained output identity. Extend the
shared release inventory, checksum controls and attestation jobs together. Do not
teach the application archive parser to treat a disk image as an application.
The publication integration checkpoint below extends the inventory without
enabling production activation.

## Payload staging checkpoint

`cargo xtask stage-installer-dmg <installer-archive> <target> <tag> <dist-manifest>`
performs the preparation boundary without native tools. It accepts only the two
Mac installer archive names on macOS, validates the bounded archive, installer
manifest, adjacent checksum and cargo-dist authority, and revalidates all inputs
before and after staging. Its fresh private temporary directory contains exactly
`kitrove-installer`, the original installer archive, and its canonical checksum.
The executable has mode 0700 and the other leaves 0600. No existing output is reused.
Success retains that directory and reports its path for subsequent operator work.
Failure drops only the newly owned temporary payload. Source files remain unchanged.

This is structural build-input validation, not signature authentication. Unsigned
development archives can pass it; later image preparation must freshly validate
native signatures before using the payload. This command creates no disk image,
does not mount or launch content, and changes no production release inventory.

## Native preparation checkpoint

The separate `prepare-installer-dmg` command reuses fresh payload preparation and
the shared Apple signature/team/timestamp and notarization helpers. It builds only
`kitrove-installer-aarch64-apple-darwin.dmg` or
`kitrove-installer-x86_64-apple-darwin.dmg` in a new private output directory.
Native hdiutil creates a compressed read-only UDZO/HFS+ image from the closed
payload. The preexisting installer signature must satisfy the executable runtime
and timestamp policy; the container requires the same team and timestamp, not an
executable runtime flag. Accepted image notarization, stapling, ticket validation,
container signature verification and image integrity verification precede checksum
creation. The existing 256 MiB archive bound also limits the resulting DMG.

Mount with read-only, no-browse and no-autoopen options, compare all three leaves
through bounded no-follow reads to retained payload bytes, and detach before
checksum creation. Revalidate final image identity/bytes around verification.
Unknown inventory, links, changed content and failures stop preparation. Never
recursively clean an uncertain mount: retain its separately allocated mountpoint
and report it. Incomplete output is retained on errors, not published or retried.

The native unsigned round-trip test is operator-only and excluded from ordinary CI.
Synthetic tests cover stage failures, substitutions and cleanup uncertainty.
Local signed preparation passed for both Mac payload targets on 2026-09-16; see the
[native rehearsal record](../review/installer-dmg-native-rehearsal.md). No installer
or CLI was launched. Clean-machine online/offline consumer acceptance remains open.
This native preparation evidence does not by itself validate the later hosted
publication integration.

## Shared catalog checkpoint

`InstallerContainerSpec` reserves the two exact Mac image names and their embedded
installer archive selections in a type separate from application/installer archives.
Local preparation consumes this shared catalog. The canonical JSON policy contains
the same mappings; Rust correspondence tests and the publication tool's strict
policy validation bind them. The existing 256 MiB image bound is unchanged.
The initial catalog checkpoint did not extend the publication inventory. The
following integration connects native workflow preparation, checksum inventory and
attestations together.

## Publication integration checkpoint

The disabled tag workflow explicitly enables DMG preparation in the existing Apple
credential lifetime after both archives are prepared. Local/manual archive-only
rehearsals retain their old default. A named output directory must be fresh, private
and under an existing canonical absolute parent; no existing artifact is overwritten.
After credential cleanup, reverify the copied image and checksum against the exact
staged installer archive/build manifest, including signatures, ticket, image integrity,
read-only payload comparison and detach. Attest that one image only afterward.

The closed publication set is nine archives plus the two named Mac DMGs and their
checksum controls. Linux copies containers as bounded opaque bytes, not through TAR
or ZIP parsers and not as proof of a native signature. Complete cargo-dist's combined
checksum only after its original nine-archive (or already complete eleven-artifact)
map and every adjacent digest match the exact file set. Write a new checksum file
without overwrite; the workflow replaces only its generated build checksum control.
Private global and host staging recheck the exact eleven-artifact digest set before
publication. Attest the final combined checksum as well as each individual image.

Native-tool reverification passed locally for both preserved images without signing
credentials or product execution. Synthetic workflow and inventory tests are not
hosted signing acceptance or production-tag provenance. A hosted rehearsal still
needs separate approval. Production activation and release publication remain gated.

## Consumer trust

An independently trusted verifier authenticates the exact image, repository,
release workflow, tag, source commit and checksum before mounting or executing
anything from it. Apple's native verification is additional evidence, not a
substitute for release provenance. Mount without automatic execution, read-only;
retain exact installer bytes when staging outside the image. The installer must
still authenticate application archives using ADR-0040/0041.

No downloaded binary authenticates its own first execution. The separately
reviewed-source-built verifier remains the development starting point until the
public binary bootstrap is tested. Do not remove quarantine or disable Gatekeeper.
Staple validation alone does not prove an extracted standalone CLI will launch
offline: native acceptance must cover the actual user path on a clean machine.

## Acceptance and authorization

Synthetic tests cover target/product refusal, invalid inputs, identity changes,
occupied output, tool failure at each stage, cleanup and unchanged input archives.
Native tests cover each Mac architecture, both online and offline first launch,
quarantined downloads, exact payloads, installer execution and later CLI launch.
Record the macOS version and clean-machine conditions; warm notarization caches
are not offline-first-launch evidence.

The selected direction authorizes implementation, not production activation,
credential export, provider changes or publication. A new native signing rehearsal
requires its protected approval. The existing successful archive rehearsal remains
valid for its exact bytes but cannot establish DMG acceptance.

## Impact

NS-07/NS-08/NS-09 and INV-06/INV-07/INV-08/INV-12 remain intact. This is distribution
of Kitrove itself, not general package management. Credentials and staging remain
local; discovery/adoption, portable/native content, fidelity, capability receipts,
synchronization and conflict semantics are unchanged.

The tradeoff is additional release artifacts and Mac acceptance work. Shared
validation and native tools avoid another cryptographic or archive implementation.
Follow [release acceptance](../RELEASE-ACCEPTANCE.md) for the remaining sequence.
