# ADR-0043: A stapled Mac installer container supplements release archives

Status: Accepted direction; implementation and native acceptance pending

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
The current nine-archive release inventory remains authoritative until that
integration is implemented and reviewed.

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
