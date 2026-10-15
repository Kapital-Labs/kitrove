# ADR-0048: Native packages have separate distribution authority

- **Status:** Proposed; package development authorized, publication gated by validation
- **Date:** 2026-10-14
- **Deciders:** Maintainer requested Windows and Linux packages
- **North Star invariants:** NS-07, NS-08, NS-09

## Context

The maintainer requested simpler Windows and Linux installation after approving
the Homebrew channel. Published release archives exist, but their existence does
not establish a package-manager channel. ADR-0046 separates package-manager
authority from the source-verifier installation path. This decision extends that
boundary to Windows and Linux without changing Kitrove's runtime trust model.

## Proposed decision

Prepare a user-scoped WinGet portable package from the immutable Windows CLI ZIP.
Prepare Debian and RPM packages from the immutable Linux CLI archive. Reuse the
authenticated executable bytes rather than compiling or signing another binary.
The initial targets are x86-64 Windows and x86-64 GNU/Linux. Chocolatey and other
architectures remain outside this unit.

Maintainers must authenticate each archive against the protected release workflow,
exact source commit and release tag before approving package pins. Retain archive
and executable digests, attestation results and applicable native signature
results. Package checksums bind downloads to reviewed bytes; checksums alone do
not establish provenance. Do not resolve a mutable latest release at install time.

Users trust WinGet's reviewed source or an explicitly selected Linux package
source. Neither path claims that the package manager runs Kitrove's independent
attestation verifier on each installation. Keep platform security checks intact.
Do not suppress certificate, signature, quarantine or reputation failures.

Packages own the CLI executable and package metadata only. They must not run
Kitrove during installation, generate completions by execution, initialize state,
discover harnesses, change capability trust, acquire credentials, write shell
profiles, or remove user data. Let WinGet manage its portable command alias and
let Linux package managers own `/usr/bin/kitrove`. Do not force package ownership
conflicts. Linux package managers may overwrite unowned files, so installation
instructions must check for a standalone executable before installing. Do not
claim that the package itself protects an unmanaged file at that destination.

Package replacement does not acquire Kitrove state locks or implement ADR-0040's
rollback-kit protocol. Users must complete pending application transactions
before changing versions. A binary downgrade cannot roll back application data.
Review state compatibility for every package update and never run
`kitrove-installer` against package-manager-owned paths.

## Publication gates

Stage manifests and package builders in the public source repository first.
Static tests must freeze release pins, permitted files, architecture, version
ordering and absence of install/remove hooks. Native tests must cover package
installation, version/help execution after authentication, upgrade, uninstall,
foreign-package ownership refusal and preservation of isolated state/harness canaries.
Use disposable test resources rather than operator data.

A WinGet community submission requires schema validation and native WinGet
acceptance before submission. Community review remains an external publication
gate. A staged manifest does not make `winget install` available.

A locally validated `.deb` or `.rpm` does not create an APT or DNF repository.
Repository publication additionally needs a selected signing identity, signed
metadata, key distribution and rotation procedures, and tested repository setup
and update commands. Do not invent repository keys or advertise `apt install`
or `dnf install` before that channel exists. Local package acceptance may precede
repository publication, with that limitation stated in the installation docs.

## Consequences and alternatives

This scope changes distribution, not discovery, adoption, synchronization,
fidelity, credential storage or executable capability trust. NS-07 keeps operator
data and credentials outside packaging. NS-08 keeps Kitrove from becoming a
general package manager. NS-09 requires a trusted starting distribution authority.

Source builds would introduce another build authority. Downloaded installer hooks
would mix package-manager ownership with Kitrove replacement authority. Neither
is needed to distribute one CLI executable. Native package tests do not satisfy
clean-Mac offline launch or a real two-machine product roundtrip.
