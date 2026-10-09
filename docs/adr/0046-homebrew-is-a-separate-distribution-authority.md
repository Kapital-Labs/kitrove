# ADR-0046: Homebrew is a separate distribution authority

- **Status:** Proposed; local packaging implementation only, publication gated
- **Date:** 2026-10-09
- **Deciders:** Maintainer requested Homebrew installation work
- **North Star invariants:** NS-07, NS-08, NS-09

## Context

The verified-archive procedure asks users to bootstrap a trusted verifier and
select several release inputs. Homebrew users already trust Homebrew and selected
taps to install executables. A tap can offer a shorter path, but a checksum in
Ruby is not independently verified release provenance. This is an explicit new
distribution authority, not a shortcut around ADR-0043's existing verifier.

## Proposed decision

Stage a third-party tap cask named `kitrove-rc`, initially for Apple Silicon Mac.
It links only `kitrove` from the immutable signed RC3 CLI archive. A cask's `binary`
artifact avoids a source rebuild, binary relocation, custom installer execution
and alteration of the signed executable. This is not a Homebrew/core submission
or a claim of Intel/Linux/Windows acceptance. Do not publish until the channel
decision, tap creation and its native acceptance are reviewed.

Maintainers authenticate each exact candidate using the existing release policy
and independently trusted verifier before reviewing its fixed URL and SHA-256
into the tap. Retain the tag, full commit, workflow run, archive and executable
digests, provenance and native signature results in review evidence. A release
page checksum, filename or prior verification log alone is insufficient. No
automatic latest-release resolution or unattended package bump is permitted.

Consumers explicitly trust Homebrew and the reviewed tap revision to select the
artifact; Homebrew checks the pinned download digest. This does not mean Homebrew
applies Kitrove's offline attestation policy on every installation. Keep normal
quarantine and Gatekeeper behavior. Do not strip attributes, disable assessment,
ad-hoc sign, or fall back to unchecked installation on a native refusal.

Homebrew exclusively owns the cask payload and its `kitrove` link. Package hooks
must not run Kitrove, initialize state, discover harnesses, install capabilities,
edit PATH or shell profiles, acquire credentials, or remove application data.
There are no pre/post-install scripts, `zap` rules or completion-generation probes.
Existing link conflicts must refuse without force. Migration from a standalone
installation is explicit, not an automatic overwrite or deletion.

Before any future cask version update, review state compatibility and the
Homebrew upgrade path separately. Homebrew replacement does not acquire Kitrove
state locks, retain ADR-0040 rollback kits, or provide its recovery protocol.
Never invoke `kitrove-installer` on a Brew-managed path. Binary downgrade is not
application-data rollback. An incompatible migration blocks a package update
until an appropriate backup and recovery design is accepted.

## Relationship to existing decisions

If accepted for publication, this is a narrowly scoped alternative to ADR-0040's
installer-managed acquisition/replacement contract for Homebrew-owned binaries.
The existing installer, its provenance requirements and ADR-0041/0043 remain
unchanged. While this ADR is proposed, it grants no new supported-install claim.

NS-07: no credentials or operator state enter packaging. NS-08: distributing
Kitrove itself does not make Kitrove a general package manager. NS-09: the
independent starting authority is the trusted package manager/tap, never the
downloaded Kitrove binary authenticating itself. Discovery/adoption, portable and
native representations, fidelity, capability provenance/receipts, synchronization
and conflict handling are unchanged. No runtime product code changes are needed.

## Alternatives

- Source formula plus bottles: useful later, but introduces a separate build and
  signing path rather than reusing exact RC3 bytes.
- Cask invoking the downloaded installer: adds execution and conflicting ownership
  with no benefit for linking one CLI.
- Shell bootstrap: requires another independently trusted execution path and does
  not give existing Homebrew users familiar ownership and removal.

## Validation and remaining gates

Static tests freeze the declarative package surface, exact release pins and
single binary path. Homebrew must parse and audit the cask. Native acceptance
must independently authenticate the selected archive, install with quarantine
enabled, compare installed bytes/signature, exercise explicit version/help,
refuse an occupied link without changing its canary, and uninstall without
changing isolated state/harness canaries. Preserve failure output.

Static checks and warm-Mac tests do not establish clean-Mac online/offline first
launch. That gate remains open until a clean Mac is available. Public tap creation,
protected review policy and package publication are separate approval gates.
The initial package must remain marked experimental until its actual acceptance
limits are documented. Do not advertise a working installation command prematurely.
