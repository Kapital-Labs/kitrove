# RC5.5 website release copy

The maintainer requested updating the public website after RC5.5 publication.
This unit changes only the home page, getting-started page, site tests and
maintenance/review documentation. The existing layout, static build inventory,
workflow permissions, package payloads, signatures and metadata stay unchanged.
No application release, signing activation, channel update or resumed readiness
automation is authorized or needed.

RC5.5 is a public nondraft prerelease at immutable source
64771911eecdb5f167c07c88e1606dc5bf83c9a3, release run41241628037. Independent
consumer verification covered all21 public files,14 exact-source attestations,
archive notice bytes and the native Apple Silicon image/payload. Those checks did
not execute or install downloaded products. Publication and source CI do not
establish clean-Mac/offline first launch or full fresh-install acceptance.

Both pages make RC5.5 the primary download and link its exact tag, reviewed notes
and versioned installer/verification guide. Apple Silicon, Linux x86-64 and
Windows x86-64 are selected; Intel Macs are unsupported. Existing Homebrew and
APT/DNF instructions explicitly remain RC4.2, not RC5.5 or an upgrade route. The
old WinGet submission is not advertised as RC5.5 availability. No installer script
is piped to execution, checksum-only trust or self-authenticating first execution
is suggested. Users must keep new isolated collections and empty destinations;
binary rollback is not data recovery and installer refusals must not be bypassed.

NS-04/NS-07/NS-09/NS-10 impact is communication only: truthful fidelity/support,
local identity/secrets and independent executable trust remain mandatory.
Discovery/adoption, portable representation, native-variant preservation,
provenance/receipts, synchronization/conflicts and local-only boundaries do not
change. No new platform guarantee or ADR is introduced. Cloud-provider sync
remains roadmap work. Review is manual full-diff/content review, not an independent
agent or exhaustive repository assurance.

Require offline site/link/claim tests (new RC5.5 assertions fail on old copy),
desktop/mobile/no-JavaScript browser smoke, full stable/Rust1.88 canonical CI,
fresh audit and secret scans before commit. Exact PR checks and freshly green
latest main precede guarded squash; exact merged main must be green before the
existing manually dispatched website deployment. Verify both live HTML files
byte-for-byte against merged source, normal routes/redirect/404, and the unchanged
reviewed package inventory after deployment. No package metadata renewal or
signing is part of this copy-only change.
