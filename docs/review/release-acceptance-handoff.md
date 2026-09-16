# Release acceptance handoff review

Documentation-only update after signing rehearsal `35118722213` at source
`1267b8438276d70fd3f083cfa9e4a8576a31178b`. Read-only GitHub run results and the
preserved evidence establish success for both products on all three signing targets.
All six preserved archive checksums matched. No claim of installer execution or
public provenance is derived from those results.

The roadmap, signing guide, release guide, installer guide and ADR-0042 checkpoint
now point to one acceptance plan. It separates first acquisition, isolated lifecycle
tests, approved candidate publication, real two-version evidence and bounded alpha.
The ordering resolves a circular gate: production provenance requires a tag release,
so real two-version acceptance gates stable support, not first candidate publication.

Security review retains NS-07/NS-09 and INV-06/INV-07/INV-08/INV-12. No changes to
discovery/adoption, portable/native representation, fidelity, receipts, sync/conflicts,
executable trust, signing credentials, workflow policy or production activation.
No new parser, signature implementation or duplicate mutation path was introduced.
Existing shared verification/staging is required for the next implementation unit.

The maintainer selected a stapled Mac DMG; implementation and native acceptance
remain open, and no offline-first-launch promise is made.
The four-target release catalog does not include Linux arm64. Neither the old private
context map nor historical checkpoint text is current release acceptance evidence.

Full local cargo ci and git diff --check passed. No new MSRV or native signing run
was needed for this documentation-only change. Native DMG and real-release lifecycle
acceptance are explicitly not claimed. No release publication was performed.
