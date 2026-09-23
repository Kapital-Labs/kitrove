# Shared source archive family review

NS-09: keep a closed archive inventory and fail before publication on malformed
content. Release 35923739891 completed all four signed/staged/attested local
artifact jobs, then stopped on source-root validation. No release was published.

Pinned cargo-dist 0.32.0 locally reproduces the source archive root
`kitrove-installer-0.1.0-rc.1.2/`. The validator assumed only `kitrove-cli-*` even
though both products are shipped. It now derives permitted prefixes from the
existing closed release-family table and shares the existing version grammar.
No arbitrary prefix, multi-root archive, traversal, links, unsafe modes, duplicate
entries or checksum mismatch becomes acceptable. No workflow, signing, provenance,
credential, dependency or publication policy changes.

Regression coverage accepts both known products with stable and prerelease versions
and rejects unknown products, absent/malformed versions and nested root tricks.
The complete publication fixture now uses the installer-named source archive.
All 54 archive-validator tests pass. A local global build using the pinned packager
and retained successful platform artifacts passes the full 11-artifact check and
publication staging, including hardened generated installers. This is byte-level
validation only, not independent provenance acceptance or clean-machine evidence;
no downloaded product executable was run and no signing was repeated.

Review found no further change necessary in this bounded unit. Failed tags remain
immutable; a future candidate must be built and authenticated under its own tag.
