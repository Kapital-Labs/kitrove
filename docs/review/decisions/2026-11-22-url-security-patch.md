# URL parser security patch

Fresh audit identifies RUSTSEC-2026-0592 in pinned url2.5.8: repeated blob URL
origin computation can overflow the stack and abort a process. url2.5.9 bounds
this behavior by allowing only http/https/file inner origins. The patched crate
was published after RC5.20. No reachable Kitrove exploit or connection to the
reported retained-cleanup mismatch has been demonstrated.

Update only url2.5.8 to2.5.9 and its required form_urlencoded1.2.2 to1.2.3.
The manifest retains an exact url pin. The lock comparison proves only these two
versions/checksums change: no graph nodes, dependency edges, other package fields,
workspace versions or features change. Authenticate all four published archives
against registry checksums and retain complete file hashes and source diffs.
Both packages retain byte-identical MIT/Apache license files, no build scripts,
and minimum Rust1.63/1.51, below project1.89. Update the reviewed-lock BLAKE3 only
after this source/license/identity review; do not relax license or audit guards.

The published patch also updates WHATWG path escaping, file URL/drive handling,
port/backslash rules and double-dot scanning. Review these source deltas and run
existing canonical HTTPS/SSH URL, sync, TLS and complete source checks. Kitrove's
direct HTTPS parser rejects non-HTTPS schemes and derives its origin string;
that is not a proof about every transitive call path. The required form encoder
patch clamps a suffix position beyond the target length instead of panicking.

Fresh audit reports zero known vulnerabilities after this update. Retain the
existing chrono0.4.45 RUSTSEC-2026-0543 unmaintained notice and do not add ignores.
Fullstable/Rust1.89, notice/license/governance, exact public PR/native and fresh
green-main checks remain required. This note does not claim unrun checks, legal
compliance, whole-repository security or deployed-binary acceptance. No personal
installation, collection/sync, application version, signing/tag/channel update or
security bypass is part of this source repair.
