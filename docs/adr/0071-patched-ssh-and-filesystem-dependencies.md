# ADR-0071: Patched SSH and filesystem dependencies

- Status: Accepted for RC5.13 implementation; validation pending
- Date: 2026-11-13
- North Star: NS-05, NS-06, NS-07, NS-09

## Decision

Use exact-pinned russh 0.65.1 with the existing disabled default features and
ring backend. The release addresses RUSTSEC-2026-0492 and RUSTSEC-2026-0495.
Its declared compiler requirement raises source builds and the CI and release
minimum from Rust 1.88 to Rust 1.89. This supersedes the current compiler floor
in ADR-0054 and the original dependency selection in ADR-0028. Their validation
records continue to describe the versions used at that time.

The client accepts plain server keys through the existing bounded known-hosts
verifier and refuses host certificates. Credential acquisition remains after
host verification. Transport limits, remote command construction, agent
selection, trust decisions and synchronization approval retain their existing
authority.

Use rustix 1.1.6 for RUSTSEC-2026-0486. Its extended-attribute functions handle
empty output buffers without marking unwritten memory initialized. Keep the
existing features and dependency edges, including each locked Windows binding.
Regenerate the complete license inventory and included license material.

## Validation and scope

Review the exact dependency graph, published crate identities and license
inputs. Run complete stable and Rust 1.89 checks, the current advisory audit,
native platform CI, the distribution plan and archive verification before
publication. No audit exception is introduced.

This decision updates dependencies used by the CLI and installer. It does not
establish a new capability kind, source trust, migration or stable-support
promise. Native signing and verification retain the configured release gates.
