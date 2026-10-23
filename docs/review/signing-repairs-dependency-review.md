# Dependency review accompanying hosted signing repairs

The fresh RustSec audit found RUSTSEC-2026-0385 in ctutils 0.4.2 and the
RUSTSEC-2026-0386 unsoundness notice in Tokio 1.53.1. Upgrade only ctutils to
0.4.4 and the existing exact Tokio workspace pin to 1.53.3. No advisory is
suppressed. The complete lockfile delta changes only these two versions and
registry checksums; package identities, dependency edges and features are unchanged.

## Source, provenance and license review

- ctutils 0.4.4: Apache-2.0 OR MIT, Rust 1.87, source commit
  `a993c0ba50db6510d8db15a6219572de65115438` under `ctutils` in RustCrypto/utils.
  Registry archive SHA-256:
  `12218662ccac37d9714f2191252553d67585b97df8c839cbe49e0bde278dc865`.
  Source changes route masks through the existing optimization barrier and use
  opaque half-width predicates for 32-bit u128 comparisons. Const conversions and
  boundary tests accompany the fix. No unsafe code or build script is added.
- Tokio 1.53.3: MIT, Rust 1.71, source commit
  `a85c3f5baa298a6b554fd3700daf0342289881af` under `tokio` in tokio-rs/tokio.
  Registry archive SHA-256:
  `ce3335fa71841cda333a58d7615b03901380ecf09d59b3296d21f8bbac0dde4e`.
  Review covers the AsyncFd registration fix, registration retention on deregister
  error, Windows process-handle cleanup ordering and selected runtime/waker changes.
  Existing safe constructors are deprecated; Kitrove has no direct AsyncFd calls.
  Manifest dependency/feature sections and license text are unchanged. This is
  targeted security review, not a complete audit of every Tokio changed line.

The registry archive hashes match the locked checksums. Cargo authenticates these
downloaded archive bytes against the lockfile; no separate publisher signature is
claimed. Dependencies remain distributed under their upstream license obligations
in source and compiled products. No new package or license expression enters the
graph. Existing offline provenance verification restrictions remain mandatory.

The reviewed Cargo.lock BLAKE3 is
`e3edb10b3984a8e0d50a312cab8080e3fd051c195d09b29f28e1d94f78279af6`.
Rust 1.88 remains the project minimum. Full stable/MSRV validation, fresh audit,
385-package license review and public checks remain required before merge.

NS-07/NS-09 and INV-07/INV-12 remain unchanged. These patches change no portable
schema, fidelity, adoption, local trust, deployment receipt, synchronization or
conflict policy. They grant no release, signing or retry authority.
