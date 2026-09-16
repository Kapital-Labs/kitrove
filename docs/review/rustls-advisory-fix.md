# Rustls advisory fix

Main CI found RUSTSEC-2026-0285 in rustls 0.23.32. The advisory identifies
0.23.45 as patched. Update the exact workspace pin and Cargo-generated lockfile
to that version; no other package, feature, or TLS configuration changes.

NS-07/NS-09 and INV-07/INV-12 remain intact. This repairs the existing transport
security implementation without changing trust boundaries, local-secret handling,
discovery/adoption, portable/native representation, fidelity, provenance, receipts,
or synchronization/conflict semantics. No advisory suppression or insecure fallback
is introduced. Existing HTTPS validation and round-trip tests remain applicable.

Scoped security and consolidation review: use the upstream patch through the
existing shared workspace dependency. No custom protocol logic or duplicate
implementation is needed. The lockfile changes only rustls's version and checksum.
Local cargo audit, Rust 1.85 checks for core and xtask, and full cargo ci passed.
Hosted CI and signing acceptance remain separate gates.
