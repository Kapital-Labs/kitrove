# RC5.2 dependency security review

The fresh prepublication audit found RUSTSEC-2026-0387 in crypto-bigint 0.7.5:
intended constant-time integer operations can have timing variability. It enters
the application through the existing russh/SSH elliptic-curve dependency graph.
This is an upstream advisory, not a demonstrated Kitrove secret-recovery exploit.
Update only crypto-bigint to 0.7.6 and its required ctutils to 0.4.5.
No advisory suppression, dependency feature or graph-edge change is introduced.

## Identity and license

- crypto-bigint 0.7.6: Apache-2.0 OR MIT, Rust 1.87, upstream source commit
  `c34044b8a1479ef32bec0a9030cf2f07b06506d9` in RustCrypto/crypto-bigint.
  Registry archive SHA-256:
  `6bb08299a6046833a879ace115697f12fd2bd6c8d3e93c909ffc9e0738e7cae0`.
- ctutils 0.4.5: Apache-2.0 OR MIT, Rust 1.87, upstream source commit
  `88d6e90d4cfd2fc3333d00e13c99241507d2138f`, path `ctutils` in RustCrypto/utils.
  Registry archive SHA-256:
  `38d28fb6aa7dd680b3ffd1a3e64e115c177bdba63c0ae7f9cd48129ff05c4fa0`.

Both license texts compare unchanged, and neither adds a build script. Registry
archive hashes match the lockfile and are checked by Cargo; no separate publisher
signature is claimed. Rust 1.88 remains the project minimum. The upstream
changelog mentions ctutils 0.4.4, but the published 0.7.6 manifest requires 0.4.5;
the actual reviewed manifest and resolved graph govern this update.

## Targeted source review and validation limits

Review covered the ctutils integer primitives/choice routing, subtraction borrow
barriers, zero-count fallback and add/carry helpers and accompanying tests;
crypto-bigint word forwarding, limb bits/subtraction, UintRef equality, boxed
Montgomery inversion, multiplication/reduction and division changes. The release
also contains upstream arithmetic correctness, zeroize and square-root changes.
No new unsafe addition was found in the captured source delta. This is targeted
dependency review, not a complete cryptographic proof or every-line upstream audit.
No local timing exploit or cross-target constant-time proof is claimed.

The original audit failure and initial version-only stable/MSRV passes are retained
separately. The final locked graph must pass fresh audit, all dependency licenses,
full stable/Rust 1.88 and exact public checks. Tests are integration/regression
evidence; they do not establish constant-time code generation on every CPU.

The final reviewed Cargo.lock BLAKE3 is
`d05a78545ecc0cef68e5e3fdffcb2d8a27ff6b7010738a9af57b9099ccda9121`.
Besides 27 workspace version changes, its delta changes only the two listed
registry versions/checksums. An unrelated tempfile/getrandom selection proposed
by the resolver was restored before validation; no other lock changes are needed.

NS-07/NS-09 and INV-07/INV-12 remain unchanged. No portable/native format,
fidelity, adoption, deployment receipt, synchronization, trust or credential
authority changes. Provider permissions, release gates and signing are unchanged.
