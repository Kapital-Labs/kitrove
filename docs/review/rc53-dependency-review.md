# RC5.3 withdrawn-dependency repair

Under separate user approval, replace withdrawn crypto-bigint 0.7.6 with 0.7.10
and its required ctutils 0.4.5 with 0.4.6. The upstream changelog attributes the
0.7.6 withdrawal to corrected NonZero multiplication trait bounds in 0.7.9;
older versions also had timing issues. Fresh audit did not identify a new 0.7.6
vulnerability. Do not turn the withdrawn-package warning into an exploit claim.

## Identity, provenance and license

- crypto-bigint 0.7.10: Apache-2.0 OR MIT, Rust 1.87, source commit
  `55af01b1957b1f90d718bf697ea9a6db7287151c` in RustCrypto/crypto-bigint.
  Registry archive SHA-256:
  `9c035cb64cba03dad2fb921f3e218785e8cf9a41790da5eb3a1400f62fa2be11`.
- ctutils 0.4.6: Apache-2.0 OR MIT, Rust 1.87, source commit
  `79275f704220fe32574c2a61973af40e4e1925b2`, path `ctutils` in RustCrypto/utils.
  Registry archive SHA-256:
  `fe3e9d21d39e6f39ff46e03d5b621424f88ee23d8a1672c6bfc9ccc7f2da4f6a`.

Published archives match the exact locked hashes; their VCS metadata names the
upstream commits. Both license texts compare unchanged, and neither adds a build
script. Cargo authenticates registry bytes against these hashes; no separate
publisher signature or complete cryptographic audit is claimed. Existing source
and binary attribution obligations and THIRD_PARTY_NOTICES.md remain applicable.

## Delta and compatibility review

The entire lock delta changes only these two versions and checksums. An unrelated
tempfile/getrandom resolver selection was restored before validation. Package
identities/count, dependency edges/kinds, enabled features, other versions and
workspace versions are unchanged. Rust 1.88 remains the project minimum.

Reviewed the full captured published-source delta: corrected NonZero integer
trait bounds, wider-modulus inversion result precision, zero/max special-modulus
multiplication, Montgomery carry propagation, internal subtraction/zero-count
primitives, constant-evaluation changes and accompanying upstream regressions.
ctutils adds word-mask subtraction with the existing optimization barrier and
32/64-bit boundary/propagation tests. No new unsafe addition or build script was
found. This is targeted dependency review, not a constant-time proof for every CPU.

The upstream API-bound correction is explicitly acknowledged, not assumed away
because the version is a patch. Kitrove has no direct crypto-bigint/ctutils source
calls; affected callers remain the existing SSH elliptic-curve/primefield graph.
All-feature workspace builds/tests and exact native public checks must establish
integration compatibility, including Rust 1.88 and Windows.

## Validation and impact

Fresh audit after the update exits successfully with zero vulnerabilities and no
warnings; retain the original withdrawn-package warning. The pre-review lock
fingerprint refusal is also retained. The reviewed Cargo.lock BLAKE3 is
`e79d75db8fa6d4be6a8e418b7e3236a5cc725b53b69fffbae5cb8ffb3a684f37`.
Full stable/Rust1.88, all dependency licenses, manual source review and fresh
exact public checks remain mandatory before merge and release.

NS-07/NS-09 and INV-07/INV-12 remain enforced. Discovery/adoption, portable/native
representations, asset identity, fidelity, provenance, receipts, synchronization,
conflict semantics and local-only authority boundaries do not change. No new
provider, credential access, trust-root change, signing permission, schema,
release retry or publication authority is introduced. No ADR model change is needed.
