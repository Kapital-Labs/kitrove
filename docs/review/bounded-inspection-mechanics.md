# Bounded inspection mechanics

ADR-0045 requires shared bounded mechanics before adding a consumer native verifier.
This first extraction moves the existing Unix child lifecycle and cross-platform
output readers into private modules of the version-probe crate. Existing probe calls,
limits, deadlines, error classifications and cleanup behavior remain unchanged.
Windows still uses its existing contained-process launcher.

No process launch moves: the exact governance launch allowlist stays unchanged.
The extracted modules expose only parent-module helpers, not a new public command
runner. No installer native verification, new execution authority or signing is added.
This is a preparatory refactor, not complete implementation of ADR-0045.

Existing probe regressions continue to cover timeout and descendant behavior.
Additional pure reader tests cover the exact output limit, one excess byte, invalid
UTF-8 and read errors. Review must compare moved lifecycle paths, including Drop,
with the original source. Focused probes, canonical stable and Rust 1.85.0 validation,
and strict Windows GNU Clippy with native test fixtures passed. A normalized source
comparison confirmed the moved lifecycle (including Drop) and output collection are
unchanged apart from visibility and module-level platform gating. Native Windows
feature-enabled process/probe results remain required before acceptance; local Mac
results do not prove Windows behavior.

NS-07/NS-09 and INV-06/INV-07/INV-08/INV-12 remain unchanged. Credentials, capability
formats, native preservation, receipts, synchronization and rollback are unaffected.
