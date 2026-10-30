# Private native-inspection source

These Rust modules are included privately by reviewed caller crates. This is not
a Cargo package or public execution API. Lifecycle policy and closed launch
selection belong to each caller; these mechanics confer no trust/readiness.

The first extraction changes no version-probe launch, limits or cleanup policy.
Its lifecycle and failure types are byte-identical to the reviewed preimage;
output collection differs only in private visibility and formatting. Keep the
probe's error/API-specific tests with that caller. Production governance scans
this source tree and allows launch only in the exact lifecycle module.

Do not add a new caller until its process ownership/cancellation, output/deadline
bounds and file/tool identity have been separately reviewed. In particular, a
nested group must not escape an outer supervisor's cleanup accounting. See
ADR-0045 and ADR-0068. This source grants no signing/release or retry authority.

ADR-0069 adds the reviewed closed ticket caller's opt-in completion proof: direct
reaping plus bounded group-absence confirmation. Its outer supervisor must also
account for nested ownership. The original probe path does not opt into the new
method and keeps its former behaviour; it is not silently assigned stronger proof.
