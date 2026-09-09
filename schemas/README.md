# Schemas

Generated JSON schemas will live here after the version-1 Rust manifest, lockfile, machine-state, and adapter-report contracts stabilize through the skills vertical slice. The current authoritative schemas are the strict Serde types in `kitrove-model` and the checked-in fixtures in `kitrove-testkit`.

Do not hand-maintain generated schema files. Future generation remains owned by `xtask` so generated artifacts cannot drift from the executable parsers.
