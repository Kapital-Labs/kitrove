# Release archive conformance corpus

These archives contain only synthetic fixture bytes. Both the Rust release-policy tests and the
Python publication verifier consume `cases.json` and must reach the recorded decision for the same
digest-bound bytes.

Check the corpus against its deterministic generator with:

```text
python3 scripts/generate_release_archive_corpus.py --check \
  crates/kitrove-release-policy/tests/fixtures/archive-conformance
```

To intentionally regenerate it, run the generator against an empty temporary directory and replace
only the generated files after reviewing the resulting diff. The generator refuses nonempty output
directories so stale cases cannot survive.

Review the generator, manifest, and changed binary fixture digests together. The corpus is parity
evidence; format-specific unit tests remain the exhaustive boundary tests.
