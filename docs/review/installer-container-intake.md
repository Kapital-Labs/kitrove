# Read-only installer container intake review

`verify-installer-container` connects ADR-0043's opaque provenance result to the
trusted installer's existing local-input boundary. It accepts only the five exact
release inputs, rejects all mutation/state options, and returns before installation
preflight or mutation dispatch. Non-Mac compiled targets reject before filesystem
intake. No automatic mounting, native tools, network, downloads or execution occur.

The existing retained-file helper enforces exact basename, bounded no-follow reads,
safe parent/leaf permissions, asserted digest and revalidation before any successful
output. Its owned snapshot is passed to the shared container provenance verifier;
no application archive parser or replacement/rollback type is involved. Native
signature and payload acceptance remain explicitly unclaimed in success output.

Release input-to-request construction was consolidated for application authentication,
bundle selection and image verification. Review checked parsing and dispatch against
every existing command, exact host catalog selection, failure redaction, fresh
verification, snapshot revalidation and unchanged filesystem authority. Existing
generic intake substitution and permission tests cover the shared path; new tests
cover strict command options, non-Mac early refusal, synthetic provenance refusal
and unchanged filesystem snapshots. No verification bypass was added for testing.

NS-07/NS-09 remain intact. This is a local verification command, not a completed
bootstrap or clean-machine acceptance. Real production-tag provenance remains open.
No dependency, signing or publication change.

`select-installer-container-bundle` shares the existing bounded JSONL selector,
exact-one-match rule and retained local intake. It computes the image digest once,
uses the shared image bound and fixed production identity policy, and never passes
image bytes to an archive parser. Existing selector tests cover ambiguity and framing;
new container cases cover empty images, malformed collections and unrelated provenance.

Windows CI exposed an existing fixture publication race: the reader could observe
an empty PID file between creation and writing. The fixture now writes and closes
a sibling pending file before renaming it into view. Read-side PID validation and
process-containment assertions are unchanged; native Windows CI must confirm the fix.

Local validation passed: all 220 installer library tests on macOS, all-target/
all-feature installer Clippy, Rust 1.85 all-target installer check, governance,
repository, formatting and diff checks. Native Windows/non-Mac verification remains
part of hosted validation; this local run does not claim it.
