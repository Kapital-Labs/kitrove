# Native consumer binding investigation

Consumer native verification remains unimplemented. Do not expose installer readiness
while the relationship between the checked native object and retained bytes is unresolved.

The Mac SDK and Apple's [static-code API documentation](https://developer.apple.com/documentation/security/secstaticcodecreatewithpathandattributes(_:_:_:_:))
describe a filesystem-path input. Creating the code object is not validation and can
succeed for unsigned input. The installed SDK attributes cover architecture, slice
offset and bundle version; they do not establish a retained-descriptor API.

A read-only experiment on the existing Mac invoked `/usr/bin/codesign` with an inherited
descriptor for the trusted system `/usr/bin/true`, addressed as `/dev/fd/3`. Both strict
verification and display refused with `cannot find code object on disk`. No downloaded
binary was executed or inspected in this experiment, and no signing occurred. This
rules out assuming that descriptor-path invocation works on this host; it is not a
general claim about every native verification API.

Apple's [SecCodeMapMemory documentation](https://developer.apple.com/documentation/security/seccodemapmemory(_:_:))
also describes signing information taken from code on disk, not validation of an
arbitrary captured byte buffer. It changes kernel page-in validation state, so it is
not an appropriate read-only substitute here. Inspection of Apple's published
`SecStaticCode.cpp` confirms that the reviewed create-with-attributes implementation
constructs a disk representation; this source inspection does not establish that no
other supported mechanism exists. Do not use private APIs as an undocumented escape.

The implementation must not claim that pre/post path checks alone prevent a temporary
substitution during verification. Evaluate a native identity-bound API or a separately
reviewed authenticated-snapshot binding before returning readiness. Avoid introducing
a bespoke Mach-O/signature parser just to work around this constraint. Existing Windows
read leases and containment should be reused, but do not infer Mac guarantees from them.

ADR-0045's process deadlines, bounded output, trusted tool selection and cleanup still
apply. This investigation changes no production policy, filesystem permissions or
release acceptance status. NS-07/NS-09 remain unchanged.

## Parser evaluation

The broad `apple-codesign` toolkit was not selected: its current source declares
Rust 1.92 and includes substantial unrelated signing/network functionality; its
older 0.28 release supports an older compiler but retains that broad dependency set.
The narrower [`object` library](https://github.com/gimli-rs/object) provides Mach-O
CodeSignature and CodeDirectory readers. A local evaluation pinned version 0.40.0
with only `read_core`, `macho` and `std`; Rust 1.85 compilation passed. The lockfile
adds only `object`, using the existing `memchr` dependency. No write, compression,
network, signing or general object-format features are enabled.

Candidate design: derive a bounded CodeDirectory binding from authenticated archive
bytes with this library, then require the native check to match that binding as well
as the existing publisher policy. Parsing alone grants no authority. Before acceptance,
review hash selection, architecture, ambiguous/duplicate structures, slot bounds and
whether the native requirement really binds every relevant check to that snapshot.
The evaluation dependency is not yet a completed consumer implementation.

## Candidate implementation and limits

`apple_code_directory::candidate_cdhash` now uses borrowed `object` header,
load-command and signature readers. It accepts only thin little-endian 64-bit
executables for the two existing Mac targets, bounds commands/signature/blob counts,
rejects duplicate or overlapping blobs and alternate directories, and checks every
ordinary SHA-256 code page against the captured bytes. The result is only a candidate
20-byte CodeDirectory digest. Apple's [TN3126](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes)
documents the truncation of the SHA-256 digest to 20 bytes.

This does not authenticate CMS, timestamps or native metadata semantics. In particular,
the CodeDirectory digest does not bind the entire signature container: a different CMS
wrapper can retain the same directory digest. A native pathname check constrained by
that digest therefore does not, by itself, prove that the captured CMS/timestamp was
the one inspected. Keep consumer readiness disabled until that remaining binding is
resolved; do not relabel the candidate API as signature verification.

Tests cover all truncations of a synthetic executable, wrong targets, malformed
commands/ranges/hash selection, modified code pages, duplicate/overlapping/alternate
directories, and the independently attested public RC2 arm64 installer. The public
artifact test checks archive digest and provenance before candidate extraction and
never executes the installer. No signature or timestamp acceptance is inferred from it.

Impact: NS-07/NS-09 and existing installer trust boundaries are unchanged. This pure
inspection adds no discovery/adoption, portable model, native variant, fidelity,
receipt, synchronization or conflict behavior. No credential or local-only data is
exported. Unsupported inputs fail explicitly; parsing yields no launch authority.
Full canonical validation and minimum-version tests must pass before any push.

The final canonical run passed formatting, strict Clippy, all workspace tests,
archive/workflow checks, governance, license inventory and repository hygiene.
All four candidate-binding tests also passed on Rust 1.85. This establishes only
the candidate parser's local evidence, not completed consumer verification.

Next supported-API investigation: the installed Security SDK documents
`SecCodeCopySigningInformation` with `kSecCSSigningInformation` after successful
validity checking, including `kSecCodeInfoCMS`, `kSecCodeInfoUnique`, static flags
and secure timestamp. Compare the CMS and directory identity from the same validated
static-code object with the captured bytes. This is an investigation, not an accepted
race-free binding: object caching, exact field types and native behavior still need
review and adversarial tests. The currently cached security-framework 3.7.0 wrapper
offers static-code construction/validity checking but not this information API;
do not substitute private framework fields or claim an existing safe binding.

Apple's published [StaticCode implementation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/StaticCode.cpp)
caches the CMS and directory digest in the static-code object; signing-information
uses those accessors. Its validity result is also cached. This supports investigating
one-object verification followed by exact CMS/digest comparison, but is not a
guarantee that every supported OS implementation has identical behavior. Reject
missing fields: the information path can suppress internal errors and return a
partial dictionary. Never request Apple's internal-information flags to extract
undocumented fields. Native substitution tests and a bounded helper remain necessary.

The shared parser now also returns an `AppleSignatureCandidate` containing the
directory digest and SHA-256 of the raw CMS content (without its Mach-O wrapper).
It refuses missing, empty, mistagged, duplicate or overlapping CMS containers. One
regression changes only same-length CMS content and proves the directory digest
stays identical while the CMS fingerprint changes. The fixture deliberately has no
valid CMS signature: this API captures bytes, not trust. The public RC2 test still
authenticates provenance first and never executes the installer. Native validation,
metadata interpretation, timestamp policy and retained-object binding remain open.

After PR #36 merged the separately reviewed faster-hex advisory fix, the combined
lockfile differs from that main revision only by the reviewed object 0.40.0 addition.
Its reviewed BLAKE3 is now
`929142b0a98de214b042913d1f083ddd9e93fcddf18cf1d5d86c70ac8b3578f1`.
The earlier d0223b11 digest above records the pre-advisory-fix evaluation, not the
current graph. Six candidate tests, strict focused Clippy and the independently
authenticated RC2 test pass with CMS capture; no native readiness is inferred.
Rerun canonical validation against the combined graph before pushing this branch.

## Captured metadata and supported API probe

The candidate parser now checks SHA-256 special slots against complete captured
requirements/XML-entitlements/DER-entitlements blobs. It permits only those embedded
slots plus the primary directory and CMS, with matching magic tags; external
Info.plist/resources and launch-constraint layouts fail closed. Absent slots must
have zero hashes, present blobs must be covered, and counts are bounded to seven.
Missing, substituted, unsigned and unsupported metadata are covered by regression
tests. The authenticated public RC2 arm64 artifact still passes this narrower policy.
These are hash-consistency checks, not interpretation or cryptographic trust.

A read-only Swift probe on trusted system `/usr/bin/true` successfully called
`SecStaticCodeCreateWithPath`, `SecStaticCodeCheckValidity`, and then
`SecCodeCopySigningInformation` on the same object, using default flags and no
publisher requirement solely to exercise the supported API. It returned a 20-byte CDHash
and 4567 CMS bytes, but no secure timestamp. That last result must be refused by
Kitrove's Developer ID policy, not treated as permission to relax timestamp checks.
No downloaded product was executed; no signing or credentials were used. Swift is
only a development probe, not a proposed consumer dependency or shipped verifier.

Implementation direction: the maintained security-framework 3.7.0 wrapper supports
Rust 1.85, static-code creation, requirements and validity checks. Its missing
signing-information function needs a narrowly isolated binding to the documented
public API, with Core Foundation ownership/type checks, similar in scope to the
existing isolated Windows native boundary. Any such helper must stay behind the
closed, deadline-bounded process boundary in ADR-0045. This direction is not yet
integrated into consumer readiness; native substitution tests remain open.

Dependency identity/license review: Cargo.lock adds only `object` 0.40.0 from
crates.io, checksum `dd229a0361b9d0d4396176e02d65897f487eebeab7caa6d443855ee152ca0b9c`.
Package metadata points to `gimli-rs/object`, declares Rust 1.85 and
`Apache-2.0 OR MIT`; its shipped license files match that declaration. The selected
normal/build graph contains only the already locked `memchr` 2.8.3. The reviewed
lockfile BLAKE3 is `d0223b11a4be709b7212a0707edaa91e3b678a563a04abdc6aa061d842c777ca`.
The first canonical run reached the expected old-digest gate; update the review
constant only after this inventory check, then rerun validation.

The fresh advisory audit returned success but reported RUSTSEC-2026-0306 on the
pre-existing `faster-hex` 0.10.0 Git dependency. Its advisory identifies an x86/x86_64
AVX2 over-read in `hex_decode_unchecked`, patched in 0.10.1. This is separate from the
new parser and must be followed up before release acceptance; an audit success exit
does not resolve this informational unsoundness warning.

## Isolated public Apple API implementation

`kitrove-macos-signature` now uses the maintained wrappers for static-code creation,
strict publisher validation and Core Foundation ownership. Its isolated binding
adds only the missing public signing-information function and four public keys.
It queries the same validated object, requires typed CDHash/CMS/flags/timestamp
values, matches both captured fingerprints, requires hardened runtime and refuses
missing, nonfinite or wrong-typed timestamp evidence. No internal flags, process
launches, installer readiness tokens or publication operations are exposed.

The native dictionary tests cover missing and wrong-typed fields, mismatched hashes,
empty CMS, malformed directory length, invalid flags and nonfinite dates. Their
synthetic CMS is deliberately not trusted. Rust 1.85 tests pass. The ignored operator
test independently authenticates the public RC2 archive before native inspection;
strict publisher validation and every captured-field comparison passed without
executing the downloaded installer. This is existing-host API evidence, not a
bounded consumer-helper or clean-machine acceptance result.

Dependency review adds three crates.io packages: core-foundation 0.10.1
(`b2a6cd9ae233e7f62ba4e9353e81a88df7fc8a5987b8d445b4d90c879bd156f6`),
security-framework 3.7.0
(`b7f4bc775c73d9a02cde8bf7b2ec4c9d12743edf609006c7facc23998404cd1d`),
and security-framework-sys 2.17.0
(`6ce2691df843ecc5d231c0b14ece2acc3efb62c0a398c7e1d875f3983ce020e3`).
Their upstream identities are servo/core-foundation-rs and
kornelski/rust-security-framework; shipped MIT and Apache-2.0 licenses match
metadata. All declare no build script and Rust minimums at or below 1.85.
Other dependencies reuse locked versions; default security-framework features are
disabled. The exact reviewed lockfile BLAKE3 is now
`6650de88e6f6eabc8674abc286d5b56385fcef4ff84fb28e0f6b84b0e50486bc`.
The fresh advisory audit passes without the earlier faster-hex warning, already
fixed separately in PR #36. Earlier digests above are historical checkpoints.

Remaining integration work: closed helper framing, process deadline/output bounds,
retained-object revalidation and adversarial file/CMS/metadata substitution tests.
Native API success alone must never grant executable or installation authority.

## Native sequential substitution evidence

The ignored, independently authenticated RC2 arm64 operator test now also checks:

- A valid payload refuses a candidate with the same CDHash but a different CMS hash.
- A same-length CMS mutation is refused even when the supplied candidate fingerprints
  match those mutated bytes. Fingerprint agreement cannot substitute for native trust.
- Changing a byte in the signed prefix outside the Mach-O header fails both the
  captured-code parser and native verification with the original candidate.
- Retained payload revalidation refuses both on-disk mutations, and dropping the
  staging handle preserves the test payload until its owning temporary directory
  cleans it up.

The signature mutation targets the last nonzero byte of this exact digest-pinned
fixture. Assertions establish that it changes only the captured CMS fingerprint,
not the CDHash; it is not a general Mach-O parsing strategy. All native assertions
pass on the existing arm64 Mac without executing the downloaded installer. These
are sequential substitutions, not a concurrent path-swap or helper-cleanup proof.

Process reuse review: the existing Unix lifecycle and bounded readers are private
to version-probe, but still use its version-specific error types and deadline.
Reuse the lifecycle with explicit closed-operation limits; do not route native
inspection through `probe_version`, whose `--version` argument, shebang support,
PATH and inherited home/temp environment are inappropriate for a verification
helper. Helper executable trust and retained identity need their own checks before
launch. No process allowlist or consumer readiness was changed in this test unit.
