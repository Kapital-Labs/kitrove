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

This deliberately does not validate CMS, timestamps or special slots. In particular,
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
