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

## Closed Apple request framing

The native crate now encodes and decodes one binary request version: eight-byte
`KRVAM001` discriminator, two-byte big-endian path length, 20-byte CDHash, 32-byte
CMS SHA-256, then native Unix path bytes. Total input is capped at 4158 bytes;
decoding borrows the validated buffer and requires exact length with no suffix.
Paths must be absolute, nonempty, NUL-free, at most 4096 bytes, and contain no empty,
dot or parent components. Non-UTF-8 names round-trip without lossy conversion.

There are no caller-selected operations, tools, arguments, environment settings or
publisher overrides. Decoded fingerprints remain claims, not verified candidates
or readiness receipts. The direct and framed APIs share the same native validation
implementation. Tests cover every truncation of a valid frame, malformed version
and length fields, trailing/oversized input, ambiguous paths and exact bounds.

The operator RC2 test exercises native positive and sequential-substitution cases
through this framing. This is still an in-process operator call, not production
helper isolation. A transport must enforce the exported bound before collecting
input, bound writes and native execution time, and establish trusted helper identity
and cleanup. No launcher, helper CLI entry point or installer authority is added.

## Operation-neutral private lifecycle outcomes

The private Unix lifecycle and bounded-output collectors no longer depend on the
version probe's timeout constants or user-facing errors. Their caller supplies the
wait duration, stream cap and reader receive duration. A private five-variant
`InspectionFailure` separates failed operations, timeouts, cleanup failures, excess
output and invalid output; the version probe maps these back to its exact existing
error codes/messages. The Windows Job result uses that same mapping, retaining the
existing native Job implementation.

Version calls still supply the same constants. Process-group setup, signal/reap
ordering, Drop behavior, stream collection and Windows launch policy are unchanged.
These helpers remain private, with no arbitrary public launcher or process allowlist
change. Tests pin every version-error mapping and cover caller-supplied zero/small
output limits, exact/overflow bounds, ready and expired reader channels, alongside
the existing timeout and descendant-cleanup regressions. This enables the next
closed caller without granting native readiness or claiming a new helper deadline.

## Child-side bounded transport

The native crate can now serve exactly one inspection frame from a reader. It
collects at most the request bound plus one overflow byte, validates the exact frame,
and emits one fixed acknowledgement only after native validation succeeds. Read,
write and flush failures return the same redacted refusal. A partial or complete
acknowledgement is not proof by itself: the future parent must also require a trusted
child, empty stderr, successful exit and confirmed cleanup. Input EOF and blocking
native calls still require the parent's wall-clock deadline.

Tests cover endless oversized input, bounded consumption, failed reads, exact output,
write/flush failures, and no acknowledgement on refused input. The authenticated RC2
operator fixture uses this transport in-process, checking exact success output and
empty output on native refusal. This neither launches a helper nor proves isolation.

A read-only launch experiment opened the trusted system `/usr/bin/true` and attempted
to execute `/dev/fd/3` from `zsh`; this Mac refused with permission denied (exit 126).
Do not infer that descriptor-path execution is a supported helper binding mechanism.
No downloaded program was executed. Trusted helper resolution and concurrent
substitution-safe launch remain unresolved implementation work; no fallback to
arbitrary paths or to checksum-only readiness was introduced.

The initial canonical run stopped at the source side-effect sentinel because it
classifies `write_all` as filesystem mutation. The reviewed adjustment allows only
that token in this exact protocol file for the fixed acknowledgement stream; it
does not add the file to the filesystem-mutation allowlist. Regression tests refuse
file creation, writable opens, network access and process launch in the protocol,
and still refuse stream writes in adjacent files. A fresh canonical run is required
after this narrow governance change.

## Suspended-process validation experiment

The installed public SDK exposes `POSIX_SPAWN_START_SUSPENDED`. A development-only
Swift experiment spawned Apple's installed `/usr/bin/true` with this flag and an
empty environment, obtained its dynamic code object by PID, and checked `anchor
apple`. The native check succeeded; an all-zero CDHash requirement failed with
`-67050`. The experiment never resumed the child and explicitly killed and reaped it.
No downloaded artifact, credentials or signing operation was involved.

A second experiment used the installed `/usr/bin/codesign --verify -R REQUIREMENT PID`
on another suspended system `true` child, with empty environment and discarded output.
The Apple requirement returned zero; the wrong CDHash returned 3. A nonblocking wait
confirmed the child had not exited, and explicit kill/reap completed. The installed
codesign manual documents PID verification as dynamic validation. These development
experiments used direct waits, not the proposed production deadline implementation.

[Apple's dynamic validation documentation](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
describes checking the host-reported validity and required identity while resisting
changes to filesystem source. In contrast,
[signing-information lookup](https://developer.apple.com/documentation/security/seccodecopysigninginformation(_:_:_:))
can still return static data from disk for a dynamic object. Lookup alone therefore
cannot establish the executing helper's identity.

Candidate direction, not yet accepted runtime implementation: obtain an independently
bound identity for the trusted first verifier, start its helper suspended, and use the
fixed system codesign verifier under existing process deadlines to validate the
retained child's exact identity before resume. Root-controlled verifier resolution,
suspension-before-user-code guarantees, trusted-self identity acquisition, PID lifetime,
bounded input/output, cleanup on every refusal and concurrent substitution tests
must all be established. An Apple-anchor success in this experiment does not prove
Kitrove helper identity. Do not run an unverified helper and check it afterward, use
private code-signing syscalls, or treat this experiment as consumer readiness.

## Exact process-identity candidate

Shared native policy now captures one canonical 40-character lowercase CDHash from
at most 4096 bytes of UTF-8 display text. Missing, duplicate, malformed, oversized,
NUL-containing and requirement-injection inputs fail closed. A private field prevents
construction with arbitrary requirement syntax; the only output is the exact inline
CDHash requirement. The type deliberately grants no trust and has no debug formatter
that could expose the surrounding display output. Display is not verification, and
this type does not establish the initial verifier's trust or digest algorithm policy.

An additional development experiment captured the installed system `true` CDHash,
then used that exact requirement with the fixed system codesign verifier against
suspended `true` and `false` children. The matching child returned zero and the other
Apple binary returned 3. Both children were killed and reaped without resumption.
This demonstrates exact identity discrimination, not merely an Apple-publisher check;
it does not yet establish trusted Kitrove self-identity acquisition, bounded launch,
or concurrent replacement resistance. No downloaded artifact was executed.

## Suspended-self lifecycle checkpoint

`kitrove-macos-process` creates only a suspended copy of the current executable,
using a fixed internal argument, empty environment, `/` working directory, null
standard streams, close-on-exec-by-default and a new process group. Its public API
has no resume method and takes no executable path, arguments or environment. It
retains child ownership until explicit termination/reaping or best-effort Drop.
Cleanup signals the group before nonblocking exact-child waits, with a five-second
wait budget per attempt; a failure is reported rather than treated as readiness.
Drop can retry cleanup, but cannot report success or guarantee cleanup after an OS
failure. Callers must not externally reap the owned child or change SIGCHLD handling
while it is owned. Review found that automatic child reaping could otherwise release
the retained PID before cleanup. Launch now queries the parent signal disposition
without changing it and refuses ignored/custom SIGCHLD handlers or `SA_NOCLDWAIT`.
A regression test covers each refusal and the default accepted policy. This is a
caller lifetime contract, not synchronization against other threads changing signals.

The native tests confirm a distinct child process group, no child exit before
termination, explicit kill/reap and Drop reaping. These are not proof that an
untrusted image can safely resume; no resume or consumer linkage exists. The
current-executable path remains an untrusted selection until dynamic identity checks
are implemented. The native primitive exists because Rust's `Child` cannot be
constructed from a raw `posix_spawn` PID; shared parent stream/error policy remains
separate rather than pretending the handles are interchangeable.

The initial missing public libc binding was `posix_spawn_file_actions_addchdir_np`,
declared in the installed SDK for macOS 10.15+. The availability checkpoint below
replaces the initial strong import. No current release executable depends on this
crate, and older-host runtime acceptance remains unobserved.
Governance recognizes the native spawn token and permits it only in this exact
reviewed source; adjacent files and generic process/network/filesystem operations
remain refused by regression tests.

The lockfile adds only this workspace package and its edge to already-reviewed
libc 0.2.189: no third-party package, version or checksum changes. The reviewed
lockfile BLAKE3 becomes
`859b33abc314a35838f96bf863d32d4cfa5050cf6b7849a3e57611fcf5be54d6`.

## Fixed system-verifier filesystem selection

`SystemVerifier` retains handles for `/`, `usr`, `bin`, and `codesign`, opening each
component relative to its retained parent with no-follow, nonblocking, close-on-exec
flags. Directories additionally require directory-only opens. Selection accepts only
root-owned objects with the expected type, executable/search permissions, no group
or other write permission, and no set-ID bits. The executable must be nonempty and
at most 16 MiB. There is no PATH search or caller-selected location.

The existing `calcifer-macos-acl` handle reader and canonical empty predicate enforce
an empty ACL on every object; no ACL parser is duplicated. This is intentionally
stricter than user-state ancestry's deny-only ACL policy or version-probe ownership
rules. No permissions are repaired. Identity includes device/inode, size, ownership,
mode, link count, and nanosecond modification/change times. Inspection brackets ACL
reading with metadata checks. Revalidation both reinspects retained handles and
reopens the fixed chain, requiring every identity to match.

Tests cover unsafe metadata and retained-identity mismatches at every chain position,
plus read-only selection/revalidation of the installed system verifier. They do not
execute codesign, replace system files, prove concurrent substitution resistance, or
establish a helper signature. This is filesystem evidence only; privileged OS changes
remain outside the guarantee. Process identity validation and bounded execution must
still be connected before a helper can resume or consumer readiness can be issued.

Dependency review adds only edges to already-locked `rustix` and
`calcifer-macos-acl`; no third-party version or checksum changes. The reviewed
lockfile BLAKE3 is now
`0b82ff2c03cc11643a69727ff4b976ffe0c25e56ac9e7e25e074c54c02a3b600`.

## Bounded shared Unix cleanup

Review of the shared probe lifecycle found that a bounded inspection could still
enter an unbounded `Child::wait` during termination or Drop. Both cleanup paths now
reuse one private nonblocking `Child::try_wait` loop with an absolute deadline.
The cleanup attempt has a five-second budget and records reaping only after an
observed child exit. Timeout or wait failure returns the existing cleanup refusal;
Drop may retry once with the same finite budget and cannot grant success.

The cleanup budget is separate from the operation deadline, not a claim that the
whole operation finishes within five seconds. An OS that cannot terminate/reap its
child can still leave unresolved cleanup; this must refuse consumer readiness.
Review also found that `wait-timeout` installs a process-wide SIGCHLD handler, which
conflicts with suspended-self ownership policy. The shared normal wait and cleanup
now use the same polling loop without installing signal handlers. The direct
dependency was removed; no new dependency, launch permission, command policy or
version-error code is added.
A native regression test expires a zero reaping budget on a retained system sleep
child, verifies ownership remains, then kills/reaps its group and checks that
repeated reaping is a no-op. Existing timeout/descendant tests remain in the suite.
On Mac the test then starts and terminates a suspended self in the same process,
checking compatibility with its SIGCHLD ownership guard. The macOS-only development
dependency does not wire suspended launch into production version probing.

Lock review removes `wait-timeout` 0.2.1 and adds only the workspace test edge to
`kitrove-macos-process`; no new third-party package/version/checksum is introduced.
The updated reviewed lockfile BLAKE3 is
`70dce02f2e4feba3ab2c94d1fcf926142b52c81bcc72a1d8cb09ca2bd33ff2b1`.

## Bounded native self/helper identity experiment

An ignored, operator-only Mac test now connects the retained fixed system verifier,
shared process lifecycle/output readers, canonical CDHash candidate, and suspended
self primitive. One 15-second operation deadline supplies the remaining budget to
each child wait and output receive, with the existing separate cleanup budgets.
Both streams are capped at 4096 bytes; environment is empty, cwd is `/`, stdin is
null, and every system-verifier operation is bracketed by retained revalidation.

The test captures current-process display metadata, dynamically verifies the
current PID against that candidate, and only then compares a suspended copy against
the same requirement. The correct identity succeeds with empty verifier output;
an all-zero identity is rejected. The child is explicitly killed/reaped before
asserting those outcomes and is never resumed. The test passed on the development
Mac using the reviewed-source test binary; no downloaded product was executed.

This is executable native evidence, not production integration or independent
bootstrap trust. The initial test executable is trusted through its reviewed-source
build, not through the display metadata. No generic runner is exported and no
production launch exception is broadened. Test-only module classification uses the
existing explicit cfg-test/path convention. Release linkage still requires resolving
the suspended primitive's macOS deployment minimum. Concurrent source substitution,
end-to-end transport and retained installer readiness remain unproved.

The lock adds only a macOS test edge to existing workspace release policy; no new
third-party packages, versions or checksums. Reviewed lockfile BLAKE3:
`96622894b7e98bb60e15b72742ac97005ff12e9e43321d8976dfe43fe91ef2b0`.

## Optional native spawn action availability

The Mac primitive now resolves only the fixed public
`posix_spawn_file_actions_addchdir_np` symbol through `dlsym(RTLD_DEFAULT, ...)`,
instead of importing it unconditionally. The null result refuses before native
attributes or a child are created; a nonnull result is converted to the exact
installed SDK C ABI inside the isolated unsafe boundary. No library is loaded,
no caller-selected symbol or path is accepted, and no minimum OS version changes.
Governance permits the lookup token only in the existing reviewed spawn source.

Apple's [dlsym manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dlsym.3.html)
documents fixed-name lookup among loaded images and a null result for absence.
This assumes the initial process and loaded runtime are already trusted, as the
other native calls do; it does not authenticate loader state or defeat in-process
interposition. The primitive still cannot resume a child.

Tests cover null-symbol refusal and actual suspended spawn/cleanup on this Mac.
The linked local test executable's undefined-symbol inspection found `_dlsym` and
no import of the optional spawn action. This validates the build shape and simulated
missing-symbol path, not operation on a real older Mac or clean-machine acceptance.

Apple's [public spawn-flags manual](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man3/posix_spawnattr_setflags.3)
documents that `POSIX_SPAWN_START_SUSPENDED` stops the child before user-space
execution, including early dyld work. It also specifies that `CLOEXEC_DEFAULT`
leaves only explicitly created file-action descriptors available. This establishes
the documented API contract for the chosen flags, not adversarial native acceptance
or permission to resume before exact identity verification.

## Retained group-anchor experiment

Review identified a window in ordinary `ProbeProcess` cleanup: reaping its leader
before signaling the remaining numeric group permits group-ID reuse after the group
empties. An attempted `waitid(..., NOWAIT)` ordering change was withdrawn: on this
Mac, signaling a group containing only an exited, unreaped child returned `EPERM`.
Accepting every permission error would hide real descendant cleanup failures.

The native test now uses a separate suspended self as the group leader and launches
the system verifier into its group. This anchor never runs user-space code and stays
owned after the verifier exits. Cleanup consumes the anchor, signaling its group
while the anchor is alive, then reaping it. No later path signals that numeric group
again. Error paths still refuse success and use the existing bounded direct-child
cleanup. The initial ownership/SIGCHLD contract remains necessary.

The anchor constructor and storage are Mac test-only. Normal production probes do
not acquire an anchor, so this does not claim the existing production race is fixed.
Shared cleanup now has one idempotent entry point for explicit termination and Drop;
output limits, deadlines and error mapping remain shared. The initial test-only
constructor required the caller to launch its child into the retained anchor's
group; the launch-boundary consolidation below removes that requirement. Production
integration must preserve that relationship, not accept arbitrary children or groups.

Native tests verify the anchor's group ownership after verifier reaping, timeout
cleanup, Drop reaping of both direct children, and SIGKILL delivery to another live
group member. The bounded native identity experiment also passes through this anchored
path, including wrong-identity refusal. These establish a viable local prototype,
not arbitrary descendant containment, concurrent-attacker resistance or readiness.
No new dependencies or release executable linkage are introduced.

An additional hostile-lifetime test kills the anchor after its verifier has exited,
observes the anchor exit without reaping, and requires cleanup refusal rather than
success. This exposed a resource leak in `SuspendedSelf`: returning immediately on
a failed group signal skipped reaping an already-dead owned child. It now attempts
one nonblocking reap even after signal failure, preserving the failure result and
disarming a reaped PID. It does not wait indefinitely or accept `EPERM` as success.
The regression confirms the dead anchor is reaped and its numeric group is not
signaled again. A still-live child that the OS refuses to terminate remains a
reported cleanup failure, not a successful or guaranteed cleanup.

The test-only lifecycle boundary now creates the anchor, assigns the command to
its group and immediately owns both children in one operation. The former
constructor accepting an independently spawned child and anchor is removed.
Group validation precedes launch; no fallible conversion follows a successful
spawn before cleanup ownership is established. A failed spawn drops its anchor.
Tests check that a caller's group selection is overridden and a missing executable
is refused, alongside the existing timeout, Drop and lost-anchor regressions.
This is ownership consolidation, not a public arbitrary-command API or production
activation. The fixed native verifier runner still needs production integration.

## Closed native identity library integration

The subsequent library checkpoint moves the tested native runner into
`apple_process_identity`. Its two public operations capture and dynamically check
the executing process's candidate, or check an owned `SuspendedSelf` against that
candidate. Neither accepts an executable path, argument list, environment override
or arbitrary PID. Native output stays private and errors are redacted. The native
operator test now calls these same production functions rather than a duplicate
runner. Correct identity passes; the wrong identity refuses. No child is resumed.

Each public operation has a 15-second inspection budget, shared across candidate
display and dynamic self validation where applicable. Shared output readers enforce
4096-byte bounds per stream. Successful verification requires zero exit status,
empty stdout and empty verification stderr, retained system-verifier revalidation
and completed group cleanup. Cleanup retains its separate finite budget; this is
not a strict whole-call wall-clock bound on synchronous filesystem or spawn calls.
The internal anchored launcher now serves this production path. Ordinary harness
probes still use their prior lifecycle; their group-reuse concern is not fixed here.

The existing Mac process and release-policy dependencies move from test-only to
Mac production dependencies, without changing the lockfile or adding third-party
packages. Governance explicitly permits launch in the closed native-policy module
and its private retained-lifecycle module, with adjacent-module rejection tests.
This is a reviewed authority extension for those two files, not a blanket exception.

The library is not yet connected to installer execution, a helper resume operation,
transport or consumer readiness. A dynamically matching candidate does not prove
provenance or independently trust the verifier's first execution. Retained input
binding, concurrent substitution tests, native Windows acceptance and clean-Mac
launch evidence remain separate requirements.

## Retained verified-child ownership

`prepare_verified_suspended_self` now captures and checks self identity, spawns the
fixed suspended self, and dynamically verifies that child under one shared inspection
deadline. Success returns an opaque owner of that exact child, not a boolean that
could be applied to another PID. There is no public constructor, child extraction,
clone or resume method. Explicit termination reports cleanup failure; dropping the
owner uses the existing best-effort cleanup. Refusal during binding also drops the
owned child. Shared private identity routines serve both borrowed inspection and
owned preparation, with no duplicate native verification implementation.

An expired-deadline regression confirms the refused child is reaped, and an
operator-only native test confirms dropping a successfully verified owner reaps
that same child. These checks do not establish transport, readiness, authenticated
payload binding or clean-machine acceptance. The first executing verifier still
requires independent trust. Helper transport and conditional resume remain absent.

## Withdrawn pipe transport experiment

A local pipe prototype passed nine native tests, including nonblocking parent I/O,
blocking child I/O, close-on-exec flags, input EOF and output EOF after suspended
child termination. Review nevertheless found a construction-time inheritance race:
temporary `pipe()` descriptors existed before close-on-exec duplication. Duplicating
above stdio also fixed an independent collision with initially closed descriptors
0 through 2, but did not eliminate the inheritance window.

The installed public SDK exposes `pipe`, not `pipe2`, and rustix 1.1.4 excludes
`pipe_with` on Apple. Apple's current [Swift System source](https://github.com/apple/swift-system/blob/main/Sources/System/FileDescriptor.swift)
marks its new pipe options API as macOS 27+, which is not a justification for
silently raising this project's platform requirements. The reviewed
[Rust 1.85 launch implementation](https://github.com/rust-lang/rust/blob/1.85.0/library/std/src/sys/pal/unix/process/process_unix.rs)
does not establish a universal close-all-descriptors contract for other concurrent
launches. Our suspended child's close-on-exec-default flag covers that child only.

The prototype was withdrawn, including its rustix feature change and public pipe
API. Previously validated identity and verified-child ownership code is unchanged.
There is no pipe transport in the current implementation and no request was sent
to a resumed helper. Passing final-descriptor tests was insufficient acceptance.

Before retrying, design and test a launch-synchronization boundary that covers every
Kitrove launch site and pipe-construction failure, with bounded lock acquisition
and no nested-lock deadlock. A mutex local to pipe creation is insufficient. Account
explicitly for foreign-library or embedding-runtime launches outside that boundary;
do not claim that a cooperative application lock controls arbitrary process code.
Alternatively use a supported atomic primitive without silently dropping support
for existing targets. Private Apple APIs and a best-effort flag fallback are excluded.

## Cooperative launch gate

A shared Mac launch guard now serializes the reviewed explicit launch sites:
suspended-self creation, the fixed native verifier's anchored launch and ordinary
Unix version/application probes on Mac. It uses bounded `try_lock` polling and
refuses expired, overflowing or poisoned acquisition. RAII releases the guard on
spawn failure and success. The anchor spawn releases its guard before verifier
launch acquires another; no guard is retained across child waits or output reads.
Tests cover contention refusal, release, expired/overflowing budgets and poisoning.

The gate does not itself enable pipe transport. Its eventual pipe-construction
caller must hold the same guard until temporary inheritable descriptors have closed,
and call a non-relocking internal spawn path. Synchronous spawn and filesystem calls
still do not have a hard wall-clock deadline. Existing operation deadlines remain
necessary after lock acquisition and spawn.

This is cooperative application serialization, not a universal OS inheritance
guarantee. Tests, dependencies, foreign code and embedding applications can spawn
without participating. The audited product source has the three explicit launch
paths above; that source inventory alone is not proof about every dependency's
runtime behavior. Before sensitive transport use, the standalone consumer's launch
contract must exclude uncoordinated spawning and validate the relevant dependency
paths. Do not expose the pipe prototype as generally safe library transport.

### Standalone installer dependency audit

At launch-gate commit `b836949`, offline locked Cargo metadata filtered to
`aarch64-apple-darwin` yielded a conservative normal-dependency closure of 182
packages. This includes procedural-macro dependencies, not just linked runtime
code. Searching their library sources for Command/process launch, fork/exec,
system and popen calls found declarations, examples and non-process methods
such as parser forks, plus one relevant platform fallback in rustix.

Rustix 1.1.4's Apple `utimensat` implementation can fork when the native function
is unavailable on pre-10.13 systems. The native helper already refuses hosts
without the public 10.15+ spawn chdir action, so this fallback is outside its
usable host range; it must not be silently ignored in broader platform claims.
The bundled AWS-LC and ring crypto source search found fork calls in tests and
fork-detection commentary, not an additional runtime launch call. The standalone
installer entry point is synchronous; no installer production thread-spawn call
was found. Its version-probe output-reader threads remain separate from launch.

This review supports a standalone-installer-specific cooperative contract, not a
proof about arbitrary native frameworks, generated code, future dependency changes
or embedding applications. Reaudit the closure when dependencies or entry-point
concurrency change. Before enabling pipe transport, add a regression that races
participating launch attempts with pipe creation, holds the gate through temporary
descriptor closure, and verifies failure cleanup without nested acquisition.
The general library must continue to state that uncoordinated foreign launches
are outside this contract. No pipe or resume path is enabled by this audit.

### Guarded pipe preparation checkpoint

The revised pipe preparation now acquires the shared launch guard before creating
any descriptors. Both pipe creation and the private suspended spawn require a
borrowed guard. The private spawn does not reacquire the mutex. Temporary original
pipe ends close during close-on-exec duplication, and child-side parent handles
close before the guard is released. RAII preserves this ordering on failures.
The ordinary null-stdio suspended spawn uses the same private implementation.

Parent endpoints are nonblocking, child endpoints remain blocking, all retained
sources are close-on-exec and above stdio, and request input closes independently
of retained stdout/stderr. Tests cover those flags, byte delivery, EOF and native
suspended-child cleanup. A competing native launch test remains pending while the
preparation guard is held, then completes after endpoints close and the guard drops.
Abandoning prepared pipes produces EOF without leaking child-side parent handles.

This API is only for the reviewed standalone cooperative-launch contract described
above, not arbitrary embedding code. It does not stop foreign launches, impose
protocol byte limits or provide a strict spawn wall-clock bound. The verified-owner
API, bounded protocol loop and resume step are still disconnected. No child was
resumed and no downloaded installer executed. The existing rustix pipe feature is
enabled again; the lockfile and third-party package set are unchanged.

### Verified owner retains transport

Verified preparation now creates the guarded suspended child and its pipes together,
then dynamically checks the child's identity before returning their opaque owner.
The public owner exposes neither descriptors nor child extraction, and still has no
resume operation. The same standalone cooperative-launch restriction applies.
Verification failure drops both resources; explicit termination closes parent ends
and confirms child reaping. Ordinary Drop remains bounded best-effort cleanup.

The expired-binding regression retains output observers and checks EOF and reaping
after refusal. Native operator tests check pending pipes before owner Drop, EOF and
reaping afterward, and the same cleanup after explicit termination. These observers
are test-only descriptor copies, not public output access. No request bytes were
sent and no helper resumed. A bounded protocol driver, authenticated payload binding
and conditional resume still remain; owned pipes are not a readiness receipt.

### Nonblocking request-write primitive

Transport now offers a checked write of at most 1024 bytes per call. It distinguishes
written bytes from pending backpressure/interruption, and refuses zero progress,
empty input, closed input and other errors. It does not treat a partial write as a
complete request; the future driver must retain its offset and enforce total input
limits and a deadline.

Before writing, it queries SIGPIPE handling and requires it to be ignored. No signal
handler is installed or changed. This avoids accepting a default/custom disposition
that could terminate the parent on a closed pipe. The reviewed caller must maintain
that disposition throughout transport use; a read-only check cannot prevent foreign
threads from changing it concurrently. This is an explicit standalone process
contract, not signal-race safety for arbitrary embeddings.

Tests cover the policy without modifying global handlers, bounded partial input,
closed-peer refusal and nonblocking backpressure. The primitive remains disconnected
from verified-owner request execution. No protocol success or resume is added.

### Nonblocking response-read primitive

One shared reader handles stdout and stderr without combining them. Each call reads
at most 1024 bytes into caller-owned storage, distinguishing bytes, pending input
and EOF. Empty buffers refuse so a zero-length read cannot masquerade as EOF.
Neither EOF nor a successful read establishes protocol success. Cumulative limits,
exact acknowledgement, an empty stderr, deadline, successful exit and confirmed
cleanup remain the driver's responsibility. The verified owner still exposes no
transport access or resume method.

Native pipe tests cover pending input on both streams, distinct stream contents,
bounded reads with untouched buffer tails, small buffers and draining bytes before
EOF after peer closure. No allocation, threads, launch authority or signal handling
is added by the reader.

### Shared response framing

The signature protocol now owns an allocation-free incremental response validator
beside its existing acknowledgement constant. It accepts only an exact prefix at
each step, so mismatches and excess bytes refuse without accumulating output.
Any stderr bytes, empty data events, premature or repeated EOF, and data after EOF
refuse permanently. Completion consumes the validator and requires both streams
to have reached EOF. Tests cover every acknowledgement split, bytewise input,
corruption at every byte, every truncated prefix, missing EOF and sticky refusal.

This validates framing only. It is not yet connected to the transport driver and
does not prove trusted execution, successful child exit, bounded lifetime, cleanup
or retained payload identity. Those checks must accompany framing before native
inspection can affect installer readiness. No helper is resumed by this change.

### Request progress and deadline

The same protocol module now owns one encoded request, its write offset and an
absolute deadline. Construction reuses the existing encoder and frame validation;
there is no second wire format or path parser. Reads of remaining bytes and progress
updates check the unchanged deadline. Pending writes do not advance the offset.
Zero, oversized or expired progress permanently refuses. Offset addition occurs
only after checking the remaining length, including hostile `usize::MAX` input.

Completion consumes the tracker and refuses partial input or expiry. Its name and
contract require the caller to close transport input first, but it cannot prove a
descriptor was closed. It is byte accounting, not a receipt for trusted execution.
The driver must supply observed write counts and retain its deadline through output,
exit and cleanup checks. No process or filesystem operation is introduced here.

### Cooperative exchange driver

The signature crate now combines the shared request/response states with the
existing nonblocking process transport. Each poll performs at most one write and
one read from each output stream, closes input immediately after the final observed
write, and checks the unchanged absolute deadline before and after the step.
Streams that reached EOF are not polled again. Refusal and completion are terminal;
subsequent polls refuse without further I/O. The private scripted-transport seam
tests partial writes, pending input, stream errors, closure ordering and bounded
work without starting or resuming an executable.

The public result is framing only, not native verification or installer readiness.
The future verified owner must bind the exact transport and exchange state, retain
the child, avoid busy polling and require successful exit, cleanup and payload
revalidation under the same operation deadline. This unit does not add that owner
integration or a resume path. A caller can supply a transport, but cannot select a
command, verification implementation or signature policy.

Dependency review: the lockfile adds only the existing workspace macos-process edge
to macos-signature. No package versions, registry identities or third-party packages
change. The reviewed lock digest is updated for that single edge. Existing process
launch and side-effect governance allowances remain unchanged.
