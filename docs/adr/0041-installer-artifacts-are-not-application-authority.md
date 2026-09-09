# ADR-0041: Installer artifacts are not application replacement authority

- **Status:** Accepted for Phase 6 implementation; publication remains gated
- **Date:** 2026-09-06
- **Deciders:** Implementation decision within the approved Phase 6 distribution scope
- **North Star invariants:** NS-07, NS-09

## Context

ADR-0040 requires a separately verified installer executable. Existing archive policy
accepts only application artifacts and an application compatibility manifest. Adding
installer filenames to that application catalog would allow the wrong product to cross
the application authentication boundary. Copying archive decoders would duplicate the
security-sensitive limits, path checks and complete-stream validation.

## Decision

Installer archives have a separate closed four-target catalog and opaque inspected-release
type. Public APIs expose no conversion to application archive specs, intake, authenticated
executables or rollback material. Internal layout reuse may invoke the existing bounded
archive decoders, but the wrapper never exports their application-shaped internal values.

Installer archives use `kitrove-installer-TARGET.tar.xz` with a matching root on Unix and
`kitrove-installer-x86_64-pc-windows-msvc.zip` with a flat layout on Windows. They contain
exactly `kitrove-installer` (or `.exe`) and the existing six release companions. The
`kitrove-release.json` companion is an installer-specific schema-1 document with exactly:
`schema`, `artifact_kind` (the fixed string `installer`), `release_version`, `target`,
`executable_name`, and `executable_sha256`. It makes no application-state or rollback
compatibility claims. The existing application manifest and its parser are unchanged.

Manifest parsing is bounded and strict, and binds the selected installer target/name.
Validation additionally binds the expected release version and executable bytes from the
same archive snapshot. This remains structural evidence, not cryptographic authentication.
Bootstrap must independently authenticate the installer archive before execution using
the exact release-workflow/tag/commit policy. Runtime application intake stays distinct.

## Alternatives considered

- A permissive shared executable-name parameter would erase the product boundary.
- An application compatibility manifest for the installer would make misleading claims.
- Separate tar/ZIP security implementations would duplicate policy and invite drift.

## Consequences

### Positive

The original application format remains stable. Installer archives share the reviewed
resource, path, permission and stream checks without becoming application authority.

### Negative

Publication tools must explicitly support both artifact families and their manifests.

Exact binary selections are package-local. cargo-dist 0.32.0 applies a workspace binary
override to both products, which would put both executables in both archives. Governance
therefore rejects workspace binary overrides and requires the exact single-product binary
map for all four targets in each distributable package. Application and installer archives
receive separate single-subject attestations.

### Follow-up

Integrate both catalogs into exact packaging/checksum/attestation inventories, update
bootstrap documentation, and exercise native acceptance before any release publication.

### Public identity and offline bootstrap verification (2026-09-07)

The maintainer selected and authorized creation of the fresh public repository
`Kapital-Labs/kitrove`. GitHub reports repository ID `1360443188` and organization
ID `320223113`. Release policy pins both immutable IDs, their exact URI/slug,
the existing release workflow, public visibility, hosted runner and push trigger.
The private development repository is not an alternative release authority.
Repository transfers, renames or recreation require a reviewed policy change.

Installer provenance verification consumes the opaque inspected installer archive,
validates its exact version and executable digest, and uses the same offline
Sigstore and certificate/statement policy as application verification. Its opaque
authenticated result retains those inspected bytes and has no conversion into an
application subject, replacement executable or rollback material. It neither writes
nor executes files. A previously trusted verifier is still required to authenticate
the first downloaded installer; this API alone does not solve bootstrap acquisition.
Source publication, signing and real public-release acceptance remain gated.

### Exact JSONL bundle handoff

A separate read-only selection operation accepts GitHub CLI attestation-download
JSONL: at most 32 records, each at most 256 KiB, and at most 8 MiB total.
Each nonempty line must be a supported strict bundle; malformed records, blank
records, duplicate JSON keys and unsupported bundle shapes reject the collection.
LF and CRLF framing and one final newline are accepted without rewriting JSON.
Every candidate passes through the same offline verifier. Structurally valid but
nonmatching or invalidly signed candidates confer no authority. Exactly one must
authenticate the selected archive, workflow, repository identity, tag and commit;
zero or multiple matches (including identical duplicates) fail closed.

Selection returns only the exact selected JSON bytes, not a saved authorization.
Installation and recovery continue to verify that single bundle freshly. Read-only
`select-application-bundle` and `select-installer-bundle` commands share retained
file capture, exact release-option parsing and the compiled platform catalog. They
take no destination, state roots or operation ID, create no files, execute nothing,
and emit the selected bundle only after both inputs have been revalidated. They
require an independently trusted or reviewed-source-built installer to run.

## Validation

Test all four exact catalogs, manifest field/schema/target/name/version/digest refusals,
cross-family rejection, archive byte binding and existing archive conformance fixtures.
Require that no public conversion exposes installer material as application intake.

Implementation checkpoint: 49 release-policy unit tests, the existing shared
archive conformance corpus, a compile-fail application/installer type-separation test,
and all-target release-policy Clippy passed. Connected publication tooling, a real
macOS packaging rehearsal, canonical repository validation and pre-push host/Windows
Rust 1.85 checks passed; see the installer-packaging review record. Full-matrix release
acceptance and authenticated bootstrap remain outstanding.

## Supersession

Extends ADR-0040 for installer packaging only; does not change its replacement guarantees.
