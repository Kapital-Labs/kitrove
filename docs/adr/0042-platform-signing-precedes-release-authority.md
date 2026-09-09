# ADR-0042: Platform signing precedes release authority

Status: Accepted for local Phase 6 implementation; hosted signing activation remains gated

## Decision

Release preparation signs an isolated copy of the structurally inspected executable,
verifies the native signature, and only then constructs the final release manifest,
archive, checksum and cargo-dist digest authority. Application and installer artifacts
use the same preparation machinery without merging their authentication roles.
Unsigned development packaging remains an explicitly different command. The release
workflow uses the signing-required command and never falls back to unsigned output.

Use Apple's system codesign/notarytool and Microsoft's SignTool/Artifact Signing
provider; do not implement certificate, signature or cloud authentication protocols.
macOS requires a Developer ID Application identity for the reviewed team, hardened
runtime, a secure timestamp and an Accepted notarization submission for the exact
signed executable. Standalone Mach-O files cannot carry stapled tickets; offline
Gatekeeper bootstrap remains a separate distribution acceptance gate.
Windows requires SHA-256 Authenticode and RFC3161 timestamping, verification under
the Windows Authenticode policy, and an exact expected publisher subject. Azure's
short-lived certificates are not pinned to a single leaf thumbprint. A Public Trust
profile and real native Windows evidence are required before release acceptance.

Signing credentials stay in the operator's Keychain or provider-managed key storage.
Only an existing Keychain profile name or public provider configuration enters the
tool invocation. No automatic enrollment, credential export, SDK installation, key
import, publication or signing-provider purchase is authorized by this implementation.
The initial hosted workflow fails closed until a separately approved secure runner
credential/tool provisioning step is integrated. Never point signing jobs at a
developer workstation or export keys just to satisfy the workflow.

## Impact

### Approved Apple credential custody and explicit Keychain selection

The operator separately approved storing the Developer ID PKCS12 and its wrapping
password, Apple ID/team, and a dedicated notarization password in the protected
`release` environment of `Kapital-Labs/kitrove`. The environment requires operator
review, disallows administrator bypass and normally permits only version tags.
The isolated credential check in run `34365796564` verified the exact certificate,
key pair and read-only notarization authentication. Temporary branch permission
and exact-SHA activation were removed afterward. This does not authorize publishing
the product source, activating production releases or claiming hosted signing
acceptance. The only public source approved so far is that credential-check workflow.

Release tooling may select an explicit absolute regular Keychain file through
`KITROVE_SIGNING_KEYCHAIN`. Both codesign and notarytool receive that same path;
the default remains unchanged. Codesign additionally requires temporary search-list
membership even with explicit selection. Hosted provisioning snapshots the old list,
appends only its own store and restores the list before deleting the store in finally.
Deletion is still attempted if restoration fails. An absent setting preserves local
operator behavior, but an empty, relative, symlinked or non-file setting fails
closed rather than falling back. Hosted provisioning must set this explicitly,
create/unlock only its temporary store, and remove it on success or failure.
The isolated hosted native rehearsal `34378308650` passed actual signing, exact
team/runtime/timestamp verification, Accepted notarization and cleanup for a tiny
test executable. Its temporary branch permission and activation were removed.
This expands the approved public source only to that isolated workflow and helpers,
not product source or history. Actual Kitrove archive rehearsal remains required.

The private production workflow now integrates the proven lifecycle through an
operator-only Python wrapper and native Swift import helper. Compile the helper
and xtask before the credential-bearing step. Remove credential environment values
before child processes; deliver import passwords through stdin and notarization
passwords only through a no-echo terminal. Invoke the prebuilt xtask for exactly the
CLI and installer archives derived from the supported target, retaining its archive
validation, signature checks and manifest binding. Never execute either product.
Cleanup completes before verification/staging/attestation. Failure stops the job;
there is no unsigned fallback. Runner destruction covers abrupt cancellation.
Production activation, Windows production provisioning, source publication and
real artifact acceptance remain gated. Ordinary CI uses synthetic mocks only.

### Approved private Windows rehearsal

The operator separately approved a bounded Windows GitHub Actions rehearsal and
the Microsoft SDK/client licenses. Only the private development repository's
`windows-signing-rehearsal` environment may exchange GitHub OIDC for the dedicated
Azure application. Its deployment policy permits only `test/windows-signing-rehearsal`;
the workflow additionally requires an exact operator-selected commit SHA. Azure
grants only Certificate Profile Signer on `kitrove-public`, not account management.
Build on a separate runner without OIDC, transfer an exact digest-bound inventory,
and authenticate only after checksum-pinned tools and the inventory are verified.
Do not execute product binaries in the authenticated job. Clear Azure authentication
afterward, retain private evidence briefly, and disable federation after the test.
This does not activate the release workflow, public publication, or Apple key export.

A signing-only retry may reuse the already verified build from run `34303342930`,
attempt 1, source `8aab6ebe028e99bb45f963cdfa4c540cd0dd307d`. Pin its inventory
SHA-256 (`d4864a9be93294a2d7b35d85c3de7da62a18edd22cc01272469ce730e1131e27`)
in the reviewed workflow, not a caller-supplied value. Record build and signing
workflow commits separately. The source SHA activation guard still applies to
the signing workflow; reuse grants no authority to arbitrary prior artifacts.

After the DOS ZIP fix, supersede that reuse pin with run `34305010454`, attempt 1,
source `65af48a7c8e94da59311530c19505ea350b6dcb3`, inventory SHA-256
`9766889ea7d2acd58afb5bd25b54c3b0454771ce30210f7eb7ee0966130d5e57`.
A bounded publisher diagnostic may sign an isolated, structurally verified CLI
copy and inspect only public certificate fields under both Windows PowerShell
and PowerShell 7. It must not execute the CLI or emit token/provider diagnostics,
and it is not successful production archive preparation.

NS-07/NS-09 and INV-07/INV-12: release credentials never enter portable state,
source or logs. Only operator-requested release tooling invokes platform signing
tools and uploads the isolated release executable to Apple's notary service.
Discovery/adoption, portable/native preservation, fidelity, receipts, synchronization
and conflict behavior are unchanged. Native signatures supplement, not replace,
ADR-0040/0041 exact GitHub provenance and rollback authority.

## Native Windows ZIP origin attributes

Native cargo-dist Windows ZIPs identify their origin as DOS while retaining
regular-file Unix attribute bits. Accept this file-only form using the ZIP
library's documented DOS read-only interpretation; reject DOS directory, volume,
device or unknown attributes and conflicting high-word nonregular types. Unix
entries retain their existing type checks. Unknown origin systems fail closed.
The independent Python verifier applies the same file-only origin policy.

## Validation and limits

Require target/host mismatch and missing-configuration refusal, native signature and
notary rejection propagation, exact post-signing digest binding for both product
families and archive formats, and unchanged input archives on signing failure.
Signing tools are trusted local prerequisites; hostile same-user processes and a
compromised release runner are outside this build-tool isolation boundary. No
generated release binary is executed by preparation. Signing timestamps mean final
signed bytes are not promised to be bit-for-bit reproducible across signing runs.

Pinned cargo-dist 0.32.0 source has Apple and SSL.com backends, not the Azure backend
described by newer documentation. Its Apple backend imports an exported key and
does not notarize. Reuse its packaging, but call native signing separately rather
than silently enabling unavailable or insufficient functionality.
