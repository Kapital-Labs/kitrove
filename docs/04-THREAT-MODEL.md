# Threat Model

**Status:** Public-alpha release-candidate threat model
**Review trigger:** Any new source type, executable capability, sync backend, secret resolver, or public adapter interface.

## Security objective

Move agent capabilities without turning synchronization into a path for credential theft, arbitrary code execution, silent instruction injection, or destructive filesystem mutation.

## Protected assets

Harness credentials, API keys, private sources, work/personal identity boundaries, portable-state integrity, harness configuration integrity, trust decisions, provenance, receipts, release signing identities and keys, private development history, and the filesystem outside managed destinations.

## Trust boundaries

```text
remote source -> resolver -> untrusted captured object -> inspect/classify -> trust -> staging -> managed destination
remote sync state -> transport -> semantic merge -> local portable state
local binding resolver -> transient secret -> target process/config
verified executable object -> machine-local exact-content trust -> fresh plan -> recovery journal -> Pi auto-discovery root
private staging tree -> approved source manifest -> materialized clean tree -> secret scan -> fresh public repository
reviewed source revision -> pinned CI workflow -> release build -> signing identity -> public artifact
```

## Adversaries and failures

Malicious publishers, compromised repositories, careless collaborators, accidental credential capture, generated-state scanning, path traversal, source-layout aliasing, malicious plugins/hooks, receipt or recovery-journal tampering, stale or over-broad executable trust, adapter deletion bugs, merge bugs, stale harness assumptions, active probe execution, lockfile substitution, private-history disclosure, compromised CI dependencies, release-artifact substitution, signing-key exposure, and secret leakage through logs or process arguments.

## Content classes

- **Data-only:** static content; still capable of influencing an agent.
- **Agent-active:** instructions, skills, prompts, and agents.
- **Executable:** hooks, plugins, extensions, scripts, binaries, installers, and lifecycle commands.

## Key threats and mitigations

### Credential synchronization

Use explicit portable/local schemas, adapter exclusions, known-auth path deny rules, canary secret tests, symbolic bindings, redaction, and a future `inspect-portable` command.

### Arbitrary upstream execution

Fetch and inspect without execution; inventory executable content; require local trust; support exact-hash trust; never run arbitrary installers automatically.

### Executable trust inheritance

Trust only the independently verified exact native object hash in machine-local state. Bind layout, paths, modes, bytes, entrypoint, and native identity into that object. A changed object returns to unreviewed, denial overrides prior trust, and portable synchronization never transports or infers the decision.

### Auto-discovered executable placement

Keep preservation, trust, and destination mutation as separate confirmations. Re-verify trust before selecting or mutating the destination; confine the first supported target to the compiled Pi user-extension root; require receipt ownership for replacement; never launch Pi, import TypeScript, resolve modules, or install dependencies.

### Local transaction substitution

Serialize trust, adoption, skill, extension, and synchronization mutations through the reviewed local-state interlock. Bind recovery journals to the complete old/new authority tuple, exact staged hashes, operation policy, and confined paths. Unknown, malformed, cross-operation, redirected, or concurrently changed recovery evidence fails closed without deleting it.

### Prompt supply-chain attack

Classify Markdown instructions as agent-active, retain provenance and diffs, pin sources, and never equate text-only with safe.

### Path traversal and symlink escape

Normalize paths, reject absolute and parent-traversal entries, inspect symlinks, stage in isolated directories, and test cross-platform edge cases.

### Aggregate scan exhaustion

Bound discovery globally and apply request-wide capture file-attempt and byte budgets in addition to per-candidate limits. Repeated reads through overlapping roots consume the global budget again. When capture capacity is exhausted, stop opening content and retain remaining safe locators as unknown.

### Unreadable managed-instruction output

Refuse insertion when a co-owned document has reached its existing managed-region
ceiling. Single and coalesced planners share that pure guard before mutation;
same-region updates remain allowed and all surrounding bytes are preserved.
Do not raise limits, truncate another region or repair invalid input implicitly.
See ADR-0064.

### Profile graph stack exhaustion

Validate flat profile-parent graphs iteratively with completed-node memoization
and per-walk cycle detection. A valid deep chain must not exhaust the native
thread stack, and deep or disconnected cycles still return the existing closed
validation error. Intake byte/record limits remain unchanged. See ADR-0063.

### Source-layout aliasing

Include the layout tag, original document name, modes, and raw bytes in exact identity. Keep portable projection identity separate. A standalone file cannot satisfy a directory receipt through equal portable content.

### Destructive ownership mistake

Require receipts, compare hashes, plan destructive operations, preserve backups, and treat unmanaged content as advisory rather than removable.

Atomic-batch rollback resumes only persisted journal progress after interruption;
it does not repeat prohibited transitions or broaden destination ownership.
Target removal/restoration and terminal artifact cleanup retain exact identity
checks and never overwrite later user changes. See ADR-0062.

### Silent capability loss

Require fidelity results and structured reasons, golden and round-trip tests, and native preservation.

Portable skill projection reports omitted native-only frontmatter with a fixed
redacted reason. Adoption consumes the projector's complete loss report;
cross-harness results cannot claim full portability after such an omission.
Exact native source bytes remain preserved. See ADR-0060.

Present MCP activation switches must be booleans. Malformed values block portable
intake and exact-native object decoding rather than becoming an enabled portable
declaration. Diagnostics retain fixed reasons, not authored values. See ADR-0061.

### Sync-state compromise

Use hashes and immutable resolutions, review executable changes, retain provenance, and add optional signing only after the core model is stable.

### Private history or source-boundary disclosure

Never change the private staging repository's visibility or publish filtered history. Materialize a fresh tree from the copyright-holder-approved include set, require the private continuity set to be completely absent, inspect the exact file list, reject links and credential-like filenames, run a whole-tree secret scan, and create clean public commits only after separate authorization.

### CI and release supply-chain compromise

Keep workflow permissions minimal, pin reviewed third-party actions and release tools, bind builds to an accepted source revision and locked dependency graph, inspect archive contents, build supported platforms reproducibly, verify signatures and checksums from an isolated consumer context, and keep signing material outside source, logs, caches, and portable state. Repository creation, package publication, and signing identities remain separate approval gates.

Platform signing uses an isolated copy of the validated release executable. Native
signature verification and Apple notarization must succeed before final manifest,
checksum and provenance generation. Retain the signed file identity and bytes through
verification; a signer failure cannot publish unsigned output. Hosted signing remains
disabled until protected credential/tool provisioning is separately approved. The
release tool never exports a key or enrolls a signing provider automatically. See ADR-0042.

The hosted Apple operator wrapper owns each native process group through completion,
timeout and cancellation. Confirm descendant termination before Keychain cleanup;
if that cannot be confirmed, refuse success and preserve the private temporary
credential directory for ephemeral-runner destruction. Notarization diagnostics
retain only validated submission IDs, fixed statuses and artifact/source/target
bindings. Raw provider messages, account details and credential-bearing paths never
enter logs. These diagnostic receipts grant no retry or release authority. See ADR-0059.

One separately approved existing-image diagnostic may use repository-scoped
Actions-read only to fetch a fixed producer/artifact/ZIP/component-hash-bound ARM
input before its fixed expiry. Its native step receives no token or signing
credentials. Strip Authorization at the closed HTTPS blob redirect, parse bounded
exact ZIP members in memory, and preserve the original snapshot. Attempt-one and
single-run guards permit only one ticket attachment on a fresh private copy;
strict Developer ID and native ticket checks remain mandatory. Output only closed
error categories, numeric codes and exact hashes. No image upload, new submission,
signing, product execution, trust/network workaround or release authority follows
from this copy-only diagnostic. Missing/expired input refuses without refresh.
See ADR-0059; this explicit token-read grant is not an artifact-only server grant.

Apple artifact CPU targets are independent of the reviewed macOS build host CPU.
Both Apple targets use separate single-target jobs on Apple Silicon; the pinned
build tool must match the host, while product/archive verification must match the
artifact target. Cross-compilation grants no product execution, firewall change,
signature bypass, retry or publication authority. All native macOS verification
and final source/target-bound attestations remain required. See ADR-0065.

Release archives require reviewed third-party notices, complete locked inventory
and license text as exact named companions before signing. Reproduce checked-in
material from checksum-bound source archives and tracked supplements, without
extracting or executing upstream content. Reject missing, empty or stale material;
do not relax path/mode/size/signature/provenance gates. See ADR-0066.

### Secret resolver leakage

Never log resolver output; minimize exposure; avoid argv where possible; use transient values; prefer target environment references over materialized values.

### Adapter version drift

Production scan reports unknown version and runs no harness process. Typed callers may supply verified evidence that selects a documented policy line. Unknown versions use conservative read-only rules and block later destructive behavior when evidence is missing.

### Active harness probing

Keep process execution and network APIs out of scan. A future diagnostic probe requires a separate command, consent model, and threat review. Process-spawn sentinels cover every C2 policy.

### Local receipt tampering

Use restrictive permissions, scoped receipt identities, normalized destinations, per-record shape checks, plans for destructive operations, and explicit local state boundaries. One malformed receipt cannot prove ownership or hide valid sibling receipts during scan.

## Secret boundaries

Portable state may include a binding name and placement rule. It may not include resolved values, OAuth tokens, API keys, cookies, credential databases, or password-manager exports.

## Logging rules

Never log environment-variable values, resolver output, or full secret-bearing target configuration. Use redacted wrappers and apply the same rules to JSON output and error chains.

## Public-release gates

Private native-inspection lifecycle/output mechanics have one shared source,
with only exact reviewed launch exceptions; neighbouring files remain denied.
This prerequisite alone adds no native verifier caller or retry. A future ticket
caller must preserve the outer supervisor's cancellation/cleanup contract and
refuse uncertainty, not hide a surviving nested group behind an outer cleanup
claim. See ADR-0068.

Independent threat-model review; secret scanning; archive and path traversal tests; Windows filesystem tests; dependency audit; complete executable trust UX; supported-version policy; canary credential tests; and no known silent-loss path.

## Required security fixtures

- directory containing `.env` canary
- standalone Markdown with credential metadata and an unsupported source position
- archive with `../` entry
- symlink to a credential file
- pack with setup/postinstall script
- stale receipt pointing to user-replaced content
- malformed receipt beside a valid sibling receipt
- process sentinel proving scan launches no harness binary
- sync conflict touching an executable variant
- resolver returning a known secret followed by failure
- unknown future harness version
- adapter omission that must produce `Partial`
