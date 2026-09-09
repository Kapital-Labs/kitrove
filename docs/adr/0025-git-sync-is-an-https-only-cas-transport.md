# ADR-0025: Git synchronization is a bounded HTTPS compare-and-swap transport

- **Status:** Accepted for Gate D D4 implementation
- **Date:** 2026-08-27
- **North Star:** NS-03, NS-05, NS-06, NS-07, NS-09, NS-10
- **Invariants:** INV-03, INV-05, INV-07, INV-08, INV-09, INV-11, INV-12

## Context

D1 defines canonical snapshots, bounded opaque backend identities, retained local bases, and pure semantic merge. D3 implements the shared transport and recovery contract against a filesystem directory. D4 must implement that same contract over Git without making Git the product workflow or importing Git merge, checkout, hook, filter, credential-helper, or ambient-configuration behavior.

A Git remote is hostile network input. Its reference advertisement, packets, pack, object graph, trees, paths, modes, redirects, certificates, and server messages are untrusted. A remote can race publication, replay an earlier snapshot, send oversized or malformed input, report an ambiguous push result, or expose unrelated repository content. Credentials are machine-local authority and must not enter URLs, portable snapshots, plans, journals, diagnostics, or rendered output.

The first candidate used libgit2's built-in HTTPS transport. Focused review rejected it because transfer callbacks do not bound the initial advertisement or every pre-pack protocol surface. A proposed custom libgit2 transport was also rejected during remediation because registration requires an unsafe process-global extension point, contrary to this workspace's no-unsafe policy. The selected design uses a small safe-Rust smart-HTTPS client with explicit byte boundaries and only narrow Git object/packet/pack crates; it does not use libgit2, `gix`'s high-level network client, or an ambient Git executable.

## Decision

### Dependency boundary

D4 adds exact direct pins for:

```toml
ureq = { version = "=3.4.0", default-features = false, features = ["rustls"] }
rustls = { version = "=0.23.32", default-features = false, features = ["ring", "logging", "std", "tls12"] }
webpki-roots = "=1.0.9"
url = "=2.5.8"
gix-hash = { version = "=0.26.2", default-features = false, features = ["sha1"] }
gix-object = { version = "=0.64.1", default-features = false }
gix-pack = { version = "=0.74.2", default-features = false, features = ["sha1"] }
gix-packetline = { version = "=0.22.2", default-features = false, features = ["blocking-io"] }
gix-zlib = { version = "=0.1.0", default-features = false }
zeroize = "=1.8.1"
```

The Git crates provide only SHA-1 object identity, object parsing, bounded in-memory pack decoding, zlib pack-entry compression/decompression, and packet-line framing. `gix-zlib` is a direct exact pin because the narrow push-pack writer must construct deterministic zlib entry streams without enabling `gix-pack`'s broader generation feature. D4 does not depend on `git2`, `libgit2-sys`, `gix`, `gix-protocol`, `gix-transport`, `gix-credentials`, or `gix-command`. It implements the minimal upload-pack and receive-pack client state machines directly over the bounded HTTPS response/request body. Push packs contain only complete non-delta objects; received packs may contain deltas but every base, result, depth, expansion, and aggregate allocation is bounded before insertion into the in-memory object map. The exact lock therefore intentionally includes `gix-zlib` and `zlib-rs`; they are admitted only for Git pack entries, not HTTP content encoding, and their compressed input and expanded output are both metered and audited.

`ureq` selects Rustls with an explicit Ring crypto provider and the exact Cargo.lock-pinned `webpki-roots` trust set. It does not load the operating-system trust store. HTTP compression, cookies, proxies, redirects, connection pooling, HTTP/2, and optional content decoders are disabled. Cargo.lock pins the full transitive graph. Stable and Rust 1.85 probes must compile the exact feature graph. Canonical CI installs `cargo-audit` 0.22.1 with `--locked`, audits the default locked graph, and asserts through `cargo tree -e features` that forbidden Git clients, transports, credential helpers, process-launch crates, alternate TLS providers or native-certificate loaders, HTTP content compressors/decoders, and proxy/cookie features are absent while the exact reviewed `gix-zlib`/`zlib-rs` pack path and pinned WebPKI roots are present. Any dependency or feature change, TLS-provider or trust-root change, or applicable advisory requires reassessment.

The D4 CLI uses exact-pinned `rpassword` 7.5.4 and locked `rtoolbox` 0.0.6 solely to obtain a no-echo token from the attached cross-platform console. The composition root first requires terminal-backed standard input and standard error, supplies no alternate input path or data source, and retains the credential only in the operation-local zeroizing provider. Governance binds both releases in the locked feature graph; advisory, license, MSRV, native-platform, and exact-head review apply to this added boundary.

The integrated HTTPS fixture carries only inert test-module DER certificate and private-key bytes for its ephemeral loopback server. The fixture has no certificate-generation dependency in the locked graph; separate valid and expired certificates exercise hostname, issuer, and validity failures without weakening production roots.

All production Kitrove crates continue to forbid unsafe code and process launch.

### Canonical remote identity

Production accepts one HTTPS URL and uses only `refs/heads/kitrove-sync-v1`. `url` 2.5.8 is the sole parser. The accepted grammar is narrower than general URL syntax:

- scheme exactly `https`;
- a lower-case ASCII DNS hostname without an IP literal, trailing dot, empty label, or explicit port;
- no username, password, query, fragment, percent escape, backslash, control, whitespace, or dot path segment;
- a nonempty absolute path whose segments contain only ASCII letters, digits, `.`, `_`, `-`, or `~`; and
- input bytes exactly equal to the parser's canonical serialization.

The exact canonical origin is `https://<host>`. The complete canonical URL is hashed with the backend kind to derive `RemoteKey`; neither raw value crosses into portable state, plans, journals, errors, `Debug`, text output, or JSON output. The exact validated bytes, plus only the compiled smart-HTTP suffixes, are passed to `ureq`. Parser-differential tests cover IDNA, Unicode, host case, explicit default ports, trailing dots, encoded delimiters, literal or encoded dot segments, double slashes, and user-info confusion. D4 does not support HTTP, file, Git, SSH, SCP-like, custom, or redirected schemes.

### Bounded smart HTTPS

The client implements exactly four Git smart-HTTP exchanges:

1. `GET <remote>/info/refs?service=git-upload-pack`;
2. `POST <remote>/git-upload-pack`;
3. `GET <remote>/info/refs?service=git-receive-pack`; and
4. `POST <remote>/git-receive-pack`.

Requests use only compiled `Accept`, `Content-Type`, `User-Agent`, and optional internally constructed `Authorization` headers. Redirect count and proxy are zero. TLS hostname verification and the pinned WebPKI root set are mandatory; production has no verifier-injection, platform-store, environment-root, or disable switch. `SSL_CERT_FILE`, `SSL_CERT_DIR`, platform keychains, and every other ambient CA source are ignored. Response status, content type, content encoding, and length are validated before body parsing. Content encoding must be absent or identity.

D4 extends `SyncLimits` with refusing request-global Git limits. Defaults are:

| Counter | Default |
|---|---:|
| complete HTTPS response headers | 32 KiB per exchange |
| HTTP input/output buffers | 8 KiB each |
| aggregate response bodies | 512 MiB |
| one outbound request body | 384 MiB |
| advertisement packet bytes | 4 MiB |
| advertisement refs | 4,096 |
| packet-line records | 65,536 |
| received pack bytes | 384 MiB |
| decoded Git objects | 16,384 |
| one decoded Git object | 32 MiB |
| aggregate decoded Git objects | 512 MiB |
| delta depth | 64 |
| commit history | existing `max_backend_history` (4,096) |
| connect timeout | 10 seconds |
| response-header timeout | 15 seconds |
| body-read inactivity timeout | 15 seconds |
| one HTTP exchange deadline | 120 seconds |
| complete backend-operation deadline | 300 seconds |

`ureq` rejects a response header beyond 32 KiB and uses the configured fixed input buffer. Every body is consumed through a `Read::take(remaining + 1)` boundary; the crossing byte produces the one terminal limit result and is never passed to packet or pack parsing. Packet-line, ref, pack, object, delta, history, and shared snapshot/object meters all share one request budget. Declared sizes are checked before allocation. Delta arithmetic is checked, a result larger than the remaining single or aggregate budget is refused before materialization, and external or cyclic delta bases are refused. After any terminal limit or parse result, no further read, decode, graph walk, credential attempt, or request occurs. No transport bytes are written to disk.

Exact and over-by-one instrumented tests cover the documented parser buffer as the only bounded pre-callback allocation, huge headers, chunked bodies, slow or endless peers, unrelated advertisements, packet counts, compressed packs, compression bombs, object counts, individual and aggregate expanded objects, delta depth, and history exhaustion.

### Read and object validation

Upload-pack advertisement parsing accepts protocol v0/v1 only, requires SHA-1, and records only the exact fixed ref after charging every advertised ref. Symrefs, peeled tags, unknown object formats, duplicate fixed refs, malformed capabilities, and inconsistent advertisements are refused. Fetch requests exactly the selected OID, no tags, no progress, no thin pack, and depth `max_backend_history + 1`; a server that cannot supply a self-contained bounded pack is refused.

Fetched objects live only in a request-local in-memory map keyed by verified SHA-1 OID. The selected commit chain must be acyclic, have zero or one parent per commit, and terminate at the root or the explicit shallow boundary within the history limit. Only the selected commit's exact tree is interpreted. Every entry must be an ordinary `100644` blob or ordinary tree. Extra entries, executable modes, symbolic links, gitlinks, submodules, duplicate/noncanonical paths, case or Unicode aliases, and missing objects are refused.

One validated `PortableSnapshotV1` maps deterministically to:

```text
snapshot.json
objects/<exact descriptor-derived portable path>
```

The tree must contain exactly that set. Snapshot and object blobs are checked against the shared byte meters, then parsed and verified through the existing core validators. No object is executed, checked out, filtered, or materialized by Git code. Dropping a read session destroys every received Git object and leaves no file, ref, configuration, or cache mutation.

### Deterministic publication

`prepare_publication` performs no I/O or persistent mutation. It constructs canonical Git blob, tree, and commit bytes in memory and computes their exact SHA-1 OIDs. The commit has the staged snapshot tree, the exact expected selected commit as its sole parent, or no parent for initial publication. Author, committer, timestamp, timezone, encoding, and message are compiled deterministic values. The bounded message contains only the schema tag, publication ID, and snapshot digest.

The opaque canonical `PublicationIntent` binds the fixed ref, exact expected absent token or prior OID, publication ID, snapshot digest, every required object OID, proposed tree OID, proposed commit OID, and sole-parent relationship. The proposed commit OID is the proposed `RemoteRevision`. Publishing reconstructs every object from the journal-bound staged snapshot, requires every OID and the deterministic non-delta pack checksum to match the intent, and bounds the complete request before network mutation.

Receive-pack advertisement parsing charges every ref but accepts authority only for the exact fixed ref. The push command contains exact old OID (all-zero for absence), proposed new OID, and exact fixed ref, followed only by the required report-status capability and the deterministic pack. No force, delete, atomic multi-ref, push option, sideband progress, or alternate ref is sent. Git receive-pack compares the command's exact old OID while holding its ref transaction; a race must reject the update. Success requires one unpack-ok record and one ok record for the exact fixed ref. Every other, missing, duplicated, or malformed status is uncertain after the POST begins.

### Publication recovery

The durable `Publishing` phase remains the uncertainty boundary. A timeout, cancellation, disconnect, malformed response, or missing acknowledgement after the receive-pack POST begins never proves nonpublication. `reconcile` fetches the selected fixed ref and walks only its bounded validated sole-parent chain:

- the exact proposed commit in the selected chain returns `Published(proposed_revision)`;
- the selected ref still exactly equals the intent's expected authority and the canonical intent is internally self-consistent, returns `Ready`; because the unchanged `reconcile` API has no staged bodies after restart, `Ready` authorizes only an idempotent retry, and `publish(intent, staged, objects)` must reconstruct and reverify every object, OID, and pack identity before sending any request;
- an alternate, missing, malformed, multi-parent, cyclic, shallow-before-proof, over-budget, or otherwise unproven history returns `Uncertain`.

Recovery never force-pushes, deletes, rewinds, merges, rebases, selects a semantic winner, or treats exclusion from an alternate chain as proof of nonpublication. A later valid successor is left intact after it proves the proposed commit was selected. Same-snapshot recurrence remains ABA-resistant because each successor has the exact prior commit parent and a distinct confirmed publication ID.

### Credential boundary

Credentials are supplied through a sealed machine-local `GitCredentialProvider` for one operation. The provider and secret have no serializable, renderable, or `Debug` representation and are zeroized after use.

The D4 CLI provider supports anonymous HTTPS and interactive Basic authentication only. After one bounded unauthenticated `401` with one valid Basic challenge, it may prompt on an attached terminal for a username and no-echo token, then retry that exact request once. It refuses without a terminal. The provider answers only for the exact canonical origin. Redirects remain disabled. Unsupported/multiple challenges, malformed realms, changed origins, and further authentication requests are refused.

Secrets are not accepted in URLs, command-line arguments, environment variables, Git configuration, credential helpers, `GIT_ASKPASS`, SSH agents, arbitrary headers, or files. Noninteractive keychain support is deferred. Server text, URLs, usernames, tokens, certificates, refs, packets, and library error strings are translated to compiled structural errors before crossing into core or CLI output.

### Test and acceptance boundary

D4 implementation is not accepted until:

- the unchanged shared backend contract passes for Git, including absence, exact fetch, immutable reuse, stale publication, ABA/history proof, interruption, limits, and redaction;
- a standards-conforming local smart-HTTP fixture covers initial publication, receive, successors, exact-old races, lost acknowledgement, later-successor recovery, alternate and malformed history, extra trees, forbidden modes, aliases, and every receive status;
- an instrumented hostile HTTPS server covers every exact/over-by-one limit, huge unrelated advertisements, malformed packets, truncated/chunked bodies, pack/delta bombs, timeouts, operation-deadline cancellation, zero disk use, and no work after refusal;
- the HTTPS/auth matrix covers anonymous and Basic success, no-terminal refusal, retry exhaustion, challenge confusion, same/cross-origin redirect refusal, poisoned proxy/helper/ASKPASS/Git environment, poisoned `SSL_CERT_FILE`/`SSL_CERT_DIR`, hostname mismatch, expiry, and untrusted issuer;
- test-only builds may inject one local test root and a loopback connector for the integrated HTTPS fixture. The connector preserves the exact production canonical URL, origin, SNI hostname, Host header, request paths, and client state machine while routing that hostname's port 443 connection to an unprivileged ephemeral loopback socket. These constructor fields and traits exist only under `cfg(test)` inside the backend crate, have no public or feature-gated production form, and compile-fail governance proves production cannot name or inject either a root or connector. Native Ubuntu, macOS, and Windows tests run anonymous, Basic, redirect, TLS-failure, hostile-body, and disconnect cases through this path; native CI additionally reads a public fixture through the exact production connector and pinned-root verifier;
- distinct URL, username, token, certificate, server-status, ref, packet, authored-content, native-ID, object, path, revision, intent, receipt, and secret canaries satisfy the accepted D3 allow/deny surfaces;
- governance proves no unsafe code, process launch, ambient Git client, checkout, filter, hook, submodule, credential helper, proxy, redirect, content decoder, or certificate override in production;
- exact locked dependency/features, Rust 1.85, advisory, Ubuntu, macOS, and Windows evidence passes; and
- fresh independent architecture, security, and test/evidence reviews approve the exact implementation head.

### 2026-08-28 clarification: cancellation boundary

For D4, “cancellation” means the transport stops a stalled exchange when the refusing exchange or complete-operation deadline expires. The unchanged synchronous `SyncBackend` contract has no caller-supplied cancellation token, and D4 does not add a Git-only cancellation API. Tests must prove that a stalled HTTPS peer is terminated within the configured deadline and that no later request or protocol work begins after that terminal result. A general caller-driven cancellation contract, if needed, is deferred to a separate cross-backend design decision.

## Consequences

- Git remains transport and history, not the merge engine or user workflow.
- The client implements a deliberately small Git smart-HTTP subset so every hostile byte crosses an application-owned bound.
- No checkout, repository cache, persistent Git state, C dependency, unsafe transport registration, or ambient Git behavior enters D4.
- HTTPS Basic credentials are usable interactively; SSH and noninteractive keychains remain later reviewed work.
- Exact version pins and locked advisory checks trade upgrade flexibility for a reviewable MSRV and network boundary.

## Rejected alternatives

- **Shell out to ambient Git:** imports executable lookup, user configuration, hooks, helpers, prompts, and platform-dependent parsing.
- **Use libgit2 HTTPS:** its callbacks cannot bound every hostile protocol surface before parsing; custom transport registration also requires unsafe global state.
- **Use high-level `gix` transport:** the reviewed release has no complete push operation and imports credential/process surfaces outside the narrow client.
- **Use GitHub's REST ref update:** `force=false` enforces fast-forward, not exact old-OID compare-and-swap, so an intervening force rewind can pass incorrectly.
- **Use a persistent repository or checkout:** mutates read-only planning and admits ODB/configuration indirection, filters, worktree paths, and executable modes.
- **Follow redirects, proxies, or helpers:** allows credentials and remote identity to leave the reviewed origin boundary.
- **Treat a failed push as absent:** can replay publication after the server accepted the ref update but acknowledgement was lost.
