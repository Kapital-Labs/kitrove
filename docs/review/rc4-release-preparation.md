# RC4 guided setup and compatibility review

The maintainer requested interactive first-computer onboarding, configuration,
second-computer full/combined/selective setup, and publication of RC4. This is a
prerelease, not stable support or completion of platform acceptance.

## Behavior and authority

Bare `init` now runs a terminal-only walkthrough. Explicit initialization flags
retain the scripted interface. `configure` revisits an existing collection.
Default scan output is human-readable; `--verbose` retains detailed diagnostics
and `--json` retains machine-readable observations. Skill names resolve only when
unambiguous within the selected scan scope. Exact observation IDs still work.

The wizard delegates initialization, adoption, synchronization and materialization
to their existing shared implementations. It never grants trust, copies local
credentials, installs agent tools, edits shell profiles or starts background sync.
Each mutation has a separate preview and affirmative confirmation. EOF, errors
and cancellation retain prior confirmed work without running subsequent steps.
The first walkthrough collects user-scope portable skills; advanced capability
types and project scopes remain available through explicit commands.

ADR-0047 adds a one-time selective remote asset/pack import. It retains exact
portable and native records, provenance, symbolic requirements and pack closure;
refuses differing identities; verifies exact object envelopes; and commits through
the existing locked manifest transaction. It does not create a selective sync
subscription or change conflict resolution. Native payloads are never executed.
Human terminal summaries escape untrusted names and paths; typed JSON remains
available for complete details.

The actual terminal exercise also found that the old batch coordinator rejected
ordinary home-contained collection/state roots. ADR-0047 specifies a dedicated
application-only root admission path: disjoint control namespaces, all exact-root
locks in identity order, no target nested inside authority, and protected-path
checks shared by commit and recovery. General transaction root rejection remains
unchanged. Native default-home application and synthetic interruption recovery
are required regression checks for this correction.

## RC3 rollback compatibility

The public preparation base is `4d7378c4503d39f8e06dd15c7f9fed968241ab6c`.
No model schema, persisted local state, deployment receipt, portable object format,
sync snapshot format, or compatibility catalog schema changes. The selective
import uses the existing schema-9 `Manifest` journal and existing recovery path,
as pack adoption already does. Its new plan digest domain is opaque journal
identity, not a new recovery variant. The new import does not serialize new
fields or grant a new kind of trust. CLI presentation changes are not persisted.

The application-layout correction does not change journal encoding. Finish any
pending RC4 transaction before binary rollback: RC3 still rejects the previously
unsupported nested-home layout during application/recovery. Completed manifests
and state remain readable by RC3, whose earlier behavior remains unchanged.

RC4 declares RC3 as its sole reviewed rollback predecessor. Earlier declarations
remain unchanged; no transitive rollback authority is inferred. Binary rollback
does not undo user-confirmed application data changes. Real RC3/RC4 lifecycle
acceptance must use the exact authenticated published artifacts, not this review
as proof that it passed. Third-party dependency versions must remain unchanged.

## Required validation and remaining limits

Local full CI, Rust 1.85 locked workspace/all-targets, isolated multi-computer
fixtures, cancellation/conflict tests, selective object/stale-plan refusals and
an actual terminal smoke test precede publication. Protected exact-head checks,
normal merge, green main, and the normal protected signing workflow are required.
Signing activation is temporary. Homebrew must be updated only after RC4's exact
archive, provenance, checksums and native policy are verified independently.

NS-07/NS-09 and INV-06/INV-07/INV-08/INV-12 remain constraints, not waived gates.
Warm Apple Silicon tests do not establish quarantined clean-Mac offline first
launch, Intel/Windows coverage, real credential resolution, or a real two-machine
product roundtrip. Isolated multi-home fixtures prove only their stated scope.
