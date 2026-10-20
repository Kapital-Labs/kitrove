# ADR-0056: Locally Authored Packs Preserve Member Provenance

- **Status:** Accepted for implementation; acceptance evidence pending
- **Date:** 2026-10-20
- **North Star invariants:** NS-01, NS-03, NS-05, NS-06, NS-07, NS-10

## Context

Native-harness adoption captures real component provenance. Existing pack creation
requires one shared exact non-harness distribution source and therefore cannot
group those tools. Inventing a local path or replacing component provenance would
misrepresent their origins. The maintainer approved explicit locally authored packs.

## Decision

Add an explicit `pack create --authored` mode, not an automatic fallback. Existing
distribution creation keeps its shared-source requirements. An authored pack has
the distinct portable source kind `authored_pack`, without a machine path, account,
credential, claimed author identity, or upstream distribution. This source kind is
valid for packs only, never component provenance.

Its source resolution identifies a versioned authored declaration consisting of
the pack ID. `revision` is `authored-pack-v1`; `exact_source_hash` hashes the
domain-separated declaration `kitrove-authored-pack-declaration-v1`, then the
length-framed pack ID. This hash is NOT a claim to have captured an upstream
archive. Exact membership and member revisions remain bound by the complete pack
content hash, manifest, lock and approval digest. Stable declaration identity lets
existing semantic merge independently reconcile membership and member edits.
Validation rejects any authored declaration resolution that differs from its
derived value; existing distribution hash frames remain unchanged.

Authored creation accepts existing native-origin, mixed-source or nested members.
It copies no provenance and grants no executable trust. Member records remain
byte-for-byte equivalent in canonical serialization. Existing graph, depth,
aggregate classification, binding and fidelity validation apply unchanged.

Exact-prior update preserves the selected pack's mode; there is no implicit
conversion between authored and distribution-backed packs. Distribution creation
cannot use an authored pack as shared upstream evidence. Plans, approval and
portable commits reuse existing coordinators and recovery refusal. Verified sync,
selective import and rollback preserve this source kind and original member
provenance. Older clients reject the new source kind rather than misinterpret it;
use matching supporting versions at both ends. No release is authorized here.

## Validation gates

- Explicit opt-in, strict argument parsing, read-only preview and exact approval.
- Mixed/harness provenance unchanged; nested packs retain complete revisions.
- Distribution source rejection unchanged; authored evidence cannot masquerade
  as captured upstream provenance or component provenance.
- Serialization, declaration tamper refusal, lock and aggregate identity tests.
- Update, stale approval, sync/import/rollback and receipt-backed removal tests.
- Full stable/MSRV checks and real Mac/Linux closed-stdin roundtrip before claiming
  acceptance. Transport never grants materialization or execution authority.
