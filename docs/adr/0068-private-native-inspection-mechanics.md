# ADR-0068: Native inspection shares private mechanics, not an execution API

Status: Accepted for the approved prerequisite implementation; exact validation pending

## Context

The approved read-only Apple validation recovery must confirm cleanup between
attempts within one existing outer deadline. The final operator verifier currently
uses `Command::output`, while the Python wrapper owns only the complete outer
verifier group. The Rust bounded lifecycle/output implementation remains private
to version probing. Repeating the whole verifier, copying a process runner or
exposing arbitrary command execution would not satisfy that contract.

The maintainer approved a separate reviewed process-boundary prerequisite before
the narrow recovery. No signing, release, provider request or longer deadline is
authorized by that source work. ADR-0067 is reserved in the separate unmerged
preview-scope decision and is not superseded by this record.

## Decision — staged prerequisite

Put the existing private Unix lifecycle, output collection and closed failure types
in one source location, `support/native-inspection/src`. Include them as private
modules in the reviewed caller crates. No new public Rust type/function, Cargo
package, generic command API, dependency or version is introduced by this first
extraction. Version-probe entry points, launch policy, environment, limits and
cleanup behaviour stay unchanged. Windows keeps its existing contained launcher.

Keep probe-specific assertions in its own cfg(test) module. Scan the shared source
directory under the same production governance rules as compiled tier-one source.
Move only the exact Unix lifecycle launch exception; adjacent files and the retired
source path must not gain execution authority. The common code still exposes only
pub(super) helpers to its enclosing closed caller, never user-supplied launch policy.

This first change does **not** launch an Apple verifier or add retries. Before a
new closed ticket caller uses these mechanics, separately review its complete
ownership chain with the outer Python supervisor. Merely creating a nested group
is insufficient: cancellation or termination must never be followed by a cleanup
claim that ignores a possible surviving inner group. Uncertainty must stop further
attempts and prevent credential cleanup/evidence promotion. Existing absolute
verification and cleanup budgets must not be extended.

The later recovery remains restricted to the observed read-only validation68/
NSURLErrorDomain-1005 class, at most3 attempts, 1s/2s bounded backoff, unchanged
image/source and mandatory final success/all original checks. Signing, notary
submission/wait and ticket attachment remain single-pass. No live invocation is
authorized here. Raw provider/account/path output stays private.

## Verification

Compare the moved lifecycle/failure sources byte-for-byte with the reviewed
preimage. Compare output collection ignoring only its private visibility and
formatting; preserve all test bodies and probe errors. Run existing harmless
deadline/output/descendant tests, exact governance positive/adjacent negative
tests and private-source correspondence tests. Require complete stable/Rust1.88,
manual review and exact public PR/main gates before committing/merging. Native
platform checks do not substitute for signing or release acceptance.

## Product and threat impact

NS-07/NS-09 and INV-07/INV-12 remain unchanged. This is release-inspection plumbing,
not a new harness runner, installer, portable schema, credential capability or
product feature. Discovery/adoption, asset identity, portable/native preservation,
fidelity, provenance/receipts, synchronization and rollback are unchanged.
Other readiness monitoring remains paused. Intel preview exclusion and its pending
publication-target implementation remain separate; this extraction changes no
release matrix, catalog, tag or package channel.
