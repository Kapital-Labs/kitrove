# Release build handoff review

Run `35873721343` failed before publication. Windows used the default PowerShell
shell with Bash's `$RELEASE_TAG`, passing an empty tag to cargo-dist. Linux refused
the build manifest because it had no matching archive with a local path. Both Mac
archive preparations failed with suppressed diagnostics; their cause is not claimed
independently proven, although they share this manifest input. Both Mac cleanup
steps passed. Release activation was removed; the failed tag is preserved.

Pinned cargo-dist 0.32.0 imports `*dist-manifest.json` from `target/distrib`. Its
artifact merge retains the first record's fields except checksums and assets. The
downloaded planning manifest has pathless archive records. A local reproduction
with that exact plan produced null archive paths; moving the plan outside the
import directory restored proper paths. Both runs retained the same GitHub hosting
URLs. This explains why earlier clean local packaging succeeded.

The plan stays available as `release-plan-dist-manifest` evidence, outside the
`artifacts-*` glob used by global build and hosting. Local builds do not import
other jobs' manifests. Matrix selection still uses the plan job output. Global
and host jobs still import actual prepared build artifacts/manifests with checked
checksums, paths and GitHub hosting metadata. No archive path is invented and no
validation condition is weakened. The cross-platform build step explicitly uses
Bash, including on Windows, so tag expansion and stop-on-error semantics agree.

NS-07/NS-09 remain unchanged. No new dependency, credential flow, signing policy,
publication authority or parser is introduced. Regression tests exercise tag
argument preservation and failure propagation with a stub tool, plus plan isolation
from downstream artifact imports. Python tests: 80 passed with one platform skip.
Pinned-tool reproduction is manifest-generation evidence, not a new signed build
or release acceptance result. Hosted checks and subsequent candidate verification
remain required. Never retag the failed RC1 to deploy this change.

The exact workflow digest was refreshed only after reviewing this handoff delta.
Local validation also passed 54 xtask tests (one operator-only native test ignored),
actionlint, formatting, governance, repository hygiene and diff whitespace checks.
