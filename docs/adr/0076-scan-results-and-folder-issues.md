# ADR-0076: Separate scan issues from skills and offer compact navigation

- **Status:** Accepted for implementation by maintainer request, 2026-11-18
- **North Star:** NS-01, NS-02, NS-03, NS-04, NS-05, NS-06, NS-07, NS-09, NS-10
- **Related:** ADR-0012, ADR-0047, ADR-0072

## Decision

Human scan output counts candidate skills separately from identity-less failed
folders. Failed folders appear under Scan issues with the compiled source tier,
compiled location hint (or logical folder ID), an explanation, scoped diagnostic command and explicit retry.
An administrator folder is not mislabeled as the user's own skills folder.
Unavailable folders make the displayed inventory incomplete; a failed scan is
never proof that the folder contains no skills. No raw filesystem/provider error
or resolved private absolute path is added to the human or canonical report.

Scan begins with a compact summary and short actions. Recognized, sufficiently
wide Unix terminals support arrow selection, Enter and immediate shortcuts.
Native Windows, narrow and unrecognized terminals retain immediate shortcuts and
an explicit marked Enter default. NO_COLOR suppresses color independently of
navigation. Escape, interrupt, EOF and errors restore the exact terminal mode.
Escape continuation reads are limited to two native 100ms intervals; unsupported
sequences cancel without interpreting their digits as later approval.

Scan again invokes the original read-only scan with unchanged tools, scope,
project boundary, explicit roots and collection selection. Its final report
supplies both the optional collection handoff and scan exit status. There is no
automatic retry or background observation. Empty scans default to Quit. Other
menus default to read-only viewing or Back, never collection writes.

Navigation cannot initialize, adopt, apply, grant trust or sync. Existing fresh
source/plan, authority, recovery and explicit write confirmations remain in force.
JSON/verbose schemas, observation IDs, root resolution/no-follow rules, capture
budgets, receipts, state and dependencies are unchanged. No version, tag, signing,
release, distribution or personal installation change is authorized by this work.
