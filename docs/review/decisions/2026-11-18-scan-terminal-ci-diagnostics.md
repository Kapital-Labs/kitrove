# Terminal fixture isolation and failure evidence

Main CI44363779176 executed its Mac test and failed waiting for a fragmented
scan-arrow selection. The old fixture retained only the expected marker. Its
original child state, output and input timing remain unknown. An isolated local
arrow case passed. A controlled 150ms continuation delay cancelled under the
existing 100ms bound; that demonstrates a possible mechanism, not hosted cause.

Diagnostic-only local canonical validation then failed earlier: after init
confirmation, the child remained alive but did not reach skill selection within
the existing 5s deadline. A targeted reproduction retained the same state, and an
owned-child stack showed init's scan_report capturing skills and running content
risk checks. HOME isolation alone did not stop project discovery walking into
ambient ancestors. No input parser or timeout repair follows from this evidence.

The trusted terminal fixture now contains a synthetic .git directory that bounds
all descendant project discovery. No Git process, remote, trust approval or real
repository is created. A synthetic ambient ancestor skill regression fails before
and passes after this boundary. The complete existing terminal flow then passed
with its original fragment sleeps, deadlines and restoration/write assertions.
Production discovery, no-follow/ownership policy and personal capabilities are
unchanged. This fixes the demonstrated local isolation defect; it does not
attribute the historical hosted arrow failure.

Failure context retains an escaped 4096-byte synthetic output tail, owned child
exit status, terminal lflag/VMIN/VTIME, and the last 16 writes with elapsed time,
original length and at most 16 bytes in hex. Native terminal/read errors retain
numeric codes only. Closed streams fail with context instead of spinning. Four
mock regressions cover bounds/escaping, read errors, closure and native terminal
error handling; only Session is AST-loaded, never fixture CLI invocations.

The new exact-source Mac job 135081126423 in full run 44383275096 retained the
missing evidence: requested 20ms sleeps became 166.152ms and 139.271ms inter-write
gaps. The child exited 3 with exact restored flags and late literal [B output,
matching the controlled delayed-continuation cancellation. A sleep is a minimum,
not an upper-bound input delivery guarantee; the precise VM scheduling cause is
not inferred. This establishes this new hosted failure's test-driver mechanism;
the original marker-only main log cannot establish its own historical timing.

The real terminal driver now submits one arrow key in a single write. The Rust
fragmented-reader unit cases still cover separate decoder reads, while native
lone-Escape cancellation and terminal restoration assertions remain. A synthetic
160ms pacing control fails before and passes after this driver-only correction
using the same source-built binary. No test is skipped and no assertion is removed.

The CLI decoder, 100ms continuation limit, fixture 5s deadline, all navigation,
restoration/write assertions, workflows and permissions remain unchanged. Full
stable/Rust1.89 and complete manual review precede an append commit. Exact normal
PR checks and a new full-platform check on the changed source, serialized after
the prior run finishes, precede any remediation merge. Preserve all failed runs
and successful independent jobs; no failed-run rerun or signing/publication.
