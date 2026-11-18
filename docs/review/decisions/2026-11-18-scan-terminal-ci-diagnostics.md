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

The CLI decoder, 100ms continuation limit, fixture 5s deadline, 20ms fragment sleeps,
navigation/restoration/write-boundary assertions, workflows and permissions stay
unchanged. Require full stable/Rust1.89 and complete manual review before commit,
exact normal PR checks and one new normal full-platform check in sequence before
any remediation merge. Preserve failures and choose further repair from evidence.
Signing/publication remains held; no failed-run rerun or safety-check weakening.
