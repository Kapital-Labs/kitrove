# Apple diagnostic signature requirement literal

## Decision

Use the existing read-only control's strict Developer ID requirement in the
nonpublishing Apple diagnostic. Apple's `codesign -R` treats a plain argument as a
filename; a literal requirement must begin with `=`. The diagnostic omitted that
marker and returned an operational failure instead of evaluating its expression.
Share the already reviewed requirement rather than duplicating it: Apple anchor,
Developer ID intermediate and application certificate extensions, and exact team.

## Product, architecture and security review

This corrects diagnostic invocation only, not product preparation, signing,
notarization, archive/source authority, fidelity, synchronization or lifecycle.
No identity predicate is removed. No credentials, protected environment policy,
workflow permissions, retries, production activation, version or catalog change.
Cancellation/uncertain cleanup still prevents evidence eligibility, retained image
identity/hash checks remain, and passing controls do not erase preparation failure.

## Evidence and implementation review

Nonpublishing run40786138222 at d9ece29286888c35e0df98680830fe43f0fbe399 captured
both images only after confirmed credential cleanup. Both returned signature1 with
the malformed diagnostic argument, but plain signature verification returned0.
Read-only checks using the existing full literal requirement returned0 on both
unchanged SHA-bound images, without signing, mounting or executing a product.
Apple's installed codesign manual, section “SPECIFYING REQUIREMENTS,” documents
the filename-versus-literal rule. This is a confirmed diagnostic bug, not evidence
that the images had invalid signatures or that historical release failures share
its cause.

A synthetic regression asserts the complete canonical command for both artifact
CPUs and signature success/failure statuses. It fails on the old invocation and
checks that the original preparation failure still wins. Other cleanup, alias,
cancellation, context, receipt and output-redaction tests remain mandatory.
Full stable/Rust1.88 validation and fresh exact public checks are required before
commit/merge; exact merged main must be green. Review is manual, not an independent
agent sign-off. No release acceptance or cryptographic implementation claim.

## Unresolved concerns and reassessment

The same diagnostic separately reproduced ARM stapling exit68 after Accepted
notarization. Intel preparation succeeded but hosted ticket validation returned68;
the retained Intel ticket later validated0 locally. This repair does not explain or
resolve ticket-service behavior, and does not prove an HTTP/3/network cause.
Historical RC5.3 native statuses remain unknown. No firewall, trust, permission or
native-validation workaround is authorized. Another fresh signed diagnostic or
release requires separate authority; do not retry the completed diagnostic.
