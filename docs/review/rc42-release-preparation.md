# RC4.2 release preparation

The maintainer approved preparation, signing and publication of RC4.2 on
2026-10-14, followed by the website and package channels after validation.
Keep earlier tags and published artifacts unchanged.

Main CI found four new rustls advisories against 0.23.45. Upstream identifies
0.23.46 as patched for RUSTSEC-2026-0346, 0347, 0348 and 0349. This unit updates
the shared exact dependency pin and its governance assertion. It preserves ring,
logging, std and tls12 with default features disabled. No advisory ignore or TLS
fallback is added. The advisories have configuration-dependent preconditions;
the audit result alone does not demonstrate exploitation of Kitrove.

RC4.2 also includes the reviewed static website merged after RC4.1. There are no
application-state, lifecycle-lock, receipt, sync or capability-format changes.
The compatibility catalog permits RC4.1 as the prior version for bounded lifecycle
testing and explicit rollback. Returning to RC4.1 restores its older dependency;
format compatibility does not remove those security advisories.

NS-07/NS-09 and INV-07/INV-12 remain intact. Credentials remain local, shared
HTTPS transport retains its existing policy, and artifact authentication precedes
execution. Discovery/adoption, fidelity, provenance and conflict semantics do not
change. Package channels remain separate distribution authorities.

Before tagging, require full local CI, Rust 1.85 locked all-targets checks, a clean
dependency audit, reviewed exact-head checks and green merged main. Then use the
normal protected release workflow for a new annotated tag. Remove temporary
signing activation on terminal success or failure. Independently verify the exact
public inventory, attestations and native images with a source-built verifier;
test RC4.1/RC4.2/RC4.1 only in fresh private synthetic destinations.

This preparation record does not claim publication, native acceptance, clean-Mac
offline first launch, Windows package acceptance or a real two-machine roundtrip.
