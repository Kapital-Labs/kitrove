# ADR-0044: Pin the protected release environment identity

Status: Implementation correction under the approved prerelease path

## Decision

Kitrove's application, installer and DMG attestations must identify the protected
`release` environment and its immutable repository subject. Require both Fulcio
environment extension 1.3.6.1.4.1.57264.1.23 and token-subject extension .24.
The subject is exactly
`repo:Kapital-Labs@320223113/kitrove@1360443188:environment:release`.
Continue separately verifying repository and owner IDs, workflow identity, source
tag and commit, trigger, hosted runner, public visibility, invocation, signature,
transparency evidence and exact artifact digest. An environment subject is not a
substitute for the independently signed source-ref claims.

No fallback to legacy name-only, ref-based or arbitrary environment subjects is
permitted in production. The legacy external test fixture remains test-only.
Missing, duplicate, critical or malformed environment/subject extensions fail.
This corrects an unexercised assumption, not an authorization to change GitHub
protections, provider credentials or accepted source identities.

## Evidence

The published RC1.3 run 35941035846 certificate has exactly the environment and
immutable-ID subject above. The old verifier instead required a legacy ref subject.
[GitHub's OIDC reference](https://docs.github.com/en/actions/reference/security/oidc)
documents environment subjects and immutable owner/repository IDs. Retain a public
production attestation fixture and test full offline verification as well as
adversarial claim mutations; GitHub CLI verification alone is not acceptance by
Kitrove's verifier. Any additional cryptographic failure remains blocking.

## Impact

NS-07/NS-09: identity and trust stay explicit; no downloaded executable runs before
authentication. Published RC1.3 remains immutable. A reviewed-source corrected
verifier can authenticate it; the old downloaded installer is not a bootstrap.
No new signing run is needed to validate this correction.
