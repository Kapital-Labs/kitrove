# GitHub Actions public SLSA fixture

`github-actions-public-slsa-v1.json` is the public Sigstore bundle returned by GitHub's artifact
attestation API for `GAM-team/GAM` release artifact
`gam-7.48.02-macos26.5-arm64.tar.xz`, SHA-256
`a0bca14464b5244d36dbaed162f7194d09d5be4564f5beed841d97cb3893c46f`.

- Source: `GET /repos/GAM-team/GAM/attestations/sha256:a0bca14464b5244d36dbaed162f7194d09d5be4564f5beed841d97cb3893c46f`
- Selected record: the SLSA provenance v1 bundle created by `.github/workflows/build.yml`
- Source commit: `106b6abc5df1d2e325a15606921ca54b6a849c28`
- Retrieved: 2026-09-02

The fixture contains public cryptographic evidence, not executable or third-party authored source.
It is retained to prove that Kitrove's offline verifier accepts the current GitHub Actions certificate
and SLSA claim shape without contacting GitHub, Fulcio, Rekor, or a timestamp service.
