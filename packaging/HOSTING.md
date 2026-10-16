# Linux repository publication

The maintainer approved a separate package-only GitHub prerelease and HTTPS
repository metadata on kitrove.dev on 2026-10-15. RC4.2 release assets stay
unchanged. Public APT and DNF preview repositories are live on kitrove.dev.
On 2026-10-16, Ubuntu 24.04 and Fedora 44 passed HTTPS fresh install,
RC4.1-to-RC4.2 upgrade and removal, with authenticated executable digest checks,
ordinary-user version/help and unchanged synthetic canaries.
See [user setup instructions](../docs/LINUX-INSTALL.md).

The package-only release `linux-packages-rc42-1` holds the tested Debian and signed
RPM files. The reviewed site inventory pins the path, size and SHA-256 of each
package, metadata file and public key. The deployment fetches package assets from
that exact release, then stages them at the paths signed metadata names.
The website builder accepts an explicit payload directory and performs no network
requests or signing. Deployment inventory and native HTTPS acceptance are
separate checks.

`website/prepare_packages.py` bounds downloads and restricts redirects to HTTPS
GitHub asset hosts. It checks exact local metadata inventory and all file hashes.
`website/verify_package_metadata.py` then verifies the pinned public key and
repository signatures in a temporary public-only keyring. It compares the verified
InRelease plaintext with Release and checks both detached signatures. APT dates
must be current and validity cannot exceed seven days. Every RPM metadata timestamp
must be current and less than seven days old at deployment. This RPM deployment
check is not a claim that DNF enforces an APT-style Valid-Until on clients.

For a new package or metadata renewal:

1. Authenticate the upstream release and compare each packaged executable with
   the retained release digest. Verify package inventories and RPM signatures.
2. Use the existing package-only release with fixed versioned names. Do not overwrite
   published files, alter the application release, or resolve a mutable latest URL.
3. Generate repository metadata with fresh timestamps. Sign it outside CI with
   the dedicated package signing subkey. Keep private keys and passphrases out of
   repositories, build artifacts, guests and deployment jobs.
4. Review the public key, signed metadata and exact file inventory through a PR.
   Preserve the website's exact-green-main publication gate. Download payloads
   using explicit versioned URLs and compare them with the reviewed inventory.
5. Test the deployed HTTPS repositories in the Ubuntu and Fedora VMs. Retain
   signature, expiry, digest, install, upgrade, removal and canary evidence before
   publishing user-facing install commands.

APT uses a dedicated Signed-By keyring and a seven-day Valid-Until. A maintainer
must refresh and sign metadata before expiration, even if package bytes stay
unchanged. An expired repository must fail closed. Do not remove the expiry check
to recover availability. Each refresh uses reviewed metadata and the same main
publication gates. DNF must require both package and repository signatures.

## Renewal checklist

The release maintainer owns renewal. Start at least two days before APT's
published `Valid-Until`, leaving time for PR checks and deployment. The initial
metadata expires on 2026-10-23 UTC. Read the exact timestamp from
`website/package_metadata/packages/apt/dists/preview/Release`.
No unattended signing job or private-key access exists in CI.

1. Start a worktree from green public main. Retain the current metadata and
   inventory as evidence. Keep package bytes and immutable release URLs fixed
   for a metadata-only renewal.
2. Generate APT metadata with a fresh `Date` and `Valid-Until` no more than seven
   days apart. Check the generated file: a tool option alone does not prove it
   emitted expiry. Exclude Release, InRelease and signatures from package-index
   hash input. Regenerate RPM metadata timestamps too.
3. Sign APT InRelease and Release.gpg and RPM repomd.xml.asc outside CI with the
   dedicated key. Update the exact inventory. Keep the private key outside the
   checkout and deployment payload.
4. Run retrieval and signature/freshness verification against a fresh payload.
   Retain authentic, tampered and expired-metadata test results. Review the full
   diff and run required local checks.
5. Merge after exact-head checks pass, then deploy through the green-main Pages
   gate. Fetch all public files and compare hashes and signatures. Check APT and
   DNF refresh in isolated native clients before calling renewal complete.

If renewal misses the deadline, leave expiry enforcement enabled and report the
outage. Publish reviewed signatures through the same workflow. Do not extend
unsigned dates, reuse expired metadata or alter application release assets.

The pipeline must preserve prior package paths while clients can reference their
signed metadata. Publish metadata and package payloads in the same Pages artifact;
do not deploy a partial repository. Signature verification and freshness checks
remain separate from inventory hash checks. A hash-pinned file alone does not
prove that its signature or upstream provenance is valid.
