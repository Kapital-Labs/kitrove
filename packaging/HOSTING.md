# Linux repository publication

The maintainer approved a separate package-only GitHub prerelease and HTTPS
repository metadata on kitrove.dev on 2026-10-15. RC4.2 release assets stay
unchanged. Public APT and DNF channels are not available yet.

The package-only release `linux-packages-rc42-1` holds the tested Debian and signed
RPM files. The reviewed site inventory pins the path, size and SHA-256 of each
package, metadata file and public key. The deployment fetches package assets from
that exact release, then stages them at the paths signed metadata names.
The website builder accepts an explicit payload directory and performs no network
requests or signing. The repository files are prepared for deployment; this alone
does not establish a working public package-manager channel.

`website/prepare_packages.py` bounds downloads and restricts redirects to HTTPS
GitHub asset hosts. It checks exact local metadata inventory and all file hashes.
`website/verify_package_metadata.py` then verifies the pinned public key and
repository signatures in a temporary public-only keyring. It compares the verified
InRelease plaintext with Release and checks both detached signatures. APT dates
must be current and validity cannot exceed seven days. Every RPM metadata timestamp
must be current and less than seven days old at deployment. This RPM deployment
check is not a claim that DNF enforces an APT-style Valid-Until on clients.

Before enabling the channel:

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

The pipeline must preserve prior package paths while clients can reference their
signed metadata. Publish metadata and package payloads in the same Pages artifact;
do not deploy a partial repository. Signature verification and freshness checks
remain separate from inventory hash checks. A hash-pinned file alone does not
prove that its signature or upstream provenance is valid.
