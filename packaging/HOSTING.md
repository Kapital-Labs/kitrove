# Linux repository publication

The maintainer approved a separate package-only GitHub prerelease and HTTPS
repository metadata on kitrove.dev on 2026-10-15. RC4.2 release assets stay
unchanged. Public APT and DNF channels are not available yet.

The package release will hold the tested Debian and signed RPM files. A reviewed
site inventory will pin the path, size and SHA-256 of each published package,
metadata file and public key. The site deployment will fetch package assets from
that exact package release, then stage them at the paths signed metadata names.
The website builder accepts an explicit payload directory and performs no network
requests or signing. Its current inventory is empty and enables no package channel.

Before enabling the channel:

1. Authenticate the upstream release and compare each packaged executable with
   the retained release digest. Verify package inventories and RPM signatures.
2. Create a new package-only release with fixed versioned names. Do not overwrite
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
