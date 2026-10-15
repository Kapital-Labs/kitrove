# Linux package signing custody

The maintainer approved a dedicated Kitrove APT/RPM signing identity on
2026-10-14. It is separate from release provenance and native code signing.

Primary fingerprint: `0C0E4DE98C93CD1059995A3974386FFE8762A9E1`

Signing subkey: `83156965F7FF656ABF6C4EFB60C2FBF8510658DF`

Both keys use RSA 4096. The certification primary expires on 2028-10-13;
the signing subkey expires on 2027-10-14. The primary certifies subkeys and does
not sign packages. The subkey signs package and repository metadata.

The maintainer keeps the passphrase-protected key outside the source repository.
The private 1Password vault holds the protected export, public key and revocation
certificate, with the generated passphrase in a separate Password item. A
download, byte comparison, isolated restore and test signature verified the
backup. Do not put private keys or passphrases in Git, release assets, test VMs,
CI logs or package repositories. Test guests receive only the public key.

Before signing a package, authenticate its immutable upstream release, compare
the packaged executable with the authenticated digest, check the exact package
inventory and confirm there are no install/remove scripts. Preserve unsigned
inputs and sign a separate output. Verify the signature on the target platform
before distribution. A valid package signature alone does not authenticate the
original build or prove lifecycle acceptance.

Before repository publication, distribute the public key and full fingerprint
through reviewed HTTPS documentation. APT configuration must use a dedicated
keyring and `Signed-By`; DNF must require package and repository signature
verification. Do not install this key as a general-purpose trust anchor or turn
off verification when an import, signature or expiration check fails.

Rotate the signing subkey before expiration. Verify the backup, certify a new
subkey, publish the updated public certificate through review and test client
refresh before using the new subkey. Preserve old package signatures and
verification evidence. If the signing subkey is compromised, revoke that subkey
and stop publication. If the primary key is compromised, revoke the primary and
establish a new identity through an explicit maintainer-reviewed trust handoff.
Do not automatically accept a replacement key from an unauthenticated error or
download response.

Repository hosting, signed metadata freshness and client repository acceptance
remain publication gates. This document does not announce an APT or DNF channel.
