# Local signed installer DMG rehearsal

On 2026-09-16, the maintainer authorized local signing using the existing identity
and Keychain profile. Both Mac payload targets passed `prepare-installer-dmg`.
The command implementation was reviewed as `48607f677571653b0192575aec8e1f9929eb32a2`
and merged in [PR #11](https://github.com/Kapital-Labs/kitrove/pull/11) as
`6b3188be76b4e8c910a42b148c733408ee0a150e`, with an identical tree.
Full local CI, required PR CI, Rust 1.85 compatibility and secret scanning passed.

## Inputs and environment

Both inputs are the preserved `v0.0.0` installer archives and cargo-dist manifests
from [rehearsal 35118722213](https://github.com/Kapital-Labs/kitrove/actions/runs/35118722213),
source `1267b8438276d70fd3f083cfa9e4a8576a31178b`. No input was rebuilt or relabeled.
Both images were prepared on one arm64 Mac running macOS 26.6, build 25G72.
Preparing an Intel payload on this host is not an Intel execution test.

## Verified results

Both commands exited successfully after installer signature/runtime/timestamp
verification, native image creation, container signing, accepted notarization,
ticket stapling and validation, container signature verification, image integrity
verification, exact read-only mounted payload comparison and confirmed detach.
Final checksums were produced afterward, independently checked, and preserved
with the images in private local evidence storage.

| Image | SHA-256 |
|---|---|
| `kitrove-installer-aarch64-apple-darwin.dmg` | `aff2924796c3360e20904ffd9f2dd128baf84934236c65bf754a486eed0006b8` |
| `kitrove-installer-x86_64-apple-darwin.dmg` | `981bf5aacab26c85f3f1d12a68d04da8f58413b4b063f9a57cf6795fc66484de` |

No installer or CLI was executed. No private key was exported, no hosted signing
job was started, and no release was published or activated. These local images
have no production-tag provenance and are not supported public downloads.

## Remaining gates

1. Integrate the two named containers with the shared exact release inventory,
   checksum generation and attestation workflow together. Preserve the separate
   application/installer authority types and keep release activation disabled.
2. Implement independently trusted image authentication before mounting, binding
   repository/workflow/tag/source/digest pins without another cryptographic parser.
3. Test the actual quarantined download, installer and installed CLI path on clean
   ordinary-user Mac environments, online and offline, for both architectures.
   Do not reuse this signing host's notarization cache as offline acceptance.
4. Obtain explicit candidate publication approval before exercising production-tag
   provenance and two-version install/upgrade/recovery/rollback acceptance.

The existing release acceptance order and invariant boundaries are unchanged.
