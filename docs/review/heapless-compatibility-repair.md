# Heapless compatibility repair

Status: local maintained dependency override with reviewed source preparation,
normal targeted resolution, Rust1.89 metadata and fresh audit complete.
Preparatory Rust1.89 feature contracts, license binding and retained notices
pass as described below. Exact combined stable/Rust1.89 and native public
validation are required merge gates, recorded with the pull request.
No release authority.

The reviewed RustSec database added nine informational unsound heapless records,
0574 through0582, with package-level patched range>=0.9.4. The selected Git graph
uses faster-hex0.10.1 with std/alloc, but its published target dependency still
resolves heapless0.8.0. Alloc selection does not remove that package from the
locked audit, and source reachability is not an exemption.

The complete authenticated faster-hex0.10.1 archive is preserved under
`third_party/faster-hex`. Its only upstream-file change is the active manifest's
heapless requirement `0.8` to `=0.9.4` and package rust-version `1.61.0` to
`1.88`; no Rust, build-script or feature-definition byte changes.
Archive identities, every member hash, license material, nominal noalloc type
boundary and removal conditions are recorded in `KITROVE_PATCH.md` and its
`UPSTREAM_FILES.sha256.json`. The root path patch and workspace exclusion select
the maintained override without changing gix, public CLI code or Rust1.89.

Heapless0.9.4 declares Rust1.88 and MIT OR Apache-2.0. Its base hash32 and
stable_deref_trait edges already exist in the locked graph. Faster-hex remains
MIT and retains its Rust Project Developers and fast-hex MIT attributions.
Normal targeted resolution changes only faster-hex0.10.1's source from registry
to the tracked path (removing its registry source/checksum fields), and heapless
version0.8.0 to0.9.4 with checksum
`411fdef4df93751117bd9ef8caa0e7f99c65dafec5bd84313eb8e2fdd75e32f2`.
All dependency lists and every other lock field are unchanged; package count
remains413. Rust1.89 metadata reports faster-hex features alloc+std and no
heapless features. Both changed packages declare Rust1.88; base dependency
versions remain hash32 0.3.1 and stable_deref_trait 1.2.1. This is metadata
analysis, not compilation or all-feature/API acceptance. Cargo.lock was not
edited by hand.

The noalloc public String<N> nominal crate type changes0.8 to0.9.4. Approval
covers that scoped local-patch boundary; it is not a general upstream semver or
nominal-type compatibility claim. Source signatures still provide the Vec
constructor/resize/slice and String conversion operations used by unchanged
faster-hex. Disposable dependent fixtures on Rust1.89 pass six profiles:
noalloc typed heapless0.9.4; alloc; std; std+serde; noalloc+defmt03; all features.
They exercise lower/upper encoding, caller-buffer encode/decode/refusals, fixed
capacity and the expected0.9.4 return type. The short-source/large-destination
legacy decoder regression passes in each profile; this is not proof that every
SIMD backend executed on the local ARM host. The vendor Cargo.lock is unchanged.

The additional serde-without-std profile fails with a missing Vec import and
missing Cow Deserialize support. Exactly one disposable control using the
checksum-authenticated registry0.10.1 and its original heapless0.8.0 reproduces
the same three errors. This unchanged profile is not accepted as supported by
this repair; no Rust or feature edit was made to fix it. Selected Kitrove
std/alloc behavior and the mandatory noalloc0.9.4 contract pass. Full native
platform and final combined-source validation remain separate.

License policy requires review of the complete lock and source identities, then
updating its reviewed BLAKE3 binding. Existing inventory classification counts
excluded path packages as third party; no registry-check relaxation is needed.
Notice generation now recognizes the exact LICENSE-THIRD-PARTY ancestor
without changing source authentication or file/resource bounds. Two synthetic
registry/vendored regressions first failed because the nested texts were absent;
after the narrow correction, all 12 notice tests passed with Python3 and -B.
The actual vendored LICENSE and both nested attributions match authenticated
upstream bytes. Normal authenticated notice --write and --check now pass.
The inventory still contains386 third-party packages and changes only the
heapless version row. The bundle switches faster-hex to its tracked source,
retains both nested MIT texts and updates heapless's checksum/version/MIT source
reference; no attribution or registry authentication is waived.

Fresh cargo-audit exits0 with zero vulnerabilities and zero unsound warnings;
only the existing chrono RUSTSEC-2026-0543 unmaintained record remains. The
observed RustSec database commit is
`074ea9a7ed619f511b5b7374c7a97e98d1e98be4`. No ignore is added. The resolved
workspace lock SHA256 is
`735ac4479ba0eca613a7deae9606f343ac7328d9ae3dbe046066d6c6ad771545`.
Every third-party license expression matches the prior inventory, allowing for
heapless's new version; excluded faster-hex remains third party. The root's independent TOML equality review approved this exact graph delta.
The normal Rust1.89 xtask licenses command first failed at the old binding and
reported BLAKE3
`e7a4c54ca22428ca1b690172797fa95ead404b64a1b1fae7be98a1f6b77d306b`.
Only that reviewed constant was then changed; the normal command passes with
386 third-party packages. Both failure and success logs are retained. Audit/metadata logs are retained in the
scoped release evidence; they do not constitute runtime or release acceptance.

The focused Rust1.89 Git backend command passes45 synthetic module tests,
including packet parsing, object/pack hashes and bounded transport fixtures.
The live public-provider fixture was explicitly excluded. This is targeted
preparation, not final combined-source acceptance. The original49ba patch and
archive were preserved before advancing onto merged PR152 source
`2da8a9b986eb3cc811b8c08aa0d98d4e197e3725`. Normal offline targeted resolution
preserves its new test-only macOS edge; every other lock field is unchanged except
the approved faster-hex source and heapless version/checksum. Require full stable,
Rust1.89, native public checks and exact green main before merging or publication. Do not transfer the disposable fixture's lock into the vendor directory.

No warning ignore, waiver, policy bypass, graph-wide update, compiler-floor bump,
version/tag/signing or publication is part of this repair. The frozen doctor/UX
feature work stays separate. The user's storage failure cause remains unknown.
