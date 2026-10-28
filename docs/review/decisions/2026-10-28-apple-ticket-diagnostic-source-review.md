# Protected fresh-image diagnostic source review

Scope: explicitly approved diagnostic-only Apple signing, temporary main access
with existing reviewer/no-admin-bypass protections, and restoration afterward.
No release/version/tag/channel change, migration, stable support or new signing
implementation. This is a manual source/caller review, not an independent-agent
or exhaustive repository review. Hosted results remain pending.

NS-07/NS-09 and INV-07/INV-12: credential lifetime stays in the reviewed Apple
helper. Portable/local schemas, discovery/adoption, native preservation, fidelity,
asset provenance, deployment receipts, synchronization/conflicts and local trust
remain unchanged. Signed diagnostic bytes never enter portable state. The
diagnostic JSON is not release provenance or a capability deployment receipt.

Review boundaries:

- Manual public main, exact SHA and ARM hosted context only; refuse any production
  activation. No caller-provided command, version, file path or signing target.
- Both target builds credential-free; pinned ARM cargo-dist0.32.0, locked notices,
  exact catalogued source version. Only existing owned prebuilt tools reach signer.
- Separate named build outputs bind the inventory digest before credentials;
  no trust in self-reported downloaded artifact digests, inherited secrets or OIDC.
- Shared production preparation defaults unchanged. Optional cleanup observer
  fires only after restoration, Keychain absence and directory removal. Callback
  never converts primary failure into success. Process uncertainty/cancellation
  prevents capture; ephemeral runner destruction remains the abrupt-death boundary.
- Read-only post-cleanup controls may compare credential-free context to the
  preparation failure. They neither modify ticket/image bytes nor retry signing.
- Exact bounded regular image copy, no-follow parent/leaf, one link, identity/hash
  checks and exclusive destinations. Only fixed image+JSON upload for one day;
  output flag is written only after a complete JSON record and confirmed cleanup.
- Raw native/provider/exception text discarded. Safe receipts are validated again;
  numeric statuses/closed failure detail retained. No product execution or failure
  image mounting. Primary nonzero status remains nonzero.
- Temporary main policy/exact-SHA lifecycle is an operator action after green
  exact merged source; production activation absent throughout, reviewer and no
  bypass unchanged. Terminal watcher must restore original tag-only policy and
  remove diagnostic SHA, then independent readback. No release job can be enabled
  by this diagnostic marker.

Test plan: preserved missing-feature and corrected behavioral reds; complete
context refusal, bad version/catalog, source/target handoff, copy links/nonfiles,
canary suppression, cleanup/restore uncertainty, cancellation before next operation,
failed preparation retained despite passing later control, source workflow limits,
existing rehearsal tests, full stable/Rust1.88, fresh audit and secret scans. Exact
public PR/Required CI plus green prior/latest merged main precede the actual run.
No local/hosted source test is production artifact or historical root-cause proof.
