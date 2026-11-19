NOT PUBLISHABLE — exploratory draft for Brandon's review

Collecting a skill and adding it to another coding tool are separate jobs.
You need to know what the second tool will receive before changing its files.

Kitrove RC5.18 puts a collection and a destination preview between those steps.
You choose the saved skills or packs, select a supported tool, and review the
changes before approving placement. Kitrove retains native content and reports
compatibility limits when the target cannot represent it.

Shared folders solve part of this. If OpenCode can discover your Claude or shared
skills, another copy may add no value. Kitrove is useful when you want to manage
the collection, ownership and later changes rather than keep several folders
aligned by hand.

RC5.18 fixes a case where collecting another skill caused planning errors for an
unchanged managed file. A signed-CLI check across four synthetic destinations
confirmed the new behavior: refresh the receipt, preserve the file and its
modification time. Script review remains separate; a fresh plan does not grant
execution trust.

The preview is available through the Homebrew tap on Apple Silicon, with
versioned Linux and Windows downloads. Stable support and collection migration
remain outside this release.

Try the isolated walkthrough at kitrove.dev/docs with a disposable skill before
using a collection you depend on.

---

Review record: KITROVE-LAUNCH-01, exploratory version 1. Claims trace to
[CLAIMS.md](CLAIMS.md), the actual RC5.18 regression proof and the versioned
tool guide. The shared-folder objection appears in the post. No employer details,
invented testing experience, hashtags, diagram or social-platform action.
Premise and final editorial approval remain pending. Do not treat this record
as READY or APPROVED; publication needs Brandon's decision.
