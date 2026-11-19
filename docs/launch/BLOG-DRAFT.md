NOT PUBLISHABLE — exploratory draft for Brandon's review

# Collecting and reusing skills across coding tools

You can keep a useful skill in Claude Code and want to use it in OpenCode. Both
tools understand skill files, but deciding where to put another copy raises a
different question: which copy do you edit next?

That is the workflow behind Kitrove. You collect capabilities you want to keep,
preview their use in a supported tool, and approve the destination changes. You
keep the source content and a record of the files Kitrove manages.

[RC5.18 is an evaluation preview](https://github.com/Kapital-Labs/kitrove/releases/tag/v0.1.0-rc.5.18).
It supports Claude Code, Codex, Pi and OpenCode within the capabilities described
in the [tool guide](https://github.com/Kapital-Labs/kitrove/blob/v0.1.0-rc.5.18/docs/ADD-TO-TOOLS.md).

## Collect, then choose a destination

Collection and placement are separate operations. You can inspect local skills
with `kitrove scan`, then use guided setup to collect selected content. Running
`kitrove apply` opens the tool and pack picker for a collection you have set up.
You review the destination plan before approving a write.

A pack lets you choose related saved items together. It does not hide a blocked
member or grant permission to execute a helper. Some native fields do not have
an equivalent in another tool; Kitrove reports the compatibility limit and
retains native content instead of presenting that transfer as complete.

RC5.18 also fixes a repeat-run problem: collecting another skill could make a
previously placed, unchanged file look like an update. The planner now retains
the unchanged file while an approved operation refreshes its receipt. The
maintainer checked the signed Mac CLI across four synthetic tool destinations,
including unchanged file bytes and modification times. That result does not
claim a repair or migration of anyone's existing collection.

## Shared folders and other projects

If your tools discover the same skill in a shared folder, you may not need
another copy. An OpenCode-specific definition can also override a matching
definition it discovers elsewhere. A matching name does not prove equal content
or ownership.

Other projects cover useful parts of this work. Vercel skills provides skill
discovery and installation. Kasetto offers declarative environment distribution.
Kanon includes existing-settings import, and agentctl and agentenv document
planning or environment lifecycle features. The
[dated comparison](../research/2026-11-18-landscape.md) links their sources and
records the overlaps. A lockfile or support for several tools is not a unique
Kitrove feature.

Kitrove focuses on the managed collection journey: retain what you collected,
see what can travel, and review later changes without treating a tool folder as
the whole environment. The next test is whether users complete that journey
with less effort and understand the results.

## Try a bounded preview

On an Apple Silicon Mac, Homebrew selects the verified preview:

```sh
brew install --cask kapital-labs/tap/kitrove
kitrove --version
```

Start with a new isolated collection and disposable skills, then follow the
[walkthrough](https://kitrove.dev/docs/). Linux and Windows users can choose the
versioned release archives and follow their verification instructions.

This is a preview rather than stable support or a collection migration promise.
The release checks do not establish clean-Mac offline first launch or every
live-tool workflow. Grok Bot integration is proposed work, not a feature in
RC5.18. Try the disposable collect-and-place journey and report the step where
the next action becomes unclear.

---

Editorial note: confirm the premise, final wording, relative comparison link and
publication destination before approval. The linked claims ledger is the factual
gate; this draft has not passed Brandon's editorial approval or been posted.
