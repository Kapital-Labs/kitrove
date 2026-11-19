# Grok Bot pilot

Status: source-only read-only MCP prototype, not a released or live integration.
Reviewed November 18, 2026. No Grok account, computer access or provider upload
was used. See the [operator guide](OPERATOR.md) for the implemented local boundary.

Build a focused **Kitrove Collection Manager** Bot that helps a person choose
saved skills and understand a destination preview. Begin with inspection on
synthetic data. The existing [agent CLI](../../AGENT-WORKFLOW.md) supplies the
plan contracts; the Bot does not need a second collection or mutation engine.

## Deliverables

- [Bot brief](BOT-BRIEF.md): proposed role and behavior, not a provider import file.
- [Tool contract](TOOL-CONTRACT.md): source-prototype inspection/preview tools
  and the boundary before writes. They are not shipped RC5.18 endpoints.
- [Operator guide](OPERATOR.md): source invocation, exact configuration and limits.
- [Prototype acceptance](PILOT-VALIDATION.md): actual stdio and signed-CLI proof,
  boundary regressions and explicit remaining limits.
- [Offline demonstration](DEMO.md): results from the released CLI on a disposable
  collection; it does not establish live Grok Bot acceptance.
- [Sample skill](../../../examples/grokbot/skills/review-notes/SKILL.md): public
  inert content for reproducing the first journey.

## Provider evidence

Grok Bot supports reusable skills and shareable Bot templates; its documentation
describes command and HTTPS custom connectors. Its local-computer permission is
separate from its cloud computer. Account Bots share cloud files and credentials.
[Bots](https://docs.x.ai/grok-bot/bots),
[skills](https://docs.x.ai/grok-bot/skills-routines-and-automations),
[computers and connectors](https://docs.x.ai/grok-bot/computer-and-apps).

Those facts make a controller feasible. They do not establish a stable native
skill-directory or import/export API for a new Grok destination adapter. Do not
write to guessed Grok roots or describe another project's GrokBot files as this
product's contract. Research a destination adapter as a separate job.

## Execution stages

1. **Offline proof:** seed a synthetic collection, capture pack inspection and
   ordinary-skill plans for the four existing tools, and verify that inspection
   leaves source, collection, state and destinations unchanged.
2. **Reviewed read-only connection:** validate the source prototype, then choose
   a disposable Bot-computer collection or an approved isolated local
   runner. Verify account policy, platform and data exposure before connection.
   Neither connection is authorized or performed by this document.
3. **Approved writes:** design an authorization boundary distinct from the plan
   digest. Test stale content, replay, ownership and trust refusals before adding
   any mutation tool. Keep journals and recovery with the existing core.
4. **Template distribution:** share public role instructions and inert examples
   after live acceptance and maintainer review. Never include private collections,
   tokens, local receipts, approval grants or conversations in a template.

The first account pilot needs a choice of execution location and authorization
for that connection or provider transfer. Creating an account, purchasing a plan,
publishing a template and enabling unattended routines are separate decisions.
The maintainer's installed executable, collections and sync remain excluded.
