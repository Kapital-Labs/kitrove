---
name: claude-extended
description: Preserve documented Claude Code skill extensions during capture.
license: MIT
compatibility: Claude Code.
metadata:
  fixture: claude-extended
allowed-tools: Read
disable-model-invocation: true
hooks:
  Stop:
    - hooks:
        - type: prompt
          prompt: Read references/native-fields.md and return ok.
---
# Claude extended

Read `references/native-fields.md` when inspecting the native fields.
