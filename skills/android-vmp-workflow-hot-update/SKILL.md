---
name: android-vmp-workflow-hot-update
description: Resume and safely hot-update a BLOCKED vmp-recovery-workflow case at stage boundaries, with evidence-based answers, dependency invalidation, revision preservation, and author questions for unresolved case facts.
metadata:
  short-description: Resume a blocked VMP workflow case
---

# Android VMP Workflow Hot Update

Use this repository-local Skill only for an existing `vmp-recovery-workflow` case that is `BLOCKED`, needs a configuration correction, or must resume after a framework fix. It does not authorize changing the target or inventing missing reverse-engineering facts.

Read `../../prompts/hot_update_operator_zh.md` before preparing an answer.

Required behavior:

- Inspect the open question and every cited evidence item before proposing an answer.
- Apply changes only with `vmpwf resume`; never edit checkpoints, questions, events, or stage records directly.
- Select `invalidate_from` from the earliest stage whose artifact or configuration is actually invalid.
- Reload configuration only at stage boundaries. Do not hot-swap a running Frida or Unicorn session.
- Keep answers minimal and limited to fields accepted by `resume_case`.
- Preserve every prior revision, artifact hash, failure log, and stage-history record.
- After resume, verify revision increment, question status, dependency invalidation, event logging, artifact preservation, and the rerun stage gate.
- Treat a new BLOCKED state as a new evidence problem, not permission to submit speculative answers repeatedly.
- If a value is not uniquely supported by current-case evidence, ask the user/framework author using the prompt's structured question format.
- For framework code changes, add a regression test and run the full test suite, `git diff --check`, and `vmpwf doctor` before resuming the case.

This Skill is source-only in the repository. Do not install it globally unless the user explicitly requests installation.
