---
name: steward
description: Steward Culvert pull requests when a CI, review or comment event arrives or when asked to triage, deduplicate, unblock or report on open PRs. Not for ordinary code questions or edits inside a single task.
---

# Steward a Culvert pull request

Read `docs/agent-context/workflows/pr-stewardship.md` from the repository root before acting on a CI, review or fleet event. It carries the duplicate rule, conflict conventions, ID allocation, CI noise table, readiness gates, owner decisions and report format. Defaults that hold even before that read:

- Drive a PR to ready and report; never merge. Merging needs explicit human approval for that PR.
- Never rebase or force-push another author's branch, skip or disable a test, lower a gate, or push an empty commit to re-run CI. Bring main in with a merge commit.
- Do not modify owner-managed PRs: the appliance/OVA stack (`feat/onprem-appliance-*`, `harden/appliance-*`, `test/esxi-*`, `test/appliance-*`) and Dependabot.
- Search open PRs before opening or reworking one; update or comment on an equivalent instead of duplicating. With duplicates, keep one canonical and close the rest with one comment naming it.
- A real CI failure is fixed in the PR; known noise is verified on each occurrence, never assumed.

This skill does not grant permission to merge, approve, force-push, close a human's PR, disable checks, or change settings.
