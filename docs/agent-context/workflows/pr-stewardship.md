# Steward a Culvert pull request

Use this procedure when a CI, review or comment event arrives on a pull request, or when asked to triage, deduplicate, unblock, conflict-resolve or report on open PRs. The steward drives a PR to "ready" and reports; it is not an implementation task on its own and not a license to rework every open branch.

This procedure grants no permission beyond the task's. It never merges, approves on a human's behalf, force-pushes or rebases another author's branch, closes a human-authored PR without that author, skips or disables a test, lowers a gate, pushes an empty commit to re-run CI, or changes repository settings. Merging requires explicit human approval for that specific PR; the session's safety policy blocks it otherwise.

## Fleet and ownership

Seven scheduled daily agents open PRs from branches named `claude/<adjective-scientist>-<suffix>`: `serene-cerf` (chaos), `determined-mccarthy` (performance), `epic-bardeen` (security-regression review), `affectionate-mccarthy` (terminology governance), `friendly-brahmagupta` (product-experience diagnostics), `clever-feynman` (small fixes) and `confident-darwin` (docs). When a fix is not merged, the next day's run re-opens the same fix, so the fleet accumulates near-identical PRs (five copies of one config fix, five competing designs for one package) unless deduplicated.

Owner-managed scope the steward does not modify: the appliance/OVA stack (`feat/onprem-appliance-*`, `harden/appliance-*`, `test/esxi-*`, `test/appliance-*`) and Dependabot PRs. Report them in the fleet summary; do not push to them, rebase them, re-run their checks or close them.

## Before opening or reworking a PR

1. Search open pull requests for the same files, symbols, finding IDs (`T-NN`, `CHAOS-NN`, `RISK-NNN`, `SEC-*`) and title intent. If an equivalent is open, update it or comment on it; do not open a duplicate.
2. When duplicates already exist, pick ONE canonical PR by, in order: correctness, completeness (a superset wins), tests, conflict size, freshness. Close the rest with one comment each naming the canonical PR and why it won, and list any unique delta the canonical must port before it is ready.
3. A closed duplicate's unique delta is the canonical's debt: port it (or record why not) before calling the canonical ready.

## Bring main in and resolve conflicts

- The repository merges PRs with merge commits. Bring main into a PR with a merge commit; never rebase or force-push another author's branch.
- Root [CLAUDE.md](../../../CLAUDE.md) on main is a short adapter (decomposed by #1592). A PR hunk that adds file-map or section lines to the old monolithic `CLAUDE.md` is resolved by keeping main's adapter and dropping those lines. A durable contract the hunk carried belongs beside its owner and tests or in the matching `docs/agent-context/domains/*` document, never in a `docs/agent-context/history/*` file (those blocks are hash-frozen).
- [CHANGELOG.md](../../../CHANGELOG.md) `[Unreleased]` conflicts: keep both entries.
- Finding and registry IDs are assigned in merge order. Check the highest ID on current main for the register being extended (terminology `T-NN` in the latest `docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-*.md`, chaos `CHAOS-NN` in [the chaos review](../../../roadmap/CHAOS-ENGINEERING-REVIEW.md), [technical risk](../../engineering/TECHNICAL-RISK-REGISTER.md) `RISK-NNN`, security-review `SEC-*`). The PR that merges next takes the next free number; later PRs renumber when they bring main in. Do not resolve an ID collision by keeping both numbers.
- After bringing main in, re-read the pins and gates the merge may have changed ([verification](verification.md), "Toolchains and module boundaries").

## CI triage

Known noise, verified on each occurrence and never assumed:

- golangci-lint "Timeout exceeded ... 0 issues" (exit 4) is runner time, not a finding. Re-run that child once. A second timeout or any reported issue is a real failure.
- govulncheck failures for `x/net` advisories, and frontend lockfile audit failures, on branches based before `28a43efb` are fixed by bringing main in, not by waivers.
- The rollup jobs ("Fast PR Gate — APPROVED", "Race · verdict") fail only because a child failed: read the child, never the rollup.
- A suspected flaky timing test is confirmed against main (same test, recent main runs) before it is called a flake; [migration.md](../migration.md) records examples. Record the run id, seed and test name.

A real failure is fixed in the PR, not re-run. Choose the fix's checks with [verification](verification.md). Do not lower a floor, add an exclusion, update a snapshot blindly or weaken an assertion to turn a gate green.

## Readiness gates

A PR is "ready" only when all of these hold, and the report says which hold:

1. CI is green on the CURRENT head, evaluated against current main (the required aggregates are "Fast PR Gate — APPROVED" and "Deep PR Gate — APPROVED"; an old green run on a stale head does not count).
2. No unresolved blocking review thread: Codex P1/P2, CodeRabbit major, red-circle Claude Code Review findings. Bot findings are claims to verify with a traced path (caller, contract, consequence) using [review-change](review-change.md); a verified non-issue is resolved with the evidence, not ignored.
3. The PR's latest meaningful review covers the current code; a review of an older head is stale.
4. No open duplicate or superseding PR, and every PR it depends on is merged.
5. The PR is outside the owner-managed scope above, or the owner acted on it.

## Owner decisions already made

Treat these as the default; do not re-litigate them in review threads or re-implement the rejected alternative:

- Viewer-readable diagnostics (`/api/diagnostics`, `/api/health/explain`, `/api/stats`) follow least privilege: viewers get status plus a fixed message; counts, 2FA and backup-code detail are admin-only through a role-aware redaction helper (`redactContractForRole` in the canonical PR). See [admin control plane](../domains/admin-control-plane.md).
- IdP unavailability is degraded availability, not revocation. Only delete/disable revokes sessions. Stale-if-error applies only to transport errors and 5xx, bounded by min(7 days, SAML `validUntil`).
- Login throttling keeps main's atomic Reserve/Refund; no check-then-act replacement.
- Alert event names follow `<contract-row>_down` (for example `socks5_listener_down`), and every new alert event needs its `wh-event` webhook checkbox (GUI parity, [conventions](../conventions.md)).
- A node must not claim the CP role or renew an HA lease while its listener is not serving.
- The product term for console accounts is "Administrators" ([product terminology](../../design/PRODUCT-TERMINOLOGY.md)).

## Merging and reporting

The steward never merges. It reports a PR as ready with the gate evidence and waits for explicit human approval of that PR; "green and reviewed" is a readiness fact, not approval.

- One comment per PR when standing it down (closing a duplicate, superseding, or declining a bot finding), naming the canonical PR or the evidence.
- A fleet summary is concise: counts per state (ready, blocked on CI, blocked on review, duplicate/closed, owner-managed, untouched), the recommended merge queue in order, and the current action. Comments and summaries end with the repository's Claude Code footer (`🤖 Generated with [Claude Code](https://claude.com/claude-code)` plus the session link).
- Report what was not verified (checks not run, reviews not re-requested) and why. A passing local check is not a passing hosted gate.
