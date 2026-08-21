# PR Backlog Liquidation — 2026-08-21

Audit ledger for the repository-wide open-PR reconciliation operation.

- **Baseline `origin/main`:** `40a8f465b76d25dd2ed64aa6512e269ecb3ce5bc` (merge of #1182)
- **Open PRs at start:** 100 (99 actionable; **#1181 excluded/protected** — head `claude/culvert-policy-learning-mode-kwp122`, untouched throughout)
- **Target terminal state:** exactly one open PR (#1181)

## Method

1. All 99 actionable PR heads fetched as `refs/prs/<N>`; per-PR merge-base, diffstat,
   `git merge-tree` conflict status, and already-in-main status computed against baseline main.
2. Relationship graph built from file overlap + title/subsystem/finding identity; families
   analyzed with coverage matrices before choosing canonical PRs.
3. Every merge candidate revalidated against **current** `origin/main` (build + focused tests +
   repo gates), not historical CI.
4. Every close carries a recorded reason and a check for unique value to port.

## Decision log

(One row per PR; appended as decisions are executed. Outcomes: MERGED, FIXED+MERGED,
CLOSED-DUPLICATE, CLOSED-SUPERSEDED, CLOSED-ALREADY-PRESENT, CLOSED-OBSOLETE, CLOSED-UNSAFE.)

| PR | Title (short) | Outcome | Rationale / evidence |
|----|---------------|---------|----------------------|
