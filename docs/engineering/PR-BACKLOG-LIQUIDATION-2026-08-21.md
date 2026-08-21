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
| #957 | codeql-action/init →4.37.3 | CLOSED-SUPERSEDED | main already at 4.37.4 on all codeql pins; net diff was comment-only; branch conflicted. Family consolidated to 4.37.7 via #1150. |
| #1148 | golang.org/x group (crypto 0.55, net 0.58, text 0.41) | MERGED (`292be8e`) | Newest known versions; both PR gates green; local build+vet on merge with current main passed. |
| #1149 | protobuf 1.36.12 | MERGED (`5ffdc4b`) | Gates green; verified clean stack on top of #1148 locally (go.mod/go.sum auto-merge + build). |
| #1151 | harden-runner 2.21.0 | MERGED (`5b0407a`) | All 21 pins across 12 workflows updated consistently; both gates green. |
| #1150 | codeql-action → 4.37.7 (consolidated) | FIXED+MERGED (`88bd9bd`) | `codeql_action_pin_test.go` requires ONE revision across init/analyze/upload-sarif in codeql.yml + security-release-gate.yml; original PR bumped analyze only (its own CodeQL run failed on the mixed pins). Carried #1152's upload-sarif ×5 into this branch + lock-step init bump; pin test verified locally vs current main. |
| #1152 | codeql-action/upload-sarif → 4.37.7 | CLOSED-DUPLICATE | Consolidated verbatim into #1150 (merging alone would break the pin wall on main). |
