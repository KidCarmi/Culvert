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
| #1137 | perf(blocklist) alloc-free matcher | MERGED (`5dd58ba`) | Behavior-preserving, differential bench in-tree, both gates green; validated locally on current main. |
| #1158 | perf(proxy) HTTP via transport | MERGED (`f0d24aa`) | Behavior audit clean (no-redirect preserved, timeout semantics reproduced via context, userinfo→Basic promotion reimplemented + pinned); forward tests + benchgate green locally. |
| #1123 | perf(threatfeed) lock-free read view | MERGED (`2cf650f`) | Canonical of the threatfeed pair (deeper than #1142's flag-only variant); race tests green on current main. |
| #1142 | perf(secscan) lock-free scan gates | FIXED+MERGED (`4dd03ee`) | Reduced to its unique secscan half; threatfeed half superseded by #1123 and dropped in a semantic merge. |
| #1087 | perf(urlcat) index (v1) | CLOSED-DUPLICATE | Superseded by #1164; heavier per-pattern struct was the open P1 memory finding; conflicted with main. |
| #1131 | perf(urlcat) index (v2) | CLOSED-DUPLICATE | Superseded by #1164; least complete of the four (no benchgate/fuzz/CLAUDE.md; failing race job). |
| #1164 | perf(urlcat) reverse index (canonical) | FIXED+MERGED (`5735f92`) | Canonical of 4 competing implementations. Pre-merge: G404 fix, #1171's O(1) AddHost fold ported (3 pin tests), policy.go cost comment ported. Race + differential + benchgate green vs current main. |
| #1171 | perf(urlcat) index (v4, lazy) | CLOSED-DUPLICATE | Unique value (O(1) AddHost fold, policy.go comment) ported into #1164 before closing; lazy-rebuild design rejected (request-path write lock after every mutation; MatchesHost race left in place). |
| #1180 | perf(policy) once-per-scan category fusion | FIXED+MERGED (`2d32b8e`) | Complementary to #1164; composed on rebase (dedup'd benchmark helpers, refreshed stale cost comments, redesigned ratio gate to marginal-vs-one-fusion since the index changed the cost floor). Full root suite green locally. |
| #1109 | perf(proxy+ssrf) alloc-free scrub + netip guard table | FIXED+MERGED (`c0e7651`) | The two G115 test-lint nits fixed (#nosec with bounds justification); additive bench_regression_test.go merge resolved keeping both sides; full benchgate suite (235s) green locally. |
| #1115 | perf(scan) pre-size scan buffer | FIXED+MERGED (`873adae`) | Open P1 fixed before merge: hint allocation deferred until the origin delivers bytes (512-B seed first), so declare-and-stall origins cost the old path's footprint; new pin test + ReadAll-equivalence preserved. |
| #1082/#1062/#912/#930/#1160/#1042/#1104/#899/#1168/#1174/#878/#915/#982/#863/#965/#981/#1084/#1107/#1121/#1169/#1175/#1162/#1111/#805 | docs family (24 PRs) | MERGED | Each fact-checked against current main before merge. Reworked pre-merge: #1062 dropped its wrong README count (#1082 canonical); #1174 absorbed #1141's unique rows; #982 moved into the maintained docs/security-reviews/ series; #981 renamed its same-day report to -B and had its kin-openapi pins corrected to the real v0.146.0; #1111 kept its corrected trusted-root sentence over main's stale one and absorbed #1089's M1-4 bullet; #805 had its now-false "M6/M7 design-only" claims rescoped to the TAC cloud tier. |
| #1127 | pkg-count docs | CLOSED-SUPERSEDED | By #1082 (strict superset). |
| #1002 | pkg-count docs (old) | CLOSED-OBSOLETE | Counts wrong twice over; conflicted; MCP bullet contradicted by shipped ADR-0024 state. |
| #1135 | MCP PR-12 naming docs | CLOSED-SUPERSEDED | By #1168 (14 files + D-12 record vs 1 file; same lines edited). |
| #1141/#1154 | /ready docs | CLOSED-SUPERSEDED | By #1174; #1141's two unique rows (clamav fixed-detail, admin_settings kind) ported into #1174 first. |
| #1090/#1113/#1128/#1155 | report-only terminology runs | CLOSED-SUPERSEDED | All strict-subset windows of #1175 (merged) against the same 08-07 baseline; #1113's T-9 evidence footnote recorded here: T-9's rename evidence now depends on the alerts_event_rename_import_test.go fixture. |
| #1089 | release-catalog docs | CLOSED-SUPERSEDED | By #1111; unique M1-4 re-sign bullet ported first. |
| #932 | terminology + metric rename | CLOSED-OBSOLETE | Its support_uptime_bucket rename now breaks the M7 telemetry golden-fixture wall built after it (verified: 8 tests fail, regeneration refuses without a coordinated fixture value) — a cross-repo wire-contract decision for the telemetry owner, not a sweep. Unique UI copy fix (Per-appliance→Per-node ×2) ported via #1136. |
| #854 | ADR-0023 re-land ("do not merge") | CLOSED-OBSOLETE | Explicit do-not-merge; documents internal/filetxn which still does not exist on main a month later; ADR number 0023 remains free; branch preserved for revival. |
