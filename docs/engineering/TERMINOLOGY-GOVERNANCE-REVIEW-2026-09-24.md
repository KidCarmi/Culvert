# Culvert Language & Terminology Governance Review — 2026-09-24

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope (read this first):** this is a HISTORICAL record of `origin/main` at `6ec745d` on
> 2026-09-24. It was merged later, after `main` had moved on, so the tree it ships in contains commits it
> never audited. Every finding, file:line citation, backlog count and score below describes `6ec745d`
> unless it is explicitly labelled "for comparison only". This report makes no copy or code change, so
> there is no separate "after this PR's corrections" state. Fixes merged to `main` after `6ec745d` —
> T-57 (#1407), T-58 (#1434), T-17 (#1444), T-59 with the T-51 recurrence lines (#1456), and #1482's
> zero-ID copy and comment changes — are NOT applied to the audited state; they appear only in the
> comparison row.
>
> Neither this snapshot nor the comparison row is the tree this file is published in; the current
> governance state is whatever the most recent review in this series says. Later windows are audited by
> later reports, never retroactively by this one.
>
> **Method:** audited `3febe59..6ec745d` — 3 first-parent merges (#1478, #1486, #1487), 31 files, 2,409
> insertions. `3febe59` is the audited snapshot of the 2026-09-23 report (#1482), which is an ancestor of
> `6ec745d`. The end commit `6ec745d` was the then-current `origin/main` HEAD by a fetch immediately
> before this report was first written (the DEBT-014 lesson: sync against `main` right before opening a
> PR). All three merges are CI-REDESIGN stage 6B work and a test refactor: `cmd/cireport`,
> `.github/workflows/ci-perf-report.yml`, `apicontract_*_test.go` and `ci_perf_report_dispatch_test.go`,
> `roadmap/CI-REDESIGN.md`, one `CLAUDE.md` line (the `cireport` entry) and one number in
> `docs/operator/mcp-first-controlled-canary-review.md` (a scanned-file count, 2,602 → 2,605). No GUI
> file, REST handler, OpenAPI file, audit action, alert name, metric, config key or generated type
> changes (`git diff --name-only 3febe59 6ec745d` lists no such file).
>
> **Window correction (reconciliation with the merged #1456 and #1482):** earlier revisions of this
> report audited `574d265..6ec745d` (34 merges, 256 files). That range overlaps windows already audited
> by merged reports: `46410c3..6c46ebd` by the 2026-09-21 report (#1456; `46410c3` is the 2026-09-11
> report's branch head, two report commits on top of `574d265`, so that window covers every other commit
> from `574d265` to `6c46ebd`, including #1362 and #1366), and `6c46ebd..3febe59` by the 2026-09-23 report (#1482). The window is narrowed to
> the part neither covers. Everything those earlier revisions recorded about the overlapping part —
> the OCSP, GeoIP, admin-login and MCP `reviewed_operation_class` name mappings, the 30-line "appliance"
> inventory, the glossary sweep of 574d265..6ec745d and the two merges added in review (#1362, #1366) —
> is withdrawn from this report and left to the reports that own those windows. Their IDs (T-54,
> T-59, T-59b, T-59c, T-60, the T-51 recurrence, T-61, T-62, T-63) are carried below, not charged again.

---

## Executive Summary

**No new terminology drift found in `3febe59..6ec745d`, no new ID minted, and no fixes made.**

1. **No admin-facing name changed in the window.** The three merges touch CI tooling, CI workflows,
   tests and engineering records only. The one `docs/operator/` change is a number inside a sentence
   (`mcp-first-controlled-canary-review.md:3022`), with no new word.
2. **Glossary sweep of the window's added lines** (literal patterns only; see "Glossary term sweep"):
   no visible hit. Every hit is in `roadmap/CI-REDESIGN.md`, test files, or `cmd/cireport` output, which
   is CI vocabulary, not product copy.
3. **Carry-over spot-checks at `6ec745d`** (rather than trusting the prior report alone):
   - **T-11** — `config.go:532` still accepts only `"allow"`/`"deny"` for `default_action`, while
     `policy.go:24-27` still has no `Deny`/`Block` value (`ActionAllow | ActionDrop | ActionBlockPage |
     ActionRedirect`).
   - **T-12** — `cmd/culvert-maint/internal/server/server.go:406` still registers
     `POST /v1/upgrades/apply`. No code or config file contains `/v1/updates/apply`; the only occurrence
     in the tree is a recommendation in `TERMINOLOGY-GOVERNANCE-REVIEW-2026-07-16.md:191`.
   - **T-29/T-30** — `config.go` still has no `rate_limit_rpm` or `conn_limit_max_per_ip` key; only
     `security.rate_limit` and `security.max_conns_per_ip` exist (`config.go:56-57`).
   - **T-54** — `ui_security.go:1843` still says `malformedResponseTotal` and `ocsp_metrics.go:62` still
     counts `responder_blocked` in the rejected-responses series.

   The other carried IDs were not re-verified. Because the window changes no GUI, API, audit, alert,
   metric or config file, none of them could have been opened or closed in it.

**Terminology Health Score — audited snapshot `6ec745d`: 7.5 / 10** (lineage figure; fully charged
equivalent **7.4** — see below).

- **Rule** (the 2026-09-08 precedent, as applied by the 2026-09-19, 2026-09-21 and 2026-09-23 reports):
  each open backlog item a report newly records costs 0.1, and each item it fixes gives 0.1 back. An item
  already charged by an earlier report is never charged a second time.
- **Baseline: 7.5**, the 2026-09-23 report's figure for its audited snapshot `3febe59`. That is the right
  baseline for `6ec745d`: `3febe59` is an ancestor, nothing in `3febe59..6ec745d` opened or closed a
  backlog item, and every terminology fix merged since — T-57, T-58, T-17, T-59 and #1482's own changes
  — merged AFTER `6ec745d`.
- **Audited snapshot `6ec745d`:** no new ID, no fix → **7.5**.
- **For comparison only (not a claim about any audited tree):** applying the same rule to `6ec745d` plus
  the four later fixes (T-57, T-58, T-17, T-59) gives 7.5 + 0.4 = **7.9** (same lineage; fully charged
  7.8). #1482's changes close no ID, so they move neither figure. This matches #1482's own comparison
  row.
- **Disclosed, not amended (carried from the 2026-09-16, -19, -21 and -23 reports):** the 2026-09-13
  report measured its drop from 8.7 rather than from the 2026-09-12 report's 8.6, so T-54's 0.1 charge
  was not carried into its 8.4. Merged reports' scores are not amended retroactively; this report takes
  the merged figures as recorded. It neither restores T-54's missing 0.1 nor charges T-54 again: 7.5 and
  7.9 are lineage figures that UNDER-charge by 0.1. For transparency only, the fully charged equivalents
  are **7.4** (audited snapshot) and **7.8** (comparison row); they are not this report's score.
- **Disclosed, not amended — a second, parallel lineage:** the 2026-09-20 report (#1444, the T-17 fix)
  records **8.8 / 10, up from 8.7**, with twelve open backlog entries. It scores from the 2026-09-11
  report's lineage and does not count T-54..T-63 or the T-51 residual, so its 8.8 and this chain's
  figures are not comparable. This report does not reconcile the two lineages; that is left to an owner.

(Earlier revisions of this report said 8.7, then 8.6, with a fourteen- then fifteen-ID backlog. Both
came from the 2026-09-11/-12 lineage, which omits T-55 through T-63 and the T-51 residual, all open at
`6ec745d`. They are corrected here rather than silently replaced.)

---

## Carried-Over Findings

Every ID below is carried as open at `6ec745d`, taken from the 2026-09-23 report's audited-snapshot
backlog (27 IDs / 26 entries at `3febe59`). Full descriptions live in the report that owns each ID and
are not restated here, to avoid two descriptions of one item drifting apart:

- T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33,
  T-34, T-39 — owned by `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md`. T-17 is fixed on `main` by #1444,
  merged after `6ec745d`.
- T-54 — owned by the 2026-09-12 report (#1372).
- T-55, T-56 (code half) and the T-51 residual — owned by the 2026-09-13 report (#1380).
- T-57 — owned by the 2026-09-16 report (#1407); fixed on `main` by #1407, merged after `6ec745d`.
- T-58 — owned by the 2026-09-19 report (#1434); fixed on `main` by #1434, merged after `6ec745d`.
- T-59, T-59b, T-59c, T-60 — owned by the 2026-09-21 report (#1456). T-59 (and the T-51 recurrence
  lines, which carry no ID of their own) is fixed on `main` by #1456, merged after `6ec745d`.
- T-61, T-62, T-63 — owned by the 2026-09-23 report (#1482). Its T-61 comment and T-62 legacy-GUI copy
  merged after `6ec745d` and close neither ID.

**Backlog count:**

| State | Open IDs | Backlog entries (T-21+T-32 counted once) |
| --- | --- | --- |
| 2026-09-23 report, its audited snapshot `3febe59` | 27 | 26 |
| Audited snapshot `6ec745d` (no ID opened or closed) | 27 | 26 |
| For comparison only: `6ec745d` plus #1407 (T-57), #1434 (T-58), #1444 (T-17), #1456 (T-59) and #1482 (no ID closed) | 23 | 22 |

The comparison row agrees with the 2026-09-23 report's own comparison row (23 / 22).

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to the
numbered backlog, per the 2026-09-09 report's reasoning.

### Reproduction commands

Run from any clone that has fetched `6ec745d`:

```sh
R=6ec745d
git diff --shortstat 3febe59 $R                       # 31 files, 2409 insertions
git log --first-parent --oneline 3febe59..$R          # 3 merges
git grep -n 'da != "allow" && da != "deny"' $R -- config.go            # T-11
git grep -n 'POST /v1/upgrades/apply' $R -- cmd/culvert-maint/internal/server/server.go   # T-12
git grep -n -e rate_limit_rpm -e conn_limit_max_per_ip $R -- config.go # T-29/T-30: expect none
git grep -n '"malformedResponseTotal"' $R -- ui_security.go            # T-54
git grep -n 'responder_blocked' $R -- ocsp_metrics.go                  # T-54
```

---

## Glossary term sweep

The literal terms `docs/design/PRODUCT-TERMINOLOGY.md` forbids, reserves or replaces were checked against
the lines this window ADDED:
`git diff 3febe59 6ec745d -U0 | grep -v '^+++' | grep -ciE '^\+.*<pattern>'` (case-insensitive substring;
`grep -v '^+++'` drops diff file headers). "Visible" means `static/index.html`, non-test `frontend/src`,
`api/openapi/openapi.yaml`, `docs/` outside `docs/engineering`, `docs/design` and `docs/adr`,
`CHANGELOG.md` and `README.md`.

The sweep covers only the literal patterns in the table: the glossary's forbidden or replaced words,
matched as substrings. It does **not** cover the glossary's context-sensitive rules, which a pattern
count cannot decide and which this pass did not check: "policy" used loosely for a single rule, bare
"profile" on the steering-profile screen, "status" used for a health roll-up, "user" where it could mean
a console account, "kill switch" without its qualifier (the table counts the literal only),
"exception"/"bypass"/"allowlist" used for the wrong kind of skip, and sentence case. A term missing from
the table, or a zero count, is not evidence that those rules hold.

| Term (pattern) | Added lines | Visible | Where | Outcome |
|---|---|---|---|---|
| appliance (`appliance`) | 1 | 0 | `roadmap/CI-REDESIGN.md` | Engineering record — not product copy |
| verdict (`verdict`) | 29 | 0 | `roadmap/CI-REDESIGN.md` (13), `cmd/cireport` (6 in 4 non-test files), tests (10) | CI vocabulary (the race job's `verdict.json`) — no violation |
| result (`result`) | 15 | 0 | `roadmap/CI-REDESIGN.md` (9), `cmd/cireport/evidence.go` (1), tests (5) | CI vocabulary — no violation |
| incident, scanner, policy rule, exclusion, kill switch (`kill.?switch`), unauth mode (`unauth.?mode`), threat engine, Cluster Nodes, blacklist/whitelist, Live Feed, Live Request Log, Recent Requests, Users & Roles, proxy pool | 0 each | 0 | — | — |

**Strings emitted by Go code.**
`git diff 3febe59 6ec745d -U0 -- '*.go' ':!*_test.go' | grep -v '^+++' | grep -iE '^\+.*"[^"]*<pattern>[^"]*"'`
finds 4 "verdict" and 1 "result" lines, all in `cmd/cireport` (`analyze.go`, `evidence.go`, `main.go`,
`trend.go`): a problem line about the race verdict's shard count, the `verdict.json`/`results.json`
artifact names, the `run` summary line and the trend table header. `cmd/cireport` is the CI performance
reporter; maintainers read its output in the Actions log and step summary, and no page under
`docs/operator/` sends an operator to it. CI vocabulary, not product copy — no violation. Every other
table term: 0 lines.

**Emitted text outside Go.** The same patterns over
`git diff 3febe59 6ec745d -U0 -- '.github/**' 'scripts/**' 'packaging/**' '*.sh' 'Dockerfile*' 'Makefile' 'docker-compose*.yml' ':!*.json' | grep -v '^+++' | grep -vE '^\+\s*#'`
find 0 added lines. (`ci-perf-report.yml` is the only such file the window changes.)

This report mints no IDs and changes no product copy.

---

## Stop-Condition Assessment

No production-worthy new terminology improvement was identified in `3febe59..6ec745d`: the window is
CI-REDESIGN stage 6B tooling, a test refactor and engineering records, with no admin-facing name added
or changed. The carried backlog — 27 IDs / 26 entries at `6ec745d` — stays open with its original
evidence; T-11, T-12, T-29, T-30 and T-54 were spot-checked at their cited locations and the rest were
not re-verified. Score 7.5 (lineage; fully charged 7.4). For comparison only, with the fixes merged
after `6ec745d`: 23 / 22 and 7.9 (fully charged 7.8). T-54's lost 0.1 is disclosed, not renormalised,
and the parallel 8.8 lineage of the 2026-09-20 report (#1444) is disclosed, not reconciled. The checks
matched literal patterns only (see "Glossary term sweep"). No cosmetic or preference-driven renames are
proposed.
