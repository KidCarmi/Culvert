# Culvert Language & Terminology / Documentation Governance Review — 2026-09-05

> **Owner:** Documentation Governance & Knowledge Guardian routine · **Status:** Point-in-time review (repeatable)
> **Method:** This pass departed from the usual single-window commit diff. `main` has not moved since
> `2026-08-25` from this program's point of view (no governance PR has merged in that window), so instead
> of auditing new commits for fresh drift, this pass audited **the governance program's own output**:
> every open `docs`/`docs(governance)` pull request against KidCarmi/Culvert, cross-checked line-by-line
> against the current `origin/main` tip (`290e376`) to confirm (a) the claimed drift is real, (b) the fix
> is still correct, (c) CI is green and no reviewer changes are outstanding, and (d) no two open PRs
> silently conflict. This was prompted by PR #1260 (2026-08-30) recording a "process note" that two
> earlier governance PRs contained unmerged, un-superseded fixes — that note has itself now sat unmerged
> for six days, which is itself evidence for the finding below.

---

## Executive Summary

**No new terminology drift was found in `main` this pass, because `main` has not moved through this
program's usual review surface since 2026-08-25.** Instead, this pass found and verified a **process
defect in the governance program itself: verified, CI-green, non-conflicting documentation fixes are
accumulating in open PRs faster than they are being merged, and later scheduled runs are re-discovering
and re-fixing defects that earlier runs already fixed**, because a fix that never reaches `main` is
indistinguishable, from the next run's point of view, from a defect nobody has looked at yet.

**Concretely verified against `origin/main` @ `290e376` today:**

| PR | Opened | Claim | Verified against `main` today | CI | Reviewer changes requested |
|---|---|---|---|---|---|
| #1239 | 2026-08-28 | T-31: dual-emit `culvert_clamav_scan_errors_total` | Still missing on `main` | ✅ green | None |
| #1250 | 2026-08-29 | `internal/mcp` subpackage count 25→27 (CLAUDE.md ×3, dashboard ×1) | `internal/mcp` has 27 subdirs today; CLAUDE.md still says 25 in 3 places | ✅ green | None |
| #1253 | 2026-08-29 | T-48: ADR-0034 collision (4th recurrence), +T-49–T-51 | Collision still live on `main` | ✅ green | None |
| #1284 | 2026-09-01 | T-48 again (independent rediscovery) | same live collision | ✅ green | None |
| #1294 | 2026-09-02 | T-48 again (independent rediscovery) | same live collision | ✅ green | None |
| #1293 | 2026-09-02 | README `internal/` package count 63→65 | README still says 63; actual count is 65 | ✅ green | None |
| #1300 | 2026-09-03 | Stale/overstated ADR status on 5 supportability/policy-learning ADRs | All 5 status lines unchanged on `main` | ✅ green | None |
| #1302 | 2026-09-03 | T-48 again (independent rediscovery) | same live collision | ✅ green | None |
| #1308 | 2026-09-04 | README "near-term" claim re: catalog-driven release path, already shipped | Sentence unchanged on `main`, contradicts DEBT-008 (closed) and CLAUDE.md's P2b-2b section | ✅ green | None |
| #1309 | 2026-09-04 | T-48 again, **plus a new CI gate** (`TestADRNumbering_NoDuplicateAcrossADRAndRFCTracks`) that fails the build on a future recurrence | same live collision; gate verified in the PR description (synthetic-duplicate test) | ✅ green | None |

**One finding, T-48 (the ADR-0034 numbering collision, first raised 2026-08-25 as T-47's successor),
was independently fixed five separate times** (#1253, #1284, #1294, #1302, #1309) by five different
scheduled runs, each of which correctly found the live defect on `main`, correctly wrote the same
docs/adr/rfc rename, and had no way to know four earlier runs had already done the identical work,
because none of that work had merged. #1309 is the canonical keeper: identical content rename plus a
permanent regression gate the other four lack. The other four are strict duplicates once #1309 lands.

This is not a new terminology-drift finding in the sense the rest of this report series tracks — it is
a **program-health finding**, recorded as **DEBT-014** in `docs/engineering/TECHNICAL-DEBT-REGISTER.md`
rather than as a numbered `T-` item, following the same precedent the 2026-08-25 report used for its
"ADR-number reservation convention" recommendation (a process gap, not a mechanical rename with a
migration plan).

**Terminology Health Score: 8.6 / 10 (unchanged).** The score tracks drift *in the codebase and its
current documentation*, and none of that changed this window — `main`'s content is byte-identical to
2026-08-25 from this program's perspective. The score does not drop for the backlog itself (that is a
process/delivery metric, tracked separately in the Technical Debt Register), but it also cannot rise:
five of this program's own prior findings (T-31, T-48, the two README count fixes, the ADR-status fix)
are fully diagnosed and fixed in PRs, yet remain live defects on `main` today.

---

## Documentation Health Score

| Axis | Score | Basis |
|---|---|---|
| Knowledge coverage | 8.5 / 10 | Unchanged since 2026-08-25; CLAUDE.md remains the authoritative, current map for every shipped subsystem this pass touched. |
| Currency (docs match `main` today) | 7.0 / 10 ↓ | Five previously-diagnosed, already-fixed drift items (T-31, T-48, README×2, ADR-status×5) remain live on `main` solely because their fixes are unmerged — a currency gap this program has already closed on paper but not in fact. |
| Process health (fixes reach `main`) | 3.0 / 10 (new axis) | 0 governance PRs merged in 11 days; 1 finding independently fixed 5 times; a prior process-note PR (#1260) about this exact problem is itself unmerged. |
| Contradiction-freedom | 9 / 10 | No new same-window contradictions found (none to find — no new commits to `main` in this window). |

The new **Process health** axis is added this pass because the existing four-axis model (from the C3
governance-surface precedent this program borrows its health-axis framing from) has no way to represent
"the finding was correct and the fix was correct, but nothing changed" — which is exactly this window's
dominant condition and needs its own signal so it cannot be silently absorbed into a healthy-looking
Currency or Coverage score.

---

## New Finding: the governance-PR merge backlog (recorded as DEBT-014, not a `T-` item)

See `docs/engineering/TECHNICAL-DEBT-REGISTER.md` DEBT-014 for the full principal/interest/remediation
write-up. Summary for this report:

- **What:** 10 open, CI-green, non-conflicting `docs`/`docs(governance)` PRs, oldest 11 days old, none
  merged since `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md` landed.
- **Worst instance:** T-48 (ADR-0034 numbering collision) independently fixed in #1253, #1284, #1294,
  #1302, and #1309 — five complete, correct, mutually-redundant diffs for a one-file rename plus five
  citation updates.
- **Recommended merge order** (verified non-conflicting by file-list, except the T-48 quintet which are
  mutually exclusive by design — merge exactly one):
  1. **#1309** for T-48 (supersedes #1253/#1284/#1294/#1302 — same content, plus the
     `adr_numbering_test.go` CI gate the others lack). Close the other four as superseded.
  2. **#1239** (T-31 ClamAV metric dual-emit), **#1250** (mcp subpackage count), **#1293** (`internal/`
     package count), **#1300** (ADR status corrections), **#1308** (README release-path claim) — five
     independent, non-overlapping, single-concern fixes, mergeable in any order.
  3. **#1260** (T-52 Incident-row fix) — re-verify against `main` at merge time since it is the oldest
     of the batch and touches `docs/design/PRODUCT-TERMINOLOGY.md`, a file none of the above touch.
- **Why no PR is opened by this pass to re-fix any of the above:** doing so would add an eleventh
  duplicate to the exact backlog this finding is about. This report's only content-level action is
  the DEBT-014 entry itself, which is new (no open PR already tracks the backlog as a debt item) and
  therefore not a duplicate of anything pending.
- **Action needed:** merge, by a human with repository write judgment. No further automated documentation
  pass can discharge this — the fixes already exist and are correct; what is missing is the merge.

---

## Carried-Over Findings

All content-level backlog items from `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md` (T-9, T-11, T-12,
T-13 residual, T-17, T-18, T-21+T-32, T-25 residual, T-29, T-30, T-31, T-33, T-34, T-39) are unchanged:
`main`'s content has not moved for this program's review surface since that report, so there is nothing
new to re-diff them against. T-31's disposition is additionally clarified above: it has a correct,
unmerged fix (#1239), it is not undiagnosed.

---

## Stop-Condition Assessment

Terminology in `main` is unchanged from the 2026-08-25 assessment (not fully consistent, no new drift
found or introduced). This pass's production-worthy contribution is not a terminology rename but a
governance-process finding that a future automated pass cannot fix by writing more prose: **DEBT-014**,
newly recorded, non-duplicative of any open PR, with a concrete recommended merge order for the
repository owner. Per this program's own stop condition ("no documentation governance changes are
required" only when nothing production-worthy exists to report) — this does not apply here, since the
backlog itself is a live, evidenced, previously-untracked risk. No cosmetic or preference-driven change
is proposed, and no existing open PR's content is duplicated.
