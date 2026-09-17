# Culvert Language & Terminology Governance Review — 2026-09-17

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Fetched `origin/main` and confirmed HEAD is still `993b390` (Merge PR #1374) —
> byte-identical to the state `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-16.md` (open PR #1407) audited the
> day before. **Zero commits landed on `main` in the 24 hours between that report and this one**, so
> there is no new diff window to run the usual cross-surface sweep against. This pass instead (1)
> independently spot-verified three carry-over/pending items directly against the tree rather than
> trusting the prior report's word for it, and (2) re-surveyed the open-PR backlog this program's own
> DEBT-014 finding tracks, since that backlog has materially worsened since it was last measured.

---

## Executive Summary

**No new terminology drift to report — `main` has not moved.** This is a legitimate, verified stop
condition, not an assumption: `git log --oneline -1 origin/main` was checked before writing this report
and again immediately before opening its PR, both times returning `993b390`. Every subsystem merged since
the last *merged* governance report (`d378dff`, 2026-09-11) — the CHAOS-65 OCSP work, the MCP
"read-first"/"First Canary exact scope" classification slices, and the rate-limit exempt-CIDR sharding —
was already swept by #1407 (2026-09-16), which found one real fix (T-57, the legacy Support panel's
"diagnostic bundle" vs. canonical "support bundle" wording) and nothing else. Re-auditing that same,
unchanged window a second time would manufacture exactly the duplicate-analysis cost DEBT-014 exists to
name, so this pass does not repeat it.

**Spot-checks performed directly against the current tree** (not inherited from a prior report's text):

1. **T-57 confirmed still open on `main`** — `static/index.html:5184,6119,16205` still read "diagnostic
   bundle" in the legacy Support panel's button tooltip, nav subtitle, and create-confirmation dialog,
   exactly as #1407 describes. Its fix exists only inside the still-unmerged #1407; this review does
   **not** write a second, competing fix for the same finding (that would recreate the T-48/ADR-0034
   five-way-duplication pattern DEBT-014 already catalogued). The correct action is merging #1407, not
   re-deriving its diff.
2. **T-13 confirmed still open** — `docs/enterprise/TLS-INSPECTION-DEPLOYMENT.md:1` is still titled
   "TLS Inspection Deployment," unresolved against the in-app "SSL Inspection" vocabulary, unchanged
   from every prior report back to its first appearance.
3. **T-29/T-30 confirmed still open** — `config.go` still has no `rate_limit_rpm` or
   `conn_limit_max_per_ip` alias; grepping the live file for both strings returns nothing.

No new finding is added to the numbered backlog this pass. All fourteen previously open finding IDs
(T-9, T-11, T-12, T-13, T-17, T-18, T-21+T-32 paired, T-25, T-29, T-30, T-33, T-34, T-39) remain open and
unchanged; three of them were independently re-verified above rather than carried forward on trust alone.

**Terminology Health Score: 8.7 / 10** (unchanged since 2026-09-08/09/11 — no drift was introduced
because nothing merged, and the carry-over backlog has not moved).

---

## DEBT-014 status update — the backlog this program depends on being merged has grown, not shrunk

DEBT-014 (`docs/engineering/TECHNICAL-DEBT-REGISTER.md`, opened 2026-09-05) names the mechanism precisely:
this routine correctly finds real, low-risk, CI-green drift and opens PRs, but the PRs pile up unmerged,
so later runs either re-find the same defect or spend part of their pass on backlog archaeology instead of
new drift. Fresh numbers, checked live via the GitHub API immediately before writing this section (not
inherited from any prior report):

- **39 open pull requests** on `KidCarmi/Culvert` as of this pass (`is:pr is:open`, full-repo count).
- **6 of those are this program's own dated reports**, none merged since #1380 (2026-09-11's `d378dff`
  merge) was the last one to land — every report since has stacked up unmerged:
  - **#1372** (2026-09-12) — per #1402's and #1407's own re-verified triage, genuinely merge-ready
    (every review thread resolved, verified follow-up commits). Open **5 days**.
  - **#1373** (2026-09-12) — same triage verdict, disjoint files from #1372. Open **5 days**.
  - **#1380** (2026-09-13) — held per its own review threads disputing content accuracy. Open 4 days.
  - **#1395** (2026-09-14) — held for the same reason (T-21/T-32 risk-rating correction under dispute).
    Open 3 days.
  - **#1402** (2026-09-15) — the triage report itself, which produced the #1372/#1373-ready,
    #1380/#1395-held split above. Open 2 days.
  - **#1407** (2026-09-16) — the T-57 fix + this same DEBT-014 escalation, one report earlier. Open 1 day.
- **The pattern is no longer confined to `docs(governance)` PRs.** Three *functionally identical* fix PRs
  — #1383 (2026-09-13), #1403 (2026-09-15), and #1409 (2026-09-16), all titled `fix(config): validate
  -ip-filter-mode on the CLI path, not just config.yaml` — are open simultaneously against the same
  defect. This is outside this program's terminology mandate (it is a CLI-validation bug fix, not a
  naming concern) and is **not** added to the numbered T-backlog, but it is recorded here as
  corroborating evidence for DEBT-014's core mechanism: parallel scheduled runs that do not check the
  open-PR list before starting independently re-derive and re-submit the same fix. The mechanism DEBT-014
  named for documentation PRs is generalizing to code PRs.

**This pass takes DEBT-014's own prescribed lesson rather than adding to the pile it describes**: rather
than open an eighth `docs(governance)` PR proposing work that duplicates #1407's already-written T-57 fix,
this report itself is the minimal artifact — a verification pass plus a debt-register update — and its
PR description repeats the standing recommendation plainly, since apparently it has not yet reached the
person who can act on it: **merge #1372 and #1373 now** (independent of each other, of #1407, and of this
PR); leave #1380/#1395 open pending their own threads' content disputes; merge #1407 for the T-57 fix
once #1372/#1373 are through. No further automated pass can substitute for that merge action — the
fixes already exist, correctly, and re-describing them a ninth time is itself the debt.

The full dated status line is appended to `docs/engineering/TECHNICAL-DEBT-REGISTER.md`'s DEBT-014 entry
below the existing 2026-09-05 evidence, per the established convention of appending rather than rewriting.

---

## Carried-Over Findings (unchanged)

T-9, T-11, T-12, T-13, T-17, T-18, T-21+T-32 (paired), T-25, T-29, T-30, T-33, T-34, T-39 — full
descriptions and the priority-ordered refactoring plan are unchanged from
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` (the most recent report to restate them in full) and are
not repeated here, to avoid the same two-descriptions-of-one-item drift risk this program watches for in
the product it reviews. T-13, T-29, and T-30 were independently re-verified above rather than assumed.

The "Content & Scanning" vs. "Content Security" soft finding (a design-document reconciliation between
two deliberate naming decisions, not a mechanical rename) also remains unresolved and un-queued, per
2026-09-09's reasoning.

---

## Stop-Condition Assessment

No production-worthy NEW terminology improvement was identified this pass, because no new commits
reached `main` for this pass to audit — verified directly (`origin/main` HEAD unchanged at `993b390`
across two checks) rather than assumed. The fourteen-ID carry-over backlog is unchanged and three of its
members were independently re-confirmed rather than carried on trust. The one real, already-diagnosed
fix in flight (T-57) is not re-implemented here because a correct, verified fix for it already exists in
open PR #1407 — writing a second copy would be pure waste under this program's own DEBT-014 finding, not
diligence. Per the stop-condition instruction, this pass reports:

**No production-worthy terminology improvements were identified that are not already captured in an
existing, correct, open pull request.** The action this pass calls for is merge triage by the repository
owner (see the DEBT-014 section above), not further automated writing.
