# Culvert Language & Terminology Governance Review — 2026-09-15

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Fetched `origin/main` fresh immediately before writing this report. `main` is still at
> `993b390` — unchanged since the 2026-09-13 window (the tip PR #1395, dated 2026-09-14, already
> audited), so there is **no new commit window** on `main` for a content re-audit to cover. Rather than
> file a fourth/fifth content report re-describing a window three still-open PRs already cover
> (`#1372` 2026-09-12, `#1380` 2026-09-13, `#1395` 2026-09-14 — see below), this pass instead did what
> the 2026-09-05 report's own recommendation asked for and no pass since has done: **queried the live
> PR list and individually triaged every open governance PR by reading its actual review threads**,
> not just its CI/mergeable-state summary, before writing anything new.

---

## Executive Summary

**No new terminology drift on `main`.** An independent re-verification of representative claims from
the still-open backlog (T-9 … T-39, `docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-11.md` —
the last report actually merged to `main`) found the thirteen-entry backlog unchanged and every cited
`file:line` still accurate. Terminology Health Score: **8.7 / 10** (unchanged — nothing merged, nothing
new to score).

**The real, actionable finding this pass is process, not content: DEBT-014 (documentation-governance PR
backlog) has recurred and is active again**, three and a half weeks after the 2026-09-05 report first
named it. Four `docs(governance)` PRs are open against `main`, spanning 2026-09-12 through 2026-09-14,
and **none has merged** despite `main` sitting still since before the oldest of them opened:

| PR | Date | Subject | `mergeable_state` | CI | Review threads |
|---|---|---|---|---|---|
| #1372 | 2026-09-12 | Terminology review — MCP canary vocabulary; T-54 (OCSP metric-name mismatches) | clean | green (`security/snyk`) | 6, **all resolved** |
| #1373 | 2026-09-12 | CDR operator guide + doc-governance review | clean | green | 9, **all resolved** |
| #1380 | 2026-09-13 | Terminology review — T-55 (Policy Learning wording), T-56 (PAC "steering profile") | clean | green | 2, **both unresolved** |
| #1395 | 2026-09-14 | Terminology review — T-21/T-32 risk-rating correction | clean | green | 3, **all unresolved** |

The naive triage — "all four are `mergeable_state: clean` with green CI, so all four are safe to merge"
— is **wrong**, and checking only that would have repeated the exact mistake this program has already
made once (the 2026-09-05 report listed PRs as ready by CI/conflict state alone). Reading the actual
review-thread content changes the picture:

### #1372 and #1373 are genuinely merge-ready

Both received substantive automated review (`chatgpt-codex-connector`) that caught real defects, and
both were fully addressed in-PR with verified follow-up commits — every thread on both is now marked
`is_resolved: true`:

- **#1372** — Codex caught that T-54's "OCSP names are just camelCase renamings" claim was wrong for
  three identifiers (`malformedResponseTotal`/`MalformedTotal()`/`malformed`,
  `unknownStatusTotal`/`UnknownTotal()`, and `staleResponseTotal`/`StaleTotal()`/`stale` each insert or
  drop a word the other surface doesn't have), that the report's audited window omitted several
  user-facing changes (`loginOversizeRejected`, `trust_forwarded_headers`, a `docker-compose.yml`
  `/app/yara`→`/data/yara` path fix, a new MCP Canary-readiness-matrix doc row), and that
  `responder_blocked` is a pre-request refusal miscategorized under a "response was discarded" metric
  family. Each was independently re-verified against source by the PR author and fixed across three
  follow-up commits (`6c41ea0`, `69f6244`, `fe89959`); the health score in that report was correctly
  adjusted 8.7→8.6 to reflect T-54's genuine growth from three mismatches to a documented family-scope
  issue.
- **#1373** — Codex caught five real CDR (Content Disarm & Reconstruction) reliability/security defects
  while reviewing the new operator guide, none of which this pass re-derives (they are implementation
  bugs, not terminology, and out of scope for a documentation PR to fix) but which are worth naming
  because they were correctly *not* silently written around: CDR only ever inspects the buffered
  scan-window prefix and forwards an untouched tail on large files; CDR performs no inspection at all
  when enabled without another body-scanning stage also active (`bodyNeedsBuffering` never checks CDR's
  own enabled state); an unavailable pool bypasses `fail_mode` entirely regardless of fail-open/closed
  configuration; a single-instance CDR pool's half-open circuit-breaker probe is silently discarded by a
  double-selection bug, so it never reports a probe outcome and the breaker can never leave half-open
  after one trip; and disabling then re-enabling CDR at runtime silently drops a configured
  `fail_mode: closed` back to fail-open. All five are documented as "Known limitations" in the new guide
  (commits `518a854`, `14cc54f`, `9ac10cc`) rather than fixed, which is the correct scope discipline for
  a docs-only PR — but they are real, and worth a dedicated CDR reliability follow-up outside this
  program's remit.

### #1380 and #1395 are not ready, and should not be merged as-is

- **#1380** has two open threads: Codex correctly points out that the claimed T-56 doc fix
  ("steering profile" for PAC) is incomplete — the same runbook still says bare `ACTIVE profile`,
  `Each profile carries`, `default profile`, and more, a few lines below the one paragraph that was
  edited — and that the report's premise ("this pass extends the program's audit scope to
  `frontend/src/**`... which prior passes checked only via `static/index.html`") is factually
  contradicted by the 2026-08-22 and 2026-08-29 reports, which already audited `frontend/src/` directly
  and fixed a violation there. Neither thread has a reply or a follow-up commit.
- **#1395** has three open threads, all disputing the accuracy of the risk-rating corrections the PR
  itself makes: that leaving T-21 (`cp_version`) at anything but a corrected-upward compatibility risk
  ignores that the field is part of a `stable`-tagged OpenAPI operation under a documented
  breaking-change policy; that the T-32 migration-failure mechanism described (a silent empty-field
  decode leading to `errActCRC`) is not how the actual code behaves (`DisallowUnknownFields` rejects the
  old key first); and that the cited `OnInspectError` precedent for a dual-key migration doesn't apply
  (the old-binary-ignores-the-field behavior it's compared to was superseded and no longer holds). These
  are not nitpicks — they mean the PR's own corrected risk ratings are, per the reviewer, still wrong.

**Recommended action for the repository owner:** merge #1372, then #1373 (independent, touch disjoint
files, no open threads on either) now. Leave #1380 and #1395 open until a follow-up commit on each
addresses its open Codex threads — merging either today would land governance content that a reviewer
has already shown to be inaccurate onto `main`, which is a worse outcome than the current unmerged
state.

This report's own content was deliberately kept to the PR-backlog triage above, rather than adding a
duplicate content-only pass — see the note under Method.

---

## Carried-Over Findings (on `main`, unchanged)

The thirteen-entry backlog from `docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-11.md` (T-9,
T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34,
T-39) remains open, unchanged, and re-confirmed against the current tree. **Three additional entries
exist only inside still-open, unmerged PRs and are therefore not yet part of `main`'s backlog**: T-54
(OCSP metric-name mismatches, #1372), T-55 (Policy Learning "Accept to Draft" vs. "Accept to Policy
Draft" wording split between the legacy and new frontends, #1380), T-56 (PAC "steering profile" missing
from the new frontend and incompletely fixed in the operator runbook per the open thread above, #1380).
Once #1372 and #1380 (after its follow-up fix) merge, these should be folded into the canonical backlog
list in the next report that observes them on `main`.

---

## Stop-Condition Assessment

No new terminology-content finding was identified this pass beyond what three already-open PRs already
cover, and this report deliberately did not re-derive or duplicate that content. The pass's actual
deliverable is the PR-backlog triage above: a concrete, individually-verified merge/hold recommendation
for each of the four open governance PRs, plus the corresponding `docs/engineering/TECHNICAL-DEBT-REGISTER.md`
(DEBT-014) update recording that the pathology has recurred. Per that entry's own 2026-09-05 conclusion,
this is a merge/triage action item for the repository owner — not something a further automated
documentation pass can resolve by writing more reports.
