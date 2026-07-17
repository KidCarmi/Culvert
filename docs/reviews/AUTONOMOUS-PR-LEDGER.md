# Autonomous PR Operator — Ledger

Session start: 2026-07-17. Operator branch: `claude/culvert-pr-operator-xvo76u`.
Required merge gates: `✅ Fast PR Gate — APPROVED` + `✅ Deep PR Gate — APPROVED`.
Review bot: `chatgpt-codex-connector` (Codex) posts P1/P2/P3 inline findings.
**Workflow rule (learned):** ALWAYS pull `get_review_comments` (Codex threads) for
every PR and address every valid finding before merge. `get_comments` (issue
comments) alone is insufficient — it misses Codex review threads.

## Portfolio structure

- **Stacked "TAC support framework" chain** (#760, #768–#785, 19 PRs): each PR's
  base is the previous PR's head; root is `claude/culvert-tac-support-framework-vf4plr`.
  **No open PR merges the root into main.** This is a large new support/diagnostics
  subsystem (bundles, redaction, incident scopes, diagnose verbs, encrypted export).
  → **NEEDS OWNER DECISION as a unit** — do not merge piecemeal into non-main bases.
- **17 standalone PRs targeting `main`** — processable independently (table below).

## Standalone PR status (targeting main)

| PR | Title | Codex findings | Disposition |
|----|-------|----------------|-------------|
| #762 | docs: legacy-updater superseded banner | P2 Phase-5 overclaim | **MERGED** 7ec9921; follow-up banner fix on operator branch (5432150) |
| #763 | fix(install): scope compose_command_flags to proxy | P2 anchored-header regression → **fixed 65e2b2c + test**, resolved/outdated | Verify + merge |
| #764 | perf: gate destination-country tracker before goroutine | none | Review diff + merge |
| #765 | fix(auth): IdP login admin label + terminology cleanup | none | Review diff + merge |
| #766 | docs(security): regression review window | none | Review diff + merge |
| #767 | chaos: /ready DP dependency health (CHAOS-09) | none | Review diff + merge |
| #734 | feat(diagnostics): surface audit-log persistence fallback | none | Review diff + merge |
| #758 | feat(decryptobs): ADR-0011 bounded-enum vocabulary | P2 enum-mutation → **fixed b230361 + parity test**, thread open | Verify + resolve + merge |
| #738 | fix: harden policy decisions + OIDC identity | 3 resolved; **OPEN P2** metrics.go:96 preserve loaded counters before restore | Verify remaining finding; fix if needed |
| #761 | feat(ui): syslog/SIEM drop count in GUI | **OPEN P2** reset stale s-syslog-drops on save/disable | Fix (static/index.html) |
| #737 | chaos: expired-node re-enrollment recovery (CHAOS-12) | **OPEN P2** preserve draining state on re-enroll | Fix (controlplane_server.go) |
| #736 | security(review): 07-16 window | **OPEN P2** policy_draft.go:404 candidate-version conflict + 2 dupl lint | Fix |
| #733 | docs(ha): standby sync-health fields | **OPEN P2** ha-lease-failover.md:119 3/3-promote wording | Doc fix |
| #731 | perf: skip geo-tracker goroutine when GeoIP disabled | **OPEN P2** drain bench goroutines before return | Test fix |
| #728 | docs(governance): reconcile stale updater refs | **OPEN P2 x2** restore dispatch route + keep direct-agent risk | Doc fix |
| #699 | fix(terminology): unify DPI naming (T-10) | **OPEN P2** empty canonical DPI patterns (nil vs len) + gocognit lint | Fix (config.go) |
| #759 | feat(maint): RISK-022 E1b capture image config digest | **OPEN P1** capture digest before PhaseRestarted (crash window) | Fix (journal_phases.go); part of gui-redesign branch |

## Processing log

- 2026-07-17: Inventoried 39 open PRs. Merged #762 (docs, verified). Caught a
  premature merge (missed Codex P2) → pushed banner correction to operator branch.
  Collected Codex review threads for all 17 standalone PRs (map above).

### Codex findings — all standalone PRs addressed (fixed + replied + resolved)
- #762 MERGED (7ec9921); follow-up banner correction on operator branch (5432150).
- #733 — lease-mode 3/3 promotion wording → a6747b9.
- #728 — live release-dispatch routes in Critical table + RISK-010 direct-agent
  residual → 9bb5953 (both threads).
- #758 — verified author's pre-landed Valid() compile-time-switch fix; resolved.
- #738 — metrics.go:96 startup-window counter clobber → 58527ff (reorder
  load→restore→start-saver; +3 regression tests). All 4 threads resolved.
- #761 — reset s-syslog-drops on reconfigure/disable → 332c13a.
- #736 — draft commit vs candidate version + dedup Cascade*Rename (2 dupl) →
  ef82c23 (+regression test). All 3 threads resolved.
- #737 — [agent] preserve draining status on expired-node re-enroll → 9160182
  (+regression test). Diff reviewed.
- #731 — [agent] drain geo-tracker goroutines in PreGate benches → e436961. Diff
  reviewed.
- #699 — [agent] nil-vs-len DPI-pattern precedence + validate() decomposition →
  9f9f46b (+regression test). Both threads resolved. Diff reviewed.
- Clean (no findings, review + merge): #734, #764, #765, #766, #767, #763.

### Remaining
- #759 — OPEN P1 (capture image config digest before PhaseRestarted). Part of the
  `claude/culvert-gui-redesign-1qo2n8` branch (RISK-022 E-series).
- Stacked TAC support-framework chain (#760, #768–#785): NEEDS OWNER DECISION —
  large new subsystem, no root→main PR. Do not merge piecemeal.
- MERGE PHASE: verify CI green + branch up-to-date, merge in dependency-safe order.
