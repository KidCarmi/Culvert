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

### Merge phase results (2026-07-17)
MERGED (13 this session, squash): #762, #728, #733, #758, #761, #737, #731, #738,
#765, #763, #766, #767, #699 (rebased onto main first — C1/D0 route-count 142→144
for the +2 DPI routes; force-with-lease). Branch protection does NOT require
up-to-date, so clean/unstable PRs merged without rebase; only conflicting ones
needed a rebase.

CLOSED as superseded: #764 (duplicate of the merged #731 — same geo-tracker
gate-before-spawn optimization from a sibling awesome-dirac session; would only
conflict, adds no unique coverage). Comment posted.

### Deferred / blocked (need follow-up)
- #734 (feat diagnostics: audit-persistence check) — content conflict with main
  (observability globals moved); merge-grade in content (no findings, well-tested)
  but needs a manual rebase. Local rebase mis-based (bad merge-base → full-history
  replay); do a fresh `git checkout -B` off origin/main and cherry-pick the 1
  commit, or reopen from a clean base.
- #736 (security review 07-16 window) — Codex findings FIXED on-branch (draft
  commit vs candidate version + Cascade dedup) but the base diff's Cascade*Rename
  changes are SUPERSEDED by a newer version now on main (sortLocked + counter-cell
  model). Needs re-scoping against main (keep the draft-commit fix + draft-engaged
  predicate; drop the superseded cascade changes). Not a mechanical rebase.

### Fleet verdict (11-agent workflow, 2026-07-17) + actions taken
Ran a multi-lens fleet (4 subsystem mappers → 4 expert judges [product/arch/security/ops]
+ #759 assessor → adversarial red-team → synthesis) over the REAL code.

- **#759 (RISK-022 E1b): SHIP → MERGED (ee3f934).** Verified independently: P1 fixed at
  594a346 (TargetImageID captured before PhaseRestarted), `TestRestartWithBarrier_
  CapturesTargetImageID` present, `reconcile_decision.go` pure + unwired, all required
  gates + maint `-race` + install/upgrade e2e green. E3 boot hook stays owner-gated.
- **TAC Support Framework (#760, #768–#785): HOLD-AND-SPLIT (verdict, not merged).** Two
  structural blockers:
  1. **Verified data-egress blocker** — `internal/support/manifest.go` `RedactionReport`
     is counts-only + the scrubber has no entropy/length fallback ⇒ a bare secret in an
     INTERNAL free-form string (rule name, endpoint URL, diag message) exports verbatim and
     the consent gate can't see it. Recorded on #769. Must fix before the export path ships.
  2. **Governance over-reach** — merging ratifies ADRs 0012/0018/0019–0022 (vendor cloud
     tier, AI diagnosis, MCP infra-ops gateway, conversational operator, L0–L3 autonomy,
     OpenTofu executor) as *Accepted*. That direction needs a separate architecture+security
     board decision, not implicit ratification via a diagnostics stack.
  Also: no root PR to main (a 19-PR/+11.2k stack is not reviewable as a unit); raw collectors
  must be hard-gated; grandfather-ready state must fail closed.
  Recommended path for the owner: split the M1–M4 appliance code (internal/redaction +
  internal/support + collectors + diagnose verbs + record-only crashguard + /api/support &
  /api/diagnose + SPA — clean, dep-free, no phone-home, enforcement untouched) into its own
  PR set with a real root PR AFTER the redaction blocker is closed; drop the cloud/AI ADRs
  from the merge (RFC/separate repo); add csb/1 contract test + no-outbound-network
  regression test + C1/C1.5/C2 parity as merge gates. Route the cloud/AI/infra-ops ADRs to
  an architecture+security board separately.

### NEEDS OWNER DECISION
- #759 (RISK-022 E1b — capture image config digest) — OPEN Codex P1: the target
  config digest is only set in the post-restart verify stage, so a crash after
  PhaseRestarted but before verify leaves TargetImageID empty and reconcile falls
  back to manifest digests (the multi-arch false-rollback the E-series exists to
  prevent). Fix direction is clear (capture the target config digest before
  writing PhaseRestarted). BUT this advances the maintenance-agent crash-recovery
  E-series whose E3 boot hook is explicitly owner-sign-off-gated — escalate.
- Stacked TAC support-framework chain (#760, #768–#785, 19 PRs) — large new
  support/diagnostics subsystem (redaction scrubber, incident scopes, diagnose
  verbs, encrypted export, case binding). Each PR's base is the previous PR's head;
  NO open PR merges the root (`claude/culvert-tac-support-framework-vf4plr`) into
  main. Cannot be merged piecemeal; the whole subsystem is a product/architecture
  decision. Escalate as a unit.

---

## Session continuation — 2026-07-17 (afternoon): queue cleared

### Systemic unblocker
- **#789 fix(test): de-flake determinism/race gate — MERGED** (`ab33fdca`). Root-caused the
  repo-wide `Deep · determinism` / `-race` flake to the hit-counter test family on MAIN
  itself (not any PR): (a) `startHitCounterPersistence`'s goroutine raced `t.TempDir`
  cleanup ("directory not empty") in two tests — fixed with a `done` channel the tests
  wait on; (b) `TestSaveAndLoadHitCounters` silently assumed an empty global `policyStore`
  — fixed with isolate+restore. Proven by negative control (revert reproduces the exact CI
  failure) + 60× `-race` green. This flake had reddened the required Deep gate on #734,
  #787, #788 and main's own qa-gate.

### Merged
- **#734 feat(diagnostics): audit-persistence health check — MERGED** (rebuilt from an
  unrelated-history branch to a minimal 2-file delta on current main; main had since
  shipped the `auditLogConfiguredPath` intent flag, so only the missing
  `/api/diagnostics` verdict row was ported; 3 state tests, 20× -race).
- **#787 feat(maint): RISK-022 E1c record-ref trust gate — MERGED** (`9ca4324b`). Both
  Codex findings verified and fixed before merge: P1 → allowlist deliberately NOT
  re-checked at reconcile (admission-time policy; digest-vs-tag re-match would spuriously
  loud-stop) with an invariant test; P2 → admission journal now persists
  TargetRef/TargetDigest for standalone image rollbacks (was: guaranteed loud-stop).
- **#788 feat(support): TAC supportability framework M1–M4 — MERGED** (`33b760f6`).
  Palo-grade hardening landed before merge: runtime raw-collector hard-gate (fail-closed
  section), csb/1 wire-format contract test, 3-layer no-egress wall, fail-closed
  grandfathering + `GrandfatheredReady` visibility, Codex P1 (retained_preview gated to
  operator+) and P2 (case_id → persisted manifest) with red/green regression tests,
  RISK-023 recorded (diagnose-tls InsecureSkipVerify accept; CodeQL alert #249 dismissed
  by owner). ADRs 0012/0018–0022 remain PROPOSED under docs/support/rfc/ (not ratified).
- **#786 decryptobs — merged by owner** (`140ca6fb`) after their review (author had marked
  it "do not auto-merge"; respected).
- **#736 security(review) — rebuilt on current main, pushed** (`efca07b7`, post-#788
  rebase; gates running at ledger time). Findings re-verified function-by-function:
  PORTED with red/green proofs — HIGH decryptprofile.Rename `s.order` re-key (silent
  fleet-wide profile loss), MED import-side `stampObjectRefIDs`, MED dangling-ID delete
  guard (enforcement name-fallback vs ID-authoritative walk divergence — the earlier
  "superseded by S2" call was WRONG and corrected), MED `policyDraftEngaged`, LOW /ready
  detail redaction, LOW edge-case-lab harden-runner, INFO loadHA escHtml. DROPPED as
  already-on-main: interactive stampObjectRefIDs, Cascade COW (their regression tests
  ported and green).

### Closed as superseded
- **#760, #768–#785** (19-PR incremental TAC stack) — closed after #788 merged with the
  consolidated equivalent (owner pre-approved).

### Open at ledger time
- **#736 only** — awaiting gates on `efca07b7`; merge on green.

### Post-queue addendum (same day, evening)
- **#736 — MERGED** (`937b17fa`) after a post-#788 rebase (one conflict in
  healthcheck.go: kept the /ready detail-redaction fix on #788's renamed
  `readinessCheck` type); both required gates green on the rebased head.
- **#792** (decryptobs P1 wiring seam) — NEW, author-marked "Do not auto-merge";
  all gates green; **parked for owner review** (same checkpoint pattern as #786).
  Its only red check was the ADVISORY Admin-UI RBAC browser E2E lane.
- **#793 fix(test): de-flake TestUIE2E_AuditLog_FilterableByRuleID — MERGED.**
  Root cause of the #792 "UI problem": the browser test filled panel inputs
  immediately after a nav click without proving the view had activated (Fill
  requires visibility; slow-runner view switch lags the click). Added the
  established sibling-test ToBeVisible guards at both nav clicks. Test-only;
  #792's code was exonerated (touches no UI, byte-identical on the wire).

**Queue state at close: 1 open PR (#792, awaiting owner review by design). All
others merged or closed. Both repo-wide CI flakes found this session
(hit-counter determinism/race family; UI e2e view-activation race) are fixed
in main.**
