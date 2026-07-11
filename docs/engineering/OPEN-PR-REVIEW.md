# Open PR Backlog Review — 2026-07-11

**Reviewer:** PR consolidation lead (independent re-review of every open PR against latest `main` @ `76584f1`, merge of #640).
**Scope:** all 7 open PRs (#641–#647) plus the threat-feed domain-allowlist initiative (#614, #615, #623) that this review cycle was chartered to consolidate.
**Method:** one isolated review agent per PR (full description, commits, diff, CI check runs, review threads, merge-tree vs latest `main`, architecture docs, risk/debt registers), followed by lead cross-PR reconciliation and a combined-merge validation of every code PR together. No PR was merged or closed as part of this review.

---

## 1. Executive summary

- **10 PRs examined**: 7 open (#641–#647), 3 threat-feed lineage (#614 closed, #615 closed, #623 merged).
- **The chartered consolidation is already done.** PR #623 (`fix/threatfeed-domain-allowlist-consolidated`) merged to `main` on 2026-07-10 and was adversarially re-verified in this cycle: it fully supersedes #614 and #615 with the security boundary intact. **No new consolidated PR is created by this review** — creating one would duplicate merged work. #614/#615 stay closed; no reopening criterion is met.
- **4 open PRs are mergeable now** (#642, #643, #644, #645): CI green on both required gates, clean merge-tree against latest `main`, drift-checked, and validated *together* (combined four-PR merge builds, vets, and passes the full 50-package suite plus targeted `-race` suites).
- **3 open PRs need small updates first** (#641, #646, #647): one open-and-valid review thread (#641), post-window staleness in a security ledger (#646), and a single one-line lint finding that fails the required Fast PR Gate (#647).
- **0 PRs are obsolete.** Nothing among the open PRs duplicates `main` or another PR. The one apparent contradiction (#644's SOCKS5 rejection vs #647's SOCKS5 conversion) was resolved on the facts: both changes are compatible (see §4).
- **No PR needs splitting.** Every open PR has one clear purpose and bounded blast radius.

## 2. Counts by recommendation

| Recommendation | PRs |
|---|---|
| MERGE_AS_IS | #643, #642, #644, #645 |
| UPDATE_AND_KEEP | #647, #646, #641 |
| SUPERSEDED_BY_MAIN (stay closed) | #614, #615 |
| Already merged (verified) | #623 |
| REBUILD_FROM_MAIN / SPLIT / CLOSE_AS_OBSOLETE | none |
| NEEDS_HUMAN_PRODUCT_DECISION | none as a PR; one *follow-up* item (T-10 from #642, see §6.2) |

## 3. PR action table

| PR | Intent | Status | Risk | Overlap | Recommendation | Next action |
|---|---|---|---|---|---|---|
| #645 | Fix lost-update race in `SaveUIUsersFile` (admin users vanish on restart) | CI green, race independently reproduced on main | Low | store.go with #644 (disjoint, verified) | MERGE_AS_IS | Merge first (correctness, auth persistence) |
| #643 | Lockout visibility + audited GUI unlock | CI green, drift-checked (route pin 145→146 still correct) | Low | none (only PR adding a route) | MERGE_AS_IS | Edit stale PR description (GET is admin, not viewer), merge |
| #644 | Lock-free `topHosts.Record` (hot-path perf) | CI green, memory model + benchmarks verified | Low | store.go with #645 (disjoint); narrative-only with #647 | MERGE_AS_IS | Merge; optionally fix bench `Sprintf` nit (open Codex P2, non-blocking) |
| #642 | Terminology governance: T-8 rename, F-1 comment, T-10 doc | CI green, zero compat surface | Minimal | none | MERGE_AS_IS | Merge |
| #647 | Idle-bound all 5 tunnel relays (CHAOS-03 HIGH) + refresh-tick recover guard (CHAOS-22) | **Fast Gate RED — one `noctx` lint finding** | Medium (hot path, well-tested) | corroborates #646 (F4=CHAOS-23); compatible with #644 | UPDATE_AND_KEEP | Fix `proxy_tunnel_idle_test.go:32` lint; correct statusMu over-claim; register double-write-block residual; merge |
| #646 | Security regression ledger for the M0/M1 window | CI green, but F7 finding already fixed on main by #640 | Minimal (docs) | F4 duplicates #647's CHAOS-23 (cross-ref needed) | UPDATE_AND_KEEP | Add post-window addendum (F7 fixed by #640; F1/F8 line drift), cross-ref CHAOS-23, merge |
| #641 | Document M1-3 catalog alerting; close Phase-6 TODO | CI green, **open valid Codex thread** | Minimal (docs) | none | UPDATE_AND_KEEP | Narrow the Phase-6 TODO instead of deleting it (dispatch/digest alerting never shipped), merge |
| #623 | Consolidated threat-feed domain-allowlist enforcement | **MERGED 2026-07-10**, re-verified this cycle | — | supersedes #614/#615 | (done) | Record residual follow-ups (§5.4) |
| #614 | Apply threat-feed domain allowlist immediately | Closed unmerged | — | superseded by #623 | SUPERSEDED_BY_MAIN | Keep closed |
| #615 | Harden threat-feed domain allowlist | Closed unmerged | — | superseded by #623 | SUPERSEDED_BY_MAIN | Keep closed |

## 4. PR relationship map

```
#644 (store.go: topHosts)  ──┐ disjoint hunks, merge-tree clean ┌── #645 (store.go: SaveUIUsersFile)
                             └───────── store.go ───────────────┘
#644 ←— narrative contradiction only —→ #647 (socks5.go io.Copy→idleCopyCounted)
        RESOLVED: io.CopyBuffer delegates to WriterTo/ReaderFrom before touching the
        buffer (verified against go1.25.12 $GOROOT/src/io/io.go), so TCP↔TCP splice is
        preserved in #647 and #644's code-level premise stays true. #644's *description*
        overstates ("forcing a userspace buffer would be a regression" — CopyBuffer
        doesn't force one); #647's socks5.go comment slightly oversells pooled buffers
        (bypassed on the splice path). No code conflict; both merge cleanly.

#646 (security ledger F4) ══ same finding ══ #647 (CHAOS-23, registered-not-fixed)
        Both ledgers register "stale-catalog watchdog inert in fetch-disabled/permissive
        mode". Cross-reference required so the item isn't double-tracked.

#646 (F7: publisher glob asset selection) ←— already FIXED on main by #640 (OPS-F2).
#641 / #646 / #647 all document the release-platform M1 window — complementary, zero file overlap.
#643 — the only open PR touching routes/auth surface; route-count pin verified against main.
#642 — zero file overlap with everything (release_alerts.go comment ≠ #647's release_refresh.go).

Dependencies / sequencing constraints:
  • #646 should merge AFTER #647 (so its addendum can cite CHAOS-22 as fixed-on-main
    rather than in-flight) — soft ordering, not a conflict.
  • Everything else is order-independent (pairwise + triple + quadruple merges verified).

Threat-feed lineage: #614 ─┐
                           ├─ superseded by #623 (merged) — verified §5
                    #615 ─┘
```

## 5. Threat-feed domain-allowlist initiative (#614 + #615 → #623)

This review cycle was chartered to consolidate #614 and #615 into a single clean PR from latest `main`. That work **already happened and merged as #623** (branch `fix/threatfeed-domain-allowlist-consolidated`, merge commit `90a4cbb`, 2026-07-10; #614/#615 closed immediately after). This cycle therefore performed an independent adversarial verification of the merged result instead of duplicating it.

**Verdict: `main` fully supersedes both PRs (high confidence).** All 17 distinct behavioral intents from #614/#615 are present on main in equal-or-stronger form, verified file:line, with `go vet` / `go test -race ./internal/threatfeed/` / targeted main-package suites / `TestConfigSurfaces_*` all passing in an isolated worktree at `76584f1`.

### 5.1 Retained changes (both PRs → main)
Lookup-time allowlist masking in `CheckURL`'s domain fallback and `CheckDomain` (`internal/threatfeed/threatfeed.go:282-321`); operator-input normalization `normaliseDomain`/`canonicalHost` (`:529-557`) applied symmetrically to allowlist writes, lookups, `NormaliseURL`, `ImportFeedData` (domains **and** URL keys), and disk load (legacy keys re-keyed); allowlist-before-import snapshot ordering (`controlplane_snapshot.go:508-530`); persist-error propagation with 500 + distinct `threatfeed.allowlist.update_unpersisted` audit action (`ui_security.go:569-580`); feed ingest keeps allowlisted domains as intel (#615's version won over #614's ingest-skip).

### 5.2 Rejected changes (deliberate, with cause)
- **#614's `pruneAllowlistedDomainsLocked`** (in-place delete of allowlisted domains from the feed map) — rejected in favor of in-memory retention + mask-at-lookup + save/export filtering. This single design change fixed **both** old PRs' unresolved Codex P1s (#614: in-place delete races `saveToDisk`'s unlocked marshal; #615: pruning loses intel so allowlist removal fails to re-block until next sync) and made #614's `cloneEntries` deep-copy unnecessary.
- **#614's Go 1.26.5 toolchain + x/crypto v0.54 / x/net v0.57 bumps** — superseded by the minimal #624 pin (`go 1.25.12`, fixing the actual gate blocker GO-2026-5856).

### 5.3 Security invariants (re-verified in current main code, not PR text)
1. The allowlist is consulted in exactly two places — `CheckDomain` (`threatfeed.go:315`) and `CheckURL`'s domain **fallback** (`:284`). Nothing else keys a verdict on it.
2. Exact malicious-URL matches are checked **before** the domain fallback (`:277-281`) and can never be allowlist-masked — no URI glassbreak. Pinned by `TestThreatFeed_DomainAllowlistMasksDomainButKeepsThreatIntelAndURLBlock`.
3. No feed-write path to the allowlist: write sites are `Init` (baked defaults), `loadFromDisk` (0600 admin-written file), the admin API (RoleAdmin, mutating, audited), and the CP→DP snapshot. `Sync`/`fetchTextFeed`/`applySync`/`ImportFeedData` never touch it.
4. Exact-host semantics — allowlisting `example.com` does not suppress `www.example.com` (`TestThreatFeed_DomainAllowlistIsExactHost`).
5. Documented residual (operator doc, not a code gap): on a non-inspected CONNECT tunnel only the hostname is visible, so allowlisting a host trusts all opaque traffic to it.

### 5.4 Normalization test matrix
Uppercase, trailing dot, `host:port`, full URL, URL+path, IDN/punycode convergence (allowlist ↔ domains map ↔ URL host), and malformed-input rejection are all pinned by repo tests (`TestThreatFeed_DomainAllowlistNormalizesOperatorInputs`, `..._CheckDomain_CaseInsensitive`, `..._CheckDomain_TrailingDot`, `..._DomainAllowlistCanonicalizesIDNConsistently`, `..._ImportFeedDataRecanonicalizesURLKeys`, `..._LoadFromDiskRecanonicalizesLegacyKeys`, `..._NormaliseDomainRejectsHostlessPathInput`). **IPv4/IPv6 (incl. `[2001:db8::1]:443`) verified empirically this cycle (14/14 ad-hoc matrix cases pass via `hostutil.StripHostPort`/`NormalizeHost`) but have no repo test** — see residuals.

### 5.5 Resulting branch / replacement PR
Branch `fix/threatfeed-domain-allowlist-consolidated` → PR **#623**, merged. No new PR is created by this review; a duplicate would add noise without value.

### 5.6 Residual follow-ups worth tracking
1. Add an IPv6/IP-literal case to `TestThreatFeed_DomainAllowlistNormalizesOperatorInputs` (behavior verified correct, untested in-repo; #623's body claims IPv6 in its matrix but the merged test file has no such case).
2. Stale doc comment in `internal/threatfeed/savetodisk_race_test.go:19-20` (describes the old reference-not-deep-copy shape; `saveToDisk` now deep-copies via the filter loop).
3. Declared #623 follow-up still open: eliminate the hot-path duplicate IDNA pass (pass the RISK-013-normalized host through to `CheckDomain`). Perf-only.
4. `PUT {"domains": null}` wipes the allowlist to empty (pre-existing, admin-only; consider an input-shape guard).

## 6. Per-PR review reports

### 6.1 PR #647 — chaos: idle-bound all raw tunnel relays (CHAOS-03) + recover-guard catalog refresh tick (CHAOS-22)
```
PR: #647
Title: chaos: idle-bound all raw tunnel relays (CHAOS-03) + recover-guard catalog refresh tick (CHAOS-22)
Original intent: Close CHAOS-03 (HIGH, top open finding since 07-04): no relay armed any
  deadline after streaming began — a half-open peer pinned 2 goroutines + 2 FDs + a pooled
  128 KB buffer forever on all five relay paths. Also CHAOS-22: a panic in the catalog
  refresh tick silently killed refresh + the M1-3 freshness watchdog until restart.
Problem being solved: Resource-exhaustion fail-safety + background-worker panic containment.
Current relevance: Fully relevant — CHAOS-03 still open on main; no idleCopyCounted/
  refreshLoopTick on main. Recover guard is MORE valuable post-#640 (M1-4 code runs in the tick).
Overlap with other PRs: Narrative-only with #644 (resolved compatible, §4); corroborates
  #646 (F4 = CHAOS-23, both register-not-fix). No file conflicts.
Architecture alignment: Strong. Splice preserved (deadlines armed around io.CopyBuffer, no
  reader wrapper — stdlib dispatch verified); read-deadlines-only (TLS-safe); half-window
  activity-stamp logic proven (active tunnel can't be reaped; half-open can't escape);
  graceful CloseWrite path intact; byte accounting exact; CLAUDE.md updated consistently.
Security impact: Positive (DoS hardening). Two residuals found in review:
  (1) LOW-MED — double-write-block escape: if BOTH directions are blocked in deadline-less
      Write (both peers fill the TCP window and stop reading), no read pop ever fires and
      the tunnel still pins forever. Not in the PR's residual list.
  (2) LOW — the CHAOS-22 "lock releases are deferred" claim is imprecise: statusMu in
      recordRefreshOutcome (release_api.go:138/151) and evaluateCatalogFreshness
      (release_alerts.go:166-168) is Lock/Unlock without defer; a panic there would be
      recovered but strand statusMu (silent hang of the loop + /api/releases). The realistic
      panic surface (rm.refresh) is outside statusMu, so the guard is sound in practice.
Regression risk: Low-medium, well contained — behavior changes only for tunnels silent in
  both directions ≥1 h (previously leaked forever). Graceful EOF/splice/accounting pinned
  by tests over real TCP conns.
Test quality: Good — 4 relay tests + panic-injection loop test. Gaps: no double-write-block
  test (consistent with it being unhandled); panic test doesn't panic under statusMu.
CI state: Deep PR Gate GREEN; Fast PR Gate RED on exactly one golangci-lint finding:
  proxy_tunnel_idle_test.go:32 noctx (net.Listen → (&net.ListenConfig{}).Listen). All other
  jobs green (race+coverage, perf gate, CodeQL, determinism, Snyk 0 issues).
Main branch drift: merge-tree with 76584f1 clean (only CLAUDE.md touched by both #640 and
  this PR, different lines); merged tree builds and passes targeted -race suites including
  the full release-platform set.
Recommended disposition: UPDATE_AND_KEEP
Required actions: (1) fix the one-line noctx lint (only gate blocker); (2) correct the
  deferred-locks over-claim or defer the statusMu unlocks; (3) add the double-write-block
  residual to the review doc / register a CHAOS ID; (4) optional rebase (cosmetic).
Confidence: High
```

### 6.2 PR #645 — fix(auth): serialize SaveUIUsersFile
```
PR: #645
Title: fix(auth): serialize SaveUIUsersFile to stop concurrent saves losing users
Original intent: Fix a lost-update race: SaveUIUsersFile snapshots under a brief RLock then
  writes via AtomicWrite with nothing ordering concurrent renames — last rename wins
  regardless of snapshot recency.
Problem being solved: Concurrent admin-user mutations (user create, password change, TOTP
  counter persist) could silently drop a user from ui_users.json; the account works until
  restart, then vanishes. Documented residue of chaos-review F4 (07-05), which fixed the
  torn-write but left the ordering race.
Current relevance: High — race INDEPENDENTLY REPRODUCED on main's code this cycle (the PR's
  test run against main's store.go fails on trial 0: 30 users in memory, 28 on disk).
Overlap with other PRs: store.go with #644 — disjoint hunks, pairwise merge-tree clean.
Architecture alignment: Good — dedicated mutex for the write path, RWMutex kept for reads;
  lock order strictly saveUIUsersMu → c.mu.RLock; audited all call sites: none holds c.mu
  at call time (SetDefaultAuthOutcome unlocks first; all 7 ui_auth.go sites lock-free).
  Writer coverage complete: SaveUIUsersFile is the only AtomicWrite to uiUsersFile in the
  tree; restore.go only reads at runtime (restore commit is offline per D1.5).
Security impact: Positive only — prevents silent loss of admin accounts, TOTP replay
  counters (loss would REOPEN a replay window), consumed backup codes, default_auth_outcome.
Regression risk: Very low — purely additive serialization; saves queue at admin-API rates.
Test quality: Strong — fresh Config + t.TempDir per trial, deterministic, race-clean,
  proven bug-catching. Nit: 6.68s under -race; 40 trials could drop to ~10.
CI state: Both required gates green; zero review threads; AegisDiff bot infra error only.
Main branch drift: None (#640 touched release files only); merge-tree clean; scratch merge
  builds + race suite passes.
Recommended disposition: MERGE_AS_IS
Required actions: None blocking. Optional: reduce test trials.
Confidence: High
```

### 6.3 PR #644 — perf(stats): lock-free tracked-host counting
```
PR: #644
Title: perf(stats): lock-free tracked-host counting in topHosts.Record (3.1× under contention)
Original intent: Remove the global-mutex serialization in topHosts.Record (runs on every
  allowed request): RWMutex + map[string]*int64, RLock + atomic.AddInt64 fast path.
Problem being solved: Every in-flight request goroutine serialized behind one lock for the
  ~100%-common already-tracked-host increment.
Current relevance: Fully relevant — main still has the mutex version (store.go:1114-1118).
Overlap with other PRs: #645 (same file, disjoint — verified); #647 (narrative only, resolved
  compatible — #644's rejection of the SOCKS5 buffer conversion was perf-motivated and its
  code-level premise is true; its description overstates that CopyBuffer "forces" a
  userspace buffer, which it does not).
Architecture alignment: Strong — implements the CLAUDE.md convention, mirrors
  ruleMetrics.RecordHit, preserves the documented top-hosts bound/decay contract verbatim
  (CLAUDE.md needs no edit), keeps /api/stats/hosts shape, records a negative result
  (timeSeries conversion measured flat and reverted) per the Engineering Constitution.
Security impact: None negative — attacker-controllable-hostname memory bound preserved and
  still tested (TestTopHosts_MemoryBounded).
Regression risk: Low. Memory-model correctness verified at every counter access site
  repo-wide: atomic writers only under RLock/Lock; plain reads in decayLocked/Top only under
  the EXCLUSIVE lock (RWMutex happens-before); map never mutated under RLock; rejected
  newcomers at cap allocate nothing. Ad-hoc -race -count=3 stress (Record+Top+decay-at-cap)
  passed.
Test quality: Good — benchmarks re-run both trees this cycle (serial −29%, parallel −43% at
  short benchtime; direction confirmed), deterministic zero-alloc gate. One OPEN Codex P2
  (valid, non-blocking): fmt.Sprintf inside timed parallel bench loops adds harness noise.
  Gap: no permanent -race concurrent stress test (follow-up).
CI state: Both required gates green incl. perf-regression gate, determinism, CodeQL.
Main branch drift: None; merge-tree clean; triple merge 644+645+647 validated green.
Recommended disposition: MERGE_AS_IS
Required actions: None blocking. Optional: bench hygiene (precompute hostnames before
  ResetTimer); follow-up permanent -race stress test.
Confidence: High
```

### 6.4 PR #643 — Surface active login lockouts + GUI unlock
```
PR: #643
Title: Surface active login lockouts + GUI unlock (Product Experience)
Original intent: GUI visibility of active lockouts (tier-1 IP+user, tier-2 account-wide) +
  audited one-click unlock, wiring the previously caller-less LoginLimiter.ResetUser.
Problem being solved: Locked-out legitimate account meant "wait 15 min, read logs, or
  restart" — a genuine gap in a GUI-first product.
Current relevance: Fully relevant — none of it on main; Snapshot() absent from internal/lockout.
Overlap with other PRs: None — the only open PR adding a route or touching ui_auth/lockout.
Architecture alignment: Strong — registerAuthRoutes wiring, method-aware uiRoutes metadata
  exactly matching handler requireRole (C1/C1.5/C2 consistent); saveConfigVersion correctly
  NOT called (in-memory runtime state, not config); ADR-0002 respected; GUI-parity satisfied
  in the right direction.
Security impact: Net positive. The Codex P2 (GET was viewer → username/attacker-IP
  enumeration) was FIXED in-PR (5f32f3b: GET now admin-only, thread resolved, pinned by
  TestAPIAuthLockouts_List_RejectsViewer). XSS clean (escHtml on username/ip; confirmAction
  uses textContent); CSRF/rate-limit via existing middleware; fixed {"ok":true} response.
  NOTE: the PR DESCRIPTION still says "viewer role" for GET — stale text contradicting the
  code; edit before merge.
Regression risk: Low — additive only; Snapshot() takes the limiter's full mutex, read-only,
  omits expired, sorted.
Test quality: Good — both tiers, viewer-403, unlock round-trip, 400/405; TEST-NET IPs;
  no audit-ring-length assertions (pitfall avoided).
CI state: Fully green at head (both required gates + CodeQL, race+coverage, determinism).
Main branch drift: None that matters — main's route pins still 145 (#640 added no routes),
  so the PR's 145→146 bump is correct; scratch merge conflict-free; merged tree passes
  D0/C1/C1.5/C2/C2c/C4 + all 6 lockout API tests.
Recommended disposition: MERGE_AS_IS
Required actions: (1) optional — fix the stale PR-description role claim; (2) optional
  follow-ups: trim username at RecordFailure/login ingestion; periodic table refresh.
Confidence: High
```

### 6.5 PR #642 — docs(terminology): close T-8, fix F-1, document T-10
```
PR: #642
Title: docs(terminology): 2026-07-10 governance review — close T-8, fix F-1, document T-10
Original intent: Execute the feasible half of T-8 from the 07-07 terminology review
  (listAccessRules → listPolicyRules; validateAccessRule deliberately kept — collision with
  the real validatePolicyRule dispatcher, documented at the point of confusion), fix the
  "canary" comment collision in release_alerts.go, document T-10 (content_scan_* vs DPI).
Problem being solved: Naming drift between internal helpers and GUI/API vocabulary.
Current relevance: Still relevant — main hasn't renamed anything; the review doc is new.
Overlap with other PRs: Zero file overlap (release_alerts.go ≠ #647's release_refresh.go;
  #640 touched neither).
Architecture alignment: Good — GUI-first vocabulary, established governance-review format,
  same risk bar as the prior T-9 deferral.
Security impact: None — no exported identifiers, routes, JSON fields, config keys,
  audit-event strings, env vars, or CLI flags touched (verified against the full diff).
Regression risk: Near zero — renamed helper called from exactly 2 sites (both updated);
  no test references it; the C1.5 AST walker analyzes route handlers, not private helpers
  (suites pass on head AND scratch merge — 150 PASS / 0 FAIL).
Test quality: Appropriate for the class — existing D0/C1/C1.5 suites are the regression net.
  Cosmetic nit: the doc cites ui_helpers.go:105 for the dispatcher (actual ~:148/155).
CI state: Both required gates green; AegisDiff bot infra error only; zero review threads.
Main branch drift: None — git log 8e88a40..main over the touched files is empty; ort merge
  clean; merged tree builds/vets/tests green.
Recommended disposition: MERGE_AS_IS
Required actions: None blocking. The T-10 FOLLOW-UP (not this PR) is
  NEEDS_HUMAN_PRODUCT_DECISION before implementation: (1) renaming audit-event strings
  breaks SIEM matchers — product judgment; (2) JSON aliasing intersects the walled
  config-surface registry; (3) GUI-parity surfacing decisions.
Confidence: High
```

### 6.6 PR #646 — docs(security): regression review, M0/M1 window
```
PR: #646
Title: docs(security): regression review — release-platform M0/M1 window + core-fix batch
Original intent: Add the dated security-review ledger for main 328c883→8e88a40 (PRs
  #567–#639): 2 MEDIUM (F1 R2 egress wildcard, F2 Terraform lock), 6 LOW, 9 INFO, plus an
  extensive verified-safe analysis.
Problem being solved: Continues the docs/security-reviews/ ledger series (#619 precedent).
Current relevance: High — 7 of 8 findings remain unfixed on current main.
Overlap with other PRs: F4 == #647's CHAOS-23 (same finding, two ledgers — cross-reference
  needed, not a conflict). No file overlap with #641/#647.
Architecture alignment: Excellent — follows the ledger format and correctly identifies the
  in-binary verification + rollback floor as the real trust boundary.
Security impact: Publishes descriptions of unfixed MEDIUM/LOW weaknesses — acceptable per
  the repo's own precedent (3 prior ledgers on main), all findings derivable from public
  code, no secrets. Spot-checks F1–F5 all reproduced against main (F1 wildcard still at
  publish-catalog-r2.yml:107; F3 /ready leak precisely cited at healthcheck.go:106-107 +
  rootca_startup.go:31-38).
Regression risk: Zero runtime (one new markdown file).
Test quality: N/A; the review's own claims are credible — 5/5 spot-checks reproduced.
CI state: Both required gates green; AegisDiff bot errored (its LLM provider 404'd —
  infra, not a finding); no review threads.
Main branch drift: Merges cleanly, BUT #640 (merged after the review window) FIXED its F7
  (publisher glob asset selection → exact-name, publish-catalog-r2.yml:182-197); F1/F8 line
  citations drifted (findings still valid). Merging unamended would present F7 as open.
Recommended disposition: UPDATE_AND_KEEP
Required actions: (1) post-window addendum: F7 fixed on main by #640 (OPS-F2); mark F1/F8
  citations "at 8e88a40"; (2) cross-reference F4 ↔ CHAOS-23 (#647); (3) optional: note
  CHAOS-22 fix status. Prefer merging after #647 so the addendum can cite it as landed.
Confidence: High
```

### 6.7 PR #641 — docs(release): document M1-3 catalog alerting
```
PR: #641
Title: docs(release): document M1-3 catalog alerting/metrics; close stale Phase 6 TODO
Original intent: Add an operator-facing "Detection, metrics, and alerting (M1-3 — shipped)"
  section to docs/operator/enterprise-release-catalog-plan.md; delete the Phase-6 TODO the
  work partially satisfied.
Problem being solved: M1-3 shipped alerts + metrics with no operator-facing documentation.
Current relevance: Fully relevant — main still lacks the section; #640 did not touch the file.
Overlap with other PRs: None.
Architecture alignment: Good — matches CLAUDE.md's M1-3 note; all facts verified against
  main code (30-day threshold release_alerts.go:52; 3-fail latch :55/:89; metric names
  :182-198; expires_in_days release_api.go:361; webhook checkboxes static/index.html:11684-11686).
Security impact: None (docs-only).
Regression risk: Zero runtime. One documentation-accuracy regression: deleting the whole
  Phase-6 TODO overstates completeness.
Test quality: N/A (docs-only); fact-check corroborated.
CI state: Both required gates green. ONE OPEN, UNRESOLVED Codex thread (P2) — and it is
  VALID: the deleted TODO also covered dispatch-failure/digest-mismatch alerting, which
  M1-3 did NOT ship (release_dispatch_attention exists at release_dispatch_service.go:450
  but has no Prometheus metric and no webhook-modal checkbox).
Main branch drift: Merges cleanly onto 76584f1; the added text is already M1-4-aware.
  Minor missed enrichment: could link docs/operator/catalog-resign-runbook.md (added by #640).
Recommended disposition: UPDATE_AND_KEEP
Required actions: (1) reinstate a narrowed Phase-6 bullet ("dispatch-failure /
  digest-mismatch metrics + selectable alert event") instead of deleting the line;
  (2) optional: link the resign runbook in the stale-alert row. Then merge.
Confidence: High
```

## 7. Risk-ranked action list

1. **#647** — highest-value open fix (closes a registered HIGH resource-exhaustion finding on all five relay paths) and highest blast radius (tunnel hot path). Blocked only by a one-line lint fix. Fix, address the two review residuals (statusMu over-claim, double-write-block registration), merge.
2. **#645** — auth-persistence correctness; race reproduced on main. Merge now.
3. **#643** — product/security UX win; fully validated including governance suites on the merged tree. Merge now.
4. **#644** — hot-path perf, memory-model verified, perf gate green. Merge now.
5. **#642** — zero-risk governance hygiene. Merge now.
6. **#646** — needs the F7/staleness addendum to avoid recording a fixed issue as open; merge after #647.
7. **#641** — needs the Codex-flagged TODO narrowing to avoid erasing unshipped Phase-6 work; then merge.

## 8. Recommended merge sequence

```
1. #645  (auth correctness — smallest, highest urgency)
2. #643  (route-count pin lands; no other open PR touches routes)
3. #644  (store.go disjoint from #645 — verified)
4. #647  (after the noctx lint fix + residual notes; hot path last among code PRs
          so it rides atop a settled tree; rebase optional — merges clean)
5. #642  (docs + private rename)
6. #646  (after #647, with the post-window addendum)
7. #641  (after the Phase-6 TODO narrowing)
```
All four code PRs (1–4) were validated **together**: quadruple merge onto `76584f1` → `go build ./...` OK, `go vet ./...` OK, combined targeted `-race` suite (governance layers, lockout API, topHosts/stats, SaveUIUsers race test, tunnel-idle, SOCKS5, catalog refresh loop) `ok 13.8s`, and the full suite `go test ./...` → **50 packages ok, 0 failures**.

## 9. Final maintainer recommendation

```
MERGE NOW
  #645  fix(auth): serialize SaveUIUsersFile
  #643  lockout visibility + GUI unlock        (edit stale PR description text first)
  #644  perf(stats): lock-free topHosts.Record
  #642  docs(terminology): T-8/F-1/T-10

FIX NEXT (small, named updates — then merge)
  #647  idle-bound tunnel relays + refresh recover-guard   (one-line noctx lint fix;
        correct statusMu claim; register double-write-block residual)
  #646  security regression ledger                          (post-window addendum: F7
        fixed by #640; F4 ↔ CHAOS-23 cross-ref; merge after #647)
  #641  M1-3 alerting docs                                  (narrow the Phase-6 TODO
        per the open Codex thread instead of deleting it)

REBUILD
  (none)

CONSOLIDATE
  (none — the chartered #614+#615 consolidation already merged as #623 and was
   re-verified this cycle; no new consolidated PR is warranted)

CLOSE
  (none open — #614 and #615 are already closed and must stay closed:
   SUPERSEDED_BY_MAIN, verified §5)

HUMAN DECISION REQUIRED
  (no PR — one follow-up item: T-10 content_scan_*/DPI unification from #642 needs
   product sign-off on audit-event renaming (SIEM matchers), config-surface registry
   impact, and GUI-parity surfacing before anyone implements it)
```

---

*Validation evidence in this document comes from actual command runs in isolated worktrees (per-PR and combined), recorded verbatim in the per-agent review transcripts. No PR was merged, closed, or commented on during this review.*
