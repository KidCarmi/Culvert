# Open-PR Backlog Review — 2026-07-10

Independent re-review of every open pull request against `main` @ `328c883`,
performed as a PR-consolidation pass (one isolated review per PR + a lead
cross-PR reconciliation). Method per PR: full description, commit history,
three-dot diff vs `origin/main`, CI check runs (including failure-log root
cause), review threads, `git merge-tree` conflict checks, overlap analysis
against every other open PR, and verification that the problem still exists
on current `main` (many claims were re-verified directly in source).

## Executive summary

- **21 open PRs reviewed** (19 general + the #614/#615 threat-feed pair).
- **Nothing was superseded by `main`** — every PR still targets a live
  problem; the backlog's real diseases are (a) *duplicate agent iterations*
  (three pairs/trios re-implement the same fix and hard-conflict with each
  other) and (b) a **repo-wide CI blocker**: `Gate · govulncheck + gosec`
  fails on every PR since 2026-07-09 because of **GO-2026-5856** (crypto/tls
  in go1.25.11, fixed in go1.25.12). Six PRs are red *solely* because of it.
- **9 PRs are merge-ready as-is**, 5 need small fixes, 2 must be rebuilt from
  `main` (both are real, still-live security/correctness bugs whose branches
  predate large refactors), 5 are closed-as-superseded once their surviving
  twin merges, 1 is an outright duplicate to close.
- **#614/#615 consolidated**: replacement draft **PR #623**
  (`fix/threatfeed-domain-allowlist-consolidated`) supersedes both. See the
  consolidation report below.
- **Single most valuable next commit on `main`**: a one-line `go.mod` bump
  `1.25.11 → 1.25.12` (chore PR, repo's established pattern). It unblocks the
  required Fast PR Gate on #616, #617, #618, #620, #621, #622 and #623.
  (#614 bundled a much more aggressive `go 1.26.5` bump into a feature PR —
  rejected as scope creep.)

## Recommended dispositions at a glance

| Bucket | PRs |
|---|---|
| Merge as-is | #619, #607, #612, #581, #603, #617, #618, #620, #621 |
| Small fix, then merge | #567, #609, #606, #622, **#623** (new, draft) |
| Rebuild from main | #515, #503 |
| Consolidated / superseded (close after survivor merges) | #583, #605 → #612 · #610 → #622 (salvage its doc) · #614, #615 → #623 |
| Close as duplicate | #616 (duplicate of #603) |

## PR relationship / dependency map

```
policy.go perf trio (pairwise hard-conflict — only ONE can merge):
  #583 (matchedConds)  ─┐
  #605 (CIDR precompute)├─▶ superseded by #612 (strict superset: matchedConds
  #612 (superset + tz)  ┘   + CIDR + tz cache). Port #583's benchgate test and
                            #605's IPv6/lazy-parse niceties as a follow-up.

Releases-panel duplicate (hard-conflict pair — pick ONE):
  #603 (badge + warning, textContent, CI green)  ◀─ keep
  #616 (banner-only, innerHTML+escHtml)          ◀─ close as duplicate

chaos family:
  #610 (CHAOS-02/04 + 2026-07-07 review doc) ─▶ code superseded by #622
       (identical fixes re-implemented); #610's doc (findings CHAOS-22..43)
       exists NOWHERE else — salvage before closing.
  #622 (CHAOS-01/02/04/06 + 2026-07-09 doc) — survivor; fix own lint first.
  #503 (connlimit Release leak) — orthogonal but interacts: #622's new SOCKS5
       Acquire/Release inherits the #503 bug; rebuild #503 against
       internal/connlimit (bug now lives at internal/connlimit/connlimit.go:97).

internal/ocsp textual adjacency:
  #581 (fail-closed counters) and #622 (indeterminate short-TTL) edit the same
  lines of internal/ocsp/ocsp.go. Merge #581 FIRST (clean vs main today),
  then trivially rebase #622.

threat-feed pair (one consolidated engineering initiative):
  #614 (prune model + save-race fix + toolchain bump)  ─┐
  #615 (retention model, iteration on #614's review)   ─┴─▶ superseded by #623

docs cluster (complementary, no conflicts):
  #567 + #617 → adjacent hunks in docs/OPERATIONS.md (auto-merge; same
  "docs name a nonexistent flag" defect class). #609 → CLAUDE.md/README (same
  -ca-bundle→-ca-path root cause as #567, different files). #607 (terminology
  docs) + #618 (terminology code) — same governance series, disjoint scopes;
  #618 supersedes #607's report conclusion T-1 (route rename), one-line
  addendum recommended.

static/index.html multi-PR surface (disjoint hunks, auto-merge):
  #581 (~2975/10062) · #603 (~3670/9784) · #606 (~10165) · #607 (~1143-3131).
  Last-merged may need a trivial branch update; no manual conflicts expected.

environmental blocker (not a PR): GO-2026-5856 fails Fast PR Gate on
  #616 #617 #618 #620 #621 #622 #623 → fix with a go.mod 1.25.12 chore PR.
```

## Risk-ranked action list

1. **Land the `go 1.25.12` chore PR on main** (unblocks 7 PRs' required gate).
2. **Rebuild #515** (auth kill-switch weakens enforcement in no-backend
   Exempt deployments — a live, spec-violating security bug at
   `proxy.go:154`; branch is uncompilable post-Slice-5, rebuild is cheap).
3. **Rebuild #503** (per-IP conn-counter leak → permanent phantom blocks;
   bug live at `internal/connlimit/connlimit.go:97`; land before/with #622,
   which widens exposure to it via SOCKS5).
4. **Merge #612**, close #583/#605 (hot-path perf with hard alloc gates;
   green CI, clean merge).
5. **Merge #581, then #622** (after #622's 4 test-file lint fixes) — closes
   two HIGH chaos findings (SOCKS5 DoS bypass, OCSP outage amplification)
   plus CP config-version persistence; salvage #610's review doc, close #610.
6. **Validate + promote #623** (threat-feed allowlist consolidation), close
   #614/#615.
7. Merge the docs/UI tail: #619, #607, #617, #609 (after its own quickstart
   value fix), #567 (drop README hunk, add `-ha-token`), #618, #620, #621,
   #606 (after tick()-staleness nit), #603 (close #616).

## Recommended merge sequence

```
0. chore: go.mod 1.25.11 → 1.25.12   (new one-line PR; re-run red gates)
1. #619  security-review doc          (docs-only, green)
2. #607  terminology docs             (docs-only, green)
3. #617  cluster-flag docs            (green after step 0)
4. #609  CLAUDE.md docs               (after fixing its own -port :8080 bug)
5. #567  HA docs                      (after dropping README hunk + -ha-token)
6. #612  policy perf survivor         → close #583, #605
7. #581  OCSP UI counters             (merge BEFORE #622)
8. #622  chaos fixes                  (after lint fixes; rebase over #581)
         → salvage #610's 2026-07-07 review doc, then close #610
9. #620  reqlog ring buffer
10. #621 installer allow_peers fix
11. #618 terminology rename           (+ release-note the audit-action rename)
12. #606 upstream CB diagnostics      (after tick() refresh nit / flake re-run)
13. #603 releases trust badge         → close #616 as duplicate
14. #623 threat-feed consolidation    → close #614, #615
15. fresh PRs: rebuilt #515, rebuilt #503 → close originals
```

## PR action table

| PR | Intent | Status | Risk | Overlap | Recommendation | Next action |
|---|---|---|---|---|---|---|
| #503 | connlimit Release must decrement when disabled | Bug live on main; branch conflicts (pre-ADR-0002 layout); test uncompilable | Low (fix) / High (as-is) | #610/#622 (SOCKS5 uses same limiter) | REBUILD_FROM_MAIN | Re-apply 3-line fix in `internal/connlimit` + port test; close #503 |
| #515 | Kill switch must not disable CR rules (no-backend Exempt) | Bug live at `proxy.go:154`; branch predates Slice 5 + DEBT-002/003; hard-conflicts | High-value security fix; low regression once rebuilt | none | REBUILD_FROM_MAIN | Re-implement in `resolveRequestAuth`; rewrite tests on `SetDefaultAuthOutcome`; close #515 |
| #567 | HA docs: wrong flag, misleading failover claim | 2 of 3 hunks valid; README hunk superseded + conflicts | None (docs) | #617 (adjacent OPERATIONS.md), #609 (same root cause) | UPDATE_AND_KEEP | Drop README hunk; add `-ha-token` per Codex P2; merge |
| #581 | Surface OCSP fail-closed blocks in UI | Green CI, clean merge, feature absent on main | Low | #610/#622 (same ocsp.go lines) | MERGE_AS_IS | Merge before #622; optional Codex-P2 episode-labeling follow-up |
| #583 | Precompute MatchedConditions (policy perf) | Correct but strict subset of #612 | Low | #605, #612 (pairwise conflict) | CONSOLIDATE_WITH_OTHER_PR | Port its benchgate test into #612's tree; close after #612 merges |
| #603 | Releases panel: trust-mode badge | Green CI, clean merge, feature absent on main | Very low | **#616 duplicate** (hard-conflict) | MERGE_AS_IS | Merge; close #616; optional neutral style for `unknown` |
| #605 | Precompute source-CIDR (policy perf) | Correct but subsumed by #612 (which loses its lazy-parse + IPv6 tests) | Low | #583, #612 | CONSOLIDATE_WITH_OTHER_PR | Port IPv6/lazy-parse/10k-gate into #612's tree; close after #612 merges |
| #606 | Upstream circuit-breaker diagnostics in UI | Red only on pre-existing `TestSelfFence_EntersStandbyResync` race flake (untouched HA files) | Low | index.html siblings (disjoint) | UPDATE_AND_KEEP | Fix Codex-P2 tick() staleness; re-run gate; file the HA flake separately |
| #607 | Terminology governance docs + report | Green, zero drift, all fixes verified still-applicable | Very low | #618 (complementary; supersedes its T-1 conclusion) | MERGE_AS_IS | Merge; optional T-1 addendum once #618 lands |
| #609 | Fix stale CLAUDE.md map/quickstart/OTLP docs | All claims verified, but its own "fixed" quickstart is still broken (`-port :8080` vs flag.Int) | Very low | #567/#617 (same defect class, no file overlap) | UPDATE_AND_KEEP | Fix `-port 8080 -ui-port 9090` (Codex P2); merge |
| #610 | SOCKS5 conn-limit + OCSP short-TTL (chaos 07-07) | Code reimplemented near-verbatim in #622; its review doc (CHAOS-22..43) unique | Low | **#622 superset**, #503, #581 | CONSOLIDATE_WITH_OTHER_PR | Salvage doc into #622/doc-only commit; close #610 |
| #612 | Policy precompute superset + tz cache | Green CI, clean merge, strict superset of #583+#605 | Low (fail-closed pinned) | #583, #605 | MERGE_AS_IS | Merge; close #583/#605; port their extra tests as follow-up |
| #616 | Releases panel: verify_mode banner | Duplicate of #603; red required gate (env); weaker UX/DOM pattern | Very low | **#603** | CLOSE_AS_OBSOLETE | Close citing #603; optionally port its extra test marker |
| #617 | Fix nonexistent `--cluster-grpc-*` flags in docs/diagnostics | Verified correct + complete; red only on env govulncheck | Very low | #567 (adjacent hunks) | MERGE_AS_IS | Merge after toolchain chore |
| #618 | Rename default-auth-outcome route (+alias) & DPI-bypass audit action | Green except env govulncheck; invariants (C1/D0/spec alias) all updated | Low (SIEM filter rename — release-note it) | #607 | MERGE_AS_IS | Merge after toolchain chore; release-note the audit-action rename |
| #619 | Security regression review doc (window ea0f2ff→328c883) | Green; every code claim independently re-verified | ~Zero | none (F1 follow-up unclaimed) | MERGE_AS_IS | Merge; track F1 (merge-import silent skip) as follow-up |
| #620 | reqlog fixed circular buffer (−96% ns/op) | Wrap math hand-verified; zero-alloc gate committed; red only on env govulncheck | Low | none | MERGE_AS_IS | Merge after toolchain chore; optional post-wrap content assertion |
| #621 | Installer: empty `allow_peers` corruption | Bug reproduced from main's awk; fix + tests verified; red only on env govulncheck | Very low | none | MERGE_AS_IS | Merge after toolchain chore |
| #622 | Four chaos fixes (CHAOS-01/02/04/06) + 07-09 doc | Fixes verified correct; red on own 4 lint issues + env govulncheck | Medium-low | **supersedes #610 code**; #503 interaction; #581 adjacency | UPDATE_AND_KEEP | Fix lint (whyNoLint/noctx); merge after #581; salvage #610 doc |
| #614 | Threat-feed allowlist immediate effect (prune model) | Superseded by #623 | — | #615, #623 | CLOSE (superseded) | Close once #623 validated |
| #615 | Threat-feed allowlist hardening (retention model) | Superseded by #623 (which also fixes its red race/determinism gates) | — | #614, #623 | CLOSE (superseded) | Close once #623 validated |
| **#623** | **NEW** consolidated threat-feed allowlist enforcement | Draft; full local suite green incl. -race + shuffle; awaiting gates (govulncheck env-red expected) | Medium (hot path, contract-tested) | supersedes #614/#615 | UPDATE_AND_KEEP (promote from draft after CI) | Watch CI; mark ready; then close #614/#615 |

---

## PR #614 / #615 consolidation report

**Initiative**: make the threat-feed Domain Allowlist an *operational* control
(immediate effect on live/persisted/imported data, forgiving operator input)
without weakening exact-URL enforcement.

**Behavior from #614** (`agent/threatfeed-domain-allowlist-ops-plan`, 6 commits):
hot-path allowlist gating in `CheckURL`/`CheckDomain`; `normaliseDomain`
operator-input normalization; normalization at import/load; snapshot-apply
reordering (allowlist before `ImportFeedData`); **pruning** of allowlisted
domains out of `tf.domains` on every mutation path; a `saveToDisk` map-clone
race fix + rewrite of `savetodisk_race_test.go` (both *necessitated by the
prune*, which introduced the first per-key mutation of `tf.domains`); and an
unrelated Go `1.26.5` toolchain bump + CI-action edits.

**Behavior from #615** (`agent/threatfeed-palo-review-hardening`, 2 commits —
the later iteration, responding to Codex review of the prune model):
everything above *except* pruning, replaced by **retention + lookup-time
masking** (`fetchTextFeed` records allowlisted domains again; the allowlist
only masks verdicts); IDNA canonicalization (`canonicalHost`) applied
consistently including `NormaliseURL`; exact-host allowlist semantics
(no subdomain suppression) pinned by test; persistence-error propagation
(`Set/Add/RemoveDomainAllowlist` return `error`; the PUT handler returns 500
and skips the success audit); IDN/punycode convergence tests.

**Duplicated changes** (identical in both, taken once): hot-path gating,
`normaliseDomain`, import/load normalization, snapshot ordering,
`AddDomainAllowlist` nil-map guard.

**Contradiction resolved — prune vs retention**: retention wins.
Pruning (a) destroys threat intel in memory *and* on disk, (b) leaves a
**no-block window** after an allowlist entry is removed (the domain cannot
block again until the next feed sync/import — Codex P1 on #615's first
commit), and (c) broke the reassign-only invariant on `tf.domains` that makes
`saveToDisk`'s unlocked marshal safe (Codex P1 on #614) — which is what forced
#614's clone fix. Retention preserves the invariant, so the clone fix and the
race-test rewrite become unnecessary and were **rejected** along with the
prune, the prune-asserting tests, and the toolchain bump (separate chore).

**Fixed beyond both**: #615's new snapshot test asserted positive
`CheckDomain` verdicts on the process-wide feed without enabling it —
order-dependent, the root cause of #615's red `-race` and determinism gates.
#623 adds a `SetEnabledForTest` seam (mirroring `SetDBPathForTest`), the test
enables/restores the flag itself, and uses neutral `*.example` hosts.
Verified: the test passes isolated under `-count=2 -shuffle=on`.

**Security invariants (verified by tests in #623)**:
1. Exact malicious-URL matches are evaluated before the domain fallback and
   remain enforced when the host is allowlisted (no URI glassbreak).
2. Allowlist bypasses domain-level matches only, at lookup time.
3. Exact-host matching — no implicit subdomain wildcarding.
4. Removing an allowlist entry re-enables blocking immediately.
5. Unicode/punycode spellings of a domain converge (IDNA), so homograph
   spellings cannot dodge or over-trigger the allowlist.
6. Persist-failure is fail-safe: in-memory state applies, API reports 500,
   no success audit entry.

**Normalization matrix** (all → `www.google.com` unless noted): uppercase,
trailing dot, `host:443`, `https://…/`, `…/path`, whitespace; bracketed IPv6
`[2001:db8::1]:443` → `2001:db8::1`; `bücher.example` ↔
`xn--bcher-kva.example`; malformed IDNA input falls back to
lowercase/trim-dot (admin-entered store keys — fail-open acceptable per
`hostutil` contract; request-path strict gates unchanged).

**Cross-plane behavior**: DP `applyConfigSnapshot` applies
`ThreatDomainAllowlist` before `ImportFeedData`; import normalizes domain
keys; persisted `feedDB` shape unchanged; legacy allowlist entries
re-normalize at load. Known bounded staleness: pre-existing persisted URL
keys for IDN hosts under the old lowercase-Unicode form won't match until the
next feed sync rewrites them.

**Test evidence** (local, branch `fix/threatfeed-domain-allowlist-consolidated`):
`gofmt` clean · `go vet ./...` clean · `go build ./...` ok ·
`go test ./...` **50 packages ok, 0 FAIL** ·
`go test -race ./internal/threatfeed/` ok ·
`go test -race -run 'TestApplyConfigSnapshot|TestDomainAllowlist|TestBucket4' .` ok ·
isolated `-count=2 -shuffle=on` on the previously-failing test ok ·
`golangci-lint run internal/threatfeed/...` 0 issues (main-package findings
are pre-existing, in untouched functions).

**Resulting branch / PR**: `fix/threatfeed-domain-allowlist-consolidated`
→ draft **PR #623** ("fix: consolidate threat-feed domain allowlist
enforcement"). CI at time of writing: Snyk clean; `Gate · govulncheck` red
(environmental GO-2026-5856); Admin-UI RBAC playwright job red on a driver
CDN 404 (job is explicitly advisory). #614/#615 stay open until #623 is
fully validated, then close both referencing #623.

---

## Per-PR review reports

### PR 503 — fix(connlimit): Release must decrement counter even when limiter is disabled
- **Original intent / problem**: `Release` early-returns when the limiter is disabled, so enable→acquire→disable→release leaks the per-IP counter; after re-enable that IP is permanently over-limit (restart-only recovery). Real bug, correctly diagnosed.
- **Current relevance**: bug is live on main — carried verbatim into `internal/connlimit/connlimit.go:97-99` by the ADR-0002 extraction; no test covers the sequence.
- **Overlap**: #610/#622 wire SOCKS5 into the same limiter (widens exposure). No PR fixes the leak itself.
- **Architecture / security**: fix is right (availability: removes a self-inflicted permanent block); but the patch targets the pre-extraction file and its test uses unexported struct literals — won't compile from package main.
- **Regression risk / tests / CI**: rebuilt fix is a 3-line guard deletion in a leaf package; PR's contract test is good and ports mechanically. CI green but stale (pre-CI-redesign, base 434 commits old); merge-tree confirms content conflict.
- **Disposition**: **REBUILD_FROM_MAIN**. Actions: delete the guard in `internal/connlimit`, port `TestConnLimiter_ReleaseWhileDisabled` using `New()`, sequence before/with #622, close #503. Confidence: high.

### PR 515 — fix(authpolicy): kill switch must not disable CR rules in no-backend Exempt deployments
- **Original intent / problem**: with the Exempt kill switch engaged in a no-backend deployment, `authRequired` evaluates false and scoped CredentialRequired rules silently stop challenging — the kill switch (meant to be strictly more restrictive) *weakens* enforcement, violating the frozen defaultAuthOutcome spec.
- **Current relevance**: bug still present at `proxy.go:154` (`resolveRequestAuth`); no main test covers the no-backend kill-switch case.
- **Overlap**: none.
- **Drift**: severe — Slice 5 deleted `SetUnauthMode` (PR's tests uncompilable), DEBT-002/003 moved the code; proxy.go hard-conflicts.
- **Disposition**: **REBUILD_FROM_MAIN** (high security value). Actions: capture `originalEffective` pre-kill-switch in `resolveRequestAuth`; add the `!credCapable && !ssoCapable` inert guard in the default arm; rewrite tests on `SetDefaultAuthOutcome`; add a browser-redirect variant; close #515. Confidence: high.

### PR 567 — docs: fix HA operator-facing gaps
- OPERATIONS.md `-ca-bundle`→`-ca-path` hunk still valid; deployment-guide HA section still valid (needs `-ha-token` added per unresolved Codex P2 — `haJoinMode()` requires both flags); README hunk superseded by the README rewrite (f4d64a9) and is the only merge conflict.
- Overlap: #617 (adjacent OPERATIONS.md hunks, auto-merge), #609 (same root cause, different file). CI green.
- **Disposition**: **UPDATE_AND_KEEP** — drop README hunk, add `-ha-token`, merge. Confidence: high.

### PR 581 — ui(ocsp): surface fail-closed revocation blocks
- Adds `failClosedTotal`/`revokedTotal`/`lastFailClosedUTC` to `internal/ocsp` + `GET /api/ocsp` + CA-panel warning banner. Decision logic byte-identical (increments only). Feature absent on main; closes a real MTTR blind spot.
- Overlap: real textual collision with #622 (same `checkResponders` lines) — merge #581 first; index.html siblings disjoint. Unresolved Codex P2: cache-hit fail-closed verdicts don't increment (underreports ongoing outage) — mitigated to ~2-min granularity once #622's indeterminate TTL lands.
- CI: both required gates green; clean merge-tree. **Disposition**: **MERGE_AS_IS** (sequence before #622). Confidence: high.

### PR 583 — perf(policy): precompute MatchedConditions
- Correct, well-gated (hard alloc benchgate), green CI, clean vs main — but functionally contained in #612; the trio #583/#605/#612 pairwise conflict on the same `PolicyRule`/`sortLocked`/`Evaluate` hunks.
- **Disposition**: **CONSOLIDATE_WITH_OTHER_PR** (#612 survivor). Port `TestBenchGate_PolicyEvalMatchAllocs` + its benchmark; close #583 after #612 merges. Confidence: high.

### PR 603 — feat(ui): surface release-catalog trust mode
- Renders `verify_mode` (badge + break-glass warning incl. remediation env var) in the Release Management panel; feature absent on main; closes a GUI-parity gap. `textContent`-only, no new route, invariants untouched. Both required gates green; clean merge-tree.
- Overlap: **#616 is the same feature** (hard-conflict on both files). #603 wins: superset UX (positive ENFORCE confirmation + warning), safer DOM pattern, genuinely green gates. #616's one extra test-marker idea can be ported in a follow-up.
- **Disposition**: **MERGE_AS_IS**; close #616. Optional: neutral styling for the `unknown` fallback. Confidence: high.

### PR 605 — perf(policy): precompute source-CIDR networks
- Correct, excellent tests (IPv6/boundary/invalid-client-IP parity, 10k-rule benchgate), lazy client-IP parse (byte-identical for FQDN-only stores). Green CI, clean vs main — but reimplemented in #612 (eager-parse variant).
- **Disposition**: **CONSOLIDATE_WITH_OTHER_PR** (#612 survivor). Port lazy parse + IPv6 parity + 10k gate; close #605 after #612 merges. Confidence: high.

### PR 606 — feat(upstream): circuit-breaker failure count + retry ETA in UI
- Additive `Status` fields (`failures`/`openedAtMs`/`retryAfterMs`) + inline UI hint; redaction contract preserved (`URL.Redacted()`); no new route. Feature absent on main; merge-tree clean.
- CI red **only** on a pre-existing `TestSelfFence_EntersStandbyResync` data race in untouched HA files (live flake on main — deserves its own issue). Valid Codex P2: the "retry in Ns" ETA freezes (tick() never refreshes the upstream view).
- **Disposition**: **UPDATE_AND_KEEP** — one-line tick() fix (or client-side countdown), re-run gate, merge. Confidence: high.

### PR 607 — docs(governance): terminology review
- Six low-risk wording fixes (whitelist→exempt, scan-panel disambiguation, SSL-inspection copy, HA term=epoch note, rolling update, Maintenance Agent) + dated report. Every old term verified still on main; zero drift; merge-tree clean; both gates green.
- Overlap: #618 is the complementary code-side follow-up; it supersedes the report's T-1 "no action" conclusion (non-blocking one-line addendum recommended).
- **Disposition**: **MERGE_AS_IS**. Confidence: high.

### PR 609 — docs: fix stale CLAUDE.md file map, quickstart flags, OTLP gap
- All claims independently re-verified (10 stale file-map entries, `-port`/`-ui-port`/`-ca-path`/`-otlp-endpoint` flags, OTLP wiring). Zero drift; gates green; merge-tree clean. One defect: the PR's *own* fixed quickstart writes `-port :8080` — `flag.Int` rejects it (unresolved Codex P2).
- **Disposition**: **UPDATE_AND_KEEP** — change to `-port 8080 -ui-port 9090`, merge promptly. Confidence: high.

### PR 610 — fix(chaos): SOCKS5 conn limit + OCSP short-TTL (2026-07-07)
- Both fixes real and still absent from main, but **#622 re-implements them near-verbatim** (superset). #610's unique value is its 319-line review doc (CHAOS-22..43 — 22 findings existing nowhere else; #622's doc does not subsume it). CI red on its own test-file lint (whyNoLint/noctx).
- **Disposition**: **CONSOLIDATE_WITH_OTHER_PR** (#622 survivor). Salvage the doc (cherry-pick into #622 or a docs-only PR, reconcile finding numbering), then close #610. Confidence: high.

### PR 612 — perf(policy): precompute request-independent rule state; cache tz locations
- Strict superset of #583+#605 plus a `scheduleLocation` cache (34× on scheduled rules; removes per-request tzdata disk reads). Invalidation verified through every mutator incl. the DP `ReplaceAll` sync path; fail-closed semantics pinned; benchgate added; compatible with main's TOCTOU fix. Fully green CI; clean merge-tree.
- Deliberate deltas (documented, acceptable): eager once-per-Evaluate client-IP parse (+1 alloc); invalid-tz cached as UTC until restart (read-once posture).
- **Disposition**: **MERGE_AS_IS** (survivor of the trio); close #583/#605; port their extra tests as follow-up. Confidence: high.

### PR 616 — ui(releases): verify_mode break-glass banner
- Same feature as #603, newer but weaker (banner-only, `innerHTML`+escHtml, no positive-state confirmation); hard-conflicts with #603; required gate red (environmental govulncheck).
- **Disposition**: **CLOSE_AS_OBSOLETE** (duplicate of #603). Optionally port its renderer-name test marker. Confidence: high.

### PR 617 — docs(cluster): fix nonexistent `--cluster-grpc-*` flags
- Verified: the flag triple never existed; real flags are `-cp-grpc-*`/`-dp-*`; fix is correct and complete (2 doc hunks + 1 static string in `checkClusterPosture`). Based on current main tip; merge-tree clean; red only on environmental govulncheck.
- **Disposition**: **MERGE_AS_IS** (after the toolchain chore). Confidence: high.

### PR 618 — fix(terminology): default-auth-outcome route + DPI-bypass audit action
- Adds canonical `/api/settings/default-auth-outcome` with the legacy path kept as an alias (spec's back-compat requirement honored); renames audit action `security.dpi_bypass` → `security.content_scan_bypass`. All admin-UI invariants updated (uiRoutes both paths, C1/D0 locks 144→145, alias regression test). Zero drift; Deep gate green; Fast gate red only on environmental govulncheck.
- Operational caveat: external SIEM filters on the old action string stop matching (repo precedent 4b3ae69 accepted this class) — release-note it.
- **Disposition**: **MERGE_AS_IS** (after toolchain chore + release note). Confidence: high.

### PR 619 — docs(security): regression review (window ea0f2ff → 328c883)
- Docs-only, third report in the `docs/security-reviews/` series; every material code claim independently re-verified against main; 4 LOW/INFO findings, F1 (merge-import silent rule skip) is a real, unclaimed follow-up. Both gates green; zero drift.
- **Disposition**: **MERGE_AS_IS**; track F1 as a work item. Confidence: high.

### PR 620 — perf(reqlog): fixed circular buffer
- Replaces append-retrim with in-place ring; newest-first `Get()` semantics preserved (wrap/partial/empty hand-verified); snapshot copy under lock (no aliasing); zero-alloc steady state pinned by `testing.AllocsPerRun`; committed benchmarks back the −96% claim; full `-race` + determinism green. Based on current main tip; red only on environmental govulncheck.
- **Disposition**: **MERGE_AS_IS** (after toolchain chore). Optional: post-wrap content assertion. Confidence: high.

### PR 621 — fix(install): empty `allow_peers` corruption
- Real bug (awk append on `[]` yields invalid TOML `[, "1000"]`; strict decoder then breaks the maint agent — fail-closed availability bug); fix is a correct additive empty-array branch; tests execute the real extracted shell function; red only on environmental govulncheck; Deep gate (incl. shellcheck) green; zero drift.
- **Disposition**: **MERGE_AS_IS** (after toolchain chore). Confidence: high.

### PR 622 — chaos: four failure-mode defects (CHAOS-01/02/04/06)
- CHAOS-01 CP config-version persistence floor (real HIGH: CP restart silently suppressed all config sync), CHAOS-02 SOCKS5 conn-limit bypass, CHAOS-04 OCSP outage-verdict 2-min TTL (stays fail-closed), CHAOS-06 root-CA load-failure visibility (healthz field, report-only readyz, deferred startup alert). All verified correct; strong tests; based on current main tip; merge-tree clean.
- CI red on (a) 4 lint issues in its own new test files (whyNoLint / noctx) — PR-caused, trivial; (b) environmental govulncheck. Supersedes #610's code (hard-conflicts with it); inherits the #503 Release-leak on its new SOCKS5 path (land rebuilt #503 alongside); rollback caveat: epoch-scale versions mean a reverted CP needs DP restarts.
- **Disposition**: **UPDATE_AND_KEEP** — fix lint, merge after #581, salvage #610's doc, close #610. Confidence: high.

### PR 614 / 615 / 623 — threat-feed domain allowlist
See the consolidation report above. **#614: CLOSE (superseded by #623)** ·
**#615: CLOSE (superseded by #623)** · **#623: validate → promote from draft**.

---

## Final maintainer recommendation

**MERGE NOW** (no changes to the PR itself required; † = required gate red
only from the environmental GO-2026-5856 govulncheck — land the go1.25.12
chore first, then re-run):
#619 · #607 · #612 · #581 · #603 · #617† · #618† · #620† · #621†

**FIX NEXT** (small, named fix, then merge):
#567 (drop README hunk, add `-ha-token`) · #609 (fix its own `-port :8080`) ·
#606 (tick() staleness + flake re-run) · #622 (4 test-file lint issues) ·
#623 (draft → validate CI → ready-for-review)

**REBUILD** (fresh branch from main, port intent, close original):
#515 (auth kill-switch, security) · #503 (connlimit Release leak)

**CONSOLIDATE** (survivor merges, twin closes after):
#583 + #605 → #612 · #610 → #622 (salvage its review doc first) ·
#614 + #615 → #623 (done — draft PR open)

**CLOSE**:
#616 (duplicate of #603) · plus the post-merge closes listed under
CONSOLIDATE (#583, #605, #610, #614, #615 — only after their survivors land)

**HUMAN DECISION REQUIRED**:
none blocking. Two flagged judgment calls, both with a recommended default:
(1) #618's audit-action rename can break external SIEM filters — proceed with
a release note (repo precedent exists); (2) #603-vs-#616 UX (always-visible
trust badge vs break-glass-only banner) — #603's explicit-positive-state UX
recommended and reflected above.
