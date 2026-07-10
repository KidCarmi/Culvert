# Merge Execution Plan & Final Release Recommendation — 2026-07-10

Companion to `docs/engineering/OPEN-PR-REVIEW.md` (the per-PR review record).
This document is the Release-Manager output of the five-phase cleanup:
Phase 1 (toolchain unblock), Phase 2 (merge-readiness revalidation),
Phase 3 (production-readiness review of PR #623), Phase 4 (merge waves),
Phase 5 (final recommendation). Nothing in this plan has been merged,
closed, or marked ready by the release process itself; PR #624 was merged
directly by the repository owner.

## Phase 1 result — global CI blocker removed (LANDED)

- **PR #624** (`chore/go1.25.12-govulncheck`, 2-line diff: go.mod pin +
  CLAUDE.md pin note) — **merged to main (`2b7df65`)** by the owner.
- Proof chain: (1) failing gates on 7 PRs all named GO-2026-5856
  "fixed in go1.25.12"; (2) the go1.25.11→go1.25.12 `crypto/tls` source
  delta is exactly the ECH/PSK ClientHello serialization guard;
  (3) **#624's own `Gate · govulncheck + gosec` passed against the live
  vulndb**, and its Fast/Deep gates went green end-to-end.
- Consequence: every previously env-red PR needs **one Fast-Gate re-run**
  (no rebase — PR CI runs on the merge ref and picks up main's go.mod).

## Phase 2 result — merge-readiness revalidation

- Main moved only by #624 (go.mod + CLAUDE.md). Re-verified post-merge:
  all nine MERGE NOW branches still merge conflict-free vs the new tip,
  **and** a sequential merge simulation of the entire set applied 9/9
  cleanly — the set is co-mergeable in any order (last-merged UI PRs may
  need a trivial branch update on `static/index.html`).
- Correction to the earlier report: **no previously-green CI result
  survived** — the five "fully green" PRs (#619 #607 #612 #581 #603) were
  green only because their govulncheck jobs ran before GO-2026-5856
  published. Post-#624, every candidate needs a fresh gate run before its
  merge button is trusted. That is the only revalidation step; the
  substantive results (race, determinism, lint) remain representative
  because main's code did not change under them.
- #567 remains the only conflicting keep-PR (its README hunk — already
  slated to be dropped).

## Phase 3 result — PR #623 production-readiness review

Three independent adversarial reviews (correctness/concurrency, security
boundary, ops/cluster) + a lead pass. Verdict: the in-process design
(lookup-time masking, in-memory retention) is sound; the review surfaced
one convergent **P1** and several P2s, all now fixed on the branch:

| Finding | Severity | Resolution (commit) |
|---|---|---|
| Mixed-version rolling upgrade / binary rollback poisoning: retained masked domains reinterpreted as "block" by old binaries (old DPs / rollback) — would hard-block github.com et al. fleet-wide | P1 | `6881c81` — masked-domain retention is **in-memory only**; `saveToDisk` + `ExportDomains` filter allowlisted hosts so the persisted key and wire field keep their legacy meaning. Immediate re-block on removal preserved within process lifetime |
| Persist-failure applies allowlist in memory with **no audit trail** (transient unaudited bypass) | P2 (sec+ops+correctness convergent) | `36614a9` — distinct `threatfeed.allowlist.update_unpersisted` audit action; 500 semantics unchanged |
| Legacy on-disk keys (IDN/trailing-dot) stop matching canonicalized lookups after upgrade (fail-open until next sync) | P2 | `a353577` — `loadFromDisk` re-keys both maps, fail-safe fallback |
| `ThreatDomainAllowlist` full-clear wire-dead (`omitempty`): DP keeps stale fail-open mask after CP clears the allowlist | P2 | `6881c81` — omitempty dropped; registry row flipped to `WireWipeCapable` (RateLimitExempt precedent); all 11 `TestConfigSurfaces_*` green |
| Allowlist PUT never publishes a snapshot → DPs lag until an unrelated admin action | P2 | `6881c81` — `publishCurrentConfigSnapshot()` after successful PUT |
| `normaliseDomain` mints unmatchable garbage keys from hostless path input (`10.0.0.1/24`) — silent no-op exemptions | P2 | `6881c81` — rejected instead of stored |
| `ImportFeedData` didn't re-canonicalize URL keys from older CPs | P2 | `6881c81` — re-keyed, fail-safe |
| Stale apply-order comment describing the superseded prune design | P2 | `6881c81` |
| Load-time entry count computed pre-rekey | nit | `6881c81` |

**Verified clean by two independent reviewers**: exact-URL-wins ordering
(no URI glassbreak), producer/consumer key symmetry (uppercase, trailing
dot, host:port, bracketed IPv6, IDN, empty, whitespace), reassign-only
map invariant (saveToDisk race analysis intact), locking discipline,
allowlist injection surfaces (admin-RBAC API + ClusterSynced snapshot
only; feeds cannot write it), nil-vs-empty default-seed contract,
old-CP→new-DP direction, `dbPath=""` DPs, config-surface registry parity.

**Deferred follow-ups (not blockers)**: duplicate IDNA pass on the hot
path (pass the RISK-013-normalized host into `CheckDomain`); a
`culvert_threatfeed_allowlist_masked_total` metric; operator-doc note
that allowlisting a host trusts all *non-inspected CONNECT* traffic to
it; `Add/RemoveDomainAllowlist` have zero production callers (test-only
API — document or remove).

**Validation on the final branch (4 commits, `56f299b..6881c81`)**:
gofmt/vet/build clean · full `go test ./...` 50 packages 0 FAIL ·
`-race` on `internal/threatfeed` and targeted main suites ·
isolated `-shuffle=on -count=2` on the once-flaky test · all
`TestConfigSurfaces_*` · Deep PR Gate APPROVED on the pre-batch head; the
final head needs one fresh gate run (post-#624 the govulncheck lane is
expected green; the only anticipated red is the **advisory** playwright
job, which 404s on its driver CDN repo-wide).

## Phase 4 — merge waves

Ordering principles: docs first (zero runtime risk), then one
hot-path-touching wave at a time with a soak between waves; every wave is
individually revertible; supersession closes happen only after the
survivor merges and its gates re-run green.

### Wave 0 — toolchain unblock (DONE)
- **PRs**: #624 (merged by owner).
- **Validation after merge**: its own gates green (confirmed). Re-run
  Fast Gate on every wave-1+ candidate before merging it.

### Wave 1 — documentation (zero runtime blast radius)
- **PRs**: #619 (security-review record), #607 (terminology docs/GUI copy),
  #617 (cluster-flag docs + one diagnostics string).
- **Why together**: docs-only or string-only; no behavioral surface; all
  three verified still-accurate against current main; no shared hunks.
- **Risk**: minimal. **Rollback**: `git revert` per PR.
- **Validation**: Fast/Deep gates green post-#624 re-run; nothing else.
- **Blast radius**: rendered docs + one `/api/diagnostics` remediation string.

### Wave 2 — docs after their named fixes
- **PRs**: #609 (fix its own `-port :8080` → `-port 8080` first),
  #567 (drop README hunk, add `-ha-token` to the deployment-guide hunk).
- **Why together**: same class as wave 1; held back only by their small
  authoring defects. **Risk/rollback/validation**: as wave 1.

### Wave 3 — policy engine precompute (#612), then supersession closes
- **PRs**: #612 alone. After merge + green: close #583 and #605 as
  superseded (with cross-references).
- **Why alone**: touches `Evaluate` — the every-request Zero-Trust hot
  path. Isolate so any anomaly is unambiguously attributable.
- **Risk**: medium-low (fail-closed fallbacks pinned; benchgates wired).
- **Rollback**: revert the single PR; no persisted/wire format involved.
- **Validation**: full race suite (in-gate), `TestBenchGate_*` perf gates,
  post-merge soak watching `culvert_*` latency histogram + policy hit
  counters; then port #583's match-alloc benchgate + #605's IPv6 parity
  tests as a test-only follow-up.
- **Blast radius**: policy evaluation for all traffic (logic-equivalent
  precompute; behavior deltas confined to log-once tz warnings).

### Wave 4 — OCSP observability then chaos fixes (ordered pair)
- **PRs**: #581 first; then #622 (after its 4 test-file lint fixes and a
  trivial rebase over #581's `internal/ocsp` hunks). After #622 is green:
  salvage #610's unique 2026-07-07 review doc (doc-only commit), then
  close #610 as superseded.
- **Why this order**: #581 is conflict-free vs main today; #622 edits the
  same `checkResponders` lines, and rebasing #622's counters-adjacent
  change is semantically obvious in that direction.
- **Risk**: medium (#622 changes failure-path behavior in four
  subsystems; happy paths byte-identical; limiter ships disabled).
  Known caveat: CP config versions jump to epoch scale — a reverted CP
  needs DP restarts to resync (documented in #622).
- **Rollback**: revert per PR (#581 trivially; #622 with the version-scale
  caveat above).
- **Validation**: `internal/ocsp` race suite; SOCKS5 conn-limit tests;
  CP restart → config-version monotonicity test; `/healthz` shape check
  against monitoring; soak on OCSP fail-closed counters (#581's new
  panel) which directly observes #622's short-TTL behavior.
- **Blast radius**: SSL-inspection failure paths, SOCKS5 tunnel setup,
  CP→DP version arithmetic, healthz payload.

### Wave 5 — independent low-risk engine/installer
- **PRs**: #620 (reqlog ring buffer), #621 (installer allow_peers fix).
- **Why together**: mutually independent, no shared files, both fully
  reviewed with hand-verified logic and strong tests.
- **Risk**: low. **Rollback**: revert per PR.
- **Validation**: reqlog zero-alloc gate + UI request-log feed spot check
  (newest-first ordering); installer shellcheck lane + the three new
  extracted-function tests.
- **Blast radius**: request-log ring (UI feed), quick-start installer.

### Wave 6 — UI + terminology rename
- **PRs**: #606 (after the `tick()` staleness one-liner; its only CI red
  was a pre-existing HA-lease flake — re-run), #603, #618 (with a
  release-note for the `security.dpi_bypass` → `security.content_scan_bypass`
  audit-action rename). After #603 merges: close #616 as duplicate.
- **Why together**: disjoint `static/index.html` hunks (verified
  co-mergeable); #618's alias keeps the old route serving.
- **Risk**: low. SIEM filters on the old audit action are the one
  external-consumer concern (release note covers it).
- **Rollback**: revert per PR; #618's alias makes route rollback a no-op
  for clients.
- **Validation**: D0/C1/C1.5 route-parity suites (in-gate), GUI marker
  tests, manual panel smoke via the playwright lane once its driver-CDN
  404 is fixed.
- **Blast radius**: admin UI panels; audit-action string consumers.

### Wave 7 — threat-feed consolidation (#623)
- **PRs**: #623 (promote from draft after: fresh gates green post-#624 +
  human maintainer review of the Phase-3 record). After merge + green:
  close #614 and #615 as superseded, citing #623.
- **Risk**: medium — hot-path verdict logic + CP/DP sync surface; every
  behavior change contract-tested; version-skew engineered for
  explicitly (see Phase 3 table).
- **Rollback**: revert the PR (single logical unit). **Binary** rollback
  after deployment is safe by design (persisted/wire surfaces keep
  legacy meaning); residual: in-memory masked intel is rebuilt by the
  next feed sync after a restart.
- **Validation**: full race suite (in-gate); the 12-case test matrix in
  the PR body; post-merge soak: verify an allowlist PUT reaches a DP
  within one poll (≤30s) and that `threatfeed.json` on a node contains
  no allowlisted hosts under `domains`.
- **Blast radius**: threat-feed verdicts on every request; threat-feed
  persistence; CP→DP threat-feed sync.

### Wave 8 — rebuilds (fresh PRs, close originals)
- **PRs**: rebuilt #515 (auth kill-switch fail-closed fix, in
  `resolveRequestAuth`, tests on `SetDefaultAuthOutcome`) and rebuilt
  #503 (delete the disabled-limiter early-return in
  `internal/connlimit/connlimit.go` Release, port the contract test).
  Close #515/#503 referencing the replacements.
- **Why last**: they need fresh implementation + review cycles; #503
  ideally lands close to wave 4 (it hardens the Release call #622's
  SOCKS5 path adds) — pull it earlier if the rebuild is ready.
- **Risk**: low-medium (small diffs on security-relevant paths, both
  red-before/green-after testable).
- **Validation**: targeted regression tests (kill-switch matrix per the
  frozen spec; limiter disable/enable cycle), full race suite.
- **Blast radius**: Stage-1 auth gate; per-IP connection limiting.

## Phase 5 — final release recommendation

### Merge order (one line)
#624 ✅ → [#619 #607 #617] → [#609* #567*] → #612 (close #583 #605) →
#581 → #622* (salvage #610 doc, close #610) → [#620 #621] →
[#606* #603 #618] (close #616) → #623* (close #614 #615) →
rebuilt-#515 / rebuilt-#503 (close originals).  (* = after its named fix;
every PR gets a fresh Fast-Gate run post-#624 before its merge button.)

### PRs that should remain open (until their step)
- #623 — draft until fresh gates + human review (constraint: not marked
  ready by the release process).
- #622, #606, #609, #567 — until their named small fixes land.
- #515, #503 — until their rebuilt replacements are open and green.
- All wave-1..6 candidates — merge-ready, awaiting execution approval.

### PRs to close after supersession (never before the survivor is merged and green)
- #583, #605 → superseded by #612
- #610 → superseded by #622 (after its 2026-07-07 review doc is salvaged)
- #616 → duplicate of #603
- #614, #615 → superseded by #623

### Remaining engineering risks
1. **HA-lease test race** (`TestSelfFence_EntersStandbyResync`) — live
   flake on main that survived the RISK-018 fix; randomly reddens
   required gates (bit #606). Needs its own issue/fix.
2. **Playwright driver CDN 404** — the advisory Admin-UI RBAC job fails
   on every PR (driver 1.60.0 missing from `playwright.azureedge.net`);
   browser-level RBAC e2e coverage is effectively dark until re-pinned.
3. **F1 from #619's review**: merge-mode config import silently skips
   conflicting rules (log-only, response says ok) — unclaimed follow-up.
4. **#503/#515 bugs are live on main** until wave 8: a conn-limit
   counter leak reachable from the admin API, and a kill-switch path that
   weakens no-backend Exempt deployments.
5. **#622 rollback caveat**: epoch-scale config versions mean a reverted
   CP needs DP restarts to resync.
6. **Old-CP nil-skip residual** (#623): snapshots from a pre-#623 CP
   omit the allowlist field, so a new DP keeps its last allowlist until
   the CP is upgraded — bounded by the upgrade window, by design.

### Remaining technical debt (tracked, non-blocking)
- Port #583's match-alloc benchgate + #605's IPv6/lazy-parse parity tests
  onto post-#612 main (test-only PR).
- #607's report T-1 conclusion needs a one-line addendum once #618 lands.
- Threat-feed follow-ups: masked-hits metric, single IDNA pass on the
  hot path, CONNECT-trust operator note, `Add/RemoveDomainAllowlist`
  caller-less API.
- #619 line-number nit (`configversion.go:229`→228) if ever touched.

### MVP-shipping blockers
**None hard.** Conditions before cutting a release from post-cleanup main:
(1) waves 1–7 merged with fresh green gates (or consciously descoped);
(2) the two live security-adjacent bugs (#503/#515 rebuilds) landed or
explicitly risk-accepted for the release; (3) the HA-lease flake either
fixed or quarantined so release gates are deterministic; (4) release notes
carry the #618 audit-action rename and #622 version-scale rollback caveat.

### Constraint compliance
No PR was merged, closed, reopened, or marked ready-for-review by this
process. PR #624 was merged by the repository owner directly. PRs #623
and #624 were created as drafts as instructed earlier; all other
repository writes are commits to `fix/threatfeed-domain-allowlist-consolidated`
(explicitly requested improvements) and the two report documents on
`claude/loving-planck-hgew3c`. Execution of waves 1–8 awaits explicit
approval.
