# Security Regression Review — Policy Learning (ADR-0025 M5A/M5B), Single-Evaluator Core (ADR-0026), Identity Ingress (F6)

- **Date:** 2026-08-21
- **Reviewer role:** Security Regression Engineer (standing charter, `docs/engineering/ENGINEERING-CONSTITUTION.md`)
- **Baseline:** `b697cf3` (tip of the 2026-08-18 review)
- **Tip under review:** `7df2677`
- **Window:** dominated by PR #1181 (Policy Learning Mode M1–M5B, the ADR-0026
  single-evaluator extraction, and the F5/F6 identity-plane rework) — 88 files,
  ~18k insertions. #1186/#1185/#1159 are documentation-only.

## Verdict

**One security regression found and fixed.** It is an availability regression on
the enforcement path, introduced by an advisory feature that is disabled by
default — the worst combination, because the cost is paid by every deployment
including those that never enable the feature.

Everything else reviewed in this window is either byte-faithful to the baseline
or **strictly tighter**. The window's headline change (F6) closes a real
pre-existing authorization defect; see "What got safer" below.

| ID | Finding | Severity | Class | Status |
|----|---------|----------|-------|--------|
| SEC-UCAT-1 | Every `urlcat.AddHost` re-hashes the entire taxonomy **inside the write lock** the request path's category lookups contend on — 17x–133x, once per host of a SaaS feed merge, and unconditionally even when Policy Learning is off | **Medium** | CWE-400 (Uncontrolled Resource Consumption) · OWASP A04 (Insecure Design) | Fixed |
| SEC-TRL-1 | The new late-trailer rescrub is reachable only through `Read`; nothing structurally prevented a future wrapper change from exposing a copy fast path that bypasses it | Low (hardening — not exploitable as shipped) | CWE-1076 / CWE-807 | Hardened + pinned |

---

## SEC-UCAT-1 — Taxonomy re-hash inside the category-store write lock

**Files:** `internal/urlcat/urlcat.go` (`AddHost`, `recomputeFingerprintLocked`,
`ContentFingerprint`)
**Introduced by:** PR #1181, the QB-2 corrective slice that added
`Store.ContentFingerprint` for the policy-learning category epoch.

### What changed

`ContentFingerprint()` is a restart-stable semantic hash of the admin taxonomy,
pinned per learning session so a recommendation goes stale when the taxonomy it
was observed under changes. It was implemented as an **eagerly maintained cache**:
every semantic mutation recomputed the hash under the store's write lock.

```go
func (s *Store) recomputeFingerprintLocked() {
	s.fp.Store(computeFingerprint(s.entries)) // O(all host patterns), sorts + allocates per entry
	s.rev.Add(1)
}
```

For the bulk mutators (`Set`, `Delete`, `RemoveHost`, `Load`, `ReplaceAll`) that is
fine — they already call `rebuildIndex()`, which is O(taxonomy) anyway. The call was
also inserted into `AddHost`, and `AddHost` is the one mutator that deliberately
does **not** rebuild. Its own helper says why:

> `addHostToIndexes` … Rebuilding here would be correct but pathological: the
> legacy SaaS feed sync calls `AddHost` once per merged host (`saas_feed.go`), so a
> large feed update would rebuild the ENTIRE index once per added host while holding
> the write lock — stalling the request path's RLock for O(hosts × patterns).

The fingerprint recompute reintroduced exactly that shape, three lines above the
comment describing it.

### Why it is a security finding, not just a slow path

1. **The lock is on the enforcement path.** `s.mu` is the same `RWMutex` that
   `MatchesHost` / `LookupHost` / `LookupHostAdmin` take for read. The policy
   evaluator resolves them for every category-scoped access rule on every proxied
   request (`policy_hostcat.go`). Go's `sync.RWMutex` blocks new readers once a
   writer is waiting, so a merge loop of N hosts injects N write-lock acquisitions,
   each O(taxonomy), into the middle of live traffic evaluation.
2. **The trigger is feed-driven, not admin-driven.** `mergeSaaSCategories` calls
   `AddHost` once per *new* host in a category feed refresh. The number of
   iterations is set by upstream feed content, not by an operator action.
3. **It is unconditional.** `ContentFingerprint()` has exactly one consumer
   (`learnCategoryEpoch`, `policy_learning_observe.go`), reachable only when a
   Policy Learning engine exists. Policy Learning is disabled by default and has no
   YAML/env/CLI enablement path. So in the shipped default posture the value was
   being recomputed on every `AddHost` and **never read at all**.

### Measured

`BenchmarkAddHost` with persistence disabled (`path == ""`, so `Save()` is a
no-op) — this isolates lock-held work:

| taxonomy | before (eager) | with the eager hash removed | factor |
|---|---|---|---|
| 27 cats × 25 hosts (≈ the shipped default, 675 patterns) | 119.7 µs, 118 allocs, 48.9 KB | 6.8 µs, 6 allocs, 5.1 KB | **17.6x** |
| 50 × 200 (10k patterns) | 1,668 µs, 211 allocs, 525 KB | 14.4 µs, 6 allocs, 12.9 KB | **116x** |
| 50 × 1000 (50k patterns) | 8,710 µs, 313 allocs, 3.6 MB | 65.5 µs, 8 allocs, 54.8 KB | **133x** |

A 10,000-host feed merge against a 10k-pattern taxonomy is ~16.7 s of write-lock
CPU and ~5 GB of allocation churn that did not exist before this window.

### Attack scenario / exploitability

- **Preconditions:** a node with the legacy SaaS category feed sync active (the
  shipped `-cat-feed` path) and a non-trivial taxonomy. No authentication and no
  admin action required to *trigger* the merge — it is periodic.
- **Scenario:** an attacker who can influence feed content (a compromised or
  hijacked feed origin, a mirror, or simply a large legitimate refresh) causes a
  merge with many new hosts. Each host stalls every category-scoped policy
  evaluation for the duration of a full-taxonomy hash. The proxy does not fail
  open — evaluation still completes correctly — but per-request latency and
  connection-slot occupancy rise sharply, which is a denial-of-service surface on
  a gateway that is in-line for all egress.
- **Likelihood:** Medium (a routine feed refresh is enough; no attacker needed for
  the degradation, only for the amplification).
- **Impact:** Availability / latency of the enforcement plane. No confidentiality
  or integrity impact; no fail-open.
- **Affected assets:** the proxy request path, the URL-category store.
- **Severity:** **Medium**. Bounded by feed size and taxonomy size; degradation,
  not bypass.

### Fix

Make the fingerprint **lazy and revision-keyed** instead of eagerly maintained:

- Writers call `invalidateFingerprintLocked()`, which only advances the monotonic
  `rev` counter — the same bump they already performed. O(1), no hashing under the
  write lock.
- `ContentFingerprint()` serves a memoized `{rev, fp}` pair while `rev` still
  matches (two atomic loads in steady state), and otherwise computes **under the
  read lock**, single-flighted through a dedicated `fpMu` so a burst of readers
  after a mutation pays for one hash rather than one per goroutine.

Freshness is preserved exactly, and this is the load-bearing half: `rev` is bumped
inside the writer's critical section, so any reader that can observe new content
necessarily observes the advanced revision, misses the memo, and recomputes. `rev`
is monotonic, so a revision names exactly one content state and a cached entry can
never describe superseded content. The returned **values are unchanged** —
`computeFingerprint` and its framing (`culvert-urlcat-content-fp-v3`) are untouched,
so no pinned epoch is reinterpreted.

Cost moves from "N × O(taxonomy) under the write lock, always" to "at most one
O(taxonomy) hash per mutation batch under the read lock, and only when Policy
Learning is actually enabled".

### Required tests (added)

`internal/urlcat/urlcat_fingerprint_cost_test.go`:

- `TestFingerprint_AddHostCostIsFlatInTaxonomySize` — the cost gate. A **ratio**
  comparison (machine-independent) of `AddHost` allocations on a 50-pattern versus
  a 100k-pattern taxonomy, with the memo pre-warmed so a lazy implementation cannot
  pass merely by not having been read. Verified to **fail** against the eager
  implementation (26.9x measured, bound 4.0x) and pass against the fix.
- `TestFingerprint_WarmMemoStillSeesEveryMutation` — the freshness gate, and the
  reason the cost gate alone is not enough: with the memo already populated, every
  mutation kind (`AddHost`, `RemoveHost`, `Set` new, `Set` existing, `Delete`,
  `ReplaceAll`) must still change the fingerprint, and no two states may collide.
  A memo that outlived a taxonomy edit would report learning recommendations FRESH
  against a taxonomy their evidence was never observed under — an evidence-integrity
  failure, not a performance one.
- `TestFingerprint_ConcurrentReadersNeverSeeAThirdValue` — concurrency gate: a
  writer toggles the taxonomy between two states while four readers loop; every
  read must return one of exactly those two fingerprints. Catches a memo published
  against the wrong revision or a hash taken over a half-applied mutation. Run
  under `-race` for the data-race half.

The pre-existing `urlcat_fingerprint_test.go` suite (reload stability, entry-order
identity, semantic no-ops, add/remove round trip, zero-value store, concurrent
reads) passes unchanged under `-race` — that is the behaviour-preservation proof.

### Regression risk of the fix

Low. The change is confined to one file, preserves the hash function and its
framing byte-for-byte, and keeps `Revision()`'s contract (bumped inside the write
lock). The one behavioural difference is *where* the hash is computed: the first
reader after a mutation now pays for it instead of the writer. That reader is the
learning drain or an admin API call, never a mutator, and it holds only the read
lock — so it cannot block other readers.

---

## SEC-TRL-1 — Late-trailer rescrub reachable only via `Read` (hardening)

**Files:** `proxy.go` (`trailerRescrubBody`)

`scrubForwardedHeaders` gained a body wrapper this window because net/http merges
*received* trailer fields back into `r.Trailer` at body EOF — after the scrub ran —
so a client can smuggle `X-User-Identity` / `X-Forwarded-For` / `X-Real-IP` upstream
as late trailers. The wrapper re-deletes them when the body reaches EOF. That fix is
correct.

Its correctness depends on `Read` actually running. Every outbound path writes the
body with `io.Copy`, which prefers `src.(io.WriterTo)` over `Read`; a wrapper
exposing a copy fast path would be drained to EOF without `Read` running once, and
the merged trailer map would reach the upstream writer unscrubbed.

**Not exploitable as shipped**: embedding `io.ReadCloser` promotes only that
interface's own method set (`Read`, `Close`), so no `WriteTo` was ever exposed.
But the property held by that language detail rather than by construction. The
wrapped body is now a **named field** with an explicit `Close`, and
`TestIdentityIngress_TrailerRescrubBodyExposesNoBypassInterface` asserts the
wrapper exposes neither `io.WriterTo`, `io.ReaderFrom`, nor `io.Seeker` even when
the body it wraps implements all three — so a later switch to a concrete embedded
body type cannot silently open the bypass. No behaviour change.

---

## What got safer in this window

Recorded so a future reviewer does not re-litigate these:

- **F6 / identity ingress (`proxy.go`) closes a real authorization defect.** Before
  this window, `handleRequest` read the identity for Stage-2 evaluation back out of
  the `X-User-Identity` *request header*, and nothing scrubbed that header at
  ingress (`scrubForwardedHeaders` runs on egress). On the identity-free postures —
  default-Exempt, scoped exempt, no-backend inert — nothing overwrote a
  client-supplied value, so a client could present `X-User-Identity: alice` and
  satisfy a `SourceIdentity: alice` access rule. The header transport is now gone
  entirely: identity travels as typed `authOutcome`/`ProxyIdentity` values, the
  header is deleted unconditionally at ingress, and the egress scrub remains as
  defense in depth. Pinned by `authz_identity_ingress_test.go`.
- **ADR-0026 single evaluator (`policy.go`) is semantics-preserving.** The scan was
  extracted to `evalAccessRules` with the identical continue-chain ordering
  (enabled → access-type → source → schedule → destination), the same per-scan
  hoists, and first-match-wins. Hit accounting and `PolicyMatch` construction stayed
  in `Evaluate`. The trace callback is nil on the enforcement path and the skip
  strings are referenced only inside `if trace != nil`. The Policy Tester now routes
  through the same core, which additionally makes it skip disabled rules — a
  fidelity *improvement* (a disabled rule could never match at runtime but the old
  simulator could report it as the match).
- **Policy Learning is advisory by construction and disabled by default.** No YAML,
  env, or CLI enablement; the singleton is nil unless an admin PUTs
  `/api/policy-learning/config`; enabling the feature does not start observation.
  Accept is admin-only inside an operator-floor route (the documented C4 divergence
  convention), requires Draft Mode armed, is fenced by a required `if_version`, and
  writes exactly one **disabled** `Allow`+`Inspect` rule into the draft candidate —
  never the running rulebase. `plTranslateRecommendation` is the only DTO→PolicyRule
  conversion and takes no field from the caller. All six new routes carry `uiRoutes`
  metadata and route-classification entries with roles matching the handlers.
- **Persistence and secrets.** The subject-pseudonym key is 32 bytes from
  `crypto/rand`, `AtomicWrite` 0600, stored separately from the aggregate document,
  never logged, and a wrong-length file is a hard error rather than a silent
  regeneration. The session store is strict-decoded (unknown fields and trailing
  data are corruption → quarantine), a newer schema forces a read-only fail-closed
  posture, and the one-active-session invariant is enforced at decode.
- **API privacy boundary.** Every response goes through explicit DTOs; subject
  tokens, the subject-key identity, aggregation cells, and `EvidenceHash` are absent
  from the wire. Reject reasons are control-char-stripped and length-bounded. The
  new GUI panel escapes every server-derived string with `escHtml` in both element
  and (double-quoted) attribute contexts.
- **Draft-commit durability.** `PolicyStore.SaveErr` and `commitActivate` close a
  real defect: a swallowed running-policy write error used to clear the draft
  anyway, leaving new policy in memory and old policy on disk, so a restart
  silently reverted a commit.

## Residual risk (accepted, not fixed here)

- **Group-string length is unbounded in learning evidence.** `MaxObservationGroups`
  bounds the group *count* at 16 per observation but not the length of each group
  name, which originates from an IdP claim. Total exposure is bounded by the
  aggregation caps (8192 cells), and the feature is disabled by default and requires
  an explicit operator-started session, so this is recorded rather than fixed.
- **`sanitizeReason` truncates on a byte boundary**, which can split a multi-byte
  rune. `json.Marshal` replaces the invalid bytes with U+FFFD, so the effect is
  cosmetic.
- **Stale enablement comments (corrected in this change).** `main.go`'s
  `initPolicyLearning` and the `CLAUDE.md` note still described the M1 "enablement
  is a constant false" posture that M5A superseded with the governed admin surface.
  Documentation drift only — the code was correct — but a composition-root comment
  asserting a feature "cannot be turned on" is the kind of thing a reviewer trusts
  instead of checking, so both were updated to describe the governed, off-by-default
  posture.
