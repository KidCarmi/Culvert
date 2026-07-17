# Adaptive Decryption Exclusion — Production Qualification

**Subsystem:** `internal/autoexclude` + `autoexclude_resolve.go` + hot-path glue (`proxy.go:resolveSSLAction`, `proxy_tunnel.go`, `proxy_tunnel_h2.go`) + admin API/UI (`ui_policy.go`, `static/index.html`) + metrics.
**Method:** Seven independent specialist reviews (Security, Performance, Concurrency, Operations, Enterprise UX, Architecture, Testing/CI), each grounded in the code, the git history (through `e48c249`), the operator doc, and — for Performance/Concurrency/Testing — real benchmark, race-detector, and coverage runs. Findings below are the converged, cross-validated result.
**Scope:** Qualification only. This document proposes; it changes no behavior.

---

## 1. Executive Summary

The Adaptive Decryption Exclusion cache is a **genuinely well-built subsystem** whose core security architecture would survive a Palo/AWS design review largely intact. Every misclassification path fails **closed** (keep inspecting); the scoped `(profileID, host)` key is a stronger isolation boundary than PAN-OS's per-firewall global cache; the feature is **provably zero-cost when unused** (measured: the fail-close gate adds ~46 ns and zero allocations, and a no-fail-open deployment never touches the cache); memory is bounded on both the active and pending maps with amortized eviction; and the concurrency design is clean under `-race` with no data races, deadlocks, or callback-under-lock. The prior six-blocker hardening pass (`e0b93f0`) already closed the sharpest edges (cert-verify exclusion, scope-by-ID, pending-map bound, provable-OFF footprint).

The subsystem is **not yet at unconditional "I trust this in production" sign-off**, and the gap is narrow and fixable. It is concentrated in three places:

1. **A promise-vs-implementation gap on the live-rescue path** (the single most important finding). The `certificate_required` origin signal rescues the *triggering* session on the **first** occurrence — confirm-count-exempt — but audit + alert fire only on **promotion**. A single client colluding with (or simply choosing) a cert-demanding origin under a fail-open rule can force the proxy to stop inspecting *every one of its own sessions* and, because one client never reaches the confirm-count, **that evasion is never audited or alerted** — only a log line. The operator doc's promise that "every host the proxy stops inspecting is alerted and audited" is therefore false for this path.

2. **The confirm-count gives near-zero protection to a deliberate attacker on the spoofable class.** For `client_pinned` (explicitly "the spoofable class"), confirm is over *distinct client-evidence tokens*, which fall back to **raw IPv4** for unauthenticated traffic. `confirmN=2` distinct IPs is trivially met. The design's headline anti-poison control protects against *accidental* self-poison, not an adversary.

3. **Operational and CI gating are underbuilt relative to the engine.** No abnormal-learning-rate (poisoning) alert; no per-scope `hit`/`active` metrics; no SIEM-queryable "bypassed due to auto-exclusion" field on the request feed; `maybeFailOpenClient` has **0% test coverage**; the benchmarks and would-be fuzz targets are wired into **no** merge or nightly gate; and there is no per-file coverage floor on a fail-open security surface.

None of these require redesigning working architecture. The load-bearing controls (fail-open gating, cert-verify exclusion, scope isolation, bounded volatile cache) are correct and should be left alone. The work is finishing the observability, hardening one evidence path, and ratcheting CI.

**Production Readiness Score: 7.5 / 10** — production-viable, with a small, well-defined set of must-fix items before a principal-engineer sign-off is unconditional.

---

## 2. Production Readiness Scorecard

| Category | Score | Evidence | Remaining gap |
|---|---:|---|---|
| **Security** | 7 / 10 | Fails closed on every misclassification; cert-verify exclusion is airtight (`errors.As` value-typed + string fallback); scope isolation proven; live-rescue re-runs SSRF guards. | Live-rescue unaudited evasion (F1); cheap spoofable poisoning (F2). |
| **Performance** | 9 / 10 | Feature-off zero-cost (measured); fail-open path 1.3–1.7 µs vs multi-hundred-µs handshake; O(1) size-independent reads; RLock read path. | Double host normalization; `evictLocked` full-map scan (hygiene only). |
| **Reliability** | 8 / 10 | `-race` clean on all runs; bounded maps; volatile/node-local; injected clock. | Brittle TLS-error-string classifier can silently go inert on a Go upgrade (F5). |
| **Operations** | 6 / 10 | Promotion fires audit + SIEM alert + metric; evict/clear audited; provable-OFF footprint. | No poisoning-rate alert (F4); node-local eviction can't remediate a cluster (F8). |
| **Observability** | 6.5 / 10 | Per-entry explainability best-in-class (reason, scope, confirm-count, TTL, hits, blast-radius); metric cardinality textbook-safe (host never a label). | Unlabeled `hit_total`/`active` (F6); no structured feed reason (F7); no learning timeline. |
| **Maintainability** | 8 / 10 | Clean engine/glue split; exemplary comments; drift guards (`allReasons`). | Classifier depends on unexported Go error strings; two scope accessors not consistency-enforced (F9). |
| **Testability** | 6.5 / 10 | Engine 91.4%; injected clock; `swapAutoExclude` isolation; audit-ring-saturation pitfall avoided; adversarial bound proof. | `maybeFailOpenClient` 0%; no race-exercised concurrency test; benches/fuzz ungated (F3). |
| **Scalability** | 9 / 10 | Read cost independent of cache size and pending size (measured at 4096); bounded cardinality everywhere. | Single RWMutex hot-host counter contention (measure-before-acting only). |
| **Supportability** | 6.5 / 10 | Strong operator doc; provable-OFF; rename-aware scope resolution + orphan badge. | Tunables are build-time-only (GUI-parity gap, F10); no cluster remediation story. |

---

## 3. Findings, ranked by severity

### F1 — Live-rescue is confirm-count-exempt AND unaudited (HIGH, security + observability)
- **Problem:** `maybeFailOpenOrigin` rescues the triggering session on the first `certificate_required` (`proxy_tunnel.go:589-593`), but `recordAutoExclude` fires audit/alert only after `Observe` returns `true` (promotion) — `autoexclude_resolve.go:222-246`. A rescued-but-not-promoted session emits only a `SSL_AUTOEXCLUDE_RESCUE` log line.
- **Risk:** A single insider client + a cert-demanding origin under a fail-open rule evades DLP on *every* session with no SIEM signal and no audit entry. The confirm-count provides zero protection here (it gates only the persistent cache future sessions read). Directly contradicts the documented observability promise.
- **Evidence:** `proxy_tunnel.go:589-593`; `autoexclude_resolve.go:222-224`; doc `decryption-auto-exclusions.md:29-30` vs `:176-182`. Cross-validated by Architecture (C1) and Security (residual #5, escalated).
- **Proposed solution:** Make the live-rescue *act itself* first-class: emit `auditEvent("decryption.autoexclude.rescue")` + `fireAlert` + a dedicated counter on every rescue, independent of promotion, with client identity/IP as actor. Optionally rate-limit rescue per `(scope, host, client)`.
- **Tradeoffs:** Marginally noisier audit/alert stream (bounded — fires only on genuine `certificate_required` under a fail-open rule). **No change to the security decision.**
- **Complexity:** Small (a few lines at one call site + one counter). Not a redesign.

### F2 — Confirm-count over raw IPv4 gives near-zero protection to the spoofable class (HIGH, security)
- **Problem:** `client_pinned` is explicitly the spoofable class, yet `clientEvidence` falls back to **raw IPv4** for unauthenticated traffic (`autoexclude_resolve.go:199-207`); `confirmN=2` (`autoexclude.go:82-88`) is trivially met with two source IPs.
- **Risk:** An attacker on a broad/unauthenticated fail-open scope can poison arbitrary same-scope hosts into a 1 h inspection blind spot by sending a cert-rejection alert from two IPs. Bounded by scope isolation, the opt-in, the 1 h TTL, and loud promotion alerting — but the code-level barrier is negligible.
- **Evidence:** `autoexclude_resolve.go:171-176, 199-207`; `autoexclude.go:69-70` (comment acknowledging spoofability). The `/24`→raw revert was a deliberate NAT-fleet tradeoff (`e0b93f0`).
- **Proposed solution (Security R1, highest leverage/lowest cost):** For `ReasonClientPinned`, count **only** authenticated-identity (`id:`) tokens toward confirmN — emit an empty token for IP-only sessions under that reason (the engine already discards `client == ""`, `autoexclude.go:242`). Unauthenticated pinned apps then require the **manual** SSL Bypass list, which is the correct posture for un-attributable traffic.
- **Tradeoffs:** Unauthenticated pinned apps no longer auto-learn — acceptable; manual bypass is the documented remedy.
- **Complexity:** Low (a reason-aware branch in `clientEvidence`/`recordAutoExclude`).

### F3 — CI does not gate the feature's benchmarks, fuzzing, concurrency, or per-file coverage (HIGH, testability)
- **Problem:** Four concrete holes: (a) `maybeFailOpenClient` is **0% covered**; (b) the single-mutex/atomic design has **no `-race`-exercised test** (only benchmarks, which `-race` skips); (c) the hot-path benchmarks lack the `//go:build benchgate` tag + `TestBenchGate_*` assertion, so no alloc/perf regression gate; (d) neither `autoexclude.go` nor `autoexclude_resolve.go` is in `coverage-floor.sh`.
- **Risk:** A regression that makes the client-leg learn on a non-pinning error, or a per-CONNECT allocation creeping into the hot path, or coverage rotting on a fail-open surface, all ship green.
- **Evidence:** measured cover (client path 0.0%, `writePrometheus` 0.0%, `_other_` overflow branch cold); `bench_regression_test.go` covers policy/tls/scrub only; `.github/scripts/coverage-floor.sh` FLOORS table.
- **Proposed solution:** R1 cover `maybeFailOpenClient`; R2 add `TestAutoExclude_ConcurrentObserveContainsEvict` (~1000 goroutines, rides the existing `go test -race ./...`); R3 tag the existing benchmarks `benchgate` + assert allocs/op ceilings (0 for FeatureUnused/FailClose); R5 add two lines to `coverage-floor.sh` (`autoexclude.go 85`, `autoexclude_resolve.go 80`).
- **Tradeoffs:** Minor floor/ceiling maintenance on legit refactors.
- **Complexity:** Low across the board (benchmarks already exist).

### F4 — No abnormal-learning-rate / poisoning alert (HIGH, operations)
- **Problem:** Promotion fires a *per-host* alert, which is exactly the wrong granularity for detecting a poisoning *campaign* — 50 promotions produce 50 alerts, none flagged anomalous.
- **Risk:** Cache poisoning — the feature's primary threat — is not detectable operationally; the signal drowns in per-host noise.
- **Evidence:** `recordAutoExclude` fires one `fireAlert` per promotion; no rate logic anywhere. The codebase already has the latched-threshold pattern in `release_alerts.go`.
- **Proposed solution:** Add a latched `decryption_autoexclude_surge` alert on learns-per-window (or `pending`/`active` crossing a threshold), fired once per crossing, on the existing alert plumbing.
- **Tradeoffs:** Needs a threshold (start with a constant, per the release-alert precedent); fire-once latching bounds false-positive noise on legitimate mass rollout.
- **Complexity:** Low–Medium.

### F5 — Learn classifier depends on unexported Go TLS/x509 error strings (MEDIUM, reliability)
- **Problem:** Learnable buckets are substring matches on Go's internal error text (`"certificate required"`, `"server selected unsupported protocol version"`, `"bad certificate"`, …) — not a stable API (`autoexclude_resolve.go:100,112,171-174`).
- **Risk:** A Go upgrade that rewords any string silently breaks *learning* for that reason. Direction is fail-safe (keeps inspecting), but it's a **silent feature regression** — pinned apps stop self-healing after a toolchain bump with no signal.
- **Evidence:** `classifyOriginInspectFailure` / `classifyClientInspectFailure`. (The do-NOT-learn bucket is robust — `errors.As` on x509 value types — but the value-generating learn paths are string-only.)
- **Proposed solution:** Add a build-tagged real-handshake canary test (a server sending `CertificateRequest`; a version-mismatch dial) asserting each learnable condition still classifies as expected — turning a silent Go-upgrade break into a red test. Prefer structured `tls.AlertError` over substrings where Go exposes it. Pair with a `FuzzClassifyInspectFailure` (nightly) asserting cert-verify-classed input never learns and the output reason stays in the bounded set.
- **Tradeoffs:** Test-only; some conditions fiddly to reproduce offline (repo has offline-harness precedent).
- **Complexity:** Small–Medium.

### F6 — `hit_total` and `active` are global/unlabeled while learns are `{reason,scope}` (MEDIUM, observability)
- **Problem:** `recordAutoExcludeHit` is a single global atomic; the self-heal read path can't be attributed per scope in metrics (`autoexclude_resolve.go:285-287`, `metrics.go:523-535`).
- **Risk:** Can't answer "which fail-open profile's bypasses carry the most traffic / hold the most active exclusions" from metrics.
- **Proposed solution:** Add a `{scope}` label to `hit_total` and `active`, reusing the existing 200-label cap + `_other_` folding (cardinality already proven safe).
- **Tradeoffs:** Slightly more (bounded) cardinality.
- **Complexity:** Low.

### F7 — No SIEM-queryable "bypassed due to auto-exclusion" on the request feed (MEDIUM, observability)
- **Problem:** The TUNNEL_CLOSED feed entry carries `SSLAction="bypass"` but no discriminator between an auto-exclusion bypass and a policy/pattern bypass; the reason lives only in a raw `logger.Printf` (`proxy.go:642`).
- **Risk:** SOC cannot filter/correlate auto-exclusion bypasses in the SIEM; forensics needs raw-log grep.
- **Proposed solution:** Add an optional `bypassReason` (omitempty) field to the feed entry, populated from `resolveSSLAction`.
- **Tradeoffs:** Minor schema addition (omitempty keeps wire compat).
- **Complexity:** Low–Medium.

### F8 — No cluster-wide eviction; DP-node caches may be unmanageable (MEDIUM, operations)
- **Problem:** Evict/clear act only on the local `autoExclude` singleton (`ui_policy.go:764,769`). On CP/DP, a poisoned entry on a DP node can't be evicted from the CP UI.
- **Risk:** An operator responding to a poisoning alert may believe they remediated when they cleared only one node.
- **Proposed solution:** Add a **transient** CP→DP evict/clear command (a control message, *not* a synced config surface — preserve volatility), OR at minimum surface per-node cache state in the panel so the operator knows eviction is node-scoped.
- **Tradeoffs:** Adds a CP→DP command path; must stay off the config-snapshot surface to preserve the never-synced invariant. **Do not sync the cache itself** — that would give one poisoned entry fleet-wide blast radius.
- **Complexity:** Medium.

### F9 — Latent-safety items: singleton pointer, scope-accessor drift, caller-gating invariant (MEDIUM–LOW, reliability/maintainability)
- **F9a (Concurrency R1):** `autoExclude` is a plain package pointer read locklessly on the hot path; race-free **today only because it is never reassigned at runtime**. If F10 (tunables via reload) or any future feature reloads the cache, the hot-path read becomes a textbook data race that unit `-race` may not catch. Convert to `atomic.Pointer[Cache]` (`Load()` on the hot path — single word read, no measurable cost). **This is a prerequisite for F10.**
- **F9b (Architecture C4):** Read scope (`FailOpenScope→ID`) and learn scope (`resolveDecryptionProfile→ID`) are two accessors; consistency is by-construction, not enforced. Route both through one helper or add a test asserting `FailOpenScope(name).ID == resolveDecryptionProfile(match).ID`.
- **F9c (Architecture invariant note):** The engine is deliberately policy-blind and trusts that its only callers are fail-open-gated. A future un-gated caller would break isolation with no compile/test failure. Add a drift test pinning the caller set (same spirit as the `uiRoutes`/C1 pattern).
- **Complexity:** Low each.

### F10 — Tunables are build-time constants (GUI-parity gap) (MEDIUM, supportability)
- **Problem:** `confirmN`, `TTL`, `PinnedTTL`, `window`, `maxEntries` are compile-time constants with no flag/API/UI (`autoexclude.go:82-88`; constructed with `Config{}`). CLAUDE.md makes GUI parity non-negotiable; this is worse than CLI-only — it's build-time-only.
- **Risk:** A customer needing `confirmN=3` in a hostile segment or a compliance-driven TTL must recompile. A production-readiness reviewer flags this immediately.
- **Proposed solution:** Expose the values as **per-profile** fields on `DecryptionProfile` (they ride the already-walled decryption-profile config surface and keep the volatile cache clean). The engine already reads them from `Config`; wiring is a resolver + a UI field. **Must be paired with F9a** (`atomic.Pointer`) since applying new tunables means rebuilding/reconfiguring the cache at runtime.
- **Tradeoffs:** More config surface + parity-test work. Raising the default pinned-class confirm (ties to F2) improves the anti-poison posture.
- **Complexity:** Medium.

### F11 — Enterprise UX workflow-at-scale gaps (MEDIUM, operations/UX)
- **Problem:** Against a 4096-entry cache the panel renders one flat, unpaginated table with **no search, no filter (by profile/reason), no sort, no export, and no pending-host list**. Per-entry evidence is a count (`client_count`), not the identities. The "Rules" blast-radius column is a dead number (the profile panel already has `openWhereUsed` to reuse).
- **Risk:** The primary admin questions — "is host X being bypassed and under which profile?", "who caused this to go dark?", "what's about to be excluded?" — are unanswerable at scale from the UI.
- **Proposed solution (all low-cost, data already present client-side):** host search + reason/scope filter + sortable Hits/Clients columns; a collapsed "Pending (N)" section (needs a small engine accessor exposing pending hosts); CSV/JSON export; make the Rules count invoke the existing `openWhereUsed`; expand-row showing the confirming evidence tokens (persist them on the entry — same node, same trust layer, bounded by the cap).
- **Tradeoffs:** Storing evidence tokens slightly grows entries (privacy-adjacent, but already in the audit ring).
- **Complexity:** Low–Medium (mostly front-end).

### F12 — Perf hygiene (LOW, do for cleanliness, not urgency)
- **F12a:** Every fail-open CONNECT IDNA-normalizes the host **twice** (once in `sslBypass.Matches`, once in `Contains→normHost`). Normalize once at dispatch and thread the canonical host into a `ContainsNorm` variant.
- **F12b:** `key()` allocates a string per read; a `struct{ScopeID, Host string}` comparable map key is zero-alloc.
- **F12c:** `evictLocked`/`evictPendingLocked` walk the *entire* map for expired entries on **every** promotion under the write Lock. Gate the scan on cap pressure (`len(active) > maxEntries`) — lazy expiry already makes reads correct without it. This is the longest lock-hold in the system and is currently unbenchmarked.
- **Risk:** All negligible vs a handshake (1–2 µs). Efficiency hygiene only.
- **Complexity:** Low–Medium. **Add the missing write-path/mixed benchmarks first (below); do not shard the cache speculatively.**

---

## 4. Engineering improvements (converged)

- Close F1 by making live-rescue first-class observability (audit + alert + counter, rescue-scoped rate limit).
- Close F2 by identity-gating the spoofable `client_pinned` evidence.
- F9a: `atomic.Pointer[Cache]` for the singleton (prerequisite for any runtime reconfiguration).
- F9b/F9c: single scope-ID helper + caller-gating drift test.
- F12c: cap-gate the eviction expired-scan.

## 5. CI improvements (converged matrix)

| Category | Command | Cadence | Blocks merge? | Rationale |
|---|---|---|---|---|
| Unit + behavior (existing) | `go test ./internal/autoexclude/ .` | Per-PR | Yes | Already in the `-race` fast gate. |
| Per-file coverage floor (F3-R5) | add `autoexclude.go 85` + `autoexclude_resolve.go 80` to `coverage-floor.sh` | Per-PR | Yes | Two-line ratchet on a fail-open surface. |
| Race concurrency test (F3-R2) | new `TestAutoExclude_ConcurrentObserveContainsEvict` under `go test -race ./...` | Per-PR | Yes | Makes `-race` actually exercise the mutex+atomic design. |
| Allocation regression (F3-R3) | tag existing benches `//go:build benchgate` + `TestBenchGate_AutoExcludeResolveAllocs` | Per-PR | Yes | Deterministic allocs/op ceilings; benchgate lane already runs on PRs. |
| Property tests (F3-R7) | `testing/quick`: confirm-count monotonicity, scope isolation ∀, `Len()≤cap` | Per-PR | Yes | Fast/deterministic; catches off-by-one the examples miss. |
| Determinism (existing) | `-count=2 -shuffle=on ./...` | Per-PR (deep gate) | Yes-if-triggered | Rewards the injected-clock discipline. |
| Classifier canary (F5) | build-tagged real-handshake test | Per-PR | Yes | Turns a silent Go-upgrade break into a red test. |
| ns/op trend | benchstat vs main | Weekly | No | Runner-sensitive; informational. |
| Fuzz classifier + normalization (F5) | `FuzzClassifyInspectFailure` + `FuzzNormHost` | Nightly | No | Coverage-guided; counterexamples become PR seeds. |
| Stress / adversarial bound (existing) | `TestResourceBounded_UnderAdversarialLoad` | Per-PR (short) + Weekly (full N) | Yes (short) | Already gated short; widen full-N weekly. |
| Chaos (clock jumps, evict-during-learn) | new test under `-race` | Nightly | No | Discovery; promote findings to PR regressions. |

**New benchmarks to add (Performance):** `ContainsHit_SpreadHosts` (isolate mutex ceiling from counter ping-pong), `Observe_SteadyState`, `Observe_Promotion` (the unmeasured longest lock-hold), `MixedReadWrite` (99% read / 1% write — the realistic contention), and a committed `-cpu=1,2,4` variant.

## 6. Performance improvements
F12a (single normalization), F12b (struct key), F12c (cap-gate the eviction scan). All hygiene — measured cost is 1–2 µs against a multi-hundred-µs handshake. Do **not** shard the cache without evidence from the new mixed/spread benchmarks.

## 7. Security improvements
F1 (audit/alert/limit the live rescue), F2 (identity-gate the spoofable class), F4 (learning-rate alert), F8 (cluster remediation without syncing the cache), F9a (atomic singleton before any reload feature).

## 8. GUI / Operations improvements
F4 (surge alert), F6 (`{scope}` on hit/active), F7 (structured feed reason), F8 (cluster evict/state), F10 (per-profile tunables in the UI), F11 (search/filter/sort/export/pending-list/evidence drill-down/blast-radius drill-down).

## 9. Documentation improvements
- Correct the operator doc's observability claim to match F1's fix (rescue is now audited/alerted), or, until fixed, explicitly document that the confirm-count-exempt live-rescue is log-only.
- Document the F2 posture change (unauthenticated pinned apps use the manual bypass list).
- Once F10 ships, document the per-profile tunables (parity mandate).
- Document the node-local eviction limitation until F8 ships.
- Fix the `autoexclude_bench_test.go:105-106` comment (hit path is under RLock + atomic, not the write mutex).

## 10. Prioritized implementation roadmap

### Must Have (before unconditional production sign-off)
1. **F1** — Audit + alert + counter on the live-rescue act (+ optional per-`(scope,host,client)` rescue rate limit). *Closes the silent-evasion gap; makes the doc's promise true.*
2. **F2** — Identity-gate `client_pinned` evidence; raise the spoofable-class confirm default. *Removes the one materially cheap poisoning vector.*
3. **F3** — Cover `maybeFailOpenClient`; add the race-exercised concurrency test; tag benchmarks into benchgate with alloc ceilings; add the two-line per-file coverage floor. *Converts good coverage into a defended ratchet on a fail-open surface.*
4. **F4** — Latched abnormal-learning-rate alert. *Makes the primary threat operationally detectable.*
5. **F5** — Real-handshake classifier canary test (+ nightly fuzz). *Prevents silent feature death on a Go upgrade.*

### Should Have
6. **F6 + F7** — Per-scope `hit`/`active` labels and a structured `bypassReason` on the request feed. *SOC can operate the fleet, not just forensically reconstruct it.*
7. **F9a** — `atomic.Pointer[Cache]` singleton. *Cheap; prerequisite for F10.*
8. **F10** — Per-profile tunables (confirmN/TTL/window/cap) with API + UI. *Satisfies the repo's GUI-parity mandate.*
9. **F11** — Panel search/filter/sort/export + pending-list + evidence/blast-radius drill-down. *Usable at 4096 entries.*
10. **New benchmarks** — write-path, promotion (the unmeasured longest lock-hold), mixed read/write, `-cpu` scaling.

### Nice to Have
11. **F8** — Transient CP→DP evict/clear command (cache stays volatile/unsynced) or per-node state in the panel.
12. **F9b / F9c** — Single scope-ID helper + caller-gating drift test.
13. **F12** — Perf hygiene (single normalization, struct key, cap-gated eviction scan). Only after the write-path benchmarks land.
14. **Property tests + chaos tests** (F3-R7 / chaos row) as standing invariant guards.

### Explicitly do NOT do (leave the working architecture alone)
- Do **not** sync the cache CP→DP or persist it — volatility/node-locality is the correct, PAN-aligned blast-radius choice.
- Do **not** broaden the learn classifier — the narrow, fail-closed set is the security keystone.
- Do **not** shard the cache or split the mutex without benchmark evidence — the single RWMutex is the right complexity for the measured load.
- Do **not** move scope keying off `profileID` — it is a stronger boundary than PAN-OS and correct for multi-tenant.
