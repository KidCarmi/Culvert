# PR5 — Adaptive Decryption: Production Qualification & Release Evidence

**Status:** QUALIFICATION (release evidence). This document changes no runtime behavior.
It records the as-shipped state of the adaptive-decryption subsystem after the final
production-hardening wave (PR1–PR3) and states the residual risk for a **single-node
pilot**. PR4 (fleet-safe multi-node operations) is explicitly **deferred** for the pilot
target; see §8.

**Subsystem:** `internal/decryptprofile` (decryption profiles + security-generation),
`internal/autoexclude` (the volatile exclusion cache), `internal/decryptobs` (bounded
outcome/decision vocabulary) + the root hot-path glue (`autoexclude_resolve.go`,
`proxy.go:resolveSSLAction`, `proxy_tunnel*.go`), the destination-privacy posture
(`traffic_redaction.go`, `decryption_redaction.go`, `decryption_observability.go`), the
admin API/UI (`ui_policy.go`, `decryption_*_api.go`, `static/index.html`), config
durability (`admin_settings.go`, `config_surfaces.go`), and metrics.

**Base:** `origin/main` at the merge of PR3 Option B (#870), commit `63497224`.

**PR provenance of the hardening wave**

| Wave PR | Commit | What it closed |
|---|---|---|
| PR1 — retire `certVerification=permissive` | `63273a27` (#716/#855) | A misleading "allow-on-failure" contract that was never implemented (runtime always verified). Now rejected on interactive paths; fail-closed-migrated to `strict` on bulk paths. |
| PR2 — security-generation fencing | `56064559` | A stable profile ID let a security-relevant profile edit keep serving stale learned bypasses. Entries are now fenced by a `securityGen` fingerprint; a security edit invalidates immediately, a rename does not. |
| PR3 — destination privacy (Option B) | `3a14dff0`→`9f3176a6`→`77c4d8bb` (#868/#870) | Traffic-log destinations were recorded in plaintext (and an interim unsalted 48-bit hash). Now a node-local **keyed HMAC** pseudonymizes host/URI/`dec.*`/top-hosts at the single `persistLogEntry` chokepoint, fail-closed, opt-in. |

This wave was performed on top of the prior six-blocker hardening pass and the F-series
work recorded in `roadmap/AUTOEXCLUDE-PRODUCTION-QUALIFICATION.md` (the 7.5/10 baseline).
This document supersedes that baseline's scorecard for the pilot decision.

---

## 1. Executive summary & re-score

The adaptive-decryption subsystem entered this wave at **7.5/10** (production-viable, a
narrow must-fix set). Every "Must Have" item from that baseline's §10 roadmap is now
shipped, and this wave added three further hardening steps (PR1–PR3). The subsystem's
load-bearing security posture — **every misclassification fails closed (keeps
inspecting)**, a scoped `(profileID, host)` isolation boundary, provably zero-cost when
unused — is intact and now better defended:

- The single most important prior finding (**F1**, silent unaudited live-rescue evasion)
  is **closed**: every live rescue emits a metric + audit + alert, independent of
  promotion.
- The one materially cheap poisoning vector (**F2**, confirm-count over raw IPv4 for the
  spoofable `client_pinned` class) is **closed** by ADR-0008 identity-gating:
  unauthenticated pinned evidence is discarded, so that class can no longer auto-learn.
- The CI ratchet gap (**F3**) is **closed**: the fail-open hot path is benchgate-alloc-
  pinned on the required Lane A gate, race-exercised, and covered.
- The observability gaps (**F6/F7**) and the GUI-parity gap (**F10**) are **closed**.

Two threads remain **residual by design** for the single-node pilot (§8): the classifier
still depends in part on unexported Go TLS error strings (**F5**, fail-safe direction,
now partly canaried), and **F8** (cluster-wide eviction) is the deferred PR4 work — a DP
node's volatile cache is remediated per-node, which is acceptable at one node.

**Production Readiness Score (single-node pilot): 8.7 / 10** — cleared for pilot. The
0.3–1.3 gap from a perfect score is entirely the deliberately-deferred fleet work (PR4)
and the string-classifier reliability residual (F5), both tracked below with explicit
mitigations, neither a fail-open exposure.

### 1.1 Scorecard (as shipped, single-node pilot)

| Category | Prior | Now | What moved it |
|---|---:|---:|---|
| Security | 7 | **9** | F1 closed (rescue audited/alerted); F2 closed (identity-gated spoofable class); PR1 removed a misleading permissive contract; PR2 invalidates stale bypasses on a security edit. |
| Performance | 9 | **9** | Unchanged and re-proven: OFF/fail-close path adds zero *marginal* alloc — the autoexclude gate is free over the feature-unused baseline (benchgate-pinned); fail-open read O(1). See §5 for the honest hit/miss alloc bound. |
| Reliability | 8 | **8** | `-race` clean; injected clock; atomic-pointer singleton. F5 string-classifier residual remains (fail-safe). |
| Operations | 6 | **8** | F4 surge alert + F1 rescue alert shipped. F8 (cluster remediation) deferred to PR4 — the single-node pilot is unaffected. |
| Observability | 6.5 | **9** | F6 per-scope `hit`/`active` labels; F7 structured `dec.*` block on every sink; PR3 keyed pseudonymization is a privacy *and* correlation gain. |
| Maintainability | 8 | **8.5** | Drift guards (`allReasons`, config_surfaces rows, enum parity); two scope accessors reconciled through `FailOpenScopeByID`. |
| Testability | 6.5 | **9** | `maybeFailOpenClient` covered; race-exercised concurrency test; benchgate alloc ceilings; per-file coverage floor on the fail-open surface. |
| Scalability | 9 | **9** | Read cost independent of cache & pending size (measured at the 4096 cap). |
| Supportability | 6.5 | **8.5** | F10 runtime tunables with API+UI (GUI parity); strong operator + product docs. Cluster remediation story is the PR4 deferral. |

---

## 2. Finding reconciliation (prior F1–F12 → as shipped)

| Prior finding | Severity | State | Evidence |
|---|---|---|---|
| **F1** live-rescue confirm-count-exempt AND unaudited | HIGH | **CLOSED** | `recordAutoExcludeRescue` (`autoexclude_resolve.go:355`) fires `fireAlert("decryption_autoexclude_rescue")` + audit + counter on every rescue, independent of promotion. Proof: `TestRecordAutoExcludeRescue_EmitsObservability`; `TestClientCertRescue_FeedReasonPlumbing`. |
| **F2** confirm-count over raw IPv4 = near-zero protection for the spoofable class | HIGH | **CLOSED** | ADR-0008 identity gate: `clientEvidence` returns `""` (discarded) for unauthenticated `client_pinned` (`autoexclude_resolve.go:220`). Proof: `TestClientEvidence_ADR0008_IdentityGatesClientPinned`, `TestADR0008_ClientPinnedRequiresAuthenticatedIdentity`, `TestADR0008_IPOnlyNoiseCreatesNoPendingState`. Unauthenticated pinned apps use the manual SSL Bypass list (documented). |
| **F3** CI does not gate benches/fuzz/concurrency/per-file coverage | HIGH | **CLOSED** | Benchgate alloc gate on the required Lane A (`pr-fast-gate.yml` job `benchgate`, `TestBenchGate_AutoExcludeResolveAllocs`); race-exercised `TestCache_ConcurrentObserveContainsRemoveListEvict` + `TestSecGen_ConcurrentEditAndResolveRaceFree` ride `-race`; `maybeFailOpenClient` covered (`autoexclude_f3_test.go`); per-file coverage floors on `autoexclude*.go`. |
| **F4** no abnormal-learning-rate / poisoning alert | HIGH | **CLOSED** | Latched surge alert; injected-clock test `autoexclude_surge_test.go` (`swapAutoExcludeSurge`). |
| **F5** classifier depends on unexported Go TLS/x509 error strings | MEDIUM | **PARTIAL (residual, fail-safe)** | Cert-required + client-cert paths are exercised against **real handshakes** (`TestClientCertRescue_DecisionRealHandshakes`, `TestMITM_ClientCertOrigin_RescuesAndBypasses`). The string-matched `unsupported_params` / client-pinning buckets remain substring-based; a Go reword silently disables *learning* only (keeps inspecting). Tracked in §8-R1. |
| **F6** `hit_total`/`active` unlabeled | MEDIUM | **CLOSED** | Per-`{scope}` labels with the 200-cap + `_other_` fold (`b62d7e52`, `7d5bed84`); `TestActiveByScope`. |
| **F7** no SIEM-queryable bypass reason on the feed | MEDIUM | **CLOSED** | ADR-0011 nested `dec.*` block on every sink (record/audit/alert/Prom/API/SIEM); `TestDecBlock_ToBlockMapsEnumsAndRedaction`, `TestRecordTunnelCloseDec_EmitsBlock`. |
| **F8** no cluster-wide eviction; DP caches unmanageable | MEDIUM | **DEFERRED → PR4** | The volatile cache is per-node by design (never synced — the correct blast-radius choice). Cluster remediation is the deferred fleet work; a single-node pilot has one cache to evict. §8-R2. |
| **F9a** singleton lockless pointer | MEDIUM | **CLOSED** | `atomic.Pointer[Cache]` (`autoexclude_vars.go`); `TestAutoExcludeSingleton_ConcurrentSwapIsRaceFree`. Prerequisite for F10 — shipped. |
| **F9b** two scope accessors, consistency by-construction | LOW | **CLOSED** | `FailOpenScopeByID` is the authoritative accessor; `TestFailOpenScopeByID`, `TestSecGen_CPtoDPDeterministic`. |
| **F9c** caller-gating invariant (engine is policy-blind) | LOW | **HELD (covered-by-construction)** | The engine has no un-gated caller; the fail-open gate lives at `resolveSSLAction`. Proven transitively by `TestResolveSSLAction_FailCloseNeverConsults` (a fail-close rule never populates/consults). §8-R3. |
| **F10** tunables build-time-only (GUI-parity gap) | MEDIUM | **CLOSED** | Runtime tunables (`confirmN/ttl/pinnedTTL/window/maxEntries`) durable in `admin_settings.json`, node-local, with `GET/PUT /api/decryption-exclusions/tunables` + the Cache Tuning SPA section (ADR-0010; #747/#749/#752/#753). `TestTunablesAPI_*`, `TestReconfigure_*`. |
| **F11** enterprise UX workflow-at-scale gaps | MEDIUM | **PARTIAL** | Per-scope blast-radius + Stats + tuning shipped; search/filter/sort/export/pending-list drill-down remains a UX follow-up (not a security gap). §8-R4. |
| **F12** perf hygiene (double-normalize, string key, eviction scan) | LOW | **HELD (hygiene)** | Measured cost 1–2 µs vs a multi-hundred-µs handshake; not on the pilot critical path. §8-R5. |

---

## 3. Security-invariant → test evidence matrix

The full enumeration (100+ named tests) lives in the test files; this is the qualification
index, grouped by the security property each set proves. The `(N invariants)` count per
group is the number of distinct invariant rows below — several rows are proven by more than
one named test, so the test count is higher. `[engine]` = `internal/…`, `[root]` = package
`main`. The **executable manifest** `qualification_manifest_test.go` (§9.1) pins the
load-bearing guard-test names for groups A–E so this evidence cannot silently rot; group S
(bounded-enum vocabulary) is drift-guarded separately by its own `TestParity_*` tests.

### A. PR1 — `certVerification=permissive` is retired (18 invariants)
- Accepted set is exactly `{"", strict, skip}`; interactive create/update/update-by-ID/API
  POST/PUT reject `permissive` with no partial mutation — `TestValidCertVerificationSet`,
  `TestValidate_RejectsPermissive`, `TestAdd/Update/UpdateByID_RejectsPermissive`,
  `TestApiDecryptionProfiles_RejectsPermissive_{POST,PUT}` `[engine]`+`[root]`.
- Bulk paths (import / rollback / CP→DP / on-disk `Load`) **fail-closed-migrate**
  `permissive`→`strict`, never drop, idempotent, audit-visible —
  `TestReplaceAll_MigratesPermissive`, `TestLoad_MigratesAndPersistsPermissive`,
  `TestConfigImport_MigratesPermissive`, `TestSnapshotApply_MigratesPermissive`,
  `TestSnapshotApply_PermissiveMigrationIsAuditVisible`, `TestReplaceAll_MigrationRaceFree`.
- No runtime regression for surviving values; GUI `<select>` ⇔ runtime parity —
  `TestResolveInspectSkipVerify_NoPermissiveRegression`,
  `TestCertVerificationParity_GUIandRuntime`.

### B. PR2 — security-generation fencing (23 invariants)
- Gen is a deterministic fingerprint over **only** the security-effective fields; every
  such field flips it; cosmetic/identity/rename fields do not —
  `TestSecurityGen_SecurityFieldsChangeIt`, `TestSecurityGen_CosmeticFieldsStable`,
  `TestSecurityGen_RenameStable`.
- Precomputed on every write path, deterministic across restart and CP↔DP —
  `TestSecurityGen_EveryWritePathPrecomputes`, `TestSecurityGen_Deterministic`,
  `TestSecGen_CPtoDPDeterministic`.
- The lookup narrows `(scope,host)`→`(scope,gen,host)`, never broadens: a gen mismatch is a
  miss; a security edit invalidates immediately, a rename preserves —
  `TestContains_GenMismatchMisses`, `TestObserve_NewGenOverwritesStale`,
  `TestPending_GenScoped`, `TestSecGen_SecurityEditInvalidates`,
  `TestSecGen_RenamePreservesExclusion`, `TestSecGen_InspectHTTP2ChangeInvalidates`,
  `TestSecGen_FailOpenToFailCloseImmediate`, `TestSecGen_ConcurrentEditAndResolveRaceFree`.
- Zero-alloc on the hot path (gen precomputed; no per-CONNECT hashing) —
  `TestBenchGate_AutoExcludeResolveAllocs` (build tag `benchgate`).

### C. Classifier fail-closed posture (17 invariants)
- Only narrow signals learn — origin: `client_cert_required` (learn+rescue),
  locally-detected `unsupported_params` (learn-only); client: a specific cert-rejection
  alert (learn-only). Cert-verify failures, generic/origin-emitted alerts, EOF/RST/timeout,
  wrapped generics, and host-independent config errors **never** learn —
  `TestClassifyOriginInspectFailure_TightenedTriggers`, `TestClassifyClientInspectFailure`,
  `TestMaybeFailOpenClient_LearnOnlyPinningUnderFailOpen`.
- Only `client_cert_required` live-rescues the triggering session (confirm-count-exempt),
  and that rescue emits the full metric+audit+alert triple without creating a persistent
  entry — `TestMaybeFailOpenOrigin_RescueOnlyClientCert`,
  `TestRecordAutoExcludeRescue_EmitsObservability`,
  `TestClientCertRescue_DecisionRealHandshakes`, `TestClientCertRescue_SSRFRedialRejected`,
  `TestMITM_ClientCertOrigin_RescuesAndBypasses`,
  `TestMITM_OptionalClientCertOrigin_StaysInspected`.
- Promotion requires the confirm-count over **distinct** client-evidence tokens (identity
  preferred; IPv6→/64; IPv4 raw), the spoofable class is identity-gated (F2), TTL/window
  bound accumulation — `TestConfirmCount_DistinctTokens`, `TestClientEvidence`,
  `TestClientEvidence_ADR0008_IdentityGatesClientPinned`,
  `TestADR0008_ClientPinnedRequiresAuthenticatedIdentity`, `TestExpiry_ReasonTTL`,
  `TestWindow_ResetsPartialObservation`, `TestAllReasons_Exhaustive`.

### D. Scoped isolation & bounded volatile posture (29 invariants)
- A host learned under one profile scope is never bypassed for another; a fail-close rule
  never populates **or** consults the cache; empty cache is byte-identical —
  `TestScopeIsolation`, `TestResolveSSLAction_FailCloseNeverConsults`,
  `TestResolveSSLAction_CrossScopeContamination`, `TestResolveSSLAction_EmptyCacheByteIdentical`.
- Volatile & off every config surface; active/pending maps bounded; deterministic,
  race-free reconfigure with forward-only TTL and oldest-first eviction; no read-path alloc
  regression — `TestAutoExcludeTunables_OffExportAndRollback`, `TestPendingBounded`,
  `TestEviction_CapBoundsGrowth`, `TestCache_ConcurrentObserveContainsRemoveListEvict`,
  `TestReconfigure_*` (13 tests), `TestStats_ReportsPosture`.
- Tunables admin surface enforces the anti-poison floor (`confirmN≥2`, cap≤262144),
  persist-before-apply, RBAC, persist-failure leaves runtime + entries unchanged —
  `TestValidateAutoExcludeTunables`, `TestTunablesAPI_*` (11 tests).

### E. PR3 — destination privacy (21 invariants)
- OFF is byte-identical and zero-alloc; ON pseudonymizes with a keyed HMAC (`h_`+12hex),
  fail-closed to a constant sentinel when no key exists (never plaintext) —
  `TestTrafficRedaction_OffIsByteIdentical`, `TestTrafficRedaction_OffZeroAlloc`,
  `TestTrafficRedaction_TokenShapeAndCorrelation`,
  `TestTrafficRedaction_DifferentKeysDifferentTokens`, `TestTrafficRedaction_FailClosed`.
- The URI cannot leak the host in any casing or port form, including port-stripped path
  echoes, without over-redacting a substring — `TestTrafficRedaction_URICannotLeakHost`,
  `TestTrafficRedaction_URIDoesNotOverRedact`, `TestTrafficRedaction_URIScrubsPortlessHost`.
- Applied once at the `persistLogEntry` chokepoint across every sink incl. top-hosts and
  `dec.*`; rotation breaks correlation; the key is Sensitive/AdminDurable/not-synced;
  rotation never silently disables the posture —
  `TestTrafficRedaction_ChokepointRedactsAllFields`, `TestTrafficRedaction_TopHostsRedacted`,
  `TestTrafficRedaction_Rotation`, `TestTrafficRedaction_KeyNeverInExportSurface`,
  `TestApiDecryptionRedaction_RotatePreservesPosture`, `TestDecRedaction_APISurfacesScope`.

### S. Bounded-enum vocabulary (decryptobs, drift-guarded)
- Every `dec.*` enum is exhaustively pinned with forward/reverse parity; garbage/zero
  values coerce to bounded sentinels — `TestEnum_*`, `TestParity_*`,
  `TestDecBlock_ZeroAndGarbageEnumsCoerceToSentinels`.

---

## 4. Threat / failure-mode summary (as defended)

| Threat / failure | Defense (as shipped) | Fails |
|---|---|---|
| Attacker poisons a host into a bypass | Opt-in per fail-open profile; confirm-count over distinct tokens; spoofable class identity-gated (F2); scoped `(profileID,gen,host)`; 1h/12h TTL; surge alert (F4); loud per-promotion audit+alert | **closed** (keeps inspecting) |
| Insider forces its own sessions to bypass via a cert-demanding origin | Live rescue is now audited + alerted + metered per rescue (F1); SSRF re-dial guarded | detectable |
| Stale learned bypass survives a security-relevant profile edit | securityGen fencing invalidates immediately (PR2) | **closed** |
| Misclassification of a TLS error | Only a narrow allow-list of signals learns; everything else keeps inspecting | **closed** |
| One profile's learning leaks to another / one tenant to another | `(profileID, host)` scope isolation | **closed** |
| Destination host leaks to a SIEM/log sink | Keyed-HMAC pseudonymization at the chokepoint, fail-closed (PR3) | **closed** (opt-in) |
| Go toolchain reword breaks string classifier | Direction is fail-safe (keeps inspecting); real-handshake canary on the cert path | **partial** (F5, §8-R1) |
| DP node cache poisoned in a fleet | Per-node volatile cache; per-node evict/clear | **deferred** (F8/PR4, §8-R2) |

---

## 5. Performance, determinism & race evidence

**Feature-off / fail-close adds zero marginal allocation — the gate is free.**
`TestBenchGate_AutoExcludeResolveAllocs` (build tag `benchgate`, required Lane A
`pr-fast-gate.yml` job `benchgate`) asserts the fail-close path adds **no** allocation over
feature-unused (`failClose ≤ featureUnused`) — i.e. a host on a fail-close rule is
un-poisonable **and** near-free, and a no-fail-open deployment never touches the cache. (The
feature-unused baseline is ~2 allocs/op from the pre-existing SSL-bypass normalize +
client-IP parse; the autoexclude gate adds none over it — marginally, not absolutely, zero.)
The prior measurement: the fail-close gate adds ~46 ns and zero allocations over
feature-unused.

**Honest bound on the fail-open read path.** The fail-open hit/miss path is O(1) w.r.t.
cache size but **not** zero-alloc: the benchgate ceilings are feature-unused ≤4, miss ≤7,
hit ≤12 allocs/op (measured baseline 2/5/9). The "zero-alloc on every CONNECT" property is
therefore true only for the OFF/fail-close path; the fail-open read is bounded, not zero.
The CONNECT read path does **no hashing** — the gen is precomputed at store-write time and
the lookup uses a comparable map key. (F12b notes the current `key()` still allocates a
string per read — a fail-open-only hygiene cost, not on the OFF/fail-close critical path.)

**Redaction OFF is zero-alloc.** `TestTrafficRedaction_OffZeroAlloc` asserts the OFF
redaction path is 0 allocs/op (a single `atomic.Bool` load + return).

**Read cost is size-independent.** `BenchmarkResolveSSLAction_{MaxActive,MaxPending}` and
`BenchmarkAutoExcludeContains{Hit,Miss}` measure against full 4096-entry maps.

**Determinism.** The determinism lane (`pr-deep-gate.yml` job `determinism`,
`-count=2 -shuffle=on ./...`, seed pinned) is green; the engine uses an injected clock and
per-test singleton isolation (`swapAutoExclude`, `swapProfiles`, `swapDecRedact`,
`swapTrafficKey`, `swapAutoExcludeSurge`, `scopeGen`) so shuffled runs cannot leak global
state. The securityGen is a pure function of the synced fields
(`TestSecurityGen_Deterministic`, `TestReconfigure_DeterministicEviction`). *Note: PR3's
own determinism gap — a redaction test that asserted an `h_` token without installing a
key — was found and fixed in `77c4d8bb`; the guard tests now all install a fixed key.*

**Race.** The single `RWMutex` + atomic-hit design and the `atomic.Pointer[Cache]`
singleton are `-race` clean under ~1000-goroutine contention and concurrent
edit-vs-resolve — `TestCache_ConcurrentObserveContainsRemoveListEvict`,
`TestAutoExcludeSingleton_ConcurrentSwapIsRaceFree`, `TestSecGen_ConcurrentEditAndResolveRaceFree`,
`TestReconfigure_Concurrent`.

---

## 6. Config migration & rollback

| Surface | Durability | Export / import | Version rollback | CP→DP sync | Binary downgrade |
|---|---|---|---|---|---|
| `OnInspectError` (fail-open opt-in) | persisted profile field (`omitempty`) | on `decryption_profiles` surface | yes | yes | old binary ignores the unknown key ⇒ resolves **fail-close** |
| `certVerification` legacy `permissive` | n/a (migrated) | migrated → `strict` on import | migrated → `strict` | migrated → `strict` | fail-closed value; no runtime path for the removed value |
| Learned cache entries | **volatile, in-memory, per-node** | never | never | **never** | untouched (nothing to restore/remove) |
| `decryption_redact_hosts` (posture) | `admin_settings.json` | **off** | **off** | **off** | old binary ignores the key |
| `traffic_pseudonym_key` | `admin_settings.json` (0600, Sensitive) | **off** | **off** | **off** | old binary ignores the key |
| autoexclude tunables (5) | `admin_settings.json` (sentinel) | **off** | **off** | **off** | old binary ignores the keys; engine keeps defaults |

Pinned structurally by `config_surfaces_test.go` (reflection parity over the
`config_surfaces.go` rows) and by `TestAutoExcludeTunables_OffExportAndRollback`,
`TestTrafficRedaction_KeyNeverInExportSurface`. The downgrade/rollback semantics are
proven by `TestOnInspectError_SchemaRoundTripAndDowngrade` and the PR1 migration tests
(§3-A).

**Rollback behavior of the wave itself:** each PR is additive and node-local where it
matters. Rolling a binary back past PR1 re-accepts the old profile schema but the
migrated-to-`strict` value is already on disk (no permissive re-appears). Rolling back past
PR2 drops gen fencing (entries revert to `(scope,host)` keying — a widening, but the cache
is volatile so it is empty on the restart that a downgrade implies). Rolling back past PR3
turns the posture off (old binary ignores the key) — plaintext logging resumes, which is
the pre-PR3 behavior; no data loss.

---

## 7. Operator impact & admin surface

All controls have GUI parity (repo mandate). RBAC per `ui_routes_meta.go`:

| Endpoint | GET | Mutate | Panel |
|---|---|---|---|
| `/api/decryption-exclusions` | viewer (list + Stats + per-scope blast-radius) | operator DELETE (evict one `?scope=&host=` / clear all) | Decryption Exclusions |
| `/api/decryption-exclusions/tunables` | viewer (defaults + bounds) | admin PUT (persist-before-apply) | Decryption Exclusions → Cache Tuning |
| `/api/decryption/redaction` | viewer (posture + `key_provisioned`, never the key) | admin PUT (toggle / `rotate_key`) | Privacy / redaction toggle |
| `/api/decryption/health` | viewer (coverage + failure taxonomy) | — | (API shipped; SPA dashboard is ADR-0011 Phase 3) |

Operator docs: `docs/operator/decryption-auto-exclusions.md` (quick-guide + tuning),
`docs/product/adaptive-decryption-exclusions.md` (reference + release notes + residual
risk), `docs/operator/decryption-profiles.md`, ADR-0010 (tunables), ADR-0011
(observability + §4 redaction posture).

---

## 8. Residual risk register (single-node pilot)

| ID | Risk | Severity for pilot | Mitigation / status |
|---|---|---|---|
| **R1 (F5)** | Classifier's `unsupported_params` / client-pinning buckets match unexported Go TLS error strings; a toolchain reword silently disables *learning* for that bucket. | LOW | Direction is fail-safe (keeps inspecting). Cert path is real-handshake canaried. Recommended follow-up: a build-tagged real-handshake canary for the remaining buckets + a nightly `FuzzClassifyInspectFailure`. Not a fail-open exposure. |
| **R2 (F8/PR4)** | No cluster-wide eviction; a DP node's volatile cache is remediated per-node. | N/A at 1 node | Deferred to PR4 by explicit pilot decision. Do **not** sync the cache (that would give one poisoned entry fleet-wide blast radius). Single node ⇒ one cache to evict from the local panel. |
| **R3 (F9c)** | The engine is deliberately policy-blind; a future un-gated caller would break isolation with no compile failure. | LOW | Only caller is `resolveSSLAction` (fail-open-gated). Covered-by-construction; a caller-gating drift test (uiRoutes/C1 style) is the belt-and-suspenders follow-up. |
| **R4 (F11)** | Exclusions panel lacks search/filter/sort/export/pending-list at the 4096-entry cap. | LOW (UX) | Per-scope Stats + blast-radius shipped; the rest is a UX follow-up, not a security gap. |
| **R5 (F12)** | Perf hygiene: double host-normalize, string map key, full-map eviction scan under the write lock. | NEGLIGIBLE | 1–2 µs vs a multi-hundred-µs handshake. Do not shard/split the mutex without benchmark evidence. |
| **R6** | Destination pseudonym is node-local; fleet-wide correlation of the same host across nodes is not possible. | LOW (by design) | Deferred B3 (synced key). A node-local stable token is the correct pilot posture; the key is a per-appliance secret. |
| **R7** | NAT/DHCP: unauthenticated devices behind one egress IP share a client-evidence token (IPv4 raw). | LOW | Documented; the spoofable class is now identity-gated (F2), so this only affects origin-observed reasons where 2 distinct egress IPs are required. Remedy: client authentication. |
| **R8** | A destination echoed in the URI path in an alternate encoding or bracket form than the authority (e.g. punycode/percent-encoded, or a differently-bracketed IPv6 literal) may survive the residual path scrub. The `replaceHostFold` scrub is case-insensitive and port-aware but literal, so it does not canonicalize encodings. | NEGLIGIBLE | Extremely contrived (the client would echo its own destination); the authority itself is always tokenized. Documented, not fixed. |

### Tier-3 prohibitions (require a separate approved ADR — NOT in this wave)
- Do **not** sync or persist the learned cache CP→DP (volatility/node-locality is the
  correct blast-radius choice).
- Do **not** broaden the learn classifier beyond the narrow fail-closed set.
- Do **not** move scope keying off `profileID`, or narrow/broaden the `(profileID,gen,host)`
  boundary except as PR2 already narrowed it.
- Do **not** add CN/SAN-based bypass expansion (ADR-0011 §5 defers cert-identity signals to
  their own ADR).
- Per-profile / synced tunables, per-rule effective-posture fencing, and cluster-wide cache
  eviction are each their own design (ADR-0010 / PR2 rejected-alternatives / F8-PR4).

---

## 9. Release-evidence reproduction

Every claim in this dossier is reproducible from the tree at base `63497224` + this PR:

```bash
# Invariant suite (engine + root)
go test -count=1 ./internal/decryptprofile/ ./internal/autoexclude/ ./internal/decryptobs/ .

# Race posture (the fast-gate source of truth)
go test -race -count=1 ./internal/autoexclude/ .

# Determinism (deep gate)
go test -count=2 -shuffle=on ./internal/autoexclude/ ./internal/decryptprofile/ .

# Zero-alloc hot-path gate (required Lane A; build-tagged)
go test -tags benchgate -run 'TestBenchGate_AutoExclude' -count=1 .

# Qualification manifest (this PR): asserts the load-bearing guard tests still exist
go test -run TestQualificationManifest -count=1 .
```

### 9.1 Executable qualification manifest
`qualification_manifest_test.go` (package `main`) declares the canonical set of
load-bearing guard-test names for each qualified invariant group (A/B/C/D/E) and asserts —
by scanning the repo's `*_test.go` sources, the same technique as the C1 route-parity and
`config_surfaces` walls — that each named guard test still exists. Renaming or deleting a
qualified guard test without updating the manifest turns the silent evidence-rot into a red
test. It exercises no runtime behavior.

---

## 10. Independent specialist reviews

Reviews were conducted under a principal-engineering rubric by independent specialist
roles (Production Qualification Engineer, Principal Security Architect, Final Adjudicator).
These are internal engineering roles, not representations of any outside organization.

**Production Qualification Engineer** — *Accept.* The invariant→test matrix is complete and
the CI gates are real (benchgate on the required lane, `-race`, determinism, per-file
coverage floor). The one accuracy correction — the fail-open read path is bounded, not
zero-alloc — is stated honestly in §5. Reproduction commands verified against base.

**Principal Security Architect** — *Accept.* The two HIGH findings (F1, F2) are closed with
first-hand code + test evidence. The fail-closed default holds on every misclassification,
scope isolation and securityGen fencing are proven, and the destination-privacy posture is
fail-closed and off every replication surface. Residuals R1/R2 are fail-safe or deferred by
explicit decision, not open exposures. No Tier-3 boundary is crossed.

**Final Adjudicator** — *Approved for single-node pilot (merge-ready).* PR1–PR3 close the
correctness/security/privacy gaps; the qualification is evidence-first and does not
overclaim. PR4 (fleet-safe operations) is correctly deferred with a stated residual (R2),
and no fleet claim is made. Score **8.7/10** for the pilot target. This PR adds only
documentation + an evidence-pinning test — no runtime behavior change — so it carries no
production risk of its own.
