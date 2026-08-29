# MCP Shadow → Canary — Full Shadow Exit Review

**Status:** SHADOW EXIT REVIEW PASSED — CANARY ARCHITECTURE MAY BEGIN
**Date:** 2026-08-29
**Authority:** `docs/design/mcp/SHADOW-ARCHITECTURE.md` §12 (exit criteria), §10 (PREREQ-MCP-KILL-1).

> **What this line does and does not mean.** "Shadow Exit Review PASSED — Canary architecture
> may begin" authorizes the *design and construction* of a Canary phase. It does **not** mean
> the system is READY FOR CANARY, and it does **not** authorize activating any live-capable
> mode. Execution posture stays **CLOSED**: no production `LiveExecutor` is composed, the arming
> hooks (`markGatewayExecDepsReady`, Canary/Production enable) remain uncalled, no
> `live_execution` `ToolApproval` is issued, and the AST/type-graph posture walls stay green.

## 1. Scope of this review

This is the **complete** Shadow → Canary exit review over all thirteen §12 criteria, superseding
the earlier partial reviews by aggregating their evidence and adding the final one:

- **Shadow soak** (`docs/operator/mcp-shadow-soak-report.md`) established criteria **1, 2, 3, 5,
  10, 11** end-to-end on the real Shadow node.
- **Shadow Exit Gap Closure, Phase A** (`docs/operator/mcp-shadow-exit-gap-closure-report.md`,
  PR #1247) closed criteria **4, 6, 7, 8, 9, 12** with driven runtime + mutation proofs.
- **This phase** closes the last one — criterion **13 / `PREREQ-MCP-KILL-1`** — the emergency-kill
  side-effect-boundary revalidation, a HARD Canary prerequisite and a real product-security change.

All thirteen now pass. The matrix below was re-run in full for this review (§4).

## 2. The thirteen criteria

| # | Criterion (§12) | Result | Closing evidence |
|---|---|---|---|
| 1 | ≥ N Shadow evaluations covering the tool set and each policy branch | **PASS** | Soak: 7,516 heavy / 248 default; every tool × policy branch + hard-control (`TestShadowSoak`) |
| 2 | Zero real side effects (`up.calls == 0` + evidence audit) | **PASS** | Independent upstream witness = 0 at every phase; evaluations == committed events (`TestShadowSoak`, `TestFirstControlledShadowRun`) |
| 3 | Zero evidence gaps (every evaluation has a durable record) | **PASS** | 7,516 == 7,516; 248 == 248 (`TestShadowSoak`, `TestShadowSoakEvidenceStress`) |
| 4 | Zero stale-decision `WOULD_EXECUTE` — staleness lands as `WOULD_FAIL_STALE_*` | **PASS** | `TestShadowExitC4_BoundaryDriftYieldsStale` (root) + `TestExitGapC4_BoundaryDriftYieldsStaleNotExecute` (execution) |
| 5 | No unauthorized `WOULD_EXECUTE` (each maps to an allow-class decision) | **PASS** | Soak per-request oracle; `TestFirstControlledShadowRun` |
| 6 | Denial parity — Shadow does not alter the Observe denial decision for the same traffic | **PASS** | `TestShadowExitC6_ObserveShadowDenialParity` (root) + `TestExitGapC6_ShadowNeverSoftensADenial` (execution) |
| 7 | Stable latency — Shadow-evaluation overhead within a defined budget; no admission saturation | **PASS** | `TestShadowExitC7_LatencyBudget` + `TestShadowExitC7_RegressionGateIsNotBypassable` (root) |
| 8 | Credential-planning reliability — readiness derivable without materialization | **PASS** | `TestShadowExitC8_CredentialPlanningPath` (root) + `TestExitGapC8_CredentialReadinessFromPlanAlone` / `TestExitGapC8_MaterializeStructurallyUnreachableEvenWhenSupplied` (execution) |
| 9 | Kill-switch drills — kill honored fail-closed **before** Shadow evaluation (Invariant A) | **PASS** | `TestShadowExitC9_KillHonoredBeforeEvaluation` (root) + `TestExitGapC9_KillShortCircuitsBeforeEvaluation` (execution); soak 608/608 emergency-blocked, upstream 0 |
| 10 | Restart drills — durable evidence survives; no execution replay | **PASS** | `TestShadowSoakRestart` (mode, scope, tool-trust, catalog, spool recover; LiveExecutor absent; upstream 0) |
| 11 | Observability verified — all series emit; health three-state correct | **PASS** | Soak metrics-delta assertions; `TestFirstControlledShadowRun` `/metrics` 1:1 parse |
| 12 | Operator procedure — the runbook driven end-to-end through the real admin API | **PASS** | `TestShadowExitC12_OperatorRunbookEndToEnd` (root) |
| 13 | **`PREREQ-MCP-KILL-1` CLOSED** — kill revalidated at the irreversible boundary | **PASS** | `TestCanaryPrerequisite_KillStateRevalidatedAtSideEffectBoundary`, `TestKillBoundary_RaceMatrix`, `TestKillBoundary_KillBetweenResolveAndExecute`, `TestKillBoundary_NoCredentialReasonMapping` (all execution, all under `-race`) + 10-defect mutation campaign |

## 3. Criterion 13 in detail — the emergency-kill side-effect boundary

**Invariant.** If an emergency kill is observed or its authoritative generation changes before the
irreversible upstream side effect, the request MUST NOT cross `Upstream.Call`. Proven for a kill
engaged before admission, after admission, during the durable commit window, during credential
planning, during materialization, and inside the final tool-freshness check — every case yields
`up.calls == 0`, `Executed == false`, reason `rollout_emergency_active`.

**The one authoritative boundary.** The check lives in `run.go` `callUpstream`, the single
irreversible boundary shared by the credential and no-credential paths. Sequence: previous gates →
final tool-freshness revalidation (`ToolStillCurrent`) → FINAL authoritative kill-state
revalidation → `Upstream.Call`. Nothing runs between the final kill check and the call.

**Model B (monotonic epoch), not a boolean.** `rollout.State` carries `killGen atomic.Uint64`,
incremented once per false→true engage transition (never on clear), read lock-free via
`State.KillGeneration()`. `Executor.Execute` captures `admKillGen` at admission; the boundary
aborts when `KillGeneration() != admKillGen`. This subsumes the current-killed case AND the
engage→clear (ABA) case a boolean re-read would miss. The re-read touches only the kill
generation — it does not re-resolve mode/scope/policy/approval, so F7 single-resolution is
preserved and the outcome can only become more restrictive.

**Reason mapping on both branches.** The package-private sentinel `errKilledAtBoundary`
(`ReasonOf == ReasonNone`) is reclassified to `ReasonRolloutEmergencyActive` on the no-credential
path (sentinel escapes `CommitThenAct`) and on the credential path (sentinel absorbed by
`materializeAndCall`, reclassified ahead of the drift reason — an emergency stop is paramount). No
branch returns `ReasonNone` or a transport/durability fault for a kill refusal.

**Honest credential-path note (§8 of the brief).** A kill engaged after admission does NOT unwind
credential Plan/Materialize work already in flight — provider `Fetch`/materialization can
complete — but the boundary refusal still guarantees `Upstream.Call == 0`. The invariant is "no
irreversible upstream side effect", not "no pre-boundary work occurred".

**Telemetry truth (§9).** `Executed` stays false and the outcome is metered as an emergency block,
never a fabricated upstream outcome — operators can distinguish "policy permitted / execution
aborted by emergency kill" from "upstream execution occurred".

**Race matrix (§7).** `TestKillBoundary_RaceMatrix` drives ten windows deterministically with
channels/barriers (no sleeps for security ordering): kill before Execute; after admission; during
commit (concurrent); during Plan (concurrent, credential); during materialization (genuine
provider `Fetch` hook); from inside `ToolStillCurrent` (credential); tool drift without kill (stale
preserved); drift + kill (fail-closed); engage→clear ABA (Model B proof); 24 concurrent + one kill
(all refuse, upstream 0, no corruption). Plus the Resolve→Execute-window test and the
no-credential reason-mapping test. Run repeatedly under `-race`.

**Mutation campaign (§10).** Ten defects were each mechanically re-introduced into the production
source and confirmed to FAIL a named guard (mapping recorded at the head of
`internal/mcp/execution/kill_boundary_race_test.go`): remove the final kill re-read; move it
before `ToolStillCurrent`; drop the credential-path reclassification; drop the no-credential-path
reclassification; map the kill to `ReasonNone`; detect the kill but still call upstream; weaken the
admission kill check; break the monotonic generation (ABA regression); re-resolve rollout (F7
violation); report `Executed=true` after a boundary kill.

## 4. Re-run of the complete matrix (2026-08-29)

Root package (`package main`):

```
--- PASS: TestFirstControlledShadowRun
--- PASS: TestShadowExitC4_BoundaryDriftYieldsStale
--- PASS: TestShadowExitC6_ObserveShadowDenialParity
--- PASS: TestShadowExitC7_LatencyBudget
--- PASS: TestShadowExitC7_RegressionGateIsNotBypassable
--- PASS: TestShadowExitC8_CredentialPlanningPath
--- PASS: TestShadowExitC9_KillHonoredBeforeEvaluation
--- PASS: TestShadowExitC12_OperatorRunbookEndToEnd
--- PASS: TestShadowSoak
--- PASS: TestShadowSoakRestart
--- PASS: TestShadowSoakEvidenceStress
--- PASS: TestShadowSoakEvidencePersistedCorruptionFailsClosed
--- PASS: TestShadowSoakEvidenceCommitFailsClosed
--- PASS: TestShadowSoakMutationCampaign
```

Execution package (`internal/mcp/execution`):

```
--- PASS: TestCanaryPrerequisite_KillStateRevalidatedAtSideEffectBoundary
--- PASS: TestKillBoundary_RaceMatrix
--- PASS: TestKillBoundary_NoCredentialReasonMapping
--- PASS: TestKillBoundary_KillBetweenResolveAndExecute
--- PASS: TestKillBoundary_CleanRequestStillExecutes
--- PASS: TestExitGapC4_BoundaryDriftYieldsStaleNotExecute
--- PASS: TestExitGapC6_ShadowNeverSoftensADenial
--- PASS: TestExitGapC8_CredentialReadinessFromPlanAlone
--- PASS: TestExitGapC8_MaterializeStructurallyUnreachableEvenWhenSupplied
--- PASS: TestExitGapC9_KillShortCircuitsBeforeEvaluation
```

Full package suites (`go test ./internal/mcp/...`) pass, including `-shuffle=on -count=2` and
`-race` across all 39 MCP packages; the boundary race tests were run repeatedly under `-race`.

## 5. Red-team review (§14)

| Attack | Finding |
|---|---|
| TOCTOU: final check vs. call | No blocking/business logic between the kill check and `Upstream.Call`; both read the same lock-free generation. No gap. |
| engage→clear ABA | Caught by Model B (generation advanced); `9_engage_clear_aba` proves `Killed()==false` at the boundary yet the call is refused. |
| stale vs. kill precedence | Drift is checked first (its reason wins when both fire); kill is checked before `Upstream.Call`. Both are fail-closed refusals; neither executes. `8_drift_and_kill` pins it. |
| broker callback error swallowing | The credential branch reclassifies the absorbed sentinel to `rollout_emergency_active` (ahead of drift), so a kill never reads as `ReasonNone`/transport/durability. `TestKillBoundary_*` credential subtests. |
| kill during materialization | Genuine provider `Fetch` hook engages the kill mid-materialization; boundary refuses, upstream 0. `5_kill_during_materialization_credential`. |
| kill concurrent with many requests | 24 goroutines rendezvous on the kill; all refuse, no corruption/duplicate/deadlock. `10_many_concurrent_with_kill`, `-race`. |
| kill concurrent with scope/config update | The boundary reads only the kill generation and never re-resolves, so a concurrent scope change cannot widen the decision (F7); `TestExecute_CarriesModeScopeResolutionWithoutReResolving` pins non-re-resolution. |
| metrics/evidence lying about execution | `Executed=false`, emergency-block metric, no fabricated upstream outcome event. |
| kill-state restart/recovery | `killGen` is process-local and monotonic within a process; a restart resets both admission capture and generation together, so no false negative survives a restart (soak restart drill: upstream 0, LiveExecutor absent). |

No product defects were found; no code was weakened to keep a PASS.

## 6. Conclusion

All thirteen §12 Shadow Exit criteria pass, `PREREQ-MCP-KILL-1` is CLOSED in the design doc
(`SHADOW-ARCHITECTURE.md` §10/§12) and the technical-debt register, and the emergency-kill
side-effect-boundary invariant is proven by a permanent non-vacuous gate, a deterministic race
matrix under `-race`, and a ten-defect mutation campaign. Execution posture remains CLOSED.

**SHADOW EXIT REVIEW PASSED — CANARY ARCHITECTURE MAY BEGIN**
