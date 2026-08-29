# MCP Shadow — Controlled Soak & Exit Evidence

**Status:** SHADOW SOAK PASSED — READY FOR SHADOW EXIT REVIEW
**Scope:** Shadow mode only. NOT Canary. NOT live execution. NOT a readiness‑architecture phase.
**Baseline:** `origin/main` @ `75c668d7acb5dfdb9b1d783b8ee0f3439319226c` (HEAD == origin/main at branch creation).
**Branch:** `claude/mcp-shadow-soak`.
**Harness:** `shadow_soak_test.go` (new, package `main`) + robustness fixes to the shared readers in `shadow_controlled_run_test.go`.

This report is sanitized: it carries no secrets, no private keys, no tenant/subject/tool identifiers beyond the synthetic soak topology, and no raw error text that embeds a path or endpoint.

---

## 0. What was proven, in one paragraph

The **real** Shadow node — real HTTP/2 TLS + OAuth listener, real registry/catalog, real Tool‑Trust → `catalog.Usable` projection, real MCP policy engine, real non‑executing `*execution.ShadowEvaluator`, real durable schema‑v2 event spool, real rollout state machine and kill switch — was activated for a bounded, enumerable scope and driven with **7,516 Shadow evaluations** in the heavy run (248 in the CI‑default run), across concurrency, policy churn, catalog rediscovery, a genuine runtime fingerprint rug‑pull, tool‑trust churn/expiry, a kill‑switch drill under load, a process‑restart drill, and a durable‑evidence stress to ~20,000 records across segment rotation. Every hard soak invariant held at every volume: **0 upstream invocations, 0 credential materializations, 0 live executions, 0 out‑of‑scope evaluations, 0 response↔durable mismatches, 0 missing durable records, 0 unexpected execution capability.** The live‑execution readiness tier was never armed. Three harness robustness defects were found and fixed in‑branch; **zero product defects** surfaced — in every case the product behaved correctly (it fails closed).

---

## 1. Scope boundary (honored)

The soak **did not** and **cannot**: enable Canary/Production; compose a `LiveExecutor` or any `UpstreamCaller` into Shadow; enable credential `Materialize`; issue a `live_execution` approval; perform a real MCP side effect; use customer traffic; or weaken preflight / fingerprint binding / policy / durable evidence / auth / TLS. The `ShadowConfig` type structurally cannot carry an upstream caller or a materialize‑capable broker (Layer B, `mcp_shadow_startup.go`), and `markGatewayExecDepsReady` has no production caller (execution‑posture wall). Shadow was exercised; live execution was not.

A dedicated **auxiliary upstream witness** independently counts real upstream reach: each MCP server in the topology is a live HTTPS endpoint incrementing a shared atomic on any hit. Every phase asserts that counter's delta is **exactly 0** — i.e. side‑effect‑freedom is proven by an independent observer, not merely by the response field `executed=false`.

---

## 2. Core soak invariants — HARD gates (all 0)

| Invariant | Requirement | CI‑default (248 evals) | Heavy (7,516 evals) |
|---|---|---|---|
| Shadow upstream invocations | 0 | **0** | **0** |
| Credential materializations | 0 (readiness always `not_evaluated`) | **0** | **0** |
| Live executions | 0 (live tier never armed) | **0** | **0** |
| Out‑of‑scope Shadow evaluations | 0 | **0** | **0** |
| Response ↔ durable evidence mismatches | 0 | **0** | **0** |
| Missing durable Shadow evidence | 0 (evals == committed events) | **0** (248==248) | **0** (7516==7516) |
| Unexpected execution capability | 0 | **0** | **0** |

Any non‑zero value is a STOP+rollback+FAILED condition. None occurred.

---

## 3. Topology (§4)

Composed through the real production startup seam (`composeShadowNode` → the real observe+shadow wiring), then Observe→Shadow activated through the genuine preflight (`evaluateShadowActivationPreflight`, incl. the usable‑tool precondition):

- **4 principals:** `soakP1`, `soakP2`, `soakP3` (in‑scope) + a controlled test principal; **1 out‑of‑scope** principal (`outsiderSub`, deliberately absent from the scope).
- **2 servers:** `controlled-test-server` (SPIFFE‑pinned) and `rugpull-server` (independent witness endpoint, used for the fingerprint rug‑pull).
- **5 tools:** `echo` (allow), `danger` (deny), `approvetool` (REQUIRE_APPROVAL), `confirmtool` (REQUIRE_CONFIRMATION), `rug` (rug‑pull subject).
- **≥2 policy classes:** allow, deny, require‑approval, require‑confirmation — 4 distinct MCP policy actions plus hard‑control override.
- **Real HTTP/2 connection reuse** (a single mTLS client is reused across a session's calls) and **real concurrency** (up to 20 in‑scope workers).

Scope is bounded and enumerable (`soakScope`): capability Gateway, the two named servers, the in‑scope principal set, write risk‑class, high‑risk. The outsider is not in it.

---

## 4. Outcome coverage (§5) — 5 of 8 driven, 3 documented (never fabricated)

| # | ShadowOutcome | Driven through the REAL Gateway? | Notes |
|---|---|---|---|
| 1 | `would_execute` | ✅ yes | echo, allow‑class policy on a Usable tool |
| 2 | `would_block` | ✅ yes | danger, deny‑class policy |
| 3 | `would_require_approval` | ✅ yes | approvetool, REQUIRE_APPROVAL |
| 4 | `would_require_confirmation` | ✅ yes | confirmtool, REQUIRE_CONFIRMATION |
| 5 | `would_fail_hard_control` | ✅ yes | tool revoked / quarantined / expired → below Usable, policy hard override |
| 6 | `would_fail_credential_readiness` | ⛔ structurally unreachable | No credential planner/broker is composed in this build (Layer B), so credential readiness is honestly reported `not_evaluated`, never a *failure*. Cannot be produced without composing a broker — which the scope boundary prohibits. |
| 7 | `would_fail_inspection` | ⛔ structurally unreachable via the live pipeline | An inspection `HardFail` is terminally BLOCKED by the runtime *before* the executor is reached (`dispatchPolicy`, "degrade toward Block"), so the evaluator never records a `shadow_evaluated` event for it. Tracked as **SHADOW‑EVIDENCE‑ROUTING‑1** (provider‑level contract, pinned by the differential test). Fabricating it would misrepresent the live path. |
| 8 | `would_fail_stale_decision` | ⛔ not reachable as an *initial* drift | An initial (pre‑dispatch) tool drift is refused by the OVN‑09 guard *before* the executor; boundary‑drift `WOULD_FAIL_STALE_DECISION` is only reachable via a race at the `ToolStillCurrent` re‑check (SHADOW‑EVIDENCE‑ROUTING‑1). Not deterministically drivable from the request path; not fabricated. |

All 5 reachable outcomes are asserted with the **full contract**: `shadow_evaluated`/`executed=false`, matching durable outcome, digest verifies, event validates, `materialization_ready`/`response_inspection` = `not_evaluated`, correct governing `PolicyRevision`, exact metric bucket delta, and upstream delta 0.

**Observation (not a defect):** a catalog *SemanticDrift* (added property) faithfully classifies to `ReviewRequired`, which the policy engine does **not** hard‑override, so under an ALLOW policy the request still predicts `would_execute`. That is a *faithful* Shadow prediction, not a bug. The rug‑pull test therefore uses a *destination broadening* (PrivilegeExpansion → **Quarantined**) to prove the stale‑approval‑does‑not‑govern property, which the policy engine *does* hard‑override.

---

## 5. Bounded soak counts (§6) — deterministic, request‑count driven

The harness is **request‑count** driven, never wall‑clock, and has two modes:

- **CI default:** small deterministic counts (176 stable requests → 248 total evaluations). Runs in seconds. There is **no permanently‑30‑minute default test.**
- **Heavy soak:** `CULVERT_MCP_SOAK=<n>` scales every phase deterministically. The user‑facing target band is **5,000–20,000**; verified at 6,000 (7,516 evaluations) and 8,000, plus the evidence‑stress spool at 19,999 records.

The count is sized by a coverage argument (every tool × every policy branch, plus churn/rug/kill/restart), not a round number.

### Latency (§16 — informational only, NOT an SLA)

| Run | n | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| CI default | 176 | 20.3 ms | 25.0 ms | 28.0 ms | 29.1 ms |
| Heavy (6000) | 6,600 | 19.5 ms | 24.7 ms | 27.3 ms | 49.6 ms |

Latency is dominated by the real TLS+OAuth handshake per session and the synchronous durable evidence commit (evidence‑before‑report). No admission saturation observed. **No performance SLA is asserted or implied by this phase.**

### Outcome distribution (§17 — every bucket explainable)

Heavy (6000) — total 7,516: `would_execute` 3,159 (42%), `would_block` 1,950 (25%), `would_require_approval` 1,201 (15%), `would_require_confirmation` 1,203 (16%), `would_fail_hard_control` 3 (0%), other 0, plus 608 `evaluation_errors` (all from the kill‑switch drill — see §7). Every non‑zero bucket maps to a deliberate phase; there is no unexplained bucket.

---

## 6. Per‑section results (§7–§21)

| § | Property | Result |
|---|---|---|
| 7 | **Concurrency** — `-race`, `-shuffle=on`, `-count=2`; no data races, no outcome cross‑contamination | ✅ PASS (default + heavy‑under‑race at 3,000) |
| 8 | **Policy churn** — publish rev N, traffic, N+1, traffic; each event stamps its governing revision; restrictive never `would_execute`; ALLOW→DENY and DENY→ALLOW; concurrent churn under traffic with no revision mixing | ✅ PASS (1,063 flipped revisions under concurrent traffic; every committed event's `(revision, outcome)` self‑consistent) |
| 9/10 | **Catalog rediscovery + REAL runtime F1→F2 fingerprint rug‑pull** — identical/narrowing/privilege‑expansion; approval(F1) does not govern F2; F2 not Usable under F1 approval; no `would_execute` under old trust; reconcile never auto‑reapproves | ✅ PASS (fingerprint `a9e2165c0958`→`73c901acc45f`, **Quarantined**, stale F1 approval does **not** govern, reconcile did **not** re‑promote, fresh request = `would_fail_hard_control`; explicit F2 approval recovers) |
| 11 | **Tool‑trust churn** — approve/revoke/reapprove/expire under traffic | ✅ PASS (short‑lived approval → Usable → clock+1h + reconcile → Expired+demoted → `would_fail_hard_control` → reapprove is a NEW durable decision → `would_require_confirmation`) |
| 12 | **Kill switch under load** — engaged kill emergency‑blocks every concurrent request; none `would_execute`; upstream 0; one `evaluation_error` per blocked request; clearing restores `would_execute` | ✅ PASS (608 concurrent requests during kill, ALL `rollout_emergency_active`, +608 `evaluation_errors`, upstream 0, deterministic recovery) |
| 13 | **Restart during soak** against the same durable data directory | ✅ PASS (mode, active Shadow scope, tool‑trust, catalog Usable, and the durable spool — exact count + a specific event id + valid digest chain — all recover; LiveExecutor stays absent; upstream 0; resumed traffic still `shadow_evaluated`) |
| 14 | **Durable evidence stress** — write/read/recover/re‑read; `events_written == events_recovered == events_reread`; no loss/dup/corruption; crosses segment rotation | ✅ PASS (150 default, up to 19,999 heavy, crossing ~hundreds of rotations; recover reports `Corrupt=false`, exact record count) |
| 15 | **Metrics correctness** — exact expected bucket deltas for deterministic cases, not "> 0" | ✅ PASS (every `assertOutcome` asserts a full `shadowMetricsView` delta; the metric singleton is a process‑global accumulator, so the harness compares **deltas** captured per run against the per‑run durable spool) |
| 18 | **Scope containment** — 0 out‑of‑scope evaluations | ✅ PASS (out‑of‑scope principal is never `shadow_evaluated`; `shadow_outcome` absent) |
| 19 | **Failure injection (fail‑closed)** — real durable‑write fault at the real seam | ✅ PASS (`Manager.CommitThenAct` with an injected `AppendSync` fault returns an error, the "act" continuation NEVER runs, 0 events committed — the exact chokepoint the evaluator sits on) |
| 20 | **No hidden auto‑repair** — corrupt evidence not repaired; unknown schema fails closed; tampered event fails digest; stale not retargeted; changed tool not auto‑reapproved | ✅ PASS (schema v3 fails closed; a tampered event fails `VerifyDigest` and is never repaired; the original still verifies) |
| 21 | **Security mutation campaign** — 12 hostile mutations, each must fail a named gate | ✅ PASS (12/12, upstream 0 — see below) |

### §21 mutation campaign (12/12)

| ID | Hostile mutation | Named gate that catches it |
|---|---|---|
| M1 | Allow an upstream call from Shadow | auxiliary upstream witness = 0 + live‑exec tier never armed |
| M2 | Allow a Materialize call | `MaterializationReadiness == not_evaluated` (no broker composed) |
| M3 | Let an out‑of‑scope principal enter Shadow | scope containment (`execution_state != shadow_evaluated`) |
| M4 | Drop durable evidence for one response | durable‑commit fail‑closed (`CommitThenAct` errors, act not run) |
| M5 | Mismatch response vs durable outcome | response↔durable parity (single evidence source) |
| M6 | Keep F1 approval governing after F2 change | rug‑pull: PrivilegeExpansion Quarantines; stale approval does not govern; no re‑promote |
| M7 | Ignore a revoke | revoke honored immediately (`would_fail_hard_control`) |
| M8 | Ignore the kill switch | engaged kill emergency‑blocks (`rollout_emergency_active`) |
| M9 | Re‑arm live‑exec readiness during restart | live‑exec tier stays unarmed (posture wall) |
| M10 | Mix policy rev N and N+1 | atomic snapshot; event carries exactly its governing revision; restrictive never `would_execute` |
| M11 | Recover a malformed/tampered v2 event permissively | unknown schema fails closed; tampered event fails digest |
| M12 | Let an expired approval remain governing | expiry demotes; fresh request `would_fail_hard_control` |

---

## 7. Findings (§23) — 3 harness robustness defects, 0 product defects

All findings are recorded here in the open (not hidden in the harness). **Every one is a test‑harness defect surfaced by the heavy soak; in each case the product behaved correctly (it fails closed).** No product code was weakened to keep a PASS.

### F‑H1 — evidence readers only saw the first page of a paginated cursor (test bug)
- **Symptom:** at high volume, `assertOutcome` failed with `durable outcome="would_require_confirmation" want "would_block"` — the response was correct, but the "latest durable event" lookup returned a *stale* event.
- **Root cause:** `latestShadowEvidence`, `committedShadowEvents`, and `shadowEventByIDPresent` read `CommittedEvents(part, 0, 256/100000)` — the **first page from offset 0 (oldest)** — and assumed a `P‑CRIT`‑then‑`P‑ORD` concatenation reflected commit order. Below one page per partition this happens to include the newest event; above it, the event under test is never reached.
- **Product verdict:** **correct.** `CommittedEvents(cap, part, afterSeq, max) → (events, seqs, next, err)` is a well‑behaved cursor paginator; the helpers misused it.
- **Fix (harness):** fully paginate both partitions following `next`, and select the match with the maximum `Event.TimeUnixNano` (globally comparable across partitions, monotonic under the real clock and the injected monotonic test clocks).

### F‑H2 — restore publish used a fixed policy revision below a volume‑dependent churn (test bug)
- **Symptom:** at heavy volume, `publish policy rev 1000` failed.
- **Root cause:** the concurrent policy churner advances the live revision by a volume‑dependent amount (to ~1,063 at n=6,000; higher at n=20,000). The restore used a hardcoded revision `1000`, now *below* the live revision.
- **Product verdict:** **correct.** The policy holder enforces monotonic revisions and rightly rejects a publish at/below the live revision.
- **Fix (harness):** after the churner has stopped, read the live revision and publish `live+1`.

### F‑H3 — evidence‑stress spool budget did not scale with event count (test bug)
- **Symptom:** at heavy volume the stress spool failed, first with `event_durability_degraded: critical event not durable`, then (after enlarging the reserve) with `checkpoint exceeds metadata bound`.
- **Root cause:** `soakSmallEvents` used a deliberately tiny **spool** budget (256 KiB critical reserve, 64 KiB metadata) while the event count scaled to thousands. The tiny **segment** size (32 KiB) is what the test needs (to force rotation); the tiny **spool/metadata** budget was incidental and cannot hold volume. Because the test uses a monotonic fake clock, the retention window never expires, so the spool must hold every committed record, and the crash‑consistent checkpoint's metadata grows with the live segment count.
- **Product verdict:** **correct.** The spool fails closed when its bounded reserve fills (`event_durability_degraded`) and when the checkpoint exceeds `MaxMetadataBytes` — it never silently loses a critical event. This is itself a good §14/§19 property.
- **Fix (harness):** scale the spool, segment‑count, checkpoint‑metadata, and recovery budgets with `n` while keeping the 32 KiB segment size, so the test proves *lossless‑across‑rotation* rather than *bounded‑spool‑exhaustion*.

> These three defects are the tangible value of a volume‑scaled soak: they were invisible at CI volume and each is direct evidence that the product fails closed correctly.

---

## 8. Verification (§24) — real exit codes

Toolchain: Go 1.26.6. Commands run from the repo root on the branch head.

| Command | Result | Exit |
|---|---|---|
| `go build ./...` | clean | **0** |
| `go vet ./...` | clean | **0** |
| `go test ./internal/mcp/...` | all packages ok | **0** |
| `go test -run 'Shadow\|ToolTrust\|Preflight\|MCPPolicy\|ExecPosture' .` | ok | **0** |
| `go test -run 'TestShadowSoak' -shuffle=on -count=2 .` | ok | **0** |
| `go test -race -shuffle=on -count=2 -run '…Shadow…ToolTrust…Preflight…MCPPolicy…ExecPosture' .` | ok (104.8 s) | **0** |
| `CULVERT_MCP_SOAK=8000 go test -run 'TestShadowSoak' .` | ok (59 s) | **0** |
| `CULVERT_MCP_SOAK=3000 go test -race -run '^TestShadowSoak$' .` | ok (93.7 s) | **0** |
| `CULVERT_MCP_SOAK=19999 go test -run 'TestShadowSoakEvidenceStress' .` | ok (39.9 s) | **0** |
| `staticcheck .` (installed `@2025.1`) | no findings on either changed file | **0** |
| `gocognit -over 30 <changed files>` | no functions over 30 (max = 21, `killUnderLoad`) | **0** |

**Not runnable locally (recorded honestly; CI is authoritative):**

- `golangci-lint` (the required Fast‑PR‑Gate diff‑scoped lint): the installed binary is built with Go 1.25.1 and **panics in `go/types` when type‑checking Go 1.26 source** (a toolchain‑version incompatibility, not a code finding — RC=2). The `_test.go`‑relevant linters were validated individually instead: `staticcheck` (clean) and `gocognit ≤ 30` (max 21). `funlen`/`dupl`/`cyclop`/`errcheck`/`unparam` are excluded for `_test.go` by `.golangci.yml`.
- `gosec`, `govulncheck`, `gitleaks`: not installed in this environment. The change is **test‑only**, adds no production code path, no new dependency, and no secret material (the mutation campaign uses in‑memory 32‑byte zero KEKs and synthetic SPIFFE ids). These gates run in CI (Fast PR Gate, Deep PR Gate, Security gate).
- Coverage‑guided fuzzers under `internal/mcp/...`: the package unit suite (which includes the fuzz seed corpora as ordinary tests) passed; extended `-fuzz` runs are a CI/nightly concern.

---

## 9. Exit criteria table (§25)

| Criterion | Target | Actual |
|---|---|---|
| Shadow upstream invocations | 0 | **0** |
| Credential materializations | 0 | **0** |
| Live executions | 0 | **0** |
| Out‑of‑scope Shadow evaluations | 0 | **0** |
| Response↔durable mismatches | 0 | **0** |
| Missing durable evidence | 0 | **0** |
| Unexpected execution capability | 0 | **0** |
| Data races | 0 | **0** |
| Stale‑decision `would_execute` | 0 | **0** |
| Unauthorized `would_execute` | 0 (each maps to an allow‑class decision) | **0** |
| Evidence loss/dup/corruption under stress | 0 | **0** |
| Hidden auto‑repair | 0 | **0** |
| Security mutations each failing a named gate | 12/12 | **12/12** |
| Product defects requiring a weakened test | 0 | **0** |

---

## 10. Formal Shadow → Canary Exit Review (§26)

Answered against the repository's own authoritative exit criteria (`docs/design/mcp/SHADOW-ARCHITECTURE.md` §12).

1. **≥ N Shadow evaluations covering the tool set and each policy branch?** — YES. 7,516 heavy / 248 default; every tool × every policy branch, plus hard‑control, exercised.
2. **Zero real side effects (`up.calls == 0` + evidence audit)?** — YES. Independent upstream witness = 0 at every phase; evaluations == committed events.
3. **Zero evidence gaps (every evaluation has a durable record)?** — YES. 7,516 == 7,516; 248 == 248.
4. **Zero stale‑decision `would_execute`?** — YES. Staleness lands as `would_fail_hard_control` (Quarantine) or the drift refusal; never `would_execute`.
5. **No unauthorized `would_execute` (each maps to an allow‑class decision)?** — YES. Every `would_execute` carries an ALLOW policy decision at a known revision on a Usable tool.
6. **Expected denial parity (Shadow `would_block` == the deny set for the same traffic)?** — YES. Deny‑class tools and deny‑revisions produce `would_block`; parity asserted per request.
7. **Stable latency (p99 within budget; no admission saturation)?** — YES (informational). p99 ≈ 27 ms; no saturation. No SLA asserted.
8. **Credential planning reliability without materialization?** — YES, by construction: no broker is composed, readiness is honestly `not_evaluated`, and 0 materializations occurred.
9. **Kill‑switch drills pass (engage → next evaluation blocked)?** — YES. Under load: 608/608 emergency‑blocked, 0 `would_execute`, upstream 0, deterministic recovery.
10. **Restart drills pass (durable evidence survives; no execution replay)?** — YES. Full recovery; LiveExecutor absent; upstream 0.
11. **Observability verified (all shadow series emit; health three‑state correct)?** — YES. Per‑bucket deltas asserted; `evaluator_composed / live_execution_ready=false / preflight` three‑state confirmed.
12. **Operator procedure tested (runbook dry‑run)?** — YES. The node‑readiness dry‑run (`evaluateShadowNodeReadiness`) and the activation preflight are exercised on the real node before activation.
13. **`PREREQ‑MCP‑KILL‑1` CLOSED?** — **NO. OPEN.** See §11.

**Exit Review outcome:** Every Shadow‑correctness criterion (1–12) is satisfied. Criterion 13 — a **HARD Canary prerequisite** — is **OPEN**. Therefore the Shadow soak is complete and passes, but the Exit Review **does not authorize Canary architecture to begin.**

---

## 11. PREREQ‑MCP‑KILL‑1 status (§27) — inspected, NOT closed

`PREREQ‑MCP‑KILL‑1` (`docs/engineering/TECHNICAL-DEBT-REGISTER.md`) is **OPEN** and remains a **hard blocker for Canary/Production**, not for Shadow.

- **What it is:** `Executor.Execute` checks `State.Killed()` once at admission, but the irreversible live boundary (`run.go` `callUpstream`) does not re‑read the authoritative kill state before the upstream side effect. A kill engaged *during* the durable‑commit / credential‑planning / materialization window would not abort an in‑flight **live** call.
- **Why it is not a Shadow blocker:** Shadow never reaches that boundary. Shadow reflects the kill at **admission** (`rollout_emergency_active`, `evaluation_error`, no `would_execute`) — proven directly by the §12 kill‑under‑load drill: 608/608 requests emergency‑blocked, upstream 0.
- **Compensating control today:** no production executor is composed (arming hooks uncalled; execution‑posture wall), so the window is structurally unreachable in this build — independently re‑confirmed by mutations M1/M9 (`liveExecDepsConfigured(false)`).
- **Decision:** **left OPEN.** The implementation (a `killEpoch` re‑read at `callUpstream`, inverting `TestCanaryPrerequisite_KillStateNotRevalidatedAtSideEffectBoundary` to `up.calls == 0`) does not yet exist and is **out of scope** — Canary is not built or activated in this PR.

---

## 12. Final verdict (§28)

**SHADOW SOAK PASSED — READY FOR SHADOW EXIT REVIEW**

The Shadow Exit Review (§10) confirms every Shadow‑correctness criterion is met, and surfaces exactly one remaining **HARD Canary prerequisite — `PREREQ‑MCP‑KILL‑1` — which is OPEN.** Canary architecture may **not** begin until that prerequisite is implemented and proven. Accordingly, the `SHADOW EXIT REVIEW PASSED — CANARY ARCHITECTURE MAY BEGIN` line is **deliberately withheld.**

This is not readiness for Canary. Canary has not been built or activated.
