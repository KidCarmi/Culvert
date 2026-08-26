# Security regression review — Shadow Layer-B + LDAP-E2E window (2026-08-25)

**Scope:** everything merged into `main` after the predecessor artifact, i.e.
`0f5cc1f..e698a12` — PR #1225 (ADR-0027 LDAP edge-case/E2E test wall) and PR #1226
(MCP Shadow Layer-B capability split). 29 files, +3074/−62.
**Branch:** `claude/epic-bardeen-v85ltf` · baseline `e698a12`
**Predecessor:** `2026-08-25-mcp-overnight-hardening-run.md` (OVN-01…OVN-19, CI-01…CI-03)
**Method:** read the whole window, then REVIEW → PROVE → FIX → TEST. Both findings below
were **reproduced against the unmodified `e698a12` tree before either fix was written**;
the reproduction output is quoted in §3.

> **Verdict (§6): no security regression. Two prediction-fidelity defects, both in the
> permissive direction, both closed. This document does not authorise enabling execution —
> Shadow, Canary and Production remain disabled and this window did not change that.**

---

## 1. What this window changed

| Area | Change | Security direction |
|---|---|---|
| `internal/mcp/rollout` | New `EffectShadowEvaluate` disposition; `resolveShadow` routes **every** in-scope Shadow request to it, including hard failures | **Tightening.** Shadow previously resolved an in-scope allow-class request to `EffectExecute` — a real upstream call. It can no longer reach the execute path at all. |
| `internal/mcp/rollout` | `Mode.Executes()` → `Mode.RequiresExecutionPlane()` | Neutral rename; all 5 call sites are exec-deps fail-closed gates and all were updated (`rg '\.Executes\(\)'` returns nothing). Shadow still returns `true`, so a Shadow transition without exec-deps still fails closed. |
| `internal/mcp/execution` | New `ShadowEvaluator` — a distinct type with **no** `UpstreamCaller` field and **no** `*broker.Broker`, holding only the bound `Plan` method value | **Tightening.** Capability absence in the type graph, not by comment. |
| `internal/mcp/execution` | `Executor` embeds the evaluator and shares its allowance store | Correct: without sharing, a Canary out-of-scope → Shadow fallback would read a fresh grant. |
| `internal/mcp/events/model` | Comment only — Shadow sub-facts deliberately NOT added to the `schema_version:1` envelope | Correct rollback-safety call (digest is computed over canonical bytes). |
| root `mcp_*.go`, `ui_mcp_rollout.go` | Rename call sites | Neutral. |
| root `auth_ldap_*_test.go` | +510 lines of LDAP IdP edge-case and live-directory E2E tests | Test-only; env-gated on `CULVERT_OPENLDAP_URL`, no-op without a directory. |

### Verified explicitly

- **Shadow cannot execute.** `EffectExecute` is produced only by `resolveEnforcing` on an
  in-scope Canary/Production subject; `resolveShadow` cannot emit it. The evaluator's own
  `EffectExecute` branch fails closed as defence-in-depth. `ShadowEvaluator`'s dependency
  graph reaches neither `Upstream.Call` nor `Materialize`.
- **The narrowed planner is genuinely narrowed.** `NewShadowEvaluator` stores
  `cfg.Planner.Plan` as a bound method value and nils the interface field. Go exposes no
  way to recover a method value's receiver, so `Materialize` is unreachable, not merely
  un-called. `Broker.Plan` was read end-to-end and confirmed metadata-only: no provider
  call, no cache decrypt, no plaintext, no secret on `CredentialPlan`.
- **Disposition enum is append-only.** `EffectShadowEvaluate` was added after
  `EffectBlock`, so no existing iota value moved; the type is never serialized.
- **No new consumer.** `rg` confirms `ResolveFor`/`Effect*` are consumed only by the
  executor and the evaluator — the new disposition cannot leak into another decision site.
- **No secret on the new response body.** `shadowResult` carries bounded status labels
  only (`credential_plan_valid|_invalid|no_credential_profile|no_planner_composed`,
  `would_pass|would_fail|not_evaluated`). It discloses no more than the pre-existing
  `observeResult`, which already returns the full policy action and reason code.
- **`wouldSatisfy` is read-only.** Pinned (`TestSR01_WouldSatisfyNeverMutatesTheStore`),
  because the store it reads is the LIVE executor's — a mutation there would let a Shadow
  evaluation burn a real `ALLOW_ONCE` grant, which is the one thing Layer B forbids.

### Deliberate posture change, recorded not flagged

In Shadow, a **hard failure no longer emits an `EffectBlock`**; it is routed to
`EffectShadowEvaluate` and reported as `WOULD_FAIL_HARD_CONTROL` / `WOULD_FAIL_INSPECTION`.
This is defensible and documented (Shadow predicts, it never enforces) and the security
outcome is unchanged — nothing executed before and nothing executes now. Two consequences
an operator should know, and neither is a regression in confidentiality or integrity:

1. The client receives a `200` `shadow_evaluated` result rather than a JSON-RPC error.
2. `Metrics.ObserveBlock` and the runtime's `requestsRejected` counter no longer move for
   that request (it counts as `observeOnly`). The observation record still carries the raw
   policy action and reason, set in `dispatchPolicy` before the executor is reached.

The reachable hard failure at the executor is a policy `HardOverride` only: an inspection
`HardFail` is terminally rejected in `dispatchPolicy` **before** `p.executor.Execute`
(already tracked as `SHADOW-EVIDENCE-ROUTING-1`).

---

## 2. Finding ledger

Severity: **P0** reachable today and security-relevant · **P1** reachable, correctness or
availability · **P2** latent / pre-activation · **P3** accuracy and maintainability.

| ID | Severity | Finding | State |
|---|---|---|---|
| SR-01 | P2 | `allowanceStore.wouldSatisfy` treated **any** present key as a reusable slot, but `consume` sweeps expired session grants **before** its capacity check — so a request whose own slot is an expired `ALLOW_FOR_SESSION` has that slot deleted and is then refused when the store is still full. Shadow predicted `WOULD_EXECUTE` where live enforcement returns `allowance_consumed`. | **Fixed** — this PR |
| SR-02 | P2 | `ShadowEvaluator.decide()` did not model the live path's **upstream-server usability** refusal (`runExecute`: `in.Server == nil \|\| !in.Server.Usable()` → `ReasonUpstreamServerUnusable`, a `HardServerTrust` hard failure). Shadow predicted `WOULD_EXECUTE` for a server enforcement will not call. `SHADOW-ARCHITECTURE.md` §4 lists "server eligibility" among the stages that must be proven equal; it was not. | **Fixed** — this PR |
| SR-03 | P3 | `wouldSatisfy`'s capacity gate ran an O(len(sess)) live-entry scan **under the store mutex** on every fresh-key prediction, not only at capacity — on a lock the live `consume` path also takes. | **Fixed** — this PR (pre-sweep count checked first, mirroring `consume`) |

### Refuted (investigated, no defect)

- **Shadow reaching the execute path.** Structurally impossible; see §1.
- **Concrete broker recoverable from the evaluator.** Method-value narrowing holds.
- **Enum renumbering / wire break** from the new disposition. Append-only, never serialized.
- **`Mode.Executes()` rename losing a gate.** All five call sites updated; no stale caller.
- **Secret or unbounded caller-controlled data on the new response body.** Bounded labels only.
- **LDAP window weakening anything.** Test-only, env-gated, uses the existing shared
  `.github/idp/openldap/bootstrap.ldif` fixture DIT; no production file changed.

---

## 3. SR-01 · allowance prediction diverges from consumption

**Attack scenario.** Not directly attacker-triggered; it is an *evidence* defect. An
operator running Shadow to decide whether a scope is ready for Canary reads
`WOULD_EXECUTE` for allowance-gated traffic that Canary/Production will refuse with
`allowance_consumed`, and promotes on that evidence. The failure surfaces as refused
production traffic after promotion, on the exact requests the evidence said were clean.

**Preconditions.** The allowance store at `maxAllowanceEntries` (65536) live entries after
reclamation, and the requesting key holding an expired `ALLOW_FOR_SESSION` slot. The store
is shared per-executor and per-node.

**Exploitability.** Low — reaching 65536 live entries requires either a very large estate
or sustained distinct-principal traffic. **Likelihood** low, **impact** medium (a
promotion decision made on false evidence), **affected assets** the Canary-readiness
evidence chain. Not reachable in a shipped build: execution is disabled.

**Reproduction (unmodified `e698a12`):**

```
--- FAIL: TestSR01_WouldSatisfyMatchesConsumeForAnExpiredSessionKeyAtCapacity
    SR-01: wouldSatisfy predicted the allowance would be satisfied where consume refuses
```

**Fix.** Only a slot that SURVIVES `consume`'s sweep exempts a request from the capacity
gate: an `ALLOW_ONCE` record (never swept) or a **non-expired** session slot. The
pre-existing tests do not reach this case — `TestAllowance_WouldSatisfyMirrorsCapacityRefusal`
uses an absent key, `…ReclaimsExpiredSessions` frees a slot so the store is no longer full.
This case is the intersection of the two.

**CWE / OWASP.** CWE-696 (incorrect behaviour order) with CWE-1288 (improper validation of
consumed state); OWASP A04:2021 Insecure Design (an assurance signal that overstates).
**Regression risk of the fix:** none in the permissive direction — it can only turn a
`would_execute` into a `would_block`, pinned by the negative test
`TestSR01_WouldSatisfyStillAdmitsALiveSessionSlotAtCapacity`.

---

## 4. SR-02 · Shadow did not model the upstream-server refusal

**Attack scenario.** A server is deregistered, disabled or marked identity-mismatched
between the moment the policy decision is computed (against the decision snapshot) and the
moment the executor re-reads the LIVE registry. The live path refuses with
`upstream_server_unusable` — that TOCTOU re-read is precisely why the refusal exists.
Shadow, having no such step, reported `WOULD_EXECUTE`. An operator revoking a server and
then reading Shadow evidence sees traffic to the revoked server described as ready to
execute.

**Preconditions.** A registry state change inside the decision→execution window, or a
registry lookup miss in `dispatchExecute` after `identity.Resolve` admitted the id
(`in.Server == nil`, the deregistration race).

**Exploitability.** Low and indirect — an attacker who can force catalog/registry churn can
widen the window, but cannot cause execution: Shadow does not execute. **Likelihood** low,
**impact** medium (an operator's revocation is invisible in the evidence they promote on),
**affected assets** server-trust evidence. Not reachable in a shipped build.

**Reproduction (unmodified `e698a12`), all three cases:**

```
--- FAIL: TestSR02_ShadowPredictsTheLiveUpstreamServerRefusal/absent_record
    SR-02 DIFFERENTIAL DIVERGENCE: live=fail_hard_control shadow=execute
--- FAIL: …/disabled_after_the_decision            live=fail_hard_control shadow=execute
--- FAIL: …/identity_mismatched_after_the_decision live=fail_hard_control shadow=execute
```

**Fix.** `decide()` gains the gate at the position live occupies — after the allowance
step, before credential planning — mapping to the existing `WOULD_FAIL_HARD_CONTROL`
outcome, because `ReasonUpstreamServerUnusable` is already classified `HardServerTrust` in
`rollout/hardfail.go`. **No new outcome label was invented**: the bounded outcome set and
the `schema_version:1` envelope are untouched, so the rollback hazard recorded in the
`SHADOW-EVIDENCE-ROUTING-1` addendum is not reopened.

**CWE / OWASP.** CWE-367 (TOCTOU) in the modelled window, surfacing as CWE-1288; OWASP
A04:2021 Insecure Design. **Regression risk of the fix:** it refuses only what live
refuses. Pinned in both directions — `TestSR02_UsableServerStillPredictsWouldExecute`
(no over-tightening) and `TestSR02_ServerUsabilityIsCheckedAfterPolicyAndAllowance` (the
gate sits where live sits it, so an allowance-exhausted request pointed at a dead server
still reports the ALLOWANCE verdict in both paths, not the server one).

---

## 5. Required tests — all present

`internal/mcp/execution/shadow_prediction_parity_test.go` (new):

| Class | Test |
|---|---|
| Negative (the defect) | `TestSR01_WouldSatisfyMatchesConsumeForAnExpiredSessionKeyAtCapacity`, `TestSR02_ShadowPredictsTheLiveUpstreamServerRefusal` (3 sub-cases) |
| Positive (no over-tightening) | `TestSR01_WouldSatisfyStillAdmitsALiveSessionSlotAtCapacity`, `TestSR02_UsableServerStillPredictsWouldExecute` |
| Boundary | at/one-below `maxAllowanceEntries`; expired vs live vs absent slot |
| Ordering | `TestSR02_ServerUsabilityIsCheckedAfterPolicyAndAllowance` |
| Concurrency | `TestSR01_WouldSatisfyIsSafeUnderConcurrentConsume` (16 goroutines, `-race`) |
| Invariant | `TestSR01_WouldSatisfyNeverMutatesTheStore` |

Every SR test is a **differential** against the live `Executor` where a live counterpart
exists, so it cannot pass by agreeing with a wrong model of enforcement.

**Runs:** `go build ./...`, `go vet ./internal/mcp/...`, `go test ./internal/mcp/...` all
clean; `go test -race -count=1 ./internal/mcp/execution/... ./internal/mcp/rollout/...
./internal/mcp/runtime/...` clean.

---

## 6. Verdict

No security regression was introduced by this window. Measured against the posture it
replaced, PR #1226 is a **net tightening**: Shadow lost its ability to make a real upstream
call, and the shadow path lost structural access to credential materialization.

The two defects found are of one kind — the Shadow evaluator's model of enforcement was
incomplete, and both gaps erred toward `WOULD_EXECUTE`. That direction is the one that
matters, because Shadow evidence is the input to the promotion decision; both are now
closed and walled by differential tests.

Unchanged and still true: guarded execution is disabled, no listener binds, no executor is
composed, and nothing here authorises Shadow activation. `SHADOW-EVIDENCE-ROUTING-1` and
its v2-envelope addendum, `PREREQ-MCP-KILL-1`, `OVN-05` and `RISK-026` remain open as
recorded.

### Residual risk

- Shadow evidence remains **partly out-of-band**: the `ShadowDecision` sub-facts ride the
  transient response body, not the durable envelope (`SHADOW-EVIDENCE-ROUTING-1` addendum).
  An operator reading only durable events sees `ExecutionState = "shadow_evaluated"` and
  the raw policy action, not which control the prediction fired on.
- A Shadow hard-control refusal no longer moves `ObserveBlock` / `requestsRejected` (§1).
  Any future alerting built on those counters must not assume Shadow contributes to them.
- The remaining pre-dispatch signals (inspection hard-fail, initial tool drift) still never
  reach the evaluator — `SHADOW-EVIDENCE-ROUTING-1`, unchanged by this review.
- `decide()`'s fidelity is enforced by a differential test, not by construction. A future
  gate added to `runExecute` without a matching `decide()` step reopens exactly this class.
  A structural wall (an ownership registry over the pre-side-effect gates, in the shape of
  `limits_ownership_test.go`) is the durable answer and is **not** attempted here.
