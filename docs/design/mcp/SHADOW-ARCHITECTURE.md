# MCP Shadow Execution — Security Architecture

**Phase:** Culvert MCP — Shadow Activation Architecture & Readiness
**Baseline:** `main` HEAD `0f5cc1f`. Branch `claude/mcp-shadow-readiness`.
**Status:** DESIGN. Shadow is NOT enabled by this document. No production executor is
armed. No real upstream side effect is possible in Observe or Shadow.
**Companion:** `SHADOW-READINESS-MATRIX.md` (ground-truth composition),
`docs/operator/mcp-shadow-activation.md` (runbook, task 17),
`docs/adr/0032-*` (assurance), `docs/adr/0033-*` (admission).

> **Core principle.** The ideal Shadow implementation is not "a live executor with a
> boolean telling it not to execute." It is **a decision system that does not possess
> the capability required to create the side effect.** Everything below builds toward
> that invariant.

---

## 1. What Shadow means (task 5 — the security contract)

Shadow answers one question about a real request — *"would this request execute, and
with what outcome?"* — and records a durable, sanitized answer. It **never crosses the
irreversible side-effect boundary.**

```
request
  → transport admission (coarse, pre-auth)
  → authentication (token verify)
  → sender-binding verification (DPoP / mTLS)
  → identity resolution
  → session / request binding
  → registry / server validation
  → catalog / tool validation (fingerprint)
  → policy snapshot evaluation
  → approval / allowance evaluation
  → credential PLAN            (metadata only — NO Materialize)
  → inspection PLAN            (request DLP classification — NO response, no CDR side effect)
  → execution preconditions
  → WOULD_EXECUTE / WOULD_BLOCK / WOULD_REQUIRE_APPROVAL / …
  → durable Shadow evidence
  → STOP
```

**Critical invariant (SH-INV-1):** Shadow may determine a request *would* execute; it
must never actually execute it. The transition it must never make is
`internal/mcp/execution/run.go:71` (`Upstream.Call`) and
`internal/mcp/credentials/broker/materialize.go` (`Materialize`).

---

## 2. The side-effect boundary (task 6)

The precise line at which Culvert transitions from *planning / validation / evidence*
to *external side effect* is **`internal/mcp/execution/run.go:71`**:

```go
r, err := e.cfg.Upstream.Call(ctx, target, in.Method, json.RawMessage(in.RawParams), ...)
```

and, on the credential path, **`broker.Materialize`** (which decrypts/fetches a real
secret). Both sit inside the durable-commit callback (`run.go:92`
`Events.CommitThenAct`) and behind a last-moment drift re-check (`run.go:67-70`).

**Credential materialization is itself side-effectful and sensitive.** Materialization
fetches or decrypts a real secret and hands plaintext to the upstream call. Shadow MUST
NOT materialize. The broker already provides the seam:

| Broker method | Retrieves secret? | Shadow may call? |
|---|---|---|
| `Plan(PlanInput) (CredentialPlan, error)` | **No** — pure metadata, no provider call, no cache decrypt | **Yes** |
| `Materialize(ctx, plan, gate, cb)` | **Yes** — provider fetch / cache decrypt, plaintext to `cb` | **No — structurally forbidden** |

Shadow reports credential *readiness* from `Plan` (profile resolves, power ceiling
satisfied, environment/tenant/tool binding valid) — never by obtaining the secret.

### The `ExecutionPlan` / `ShadowDecision` concept (task 6)

Introduce a value type that contains **everything required to determine "would
execute" without possessing the capability to execute**:

```
ShadowDecision {
  Correlation, Capability
  PrincipalType, PrincipalPseudonym, Tenant          // sanitized identity
  AuthnAssurance, SenderBinding                       // separated dimensions (ADR-0032)
  ServerID, ToolID, ToolFingerprint
  CatalogRevision, PolicyRevision, RolloutMode
  PolicyAction, Reason, ApprovalState, AllowanceState
  CredentialProfileID (NOT the secret), CredentialReadiness
  InspectionRequestVerdict                            // response NOT evaluated
  ExecutionPreconditions
  Outcome ∈ { WOULD_EXECUTE, WOULD_BLOCK,
              WOULD_REQUIRE_APPROVAL, WOULD_FAIL_CREDENTIAL_READINESS,
              WOULD_FAIL_INSPECTION, WOULD_FAIL_STALE_DECISION, … }
}
```

`ShadowDecision` carries the *inputs and the verdict*, never the `Upstream`/`Materialize`
capability. It is the durable evidence unit (§9) and the equivalence anchor (§10).

---

## 3. Capability separation — the structural barrier (tasks 7 & 15)

### Current reality (the anti-pattern)

`resolveShadow` (`internal/mcp/rollout/resolve.go:143`) emits `EffectExecute` — the
same disposition as Canary/Production — which the executor dispatches into the same
`runExecute` → `Upstream.Call`. Shadow today is "a live executor told (by scope) to
execute," gated off ONLY by the executor never being composed and by the transition-time
`execDepsConfigured` gate. There is no request-time barrier.

### Target design

Two layers of separation, weakest-to-strongest:

**Layer A — disposition severance (implemented this phase, see §3.1).**
`resolveShadow` emits a new, non-executing disposition `EffectShadowEvaluate`. The
executor dispatch routes it to a `shadowEvaluate` method that runs credential `Plan`,
inspection plan, computes the `ShadowDecision`, commits evidence, and returns — and that
method has **no call to `cfg.Upstream` or `Materialize` anywhere on its path.** Even a
composed executor in Shadow mode cannot reach `run.go:71`.

**Layer B — capability object separation (target; specified here, staged next).**
Split the single `Executor` into two composed capabilities behind distinct interfaces:

```
DecisionEvaluator            LiveExecutionCapability
  ├─ Observe                   ├─ Canary
  └─ Shadow                    └─ Production
  (Policy, Registry, Catalog,  (everything in DecisionEvaluator
   Broker.Plan, Inspection,     PLUS Upstream + Broker.Materialize)
   Events)   — NO Upstream,
             NO Materialize
```

A Shadow-only deployment composes only a `DecisionEvaluator`, which **literally does not
hold** the `Upstream` client or a broker capable of `Materialize`. This is stronger than
Layer A because it removes the objects, not just the code path. Layer A is the safe
first step and the test scaffold that makes Layer B verifiable; Layer B is the follow-on
composition change (it does not change request semantics, so it can land separately).

**Invariant (SH-INV-2):** a mutation that flips `Shadow → execute` must still be
incapable of a real side effect. Under Layer A, flipping the disposition back to
`EffectExecute` is caught by the evolved posture wall (§ tests). Under Layer B, the
Shadow runtime has no `Upstream` object to call at all.

### 3.1 Layer-A implementation shape (this phase)

- `rollout`: add `EffectShadowEvaluate` to the `Disposition` enum; `resolveShadow`
  emits it for the in-scope non-hard case (replacing `EffectExecute`). `Executed`
  becomes `false` for Shadow (Shadow does not execute — it evaluates). Hard-fail and
  out-of-scope branches are unchanged (block / record-only).
- `execution`: dispatch `EffectShadowEvaluate` → `shadowEvaluate(in, res)`, which
  produces a `WOULD_*` outcome and evidence and returns without touching `Upstream` or
  `Materialize`. `runExecute` is reachable ONLY from `EffectExecute` (Canary/Production).
- Tests: `TestExecShadowExecutesDenyWithOverride` and siblings, which encode the OLD
  "Shadow executes" semantics, are **evolved** (not deleted) to assert Shadow produces a
  `WOULD_EXECUTE` decision with `up.calls == 0`.

---

## 4. Shadow ≡ live pre-side-effect decision equivalence (task 10)

The most dangerous Shadow design uses a *different* decision path than real execution.
The equivalence requirement:

> For identical input and state, the Shadow decision equals the live pre-call decision
> for every stage up to (but excluding) the side-effect boundary.

Because both Shadow and the enforcing modes share the **same runtime pipeline** (auth,
sender-binding, identity, registry, catalog, policy, approval, allowance) and the
divergence is introduced only at `Resolve` (disposition) and below, equivalence holds by
construction for stages 1–8. The stages that must be proven equal by differential test:

- authentication, sender binding, identity, policy, catalog fingerprint, tool
  eligibility, server eligibility, approval, allowance, credential profile selection,
  inspection (request), rollout resolution, kill switch, stale-decision detection.

Differential test shape: same input + state, assert
`shadowDecision.preSideEffect == liveResolution.preSideEffect`, with the live side
effect replaced by a fake/sentinel `Upstream` that records-but-refuses. The ONLY
permitted divergence is: live proceeds to `Upstream.Call`; Shadow stops with the
equivalent `WOULD_EXECUTE`.

**Implemented:** `TestShadow_LivePreSideEffectEquivalence` (`internal/mcp/execution`)
drives both the capability-reduced `ShadowEvaluator` (Shadow) and the live `Executor`
(Canary, fake upstream) with the same input across 14 classes — ALLOW, DENY,
REQUIRE_APPROVAL, REQUIRE_CONFIRMATION, ALLOW_ONCE available/consumed, ALLOW_FOR_SESSION
valid/exhausted, credential missing, tool fingerprint drift, tool eligibility changed,
server disabled, request inspection fail, kill switch active — and asserts both project to
the same canonical pre-side-effect verdict. See §13 for the two deliberately-excluded
divergences.

---

## 5. Credential architecture for Shadow (task 14)

Shadow uses `Plan` + a readiness check; only live execution may `Materialize`.

```
PlanCredential         → Shadow may call   (metadata; no secret)
CheckCredentialReadiness → Shadow may call (derive from Plan + provider Inspect metadata)
MaterializeCredential  → LIVE ONLY         (structurally unreachable from Shadow)
```

The broker already exposes `Plan` (metadata-only) and `Inspect` (lease metadata without
materializing). A thin `CheckReadiness(plan)` helper composes these into a
`CredentialReadiness ∈ { ready, profile_missing, profile_disabled, version_stale,
power_exceeded, unknown }` without ever fetching or decrypting a secret. Test
`Shadow → Materialize is structurally impossible` (Layer A: `shadowEvaluate` contains no
`Materialize` call; Layer B: Shadow holds no materialize-capable broker).

---

## 6. Inspection architecture for Shadow (task 15)

- **Request inspection MAY run in Shadow** — `inspection.InspectRequest` is
  decision-only ("performs NO upstream execution and NO credential work"); its only
  external I/O is an optional bounded DNS read for SSRF classification (non-mutating).
  Shadow reports `request inspection would pass` / `would fail`.
- **Response inspection is NOT evaluated in Shadow** — there is no upstream response
  because no upstream call is made. Shadow reports `response inspection not evaluated`,
  never a fabricated "response would pass."
- **CDR / malware scanning / remote inspection providers** that process real content
  are classified as *side-effectful processing* and are NOT run in Shadow beyond the
  request-DLP classification of the request the client already sent.

Shadow evidence records exactly three inspection facts:
`request_inspection ∈ {would_pass, would_fail}`, `response_inspection = not_evaluated`.

---

## 7. Staleness / freshness contract at the boundary (task 13)

At the final decision boundary the following must still be current, checked via a typed
`DecisionSnapshot` of revision identities rather than a growing list of ad-hoc rechecks:

| Element | Freshness mechanism (current) |
|---|---|
| policy revision | `PolicyRevision` on the decision; snapshot compare |
| server state / usability | registry live `Get` + identity pin |
| tool fingerprint | `ToolStillCurrent` re-check (`run.go:67`) — fingerprint equality |
| tool eligibility | catalog live eligibility (see gap below) |
| catalog revision | `CatalogRevision` compare |
| credential profile | broker plan-currency recheck (`materialize.go:47-56`) |
| approval / allowance | allowance store consume-check |
| rollout mode | `State.ResolveFor` at dispatch |
| kill switch | **gap: not re-checked at `run.go` boundary** (§ task 12) |
| execution dependencies | `execDepsConfigured` |

**Recommendation:** consolidate into one `DecisionSnapshot{policyRev, catalogRev,
toolFingerprint, serverPin, rolloutEpoch, killEpoch}` captured at decision time and
re-validated atomically at the boundary. For Shadow, the same snapshot is captured and
the `WOULD_*` verdict records which element was stale if any (`WOULD_FAIL_STALE_DECISION`).
This is specified here; the kill-epoch addition is the concrete task-12 change (§ below).

---

## 8. Crash-boundary analysis (task 11)

Crash points and Shadow's required behavior:

| Crash point | Live classification | Shadow requirement |
|---|---|---|
| after auth | none | re-evaluate on retry (no state) |
| after policy | none | idempotent re-evaluate |
| after approval | none | idempotent |
| after credential **Plan** | none (no secret) | idempotent (Plan is pure) |
| after durable **decision** event | evidence persisted | on restart, evidence already durable; Shadow **must not** replay into execution — it has no execute path |
| **before side-effect boundary** | none | Shadow always stops here by construction |
| after side effect starts | **at-most-once / unknown** (live only) | N/A for Shadow |
| after side effect returns | outcome pending | N/A for Shadow |

**Shadow restart-safety (SH-INV-3):** a durable Shadow evidence record names a *decision*,
never a *pending side effect*. Restart re-evaluates fresh requests; it cannot "resume" a
Shadow decision into an execution because Shadow possesses no execution capability. For
future live execution, classify tool operations as `at-most-once` / `at-least-once` /
`idempotent` / `unknown` (propose an MCP tool idempotency-class metadata field);
**never claim exactly-once.**

---

## 9. Shadow evidence contract (task 9)

Every Shadow evaluation commits ONE durable, redacted evidence record (reusing the
existing KEK-encrypted event spool + redaction backstop). Captured (sanitized):

correlation id · principal type · principal pseudonym (stable HMAC, not raw subject) ·
tenant · **authentication assurance** and **sender binding** (separated, ADR-0032) ·
server id · tool id · tool fingerprint · catalog revision · policy revision · rollout
mode · policy action · reason · approval state · allowance state · credential profile id
(**not** the secret) · credential readiness · request-inspection verdict ·
`response_inspection = not_evaluated` · execution preconditions · final outcome
(`WOULD_EXECUTE` / `WOULD_BLOCK` / `WOULD_REQUIRE_APPROVAL` /
`WOULD_FAIL_CREDENTIAL_READINESS` / `WOULD_FAIL_INSPECTION` / `WOULD_FAIL_STALE_DECISION`).

**Never persisted:** bearer tokens · DPoP private material · client certs/keys ·
materialized credentials · upstream Authorization headers · secrets · raw sensitive
request body beyond existing retention policy. Enforced by the existing redaction
backstop that rejects any event containing secret patterns.

**Current implementation state (this architecture-only increment).** The list above is the
DESIGN target. Today a shadow evaluation commits a durable record marked by the existing
`ExecutionState = "shadow_evaluated"` field (a digest-safe value on the current
`schema_version:1` envelope), and the FULL ShadowDecision — outcome, credential-plan and
inspection readiness — rides the transient JSON-RPC response body. The
enforcement-prediction SUB-FACTS are deliberately NOT added as new digest-covered fields on
v1: doing so would misverify valid shadow events after a binary rollback (a pre-change
reader drops the unknown fields and recomputes a different `CanonicalBytes` digest — Codex
P2, PR #1226). Persisting them durably requires a `schema_version:2` envelope with explicit
v1/v2 recovery, which belongs in the reviewed Shadow-activation slice (execution is disabled
here, so no shadow event is ever written). Tracked as `SHADOW-EVIDENCE-ROUTING-1`.

Evidence is durable **before** Shadow reports success, consistent with the existing
critical-commit-before-response ordering.

---

## 10. Kill switch at the boundary — HARD CANARY PREREQUISITE (task 12, PREREQ-MCP-KILL-1)

The kill switch is checked once at the top of `Executor.Execute` but **not re-checked at
the irreversible boundary** (`run.go` `callUpstream`). Between admission and the boundary
the executor performs a durable decision commit, credential planning and credential
materialization — all of which can block — so a kill engaged during that window does NOT
stop an in-flight live call today. The existing OVN-09 tool-drift re-check sits exactly at
the boundary (`callUpstream` re-invokes `ToolStillCurrent`); the kill re-check does not yet
join it.

> **Prerequisite (blocking).** **Canary/Production activation is PROHIBITED until the
> authoritative kill state is revalidated immediately before the irreversible side-effect
> boundary.** A kill engaged during credential planning or materialization MUST abort the
> upstream call (`up.calls == 0`), landing as `WOULD_BLOCK` / block reason
> `rollout_emergency_active`. This is a HARD gate, not a nicety: the kill switch is the
> operator's only immediate stop, and a stop that a slow commit window can outrun is not a
> stop.

Scope of the change (deferred; NOT implemented in the Shadow-readiness/Layer-B increment):
add a `killEpoch` to the boundary re-check alongside the existing tool-drift re-check, so
the final `callUpstream` re-reads the authoritative execution state before the side effect.
For Shadow the kill switch already affects the verdict consistently with live at admission
(a killed capability yields `WOULD_BLOCK` reason `rollout_emergency_active`); the boundary
re-check matters only for a live-capable mode, which is why it is a Canary prerequisite
rather than a Shadow one.

Tracking: `PREREQ-MCP-KILL-1` in `docs/engineering/TECHNICAL-DEBT-REGISTER.md`. The gap is
pinned non-vacuously by `TestCanaryPrerequisite_KillStateNotRevalidatedAtSideEffectBoundary`
(`internal/mcp/execution`), which drives the admission→boundary window and asserts the
current (gap-present) behaviour; closing the prerequisite means inverting that assertion to
`up.calls == 0` and checking off the §12 exit criterion below.

---

## 11. Health & metrics for Shadow (task 16)

Bounded-cardinality series (no principal/server/tool identifiers in labels):

```
culvert_mcp_shadow_evaluations_total
culvert_mcp_shadow_would_execute_total
culvert_mcp_shadow_would_block_total
culvert_mcp_shadow_errors_total
culvert_mcp_shadow_policy_stale_total
culvert_mcp_shadow_catalog_stale_total
culvert_mcp_shadow_credential_not_ready_total
culvert_mcp_shadow_latency_seconds        (histogram)
```

Health distinguishes three states: `MCP Observe healthy` · `Shadow evaluator healthy` ·
`Live execution capability unarmed`. MCP still must never become an SWG availability
SPOF — the Shadow rows follow the existing report-only `/readyz` discipline.

---

## 12. Exit criteria — Shadow → Canary review (task 18)

Measurable gates before Canary may even be *reviewed* (rationale, not arbitrary):

- ≥ N Shadow evaluations across the controlled host (N sized to cover the tool set and
  each policy branch at least once — a coverage argument, not a round number).
- **zero real side effects** (proven by `up.calls == 0` telemetry + evidence audit).
- zero evidence gaps (every evaluation has a durable record).
- zero stale-decision `WOULD_EXECUTE` (any staleness must land as `WOULD_FAIL_STALE_*`).
- no unauthorized `WOULD_EXECUTE` (every one maps to an allow-class policy decision).
- expected denial parity (Shadow `WOULD_BLOCK` set == Observe deny set for the same
  traffic).
- stable latency (Shadow p99 within budget; no admission saturation).
- credential planning reliability (readiness derivable without materialization).
- kill-switch drills pass (engage → next evaluation is `WOULD_BLOCK`).
- **`PREREQ-MCP-KILL-1` CLOSED** — the authoritative kill state is revalidated immediately
  before the irreversible side-effect boundary (`run.go` `callUpstream`), so a kill engaged
  during credential planning/materialization aborts the call (`up.calls == 0`). This is a
  HARD blocker: Canary/Production activation is prohibited while this is open (§10).
- restart drills pass (durable evidence survives; no execution replay).
- observability verified (all series emit; health three-state correct).
- operator procedure tested (runbook dry-run).

## 13. Known Shadow-evidence limitations (deliberate, bounded)

Two divergences between the Shadow prediction and live pre-side-effect behaviour are
deliberate and documented rather than papered over. Both are safe for Shadow (which never
executes) but MUST be understood when reading Shadow evidence for a Canary-readiness
argument.

1. **Allowance prediction is optimistic (peek-only).** The `ShadowEvaluator` predicts an
   ALLOW_ONCE / ALLOW_FOR_SESSION with a NON-destructive `wouldSatisfy` peek — it never
   `consume`s, because a Shadow evaluation must be side-effect-free even against in-memory
   allowance state. A pure Shadow deployment therefore has an allowance store that is always
   empty (nothing executes to consume a grant), so an allowance already exhausted by real
   prior execution in a live mode would be predicted `WOULD_EXECUTE`. The differential test
   pins equivalence by seeding BOTH stores to the same history; in production this means
   Shadow may OVER-predict `WOULD_EXECUTE` for allowance-gated actions — an
   over-count of would-execute, never an under-count of a would-block, and never a real
   execution. Read allowance-gated `WOULD_EXECUTE` as "would execute if the allowance is
   fresh," not "the allowance is definitely available."

2. **The executor's redundant `Server.Usable()` re-check is not mirrored.** `decide()`
   predicts the policy + inspection + credential + allowance + drift decision; it does not
   reproduce the live executor's defense-in-depth `in.Server.Usable()` re-check inside
   `runExecute`. In practice a disabled/unusable server is signalled by the policy engine as
   a hard override (which Shadow DOES mirror as `WOULD_FAIL_HARD_CONTROL`), so this matters
   only in the corner where policy said ALLOW but the server record is independently
   unusable — a redundant guard, not a primary control. Modelled in the differential via the
   policy hard-override path, which both sides honour.

3. **Two failure classes are terminally handled by the runtime BEFORE the provider, so
   their Shadow-outcome branches are not produced by a Shadow evaluation today**
   (Codex review of `d0f747e`, tracked as `SHADOW-EVIDENCE-ROUTING-1`):
   - **Request inspection hard-fail.** `dispatchPolicy` (`internal/mcp/runtime/policy.go`)
     rejects an inspection `HardFail` and returns BEFORE the `p.executor != nil`
     delegation, for EVERY rollout mode. So a hard-inspected request never reaches the
     Shadow evaluator; it produces the runtime's own inspection-rejection observation, not
     a `shadow_evaluated` / `WOULD_FAIL_INSPECTION` event. The evaluator's
     `WOULD_FAIL_INSPECTION` branch is a provider-level contract (pinned by the
     differential test via direct invocation) but is unreachable through the live pipeline
     — there is no post-dispatch inspection re-check.
   - **Initial tool drift.** `dispatchExecute` runs the OVN-09 TOCTOU-narrowing
     `refuseOnToolDrift` at entry (`internal/mcp/runtime/execute.go`) and refuses a tool
     that was ALREADY stale before dispatch, before `p.executor.Execute`. The evaluator's
     `WOULD_FAIL_STALE_DECISION` is therefore reachable for drift that occurs AFTER the
     entry check (between it and the side-effect boundary — the `ToolStillCurrent`
     re-check), but the initial-drift case is runtime-refused and produces no Shadow event.

   Routing these two signals into Shadow evaluation (so a Shadow evaluation records the
   `WOULD_FAIL_*` evidence while enforcing modes keep their fail-closed block) is a
   runtime-dispatch change on security-sensitive control flow — and for drift it must not
   weaken the OVN-09 narrowing that runs before the executor for enforcing modes. It is
   therefore deferred to the separately-reviewed Shadow-activation composition slice, not
   this architecture-only increment (execution is disabled; nothing here runs in
   production). Tracked as `SHADOW-EVIDENCE-ROUTING-1` in
   `docs/engineering/TECHNICAL-DEBT-REGISTER.md`.

Neither the allowance nor the `Server.Usable()` limitation can produce a real side effect,
a hidden policy block, or a `WOULD_EXECUTE` for a policy-denied action (§8 invariant,
pinned by `TestShadow_PreservesPolicyVerdictSeparately`); the two routing gaps above only
mean certain fail-closed rejections are recorded by the runtime's own rejection path rather
than as a `shadow_evaluated` event.

## 14. Posture answers (task 24 anchor)

```
Can Observe perform upstream side effects?      NO   (no executor composed)
Can Shadow perform upstream side effects?       NO   (Layer A: no execute path; Layer B DONE: ShadowEvaluator holds no upstream client and no materialize-capable broker — structural reflection + AST gates)
Can Shadow materialize real credentials?        NO   (Plan-only; Materialize structurally unreachable)
Is a production Executor armed?                 NO   (arming hooks uncalled; AST wall)
Is Shadow currently enabled?                    NO
Is Canary enabled?                              NO
Is Production enabled?                           NO
Was any real upstream side effect performed?    NO
```
</content>
