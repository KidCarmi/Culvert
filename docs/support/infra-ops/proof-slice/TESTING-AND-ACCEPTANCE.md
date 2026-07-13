# Proof Slice — Local E2E Topology, Failure-Injection Suite & Acceptance Criteria

- **Status:** Design (implementation-ready).
- **Goal:** prove the whole loop deterministically, including every failure, **with the AI out of the loop** (driven by `tacctl`), before the MCP surface is exposed to any live model.

---

## 1. Local E2E topology (docker-compose, no cloud, no cost)

```
test/e2e/compose.yaml:
  postgres            # the operation DB (schema.sql)
  gateway             # MCP + REST
  operation-svc       # FSM + leases + idempotency + reconciler + sweeper
  policy-svc          # deterministic rules
  approval-svc        # human-approval API (test drives it as a scripted "human")
  executor            # applies against the MOCK PROVIDER only
  validator           # runs V1–V9 against mock provider + a real local worker container
  audit-svc           # append-only signed events
  identity-broker     # mints short-lived FAKE creds (no real provider)
  mock-provider       # ★ fault-injectable stand-in for Fly/OpenTofu apply + machine API
  tac-analysis-worker # a REAL local container (so synthetic-job V3/V4 are genuine)
  redis-or-pg-queue   # staging analysis queue for synthetic jobs
  tacctl              # CLI, drives the whole suite WITHOUT any model
```

- **`mock-provider`** implements the provider/OpenTofu-apply contract and exposes fault switches: `crash_before_apply`, `crash_after_apply`, `partial_success`, `return_200_but_unhealthy`, `slow(>timeout)`, `image_unavailable`, `inject_drift`, `expire_creds`, `unavailable`. Toggled per test via an admin endpoint.
- **Real worker container** so V3 (lease a synthetic job) and V4 (complete a safe synthetic analyzer task) are genuine, not mocked — the validator actually watches a real worker lease + finish a job.
- **No model** in E2E: `tacctl` issues every step. A separate contract test exercises the MCP tools, but correctness is proven model-free.

---

## 2. Happy-path E2E (must pass first)

```
E2E-1 restart (L2):  tacctl op create restart → CREATED…EXECUTING(restart)…VALIDATING(V1-V4,V8)…SUCCEEDED
E2E-2 deploy (L3):   tacctl op plan deploy → APPROVAL_PENDING → tacctl op approve (scripted human, plan-bound)
                     → EXECUTION_QUEUED → EXECUTING(tofu apply saved plan) → VALIDATING(V1-V9) → SUCCEEDED
E2E-3 rollback:      force V1 fail on a new digest → FAILED → ROLLBACK_PENDING → ROLLING_BACK → ROLLED_BACK
E2E-4 audit-after:   kill gateway+all model context; `tacctl op show <id>` reconstructs the full story from DB
```

---

## 3. Failure-injection suite (16 cases; each asserts persisted state + recovery)

| # | Injected fault | Expected persisted state | Recovery path |
|---|---|---|---|
| 1 | **chat disconnect during planning** | op in PLANNING/REVIEW_PENDING; plan persisted | reconnect → `get_operation` resumes; plan intact |
| 2 | **chat disconnect during execution** | op continues EXECUTING in executor; lease held | reconnect → `get_operation` shows live state; no loss |
| 3 | **duplicate execution request** (same idem key) | one op; second `create/execute` returns the existing op | idempotency UNIQUE + CAS; no double apply |
| 4 | **stale approval** (approval past expiry) | execute rejected; op stays APPROVAL_PENDING/EXPIRED | new approval required; audit records rejection |
| 5 | **plan changes after approval** (commit drift) | execute rejected (plan_id/signature mismatch) | re-plan → new plan_id → new approval |
| 6 | **policy rejection** (e.g. non-$0 or extra resource) | op → POLICY_REJECTED (terminal) with rule id | operator revises input; new op |
| 7 | **executor crash before provider call** | lease expires; reconciler finds NO provider change | op → FAILED; safe re-apply of same plan |
| 8 | **executor crash after provider call** | lease expires; reconciler reads provider truth = applied | op → VALIDATING (resume) or PARTIAL → resolve |
| 9 | **partial provider success** | `applied_resources` mixed; V2 fails | FAILED → ROLLBACK_PENDING → reverse-deploy → ROLLED_BACK |
| 10 | **validation failure** (unhealthy new digest) | VALIDATING → FAILED (lease held) | ROLLBACK_PENDING → ROLLING_BACK → ROLLED_BACK |
| 11 | **rollback failure** (reverse apply/validate fails) | ROLLING_BACK → **MANUAL_INTERVENTION_REQUIRED** | paged; human via `tacctl`; full audit; lease released |
| 12 | **concurrent op on same worker** | second op blocked on worker apply-lease | serialized; second re-checks preconditions (may EXPIRE/re-plan) |
| 13 | **malicious log prompt injection** | no tool mutates; at worst a *proposed* plan | plan (if any) hits policy + human gate; injection inert; audited |
| 14 | **expired credentials** (broker creds lapse mid-apply) | apply fails cleanly; op → FAILED (crash-after-like) | reconciler resolves applied set; re-mint + safe re-apply |
| 15 | **provider unavailable** | apply errors; op → FAILED; no partial | retry same saved plan when provider returns; or CANCEL |
| 16 | **AI unavailable** | none — `tacctl` performs inspect/plan/approve/execute/validate/rollback | platform fully operable; model-independence proven |

Every case is a deterministic test with the mock-provider fault toggled, asserting: (a) the exact `operations.state`, (b) the `operation_events` chain, (c) `execution_results.applied_resources`, (d) lease released/held correctly, and (e) the documented recovery reaches a clean terminal state.

---

## 4. Acceptance criteria (all required)

**Functional**
- [ ] E2E-1..E2E-4 pass.
- [ ] All 16 failure cases land in the specified persisted state and recover as specified.
- [ ] `tacctl` reproduces inspect/plan/approve/execute/validate/rollback with **no model** (case 16).
- [ ] `get_operation`/`tacctl op show` fully reconstructs an operation from the DB after the chat/session is destroyed.

**Safety (structural, tested)**
- [ ] `TestNoFreeFormParams` / `TestToolSchemasTyped` — no shell/SQL/tofu-args/env/resource-address/registry/provider/secret param exists.
- [ ] `TestNoSelfApproval` — a model/operator session cannot approve.
- [ ] `TestApprovalBoundToPlan` — a stale or mismatched approval cannot execute (cases 4, 5).
- [ ] `TestExecutorVerifiesSigApproval` — executor refuses unsigned/unapproved/expired plans.
- [ ] `TestPolicyBranchCoverage` — every policy rule P1–P17 has a pass and a fail test.
- [ ] `TestNoSecretCrossesToolBoundary` — no secret value returned by any tool; creds only in executor.
- [ ] `TestConcurrencyNoDoubleApply` — cases 3, 12.
- [ ] `TestReconcilerResolvesCrash` — cases 7, 8.
- [ ] `TestManualInterventionTerminal` — cases 9(fail), 11 land in MANUAL_INTERVENTION_REQUIRED with lease released + audit.

**Audit**
- [ ] Audit is append-only, hash-chained, signed, redacted; a compliance export is human-readable without the chat.
- [ ] Every state transition produced exactly one signed event (verified by seq continuity).

**Operational**
- [ ] Executor is the only component with provider mutate creds; creds are ≤15m and op-scoped.
- [ ] Provider-200 alone never yields SUCCEEDED (V-gates enforced) — a `return_200_but_unhealthy` fault yields FAILED.

---

## 5. Test taxonomy & where it lives

| Layer | Location | What |
|---|---|---|
| Unit | each `services/*/**_test.go` | FSM transitions, policy rules, signing, binding, lease CAS |
| Contract | `test/integration/` | tool schema fitness; REST ⇄ MCP parity; approval-binding |
| E2E | `test/e2e/` | happy path via `tacctl` on the compose topology |
| Failure | `test/failure/` | the 16-case matrix, one test per case, mock-provider faults |

CI gate order: unit → contract → E2E → failure. The MCP surface is **not** exposed to a live model until the failure suite is green — the model only ever drives a loop already proven safe by `tacctl`.
