# Proof Slice — Operation State Machine

- **Status:** Design (implementation-ready).
- **Owner store:** `services/operation` (the ONLY writer of `operations.state`). All transitions are DB transactions with optimistic concurrency (`operations.version` CAS) + append to `operation_events` (audit) in the **same** transaction.

---

## 1. States

```
CREATED → DISCOVERING → PLANNING ─┬─→ POLICY_REJECTED (terminal)
                                  └─→ REVIEW_PENDING → APPROVAL_PENDING → APPROVED
APPROVED → EXECUTION_QUEUED → EXECUTING → VALIDATING ─┬─→ SUCCEEDED (terminal)
                                                      └─→ FAILED → ROLLBACK_PENDING → ROLLING_BACK ─┬─→ ROLLED_BACK (terminal)
                                                                                                    └─→ MANUAL_INTERVENTION_REQUIRED (terminal*)
Any non-terminal → CANCELLED (terminal) | EXPIRED (terminal)
EXECUTING/ROLLING_BACK on executor loss → (lease expiry) → reconciler → PARTIAL-resolve → {VALIDATING|ROLLBACK_PENDING|MANUAL_INTERVENTION_REQUIRED}
```
`MANUAL_INTERVENTION_REQUIRED` is terminal for automation but resolvable by a human via `tacctl` (which records a follow-on operation).

**L2 restart** path skips PLANNING's OpenTofu artifact: CREATED → DISCOVERING → PLANNING(action-plan) → policy → (no human approval needed; L2) → EXECUTION_QUEUED → EXECUTING(restart) → VALIDATING → SUCCEEDED. It has **no ROLLBACK** (restart is version-invariant); a failed restart → FAILED → MANUAL_INTERVENTION_REQUIRED (a human decides).

**L3 deploy** path uses the full FSM including human approval and rollback.

---

## 2. Transition table

Legend — Txn: DB transactional boundary; Idem: idempotency behavior; Lease: worker-apply lease; Recovery: what a reconciler does if the process dies here.

| From → To | Actor | Preconditions | Txn | Idem | Lease | Timeout | Retry | Audit event | Cancellation | Recovery after restart |
|---|---|---|---|---|---|---|---|---|---|---|
| ∅ → **CREATED** | operation-svc (from a `create_*` tool) | valid env=staging, worker in registry & allowlisted; `idempotency_key` unused | insert op + event | UNIQUE `idempotency_key`; dup returns existing op | none | — | — | `operation.created` | n/a | op row exists; safe |
| CREATED → **DISCOVERING** | operation-svc | op CREATED | CAS state + event | idempotent (re-enter reads state) | none | 10s | auto | `operation.discovering` | → CANCELLED | re-run discovery (read-only) |
| DISCOVERING → **PLANNING** | planner (via svc) | current worker state read; known-good digest present | CAS + event | plan keyed by (op_id) | none | 30s | auto | `operation.planning` | → CANCELLED | re-plan (pure over inputs) |
| PLANNING → **POLICY_REJECTED** | policy-engine | any policy rule fails | CAS + event + store policy_result | deterministic | none | 5s | none | `policy.rejected` | terminal | terminal; re-read |
| PLANNING → **REVIEW_PENDING** | policy-engine | all policy rules pass; plan signed | CAS + event + store plan | plan_id content-addressed | none | 5s | none | `policy.passed` | → CANCELLED | plan persisted; resume |
| REVIEW_PENDING → **APPROVAL_PENDING** | review agents (advisory) | security+cost reviews recorded (BLOCK stops here → back to a report, op stays REVIEW_PENDING) | CAS + event + store reviews | reviews keyed by plan_id | none | 60s | auto | `review.completed` | → CANCELLED | reviews persisted; resume |
| REVIEW_PENDING → **APPROVAL_PENDING** (L2) | operation-svc | op.level==L2 AND all structural preconditions pass | CAS + event | — | none | — | — | `approval.not_required` | → CANCELLED | resume |
| APPROVAL_PENDING → **APPROVED** | approval-svc (human) | valid approval bound to plan signature; not expired; approver≠author; dual satisfied if required | insert approval + CAS + event | approval single-use, plan-bound | none | **op.expires_at** | none | `operation.approved` | → CANCELLED | approval persisted; resume |
| APPROVED → **EXECUTION_QUEUED** | operation-svc | approved; plan not expired; commit unchanged | CAS + enqueue (durable) + event | enqueue keyed by op_id | none | — | auto | `operation.queued` | → CANCELLED | queue is durable; dedup on op_id |
| EXECUTION_QUEUED → **EXECUTING** | executor | **acquire worker lease** (TTL); verify plan sig+approval+commit+lock digests; mint short-lived creds | CAS + acquire lease + event | lease holder == op_id; re-entry no-op | **ACQUIRE** | apply hard cap (e.g. 10m) | safe re-apply of same saved plan only | `execution.started` | cooperative: stop at safe boundary → PARTIAL | lease expiry → reconciler reads provider truth |
| EXECUTING → **VALIDATING** | executor | provider apply returned (full or recorded-partial) | CAS + store provider_response + event | — | HOLD | — | — | `execution.applied` | → cancel disallowed once applying provider; marks PARTIAL | reconciler determines applied set |
| EXECUTING → **FAILED** | executor | apply error before/at provider | CAS + event | — | RELEASE | — | bounded re-apply of same plan | `execution.failed` | n/a | reconciler confirms no change (crash-before) or partial (crash-after) |
| VALIDATING → **SUCCEEDED** | validator | ALL validation gates pass (health+digest+synthetic-job+drift+audit+rollback-restorable) | CAS + store validation + release lease + event | — | RELEASE on success | validation cap (e.g. 5m) | validation retried within cap | `operation.succeeded` | n/a | re-run validation (read-only, idempotent) |
| VALIDATING → **FAILED** | validator | any gate fails | CAS + store validation + event | — | HOLD (for rollback) | — | — | `validation.failed` | n/a | resume at FAILED |
| FAILED → **ROLLBACK_PENDING** | operation-svc | op has rollback_target; op.kind==deploy | CAS + event | — | HOLD | — | — | `rollback.pending` | → MANUAL if cancel | resume |
| ROLLBACK_PENDING → **ROLLING_BACK** | executor | rollback_target digest available; (data-affecting? → require approval) | CAS + event | reverse-op keyed by op_id | HOLD | 10m | bounded | `rollback.started` | disallowed | reconciler resumes |
| ROLLING_BACK → **ROLLED_BACK** | validator | reverse-deploy validated to previous known-good | CAS + release lease + event | — | RELEASE | 5m | — | `operation.rolled_back` | n/a | re-validate |
| ROLLING_BACK → **MANUAL_INTERVENTION_REQUIRED** | executor/validator | rollback failed / previous image unavailable / drift blocks | CAS + release lease + event | — | RELEASE | — | none | `operation.manual_required` | n/a | terminal*; human via tacctl |
| any non-terminal → **CANCELLED** | user (or svc on expiry precheck) | not past EXECUTING-provider boundary | CAS + event | — | RELEASE if held | — | — | `operation.cancelled` | this IS cancel | terminal |
| any non-terminal → **EXPIRED** | operation-svc (sweeper) | now > op.expires_at | CAS + event | — | RELEASE if held | — | — | `operation.expired` | n/a | terminal |

---

## 3. Transactional & idempotency rules

- **One transaction per transition:** state CAS + audit event insert (+ artifact store) commit together. A crash between them is impossible; either the transition + its audit both happened or neither did.
- **Optimistic concurrency:** `UPDATE operations SET state=?, version=version+1 WHERE id=? AND version=?`. A losing writer re-reads and re-evaluates — two sessions cannot both advance the same op.
- **Idempotency key:** every mutating tool call carries a client `idempotency_key`; `operations.idempotency_key` is UNIQUE, so a retried `create_*`/`approve`/`execute` returns the existing outcome, never a duplicate.
- **Exactly-once apply:** the executor acquires the worker lease and checks the op is EXECUTION_QUEUED via CAS before touching the provider; a second executor sees the lease/held state and no-ops.

---

## 4. Leases, heartbeats, recovery

- **Worker lease** (`leases` row, key `staging:<worker_id>`): acquired at EXECUTION_QUEUED→EXECUTING, TTL (e.g. 90s), heartbeated by the executor. Serializes all mutation against one worker (concurrency guarantee #2).
- **Executor death:** lease stops heartbeating → expires → the **reconciler** (a deterministic operation-svc job) picks up ops stuck in EXECUTING/ROLLING_BACK past lease TTL, reads **provider truth + OpenTofu state**, and resolves: no change → FAILED (crash-before); partial → drive to VALIDATING/ROLLBACK per the applied set; complete → VALIDATING. Never leaves infra silently half-applied.
- **Claude/gateway death:** irrelevant — the op continues in the executor; Claude reconnects via `get_operation(op_id)`.
- **Sweeper:** a periodic job expires ops past `expires_at` and reclaims dead leases.

---

## 5. Concurrency: two chat sessions, one worker

| Scenario | Mechanism | Result |
|---|---|---|
| Two `create_worker_restart_operation` with same idempotency_key | UNIQUE key | one op; second returns it |
| Two different ops both try to EXECUTE on the same worker | worker apply lease | one EXECUTES; the other stays EXECUTION_QUEUED until release, then re-checks preconditions (may become stale → EXPIRED/re-plan) |
| Two writers race a transition | optimistic `version` CAS | one wins; loser re-reads |
| Two `approve_operation` for one op | approval single-use, plan-bound; CAS | first approval wins; second is a no-op returning APPROVED |

---

## 6. Cancellation & expiry semantics

- **Cancel** is honored in any state up to the EXECUTING→provider boundary. Once the executor has begun a provider mutation, cancel is cooperative: the executor finishes the current resource, records PARTIAL, and the op routes to reconciliation/rollback — never an abrupt half-apply.
- **Expiry** (`expires_at`, default e.g. 30m from CREATED, and separately the plan's own expiry) auto-terminates a stale op and invalidates its approval; a stale approval can never be applied (ARTIFACTS §approval-binding).
