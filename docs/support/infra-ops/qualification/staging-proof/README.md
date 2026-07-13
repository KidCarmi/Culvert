# Stage 1 — Reviewable Staging Proof (deployment evidence)

- **What this is:** a **local, synthetic, offline, $0 reference implementation** of the approved proof-slice control loop (`../../proof-slice/`), built to produce *reviewable evidence* for the qualification board — not a cloud deployment.
- **Honesty statement (required for enterprise credibility):** this harness does **not** deploy to any cloud provider, uses **only synthetic data**, holds **no production credentials**, touches **no customer evidence, production DNS, or paid resources**, and is **not connected to any production system**. It stands in: SQLite for Postgres, an in-process `MockProvider` for Fly.io Machines + OpenTofu apply, HMAC-SHA256 for Ed25519/KMS signing. It faithfully executes the *state machine, policy engine, single mutation spine, plan-bound approval, validation, rollback, and signed audit* so reviewers can judge behavior, not just prose.
- **Reproduce:** `python3 tac_proof.py demo` (13 demonstrations) · `python3 tac_proof.py failtest` (16-case matrix) · `python3 tac_proof.py show OP-…` (reconstruct an op post-session) · `python3 tac_proof.py cli-restart <idem>` (AI-unavailable path).

---

## 1. Deployment topology (proof harness)

```
tac_proof.py  (single process; == gateway+operation-svc+policy+approval+executor+validator+audit+tacctl)
   ├── SQLite  evidence/tac_proof.db          → operation-state DB (operations, plans, approvals,
   │                                             leases, operation_events[signed,hash-chained], execution_results)
   ├── MockProvider (in-process)              → stateless worker runtime + OpenTofu-apply stand-in, fault-injectable
   └── synthetic worker registry              → 1 allowlisted worker, 2 approved digests, known-good target
Components represented (all in the approved design): TAC web console (text render), TAC API (CLI verbs),
operation-state DB, policy engine, approval workflow, deterministic executor, validator, rollback workflow,
audit history, MCP/typed-tool gateway (CLI stand-in), tacctl fallback, one stateless analysis worker,
mock object storage (digest registry), mock customer cases/bundles (synthetic op intents).
```

## 2. The 13 required demonstrations — RESULT: all pass (`evidence/run.log`)

| # | Demonstration | Evidence |
|---|---|---|
| 1 | Inspect worker state | worker healthy, allowlisted, running known-good digest |
| 2 | Request safe restart (L2) | op created (e.g. `OP-2026-…`), kind=restart level=L2 |
| 3 | Enforce deterministic policy | `policy passed=True 13/13 rules` |
| 4 | Execute through single mutation spine | executor-only; EXECUTION_QUEUED→EXECUTING |
| 5 | Validate with synthetic job | 5/5 gates (health, digest-invariant, synthetic lease + task, audit) |
| 6 | Request new worker version (L3) | op kind=deploy level=L3 |
| 7 | Produce an exact plan | `PLAN-…` content-addressed, signed, policy_passed |
| 8 | Plan-bound human approval | **self-approval by author REJECTED**; independent human (`bob`) approval bound to plan signature |
| 9 | Deploy approved image digest | running digest → new; validation 9/9 gates |
| 10 | Detect failed validation | bad digest → failing gates `[V1_health, V3_synthetic_lease, V4_synthetic_task]` |
| 11 | Roll back to previous known-good | reverse-deploy → `ROLLED_BACK`, running digest restored |
| 12 | Preserve operation after session ends | **new process** reconstructs op from DB; `audit_chain_valid=True` |
| 13 | Same workflow via `tacctl`, AI unavailable | CLI subprocess runs full L2 restart → `SUCCEEDED`, no AI |

Full signed audit trail for a deploy op is in `evidence/console_operation_view.txt` (9 events, CREATED→SUCCEEDED, hash-chain valid) and `evidence/audit_sample.json`.

## 3. Failure-injection matrix — RESULT: all 16 land in the specified state (`evidence/failure_matrix.md`)

Highlights: crash-before → `FAILED` (reconciler: no change); crash-after → reconciler reads provider truth → resumes `VALIDATING`; partial success & validation failure → auto reverse-deploy → `ROLLED_BACK`; rollback failure / prev image gone → `MANUAL_INTERVENTION_REQUIRED`; stale approval & post-approval plan change → **execute REJECTED** (`APPROVAL_PENDING`); unapproved digest → `POLICY_REJECTED (P4)`; duplicate request → same op (idempotency); concurrent op → second blocked on worker lease; prompt injection → **inert** (no mutating tool, human gate); AI unavailable → `SUCCEEDED` via `tacctl`.

## 4. Measured numbers (`evidence/metrics.json`)

| Metric | Value | Note |
|---|---|---|
| Restart time | ~0.15 s | dominated by mock restart delay; real provider larger |
| Deploy time | ~0.30 s | mock apply delay; real image swap = seconds |
| Rollback time | ~0.30 s | reverse-deploy of known-good |
| Operations persisted | 4 (demo) + 16 (failtest) | each fully reconstructable post-session |
| Resource footprint | 1 process + SQLite; peak RSS < 40 MB | local sim only |
| Estimated monthly cost (pilot) | **$0** | offline; no cloud/paid resource |

**Latency caveat (stated plainly):** these are control-plane orchestration timings in a local simulation; they measure the *spine's* overhead (sub-millisecond DB + FSM per transition) plus a synthetic provider delay. They are **not** a claim about real cloud deploy/rollback latency, which is dominated by provider image-pull/health-gate time (seconds).

## 5. Evidence index (`evidence/`)

| File | Contents |
|---|---|
| `run.log` | full transcript of the 13 demonstrations |
| `operations.json` | every operation + its signed event chain (audit) |
| `audit_sample.json` | one deploy op's full record (chat-independent) |
| `console_operation_view.txt` | rendered operation timeline (screenshot stand-in) |
| `failure_matrix.md` / `.json` | the 16-case results |
| `metrics.json` | timings, footprint, cost |

## 6. What this proof does and does NOT establish

**Establishes (behaviorally, not just on paper):** the single mutation spine, deterministic policy gate + rejection, content-addressed signed plans, plan-bound approval with self-approval rejection, validation that does not trust provider-200, explicit reverse-deploy rollback + `MANUAL_INTERVENTION_REQUIRED`, hash-chained signed audit reconstructable after the session, idempotency + per-worker lease concurrency, and full AI-independent operation via `tacctl`.

**Does NOT establish (and is not claimed):** real provider integration, OpenTofu state-backend locking under contention, Ed25519/KMS signing, real OIDC credential minting, multi-node HA, network partitions, real object storage, or production latency/scale. Those are Stage-4 phase concerns and are called out in the reviewer findings and evolution architecture.
