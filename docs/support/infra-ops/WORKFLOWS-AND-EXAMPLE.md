# Deployment, Rollback & Incident Workflows + Example Conversation

- **Status:** Proposed (design).
- **Depends on:** `MCP-GATEWAY.md`, `APPROVAL-STATE-AUDIT.md`.

---

## 1. Deployment workflow

```
1. Human: "deploy TAC staging with the new analysis-worker version"
2. Planner agent → plan_environment_deployment(env=staging, change_ref=…)
     → writes signed plan INFRA-2026-0042; returns diff + impact + rollback + cost/security notes
3. Security-review agent → analyze_security_impact(INFRA-2026-0042)  → OK / BLOCK
   Cost/quota agent      → analyze_cost_impact(INFRA-2026-0042)      → OK / BLOCK (free-tier check)
4. Claude presents to human: diff, blast radius, reversibility, rollback method, cost delta
5. Human approves (staging = single approval) → APPROVAL-… recorded, signed
6. Claude → apply_approved_plan(INFRA-2026-0042, APPROVAL-…, idempotency_key)
     → executor verifies plan signature + approval + scope → leases env → tofu apply <saved plan>
7. Executor-liaison narrates from op state (get_deployment_status polling)
8. Validation agent → validate_deployment(INFRA-2026-0042) → health-gate, smoke checks
9. Terminal: SUCCEEDED (audited) — or FAILED → auto-rollback path (§2)
```

Invariants: apply is only ever of a **previously reviewed, signed** plan (step 2 output = step 6 input); the executor, not Claude, applies; every step is audited; the op is resumable by ID at any point.

## 2. Rollback workflow

```
Trigger: validate_deployment fails, or human requests rollback
1. Claude → rollback_deployment(op_id) → the executor:
     - if reversible & no data change: apply the prior known-good signed plan (revert-plan)
     - if data-affecting: requires L3 approval (dual if over newer data) before proceeding
2. Reconciler confirms actual state == prior known-good (drift check)
3. Validation agent confirms health restored
4. Op transitions ROLLING_BACK → ROLLED_BACK; audited
Fallback (rollback unavailable, failure exercise #16): executor marks op FAILED-UNRECOVERED,
   raises incident, pages human; Claude produces a manual remediation plan (L1) for human execution.
```

## 3. Incident workflow

```
1. Alert or drift → Incident agent → enter_incident_mode (L2): sets platform incident state, pages
2. L0 sweep: get_platform_health, get_job_states, detect_infrastructure_drift, get_logs (redacted)
3. Incident agent correlates → proposes remediation:
     - reversible/safe → L2 tool (retry_analysis_job, recover_expired_job_leases, restart_stateless_worker,
       pause_failing_consumer, disable_new_bundle_uploads) executed autonomously + audited
     - high-impact → plan_remediation (L1) → review gates → human approval (L3) → apply
4. Claude drafts customer/status comms (L1) → human approves before send (L3)
5. Resolution → exit incident mode; post-incident report (L0/L1) with timeline from audit log
Fallback without AI (failure exercise #18): every L2 action + the incident runbook are executable
   by a human via the same gateway CLI; paging + the deterministic incident state machine run without Claude.
```

---

## 4. Example conversation (the target experience, end-to-end)

> **Owner:** Deploy TAC staging with the new analysis-worker image.

**Claude (Planner):** Reading current staging state…
`get_environment_inventory(staging)` → 3 workers @ v1.4.0, R2 buckets present, Postgres @ migration 019.
Generating a plan for the worker image bump to v1.5.0.
`plan_environment_deployment(env=staging, change_ref=feat/worker-1.5.0)` →

> **Plan INFRA-2026-0042** (staging)
> - **Diff:** `analysis_worker` image v1.4.0 → v1.5.0 (rolling, 3 replicas); no DB, DNS, or IAM change.
> - **Blast radius:** low. **Reversible:** yes (revert-plan to v1.4.0). **Affects data:** no.
> - **Rollback:** re-apply prior signed plan INFRA-2026-0041 (v1.4.0).
> - **Cost delta:** $0 (within free tier). **Security delta:** none (no IAM/exposure change).
> Independent review: security-review = OK, cost/quota = OK (free-tier headroom 61%).
> This is Level 3 (deployment). Staging requires **single approval**. Approve?

> **Owner:** Show me the exact diff first.

**Claude:** `get_deployment_status(INFRA-2026-0042)` (plan view) →
```
~ module.workers.analysis_worker.image  "…:v1.4.0" -> "…:v1.5.0"
  strategy: rolling  max_surge: 1  health_gate: /ready 200 within 60s
(no other resources change)
```
No secrets, DNS, IAM, or storage touched. Ready when you are.

> **Owner:** Approved.

**Claude:** Recording approval… `APPROVAL-7731` (owner, single, signed).
`apply_approved_plan(INFRA-2026-0042, APPROVAL-7731, idempotency_key=…)` → op **APPLYING**, executor-2 holds the staging lease.

**Claude (Executor-liaison, polling `get_deployment_status`):**
- 00:03 replica 1/3 → v1.5.0, /ready 200 ✓
- 00:14 replica 2/3 → v1.5.0, /ready 200 ✓
- 00:25 replica 3/3 → v1.5.0, /ready 200 ✓ → **APPLIED**

**Claude (Validation):** `validate_deployment(INFRA-2026-0042)` → all 3 workers healthy, queue draining normally, error rate nominal. Op **SUCCEEDED**. Audit: `audit/INFRA-2026-0042` (plan, review, approval, apply log, validation) signed.

> **Owner:** Something's off — one worker looks unhealthy now.

**Claude:** `get_job_states()` + `get_logs(component=analysis_worker, redacted)` →
worker-2 is failing extract jobs with lease timeouts; workers 1 and 3 healthy. This is a **stateless** worker → Level 2 safe action available.
`restart_stateless_worker(worker-2, idempotency_key=…)` (L2, autonomous, audited) → worker-2 rolling restart, /ready 200 ✓. `recover_expired_job_leases()` → 4 stuck leases reclaimed and re-enqueued. Queue recovering. If it recurs, I'll propose a rollback.

> **Owner:** It recurred. Roll back.

**Claude:** v1.5.0 is the regression; rollback is reversible and data-safe.
`rollback_deployment(INFRA-2026-0042)` → executor re-applies prior signed plan INFRA-2026-0041 (v1.4.0), rolling. Reconciler confirms actual == v1.4.0 known-good.
`validate_deployment` → 3/3 healthy on v1.4.0, error rate nominal. Op **ROLLED_BACK** (audited). I've filed a drift-free note and a Level-1 remediation plan for the v1.5.0 defect for engineering; no production impact (staging only). Want the post-incident summary?

---

## 5. What this example demonstrates

- Claude **inspects state → plans → presents impact + rollback → (human approves) → executor applies → Claude validates → all audited** — the exact target experience.
- Claude never touched a provider API, a secret, or a shell; it called typed tools.
- The one autonomous action (restart stateless worker) was L2, reversible, and audited; every state-changing deploy/rollback was L3 with human approval.
- Everything is addressable by op ID (`INFRA-2026-0042`) — a dropped session resumes with `get_deployment_status`, not chat memory.
