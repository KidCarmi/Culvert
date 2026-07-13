# Approval Model, Operation State Machine, Durability, Audit & Multi-Agent Gates

- **Status:** Proposed (design). Ratified in ADR-0021 (approval) and ADR-0022 (durable state).
- **Depends on:** `INFRA-OPS-ARCHITECTURE.md`, `MCP-GATEWAY.md`.

---

## 1. Four operating levels

| Level | Name | Claude may autonomously… | Executes change? | Gate |
|---|---|---|---|---|
| **L0** | Observe | read health/logs/metrics/deployments/quotas/job states; detect drift; produce reports | No | none |
| **L1** | Plan | create infra/deployment/remediation plans; cost & security impact; rollback plans | No (writes artifact only) | none to plan |
| **L2** | Safe autonomous action | retry job; recover expired lease; restart stateless worker; clear temp cache; pause failing consumer; disable uploads at hard quota | Yes — **predefined, typed, bounded, idempotent, reversible, audited** | pre-authorized class |
| **L3** | Explicit approval | production deploy; DNS; IAM; DB migration; data deletion; secret rotation; backup restore; retention change; enable raw-evidence access; security-policy change; infra destruction; paid-resource activation | Yes — **only after human approval**, executor applies | human approval (single or dual) |

**L2 boundary rule:** an action qualifies for L2 only if it is *reversible by construction* and *cannot affect data or cost*. Restarting a **stateless** worker qualifies; anything touching state/data/cost/security is L3. The gateway policy engine holds the L2 allowlist; Claude cannot promote an action to L2.

---

## 2. Dual approval in production

Some L3 actions carry irreversible or blast-radius risk that a single approver shouldn't clear alone. **Dual approval (two distinct human approvers, four-eyes) is required in production for:**

- infrastructure destruction / environment teardown
- data deletion (any) and retention reduction
- database migrations in prod
- backup **restoration over live/newer data**
- secret rotation of **tenant or root KMS** identities
- enabling **raw-evidence access** (ADR-0016 break-glass)
- security-policy changes that widen access
- disabling an audit or safety control

Single approval (one human) suffices in production for: standard app deploys, scaling within approved budget, DNS changes to TAC-owned zones, single-worker rollback, non-KMS scoped-identity rotation. **Non-prod:** single approval for all L3; dual never required (but drills that touch prod-like data still dual).

**The approver is never the plan's author (agent or human).** The plan-creating Claude agent cannot approve; the human who wrote a manual IaC change cannot be the sole approver of its apply in prod (needs a second human for dual-class actions).

---

## 3. Operation state machine (durable, outside the conversation — ADR-0022)

Every mutating operation is a durable record with a stable **operation ID** (`INFRA-YYYY-NNNN`). Chat memory is never authoritative; Claude reconstructs everything by reading the op record.

```
PROPOSED ──► PLANNED ──► REVIEW ──► APPROVAL_PENDING ──► APPROVED ──► APPLYING
   │            │           │             │                              │
   │            │           │             │                              ├─► APPLIED ──► VALIDATING ──► SUCCEEDED
   │            │           │             │                              │                   │
   │            │           │             │                              ├─► PARTIAL ─────────┘ (reconcile)
   │            │           │             │                              └─► FAILED ──► ROLLING_BACK ──► ROLLED_BACK
   └── any ─────┴───────────┴─────────────┴── REJECTED / CANCELLED / EXPIRED ───────────────────────────────────
```

**Record fields:**
```jsonc
{
  "op_id": "INFRA-2026-0042",
  "desired_state": { "plan_id": "…", "diff_hash": "…", "git_ref": "…" },   // what we intend
  "execution_state": "APPLYING",                                          // where we are
  "approval_state": { "required": "dual", "approvals": ["human:a","human:b"], "review_agent": "ok" },
  "class": "prod-db-migration",                                            // drives approval rules
  "reversible": true, "affects_data": true,
  "lease": { "holder": "executor-3", "expires_at": "…", "heartbeat_at": "…" },
  "idempotency_key": "op-uuid",
  "attempts": 1,
  "result": null,                                                          // set on terminal state
  "audit_ref": "audit/INFRA-2026-0042",
  "created_by": "claude:planner", "approved_by": ["…"], "applied_by": "executor-3",
  "created_at": "…", "updated_at": "…"
}
```

**Guarantees:**
- **Idempotency:** `apply_approved_plan(plan_id, idempotency_key)` is exactly-once per key; a retry after a dropped response returns the existing op, never a second apply.
- **Leases + heartbeats:** the executor holds a lease with a TTL and heartbeats; if it dies, the lease expires and a **recovery reconciler** (deterministic) inspects provider/IaC state to determine what actually applied (PARTIAL) and drives to SUCCEEDED or ROLLED_BACK — never leaves infra half-changed silently (failure exercises #6, #9, #10).
- **Cancellation:** an op in APPROVAL_PENDING/APPLYING can be `cancel`led; APPLYING cancellation is cooperative (the executor stops at the next safe boundary and records PARTIAL for reconciliation).
- **Result persistence:** terminal states persist a signed result; `get_deployment_status(op_id)` answers "what happened to INFRA-2026-0042?" **without any chat memory** — the core session-loss requirement.
- **Recovery after restart:** on Claude restart, it reconnects and reads op records; on executor restart, the reconciler resumes in-flight ops from the state DB + provider truth.

---

## 4. Session & state safety (chat is disposable)

| Concern | Design |
|---|---|
| Chat stops/restarts/loses context | all state in the op DB; Claude re-reads by op_id; no infra state in the conversation |
| "What happened to INFRA-2026-0042?" | `get_deployment_status` returns full lifecycle from the durable record |
| In-flight op when session drops | the op continues in the executor; leases/heartbeats govern; Claude re-attaches on return |
| Duplicate request after a dropped response | idempotency_key dedups; same op returned |
| Executor crash mid-apply | lease expiry → reconciler → PARTIAL resolution from provider truth |
| Two Claude sessions | per-environment apply lease → one applier; the other observes/queues (failure exercise #7) |

Claude is **stateless with respect to infrastructure**: it can be killed and restarted at any point and lose nothing, because it owns no authoritative state.

---

## 5. Audit model

- **Append-only, signed audit log** of every tool call: `{op_id, ts, actor (claude-agent-id | human | executor), tool, inputs (refs, no secrets), scope, level, policy_decision, approval_ids, result, signature}`.
- **Every decision is captured**, not just mutations: a rejected out-of-scope call, an excessive-permission request, a policy denial, and an approval/denial are all audited (failure exercises #1, #2, #15).
- **Signed + tamper-evident** (hash-chained), stored separately from operational data, exportable for compliance.
- **Human-attributable:** approvals record the approving human identity; dual approvals record both; break-glass records who/why/when with dual-control.
- **No secrets in audit** — inputs are refs; the same redaction discipline as the appliance (`REDACTION-MODEL.md`) applies to any free-form text.

---

## 6. Multi-agent operations & independent review gates

Separate Claude agents with separated duties, so no single agent both proposes and blesses a high-impact change:

| Agent | Role | May approve? |
|---|---|---|
| **Planner** | reads state, produces IaC plans, impact, rollback | ❌ never approves its own plan |
| **Security-review** | independent re-analysis of a plan (IAM/exposure/scope/least-privilege), adversarial | ❌ (advisory gate; can BLOCK) |
| **Cost/quota** | independent cost + free-tier impact of a plan | ❌ (advisory gate; can BLOCK on budget breach) |
| **Executor-liaison** | narrates apply progress from op state; does not apply | ❌ |
| **Validation** | post-apply validation, independent of the planner | ❌ |
| **Incident** | correlates, drafts runbook/comms, proposes L2 actions | ❌ (proposes; human approves L3) |

**Gate design:** Planner → (Security-review AND Cost/quota must not BLOCK) → **human approval** (single/dual by class) → deterministic executor applies → Validation confirms. The **executor is not an agent** — it is deterministic automation; agents never hold apply authority. A plan authored by the Planner and reviewed by an *independent* Security-review agent, then approved by a human, satisfies "the agent that creates a high-impact plan must not be the only agent that approves its safety." For dual-approval classes, the two independent human approvers are the final gate on top of the agent review.

**Concurrency across agents:** all agents share the durable op DB and the per-environment apply lease; parallel planning is fine, parallel applying to one environment is serialized by the lease.

---

## 7. Level → approval → dual-approval decision table

| Action class | Level | Approval (non-prod) | Approval (prod) |
|---|---|---|---|
| Read / report | 0 | none | none |
| Plan / impact | 1 | none | none |
| Retry job / recover lease / restart stateless / clear cache / pause consumer / disable uploads | 2 | none (pre-authorized) | none (pre-authorized) |
| App deploy / scale within budget | 3 | single | single |
| DNS (TAC zone) / non-KMS identity rotation / single-worker rollback | 3 | single | single |
| DB migration | 3 | single | **dual** |
| IAM change | 3 | single | **dual** |
| Data deletion / retention reduction | 3 | single | **dual** |
| Backup restore over live/newer data | 3 | single | **dual** |
| Tenant/root KMS rotation | 3 | single | **dual** |
| Enable raw-evidence access | 3 | **dual** | **dual** |
| Security-policy widen / disable a safety control | 3 | **dual** | **dual** |
| Infrastructure destruction / teardown | 3 | single | **dual** |
| Paid-resource activation | 3 | single | single (budget-scoped) |
