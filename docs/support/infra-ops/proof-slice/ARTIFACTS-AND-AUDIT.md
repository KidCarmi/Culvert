# Proof Slice — Plan Artifact, Approval Artifact & Audit Schema

- **Status:** Design (implementation-ready).
- **Rule:** the executor may apply **only the exact approved artifact**. A new plan or a changed commit invalidates prior approval. Approval is bound to the plan **cryptographically** — a generic "yes" cannot approve.

---

## 1. Plan artifact (`plans` row; signed body)

```jsonc
{
  "plan_id": "PLAN-9f2c1a7b4d3e",                 // = "PLAN-" + sha256(canonical_body)[:12]
  "op_id": "OP-2026-000042",
  "kind": "deploy",                                // or "restart"
  "environment": "staging",
  "worker_id": "tac-analysis-worker-1",
  "commit_sha": "a1b2c3…",                         // desired-state commit (deploy); null for restart
  "config_digest": "sha256:…",                     // sha256 of the rendered worker config
  "provider_lock_digest": "sha256:…",              // sha256 of .terraform.lock.hcl (deploy)
  "target_image_digest": "sha256:…",               // approved digest (deploy)
  "expected_changes": {                            // parsed `tofu plan -json` (deploy)
    "create": 0, "delete": 0, "update": 1,
    "resources": [ { "address": "module.workers.tac_analysis_worker.machine",
                     "action": "update", "field": "image", "from": "sha256:old", "to": "sha256:new" } ]
  },
  "policy_result": { "passed": true, "rules": [ { "id": "P1", "pass": true }, … ] },
  "review_results": { "security": { "verdict": "OK" }, "cost": { "delta_usd": 0 } },
  "rollback_target": { "commit_sha": "prev…", "image_digest": "sha256:known-good", "config_digest": "sha256:…" },
  "cost_delta_usd": 0,
  "health_validation": true,                        // P14 marker
  "created_at": "2026-07-13T10:00:00Z",
  "expires_at": "2026-07-13T10:15:00Z",             // ≤ now()+15m
  "signer_key_id": "plan-signer-kms-v1"
}
```
- **Canonicalization:** the body is serialized deterministically (sorted keys, no whitespace) before hashing/signing.
- **`plan_id` is content-addressed** — any field change yields a different `plan_id` (and thus a different approval target).
- **Signature:** Ed25519 over `canonical_body`, key held in KMS, produced by the **planner service** (not Claude). `plans.signature`.
- **`expected_changes`** for `restart` is `{ "action": "restart", "worker_id": "…", "version_invariant": true }` (no desired-state change).

---

## 2. Approval artifact (`approvals` row)

```jsonc
{
  "approval_id": "APPROVAL-7f3a…",
  "op_id": "OP-2026-000042",
  "plan_id": "PLAN-9f2c1a7b4d3e",
  "bound_plan_signature": "<the exact plans.signature at approval time>",   // BINDING
  "approver": "human:alice",
  "approver_is_author": false,                     // MUST be false (approver ≠ plan author)
  "dual_required": false,                          // true for dual-approval classes (not this slice)
  "second_approver": null,
  "decision": "APPROVED",
  "created_at": "2026-07-13T10:03:00Z",
  "expires_at": "2026-07-13T10:15:00Z",            // inherits plan expiry
  "single_use_consumed": false,
  "approver_signature": "<Ed25519 by the approver's session identity over {op_id,plan_id,plan_signature,decision}>"
}
```

**Binding rules (enforced by the executor before any mutation):**
1. `approval.plan_id == op.current_plan_id` AND `approval.bound_plan_signature == plans.signature` for that plan **right now** — if the plan was regenerated (new commit/config), the stored signature differs → approval invalid.
2. `now() < approval.expires_at` AND `now() < plan.expires_at` — stale approval rejected.
3. `approval.approver_is_author == false`; for dual classes, two distinct approvers.
4. `single_use_consumed == false` → set true in the same txn as EXECUTION_QUEUED→EXECUTING (single-use).
5. The commit_sha in the plan still resolves to the same tree (no post-approval commit drift).

A "yes" in an unrelated chat cannot satisfy any of these — approval is a signed record over the exact plan signature, minted by the human's approval session, not a chat message.

---

## 3. Audit schema (`operation_events` — the chat-independent record)

Every operation produces a hash-chained, signed event stream. Reconstructable with **zero** access to the original chat.

```jsonc
{
  "op_id": "OP-2026-000042",
  "seq": 7,
  "ts": "2026-07-13T10:05:12Z",
  "actor": "executor:exec-2",
  "actor_kind": "service",                         // model | human | service
  "event_type": "execution.applied",
  "from_state": "EXECUTING", "to_state": "VALIDATING",
  "detail": {                                       // refs only, NEVER secrets
    "plan_id": "PLAN-9f2c1a7b4d3e",
    "approval_id": "APPROVAL-7f3a…",
    "commit_sha": "a1b2c3…",
    "applied_resources": [ { "address": "…machine", "outcome": "updated" } ]
  },
  "prev_hash": "…", "hash": "sha256(canonical(event)||prev_hash)",
  "signature": "<audit-writer Ed25519>"
}
```

**The full audit trail per operation captures** (one event each, minimum): created (with initiating_user + session_meta + intent), discovering, planning (with generated plan_id + commit_sha), policy decision (pass/reject + rules), reviewer results (security/cost), approvals (approver + bound signature), queued, execution started (executor identity + minted-cred metadata, no value), provider response (redacted), applied resources, validation result (per gate), succeeded/failed, rollback pending/started/result, cancelled/expired, manual_required. Every field needed to answer "what was requested, what was planned, who approved, what applied, did it validate, what happened" is present without the chat.

**Guarantees:** append-only (no UPDATE/DELETE grant); hash-chained (tamper-evident); signed by the audit writer's KMS key; `detail` redacted (refs, digests, identities — no secret values); exportable for compliance.

---

## 4. Human approval UX (minimal surface, plan-bound)

The approval service renders **from the plan artifact** (not from chat):

```
┌────────────────────────────────────────────────────────────────────┐
│  Approve operation OP-2026-000042                                   │
│  Requested outcome : deploy tac-analysis-worker-1 → v1.5.0          │
│  Environment       : staging          Resource: tac-analysis-worker-1│
│  Version before    : sha256:old…      after: sha256:new…            │
│  Plan changes      : 1 update (worker image); 0 create, 0 delete    │
│  Security impact    : OK (no IAM/exposure change)                    │
│  Expected cost      : $0.00                                          │
│  Rollback target    : sha256:known-good… (verified pullable)         │
│  Policy result      : PASS (P1–P17)                                  │
│  Reviewer findings  : security OK · cost OK                          │
│  Approval expires   : 2026-07-13 10:15 UTC (12 min)                  │
│  Plan fingerprint   : PLAN-9f2c1a7b4d3e                             │
│                                                                      │
│  [ Approve this exact plan ]   [ Reject ]                           │
└────────────────────────────────────────────────────────────────────┘
```

- The **Approve** button submits a signature over `{op_id, plan_id, plan_signature, decision}` from the approver's authenticated session — **structurally bound to the exact plan artifact** shown.
- If the plan is regenerated after this screen is opened, the fingerprint changes and the stale approval is rejected at execute time.
- The same surface is available via `tacctl op approve` (opens a signed-approval flow), so approval works without Claude.
- Approving requires the human-approver session; the operator/model session cannot render or submit this (self-approval structurally impossible).
