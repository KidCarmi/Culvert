# Proof Slice — MCP Tool Schemas, REST API & CLI Fallback

- **Status:** Design (implementation-ready).
- **Rule:** typed identifiers + server-side allowlists only. Claude passes **no** shell, tofu args, env, resource address, image registry, or provider config. The same operations are reachable via REST (`tacctl` CLI) so Claude is replaceable.

---

## 1. Typed identifier types (shared)

```
WorkerId        := enum resolved server-side from worker_registry (allowlisted, staging)   e.g. "tac-analysis-worker-1"
OperationId     := "OP-YYYY-NNNNNN"
PlanId          := "PLAN-<sha256[:12]>"
ApprovalId      := "APPROVAL-<uuid>"
ImageDigestRef  := enum resolved server-side from approved_image_digests (NOT a free string)
IdempotencyKey  := client-supplied opaque string (uuid recommended)
```
There is **no** field anywhere for a raw image string, registry URL, tofu argument, env var, resource address, or provider config. `deploy` chooses its target from `approved_image_digests` by an opaque `image_ref` token, never a digest the model types.

---

## 2. MCP tool schemas (9 tools)

```jsonc
// ── L0 reads ────────────────────────────────────────────────────────────────
{ "name": "get_platform_health",
  "input": {},
  "output": { "verdict": "ok|warn|fail", "components": [{ "name": "…", "status": "…" }] } }

{ "name": "get_worker_status",
  "input": { "worker_id": "WorkerId" },              // enum; unknown/ non-allowlisted → typed error
  "output": { "worker_id": "…", "environment": "staging", "running_image_digest": "sha256:…",
              "healthy": true, "replicas": 1, "current_plan_id": "PlanId|null",
              "known_good_digest": "sha256:…", "active_operation": "OperationId|null" } }

// ── L1/L2 create ─────────────────────────────────────────────────────────────
{ "name": "create_worker_restart_operation",      // L2 — may execute autonomously
  "input": { "worker_id": "WorkerId", "reason": "string", "idempotency_key": "IdempotencyKey" },
  "output": { "op_id": "OperationId", "kind": "restart", "level": "L2", "state": "CREATED",
              "poll_with": "get_operation" } }

{ "name": "create_worker_deployment_plan",        // L1 — produces a plan; executes NOTHING
  "input": { "worker_id": "WorkerId", "image_ref": "ImageDigestRef",  // opaque token → server maps to approved digest
             "reason": "string", "idempotency_key": "IdempotencyKey" },
  "output": { "op_id": "OperationId", "kind": "deploy", "level": "L3", "plan_id": "PlanId",
              "expected_changes": [ … ], "policy_result": { "passed": true, "rules": [ … ] },
              "review_results": { "security": "…", "cost_delta_usd": 0 },
              "rollback_target": { "image_digest": "sha256:…", "commit_sha": "…" },
              "impact": { "blast_radius": "low", "reversible": true, "affects_data": false },
              "expires_at": "…", "state": "REVIEW_PENDING|APPROVAL_PENDING|POLICY_REJECTED" } }

// ── read / lifecycle ─────────────────────────────────────────────────────────
{ "name": "get_operation",
  "input": { "op_id": "OperationId" },
  "output": { "op_id": "…", "kind": "…", "level": "…", "state": "…", "worker_id": "…",
              "current_plan_id": "…", "approvals": [ … ], "result": { … }|null,
              "events": [ { "seq": 1, "ts": "…", "actor": "…", "event_type": "…",
                           "from_state": "…", "to_state": "…" } ],   // the audit, chat-independent
              "rollback_target": { … }, "expires_at": "…" } }

{ "name": "approve_operation",                    // Claude may CALL to relay a human decision, but
  "input": { "op_id": "OperationId", "plan_id": "PlanId", "approval_id": "ApprovalId" },
  "output": { "op_id": "…", "state": "APPROVED|APPROVAL_PENDING", "bound": true } }
  // NOTE: approval_id is minted by the APPROVAL SERVICE for a human, bound to plan signature.
  // A tool call with a mismatched/expired/author-approver approval is rejected server-side.

{ "name": "cancel_operation",
  "input": { "op_id": "OperationId", "reason": "string" },
  "output": { "op_id": "…", "state": "CANCELLED|<unchanged-if-past-boundary>" } }

{ "name": "rollback_operation",
  "input": { "op_id": "OperationId", "reason": "string" },   // rolls back a prior SUCCEEDED/FAILED deploy
  "output": { "op_id": "…", "rollback_op_id": "OperationId", "state": "ROLLBACK_PENDING",
              "requires_approval": false } }                  // true if data-affecting (not in this slice)

{ "name": "validate_worker_deployment",           // read-only; re-runs/reports validation
  "input": { "op_id": "OperationId" },
  "output": { "op_id": "…", "gates": [ { "name": "health", "pass": true }, … ], "passed": true } }
```

**Schema fitness invariants (tested):** no input field is a free-form command/SQL/path/URL/registry/env/resource-address/secret; every create/mutate carries `idempotency_key`; `approve_operation` requires a server-minted `approval_id`; every output that touches state returns `op_id`. `TestToolSchemasTyped`, `TestNoFreeFormParams`.

---

## 3. REST API (the gateway's HTTP surface; MCP tools are thin wrappers over this)

| Method + path | Tool equiv | Auth | Level |
|---|---|---|---|
| `GET /v1/health` | get_platform_health | operator session | L0 |
| `GET /v1/workers/{worker_id}` | get_worker_status | operator | L0 |
| `POST /v1/operations` (kind=restart) | create_worker_restart_operation | operator | L2 |
| `POST /v1/operations` (kind=deploy) → returns plan | create_worker_deployment_plan | operator | L1 |
| `GET /v1/operations/{op_id}` | get_operation | operator | L0 |
| `POST /v1/operations/{op_id}/approve` | approve_operation | **human approver session** | L3 |
| `POST /v1/operations/{op_id}/cancel` | cancel_operation | operator | — |
| `POST /v1/operations/{op_id}/rollback` | rollback_operation | operator (human if data) | L2/L3 |
| `GET /v1/operations/{op_id}/validation` | validate_worker_deployment | operator | L0 |
| `POST /v1/operations/{op_id}/execute` | (executor-internal; triggered by APPROVED) | approval-gated | L3 |

Approval is a **separate human session** (the approval service UI/CLI), never the operator/model session — a model call cannot self-approve.

---

## 4. CLI fallback (`tacctl`) — proves Claude is replaceable

Every step is reproducible with no model, over the same REST API:

```bash
tacctl health
tacctl worker status tac-analysis-worker-1
tacctl op create restart --worker tac-analysis-worker-1 --reason "stuck leases" --idem $(uuidgen)
tacctl op plan deploy    --worker tac-analysis-worker-1 --image-ref v1.5.0 --reason "bump" --idem $(uuidgen)
tacctl op show OP-2026-000042                        # full state + events (audit), no chat needed
tacctl op approve OP-2026-000042 --plan PLAN-abc123 --as-human alice   # opens approval UX, binds to plan sig
tacctl op execute OP-2026-000042                     # only proceeds if APPROVED + plan valid
tacctl op validate OP-2026-000042
tacctl op rollback OP-2026-000042 --reason "regression"
tacctl op cancel  OP-2026-000042 --reason "abort"
```

`inspect / plan / approve / execute / validate / rollback` all have a `tacctl` verb. The failure-injection E2E (TESTING) drives the entire happy path **and** every fault via `tacctl` with no model in the loop — the AI-independence proof.

---

## 5. Authorization at the gateway

Every call: schema-validate → authenticate session (operator vs human-approver vs executor-internal) → policy-scope check (`environment=staging`, `worker_id ∈ allowlist`, tool ≤ session level) → rate-limit → attach/lookup op → dispatch. Out-of-scope (e.g. a non-staging worker, or a model session hitting `/approve`) → typed 403 + audit event, no side effect (failure exercises #15, self-approval).
