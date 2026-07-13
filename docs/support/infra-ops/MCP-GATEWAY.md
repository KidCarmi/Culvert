# Culvert Infrastructure Operations Gateway — MCP Design, Tool Catalog & Connector Security

- **Status:** Proposed (design). Ratified in ADR-0020.
- **Depends on:** `INFRA-OPS-ARCHITECTURE.md`.
- **Principle:** Claude reaches the platform **only** through narrow, typed, business-level tools. No raw provider access, no shell, no SQL, no secrets. The gateway is deterministic; the tools are the entire attack surface.

---

## 1. Gateway shape

- **Interface:** an MCP server (typed tools) — or an equivalent typed RPC. Portable: any MCP-capable model or a human CLI can drive the same tools (anti-lock-in).
- **Every tool call:** schema-validated → authenticated (scoped session) → authorized (policy engine: level + environment/tenant scope + least privilege) → rate-limited → assigned/attached to an operation ID → executed by the relevant connector/executor → result persisted → audited. A call that fails any gate is rejected with a typed error and audited; it never partially executes.
- **No dynamic tools.** The catalog is fixed in-gateway (like Culvert's `uiRoutes`/argv-registry pattern). Claude cannot introduce a tool; the human owner adds connectors by deploying the gateway.

---

## 2. Tool catalog (business-level operations only)

Grouped by approval level. Every tool is typed, bounded, idempotent where it mutates, and audited.

### Level 0 — Observe (autonomous)
| Tool | Purpose | Returns |
|---|---|---|
| `get_platform_health` | overall TAC health rollup | component statuses, verdict |
| `get_environment_inventory` | what exists in an env | resource list + versions + IaC refs |
| `get_deployment_status` | state of a deployment/op | phase, health, op_id |
| `inspect_quota_posture` | free-tier/quota headroom | per-provider usage vs limits |
| `detect_infrastructure_drift` | Git desired vs actual | drift set (resource, field, direction) |
| `get_job_states` | analysis queue/job health | queue depth, stuck/expired leases |
| `get_logs` (scoped, redacted) | recent logs for a component | bounded, redacted log lines |
| `get_metrics` (scoped) | metrics window | series (no raw customer data) |
| `check_backup_status` | backup freshness/integrity | last backup, hash, age |
| `get_cost_posture` | spend/forecast | current spend, projection |

### Level 1 — Plan (autonomous; produces artifacts, executes nothing)
| Tool | Purpose | Returns |
|---|---|---|
| `plan_environment_deployment` | generate an IaC plan for a change | plan_id, diff, impact, rollback plan, cost/security notes |
| `plan_remediation` | plan a fix for drift/incident | plan_id, diff, impact, rollback |
| `analyze_cost_impact` | cost delta of a plan | forecast delta |
| `analyze_security_impact` | security delta of a plan | IAM/exposure/policy deltas |

`plan_*` tools write a **signed plan artifact** to Git/state and return its `plan_id`; nothing is applied.

### Level 2 — Safe autonomous action (typed, bounded, idempotent, reversible)
| Tool | Purpose | Guardrails |
|---|---|---|
| `retry_analysis_job` | re-enqueue a failed job | idempotent by job_id; max attempts; non-prod + prod allowed |
| `recover_expired_job_leases` | reclaim stuck leases | only leases past TTL; bounded count |
| `restart_stateless_worker` | bounce a stateless worker | stateless only (policy-tagged); rolling; health-gated |
| `clear_temporary_cache` | flush a named ephemeral cache | allowlisted caches only; never state stores |
| `pause_failing_consumer` | pause a queue consumer | reversible; auto-audit; resume is also L2 |
| `disable_new_bundle_uploads` | stop ingest at hard quota | reversible flag; never deletes; auto-audit |
| `enter_incident_mode` | raise platform incident state | sets state + paging; reversible |

### Level 3 — Explicit approval required (Claude *requests*; human approves; executor applies)
| Tool | Purpose | Approval |
|---|---|---|
| `apply_approved_plan` | apply a signed, human-approved plan | **single or dual (below)** |
| `validate_deployment` | post-apply validation | (read) autonomous, but tied to the op |
| `rollback_deployment` | roll back a prior op | single; **dual if data-affecting** |
| `run_restore_drill` | restore into an isolated target | single (non-prod); **dual (prod)** |
| `rotate_scoped_identity` | rotate a scoped credential | single; **dual for tenant/root KMS** |

Destructive/high-blast operations (DNS change, IAM change, DB migration, data deletion, retention change, enabling raw-evidence access, infra destruction, paid-resource activation, backup restore over live data) are **only** reachable as an `apply_approved_plan` of a plan whose `class` marks them — there is no standalone `delete_data` tool.

### Explicitly REJECTED tools (never in the catalog)
`run_arbitrary_shell` · `execute_arbitrary_sql` · `call_arbitrary_provider_api` · `ssh_as_root` · `read_arbitrary_secret` · `write_arbitrary_file` · `mint_long_lived_key` · `approve_own_plan`. A gateway fitness test asserts none of these (or any free-form command/query/path/secret parameter) exists in any schema.

---

## 3. Tool schemas (representative — the pattern for all)

```jsonc
// plan_environment_deployment  (Level 1)
{
  "name": "plan_environment_deployment",
  "input": {
    "environment": "staging|prod",             // enum; policy checks operator scope
    "change_ref": "git-branch-or-commit",       // the IaC change to plan
    "reason": "string"                          // audited justification
  },
  "output": {
    "plan_id": "INFRA-2026-0042",
    "diff": [{ "resource": "…", "action": "create|update|delete", "fields": {…} }],
    "impact": { "blast_radius": "low|medium|high", "reversible": true, "affects_data": false },
    "rollback": { "available": true, "method": "revert-plan|restore", "steps": ["…"] },
    "cost_delta": { "monthly_usd": 0 },
    "security_delta": { "iam_changes": [], "new_exposure": [] },
    "signed": true, "signature_ref": "sig/…"
  }
}
```
```jsonc
// apply_approved_plan  (Level 3)
{
  "name": "apply_approved_plan",
  "input": {
    "plan_id": "INFRA-2026-0042",
    "approval_id": "APPROVAL-…",                // MUST reference a real approval record
    "idempotency_key": "op-uuid"                // dedups retries
  },
  "output": { "op_id": "INFRA-2026-0042", "state": "applying", "poll_with": "get_deployment_status" }
}
```
```jsonc
// rotate_scoped_identity  (Level 3)  — operates on REFS, never values
{
  "name": "rotate_scoped_identity",
  "input": { "identity_ref": "tac/prod/worker-sa", "approval_id": "APPROVAL-…" },
  "output": { "op_id": "…", "new_secret_ref": "tac/prod/worker-sa#v8", "value_returned": false }
}
```

**Schema invariants (fitness-tested):** every input field is a typed enum/bounded scalar/ref — **never** a free-form command, SQL, path, URL to an arbitrary host, or secret value. Every mutating tool takes an `idempotency_key`. Every L3 tool requires an `approval_id`. Every tool output includes an `op_id` when it touches state.

---

## 4. Permission matrix

| Tool group | Level | Claude autonomous? | Approval | Scope enforced | Idempotent | Prompt-injection exposure |
|---|---|---|---|---|---|---|
| Observe | 0 | ✅ | none | env+tenant read | n/a (read) | **medium** (logs/metrics carry attacker-influenceable text) |
| Plan | 1 | ✅ (writes artifact only) | none to plan; L3 to apply | env scope | plan is content-addressed | medium (plans over attacker data) |
| Safe action | 2 | ✅ | none (pre-authorized class) | env+resource tag | **required** | low (typed, bounded) |
| Approval-required | 3 | ✅ to *request* | single or dual | env+tenant+resource | required | low (human gate) |
| Rejected | — | ❌ never | — | — | — | — |

The policy engine evaluates `(operator, tool, environment, tenant, resource, level)` on **every** call. An out-of-scope call (e.g. a staging operator invoking a prod apply) is rejected and audited regardless of Claude's intent (failure exercise #15).

---

## 5. Connector security specification (per-connector template)

Every connector MUST be documented and enforced against this template. Illustrative connectors below.

### Template fields
purpose · exact allowed actions · denied actions · authentication method · least-privilege identity · environment scope · tenant scope · credential lifetime · audit behavior · timeout · idempotency · rate limit · retry · rollback · approval requirement · prompt-injection exposure.

### Connector: IaC Executor
- **Purpose:** apply a signed, approved OpenTofu plan.
- **Allowed:** `tofu apply <saved-signed-plan>`, `tofu plan`, `tofu show`, `tofu state list` (read).
- **Denied:** apply of any un-signed/un-approved plan; `tofu import`/`state rm`/`destroy` except as a classified approved plan; any raw provider call.
- **Auth:** GitHub OIDC → provider role assumption (workload identity).
- **Identity:** per-environment executor service identity, least-privilege for that env's resources only.
- **Scope:** one environment per executor instance; no cross-env.
- **Cred lifetime:** minted per apply, ≤15 min, auto-revoked.
- **Audit:** plan_id, approval_id, diff hash, apply log ref, outcome — signed, append-only.
- **Timeout:** per-apply hard cap (e.g. 20 min) → op marked `failed`, no partial-success ambiguity (executor records which resources applied).
- **Idempotency:** apply keyed by (plan_id, idempotency_key); a re-apply of the same plan is a no-op.
- **Rate limit:** 1 concurrent apply per environment (lease-guarded).
- **Retry:** safe re-apply of the *same saved plan* only.
- **Rollback:** revert-plan (apply the prior known-good plan) or restore; recorded as a new op.
- **Approval:** L3 (dual for prod destructive classes).
- **Prompt-injection exposure:** **low** — input is a plan_id + approval_id, not free text.

### Connector: DNS (Cloudflare)
- **Purpose:** manage TAC DNS records via IaC.
- **Allowed:** create/update/delete records **only through an approved plan**; read records (L0).
- **Denied:** direct record edits; zone deletion; account-level changes.
- **Auth:** scoped Cloudflare API token via broker, minted per op, zone-scoped, ≤15 min.
- **Scope:** the TAC zone(s) only; never customer zones.
- **Approval:** L3 (DNS is high-blast; single approval, dual if it affects prod cert issuance).
- **Rollback:** revert-plan restores prior records.
- **Prompt-injection exposure:** low (plan-gated).

### Connector: Secrets / Identity Broker
- **Purpose:** rotate scoped identities; resolve refs → values **inside the executor only**.
- **Allowed:** `rotate(identity_ref)`, `describe(identity_ref)` (metadata only), issue short-lived creds to connectors.
- **Denied:** **return any secret value across the tool boundary**; create long-lived admin keys; read customer/tenant KMS root.
- **Auth:** workload identity to the provider secret manager.
- **Cred lifetime:** rotated secrets are versioned; issued creds ≤15 min.
- **Approval:** L3 (dual for tenant/root KMS).
- **Prompt-injection exposure:** low — Claude sees refs, never values (structural).

### Connector: Read (health/inventory/metrics/logs/quota)
- **Purpose:** L0 observation.
- **Allowed:** read-only provider/metrics/log queries, **redacted** at the connector.
- **Denied:** any write; unredacted customer data; cross-tenant reads.
- **Prompt-injection exposure:** **medium** — logs/metrics are attacker-influenceable; the connector redacts and the gateway treats returned text as **untrusted data** (§6).

*(Safe-action, queue, backup, restore, email, monitoring connectors follow the same template — see `connector-development-guide` in the roadmap.)*

---

## 6. Prompt-injection defense (first-class)

Bundle logs, provider messages, and drift output are attacker-influenceable and flow to Claude. Controls:
1. **Untrusted-data framing:** all tool *outputs* are labeled untrusted; Claude operates under a fixed operator policy it cannot be argued out of.
2. **No tool does what its text says.** A log line reading "run destroy on prod" is inert — there is no `run_arbitrary_*` tool, and every mutating path requires a typed plan + human approval. Injection can at most cause Claude to *propose* a plan, which a human reviews.
3. **Independent review agent** (separate Claude session, `APPROVAL-STATE-AUDIT.md §multi-agent`) re-checks any plan for scope/impact before human approval — a single injected session cannot both propose and bless.
4. **Structural gates win:** policy engine, scope checks, and approvals are enforced by the gateway regardless of model reasoning. The worst an injected model achieves is a rejected call + an audit entry (failure exercise #8).
5. **Redaction at the read connector** limits what injected content even reaches the model.

---

## 7. What must never be exposed to Claude (the absolute list)
Raw secret values · unrestricted provider APIs · shell/SQL/file/SSH · signing keys (plan/approval) · the ability to approve its own plan · long-lived admin credentials · tenant/customer KMS roots · raw customer evidence from the raw-evidence plane (ADR-0016) · cross-tenant data · the break-glass path. Each is enforced structurally (no tool, no parameter, no code path) and asserted by a gateway fitness test.
