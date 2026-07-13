# Infra-Ops — Implementation Roadmap, Smallest Slice & Connector Order

- **Status:** Proposed (design). Do not implement until the responsibility split (`INFRA-OPS-ARCHITECTURE.md §4`) is confirmed.
- **Depends on:** all infra-ops docs + ADRs 0019–0022.
- **Sequencing principle:** build the **deterministic spine before any connector**, then the smallest E2E loop, then widen connectors read → plan → safe-action → approved-apply. Never expose a mutating connector before its test harness + security spec pass.

---

## 1. Milestones

| M | Theme | Ships | Level reached |
|---|---|---|---|
| **G0** | Spine | op-state DB + state machine, audit log, policy engine, identity broker (OIDC/workload id), approval service, Git+OpenTofu repo, executor skeleton (no connectors) | — |
| **G1** | Observe | MCP gateway + L0 read connectors (health/inventory/metrics/logs/quota/drift) | L0 |
| **G2** | Plan | `plan_*` tools → signed plan artifacts; independent security-review + cost agents | L1 |
| **G3** | Approved apply (1 resource) | `apply_approved_plan` for **one reversible resource type** (stateless worker deploy/scale) with human approval + validate + rollback | L3 (single) |
| **G4** | Safe actions | L2 connectors: retry job, recover lease, restart stateless worker, clear cache, pause consumer, disable uploads | L2 |
| **G5** | Widen infra | DNS, object storage, DB migrations (dual-approval), secrets rotation (overlap), backups, restore-drill | L3 (incl. dual) |
| **G6** | Incident + DR | enter_incident_mode workflow, DR runbook automation, drift auto-reconcile (low-impact L2) | L2/L3 |
| **G7** | Hardening | full failure-injection suite, dual-operator concurrency, break-glass, cost governance | production |

Each milestone: every new connector passes the test harness + has a filled security spec; every new tool has a schema fitness test; no milestone ships with a self-approval or secret-crossing path.

---

## 2. Smallest implementation slice that proves it E2E

**Prove the whole loop on one reversible resource, in staging only.**

Scope: G0 spine (op-state + audit + policy + broker + approval + Git/OpenTofu) + G1 read for that resource + G2 plan + G3 apply/validate/rollback for **`restart`/`redeploy` of a single stateless analysis worker** — plus the one L2 `restart_stateless_worker`.

This exercises, end-to-end: read state → plan → independent review → present impact/rollback → human approval → **deterministic executor applies a signed plan** → validate → durable op addressable by ID → rollback → full audit. It proves the four load-bearing claims (Git-authoritative, deterministic executor, durable state, structural gates) on the smallest possible surface, with a genuinely reversible, data-free, $0 resource. If this slice is safe and repeatable, the model generalizes; if it isn't, no wider build should proceed.

**Explicitly out of the slice:** DNS, DB, IAM, secrets, data, dual-approval, multi-provider — all deferred to G5+ once the spine is proven.

---

## 3. Exact connector-development order

1. **(spine, not a connector) identity broker + op-state DB + audit + policy engine + approval service** — nothing safe exists without these.
2. **Git/IaC read + plan connector** (OpenTofu `plan`/`show`/`state list`, read-only) — enables L0/L1 without any mutation.
3. **Read connectors:** health, inventory, metrics, logs (redacted), quota, drift — L0.
4. **IaC executor connector (apply of signed+approved plan), scoped to ONE resource type** — L3, the smallest apply.
5. **Safe-action connectors:** retry_analysis_job, recover_expired_job_leases, restart_stateless_worker, clear_temporary_cache, pause_failing_consumer, disable_new_bundle_uploads — L2.
6. **Object storage (R2) + worker/compute** connectors (plan-gated) — widen apply.
7. **DNS** connector (L3) — high-blast, plan-gated.
8. **Database migration** connector (L3, dual in prod, expand-contract policy).
9. **Secrets/identity rotation** connector (overlap, L3, dual for KMS).
10. **Backup / restore-drill** connectors (restore dual-approval, isolated-target).
11. **Email ingress/egress, monitoring/alerts** connectors.
12. **DR + drift-auto-reconcile** automation.

Order rationale: read before plan before safe-action before apply; least-blast before highest-blast; each step reversible/observable before the next. A connector is added only after the previous tier is proven and its own harness passes.

---

## 4. Acceptance bar per milestone

- Every tool schema passes the fitness tests (no free-form command/SQL/path/secret; mutating tools take idempotency_key; L3 tools require approval_id).
- Every connector passes the full test harness and has a filled security spec.
- The relevant failure exercises (§FAILURE-AND-THREAT) pass for the shipped surface.
- No self-approval, no secret-crossing, no long-lived key, no unsigned apply path exists.
- The platform remains fully human-operable via the same gateway CLI (fallback-without-AI holds).
