# Culvert TAC Infrastructure Operations — Claude-as-Operator (Index & Final Decision)

Design-only evaluation and architecture for operating the **cloud-hosted TAC platform (Tier 3)** through a Claude conversation, with the human owner supplying connectors, policies, and approvals. **No implementation.** This concerns the *vendor's TAC cloud only* — never the on-prem Culvert appliance (Tier 1), which stays outbound-only and is never operable from any cloud (ADR-0014).

| # | Document | Purpose |
|---|---|---|
| 1 | [INFRA-OPS-ARCHITECTURE.md](INFRA-OPS-ARCHITECTURE.md) | Feasibility verdict, source-of-truth model, IaC/GitOps comparison + recommendation, responsibility matrix, identity model |
| 2 | [MCP-GATEWAY.md](MCP-GATEWAY.md) | Gateway design, tool catalog + schemas, permission matrix, per-connector security spec, prompt-injection defense |
| 3 | [APPROVAL-STATE-AUDIT.md](APPROVAL-STATE-AUDIT.md) | Four approval levels, dual approval, operation state machine, session durability, audit model, multi-agent review gates |
| 4 | [WORKFLOWS-AND-EXAMPLE.md](WORKFLOWS-AND-EXAMPLE.md) | Deployment/rollback/incident workflows + the concrete example conversation |
| 5 | [FAILURE-AND-THREAT.md](FAILURE-AND-THREAT.md) | 18 failure exercises, threat model, connector test harness |
| 6 | [INFRA-OPS-ROADMAP.md](INFRA-OPS-ROADMAP.md) | Milestones, smallest E2E slice, exact connector-development order |

**ADRs:** `0019` Claude-as-operator / IaC-authoritative · `0020` MCP infra-ops gateway boundary · `0021` approval levels + dual approval · `0022` durable operation state.

---

## Feasibility verdict (one line)

**Conditionally valid: Claude can be the conversational operator across the full TAC lifecycle — autonomous at Observe/Plan/Safe-Action and human-approved at high-impact — IF AND ONLY IF the source of truth (Git+IaC), the executor, the operation state, and the safety gates are deterministic platform automation, never the model.** Claude is the interface and reasoning layer; the platform's authority, execution, state, and safety are deterministic. Production-ready for L0–L2 and human-gated L3.

---

## Final decision — the ten answers

**1. Can Claude theoretically operate the full TAC infrastructure from chat?**
Yes — as the *conversational interface* over a deterministic platform. It observes, plans, takes bounded reversible actions autonomously, and requests high-impact changes that humans approve and a deterministic executor applies. It cannot and must not be the executor, the source of truth, or the safety authority.

**2. What connectors are required?**
Read (health/inventory/metrics/logs/quota/drift), Git/IaC plan, IaC executor (signed-approved apply), safe-action (retry/lease-recover/restart-stateless/cache/pause/disable-uploads), and provider connectors: DNS, object storage (R2), compute/workers, database (migration), secrets/identity broker, queues/jobs, email, monitoring/alerts, backup/restore. Each narrow, typed, least-privilege, and individually security-spec'd + harness-tested.

**3. What must exist beyond connectors?**
The deterministic spine: operation-state DB + state machine, approval service (single/dual), policy engine (OPA-style scope/level enforcement), identity broker (short-lived workload-identity creds, no secrets to Claude), signed-plan executor, drift reconciler, append-only signed audit, the Git+IaC repo, and a human approval UI + break-glass. Connectors are the easy part; the spine is what makes the claim safe.

**4. Which actions can be autonomous?**
L0 (all reads/reports/drift) and L2 (typed, bounded, idempotent, reversible, audited: retry job, recover expired lease, restart stateless worker, clear temp cache, pause failing consumer, disable uploads at hard quota). L1 planning is autonomous but executes nothing.

**5. Which actions require approval?**
All L3: production deploy, DNS, IAM, DB migration, data deletion, secret rotation, backup restoration, retention change, enabling raw-evidence access, security-policy change, infra destruction, paid-resource activation. **Dual approval in production** for: infra destruction, data deletion/retention reduction, prod DB migration, IAM change, restore over newer data, tenant/root-KMS rotation, enabling raw-evidence access, and any security-control weakening.

**6. What must never be exposed to Claude?**
Raw secret values, unrestricted provider APIs, shell/SQL/file/SSH, plan/approval signing keys, the ability to approve its own plan, long-lived admin keys, tenant/customer KMS roots, raw customer evidence, cross-tenant data, and the break-glass path. Enforced structurally (no tool, no parameter, no code path) + fitness-tested.

**7. Can this architecture support production safely?**
Yes for L0–L2 and human-gated L3, because safety is structural (deterministic executor + policy engine + durable state + signed approvals + audit), not prompt-dependent, and the platform is fully operable **without any AI** (failure exercise #18). It is **not** safe — and is explicitly out of scope — to let the model autonomously perform any L3 action.

**8. What is the smallest implementation slice that proves it E2E?**
The G0 spine + read/plan/approved-apply/validate/rollback loop for **one reversible, data-free, $0 resource** (redeploy/restart a single stateless analysis worker) in staging, plus the one L2 restart. It exercises Git-authoritative → deterministic executor → durable op → structural gates → audit on the smallest surface. (`INFRA-OPS-ROADMAP.md §2`.)

**9. What is the exact connector-development order?**
Spine → Git/IaC read+plan → read connectors (L0) → IaC executor for one resource (L3) → safe-actions (L2) → storage/compute → DNS → DB migrations (dual) → secrets rotation → backup/restore → email/monitoring → DR/drift-reconcile. Read before plan before safe-action before apply; least-blast before highest-blast. (`INFRA-OPS-ROADMAP.md §3`.)

**10. What prevents vendor lock-in to Claude?**
The gateway is a **provider- and model-agnostic typed tool/MCP interface**; the source of truth is Git+IaC (not Claude); the executor, state machine, approvals, and audit are deterministic and model-independent; the tools are business operations, not Claude-specific. Any MCP-capable model — or a human via the same gateway CLI — drives the identical platform. Swapping Claude swaps only the conversational front-end; the platform is unchanged. The fallback-without-AI requirement (every L2 action + every runbook human-executable) is the lock-in insurance.

---

## Do-not-proceed gate

Per the task: **do not begin implementation until this responsibility split is confirmed.** The one architectural line that must hold: *Claude is the operational interface; Infrastructure-as-Code, the operation-state DB, and provider state remain authoritative.* If that line is ever crossed — a model applying changes directly, holding secrets, or approving its own high-impact plans — the design is invalid regardless of how convenient it is.
