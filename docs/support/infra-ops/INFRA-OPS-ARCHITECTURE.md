# Culvert TAC Infrastructure Operations — Architecture & Feasibility

- **Status:** Proposed (design; no implementation). Ratified direction in ADR-0019.
- **Date:** 2026-07-13
- **Owner:** Principal Supportability Architect
- **Scope:** Can Claude be the primary *conversational operator* for the cloud-hosted TAC platform (`TAC-CLOUD-ARCHITECTURE.md`), with the human owner supplying secure connectors, policies, and approvals? This document establishes the model; companion docs specify the gateway, approval/state machine, workflows, failures, and roadmap.
- **Applies to:** the **TAC Cloud (Tier 3)** infrastructure only. It has **nothing to do with the on-prem Culvert appliance** (Tier 1), which remains outbound-only and never operable from any cloud (ADR-0014). This gateway operates the *vendor's* cloud, not the customer's appliance.

---

## 1. Feasibility verdict (the claim, evaluated)

> **Claim:** "Once secure connectors and policy boundaries exist, Claude can operate, deploy, troubleshoot and evolve the complete TAC infrastructure from chat, with human approval only for high-impact actions."

**Verdict: CONDITIONALLY VALID — true for the *interface*, false for the *engine*.** Claude can be the conversational operator across the full lifecycle **if and only if** four things are deterministic platform automation and never the model:

1. **The source of truth is Git + IaC**, not Claude. Claude proposes changes as reviewed IaC diffs; it never holds desired state in its head or in chat memory.
2. **The executor is deterministic.** Claude asks the executor to `apply` a *signed, pre-reviewed plan*; Claude never applies changes itself and never talks to a provider API directly.
3. **The operation state lives outside the conversation** — a durable state machine with operation IDs, leases, heartbeats, idempotency, and audit — so a lost session, a model error, or an executor crash never corrupts infrastructure or loses track of a change.
4. **Safety gates are structural, not prompted** — a typed policy engine enforces approval levels, dual approval, environment/tenant scope, and least privilege regardless of what the model "decides." The model cannot approve its own high-impact plan.

With those four in place, the claim holds: Claude autonomously observes (L0), plans (L1), and takes bounded reversible actions (L2); high-impact actions (L3) require human approval, some with dual approval. **Without** those four, the claim is false and dangerous — a model driving raw provider APIs from chat memory is unauditable, non-repeatable, and catastrophic on error.

**Bottom line:** Claude is the **operational interface and reasoning layer**; the platform's *authority, execution, state, and safety* are deterministic. This is not a limitation to work around — it is the design that makes the claim safe and true. Production-ready **for L0–L2 and human-gated L3**; not production-ready for any model-autonomous L3.

---

## 2. Source of truth (Claude is NOT it)

```
Git repository (IaC)  ──►  reviewed plan (PR + signed)  ──►  controlled executor  ──►  cloud resources
        ▲                                                                                    │
        └──────────────────────── drift reconciliation ◄─────────────────────────────────────┘

The conversation is the OPERATIONAL INTERFACE.
Infrastructure-as-Code, the operation-state DB, and provider state remain AUTHORITATIVE.
```

- **Desired state** lives in Git as IaC (OpenTofu). A change is a Git commit/PR, reviewed (by an independent Claude security-review agent + human), producing a **plan artifact**.
- **Actual state** lives in provider APIs + the IaC state backend; the **drift reconciler** (deterministic, scheduled) continuously compares desired vs actual and reports drift to Claude (L0), never silently self-heals high-impact drift.
- **Operation state** (in-flight changes) lives in a durable DB (`APPROVAL-STATE-AUDIT.md`). Claude reads it by operation ID; it is not chat memory.
- **Claude's role** is to read these authorities, reason over them, propose diffs, narrate execution, and validate outcomes — never to *be* an authority.

---

## 3. Infrastructure-as-Code strategy — comparison & recommendation

| Approach | Portability | Desired-state / drift | Rollback | $0-pilot fit | Lock-in | Verdict |
|---|---|---|---|---|---|---|
| **Terraform** | High | Yes | Plan-based | Good | HashiCorp **BSL license** risk; Terraform Cloud costs | Capable but licensing + managed-backend cost |
| **OpenTofu** | High | Yes | Plan-based | **Excellent** (OSS, free) | **None** (MPL, Linux Foundation) | **Recommended** |
| **Provider-specific config** (wrangler, fly.toml) | Low | Partial | Manual | Good | **High** (per-provider) | Only where OpenTofu providers are weak |
| **GitOps (Flux/ArgoCD)** | Medium | Yes (reconcile) | Git-revert | Heavy for non-k8s | Medium | Overkill for a non-k8s $0 pilot; revisit at scale |
| **Direct API execution** | — | **No** | **No** | — | — | **Rejected** — no desired state, no drift, no rollback, unauditable |
| **Hybrid** | High | Yes | Plan + revert | **Excellent** | Low | **The recommendation (below)** |

**Recommendation — Git + OpenTofu + a controlled plan/apply executor, GitOps-style reconciliation:**
- **OpenTofu** as the declarative engine (Terraform-compatible, OSS, no BSL, portable across providers). State in a free remote backend (e.g. object-storage backend on the pilot provider) with executor-held locking.
- **Git** as the single source of truth; every change is a PR; the plan is generated in CI and attached as a **signed plan artifact**.
- **A controlled executor** (deterministic service) that verifies the plan signature + approval record, then runs `tofu apply <saved-plan>` — apply is always of a *previously reviewed* plan, never a fresh one.
- **Provider-specific config only at the edges** OpenTofu can't reach (e.g. a Worker script), still Git-tracked and plan-gated.
- **GitOps reconciliation** as a scheduled `tofu plan` drift detector that reports (not auto-applies) high-impact drift; low-impact drift can be L2-auto-reconciled.

**Why this is simplest & portable for $0 → first prod:** OpenTofu + standard providers (Cloudflare for R2/DNS/Workers — already in the stack per `catalog-hosting-r2-activation.md`; Neon/Supabase Postgres free tier; Fly.io/Render free workers) gives a genuine $0 pilot, and the same IaC migrates to paid tiers or another cloud by swapping provider blocks — no rewrite. GitOps controllers (ArgoCD/Flux) are deferred until the platform is on Kubernetes at a scale that justifies them.

---

## 4. Responsibility matrix — Claude vs deterministic automation vs human

| Lifecycle area | Claude (conversational) | Deterministic platform | Human owner |
|---|---|---|---|
| Environment provisioning | plan (L1), narrate, validate | executor applies signed plan; state backend | approve prod (L3) |
| DNS | plan, impact/rollback (L1) | executor applies; provider connector | **approve (L3)** |
| TLS / certs | plan; validate issuance (L0/L1) | ACME/issuer automation; renewal loop | approve policy (L3) |
| App deployment | plan, progress, validate (L1) | executor; health-gate; rollback engine | approve prod (L3) |
| DB schema migration | plan, impact, rollback plan (L1) | migration runner (versioned, transactional) | **approve, dual in prod (L3)** |
| Object storage (R2) | inspect, plan lifecycle/retention (L0/L1) | provider connector; bucket policy | approve retention change (L3) |
| Analysis workers | restart stateless (L2), scale plan (L1) | executor; autoscaler | approve paid scale-up (L3) |
| Queues / job recovery | retry job, recover lease (L2) | queue connector; lease store | — |
| Email ingress/egress | inspect, plan (L0/L1) | provider connector | approve domain/DNS (L3) |
| Authentication / IAM | inspect, plan (L0/L1) | identity broker; OIDC | **approve, dual in prod (L3)** |
| Secrets / identity rotation | plan, request rotation (L1) | secret manager rotates; brokers short-lived creds | **approve (L3)** |
| Monitoring | read, report, correlate (L0) | metrics/alerts pipeline | — |
| Alerts | triage, propose runbook (L0/L1) | alerting engine | approve policy (L3) |
| Backups | check status (L0), plan (L1) | backup engine (scheduled, deterministic) | — |
| Restore | plan drill (L1); run **drill** (L2 in non-prod) | restore engine | **approve real restore, dual (L3)** |
| Disaster recovery | narrate runbook, validate (L0/L1) | DR automation executes steps | **approve invocation (L3)** |
| Quota management | inspect posture (L0); disable uploads on hard quota (L2) | quota meters; enforcement | approve paid upgrade (L3) |
| Incident response | enter incident mode (L2), correlate, draft comms (L1) | incident state machine; paging | approve customer comms (L3) |
| Rollback | invoke rollback of a prior op (L2, if reversible) | rollback engine (deterministic) | approve if data-affecting (L3) |
| Capacity scaling | plan (L1); scale within free bounds (L2) | autoscaler | approve paid scale (L3) |
| Security review | independent review agent (L1) | policy engine (OPA) enforces | approve exceptions (L3) |
| Cost review | analyze, forecast, report (L0/L1) | billing meters | approve spend (L3) |

**The three-way rule:** Claude reasons and proposes; deterministic automation executes, persists, and enforces; the human authorizes irreversible or costly change. No box moves left (toward Claude) without an ADR.

---

## 5. High-level architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  CONVERSATIONAL LAYER (model-agnostic)                                              │
│  Human owner  ⇄  Claude operator agent  +  independent review/validate/cost agents  │
└───────────────┬────────────────────────────────────────────────────────────────────┘
                │  typed MCP tools ONLY (no raw provider access, no shell/SQL/secrets)
┌───────────────▼────────────────────────────────────────────────────────────────────┐
│  CULVERT INFRASTRUCTURE OPERATIONS GATEWAY  (deterministic service)                  │
│  • tool dispatch + schema validation      • policy engine (approval levels, scope)   │
│  • operation state machine (durable)      • approval service (single/dual)           │
│  • identity broker (OIDC/workload id, short-lived creds — Claude never sees secrets) │
│  • audit log (append-only, signed)        • rate limits / idempotency / leases       │
└───────┬───────────────────────┬───────────────────────┬────────────────────────────┘
        │                       │                       │
┌───────▼─────────┐   ┌─────────▼──────────┐   ┌────────▼───────────┐
│  IaC EXECUTOR    │   │  READ CONNECTORS   │   │  SAFE-ACTION        │
│  (plan/apply of  │   │  health/inventory/ │   │  CONNECTORS (L2)    │
│  SIGNED plans)   │   │  metrics/logs/quota│   │  retry/restart/lease│
└───────┬─────────┘   └─────────┬──────────┘   └────────┬───────────┘
        │  Git + OpenTofu        │  provider read APIs    │  scoped write APIs
┌───────▼────────────────────────▼────────────────────────▼───────────────────────────┐
│  AUTHORITATIVE STATE:  Git (IaC desired state) · OpenTofu state · provider state ·    │
│  operation-state DB · audit store                                                     │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

Claude touches only the top edge (typed MCP tools). Everything below the gateway is deterministic and model-independent — which is also what prevents lock-in to Claude (§ README final answer 10).

---

## 6. Identity model (least privilege, no secrets to Claude)

- **Claude → Gateway:** the model authenticates to the gateway with a scoped, short-lived session token (per operator, per environment). It carries *authorization to request operations*, not provider credentials.
- **Gateway → providers:** the gateway's **identity broker** mints **short-lived, scoped credentials** per operation via **workload identity / OIDC** (e.g. GitHub OIDC → provider role assumption), never long-lived admin keys. Each connector runs under a **provider-scoped service identity** with least-privilege IAM for exactly its allowed actions.
- **Secrets:** Claude **never receives raw secret values.** Tools return **secret identifiers** (`secret_ref: "tac/prod/db-url#v7"`) and operation results, never the material. Rotation operates on refs; the broker resolves refs to values only inside the executor's process, never across the tool boundary.
- **Signing:** plans and approvals are signed; the executor verifies signatures before apply. Claude cannot forge a plan or an approval (it holds no signing key).

Full per-connector identity/scope/lifetime spec is in `MCP-GATEWAY.md §connector-security`.

---

## 7. What must exist beyond connectors (the deterministic spine)

Connectors are the easy part. The claim only holds because of the spine:
1. **Operation-state DB + state machine** (durable, outside chat).
2. **Approval service** (single/dual, four-eyes, scoped).
3. **Policy engine** (OPA-style) enforcing levels, scope, least privilege — structurally, not by prompt.
4. **Identity broker** (short-lived creds, no secrets to Claude).
5. **Signed-plan executor** (apply only reviewed plans).
6. **Drift reconciler** (Git ⇄ actual).
7. **Append-only signed audit log.**
8. **Git + IaC repo** (the source of truth).
9. **Human approval UI + break-glass** (deterministic, out-of-band).

Claude sits on top of all nine. Remove Claude and a human can still operate the platform through the same gateway/CLI — proof that Claude is the interface, not the system.
