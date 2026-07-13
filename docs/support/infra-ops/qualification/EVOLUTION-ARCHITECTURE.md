# Stage 4 — Evolution Architecture (no-rewrite migration path)

- **Thesis:** the **domain model, APIs, operation state machine, analyzer contracts, and MCP gateway survive every phase.** Only *implementations behind stable interfaces* are replaced (SQLite→managed Postgres, single worker→pool, local AI→hosted, etc.). Nothing above the interface line changes.
- **The invariant interfaces (frozen across A→D):** `csb/1` bundle format · collector contract · `DataClass` redaction registry · the 18-state operation FSM + operation record schema · the 9 typed gateway tools + REST API · plan/approval/audit artifact formats · analyzer input = normalized findings (ADR-0018). Everything else is swappable.

---

## Phase A — $0 Pilot

**Topology:** single control-plane process · single metadata DB (SQLite/Neon free) · single object store (R2 free) · single analysis worker · deterministic in-DB queue · local or free AI · synthetic + design-partner usage.

| Aspect | Choice |
|---|---|
| Capacity | 1 worker; a handful of design-partner bundles/day |
| Availability | best-effort single-instance; restart-recoverable (durable op DB) |
| Cost | **$0** (free tiers; the proof harness runs offline) |
| Data | synthetic + consenting design partners only |

**Necessary now:** the deterministic spine (op DB, FSM, policy, executor, validator, rollback, signed audit), source-side redaction, outbound-only upload, `tacctl`, plan-bound approval. **Dormant:** HA, multi-region, KMS, managed DB, telemetry, portal UX.

> **STAGE-5 FinOps correction (R3).** "$0" applies to the appliance + deterministic spine (they run offline, proven by the harness). It does **NOT** include: (a) **AI inference** — the product's reasoning layer has a real per-token cost, so budget a small AI line from day one; (b) **a durable, backed-up control-plane DB** — the entire "durable/reconstructable/tamper-evident" guarantee rests on the op+audit store surviving, so a free-tier DB that autosuspends/loses data is unacceptable. **First paid investment = managed Postgres with point-in-time recovery (~$19–25/mo)** for the op+audit DB — before anything else. (c) **Stale free-tier premise:** do not assume any specific provider's "free worker" tier persists (e.g. Fly.io's free allowances changed); the worker is a small paid compute line in early production. Net: the honest pilot is "**~$0 spine + a few $ of AI + ~$20/mo DB when real data appears**," not literally $0 end-to-end.

---

## Phase B — First Paying Customers

Add **only** what reliability + first real evidence demand:

| Add | Replaces | Migration | Data migration | Downtime | Rollback | Cost | Trigger to begin |
|---|---|---|---|---|---|---|---|
| Managed PostgreSQL (Neon/Supabase paid) + **reliable backups** | SQLite | point op DB DSN at managed PG; run the same migrations | `pg_dump`/logical load (schema identical) | minutes (maintenance window; ops queue drains first) | keep SQLite snapshot; DSN flip back | ~$25–50/mo | first paying customer OR >1 concurrent op |
| Monitored worker compute (paid machine + health/restart) | free worker | image digest unchanged; provider block in OpenTofu | none | rolling (deploy path) | reverse-deploy | ~$20–40/mo | real bundles arrive |
| Production email (transactional provider) | local/none | add email connector (typed) | none | none | disable connector | ~$0–20/mo | customer notifications needed |
| Stronger identity (OIDC broker → real workload identity) | demo HMAC/broker stub | swap signing to KMS; broker to real OIDC | re-issue signing key id | none (additive key id) | keep old key id in overlap | ~$0–10/mo | first real credential |
| Durable object storage (R2 standard) + availability alerts + restore testing + basic standby | free R2 | bucket policy in IaC | copy objects (lifecycle) | none | keep old bucket | ~$5–15/mo | first stored real evidence |

**Total Phase B:** ~$100–300/mo. **Nothing above the interface line changes** — the op FSM, tools, bundle format, and analyzer contracts are byte-identical.

---

## Phase C — Stable Production

| Design for | Replaces | Migration | Data migration | Downtime | Rollback | Cost | Trigger |
|---|---|---|---|---|---|---|---|
| Redundant API instances (N gateway/operation replicas) | single process | stateless services behind an LB; op state already in DB (no in-memory authority) | none | zero (rolling) | scale down | ↑ | sustained load / SLA |
| Managed/replicated DB (PG HA, read replicas) | single PG | managed HA PG; same schema | provider failover | near-zero | promote old primary | ↑↑ | availability SLA |
| Redundant worker pool + queue durability | single worker + in-DB queue | worker pool behind the same lease/queue contract; durable queue (SQS/PG-based) | none (jobs re-leasable) | zero | drain pool | ↑ | throughput |
| Object lifecycle + replication | single bucket | R2/S3 replication + lifecycle rules in IaC | background replicate | none | primary bucket | ↑ | durability/compliance |
| KMS-backed identities | broker-held key | migrate signing + cred minting to cloud KMS | re-key with overlap | none | old key id overlap | ↑ | security bar |
| Multiple AZs | single AZ | multi-AZ deploy in IaC | none (data already replicated) | zero | single-AZ | ↑↑ | availability |
| Tested DR + on-call | ad hoc | DR runbooks + restore drills (design exists) | drill only | none | n/a | ops time | first enterprise contract |

**Key point:** because the operation FSM never held state in memory or in chat (ADR-0022), horizontal API scaling and DB failover are **configuration**, not redesign. The single-mutation-spine + per-worker lease already model concurrency, so a worker *pool* is a capacity change, not an architecture change.

---

## Phase D — Enterprise Scale

| Evaluate | How the interfaces survive |
|---|---|
| Regional ingestion | additional ingest gateways route to region-local raw planes; **same** `csb/1` + upload protocol |
| Tenant data residency | per-tenant region binding at the gateway; **same** case/tenant scoping already in the model |
| Multi-region control plane | replicate the op DB per region (or global PG); **same** FSM + audit |
| Worker isolation per region | region-scoped worker pools + executor identities; **same** lease/plan/validate contract |
| Customer-managed encryption (BYOK) | per-tenant recipient key replaces the baked key; **same** E2E envelope (ADR-0016) |
| Advanced SSO | approval service adds SAML/OIDC IdPs; **same** approval artifact binding |
| Multiple support teams | entitlement + case routing on top; **same** case/op model |
| Policy-as-code governance | the policy engine is already OPA-style; add org policies; **same** gate position |
| Kubernetes / managed containers | executor's `apply`/`restart` targets a k8s/managed-container provider; **same** typed tools, plan, validate; add a `Runtime: k8s` collector/executor variant (already anticipated by the runtime-gating design) |
| Advanced incident analytics | consumes the normalized findings plane; **same** analyzer contract |

Every Phase-D item is **additive behind a frozen interface.** The one anticipated *implementation* swap — Fly Machines → Kubernetes — is contained to the executor's provider adapter + a new OpenTofu module, because the gateway tools, plan artifact, validation gates, and rollback algorithm are provider-agnostic.

---

## No-rewrite proof (what survives every transition)

| Survives A→D unchanged | Replaced (behind interface) |
|---|---|
| `csb/1` bundle format + manifest schema | archive/storage backend |
| Collector contract + `DataClass` registry | individual collectors, redaction impl |
| 18-state operation FSM + operation record | op-DB engine (SQLite→PG→HA PG) |
| 9 typed gateway tools + REST API | gateway replica count, transport |
| Plan / approval / audit artifact formats | signing impl (HMAC→Ed25519/KMS) |
| Analyzer input contract (normalized findings) | analyzer runtime, AI provider |
| Policy-as-code gate position | rule content, org policies |
| Executor's `plan/apply/restart/validate/rollback` contract | provider adapter (Fly→k8s→multi-cloud) |
| Outbound-only + consent + tenant scoping | scale of ingestion, regions |

**Migration trigger discipline:** each phase begins only on its named trigger (first concurrent op → managed DB; first real evidence → durable storage + KMS; SLA commitment → HA/multi-AZ; enterprise contract → residency/BYOK/regions). Never migrate ahead of the trigger — that is the FinOps guardrail (Reviewer 3).

## Verdict

The domain model, APIs, operation state machine, analyzer contracts, and MCP gateway **survive all four phases**. Every scale step is a swap behind a frozen interface or an additive component — **no rewrite is required to go from the $0 pilot to enterprise scale.** The single decision that *could* have forced a rewrite — holding operation state in memory/chat — was explicitly avoided (ADR-0022), which is why horizontal scale and DB/provider swaps are configuration rather than redesign.
