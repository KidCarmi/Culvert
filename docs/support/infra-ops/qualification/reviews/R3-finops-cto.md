# R3 — Independent Qualification Review: FinOps Analyst + Startup CTO

- **Reviewer role:** Independent FinOps analyst + startup CTO (public benchmarks only).
- **Date:** 2026-07-13
- **Scope reviewed:** `docs/support/infra-ops/*.md`, `docs/support/infra-ops/proof-slice/*`, `docs/support/TAC-CLOUD-ARCHITECTURE.md`, `docs/support/infra-ops/qualification/staging-proof/README.md` + `evidence/metrics.json`.
- **Lens:** three budgets — Pilot ($0–25/mo), Early production ($100–500/mo), Enterprise ($1,000–10,000+/mo). Cost honesty, right-sizing, dormant-until-scale controls, and where the first real dollar should go — **not** replicating a large vendor's complexity for a small team.
- **Basis of evidence:** the proof harness is a single Python process + SQLite that runs the control loop with mocks (SQLite→Postgres, MockProvider→Fly.io/OpenTofu, HMAC→Ed25519/KMS) and **no AI in the loop**. All measured numbers are simulation-derived.

---

## 1. Verdict

The **safety architecture is well-reasoned and the proof harness is honestly scoped** — the deterministic spine (single mutation path, typed policy gate, plan-bound approval with self-approval rejection, idempotency + lease, hash-chained signed audit, AI-independent `tacctl`) is right-sized and necessary, and the design explicitly enumerates what the proof does *not* establish. That earns real credit.

But through a **pure FinOps/CTO lens the cost story is the weakest part of the package, and two layers are miscalibrated for the team's size and budget:**

1. **Over-built operational/identity machinery for the pilot.** Eight microservices, a three-repo split, OPA/Rego, cloud KMS/HSM signing, OIDC workload-identity federation, dual-approval, and a multi-agent review board are all specified up front to operate *one staging worker*. The proof itself is one process — proving the loop needs none of that topology.
2. **Under-built cost discipline for first customers.** The "$0 pilot" headline **excludes the AI operator — i.e. the product** — rests on free tiers that no longer exist as described (Fly.io free workers are gone), gives the control plane's own op/audit DB no self-backup, and enforces budget only via an *advisory* LLM agent with no hard ceiling.

**Bottom line:** GO to build the deterministic spine — but as a lean monolith with software signing, with the heavy topology kept as documented, dormant seams. Conditional NO-GO on committing to the full 8-service/KMS/OIDC/dual-approval build and on the "$0" marketing claim until the cost model is made honest (R3-F1/F2/F3).

---

## 2. Maturity score: **3 / 5**

- **Architecture-safety reasoning: 4/5** — the four load-bearing invariants and the failure matrix are strong and behaviorally proven on the smallest surface.
- **FinOps / cost-and-operational discipline: 2/5** — headline cost is misleading, free-tier premises are stale, no self-durable control DB, no hard budget ceiling, LLM spend uncosted.
- **Blended (this review's axis): 3/5.** A mature safety design carried by an immature cost model.

---

## 3. Unusually strong

- **Honesty statement in the staging proof** (`staging-proof/README.md §6`) — explicitly lists what is *not* established (real provider, KMS signing, OIDC minting, HA, contention, scale). This is rare and exactly what a qualification board should see; it prevents mock numbers from being over-trusted (though see R3-F10).
- **AI-independence is real and cheap** — every step runs via `tacctl` with no AI (failure case #16 → `SUCCEEDED`). This is the single best cost-and-lock-in property: the platform is operable when Anthropic is down *and* the recurring LLM bill is optional, not structural.
- **The deterministic spine is genuinely minimal-cost.** Policy is 17 typed predicates; audit is a hash-chain; idempotency is a UNIQUE key; the lease is one row. None of these require paid infrastructure to be correct — a startup can ship the *safety* for near-$0.
- **Correct deferral of Kubernetes/GitOps.** `INFRA-OPS-ARCHITECTURE §3` rejects ArgoCD/Flux as "overkill for a non-k8s $0 pilot; revisit at scale." That is precisely the right FinOps call and should be the model for the *rest* of the stack (which it currently is not).

---

## 4. Blocking findings

### R3-F1 — "$0 pilot" cost excludes the AI operator (the product itself)
- **Severity:** Blocking (cost-honesty)
- **Affected component:** `evidence/metrics.json`; multi-agent review model (`APPROVAL-STATE-AUDIT §6`); staging-proof README.
- **Realistic scenario:** A CTO/board budgets the pilot from `estimated_monthly_cost_usd_pilot: 0`. Production, unlike the proof, runs a Planner + Security-review + Cost-review agent per plan plus executor-liaison narration — several LLM calls per operation. The first Anthropic invoice is a surprise.
- **Business impact:** The headline number is misleading to exactly the audience (board/qualification) it is meant to inform; runway is mis-planned; credibility risk if a reviewer notices the AI — the whole selling point — is costed at zero.
- **Technical impact:** No per-operation token/cost model exists; LLM spend is the *dominant variable cost* at every non-pilot budget and is entirely absent from the cost artifacts.
- **Evidence:** `metrics.json` `"estimated_monthly_cost_usd_pilot": 0`; `staging-proof/README.md §1` "runs with NO AI in the loop"; `APPROVAL-STATE-AUDIT.md §6` (Planner + Security-review + Cost + Executor-liaison + Validation agents).
- **Required correction:** Publish a per-operation LLM cost model (tokens × agents-per-plan × ops/day) at three op-volume points; relabel the metric "infrastructure-only, AI operator excluded."
- **Acceptance test:** A cost sheet giving $/operation and $/month at low/med/high op volume; the README `$0` line annotated to exclude the AI operator; `metrics.json` gains an `llm_cost_excluded: true` field.
- **Recommended milestone:** G2 (Plan — when review agents come online).

### R3-F2 — Free-tier premises are stale; the "$0 pilot" floor is not achievable as written
- **Severity:** Blocking (cost-honesty)
- **Affected component:** IaC/provider assumptions (`INFRA-OPS-ARCHITECTURE §3`); proof-slice go/no-go checklist.
- **Realistic scenario:** The team provisions the pilot on the named free tiers and discovers Fly.io's free allowance was removed (Oct 2024, now usage-based), Render free services spin down, and Neon/Supabase free tiers autosuspend/pause. The "genuine $0 pilot" becomes a small-but-nonzero bill plus cold-start behavior.
- **Business impact:** A stated $0 that is actually ~$5–25/mo undermines the qualification claim and the deferral logic ("$0 → first prod migrates by swapping provider blocks") that rests on it.
- **Technical impact:** Availability surprise (autosuspend of an *ops* control plane during an incident), not just cost.
- **Evidence:** `INFRA-OPS-ARCHITECTURE.md §3` "Neon/Supabase Postgres free tier; Fly.io/Render free workers … a genuine $0 pilot"; `proof-slice/README.md §10` "Postgres provisioned (Neon free tier)."
- **Required correction:** Revalidate every named free tier against current (2026) pricing/limits; replace stale ones; state a realistic pilot floor (likely $5–25/mo) rather than $0.
- **Acceptance test:** A provider-by-provider table (compute / Postgres / object-store / DNS) with current free limits + a documented minimum monthly floor; no doc asserts unqualified "$0."
- **Recommended milestone:** G0.

### R3-F3 — The control plane's own op/audit DB has no self-durability plan, yet the entire value claim rests on it
- **Severity:** Blocking (durability / compliance)
- **Affected component:** operation-state + audit store (`schema.sql`, `APPROVAL-STATE-AUDIT §5`).
- **Realistic scenario:** The pilot runs the op DB on free-tier Postgres with no guaranteed PITR/backup. A free-tier data-loss or project-pause event erases the operations/events tables. Every "durable, reconstructable, tamper-evident" property — demonstrated as `audit_chain_valid=True` — is gone, and the hash-chain has no continuity to restore to.
- **Business impact:** Single-event total loss of the auditability/compliance evidence that is the platform's sellable property; the design protects *customer* infra but not its own crown jewels.
- **Technical impact:** No RPO/RTO defined for the control-plane DB; no continuous export of the signed chain to durable object storage.
- **Evidence:** `schema.sql` (operations/events authoritative); `staging-proof/README.md §2` demo #12 "reconstructs op from DB; `audit_chain_valid=True`"; no backup of the op/audit DB appears in any doc.
- **Required correction:** Make managed Postgres with automated backups + PITR the **first paid line**; define RPO ≤ 24h / RTO for the op/audit store; continuously export the signed audit chain to cheap object storage.
- **Acceptance test:** A restore drill that rebuilds the op DB from backup and re-verifies `audit_chain_valid=True`; a documented RPO/RTO.
- **Recommended milestone:** G0/G1.

---

## 5. High-priority

### R3-F4 — No hard budget ceiling; cost control is an advisory LLM agent, not an enforced cap
- **Severity:** High
- **Affected component:** policy engine (`POLICY-IDENTITY §1`, rule P13); approval table (`APPROVAL-STATE-AUDIT §7`); cost-review agent.
- **Realistic scenario:** Beyond the pilot, `paid-resource activation` is "single approval, budget-scoped" with the budget scope undefined, and the cost agent can only BLOCK by opinion. A mis-scoped paid resource or a runaway autoscale passes the advisory agent → surprise bill. P13's `$0`-delta rule is staging-only and does not protect production.
- **Business impact:** The classic FinOps failure — spend controlled by judgment, not by an enforced meter. One bad plan = an uncapped invoice.
- **Technical impact:** Budget is not a deterministic policy input; there is no machine-checked `cost_delta` against a remaining-budget meter for production.
- **Evidence:** `POLICY-IDENTITY.md §1` P13 (`cost_delta_usd == 0`, staging); `APPROVAL-STATE-AUDIT.md §7` "Paid-resource activation … single (budget-scoped)"; `§6` cost agent "advisory … can BLOCK on budget breach."
- **Required correction:** A deterministic per-environment monthly budget meter enforced *in the policy engine*; paid-resource plans carry a machine-checked cost delta; exceeding remaining budget → `POLICY_REJECTED` regardless of any agent verdict.
- **Acceptance test:** A policy test: a plan whose cost_delta exceeds the env budget lands in `POLICY_REJECTED` with the rule id, even when the cost agent returns OK.
- **Recommended milestone:** G5 (paid resources).

### R3-F5 — Eight-service / three-repo / KMS / OIDC / Rego topology is over-engineered for a 1–2-person pilot
- **Severity:** High (over-engineering / runway)
- **Affected component:** whole `tac-infra` control-plane topology (`proof-slice/README.md §2`, §6 complexity table, repo layout).
- **Realistic scenario:** A small team spends its runway building and operating eight Go services, three repos with CODEOWNERS/CI, a Rego bundle, cloud KMS, and an OIDC federation broker — to operate one staging worker. The proof already shows the *entire loop* runs correctly in one process with software signing.
- **Business impact:** Months of plumbing before any customer value; ongoing ops burden disproportionate to a team that size; five components are self-rated "High" complexity.
- **Technical impact:** More failure surface, more deploy units, more secrets to manage than the pilot's blast radius warrants.
- **Evidence:** `proof-slice/README.md §2` (3 repos), §6 (operation/executor/rollback/broker/E2E rated "High"), layout (8 services + 2 binaries); `staging-proof/README.md §1` (proof == one process); `tac_proof.py` (single file, <40MB RSS).
- **Required correction:** Ship the spine as a **modular monolith** — one deployable, service boundaries as internal Go packages — with software (file-based Ed25519/HMAC) signing and a broker-held scoped token. Keep the 8-service split, KMS, OIDC federation, and Rego as *documented seams* activated at first paid customer.
- **Acceptance test:** A pilot deployable that runs the full read→plan→approve→apply→validate→rollback loop in ≤2 containers (app + Postgres), with the eight "services" present as package boundaries, not processes.
- **Recommended milestone:** G0–G3.

### R3-F6 — Single-executor / single-region control plane has no HA; no defined trigger for adding it
- **Severity:** High (availability at first SLA)
- **Affected component:** executor + control-plane runtime (`INFRA-OPS-ARCHITECTURE §5`; proof "Does NOT establish … multi-node HA").
- **Realistic scenario:** At first paying customer with an SLA, the single control host or region is lost *during* the incident the platform exists to manage; operations stall until manual recovery. Acceptable at pilot; an SLA breach at early production. The design defers HA to "Stage-4" with no trigger.
- **Business impact:** First real availability commitment is unbacked; an outage during an incident is the worst-case trust event.
- **Technical impact:** No standby executor, no fast-restart/failover target, no multi-region posture; the op DB durability gap (R3-F3) compounds it.
- **Evidence:** `staging-proof/README.md §6` "Does NOT establish … multi-node HA, network partitions"; `INFRA-OPS-ARCHITECTURE.md §5` (one executor in the spine).
- **Required correction:** Define the exact scale trigger (first paid customer / first SLA) at which control-plane HA — standby executor + backed-up managed DB + fast restart — becomes mandatory, and cost it in the early-production budget.
- **Acceptance test:** A documented trigger + a costed HA design with an RTO target and a failover drill.
- **Recommended milestone:** G7.

---

## 6. Medium-priority

### R3-F7 — The one long-lived secret (broker root) has no defined pilot home
- **Severity:** Medium
- **Affected component:** identity broker (`POLICY-IDENTITY §3`); harness signing key.
- **Realistic scenario:** `POLICY-IDENTITY §3` says a provider without workload identity forces "a broker-held root secret in a KMS/secret-manager" — but the pilot skips KMS to stay at $0, and the proof hardcodes the signing key in source. The single highest-value secret's storage is undefined at exactly the budget where KMS is dropped.
- **Business impact:** Risk of the root secret landing in env/source; it is "the one place a longer-lived secret exists."
- **Technical impact:** No specified pilot secret store or rotation owner.
- **Evidence:** `POLICY-IDENTITY.md §3` ("broker-held root secret in a KMS/secret-manager the broker alone can read"); `tac_proof.py` `SIGN_KEY = b"local-demo-signing-key-STANDIN..."` in source.
- **Required correction:** Specify the pilot secret store (cloud secret-manager free tier, or sops/age-encrypted with an offline key) and the rotation owner; no signing/root key in source or plain env.
- **Acceptance test:** Documented pilot secret-store choice + rotation runbook; a grep gate proving no signing/root key in source or unencrypted config.
- **Recommended milestone:** G0.

### R3-F8 — Audit-log retention cost is uncosted and grows unbounded
- **Severity:** Medium
- **Affected component:** audit store (`APPROVAL-STATE-AUDIT §5`).
- **Realistic scenario:** Append-only signed events per operation, retained for a "contractual audit window" in a separate store. At enterprise op volume this is a real storage + egress line with no budget and a possible compliance-retention surprise.
- **Business impact:** Silent cost creep; retention obligations without a costed home.
- **Technical impact:** No hot/cold tiering; no $/GB estimate.
- **Evidence:** `APPROVAL-STATE-AUDIT.md §5` (append-only, separate store, exportable for compliance); no retention or cost figure in any doc.
- **Required correction:** A retention policy with hot→cold tiering to object storage and a $/GB/mo estimate at each budget.
- **Acceptance test:** A retention/cost table + audit export to object storage with a documented tiering age.
- **Recommended milestone:** G5/G6.

### R3-F9 — Observability + paging assumed but uncosted
- **Severity:** Medium
- **Affected component:** monitoring/alerts + incident paging (`INFRA-OPS-ARCHITECTURE §4` matrix; `WORKFLOWS-AND-EXAMPLE §3`).
- **Realistic scenario:** The incident workflow sets paging and relies on a "metrics/alerts pipeline"; none is costed. At early production these (Grafana Cloud, PagerDuty/Opsgenie) are real and gate the SLA.
- **Business impact:** Incident response depends on tools absent from the budget; the SLA rests on unfunded tooling.
- **Technical impact:** No named observability/paging stack or free→paid thresholds.
- **Evidence:** `INFRA-OPS-ARCHITECTURE.md §4` (Monitoring/Alerts rows); `WORKFLOWS-AND-EXAMPLE.md §3` (`enter_incident_mode` sets paging).
- **Required correction:** Name the observability + paging stack and its free→paid thresholds per budget; add an ops-tooling line to each budget table.
- **Acceptance test:** An ops-tooling line item in all three budget tables with the crossover thresholds.
- **Recommended milestone:** G6.

### R3-F10 — Cost/footprint/latency metrics are simulation-derived but presented as measured numbers
- **Severity:** Medium
- **Affected component:** `evidence/metrics.json` + staging-proof README §4.
- **Realistic scenario:** The proof mocks the three most cost-relevant integrations (real Postgres locking under contention, KMS signing, OIDC minting). Its footprint/cost/latency come entirely from the mock. A reader makes a capacity or cost decision on `< 40 MB RSS` / `$0` numbers.
- **Business impact:** Capacity/cost decisions anchored to simulation figures.
- **Technical impact:** The `$0` and RSS numbers are not capacity-representative; the README flags this in prose but the metrics artifact does not.
- **Evidence:** `staging-proof/README.md §4/§6`; `metrics.json` `"resource_footprint": "…(local sim)"`, `estimated_monthly_cost_usd_pilot: 0`.
- **Required correction:** Add a `basis: "mock/simulation"` field to every metric and a one-paragraph real-provider cost/latency projection for the same slice.
- **Acceptance test:** `metrics.json` carries `basis` on each numeric field + a companion real-provider estimate section.
- **Recommended milestone:** G1.

---

## 7. Over-engineered (for the pilot — keep as dormant seams)

| Control | Why dormant is fine at pilot | Activate at |
|---|---|---|
| **Cloud KMS / HSM signing** | Software Ed25519/HMAC gives identical tamper-evidence at $0; proof already uses HMAC. | First paid customer / compliance ask |
| **OIDC workload-identity federation** | A broker-held scoped token (≤15 min) is enough for one worker; federation is provider-specific plumbing. | Multi-provider / prod IAM |
| **OPA / Rego policy engine** | 17 typed Go predicates already exist and are 100%-branch-tested; Rego is redundant weight. | Never required unless external policy authors appear |
| **Eight-process microservice split + 3 repos** | Blast-radius and review-authority goals are met by internal package boundaries + CODEOWNERS on one repo. | Scale / independent team ownership |
| **Dual approval** | No dual-class action exists in the slice (design admits this). Build the mechanism, don't operate it. | First prod destructive/data class |
| **Multi-agent independent review board** | A single planner + human suffices for a $0-delta staging restart; the 2 review agents are pure LLM cost. | First paid customer / first prod deploy |
| **Drift auto-reconcile, DR automation, restore drills** | No production data or SLA to protect yet. | G6+ |

**Necessary NOW (cheap, keep):** single mutation spine, deterministic policy gate, plan-bound approval + self-approval rejection, idempotency + per-worker lease, hash-chained *software-signed* audit, `tacctl` AI-independence.

---

## 8. Under-engineered (for first customers — build before/at first paid customer)

- **Self-durable control-plane DB** (R3-F3) — the safety claim is only as good as this DB; free-tier autosuspend + no PITR is the weakest link.
- **Hard budget ceiling in the policy engine** (R3-F4) — advisory cost agents are not a spend cap; a FinOps platform must fail closed on budget.
- **A published LLM cost model** (R3-F1) — the dominant variable cost is uncosted.
- **A realistic free-tier / pilot-floor table** (R3-F2) — the $0 premise is stale.
- **Defined pilot secret home** (R3-F7) — the one long-lived secret is homeless at $0.
- **Control-plane HA trigger** (R3-F6) — first SLA is currently unbacked.

---

## 9. Exact proposed changes

1. **Reframe the cost artifacts (R3-F1/F2/F10).** In `metrics.json`: add `basis` per metric, `llm_cost_excluded: true`, and replace the bare `estimated_monthly_cost_usd_pilot: 0` with an `infra_only` floor range. In `INFRA-OPS-ARCHITECTURE §3`: replace the free-tier list with a current-pricing table and a stated pilot floor.
2. **Add a control-plane durability section** to `APPROVAL-STATE-AUDIT.md`: RPO/RTO for the op/audit DB, managed-Postgres-with-PITR as the first paid line, continuous audit-chain export to object storage (R3-F3).
3. **Promote budget to a deterministic policy rule** (`POLICY-IDENTITY §1`): a per-environment monthly budget meter; production paid-resource plans carry a machine-checked cost delta; over-budget → `POLICY_REJECTED` (R3-F4).
4. **Add a "pilot topology vs scale topology" section** to `proof-slice/README.md`: pilot = modular monolith + software signing + broker-held token + Go-predicate policy; the 8-service/KMS/OIDC/Rego/dual-approval set marked as seams with explicit activation triggers (R3-F5, §7 table).
5. **Publish an LLM cost model** (new short doc or `APPROVAL-STATE-AUDIT §6` addendum): tokens × agents-per-plan × ops/day at three volumes (R3-F1).
6. **Specify the pilot secret store + rotation owner** in `POLICY-IDENTITY §3`; remove the in-source signing key from the reference harness's guidance (R3-F7).
7. **Add ops-tooling and audit-retention line items** to every budget table (R3-F8, R3-F9).
8. **Define the control-plane HA trigger + costed design** for early production (R3-F6).

---

## 10. Measurable acceptance criteria

- **AC-1 (F1):** A cost sheet shows $/operation and $/month at 3 op-volume points; README `$0` annotated "AI operator excluded"; `metrics.json.llm_cost_excluded == true`.
- **AC-2 (F2):** A current-pricing free-tier table exists; no doc asserts unqualified "$0"; a numeric pilot floor is stated.
- **AC-3 (F3):** A restore drill rebuilds the op/audit DB from backup and re-verifies `audit_chain_valid=True`; RPO ≤ 24h documented.
- **AC-4 (F4):** A policy test: over-budget plan → `POLICY_REJECTED` with rule id, even when the cost agent returns OK.
- **AC-5 (F5):** The full loop runs in ≤2 containers (app + Postgres); the eight services exist as Go packages, not processes.
- **AC-6 (F6):** A documented HA trigger + costed early-production HA design with an RTO target.
- **AC-7 (F7):** Documented pilot secret store + rotation runbook; a source/config scan proves no signing/root key in the clear.
- **AC-8 (F8/F9):** Audit-retention and ops-tooling line items appear in all three budget tables with crossover thresholds.
- **AC-9 (F10):** `metrics.json` carries `basis` on each numeric field + a real-provider cost projection.

---

## 11. Go / No-go

- **GO** — implement the **deterministic spine now, as a lean modular monolith** with software signing, a broker-held scoped token, and Go-predicate policy. This delivers the entire proven safety loop at a genuinely low cost floor and is the right use of a small team's runway.
- **CONDITIONAL NO-GO** — do **not** commit to the full 8-service / cloud-KMS / OIDC-federation / dual-approval / multi-agent topology, and do **not** publish the "$0 pilot" claim, until **R3-F1, R3-F2, and R3-F3** are corrected (honest LLM + infra cost model, current free-tier floor, self-durable backed-up op/audit DB). These are the three that would embarrass the vendor in front of a paying customer or a board.
- **First dollar of real spend:** a **managed, backed-up Postgres (PITR) for the operation-state + audit DB (~$19–25/mo)** — the entire "durable / reconstructable / tamper-evident" value proposition rests on that one store surviving. Everything else (KMS, OIDC, HA, extra agents) can wait behind its documented seam until the first paying customer.

---

## Per-budget capacity / availability / cost tables

### Table A — Pilot ($0–25/mo)

| Dimension | Assessment |
|---|---|
| **Expected capacity** | 1 staging worker, 1 environment, 1 operator, single region; a handful of deploys/restarts per day; op DB in the low-MB range. |
| **Expected availability** | Best-effort, no HA; free-tier **autosuspend/cold-start** of the ops DB/control plane (seconds–minutes) is the real limiter; effectively "business-hours reliable," no SLA. |
| **Operational burden** | LOW–MEDIUM if built as a monolith with software signing (what the proof is); **HIGH** if the full 8-service/KMS/OIDC/3-repo design is built for the pilot. |
| **Major cost drivers** | Near-zero for infra; the **hidden driver is Claude API tokens** for the multi-agent loop (excluded from the $0 claim — R3-F1). |
| **Free-tier risks** | Fly.io free workers **removed** (R3-F2); Neon/Supabase **autosuspend/pause**; Render **spin-down**; Cloudflare R2 class-A/B op limits. |
| **First paid trigger** | Ops-DB durability/uptime (autosuspend during an incident, no PITR) → managed Postgres (R3-F3). |
| **Scale trigger** | Adding prod, a 2nd worker type, or the first customer needing an SLA. |
| **Migration trigger** | Moving off the named free tiers / off Fly.io to a provider with real workload identity; multi-region. |
| **Likely hidden costs** | Claude tokens; KMS if adopted early; developer time operating 8 services; the undefined broker-root secret's eventual home (R3-F7). |

### Table B — Early production ($100–500/mo)

| Dimension | Assessment |
|---|---|
| **Expected capacity** | prod + staging, a few worker types, 1–5 operators, tens–hundreds of ops/day; real customer bundles flow through the (separate) TAC platform. |
| **Expected availability** | An **SLA is now owed**; the single-executor/single-region control plane (R3-F6) + free-tier DB (R3-F3) are the gaps. Target 99.9% requires managed backed-up Postgres + a warm-standby/fast-restart executor. |
| **Operational burden** | MEDIUM — on-call/paging, drift reconciliation, secret rotation become real. |
| **Major cost drivers** | Managed Postgres ($19–50), KMS ($1–10), compute for control plane + workers ($50–150), **Claude API for the operator loop (scales with ops; $tens)**, observability/paging (free→paid). |
| **Free-tier risks** | Outgrowing them; autosuspend now **unacceptable** for an ops plane. |
| **First paid trigger** | Already crossed — managed DB + KMS + always-on compute. |
| **Scale trigger** | Multiple customers/regions, concurrent cross-env operators, dual-approval classes actually exercised. |
| **Migration trigger** | Kubernetes/GitOps — correctly deferred by the design until here-or-later. |
| **Likely hidden costs** | LLM spend growth (planner + 2 review agents + narration per op — uncapped, R3-F4); audit-log retention/storage (R3-F8); observability/paging (R3-F9); cross-region transfer. |

### Table C — Enterprise ($1,000–10,000+/mo)

| Dimension | Assessment |
|---|---|
| **Expected capacity** | multi-region, multi-tenant, HA control plane, many worker types, high op volume, multiple operators, dual-approval flows, DR. |
| **Expected availability** | 99.95%+ with multi-node HA, multi-region failover, real KMS/HSM, workload-identity federation, break-glass — the point at which the deferred heavy topology is finally justified. |
| **Operational burden** | HIGH but amortized across a dedicated platform/SRE function. |
| **Major cost drivers** | HA Postgres + replicas ($200–1,000), KMS/HSM ($tens–hundreds), multi-region compute ($hundreds–thousands), **Claude API at scale ($hundreds–thousands — the dominant, uncapped variable; TAC analysis-diagnosis AI is a separate and likely larger LLM line)**, observability/SIEM, paging/on-call, compliance audit storage, security tooling. |
| **Free-tier risks** | n/a. |
| **First paid trigger** | n/a (all paid). |
| **Scale trigger** | Kubernetes + GitOps controllers now warranted — the design's earlier deferral was correct. |
| **Migration trigger** | To k8s/ArgoCD; dedicated KMS/HSM and security tooling. |
| **Likely hidden costs** | **Uncapped LLM spend** (no hard ceiling in the design — R3-F4) is the single biggest enterprise cost risk; unbounded audit retention (R3-F8); cross-tenant isolation compute; egress. |
