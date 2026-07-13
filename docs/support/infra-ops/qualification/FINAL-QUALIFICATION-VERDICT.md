# Final Qualification Verdict — Culvert TAC Support & Infra-Ops Platform

- **Basis:** Stage 1 reviewable staging proof (13 demos + 16-case failure matrix, re-run green after Stage-5 fixes), Stage 2 nine independent reviews (`reviews/R1..R9`), Stage 3 public-source vendor benchmark, Stage 4 no-rewrite evolution, Stage 5 consolidated ledger + closure (`CONSOLIDATED-FINDINGS.md`).
- **Aggregate maturity: ~2.6 / 5** — strong deterministic spine (≈4), near-zero product build-out (≈2). Unanimous reviewer stance: **architecture credible; not yet ready to claim production/enterprise/paid-pilot.**

---

## The 15 answers

**1. Would a mature enterprise security vendor consider this architecture credible?**
**Yes — the architecture, not the current build.** Reviewers (as vendor-archetype personas, no proprietary claims) judged the bones credible and, in several places (source-side fail-closed redaction with a CI parity wall, outbound-only + E2E-encrypt-to-TAC, hash-chained signed audit, deterministic single-mutation spine with plan-bound approval), **more disciplined than a conventional support-bundle platform**. What is not yet credible is *readiness*: the customer-facing and analysis layers are largely unbuilt.

**2. Which parts would it likely keep?**
The appliance as a thin outbound-only evidence producer; source-side redaction + `DataClass` parity wall; the `csb/1` typed bundle format; the Git+OpenTofu source-of-truth with a deterministic signed-plan executor; the 18-state durable operation FSM; plan-bound cryptographic approval; hash-chained signed audit; `tacctl` AI-independence; the three-tier (appliance/outbound/cloud) isolation and raw≠normalized planes.

**3. Which parts would it replace?**
Nothing architectural. It would replace *implementations behind interfaces*: SQLite→managed Postgres, HMAC→Ed25519/KMS, in-process mock provider→real provider, single worker→pool, and it would **build** the missing product layers (case management, customer console/status, known-issue base, analysis cloud, escalation package) rather than replace anything. Two design decisions were flagged as future-rewrite risks and **accepted for correction now** (R2-F1 ActionConnector for L2; R2-F5 composite tenant/env/region scope).

**4. Is the platform appropriate for Culvert's current budget?**
**The spine, yes; the full topology, no — as scoped.** R3's resolution stands: run the pilot as a **lean monolith** with the safety controls intact (tenant scope, separated signing, legal transitions, reconciliation — all proven in the harness in one process), not an 8-service KMS/OIDC fleet. Corrected: "$0" excludes AI inference and a backed-up DB.

**5. What is unnecessarily expensive or complex?**
For the pilot: the multi-service deployment, KMS/OIDC broker, dual-approval, and multi-agent review are premature — collapse to one process + software signing until real customers. A bespoke analysis *cloud* before proving appliance-only value (R1-F1) is the biggest premature cost.

**6. What is dangerously missing?**
(a) The **redaction secret-leak wall run on real `/data`** (R1-F2) — load-bearing, unimplemented. (b) **Tenant isolation** end-to-end (R7-F2 — closed in the harness; must be real KMS/row-level). (c) A **notification/dead-man's-switch** so `MANUAL_INTERVENTION_REQUIRED` can't sit unseen (R8-F1). (d) **Case creation + status + assignment** (R4-F1, R5-F1/F2) — without them the founder is the manual escalation point. (e) The **engineering escalation package** (R6-F1).

**7. Can the $0 pilot migrate to stable production without rewriting the product?**
**Yes.** The invariant interfaces (`csb/1`, collector contract, `DataClass` registry, 18-state FSM + record, 9 gateway tools + REST, plan/approval/audit artifacts, normalized-findings analyzer contract) survive Phases A→D; every scale step is a swap behind a frozen interface or an additive component (`EVOLUTION-ARCHITECTURE.md`). The one rewrite-forcing decision — state in memory/chat — was explicitly avoided (ADR-0022) and demonstrated (session-loss = non-event). The two accepted corrections (ActionConnector, composite scope) remove the remaining rewrite risks **if done before the second L2 action / second environment**.

**8. What is the first paid infrastructure investment?**
**Managed PostgreSQL with point-in-time recovery (~$19–25/mo)** for the operation + audit store — the durability/tamper-evidence guarantee rests entirely on that store surviving. Then a small paid worker + AI inference budget.

**9. What breaks first at 10 / 100 / 1,000 / 10,000 customers?**
- **~10:** human process — no case routing → the founder triages everything (R4-F1). Fix: case queue + auto-triage.
- **~100:** the single control-plane DB + single worker + free tiers — availability/throughput. Fix: managed HA Postgres + worker pool + durable queue (Phase C).
- **~1,000:** single-region ingestion + object-storage durability + audit-anchor scale; on-call load. Fix: multi-AZ, replication, KMS, tested DR, on-call rotation.
- **~10,000:** single-region control plane + tenant data residency + per-region isolation + BYOK + multi-team routing. Fix: regional ingestion + multi-region control plane (Phase D) — all additive behind frozen interfaces.

**10. What is the recommended production evolution path?**
Phase A ($0 lean monolith spine + AI + PITR DB) → Phase B (first customers: managed DB, monitored worker, prod email, real OIDC/KMS signing, durable storage, restore drills) → Phase C (redundant API, HA DB, worker pool, multi-AZ, tested DR, on-call) → Phase D (regional, residency, BYOK, multi-team, k8s executor adapter). Triggers gate each transition; never migrate ahead of the trigger.

**11. What blocks beginning implementation?**
**Nothing now** — the spine's code-level blockers (R9-F1/F2 legal transitions + idempotency, R8-F2/F4 crash fidelity + reconciler, R7-F1/F3 key separation + approver signature) are **CLOSED and re-run green**. Begin the spine per `proof-slice/README.md §4/§10`, mock-provider first.

**12. What blocks inviting design partners?**
Close (near-term, G0/M1): real **tenant isolation** (KMS/row-level, R7-F2), **composite scope** wiring (R2-F5), the **MANUAL notification/dead-man's-switch** (R8-F1), and **one run of the redaction secret-leak wall on real `/data`** (R1-F2). All have acceptance tests in the ledger.

**13. What blocks the first paying customer?**
A **costed, staffed cloud delivery plan + proven appliance-only value with the cloud absent** (R1-F1); **case creation/routing with `founder_actions == 0`** on the common path (R4-F1); and the **first-paid DB with PITR** (R3). Until these, "paid pilot" is NO-GO.

**14. What blocks an enterprise customer?**
**Case creation + in-product status** (R5-F1/F2); the **engineering escalation package** (R6-F1); the **ActionConnector** generalization (R2-F1); **audit global anchor + digest deny-list** (R7 design); the **full failure suite** incl. DB/object-storage/unknown-outcome/quota (R8); and the built (not designed) **known-issue matching + analysis cloud**.

**15. Final go/no-go verdict.**

| Gate | Verdict | Rationale |
|---|---|---|
| **Begin implementation (deterministic spine)** | **GO** ✅ | Unanimous; code-level blockers closed + re-run green; smallest slice and build order fixed. |
| **Invite design partners** | **CONDITIONAL GO** | After G0/M1 closures (tenant isolation real, composite scope, MANUAL notify, redaction wall run once). |
| **First paying customer** | **NO-GO (yet)** | Needs costed cloud plan + appliance-only value + case routing (no founder bottleneck) + PITR DB. |
| **Enterprise customer** | **NO-GO (yet)** | Needs case UX + escalation package + ActionConnector + audit anchor + full failure suite + built analysis cloud. |

**Overall:** **GO to build the spine; staged NO-GO on production/enterprise/paid claims until the milestoned blockers close.** The architecture is credible and evolution-safe; the work now is disciplined build-out from a proven, defect-fixed core — not redesign. Every remaining blocker has an owner-actionable acceptance test in `CONSOLIDATED-FINDINGS.md`.

---

## Integrity notes (stated plainly)

- The Stage-1 proof is a **local synthetic harness**, not a cloud deployment; it establishes control-loop *behavior*, not real crypto/provider/HA/scale. This is labeled everywhere and was the basis of several reviewer NO-GOs.
- Reviewers found **real harness defects**; the code-level ones were **fixed and re-run** (`evidence/closure_checks.txt`), not argued away. Design-level gaps are **accepted with milestones + acceptance tests**, never closed by assertion.
- No reviewer was represented as a vendor employee; benchmarks are public/observable only (`BENCHMARK.md`).
