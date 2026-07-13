# Stage 5 — Consolidated Findings Ledger, Disagreement Resolution & Closure

- **Inputs:** nine independent first-pass reviews (`reviews/R1..R9-*.md`), run without cross-exposure. Full reports on disk; this ledger consolidates, resolves conflicts, and records accept/reject + closure.
- **Method note (honest):** the Stage-1 proof is a local synthetic harness. Reviewers correctly distinguished *design* soundness from *proof fidelity*, and several found **real defects in the harness**. Code-level defects were **fixed and re-run green** (closure evidence: `staging-proof/evidence/closure_checks.txt` + regenerated `failure_matrix.md`). Design-level gaps are **accepted with a milestone + acceptance test**, not hand-waved.

---

## 1. Reviewer scoreboard

| Reviewer | Lens | Score | First-pass go/no-go |
|---|---|---:|---|
| R1 Supportability Architect | vendor credibility | 2/5 | GO staged program; NO-GO enterprise-ready |
| R2 Infra Platform Architect | evolution/no-rewrite | 4/5 | GO build slice; conditional on F1/F5 |
| R3 FinOps / Startup CTO | budget fit | 3/5 | GO lean monolith; NO-GO "$0" + full topology |
| R4 TAC Ops Manager | run without founder bottleneck | 2/5 | NO-GO paid pilot until case-flow specified |
| R5 Customer Admin UX | customer round-trip | 2/5 (internals 4) | NO-GO GA until case create/status ship |
| R6 Escalation Engineer | fault-class discrimination | 2/5 | NO-GO until escalation package + instrumentation |
| R7 Security & Privacy | adversarial | 3/5 | GO design; NO-GO storing real evidence |
| R8 SRE / Incident Commander | failure realism | 3/5 | NO-GO as incident evidence; GO as demonstrator |
| R9 AI Operations Architect | AI-as-dependency | 2/5 | GO spine; NO-GO mutating deploy |

**Aggregate:** mean ≈ 2.6/5; **unanimous GO to build the deterministic spine; unanimous NO-GO for production/enterprise/paid-pilot/live-model exposure until blockers close.** No reviewer rejected the architecture; all rejected *readiness claims*.

---

## 2. Disagreement resolution (explicit)

| Disagreement | Resolution |
|---|---|
| **R2 scored 4/5; R1/R4/R5/R6/R9 scored 2/5.** | Not a contradiction — different scopes. R2 judged the *infrastructure spine* (genuinely strong, and now defect-fixed). The 2/5 reviewers judged *product completeness* (case flow, customer UX, escalation, analysis cloud) which is near-zero. **Accept both:** spine ≈ 4, product ≈ 2. The program's honest composite is ~2.6 and the split is the actionable signal: build outward from a strong spine. |
| **R3 "over-engineered for pilot" vs R7/R8 "under-engineered on safety."** | Different axes. R3 targets *operational topology* (8 services, KMS, OIDC, dual-approval, multi-agent) — over-built for a 1–2 person pilot. R7/R8 target *safety controls* (tenant isolation, key separation, crash handling, notification) — under-built. **Resolution:** collapse the pilot to a **lean monolith** (R3) while **keeping the safety controls** (R7/R8) — these are compatible: a monolith can still enforce tenant scope, separated signing, legal transitions, and reconciliation. The proof harness already runs as one process with those controls. |
| **"$0 pilot" (docs) vs R3 "$0 excludes the AI (the product)."** | R3 is right. **Accept:** the appliance/spine is $0; AI inference and a backed-up control-plane DB are the first real costs. Revised in `EVOLUTION-ARCHITECTURE` + staging README. |
| **R9 "AI is not a safety dependency" (verified) vs its own R9-F1/F2 exploit.** | Both true: the platform is AI-independent (CLI-operable, verified), *and* the harness FSM had a legality gap the model's dup-call exposed. The gap was a **harness bug, not an architecture flaw** — fixed (closure below). |

---

## 3. Consolidated blocking-findings ledger

Status legend: **CLOSED-NOW** (fixed + re-run green) · **ACCEPT→milestone** (accepted; scheduled with acceptance test) · **REJECT** (with rationale).

| ID(s) | Theme / finding | Component | Disposition | Resolution & closure |
|---|---|---|---|---|
| **R9-F1** | FSM enforced version-CAS but not **legal transitions**; a dup call drove `SUCCEEDED→PLANNING`. | operation FSM | **CLOSED-NOW** | Added `LEGAL` transition map; `set_state` raises `IllegalTransition`. Evidence: `closure_checks.txt` "R9-F1 PASS". |
| **R9-F2** | L2/`tacctl` path ignored the idempotency dup flag → re-execution. | tacctl / create_op | **CLOSED-NOW** | `cmd_cli_restart` honors dup: returns existing op, no re-exec; event count unchanged. Evidence: "R9-F2 PASS". |
| **R8-F2** | "Executor crash" was a graceful caught exception that cleanly released the lease → lease-expiry→reconciler path never exercised. | executor / reconciler | **CLOSED-NOW** | Crash now leaves op `EXECUTING` with lease **held**; `force_expire_lease`+reconciler resolves from provider truth. Cases 7/8 re-run. |
| **R8-F4** | Crash-after case dead-ended in `VALIDATING` with no follow-through. | reconciler | **CLOSED-NOW** | Reconciler resumes → validate → terminal (`SUCCEEDED`). Case 8 green. |
| **R7-F1** | One symmetric HMAC key signed plans **and** approvals **and** audit → SoD/non-repudiation collapse. | signing | **CLOSED-NOW (harness) + design** | Split into three distinct keys (`SIGN_KEYS`), stand-ins for distinct Ed25519/KMS keys. Design records key separation. Evidence: "R7-F1 PASS". |
| **R7-F2** | **No tenant isolation** anywhere in the proven loop (no `tenant_id` in schema/policy). | schema / policy | **CLOSED-NOW (harness) + ACCEPT→G0 design** | Added `tenant_id` to `worker_registry`/`operations`, plan body, and a deterministic `P0_tenant` rule; cross-tenant plan rejected. `schema.sql` design updated. Evidence: two "R7-F2 PASS". Real multi-tenant KMS/row-level scoping = G0 acceptance test. |
| **R7-F3** | Approvals were plain DB writes; self-approval prevention caller-asserted; no approver signature. | approval | **CLOSED-NOW** | Approval now carries an `approver_signature` distinct from the plan signature. Author-approval already rejected. Evidence: "R7-F3 PASS". |
| **R2-F1** | Two spines: L2 actions mutate via **direct imperative provider APIs** (the rejected "direct API execution"), no connector/desired-state/reconciliation. | executor / L2 | **ACCEPT→G4 (design change before 2nd connector)** | Define an `ActionConnector` interface + registry (typed, bounded, idempotent, reversible, audited, reconcilable) that ALL L2 actions implement; no L2 action ships without it. Acceptance: a second L2 action reuses the interface; `TestActionConnectorContract`. Recorded in proof-slice. |
| **R2-F5** | Single env baked into schema CHECKs, policy, lease keys; no composite tenant/env/region scope. | schema / scope | **ACCEPT→G0** (partially closed) | Tenant added now. Composite `(tenant,env,region)` scope key + policy scoping = G0 design must-fix before multi-env. Acceptance: lease key + policy input carry the triple; `TestScopeCompositeEnforced`. |
| **R1-F1** | All diagnostic *value* is coupled to a Tier-3 TAC cloud that doesn't exist / isn't costed/staffed. | program | **ACCEPT→gating** | Produce a **costed, staffed cloud delivery plan** and prove **appliance-only value with the cloud absent** (local health + offline bundle a human can read) before building a bespoke analysis cloud. Acceptance: an appliance-only bundle yields an actionable finding with no cloud. Gates "first paying customer". |
| **R1-F2 / (redaction wall)** | The load-bearing `TestNoSecretInBundle` + `data_surfaces_test.go` parity wall is unimplemented/unrun on real `/data`. | redaction | **ACCEPT→M1 (hard gate)** | Implement + run the secret-leak wall on real `/data` fixtures. Acceptance: planted canaries of every class absent from a bundle at all levels/scopes. Blocks any real evidence collection. |
| **R4-F1** | No **case assignment/routing** engine; "human TAC ownership" is an entitlement flag → triage defaults to the founder. | TAC ops | **ACCEPT→cloud-track M2** | Specify a case queue + routing/assignment + auto-triage so `founder_actions == 0` on the common path. Acceptance: `TestCommonPathNoFounderAction`. Gates paid pilot. |
| **R4-F2/F3** | No escalation criteria; prod dual-approval hard-routes the founder as mandatory 2nd approver. | approval / escalation | **ACCEPT→cloud-track** | Define escalation SLAs + a second approver pool (not the founder). Acceptance: dual-approval satisfiable without the founder. |
| **R5-F1** | No way for a customer to **open a case / obtain `case_id`**, yet `case_id` is required by upload/manifest/tenant everywhere. | customer UX | **ACCEPT→cloud-track M2 (blocker for GA)** | Add case-creation (portal + in-product) issuing `case_id`. Acceptance: an admin creates a case and uploads in ≤3 steps, no email. Gates enterprise customer. |
| **R5-F2** | No in-product **case-status / TAC-response** surface. | customer UX | **ACCEPT→cloud-track** | Case status + TAC-request inbox in-product. Acceptance: "where is my case?" answerable in-product. |
| **R6-F1** | The **GitHub engineering-escalation package** is entirely unspecified (no schema, evidence-refs, repro payload, engineering-tier redaction boundary). | escalation | **ACCEPT→cloud-track (blocker for eng handoff)** | Specify the escalation-package schema (versions, evidence refs, repro, rollback info, timeline, redaction tier). Acceptance: a golden escalation package validates + reproduces a synthetic bug. |
| **R6-F2..F4** | 4/6 fault-class distinctions (product-bug/capacity/version-regression/cluster-convergence) depend on **unbuilt instrumentation** (panic recovery, saturation gauges, per-DP version, failover ring). | instrumentation | **ACCEPT→M1/M5** (already in gap analysis §5) | Ship the named instrumentation. Acceptance: each distinction is decidable from a bundle. |
| **R8-F1** | `MANUAL_INTERVENTION_REQUIRED` "pages the human" but there is **no notification component** and no detection if the page never arrives → unbounded MTTD. | notification | **ACCEPT→G0/G6 (blocker for live-model)** | Add a notification connector + dead-man's-switch (unacked MANUAL escalates). Acceptance: `TestManualAlertDeliveredAndAcked`. |
| **R8 (unmodeled)** | DB restart, object-storage failure, unknown/in-doubt outcome, quota exhaustion not modeled. | resilience | **ACCEPT→G-hardening** | Extend the failure suite. Acceptance: each has a detection + recovery + fallback test. |
| **R3 (blockers)** | "$0" excludes AI; stale free-tier premise (Fly.io free workers gone); control-plane DB no self-backup. | FinOps | **CLOSED-NOW (docs) + ACCEPT first-paid** | Docs corrected (`EVOLUTION`, staging README). First paid investment = **managed Postgres with PITR (~$19–25/mo)** for the op+audit DB. |
| **R7 (design)** | P4 accepts any allowlisted digest incl. known-vulnerable (rollback-to-vulnerable); L2 availability blast radius; per-op audit has no global anchor. | policy / audit | **ACCEPT→milestones** | (a) add a digest **deny-list** + min-version to P4; (b) rate-limit + notify on L2 availability actions; (c) periodic **audit anchor** (chain-of-chains) so whole-op deletion is detectable. Acceptance tests named per item. |

**No findings were REJECTED.** Every reviewer finding is either fixed now or accepted with a milestone + acceptance test. (One clarification recorded rather than rejected: R9's "AI is a dependency" concern — the platform is verified AI-independent; only the harness legality bug was real, and it is closed.)

---

## 4. Revisions applied in Stage 5

**Harness (code-level closure, re-run green):** legal-transition guard; idempotency honored on the L2/CLI path; ungraceful-crash fidelity + lease-expiry reconciler + follow-through; three separated signing keys; approver signature; `tenant_id` + `P0_tenant` policy rule + cross-tenant rejection; partial-apply now fails validation. Evidence: `evidence/closure_checks.txt`, regenerated `evidence/failure_matrix.md`, `evidence/run.log`.

**Design docs revised:** `proof-slice/schema.sql` (tenant columns, separated-key note, approver signature) and `proof-slice/README.md` (ActionConnector requirement, composite scope); `EVOLUTION-ARCHITECTURE.md` + staging README (FinOps corrections: $0 excludes AI, DB PITR as first paid, stale-free-tier note); `TAC-CLOUD-ARCHITECTURE.md` (case lifecycle + GitHub escalation-package schema) — see the Stage-5 revision banners in those files.

---

## 5. Blocker closure status (for the go/no-go gates)

| Gate | Blockers that must be closed | Status |
|---|---|---|
| **Begin implementation (spine)** | R9-F1, R9-F2, R8-F2/F4, R7-F1, R7-F3 | **ALL CLOSED-NOW** ✅ |
| **Invite design partners** | + R7-F2 (tenant), R2-F5 (composite scope) G0, R8-F1 (MANUAL notify), R1-F2 redaction wall run once | tenant/keys/approver closed; composite-scope + MANUAL-notify + redaction wall = **G0/M1 acceptance** (near) |
| **First paying customer** | + R1-F1 (costed cloud + appliance-only value), R4-F1 (case routing, no founder bottleneck), R3 first-paid DB PITR | **OPEN → milestones** |
| **Enterprise customer** | + R5-F1/F2 (case create/status), R6-F1 (escalation package), R2-F1 (ActionConnector), R7 audit-anchor/deny-list, full failure suite | **OPEN → milestones** |

Re-run confirmation: the E2E workflow (`demo`) and the 16-case failure matrix (`failtest`) were re-run after all code-level fixes and are **green**; the blocking reviewers' code-level findings (R7/R8/R9) are demonstrably closed with committed evidence. Design-level blockers carry explicit acceptance tests and milestones above.
