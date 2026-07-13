# R2 — Independent Qualification Review: Enterprise Infrastructure Platform Architect

- **Reviewer role:** Enterprise Infrastructure Platform Architect (independent; vendor-neutral).
- **Scope reviewed:** `docs/support/infra-ops/*.md`, `docs/support/infra-ops/proof-slice/*` (README, STATE-MACHINE, schema.sql, TOOL-AND-API-CONTRACTS, POLICY-IDENTITY, ARTIFACTS-AND-AUDIT, OPENTOFU-ALGORITHMS, TESTING-AND-ACCEPTANCE), ADR-0019…0022, and the staging-proof harness (`tac_proof.py demo` + `failtest`, executed) with its evidence set.
- **Evaluation lens:** Git+OpenTofu as source of truth; deterministic executor; operation state; policy; identity/credentials; rollback; drift; DR; provider portability; production failure modes — and specifically **whether the design evolves to multi-env / multi-region / redundant workers / managed Postgres / redundant object storage / HA / Kubernetes / multi-cloud WITHOUT a rewrite.**
- **Date:** 2026-07-13. Harness re-run confirmed: 13/13 demonstrations pass; 16/16 failure cases land in the specified persisted state.

---

## 1. Verdict

**Conditionally sound; evolution-ready with two architectural decisions that must be fixed at design time or they become future rewrites.** The design correctly refuses the dangerous shape (model-as-executor / model-as-source-of-truth) and instead builds a deterministic spine — durable FSM, content-addressed signed plans, cryptographic plan-bound approval with self-approval rejection, provider-truth reconciliation, validation that does not trust provider-200, and a demonstrated AI-independent CLI path. The executed proof is honest and behaviorally faithful to the state machine, policy gate, single-mutation discipline for the deploy path, rollback, and hash-chained audit. It is a **strong design + reference harness**, not a production system, and it says so plainly.

The evolution goals are mostly reachable by migration, not rewrite: OpenTofu + module boundary (k8s/multi-cloud), Postgres DDL (managed PG), state-backend swap (redundant object storage), and DB-held leases (redundant executors/HA) all generalize. **The one decision that most credibly forces a future rewrite is the un-abstracted dual mutation spine:** L3 deploys flow through OpenTofu desired-state, but the entire L2 action class (restart today; retry-job, recover-lease, clear-cache, pause-consumer, disable-uploads, scale-in-free-bounds per ADR-0021) mutates through direct imperative provider APIs with **no connector interface, no desired-state representation, and no reconciliation** — the very "direct API execution" the architecture rejects (§3), re-entering through the L2 door. Ratify with the corrections in §9 before building past the single restart action.

## 2. Maturity score

**4 / 5** — for a design-plus-reference-proof at this stage.

- +Strong: the deterministic-spine decisions are correct and, unusually, *demonstrated* not merely asserted.
- +Strong: explicit honesty boundary ("does NOT establish…") — high enterprise credibility.
- −Held below 5: the imperative L2 spine is unabstracted (rewrite risk); proof-fidelity gaps (symmetric in-process HMAC standing in for non-repudiable audit signing; lease TTL/heartbeat expiry not actually exercised; no Git commit-binding exercised); scope is hardcoded single-env/single-worker in both schema CHECKs and policy. None are fatal; all are addressable pre-build.

## 3. Unusually strong (call out explicitly)

- **Three independent concurrency mechanisms, all demonstrated:** `operations.idempotency_key` UNIQUE, per-worker apply lease, and optimistic `version` CAS (`schema.sql:56,59,117`; STATE-MACHINE §3–5; failtest cases 3 & 12 pass). Most designs ship one; this ships three with distinct roles.
- **Crash-before vs crash-after resolved by provider truth, not by guessing** (STATE-MACHINE §4; OPENTOFU-ALGORITHMS §recovery; `tac_proof.py:335`; failtest 7→FAILED vs 8→VALIDATING are *distinct* outcomes). This is the single hardest correctness property in infra automation and it is exercised.
- **Validation refuses provider-200:** synthetic-job lease + safe synthetic analyzer task (V3/V4) gate SUCCEEDED (OPENTOFU-ALGORITHMS §3; demo step 10 fails on a bad digest with `[V1,V3,V4]`). This is materially stronger than typical health-check-only gates.
- **Cryptographic plan-bound approval with self-approval rejection, demonstrated** (ARTIFACTS §2; demo step 8: author self-approval REJECTED, independent human bound to plan signature). Approval is a signed record over the exact content-addressed plan, not a chat "yes."
- **AI-independence proven as a real subprocess**, not claimed (`tacctl` L2 restart → SUCCEEDED, demo step 13; failtest 16). Removing the model leaves an operable platform.
- **Product/infra/control-plane repo split with CODEOWNERS** (proof-slice README §2) — the correct blast-radius decision; a product PR structurally cannot alter infrastructure.
- **Policy-as-hard-gate, reviews-as-advisory ordering** (POLICY-IDENTITY §4) — a compromised model can at most *propose*; the deterministic gate rejects.

## 4. Blocking findings

### R2-F1 — The dual mutation spine has no connector abstraction (the primary rewrite risk)
- **Severity:** Blocking (for any build beyond the single restart action)
- **Affected component:** `services/executor` (restart_action.go vs deploy_tofu.go); the L2 action class (ADR-0021)
- **Realistic scenario:** The slice ships one imperative L2 action (Fly machine-restart). ADR-0021 pre-commits an L2 allowlist (retry job, recover lease, clear cache, pause consumer, disable uploads, scale-in-free-bounds). Each is implemented as a bespoke provider-API call in the executor. A year later the platform adds a second provider (or k8s), and every imperative action must be re-implemented per provider with its own verify/lease/audit/rollback wiring.
- **Business impact:** A multi-cloud or k8s migration — sold as "swap the OpenTofu provider block, no rewrite" (INFRA-OPS-ARCHITECTURE §3) — silently excludes the entire L2 surface, which becomes an unstructured per-provider imperative layer. Migration cost and risk balloon; the "no rewrite" promise breaks for exactly the actions Claude runs most often.
- **Technical impact:** The README's "the executor is the ONLY component that changes infrastructure / single mutation spine" is already two spines: declarative `tofu apply <saved plan>` and imperative provider API (`README §3`, `proof-slice/README §1`, `tac_proof.py:129` restart bypasses OpenTofu entirely). Imperative L2 actions change runtime state that is not in Git → the drift reconciler (INFRA-OPS-ARCHITECTURE §3) will flag them forever or must be taught per-action exceptions. This is the "Direct API execution — Rejected" row (INFRA-OPS-ARCHITECTURE §3) re-entering through L2.
- **Evidence:** `proof-slice/README.md` §3 (restart = "typed orchestration action … No desired-state change"); `OPENTOFU-ALGORITHMS.md` (deploy path only); `docs/adr/0021` (L2 allowlist enumerated); `tac_proof.py:107–140,253–286`.
- **Required correction:** Define now a single `ActionConnector` interface that BOTH the OpenTofu executor and every imperative L2 action implement — with a uniform contract: `verify(sig+approval+lease) → mint-scoped-creds → apply → record per-resource outcome → validate → declare rollback (or irreversible)`. Register imperative actions in a fixed connector registry (the FAILURE-AND-THREAT §3 harness already assumes this). Make "desired-state-affecting" a declared connector attribute so the drift reconciler can distinguish runtime-only actions from desired-state changes deterministically.
- **Acceptance test:** `TestActionConnectorUniformContract` — every registered mutator (tofu + each L2 action) passes the identical verify/lease/creds/audit/rollback conformance suite; `TestDriftReconcilerIgnoresRuntimeOnlyActions` — a runtime-only L2 action produces zero standing drift; a desired-state action does.
- **Recommended milestone:** Before implementing the SECOND mutating connector (i.e. immediately after the restart slice, before any additional L2 action).

## 5. High-priority findings

### R2-F2 — Audit "signature" is a symmetric in-process HMAC; the tamper-evidence claim is not demonstrated against the writer
- **Severity:** High
- **Affected component:** `services/audit`; proof `emit()`
- **Realistic scenario:** A compliance auditor or a security reviewer asks the qualification board to demonstrate that the audit chain is non-repudiable and cannot be forged by the component that writes it. The proof uses `hmac.new(SIGN_KEY, …)` with a hardcoded key (`tac_proof.py:29,38,86–95`) living in the same process that writes events — anyone with the writer's memory can forge any "signed" event and recompute the chain.
- **Business impact:** The strongest enterprise selling point (tamper-evident signed audit reconstructable without chat) is, as *demonstrated*, only integrity-against-accident, not non-repudiation. A board that probes this finds the evidence weaker than the prose (ARTIFACTS §3 promises Ed25519/KMS "separate store").
- **Technical impact:** Symmetric HMAC gives no signer/verifier separation; hash-chaining detects out-of-band edits but not a malicious writer re-signing the whole chain.
- **Evidence:** `tac_proof.py:29,38,86–95`; `ARTIFACTS-AND-AUDIT.md` §3 (claims audit-writer Ed25519, KMS, append-only grant, separate store).
- **Required correction:** In the real build, sign events with an asymmetric key the audit writer holds via KMS, verified by an independent verifier that never holds the private key; enforce append-only at the DB grant level (no UPDATE/DELETE); place the audit store on a separate trust boundary. In the harness, at minimum use an asymmetric keypair and verify with the public half only, to demonstrate the property.
- **Acceptance test:** `TestAuditNonRepudiable` — verification succeeds with the public key alone; a writer that lacks the private key cannot produce a chain that verifies; `TestAuditAppendOnlyGrant` — UPDATE/DELETE on `operation_events` is denied at the DB role level.
- **Recommended milestone:** G0 spine, before any mutating connector is exposed to a live model.

### R2-F3 — Lease TTL/heartbeat expiry is not exercised; reconciler is invoked directly, so redundant-executor HA is unproven
- **Severity:** High
- **Affected component:** `services/operation` (lease.go, recovery.go); proof `acquire_lease`/`reconcile_after_crash`
- **Realistic scenario:** Two executors run for HA. Executor A takes the lease and dies mid-apply. The system must let B (or the reconciler) reclaim the worker only after A's lease TTL lapses, and never before. The proof's `acquire_lease` only checks for row existence (`tac_proof.py:220–226`) with no time-based expiry; `reconcile_after_crash` is called directly by the test, not triggered by an expired heartbeat (`tac_proof.py:335`). The `heartbeat_at`/`expires_at` columns exist but are inert.
- **Business impact:** The evolution goal "redundant workers / HA control plane" rests on lease reclamation semantics that the proof does not demonstrate; a subtle bug here is a split-brain double-apply — the worst infra failure mode.
- **Technical impact:** No test proves "second executor waits for TTL, then reclaims"; no test proves "a still-heartbeating holder cannot be preempted." Culvert already owns a correct fencing pattern (ADR-0005) that should be reused rather than reinvented.
- **Evidence:** `tac_proof.py:65 (schema has heartbeat_at/expires_at),220–230,335–343`; STATE-MACHINE §4 (design describes TTL+heartbeat+reconciler).
- **Required correction:** Implement time-based lease expiry (acquire fails if a non-expired lease is held; succeeds only past `expires_at`), executor heartbeat renewal, and a reconciler triggered by lease expiry — reusing the ADR-0005 halease fencing epoch semantics. Add the missing tests.
- **Acceptance test:** `TestLeaseReclaimOnlyAfterTTL`, `TestNoPreemptionOfLiveHolder`, `TestReconcilerTriggeredByExpiry` (not by direct call).
- **Recommended milestone:** G0 spine; required before "redundant executors" is claimed.

### R2-F4 — Git commit-binding ("commit unchanged") is a load-bearing precondition that is never exercised
- **Severity:** High
- **Affected component:** `services/executor` verify; planner
- **Realistic scenario:** Between approval and apply, someone force-pushes the plan branch. The design's safety property (APPROVED→EXECUTION_QUEUED requires "commit unchanged"; ARTIFACTS §2 rule 5) must reject the apply. The proof has no Git at all — the commit-drift case (failtest 5) is simulated by regenerating a *plan object*, not by detecting a changed Git tree (`tac_proof.py` plan-vs-plan comparison).
- **Business impact:** "Git+OpenTofu = source of truth" is the foundational claim; the binding that makes Git authoritative at apply time is undemonstrated, so the source-of-truth guarantee is partially prose.
- **Technical impact:** Content-addressed plan_id catches config/plan changes, but the "same commit_sha still resolves to the same tree" check (post-approval commit drift) is a separate property against the Git backend that is not implemented or tested.
- **Evidence:** `ARTIFACTS-AND-AUDIT.md` §2 rules 1 & 5; `STATE-MACHINE.md` APPROVED→EXECUTION_QUEUED ("commit unchanged"); `tac_proof.py` (no VCS).
- **Required correction:** In the real build, the executor must re-resolve `plan.commit_sha` against the Git backend and confirm the tree hash before apply; add an integration test with a real (local) Git repo that force-pushes between approval and apply.
- **Acceptance test:** `TestCommitDriftRejectsApply` — a post-approval tree change on the same or moved ref causes execute to reject with `commit_drift`, op stays APPROVAL_PENDING.
- **Recommended milestone:** Executor milestone (§4 step 8), before real-provider apply.

### R2-F5 — Single-environment/single-worker is baked into schema CHECK constraints and policy; multi-env/region/tenant scope model is undefined
- **Severity:** High
- **Affected component:** `schema.sql`; `services/policy`; lease key
- **Realistic scenario:** The platform must add `production` and a second region. Today `worker_registry` and `operations` carry `CHECK (environment = 'staging')` (`schema.sql:13,38`), policy P1 hardcodes staging (POLICY-IDENTITY §1), and the lease key is `staging:<worker_id>` (`tac_proof.py:221`) with no region/tenant dimension.
- **Business impact:** Multi-environment and multi-region are explicit evolution goals. The relaxation is a DDL migration (fine) BUT the scope model — how environment × region × tenant × resource compose into lease keys, policy scope tokens, and gateway authz — is not designed, so it will be invented ad hoc under pressure (migration risk trending toward rewrite of the scope layer).
- **Technical impact:** The lease `resource_key` conflates env+resource; regional/tenant isolation needs a composite scope identity threaded through leases, policy, gateway session scoping, and the reconciler. Retrofitting a scope model across all of these is the expensive path.
- **Evidence:** `schema.sql:13,38,59`; `POLICY-IDENTITY.md` §1 (P1 staging-only); `tac_proof.py:221`.
- **Required correction:** Define a composite scope identity now — `scope = {tenant, environment, region, resource}` — and thread it through the lease key, policy input, and gateway session scope, even while the slice pins it to `{-, staging, -, worker}`. Keep the CHECK constraints as a deliberate slice guardrail, but design the columns and keys to generalize.
- **Acceptance test:** `TestScopeCompositeKey` — lease/policy/authz all key on the composite scope; `TestMultiEnvIsolation` (design-level) — an op scoped to staging cannot acquire a production lease.
- **Recommended milestone:** Schema + policy design revision, before implementation of the operation service.

## 6. Medium-priority findings

### R2-F6 — Saved OpenTofu plan binary is not bound to the tofu/provider *binary* version
- **Severity:** Medium
- **Affected component:** `services/executor` (`tofu apply tfplan.bin`)
- **Realistic scenario:** A control-plane image upgrade changes the OpenTofu version between plan and apply; a saved `tfplan.bin` from an older tofu may be rejected or misread by a newer binary.
- **Business impact:** Spurious apply failures on otherwise-valid approved plans during routine control-plane upgrades.
- **Technical impact:** The plan captures `provider_lock_digest` (P10, invalidates on provider change) but not the tofu binary version; `tfplan.bin` compatibility is version-scoped.
- **Evidence:** `OPENTOFU-ALGORITHMS.md` §2 step 10; `schema.sql:70` (provider_lock_digest only).
- **Required correction:** Capture the tofu binary version into the plan artifact and verify it (or the exact runner image digest) at apply; on mismatch, force a re-plan rather than apply a stale binary.
- **Acceptance test:** `TestPlanRejectedOnTofuVersionSkew`.
- **Recommended milestone:** Executor milestone.

### R2-F7 — Provider portability leans on Fly.io provider maturity; the "edge config" escape hatch can grow
- **Severity:** Medium
- **Affected component:** `modules/analysis_worker`; INFRA-OPS-ARCHITECTURE §3
- **Realistic scenario:** Fly's OpenTofu provider is noted as "the variable" (proof-slice README §6). If it is weak, the design permits provider-specific config "only at the edges" (`fly.toml`) — Low-portability by the doc's own matrix. Edges have a way of growing.
- **Business impact:** Multi-cloud migration cost rises proportional to how much lives in provider-specific edge config rather than OpenTofu.
- **Technical impact:** Portability is only as good as the fraction of desired state expressed in portable OpenTofu.
- **Evidence:** `INFRA-OPS-ARCHITECTURE.md` §3 (matrix; "provider-specific config only at the edges"); proof-slice README §6.
- **Required correction:** Set a governance cap — a measurable ceiling (e.g. ≤5% of resources) on non-OpenTofu edge config, tracked as a metric; any exceedance requires an ADR.
- **Acceptance test:** `TestPortableStateRatio` — CI asserts the edge-config ratio under the ceiling.
- **Recommended milestone:** Post-slice, first real provider integration.

### R2-F8 — Restart (L2) recovery is provider-truth-only and terminal-to-manual; acceptable, but the "no rollback" hole in source-of-truth should be explicit in the operator model
- **Severity:** Medium
- **Affected component:** `services/executor` restart path; validator
- **Realistic scenario:** A restart fails validation. There is no version to roll back to (correct), so it goes FAILED→MANUAL_INTERVENTION_REQUIRED (STATE-MACHINE §1). For k8s, "restart" (rollout restart) *does* mutate a revision annotation — a desired-state change — so the L2/L3 classification of "restart" is provider-dependent.
- **Business impact:** On a provider where restart touches desired state, an action classified L2 (autonomous) would be performing a desired-state change without approval — a classification error, not a code bug.
- **Technical impact:** The L2/L3 level is asserted per action but its correctness depends on provider semantics that vary.
- **Evidence:** STATE-MACHINE §1 (L2 restart, no rollback); ADR-0021 (L2 = reversible/no-data/no-desired-state by construction).
- **Required correction:** Make "affects desired state" a per-connector, per-provider declared attribute that the policy engine reads to *derive* the level, rather than a static action-name→level map; fail closed if a provider's action would touch desired state under an L2 label.
- **Acceptance test:** `TestLevelDerivedFromDesiredStateAttribute` — a provider action flagged desired-state-affecting cannot be classified L2.
- **Recommended milestone:** Ties to R2-F1 connector abstraction.

### R2-F9 — SQLite CAS uses `total_changes` process-global counter; the demonstrated CAS does not reflect Postgres row-count semantics
- **Severity:** Medium
- **Affected component:** proof `set_state` (`tac_proof.py:97–103`)
- **Realistic scenario:** The optimistic-concurrency proof relies on `c.total_changes == 0` to detect a lost CAS. `total_changes` is a connection-lifetime cumulative counter, not the per-statement affected-row count; the demonstrated CAS is weaker/differently-shaped than the intended Postgres `UPDATE … WHERE version=? → rows_affected` check.
- **Business impact:** A board could reasonably discount the concurrency demonstration as not matching the target engine.
- **Technical impact:** Correct in the single-threaded harness by luck of ordering; not a faithful stand-in for Postgres CAS.
- **Evidence:** `tac_proof.py:101–103`.
- **Required correction:** Use `cursor.rowcount` per-statement in the harness; keep the Postgres design as `WHERE version=?` with `rowcount==1` assertion.
- **Acceptance test:** `TestCASUsesPerStatementRowcount`.
- **Recommended milestone:** Harness hardening (low effort).

## 7. Over-engineered (relative to the slice)

- **18-state FSM + REVIEW_PENDING advisory security/cost agents for a $0 single-worker staging restart** (STATE-MACHINE §1; POLICY-IDENTITY §1). The review-agent layer adds ceremony the slice does not need; defensible as forward-investment, but it should be explicitly deferred behind a flag so the slice's critical path is the minimal FSM, not the full one.
- **Dual-approval mechanism fully specified though "none required for this slice"** (ADR-0021; ARTIFACTS §2). Correct to design the seam; building/testing the dual path now is premature relative to the stated goal.
- **Content-addressed signing of restart plans** that carry no desired-state change (`expected_changes:{action:restart,version_invariant:true}`). Signing a no-op plan is harmless but adds a signing dependency to the autonomous L2 path that otherwise needs no artifact.

## 8. Under-engineered (gaps to close before scale)

- **Non-repudiable audit signing** (R2-F2) — symmetric HMAC standing in for asymmetric/KMS.
- **Lease TTL/heartbeat expiry + expiry-triggered reconciler** (R2-F3) — columns exist, semantics inert.
- **Git commit-binding at apply** (R2-F4) — the source-of-truth binding is unexercised.
- **Composite scope model** for multi-env/region/tenant (R2-F5).
- **Connector abstraction for imperative L2 actions** (R2-F1).
- **Rate limiting / backpressure** — asserted at the gateway (TOOL-AND-API-CONTRACTS §5) but not demonstrated; a runaway-automation control with no test.
- **OpenTofu state-backend locking under contention** — explicitly out of scope of the proof (staging-proof README §6) but is the real concurrency boundary for out-of-band `tofu apply`; needs a real-backend contention test before HA.
- **DR / restore-into-isolated-target** — design-only (FAILURE-AND-THREAT §17), no drill exercised.

## 9. Exact proposed changes

1. **Introduce `ActionConnector` interface + registry now** (fixes R2-F1). Every mutator — the OpenTofu executor and each imperative L2 action — implements one contract: verify(sig+approval+lease) → mint scoped creds → apply → record per-resource outcome → validate → declare rollback/irreversible → emit signed audit. Add `affects_desired_state:bool` and `reversible:bool` as declared connector attributes consumed by the policy engine (level derivation) and the drift reconciler.
2. **Replace symmetric audit HMAC with asymmetric signing** (fixes R2-F2); enforce append-only DB grant; place audit on a separate trust boundary; verifier holds the public key only. Harden the harness to at least an asymmetric keypair.
3. **Implement time-based lease expiry + heartbeat renewal + expiry-triggered reconciler** reusing ADR-0005 fencing semantics (fixes R2-F3). Add reclaim/no-preemption tests.
4. **Add Git commit re-resolution at apply** against the real backend; integration test with force-push between approval and apply (fixes R2-F4).
5. **Define and thread a composite scope identity** `{tenant, environment, region, resource}` through lease key, policy input, and gateway session scope; keep slice pinned to staging via CHECK guardrails but design columns/keys to generalize (fixes R2-F5).
6. **Bind plans to the tofu binary/runner-image version** and verify at apply (fixes R2-F6).
7. **Add a portable-state-ratio CI metric** with an ADR-gated ceiling on non-OpenTofu edge config (fixes R2-F7).
8. **Derive action level from the `affects_desired_state` connector attribute**, not a static name→level map (fixes R2-F8).
9. **Switch harness CAS to `cursor.rowcount`** (fixes R2-F9).
10. **Gate the review-agent/dual-approval layers behind a feature flag** so the slice's critical path is the minimal FSM (addresses §7).

## 10. Measurable acceptance criteria

- **AC-1 (F1):** A `TestActionConnectorUniformContract` suite is green for ≥2 mutators (tofu + restart) sharing one conformance harness; adding a mutator requires zero changes to verify/lease/creds/audit code paths (only a new connector registration). `TestDriftReconcilerIgnoresRuntimeOnlyActions` green.
- **AC-2 (F2):** Audit chain verifies with the public key alone; a writer without the private key cannot produce a verifying chain; `UPDATE`/`DELETE` on `operation_events` denied at DB role level.
- **AC-3 (F3):** Lease cannot be reclaimed before `expires_at`; a heartbeating holder is never preempted; reconciler fires from expiry, not a direct call — all three tested.
- **AC-4 (F4):** Post-approval Git tree change rejects execute with `commit_drift`; op remains APPROVAL_PENDING; proven against a real local Git repo.
- **AC-5 (F5):** Lease, policy, and gateway authz all key on the composite scope; a staging-scoped op cannot acquire a production lease (design-level test).
- **AC-6 (F6):** A tofu version skew between plan and apply forces a re-plan, not a stale-binary apply.
- **AC-7 (F7):** CI reports the non-OpenTofu edge-config ratio and fails above the ADR-set ceiling.
- **AC-8 (F8):** A provider action flagged desired-state-affecting cannot be classified L2.
- **AC-9 (F9):** Harness CAS uses per-statement rowcount; concurrency tests remain green under `rowcount`.
- **AC-10 (retained baseline):** The existing 13 demonstrations + 16 failure cases stay green after every change above.

## 11. Go / No-go

**GO to implement the proof slice as scoped (single staging restart + single deploy/rollback), CONDITIONAL on the following before any second mutating connector or any L2 action beyond restart:**

- **Must-fix before build starts (design-time, cheap now / rewrite later):** R2-F1 (connector abstraction), R2-F5 (composite scope columns/keys). These are the two decisions that, if deferred, force a future rewrite; both are inexpensive to fix on paper today.
- **Must-fix within the G0 spine, before exposing the MCP surface to a live model:** R2-F2 (audit signing), R2-F3 (lease expiry/HA), R2-F4 (Git commit-binding).
- **Should-fix on the milestones named:** R2-F6…F9 and the §8 gaps.

The design is fundamentally the right shape and the proof is honest and behaviorally faithful. The evolution goals (multi-env, multi-region, redundant workers, managed Postgres, redundant object storage, HA, k8s, multi-cloud) are reachable by migration, **provided the connector abstraction (R2-F1) and composite scope (R2-F5) are decided now** rather than retrofitted. Ship the slice; ratify §9 items 1 and 5 as blocking gate items before growth.
