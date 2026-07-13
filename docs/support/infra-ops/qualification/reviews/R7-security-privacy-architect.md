# R7 — Independent Qualification Review: Security & Privacy Architect (adversarial)

- **Reviewer role:** Security & Privacy Architect, independent/adversarial. Public-benchmark posture only (STRIDE, least-privilege, separation-of-duties, non-repudiation, zero-trust, data-minimization).
- **Scope reviewed:** REDACTION-MODEL, SUPPORTABILITY-THREAT-MODEL, TAC-CLOUD-ARCHITECTURE, SECURE-UPLOAD-ARCHITECTURE, MCP-GATEWAY, APPROVAL-STATE-AUDIT, proof-slice (POLICY-IDENTITY, ARTIFACTS-AND-AUDIT, schema.sql), ADR-0007/0009/0010/0011/0014/0016/0018/0020, and the `tac_proof.py` harness (executed: `failtest`, 16/16 cases ran; states as designed).
- **Evidence method:** doc trace + schema/harness code read + one execution. I attempted a concrete break against every named attack surface. Findings below distinguish **DESIGN risk** (would survive faithful implementation) from **SIM-HIDDEN risk** (the harness makes a control look proven when it is not).

---

## 1. Verdict

The **design corpus is genuinely strong** and, on paper, is safe enough to *begin building* a system to store enterprise-customer diagnostic evidence. The outbound-only invariant (ADR-0014), source-side fail-closed redaction (ADR-0009), raw/normalized plane separation (ADR-0016), AI-normalized-input boundary (ADR-0018), and the typed-tool gateway with no arbitrary shell/SQL/provider/secret (ADR-0020) are the right primitives and are internally consistent.

**However, the proof slice must NOT be read as evidence that those guarantees hold.** The harness collapses every cryptographic role onto one symmetric HMAC key, has **zero tenant isolation** in schema or policy, records approvals as plain DB writes with **no approver signature**, weakens policy rule P16 to a presence check, and never evaluates operator scope/authorization at all. A reviewer skimming "signed, hash-chained, plan-bound, policy-gated" would over-trust it. Several gaps are also genuine design gaps (P4 accepts any allowlisted digest incl. known-vulnerable; L2 autonomous availability blast radius; single broker root secret; audit chain lacks a global anchor).

**Conditional go:** proceed to implementation; do not store real enterprise evidence until the Blocking findings are corrected and re-proven with asymmetric keys, tenant scoping, and signed approvals.

## 2. Maturity — 3 / 5

Design maturity alone is ~4/5 (thoughtful, threat-driven, fail-closed defaults, test names attached to invariants). Proof/evidence maturity is ~2/5 (the sim proves the *state machine and workflow ergonomics* convincingly but proves **none** of the security-critical cryptographic or multi-tenant properties it appears to). Weighted for a system whose purpose is holding enterprise secrets: **3/5** — promising architecture, not yet demonstrably safe.

## 3. Unusually strong

- **Outbound-only as structure, not policy (ADR-0014).** "Cloud can never dial in" is enforced by the absence of an inbound listener/route + a route-count wall, not by a firewall rule. This is the single best decision in the corpus: a fully compromised cloud cannot reach the customer network.
- **Structural secret unreachability (ADR-0007).** `NEVER_EXPORT` is a compile-time property (`internal/secret`, opaque handle, no `[]byte` accessor), not a runtime filter. This is the correct way to guarantee "the KEK/CA keys cannot be bundled."
- **Fail-closed redaction default (ADR-0009).** Unclassified field ⇒ `SENSITIVE` (masked), plus a reflection parity wall that fails CI when a collected struct gains an unclassified field. Regex is explicitly the *last* layer, not the guarantee. Correct ordering.
- **Content-addressed, plan-bound approval (ARTIFACTS-AND-AUDIT §1-2).** `plan_id = "PLAN-"+sha256(canonical_body)[:12]` and approval bound to the exact plan signature means a regenerated plan invalidates prior approval. The harness proves this (failtest #5: `approval/plan mismatch`). This is a real, verifiable anti-rubber-stamp control.
- **Typed-tool catalog with a rejected-tools fitness test (ADR-0020, MCP-GATEWAY §2).** No `run_arbitrary_shell/sql/provider`, no free-form command/path/secret parameter, refs-not-values for identities. The gateway attack surface is enumerable.

## 4. Blocking findings

### R7-F1 — Single symmetric HMAC key collapses separation of duties and destroys non-repudiation (proof) / must be mandated asymmetric (design)
- **Severity:** Critical (as qualification evidence); High (design, if the sim's shortcut is carried forward)
- **Affected component:** `tac_proof.py` (`SIGN_KEY`, `sign()`); plan signing, approval binding, and audit `operation_events.signature` all use it.
- **Realistic attack scenario:** The proof presents plan signatures, the audit hash-chain signature, and the approval binding as three independent cryptographic controls. In the harness they are one HMAC-SHA256 key held by every actor. Any component that can *verify* (executor, audit reader, reconciler) can also *forge*. An attacker who compromises the audit-writer service (which must hold the key to sign) can rewrite any op's history and re-sign the whole chain; an attacker who compromises the executor can mint a "human:bob approved" plan signature. There is no cryptographic distinction between "the planner signed this" and "the audit writer signed this."
- **Business impact:** No court-defensible / compliance-defensible audit trail; separation-of-duties (a core SOC2/ISO control and the entire premise of the multi-agent gate) is unprovable. Enterprise customers requiring tamper-evident evidence chains cannot be onboarded.
- **Technical impact:** Non-repudiation requires asymmetric signatures with per-role private keys the verifier does not hold. Symmetric HMAC gives integrity-with-shared-secret only. The design (schema.sql "Ed25519", POLICY-IDENTITY §2 per-role KMS identities) is correct; the proof provides zero evidence for it and would mislead a decision-maker into believing the separation is demonstrated.
- **Evidence:** `tac_proof.py:29` one `SIGN_KEY`; `:38 sign()`; used at `:95` (audit signature), `:191/238` (plan sig / approval binding), `:361` (verify == re-sign with same key). schema.sql `plans.signature ... Ed25519`, `operation_events.signature ... audit-writer Ed25519` — the design intends distinct KMS keys the sim does not model.
- **Required correction:** (1) State explicitly in POLICY-IDENTITY that the proof's symmetric key is a stand-in and proves *workflow*, not *crypto separation*. (2) Before storing real evidence, implement distinct Ed25519 signing identities: `plan-signer`, per-approver session key, `audit-writer` — each KMS-held, verifier holds only public keys. (3) Add a conformance test that fails if any two roles share a signing key.
- **Acceptance test:** `TestSigningKeySeparation` — planner, approver, and audit-writer public keys are distinct; an audit-writer key cannot verify a plan signature and vice-versa; forging an approval with the audit key is rejected by the executor.
- **Recommended milestone:** Pre-implementation gate (M0) — block "store real bundles" until green.

### R7-F2 — No tenant isolation exists in the proof slice; cross-tenant enforcement is prose-only
- **Severity:** Critical
- **Affected component:** schema.sql (`worker_registry`, `operations`, `plans`, `approvals`, `leases`, `operation_events` — no `tenant_id`); `evaluate_policy()` (no tenant predicate); MCP-GATEWAY §4 ("scope enforced: env+tenant") vs the slice.
- **Realistic attack scenario:** The gateway permission matrix and TAC-CLOUD claim end-to-end "case + tenant scoping" and cite `TestUploadTenantScoped`/`TestFindingsTenantScoped`. I searched the *proof* for any tenant boundary and found none: every table is single-worker, single-env, tenant-free; the policy engine evaluates only plan properties (P1–P16). An operator or injected model scoped to tenant A has nothing in the proven control loop stopping an operation, plan, approval, or audit read that touches tenant B's resource — the enforcement is entirely in un-exercised cloud contract tests.
- **Business impact:** The platform's core multi-customer promise ("one customer never sees another's data/infra") is unproven at exactly the layer that mutates infrastructure and stores evidence. A single missed scope check leaks or damages across tenants — the worst-case in the threat model's asset table (B5/B6).
- **Technical impact:** Tenant must be a first-class column on every op/plan/approval/audit/lease row and a mandatory policy predicate evaluated against the *caller's session scope*, not the plan body (which the caller controls).
- **Evidence:** schema.sql — zero `tenant_id`/`customer_id` columns. `tac_proof.py:143 evaluate_policy` — no tenant/operator argument. POLICY-IDENTITY §1 rules P1–P17 — no tenant rule. MCP-GATEWAY §4 asserts tenant scope but the proof-slice policy cannot enforce it.
- **Required correction:** Add `tenant_id` to `operations/plans/approvals/leases/operation_events/worker_registry`; add policy rule `Pt: op.tenant == session.tenant AND worker.tenant == session.tenant`; make the gateway derive tenant from the authenticated session, never from tool input.
- **Acceptance test:** `TestPolicyRejectsCrossTenant` — a session scoped to tenant A proposing/approving/executing/reading any tenant-B op is `POLICY_REJECTED` and audited; parity test that every evidence-bearing table carries and indexes `tenant_id`.
- **Recommended milestone:** M0 (before multi-tenant onboarding).

### R7-F3 — Approval authenticity is a database write, not a signed human act; self-approval prevention is caller-asserted
- **Severity:** High→Critical (Critical once this authorizes production mutation)
- **Affected component:** `approve()`/`verify_approval()` (`tac_proof.py:232-251`); schema.sql `approvals` (no `approver_signature` column); ARTIFACTS-AND-AUDIT §2 (which *does* specify `approver_signature`).
- **Realistic attack scenario — attempted break (approval binding surface):** I traced whether a party with DB write access but no human approver credential can forge an approval. `verify_approval` checks only: approval exists, `plan_id` matches, `bound_plan_signature == plans.signature` (a value freely readable from `plans`), not expired, not consumed. There is **no** verification of an approver-held signature. So inserting `INSERT INTO approvals (…, bound_plan_signature=<copied plans.signature>, approver='human:bob', approver_is_author=0, decision='APPROVED')` fully satisfies the executor. Separately, `approver_is_author` is a **parameter the caller sets** (`approve(..., is_author=False)`) — the code never records the plan's author identity and never compares it to the approver, so "approver ≠ author" is honor-system. The ARTIFACTS-AND-AUDIT `approver_signature` (Ed25519 by the approver's session over `{op_id,plan_id,plan_signature,decision}`) — the one field that makes approval un-forgeable by a DB writer — is **absent from schema.sql and the harness**.
- **Business impact:** The human-approval gate — the top control for all L3 production changes (DNS, IAM, DB migration, data deletion, raw-evidence enablement) — reduces to "who can write a row." Four-eyes/dual-control becomes unenforceable; a compromised service account approves its own high-blast plans.
- **Technical impact:** Approval must carry the approver's own asymmetric signature, verified against the approver-identity public key, and `approver_is_author` must be *derived* by comparing the recorded plan-author identity to the approver identity, not supplied.
- **Evidence:** `tac_proof.py:243-251` verify_approval (no signature check); `:232-241` approve (writes row, no approver signature, `is_author` is a param); schema.sql approvals columns (no `approver_signature`); contrast ARTIFACTS-AND-AUDIT §2 JSON which lists `approver_signature`.
- **Required correction:** Add `approver_signature` to schema + artifact; executor verifies it against the approver public key before mutation; record `plan.created_by`; compute `approver_is_author := (approver == plan.created_by)` server-side and reject if true (dual: reject if `second_approver ∈ {author, first_approver}`).
- **Acceptance test:** `TestApprovalRequiresApproverSignature` (row without a valid approver signature is rejected at execute); `TestSelfApprovalDerived` (approver == plan author is rejected even when a caller sets `approver_is_author=false`).
- **Recommended milestone:** M0.

## 5. High-priority

### R7-F4 — Audit chain is per-operation only, symmetric-signed, with no global anchor → whole-op deletion and tail-truncation are undetectable
- **Severity:** High
- **Affected component:** `emit()`/`verify_audit_chain()` (`tac_proof.py:86-95, 355-363`); `operation_events` (chain keyed per `op_id`).
- **Realistic attack scenario — attempted break (audit integrity surface):** `emit` selects the previous hash `WHERE op_id=?`, so each op is an *independent* chain with no cross-op linkage and no published head. I can (a) delete every `operation_events` row for an entire operation and the remaining operations still `verify_audit_chain()==True` — a whole mutation vanishes with no tamper signal; (b) truncate the newest N events of an op (roll back to an earlier consistent head) undetectably, because nothing pins the expected latest `seq`/`hash`; (c) with the shared key (F1), re-sign any rewritten chain. schema.sql's "no UPDATE/DELETE grant" is a Postgres-grant assertion not modeled or tested here.
- **Business impact:** "Tamper-evident, exportable-for-compliance" audit (APPROVAL-STATE-AUDIT §5) is defeated by deletion/truncation, not just mutation. Incident forensics and regulator evidence cannot be trusted.
- **Technical impact:** Need a monotonic global sequence or a periodically externally-notarized head (e.g., signed checkpoint to an append-only/WORM store or a transparency log), plus DB-enforced append-only (revoked UPDATE/DELETE) and asymmetric audit-writer signatures (F1).
- **Evidence:** `tac_proof.py:87` `SELECT ... WHERE op_id=? ORDER BY seq DESC LIMIT 1`; `:355-363` per-op re-verify with the shared key; no head anchoring anywhere.
- **Required correction:** Add a global hash-chain (or per-tenant) with a published/notarized checkpoint; enforce append-only at the DB grant level; sign with the asymmetric audit-writer key; verifier detects missing-op and truncated-tail via the anchored head.
- **Acceptance test:** `TestAuditTruncationDetected` (deleting an op's events OR dropping the latest event fails verification against the anchored head).
- **Recommended milestone:** M1.

### R7-F5 — Policy rule P16 weakened to a presence check; operator scope/authorization never evaluated
- **Severity:** High
- **Affected component:** `evaluate_policy()` (`tac_proof.py:167`); MCP-GATEWAY §4 / POLICY-IDENTITY §1 (P16 "≤ now()+15m", "policy evaluates (operator, tool, env, tenant, resource, level)").
- **Realistic attack scenario — attempted break (approval-binding/expiry surface):** The design's P16 requires `expires_at` present **and ≤ now()+15m**. The harness implements `rule("P16", bool(plan["expires_at"]))` — presence only. A plan minted with `expires_at = now()+10y` passes P16, giving an effectively unbounded approval/execution window (approval inherits plan expiry) — the exact "stale approval" defense the design touts (failtest #4) is silently bypassable by a long expiry the policy no longer bounds. Separately, `evaluate_policy` takes only the plan; it never receives or checks the caller's operator identity or scope, so MCP-GATEWAY's headline example ("a staging operator invoking a prod apply is rejected") is **not demonstrated by the proof** — there is no operator scope in the loop at all.
- **Business impact:** Long-lived approvals defeat the time-bound-authorization control; missing operator-scope enforcement means privilege boundaries between operators are unproven where they matter most (who may act on what).
- **Technical impact:** P16 must assert the upper bound; the policy engine must take `(operator_scope, tenant, level)` and reject out-of-scope callers regardless of plan validity.
- **Evidence:** `tac_proof.py:167` P16 presence-only; `:143` `evaluate_policy(c, plan)` — no operator arg; POLICY-IDENTITY §1 P16 text vs harness.
- **Required correction:** `rule("P16", present AND expires_at <= now()+15m)`; add operator-scope predicate P17' evaluated against session scope.
- **Acceptance test:** `TestP16UpperBound` (expires_at > now()+15m ⇒ POLICY_REJECTED); `TestOperatorScopeEnforced` (staging-scoped operator on a prod/other-worker op ⇒ rejected, audited).
- **Recommended milestone:** M1.

### R7-F6 — P4 accepts any allowlisted digest, including an old/known-vulnerable one → valid, human-approved rollback-to-vulnerable
- **Severity:** High
- **Affected component:** `evaluate_policy` P4 (`tac_proof.py:152-155`); `approved_digests` table; MCP-GATEWAY prompt-injection claim ("worst case = a proposal a human reviews").
- **Realistic attack scenario — attempted break (prompt-injection + approval surface):** Injection can't invoke arbitrary tools (true, strong). But it *can* propose a fully policy-valid plan: `kind=deploy`, `environment=staging`, one worker, `target_image_digest ∈ approved_digests`, cost 0, rollback present. Nothing requires the target to be *newer than current* or *not-yanked/not-vulnerable*. `approved_digests` retains `APPROVED_DIGEST_GOOD` (the prior version) permanently. An injected planner proposes "deploy the old known-good digest" (which may be the one patched *because* it was vulnerable); the human approval screen shows "policy PASS, security OK, cost $0, rollback verified" and a reviewer rubber-stamps a downgrade to a vulnerable image. The multi-agent security review is a stub (`{"verdict":"OK"}`) and never checks vulnerability/recency.
- **Business impact:** A downgrade-to-vulnerable is achievable through the *approved* path — the injection containment narrative ("only a proposal a human rejects") assumes the human can tell a bad-but-valid plan from a good one; the surface gives them no signal.
- **Technical impact:** Digest allowlist must be *revocable and recency-aware*: a yanked/vulnerable digest must be removable from `approved_digests`, and P4 (or a new P) should require `target != known-vulnerable` and optionally `target is current-or-forward` unless the op is an explicit rollback class.
- **Evidence:** `tac_proof.py:152-155` P4 = membership only; `:192` `reviews={"security":{"verdict":"OK"}}` (stub, always OK); `approved_digests` never pruned.
- **Required correction:** Add digest revocation + a "not-yanked/not-vulnerable-at-approval-time" gate; make the security-review agent actually check the target digest against a vulnerability feed and BLOCK on downgrade-to-vulnerable.
- **Acceptance test:** `TestPolicyRejectsYankedDigest` (a revoked digest fails P4 even if historically approved); `TestDowngradeToVulnerableBlocked`.
- **Recommended milestone:** M1.

### R7-F7 — L2 autonomous actions give an injected/compromised model an availability blast radius with no human gate
- **Severity:** High
- **Affected component:** MCP-GATEWAY §2 L2 tools (`pause_failing_consumer`, `disable_new_bundle_uploads`, `restart_stateless_worker`, `enter_incident_mode`); APPROVAL-STATE-AUDIT §1 L2 rule ("reversible ⇒ autonomous").
- **Realistic attack scenario — attempted break (executor-identity + prompt-injection surface):** The L2 boundary rule is "reversible by construction ⇒ no human approval." But *reversible* ≠ *low blast radius*. An injected model (or a stolen ≤1h gateway session token, MCP-GATEWAY §4 medium injection exposure on L0 logs) can autonomously call `disable_new_bundle_uploads` + `pause_failing_consumer` + repeatedly `restart_stateless_worker` to halt ingest and flap the analysis workers — a full availability denial of the TAC platform — with **no approval**, only after-the-fact audit. "Reversible" doesn't help while the outage is live. There is no rate-limit, anomaly threshold, or mandatory human *notification* on L2 in the proof; the harness doesn't exercise L2 abuse at all (its only L2 is a benign restart).
- **Business impact:** Prompt-injection containment is sold as "worst case = a rejected proposal," but L2 has no human gate — the true worst case is an attacker-driven platform outage that is merely *auditable*, and SLA/incident-response damage.
- **Technical impact:** L2 needs a second dimension beyond reversibility: bounded rate, blast-radius cap (e.g., cannot pause > N consumers or disable ingest without an incident already declared), and mandatory synchronous human notification/paging on ingest-affecting L2.
- **Evidence:** MCP-GATEWAY §2 L2 table (autonomous, no approval); APPROVAL-STATE-AUDIT §1 L2 rule; `tac_proof.py` failtest has no L2-abuse case (#13 injection is a no-op string).
- **Required correction:** Add L2 rate-limits + a "cannot self-cause outage" guard (ingest-disable/consumer-pause require an active incident or a human ack); page-on-L2 for availability-affecting tools.
- **Acceptance test:** `TestL2RateLimited` and `TestL2IngestDisableRequiresAckOrIncident` (autonomous ingest-disable without an active incident is refused/queued for human ack).
- **Recommended milestone:** M1.

## 6. Medium-priority

### R7-F8 — Lease acquisition is SELECT-then-write (TOCTOU); concurrency is proven only single-process
- **Severity:** Medium
- **Affected component:** `acquire_lease()` (`tac_proof.py:220-227`).
- **Realistic attack scenario — attempted break (executor-identity surface):** `acquire_lease` does `SELECT` then `INSERT OR REPLACE` — two statements. Two executors racing both read "no live lease," both `INSERT OR REPLACE`, last writer wins the row but *both* return `True` and proceed to mutate the same worker. failtest #12 "passes" only because it is single-process sequential; it does not model concurrent processes. The operations-table CAS (`version`) guards op state, not the lease row.
- **Business impact:** Two concurrent applies to one worker → interleaved image writes / partial state the reconciler must untangle; the "one applier per environment" guarantee (APPROVAL-STATE-AUDIT §4) is unproven under real concurrency.
- **Technical impact:** Use an atomic conditional upsert (`INSERT ... ON CONFLICT DO UPDATE ... WHERE expires_at < now()`) or `SELECT ... FOR UPDATE`; return success only if this op holds the row post-write.
- **Evidence:** `tac_proof.py:220-227` (non-atomic acquire); failtest #12 single-process.
- **Required correction + Acceptance test:** `TestLeaseAtomicUnderConcurrency` — N parallel processes contend; exactly one acquires; others get BLOCKED.
- **Recommended milestone:** M2.

### R7-F9 — Identity-broker "$0 fallback" holds a single long-lived root secret with no pinned rotation/HSM requirement
- **Severity:** Medium
- **Affected component:** POLICY-IDENTITY §3 ("broker-held root secret in a KMS the broker alone can read").
- **Realistic attack scenario — attempted break (encryption-trust / executor-identity surface):** The design correctly keeps creds out of Claude, but concedes one standing high-value secret in the broker when the provider lacks true workload identity. Compromise of the broker = ability to mint executor creds for the one staging worker (pilot) — and, at scale, for whatever the broker fronts. No rotation cadence, HSM/KMS-hardware requirement, or split-knowledge is pinned; it's described as "audited, rotatable."
- **Business impact:** A single point whose compromise yields provider mutation authority; acceptable for a $0 staging pilot, not for production tenant/root KMS.
- **Technical impact:** Require true OIDC workload identity in production (no standing secret); if a broker root is unavoidable, pin HSM-backed storage, mandatory ≤N-day rotation, and dual-control on rotation (it is already an L3 op).
- **Evidence:** POLICY-IDENTITY §3 "$0 reality" paragraph.
- **Required correction + Acceptance test:** `TestNoStandingExecutorCredInProd` (production path uses federated workload identity; broker-root path is refused outside pilot).
- **Recommended milestone:** M2 (before production).

### R7-F10 — `idempotency_key` is client-supplied and not content-bound → request confusion / pre-registration DoS
- **Severity:** Medium
- **Affected component:** `create_op()` (`tac_proof.py:206-218`); `operations.idempotency_key UNIQUE`.
- **Realistic attack scenario:** The key dedups on uniqueness only; it is not bound to `(kind,intent,worker,plan)`. A second, *different* request reusing a key silently returns the first op (failtest #3 returns the existing op regardless of intent). An attacker who can submit ops can pre-register keys an honest client will later use, causing the honest request to no-op onto an attacker-shaped op; or reuse a restart key for a deploy and get the wrong op back.
- **Business impact:** Silent request substitution / denial of a legitimate operation.
- **Technical impact:** Bind the idempotency key to a hash of the canonical request; on key match with differing content, reject with a typed conflict rather than returning the prior op.
- **Evidence:** `tac_proof.py:212-214` (returns existing on any IntegrityError, no content compare).
- **Required correction + Acceptance test:** `TestIdempotencyKeyContentBound` (same key + different request ⇒ 409 conflict, not silent reuse).
- **Recommended milestone:** M2.

### R7-F11 — Raw-evidence deletion has no crypto-shred / deletion-proof requirement; break-glass dual-control unexercised
- **Severity:** Medium
- **Affected component:** ADR-0016 (30-day raw retention, "hard-deleted"); TAC-CLOUD §3; threat model `TestBreakGlassDualControlAudited` (named, not in this slice).
- **Realistic attack scenario:** "Hard-deleted after 30 days" is asserted without a mechanism that proves deletion (backups, replicas, snapshots commonly outlive a logical delete). For per-case-key encrypted raw, crypto-shredding the per-case key is the provable primitive; it is not required. Break-glass raw access (the one standing exposure of the highest-sensitivity plane) is dual-control in prose but has no proof artifact in the reviewed slice.
- **Business impact:** Regulatory "right to erasure"/retention commitments are unprovable; a customer cannot be shown their raw evidence is gone.
- **Technical impact:** Mandate crypto-shred (destroy per-case key) as the deletion primitive with a signed deletion record; exercise break-glass dual-control with an audit artifact.
- **Evidence:** ADR-0016 "hard-deleted"; no deletion-proof or key-shred requirement.
- **Required correction + Acceptance test:** `TestRawDeletionCryptoShredProof` (deletion destroys the per-case key and emits a signed deletion event; post-deletion decrypt is impossible even with the ciphertext).
- **Recommended milestone:** M2.

## 7. Over-engineered

- **17 policy rules + 9 validation gates + 4 review agents for a one-worker staging restart/deploy.** Several rules are constant-true in the proof and carry no signal at this scope: P3 collapses to `w is not None` (already covered by P2), P7 (DNS) / P13 (cost) / P6 (storage) are structurally impossible for an image-tag update, and the security/cost review agents always return `OK` (`tac_proof.py:192`). For the pilot's blast radius (one reversible worker) this is ceremony; it is defensible only as a *template* for higher-blast operations. Recommendation: keep the rule set but mark which rules are load-bearing at each op class, and make the review agents real (F6) or drop them from the proof rather than stubbing an always-OK verdict that reads as evidence of review.
- **Per-op audit hash-chain with signature but no anchor** is the inverse problem: heavy machinery (canonical JSON + hash + HMAC per event) that doesn't deliver tamper-evidence against deletion (F4). The cryptographic effort is spent where it's weakest.

## 8. Under-engineered

- **Tenant isolation (F2)** — entirely absent from the proven loop; the platform's multi-customer premise.
- **Operator authorization/scope (F5)** — the policy engine never sees the caller; the headline "out-of-scope operator rejected" example is not demonstrated.
- **Cryptographic separation of duties (F1, F3)** — one symmetric key; no approver signature; the multi-agent/four-eyes design has no cryptographic teeth in the proof.
- **Audit anchoring (F4)** — no global chain, no notarized head, no DB-level append-only enforcement.
- **L2 availability blast-radius controls (F7)** — reversibility is treated as sufficient; rate-limit/anomaly/notify are missing.
- **Digest revocation (F6)** — approved digests are permanent; no path to yank a vulnerable image from the allowlist.

## 9. Exact proposed changes

1. **schema.sql:** add `tenant_id text NOT NULL` to `worker_registry, operations, plans, approvals, leases, operation_events` (+ composite indexes); add `approver_signature text NOT NULL`, `second_approver_signature text`, and `created_by text` (plan author) to the relevant tables; add a `digest_revocations(worker_id, image_digest, reason, revoked_at)` table.
2. **POLICY-IDENTITY §1:** fix P16 to `present AND expires_at <= now()+15m`; add `Pt` (tenant match vs session) and `Po` (operator scope vs session); add `Pr` (target digest not in `digest_revocations`); state that reviews are advisory but the security-review MUST BLOCK on downgrade-to-vulnerable.
3. **POLICY-IDENTITY §2-3:** mandate distinct Ed25519/KMS keys for `plan-signer`, per-approver session, and `audit-writer`; require federated workload identity in production and forbid the broker-root standing secret outside the pilot.
4. **ARTIFACTS-AND-AUDIT §2-3 + schema:** make `approver_signature` a stored, verified column; executor rejects any approval lacking a valid approver signature; derive `approver_is_author` server-side; add a global/tenant audit chain with a periodically notarized head and DB-enforced append-only.
5. **MCP-GATEWAY §2 / APPROVAL-STATE-AUDIT §1:** add L2 rate-limits + a blast-radius guard (ingest-disable/consumer-pause require active incident or human ack) + mandatory paging on availability-affecting L2.
6. **ADR-0016:** require crypto-shred (per-case key destruction) as the raw-deletion primitive with a signed deletion record; add a break-glass dual-control proof artifact.
7. **tac_proof.py (evidence honesty):** add a banner and code comments stating the HMAC single-key is a stand-in that proves workflow, not crypto separation or tenant isolation; add failure cases for cross-tenant, self-approval-by-derived-identity, L2 abuse, concurrent lease race, P16 over-bound, and yanked-digest deploy so the matrix stops implying properties it doesn't test.

## 10. Measurable acceptance criteria

- `TestSigningKeySeparation`, `TestApprovalRequiresApproverSignature`, `TestSelfApprovalDerived` green; no two roles share a signing key (grep/keystore assertion).
- `TestPolicyRejectsCrossTenant` green; reflection parity test proves every evidence-bearing table has and indexes `tenant_id` (mirrors `config_surfaces_test.go`).
- `TestP16UpperBound`, `TestOperatorScopeEnforced` green; policy engine signature takes `(session_scope, tenant, plan)`.
- `TestPolicyRejectsYankedDigest`, `TestDowngradeToVulnerableBlocked` green; security-review agent returns a real verdict driven by a vuln feed.
- `TestAuditTruncationDetected` green against an anchored head; DB grants show no UPDATE/DELETE on `operation_events`.
- `TestL2RateLimited`, `TestL2IngestDisableRequiresAckOrIncident` green.
- `TestLeaseAtomicUnderConcurrency` green with N parallel OS processes (not a single process).
- `TestIdempotencyKeyContentBound`, `TestRawDeletionCryptoShredProof`, `TestNoStandingExecutorCredInProd` green.
- Policy branch coverage remains 100% (`rules_test.go`) *including* the new rules; failure-injection matrix grows to cover the six new adversarial cases in §9(7).

## 11. Go / No-Go

**CONDITIONAL GO for design; NO-GO for storing real enterprise evidence until Blocking findings clear.**

- The **design** is approved to proceed to implementation. Outbound-only, structural secret containment, fail-closed redaction, raw/normalized separation, AI-normalized-input, and the typed-tool gateway are sound and, faithfully built, are safe enough to hold enterprise diagnostic evidence.
- The **proof slice must not be cited as evidence** of cryptographic separation of duties, non-repudiation, tenant isolation, or operator scope — it demonstrates none of these, and its symmetric-HMAC/single-tenant/DB-write-approval shortcuts would be dangerous if carried into production.
- **Gate to production / first real customer bundle:** R7-F1, R7-F2, R7-F3 corrected and re-proven with asymmetric per-role keys, tenant scoping in schema + policy, and signed approvals; R7-F4–F7 corrected by M1. Until then: pilot with synthetic/non-customer data only.
