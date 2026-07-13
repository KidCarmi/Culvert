# R9 — Independent Qualification Review: AI Operations Architect

- **Reviewer role:** AI Operations Architect (independent). Public benchmarks only.
- **Date:** 2026-07-13
- **Artifacts reviewed:** `INFRA-OPS-ARCHITECTURE.md`, `MCP-GATEWAY.md`, `APPROVAL-STATE-AUDIT.md`, `proof-slice/*` (README, STATE-MACHINE, POLICY-IDENTITY, ARTIFACTS-AND-AUDIT, OPENTOFU-ALGORITHMS, TOOL-AND-API-CONTRACTS, TESTING-AND-ACCEPTANCE, schema.sql), ADR-0019/0020/0021/0022, `qualification/staging-proof/README.md` + `tac_proof.py`.
- **Executed:** `demo` (13/13 pass), `failtest` (16/16 land in specified state), `cli-restart demo-idem`, `show OP-…`, plus adversarial probes (duplicate-idempotency re-execution, terminal-state transition, event-count inspection).

---

## 1. Verdict

**CONDITIONALLY VALID — the central thesis holds; the proof overstates two safety guarantees.**

The design is architecturally correct and unusually disciplined: Claude is the *conversational interface and reasoning layer*, while authority (Git+IaC), execution (deterministic signed-plan executor), state (durable op DB outside the conversation), and safety (typed-tool boundary + policy engine + human approval) are model-independent. I confirmed **the same infrastructure is fully operable through CLI/deterministic automation** — `tacctl`/`cli-restart` drives the complete L2 restart lifecycle to `SUCCEEDED` with no AI in the loop (demo step 13, failtest case 16, and a standalone `cli-restart` run I executed). No tool in the catalog lets a model error or prompt injection cause an unsafe mutation: there is no `run_arbitrary_*`, every mutating path is a typed plan, L3 requires a human approver who is structurally never the plan author, and L2 is a fixed reversible allowlist.

**Is the AI a single point of failure? No.** Remove Claude and the platform still operates through the identical gateway/CLI; the op-state DB, policy engine, and executor carry all authority. This is the correct answer to the qualification question.

However, the *reference implementation* (`tac_proof.py`) does **not** faithfully enforce two guarantees the design claims, and my adversarial probe broke one of them live (R9-F1, R9-F2). These are proof-fidelity/implementation-pattern defects, not thesis defects — but they must not be carried into the real executor, where they would become genuine safety bugs.

**Status is honestly "Proposed (design); no implementation."** The gateway, policy engine, executor, identity broker, and reconciler are unbuilt; the proof is a single-process, single-environment, synthetic, `$0` simulation (SQLite for Postgres, `MockProvider` for the provider, HMAC for Ed25519/KMS). The honesty statement is explicit and commendable.

---

## 2. Maturity (1–5)

**2 / 5 — "Design validated by simulation."**

- Design rigor: 5/5 (would be exemplary if built).
- Behavioral proof breadth: 3/5 (13 demos + 16 failures exercised, but single-env/single-tenant/single-approver; several claimed controls unexercised).
- Proof fidelity: 2/5 (exactly-once and legal-transition enforcement are claimed but absent from the harness; injection and scope tests are prose assertions).
- Implementation: 0/5 (nothing is built; every ADR says "no code moved").

A 2 reflects: the concept is sound and the happy path plus most failure paths are demonstrated, but no production spine exists and three of the highest-consequence safety controls (exactly-once at the execute boundary, cross-scope/tenant isolation, dual approval) are unproven or contradicted.

---

## 3. Unusually strong

- **The four structural invariants are correct and load-bearing** (source of truth = Git/IaC, deterministic executor, state outside the conversation, structural gates). The architecture inverts the dangerous pattern (model drives APIs from chat memory) into a safe one.
- **Session-loss safety is real and demonstrated.** `show OP-…` reconstructs full lifecycle + hash-chained audit from the DB in a *separate process* with zero chat memory (demo step 12; I re-ran `show` independently — `audit_chain_valid=True`).
- **AI-independence is demonstrated, not asserted.** The entire spine is driven by CLI functions; I ran `cli-restart` cold and got a complete `SUCCEEDED` op with a 7-event signed chain.
- **Prompt-injection is structurally defused** by construction: the tool catalog *is* the attack surface, and it contains no arbitrary-execution primitive. The rejected-tools fitness test (ADR-0020) is the right control.
- **Plan-bound, single-use, author-excluded approval** is genuinely enforced: self-approval is rejected (demo step 8), stale approval rejected (failtest 4), and post-approval plan mutation rejected via signature binding (failtest 5, `approval/plan mismatch`).
- **Radical honesty about scope** (synthetic, `$0`, no cloud, no creds) — rare and enterprise-credible.

---

## 4. Blocking findings

**None blocking for the design-stage deliverable as scoped** (a proposed design + reviewable synthetic proof). There is no production or mutating system to block. R9-F1 and R9-F2 are rated HIGH rather than blocking *only* because the harness is a simulation and the design *prose* is correct; **they become blocking the moment any real executor is built**, and MUST be closed before Milestone G1 (first mutating connector).

---

## 5. High-priority

### R9-F1 — Harness enforces no legal-transition / state precondition; a terminal op was re-executed
- **Finding ID:** R9-F1
- **Severity:** High
- **Affected component:** `tac_proof.py` `set_state()` / `execute()` (reference implementation of the operation-svc FSM); STATE-MACHINE.md §3.4.
- **Realistic scenario:** An operator (or an automation retry) re-issues the same `tacctl` restart after a dropped response. I ran `cli-restart demo-idem` three times against the same op.
- **Business impact:** A "safe" action re-fires a real provider mutation on an already-completed operation; in a real system this is an unaudited-as-duplicate re-deploy/re-restart storm and breaks the exactly-once contract customers are being asked to trust.
- **Technical impact:** `set_state()` performs only a `version` CAS; it does **not** check that the transition is legal. The op went `SUCCEEDED → PLANNING → … → SUCCEEDED` three times, producing **19 events** on one op (I verified `SELECT COUNT(*) … =19` and the repeated `to_state` sequence). `execute()` never checks the op is in `EXECUTION_QUEUED`/`APPROVED` before touching the provider, directly contradicting STATE-MACHINE §3.4 ("the executor … checks the op is EXECUTION_QUEUED via CAS before touching the provider; a second executor … no-ops").
- **Evidence:** `python3 tac_proof.py cli-restart demo-idem` ×3 → same `OP-2026-ad1d6b`, state `SUCCEEDED`, but event count grew 7→13→19; states seen include three `SUCCEEDED` entries.
- **Required correction:** The FSM writer must reject illegal transitions (a `legal_transitions` guard keyed on `from_state`), and `execute()` must precondition on `state == EXECUTION_QUEUED` (or `APPROVED`) under the same CAS. Terminal states must be immutable.
- **Acceptance test:** A test that calls `execute()`/`cli-restart` twice on one op asserts the second is a no-op, event count is unchanged, and no second provider mutation occurs; a test asserting any `terminal → *` transition raises.
- **Recommended milestone:** G1 (before first mutating connector).

### R9-F2 — tacctl/deterministic path ignores the idempotency dedup flag; L2 exactly-once relies solely on create-dedup
- **Finding ID:** R9-F2
- **Severity:** High
- **Affected component:** `tac_proof.py` `cmd_cli_restart()`; `create_op()` dup contract; the L2 autonomous class generally.
- **Realistic scenario:** The AI-unavailable fallback (the path this qualification specifically asks me to confirm safe) is retried with the same `idempotency_key`.
- **Business impact:** The deterministic automation the design offers as the human/AI-outage safety net is itself not idempotent for the autonomous action class — undermining the "kill AI, nothing breaks" guarantee at exactly the moment it is invoked.
- **Technical impact:** `create_op()` correctly returns `(existing_id, dup=True)`, but `cmd_cli_restart()` (and the L2 flow) discards the `dup` flag and blindly re-drives `PLANNING → … → validate`. Exactly-once for L2 depends *entirely* on the create-time `UNIQUE(idempotency_key)`, with no guard at the execute boundary. L3 is incidentally protected (single-use approval consumption rejects re-execute), so this gap is specific to the unapproved L2 class — the class that runs autonomously.
- **Evidence:** Same probe as R9-F1; `dup=True` is returned yet the mutation re-runs. failtest case 3 only compares op IDs (`same_op`) and never asserts non-re-execution, so the matrix does not catch this.
- **Required correction:** On `dup=True`, callers must return the existing terminal result without re-driving the pipeline; add the missing assertion to the idempotency test.
- **Acceptance test:** failtest case 3 extended to assert the second call adds zero `operation_events` and performs zero provider calls.
- **Recommended milestone:** G1.

---

## 6. Medium-priority

### R9-F3 — Cross-scope / excessive-permission enforcement is claimed but unexercised
- **Finding ID:** R9-F3
- **Severity:** Medium
- **Affected component:** Policy engine scope check (`MCP-GATEWAY.md §4`, `POLICY-IDENTITY.md`); failtest matrix.
- **Realistic scenario:** A staging-scoped operator (or an injected model) requests a prod apply, or a tool call outside the operator's tenant/level.
- **Business impact:** The multi-tenant/least-privilege isolation that customers rely on for blast-radius containment has no behavioral evidence.
- **Technical impact:** The proof is single-environment (policy `P1` hardcodes `environment=="staging"`), single-tenant, single-worker. `MCP-GATEWAY §4` references "failure exercise #15" for an out-of-scope rejection, but harness case 15 is "provider unavailable" — the scope-violation case does not exist in the 16-matrix. `(operator, tool, env, tenant, resource, level)` evaluation is asserted in prose only.
- **Evidence:** `evaluate_policy()` has no operator/tenant/level parameters; `failtest` has no scope-rejection case.
- **Required correction:** Add a two-environment/two-tenant fixture and a failtest case where an out-of-scope call is rejected + audited (never partially executed).
- **Acceptance test:** A staging-scoped caller invoking a prod-scoped op yields a typed rejection, op state never leaves the rejected/`POLICY_REJECTED` set, and an audit event records the denial.
- **Recommended milestone:** G1.

### R9-F4 — Dual-approval mechanism (ADR-0021's core prod control) is unimplemented in the harness
- **Finding ID:** R9-F4
- **Severity:** Medium
- **Affected component:** `approve()` / approval-svc; ADR-0021; APPROVAL-STATE-AUDIT §2.
- **Realistic scenario:** Any prod destruction/data-deletion/DB-migration/KMS-rotation — the exact classes ADR-0021 mandates two distinct humans for.
- **Business impact:** The highest-consequence safety control (four-eyes on irreversible actions) has zero behavioral evidence; a reviewer cannot confirm the single-approver-cannot-clear-destruction property.
- **Technical impact:** `approve()` accepts one approver and transitions straight to `APPROVED`; there is no "two distinct approvers" path, no "second approver ≠ first" check, no dual-class routing. README/ARTIFACTS honestly scope dual out of this slice ("none required for this slice, but the mechanism exists") — but the mechanism does **not** exist in code.
- **Evidence:** `approve()` signature and the demo/failtest use single `bob`; no dual test anywhere.
- **Required correction:** Implement the dual path (distinct-approver enforcement + class→dual routing) and add a failtest case proving a second, distinct human is required and that the same human cannot satisfy both slots.
- **Acceptance test:** A dual-class op with one approval stays `APPROVAL_PENDING`; the same approver twice is rejected; two distinct approvers reach `APPROVED`.
- **Recommended milestone:** G2 (before any dual-class connector).

### R9-F5 — Prompt-injection case is a prose assertion, not a behavioral test
- **Finding ID:** R9-F5
- **Severity:** Medium
- **Affected component:** failtest case 13; `MCP-GATEWAY.md §6`.
- **Realistic scenario:** Attacker-influenced text in logs/drift/provider messages flows into the model via an L0 read tool and attempts to induce a mutation.
- **Business impact:** Injection resistance — a headline claim — is argued from architecture but never demonstrated end-to-end, so a reviewer cannot see the untrusted text actually fail to move the system.
- **Technical impact:** Case 13 constructs a malicious string and immediately `return "inert", "…"` — no read connector, no tool output labeling, no policy path is exercised with the payload. The architectural argument (no arbitrary tool; L3 human gate) is correct, but the test proves nothing behaviorally.
- **Evidence:** `f13()` body: the payload is never passed to any tool or model surface.
- **Required correction:** Route the payload through a real `get_logs`-style read connector and assert (a) it is returned labeled untrusted, and (b) the only reachable mutation still requires a typed plan + human approval, with the injected instruction producing no state change.
- **Acceptance test:** Injected log text yields at most a `PROPOSED`/`POLICY_REJECTED` op and an audit entry; no `EXECUTING` transition occurs without a human approval record.
- **Recommended milestone:** G1.

### R9-F6 — Reconciler reads the same in-process object the executor mutated ("provider truth" is not independent)
- **Finding ID:** R9-F6
- **Severity:** Medium
- **Affected component:** `reconcile_after_crash()` vs `MockProvider`; STATE-MACHINE §4.
- **Realistic scenario:** Executor crash mid-apply; reconciler must resolve PARTIAL from *independent* provider truth (failtest 7/8/9).
- **Business impact:** The crash-recovery guarantee (never leave infra silently half-applied) is demonstrated against a provider that cannot disagree with the recorded state — the failure mode that matters (op-record vs provider divergence) is structurally impossible in the proof.
- **Technical impact:** `MockProvider.digest` is set by `apply()` and read back by the reconciler in the same process; there is no separate provider/OpenTofu-state oracle, so "read provider truth" is circular. This is acknowledged indirectly (the README defers state-backend locking under contention), but the reconciliation evidence is weaker than it appears.
- **Evidence:** Case 8 resumes to `VALIDATING` because `prov.running_digest()==target` — the same field the mock's `apply()` set before "crashing."
- **Required correction:** Model an independent provider-state oracle that can diverge from the op record; add a case where recorded state and provider truth disagree and the reconciler resolves from provider truth.
- **Acceptance test:** A divergence fixture (op says applied, provider says not) resolves to the provider-truth outcome, not the recorded one.
- **Recommended milestone:** G2.

### R9-F7 — "Signed audit" is HMAC with an in-source key; proves chaining, not authenticity
- **Finding ID:** R9-F7
- **Severity:** Medium
- **Affected component:** `sign()` / `SIGN_KEY` literal; audit model.
- **Realistic scenario:** A reviewer or auditor relies on "signed, tamper-evident" audit for non-repudiation.
- **Business impact:** The audit evidence demonstrates hash-chain ordering integrity only; with the HMAC key present in the source, any holder of the file can forge or re-sign the chain, so the proof cannot establish authenticity/non-repudiation.
- **Technical impact:** `SIGN_KEY = b"local-demo-signing-key-STANDIN…"`; `verify_audit_chain()` re-derives signatures with the same in-process key. Honestly labeled a stand-in for Ed25519/KMS, but the phrase "signed audit trail" overstates what is proven.
- **Evidence:** `SIGN_KEY` literal in `tac_proof.py`; `sign()` is HMAC-SHA256.
- **Required correction:** Either qualify the claim to "hash-chained (integrity-only) in the proof; authenticity deferred to Ed25519/KMS," or wire an asymmetric signer with the private key outside the verifier.
- **Acceptance test:** Verifier accepts with only the public key and rejects a chain re-signed with a different key.
- **Recommended milestone:** G2.

---

## 7. Over-engineered

- **R9-F8 (Low):** The proof carries an 18-state FSM, six distinct agent roles (planner/security-review/cost/executor-liaison/validation/incident), dual-agent advisory review, and a hash-chained signed audit for a **single stateless worker, single environment, `$0`** pilot. The spine justification is legitimate, but the *pilot slice* only exercises ~11 of the 18 states and one agent role. **Correction:** ship the pilot with the reduced state set actually exercised and grow the FSM/agent roster by ADR amendment as connectors are added, so the implemented surface matches the tested surface. **Milestone:** G1 scoping.

---

## 8. Under-engineered

- The three items that most need strengthening are already captured as findings: exactly-once at the execute boundary (R9-F1/F2), cross-scope/tenant isolation (R9-F3), and dual approval (R9-F4) — the latter two are the two safety controls a real multi-tenant vendor cloud most depends on and currently have **no** behavioral proof.
- **Model-replacement** is asserted (model-agnostic MCP + human CLI) and is architecturally sound, but there is no test that a *different* MCP client drives the same tools — recommend a minimal "second client" conformance check at G2 to substantiate the anti-lock-in claim.
- **Provider-outage** (failtest 14/15) resolves to a clean `FAILED` with "retry same saved plan," which is correct; no gap.

---

## 9. Exact proposed changes

1. Add a `legal_transitions` map and enforce it in `set_state()`; make terminal states immutable; precondition `execute()` on `state ∈ {APPROVED, EXECUTION_QUEUED}` under the version CAS. *(R9-F1)*
2. Honor `create_op()`'s `dup` flag in `cmd_cli_restart()` and every L2 caller: on dup, return the existing terminal result without re-driving the pipeline. *(R9-F2)*
3. Add operator/tenant/level parameters to `evaluate_policy()`, a two-env/two-tenant fixture, and a failtest scope-rejection case. *(R9-F3)*
4. Implement dual approval (distinct-approver enforcement + class→dual routing) and a dual failtest case. *(R9-F4)*
5. Route the injection payload through a real read connector; assert untrusted-labeling and no mutation without human approval. *(R9-F5)*
6. Introduce an independent provider-state oracle that can diverge from the op record; add a divergence reconciliation case. *(R9-F6)*
7. Requalify the audit claim to "integrity-only in the proof" or wire an asymmetric signer with the key outside the verifier. *(R9-F7)*
8. Trim the pilot FSM/agent roster to the exercised surface; grow by ADR. *(R9-F8)*

---

## 10. Measurable acceptance criteria

- **A1 (R9-F1/F2):** Re-running any op through `execute`/`cli-restart` produces **0 additional `operation_events`** and **0 additional provider calls**; every op has exactly one contiguous CREATED→terminal event chain (no repeated terminal state). Measured by event-count assertion in the idempotency test.
- **A2 (R9-F1):** 100% of illegal transitions (any `terminal → *`, any skip) are rejected; a fuzz over all state pairs shows only whitelisted edges succeed.
- **A3 (R9-F3):** A failtest scope case shows an out-of-scope call rejected with a typed error, op never reaching an `EXECUTING` state, and exactly one audit denial event.
- **A4 (R9-F4):** Dual-class op requires two distinct approvers: one approval → still `APPROVAL_PENDING`; same approver twice → rejected; two distinct → `APPROVED`.
- **A5 (R9-F5):** Injected log text yields ≤ a `PROPOSED`/`POLICY_REJECTED` op and 0 `EXECUTING` transitions without a human approval record.
- **A6 (R9-F6):** Divergence fixture resolves to provider truth in 100% of injected op-vs-provider mismatches.
- **A7 (R9-F7):** Audit verifier accepts with public key only and rejects a foreign-key re-sign.
- **A8 (AI-independence, already met — keep as regression):** Full L2 and L3 lifecycles complete with no AI actor in any `operation_events.actor_kind` (`human`/`service` only) via `tacctl`.

---

## 11. Go / No-Go

- **GO** — to proceed from design into building the deterministic spine (operation-svc FSM, policy engine, executor, identity broker, reconciler). The architecture is sound, the AI-independence and session-loss guarantees are real and demonstrated, and **the AI is not a single point of failure** — the platform is fully operable through CLI/deterministic automation, which I verified live.
- **NO-GO** — for any production, credential-holding, or mutating deployment until **R9-F1, R9-F2, R9-F3, R9-F5** are closed (G1) and **R9-F4, R9-F6, R9-F7** are closed (G2). The exactly-once/legal-transition and scope/dual-approval controls must be *enforced and tested*, not just documented, before real infrastructure is touched.
- **Overall:** the claim "Claude can operate the platform from chat without becoming a critical safety dependency" is **substantiated as a design and largely as behavior**, with the caveat that the reference harness under-enforces two guarantees it advertises — fix those and the qualification is met.
