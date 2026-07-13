# Infra-Ops Failure Exercises, Threat Model & Connector Test Harness

- **Status:** Proposed (design).
- **Depends on:** all infra-ops docs.
- **Rule:** every claim of safety is validated by a failure exercise or a threat control with a test. Untested safety is not safety.

---

## 1. Mandatory failure exercises

For each: **prevention · detection · approval behavior · execution behavior · audit · recovery · fallback-without-AI.**

### 1. Claude produces an invalid infrastructure plan
- **Prevention:** `plan_*` output is validated against IaC schema; `tofu plan` must succeed to produce a signed artifact; independent security-review + cost agents re-check.
- **Detection:** plan validation fails or reviewers BLOCK.
- **Approval:** never reaches approval — a plan that won't `tofu plan` cleanly cannot be signed/approved.
- **Execution:** none.
- **Audit:** invalid plan attempt + reviewer verdicts recorded.
- **Recovery:** Claude revises; human unaffected.
- **Fallback:** human authors the IaC change directly through the same PR flow.

### 2. Claude requests excessive permissions
- **Prevention:** no tool can widen its own scope; identity broker mints least-privilege per-op creds; there is no `mint_key`/`call_arbitrary_provider_api`.
- **Detection:** policy engine denies any out-of-scope tool/parameter.
- **Approval:** denied pre-approval; a scope-widening *plan* is L3 + (dual for security-policy) and reviewer-flagged.
- **Execution:** blocked.
- **Audit:** the denied request is recorded with the attempted scope (a signal of injection/model error).
- **Recovery:** none needed; Claude proceeds within scope.
- **Fallback:** human grants scope explicitly via IaC/policy, reviewed.

### 3. A connector is compromised
- **Prevention:** short-lived creds (≤15 min), least-privilege identity, per-env scope, no long-lived keys; connector runs isolated.
- **Detection:** anomaly on the connector's audit stream (out-of-pattern calls); drift reconciler flags unexpected changes.
- **Approval:** unaffected — compromise can't forge an approval (no signing key in the connector).
- **Execution:** blast radius bounded to that connector's least-privilege scope for ≤15 min.
- **Audit:** all connector actions are signed/attributed; the compromise window is bounded and visible.
- **Recovery:** revoke the connector identity (L3), rotate, reconcile drift, restore from IaC.
- **Fallback:** human revokes at the provider console; IaC re-asserts desired state.

### 4. A provider API returns partial success
- **Prevention:** executor applies a saved plan resource-by-resource, recording each outcome.
- **Detection:** apply result ≠ full plan → op → PARTIAL.
- **Approval:** n/a (already approved).
- **Execution:** executor stops, does not proceed past the failed resource.
- **Audit:** exactly which resources applied is recorded.
- **Recovery:** reconciler compares actual vs desired; drives to SUCCEEDED (re-apply remaining) or ROLLED_BACK.
- **Fallback:** human inspects op state + provider; re-runs the idempotent apply.

### 5. The conversation disconnects during deployment
- **Prevention:** op state is durable; the apply runs in the executor, not the chat.
- **Detection:** session loss is irrelevant to the op.
- **Approval:** already recorded.
- **Execution:** continues in the executor under its lease.
- **Audit:** unaffected.
- **Recovery:** Claude reconnects → `get_deployment_status(op_id)` resumes narration; nothing lost.
- **Fallback:** human polls the same op via CLI.

### 6. The executor crashes after applying half the change
- **Prevention:** leases + heartbeats; per-resource outcome recording.
- **Detection:** lease expiry with op in APPLYING → reconciler triggered.
- **Approval:** n/a.
- **Execution:** halted at crash point.
- **Audit:** last recorded resource outcome pinpoints progress.
- **Recovery:** reconciler reads provider truth + saved plan, resumes remaining (idempotent) or rolls back → PARTIAL resolved.
- **Fallback:** human runs the reconciler / re-applies the idempotent saved plan.

### 7. Two Claude sessions operate concurrently
- **Prevention:** per-environment **apply lease** — one applier at a time; idempotency keys.
- **Detection:** second apply attempt sees the held lease.
- **Approval:** each op has its own approval.
- **Execution:** the second op queues or is rejected with the holding op_id; both can plan/observe in parallel.
- **Audit:** both sessions' calls attributed to distinct agent IDs.
- **Recovery:** none needed.
- **Fallback:** human serializes via the same lease.

### 8. A malicious log contains prompt-injection instructions
- **Prevention:** tool outputs framed as untrusted; fixed operator policy; no `run_arbitrary_*` tool; read connectors redact.
- **Detection:** independent review agent + human on any resulting plan; injected instruction can't reach a mutating tool directly.
- **Approval:** any injected "action" still needs a typed plan + human approval.
- **Execution:** worst case Claude *proposes* a plan a human rejects; no autonomous high-impact execution.
- **Audit:** the anomalous plan/request is recorded.
- **Recovery:** discard the plan; no infra change.
- **Fallback:** human ignores; deterministic pipeline unaffected.

### 9. DB migration succeeds but app deployment fails
- **Prevention:** migrations are forward-compatible / expand-contract by policy; deploy is health-gated.
- **Detection:** validate_deployment fails post-migration.
- **Approval:** migration was L3 (dual in prod).
- **Execution:** app rollback to prior version (compatible with the migrated schema by the expand-contract rule).
- **Audit:** migration + failed deploy + rollback recorded.
- **Recovery:** roll back app; schema stays (safe by expand-contract); or human-approved down-migration if truly needed.
- **Fallback:** human runs the versioned down-migration + prior app plan.

### 10. DNS changes but certificate issuance fails
- **Prevention:** plan DNS + cert as one op with an ordered health-gate (cert issuance is a validation step).
- **Detection:** validate step: cert not issued within timeout.
- **Approval:** DNS is L3.
- **Execution:** op → FAILED at validation; DNS revert-plan applied (records restored).
- **Audit:** DNS change + issuance failure + revert recorded.
- **Recovery:** roll back DNS; retry with corrected config; ACME retry loop is deterministic.
- **Fallback:** human reverts DNS via IaC; issuer retries.

### 11. A secret rotates but one worker retains the old credential
- **Prevention:** rotation uses **overlap** (new + old valid during a window) — mirrors Culvert's own dual-CA/overlap pattern.
- **Detection:** post-rotation validation checks all consumers on the new version; metrics show a lagging worker.
- **Approval:** rotation is L3.
- **Execution:** overlap keeps the lagging worker functional; restart_stateless_worker (L2) refreshes it before the old cred is revoked.
- **Audit:** rotation + per-consumer adoption recorded.
- **Recovery:** don't revoke old until all consumers confirm new; if one lags, restart it (L2).
- **Fallback:** human restarts the worker; overlap prevents outage.

### 12. Free-tier quota is exhausted
- **Prevention:** continuous inspect_quota_posture; alerts at soft thresholds.
- **Detection:** L0 quota check crosses hard limit.
- **Approval:** none for the protective action.
- **Execution:** disable_new_bundle_uploads (L2, reversible) to shed load; propose paid upgrade (L3) or capacity plan (L1).
- **Audit:** quota event + protective action recorded.
- **Recovery:** human approves paid tier (L3) or waits for reset; re-enable uploads (L2).
- **Fallback:** deterministic quota-enforcement disables ingest without Claude.

### 13. The provider suspends a free resource
- **Prevention:** IaC desired state + backups; multi-provider portability (OpenTofu).
- **Detection:** inventory/health shows the resource gone; drift reconciler flags it.
- **Approval:** re-provision plan is L3.
- **Execution:** re-apply IaC to the same or an alternate provider.
- **Audit:** suspension + re-provision recorded.
- **Recovery:** restore data from backup into the re-provisioned resource (restore may be dual-approval).
- **Fallback:** human re-applies IaC to an alternate provider.

### 14. Infrastructure drifts from Git
- **Prevention:** GitOps reconciler runs scheduled `tofu plan`.
- **Detection:** detect_infrastructure_drift surfaces the delta.
- **Approval:** low-impact drift → L2 auto-reconcile; high-impact drift → L1 plan → L3 approve.
- **Execution:** re-assert desired state via a plan.
- **Audit:** drift + reconciliation recorded; the out-of-band change is investigated (possible compromise).
- **Recovery:** Git remains the source of truth; actual is reconciled to it.
- **Fallback:** human runs `tofu plan/apply` to reconcile.

### 15. Claude attempts an action outside its approved environment
- **Prevention:** every call carries operator+environment scope; policy engine enforces.
- **Detection:** scope mismatch at the gateway.
- **Approval:** denied pre-approval.
- **Execution:** blocked.
- **Audit:** cross-env attempt recorded (injection/model-error signal).
- **Recovery:** none needed.
- **Fallback:** human operates the correct env explicitly.

### 16. Rollback is unavailable
- **Prevention:** plans declare reversibility; irreversible plans are flagged and dual-approved with explicit acknowledgment.
- **Detection:** op.reversible == false pre-apply; human sees it at approval.
- **Approval:** irreversible actions require explicit human acceptance of no-rollback (dual for data/destroy).
- **Execution:** proceeds only with that acknowledgment.
- **Audit:** the "no rollback available, accepted by <human>" is recorded.
- **Recovery:** forward-fix plan (L1) + backup/restore if data.
- **Fallback:** human executes the forward-fix/restore runbook.

### 17. Backup restoration damages newer case data
- **Prevention:** restore is **dual-approval** over live/newer data; restore-drills run into an **isolated target** first (L2 non-prod); point-in-time + newer-data-preservation checks.
- **Detection:** pre-restore diff shows newer data that would be lost.
- **Approval:** dual (prod); the diff is shown to both approvers.
- **Execution:** restore into an isolated/side target, then a controlled merge — never a blind overwrite of live newer data.
- **Audit:** restore plan, data-loss diff, both approvals recorded.
- **Recovery:** if merge conflicts, halt and escalate; newer data preserved by default.
- **Fallback:** human runs the restore-drill runbook into an isolated target and merges manually.

### 18. The AI provider is unavailable during an incident
- **Prevention:** every L2 action + incident runbook is executable by a human via the same gateway CLI; deterministic incident state machine + paging run without Claude.
- **Detection:** the incident automation and alerting detect and page regardless of AI availability.
- **Approval:** humans approve L3 directly.
- **Execution:** deterministic automation + human operators continue.
- **Audit:** unaffected (audit is deterministic).
- **Recovery:** Claude resumes narration when available via op IDs.
- **Fallback:** **this is the fallback** — the platform is fully operable without any AI. Claude is an accelerator, never a dependency.

---

## 2. Threat model (infra-ops specific; complements `SUPPORTABILITY-THREAT-MODEL.md`)

| Threat | Control | Test |
|---|---|---|
| Model drives raw provider API | no such tool; typed catalog only | gateway fitness test (no `call_arbitrary_*`) |
| Model obtains secrets | tools return refs, broker resolves inside executor only | `TestNoSecretCrossesToolBoundary` |
| Model approves its own plan | approver ≠ author; policy-enforced | `TestNoSelfApproval` |
| Prompt injection → mutation | untrusted framing + typed plans + human gate + independent review | `TestInjectionCannotMutate` |
| Compromised connector | short-lived least-privilege creds; bounded scope; revocable | `TestConnectorCredShortLived`, `TestConnectorScopeBounded` |
| Cross-environment / cross-tenant action | scope enforced per call | `TestScopeEnforcement` |
| Replay of an approval | approvals bound to plan_id + nonce; single-use | `TestApprovalSingleUse` |
| Unbounded/runaway automation | rate limits, per-env apply lease, L2 bounded counts | `TestRateLimitAndLease` |
| Audit tampering | hash-chained signed log, separate store | `TestAuditTamperEvident` |
| Long-lived admin key leakage | none exist; workload identity only | `TestNoLongLivedKeys` |
| Executor applies unsigned/unapproved plan | signature + approval verified before apply | `TestApplyRequiresSignedApproved` |

---

## 3. Connector test harness

Every connector ships with a conformance suite before it is registered:

| Test | Asserts |
|---|---|
| `TestConnector_SchemaTyped` | no free-form command/SQL/path/URL/secret parameter |
| `TestConnector_LeastPrivilege` | identity can perform *only* the declared allowed actions (denied set is actually denied at the provider) |
| `TestConnector_ShortLivedCreds` | creds minted per-op, ≤ declared TTL, auto-revoked |
| `TestConnector_NoSecretReturn` | no secret value crosses the tool boundary (refs only) |
| `TestConnector_Idempotent` | repeat call with same idempotency_key is a no-op |
| `TestConnector_Scope` | out-of-env/out-of-tenant calls rejected |
| `TestConnector_Timeout` | bounded; times out to a clean typed error, no partial ambiguity |
| `TestConnector_Audit` | every call produces a signed audit entry with refs (no secrets) |
| `TestConnector_Rollback` | declared rollback method actually reverses the action (or declares irreversible) |
| `TestConnector_InjectionInert` | hostile text in inputs/outputs cannot escalate the connector |
| `TestConnector_ApprovalGate` | L3 connectors refuse without a valid approval_id; dual-class refuse with one |

A connector cannot be registered in the gateway until its suite passes and its per-connector security spec (`MCP-GATEWAY.md §5`) is filled in — the same "no component without coverage" wall as the appliance framework.
