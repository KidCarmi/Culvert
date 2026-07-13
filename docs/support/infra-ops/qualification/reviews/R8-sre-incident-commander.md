# R8 — SRE & Incident Commander Qualification Review

- **Reviewer role:** Independent SRE / Incident Commander. Public benchmarks only.
- **Scope reviewed:** `proof-slice/{STATE-MACHINE,TESTING-AND-ACCEPTANCE,OPENTOFU-ALGORITHMS}.md`, `FAILURE-AND-THREAT.md`, `qualification/staging-proof/README.md` + harness (`tac_proof.py`) executed by me.
- **Evidence I generated:** `python3 tac_proof.py failtest` (16-case matrix), inspected `evidence/failure_matrix.md` and `evidence/operations.json`, plus a targeted isolation repro of case 8 (crash-after-apply) to test model fidelity.
- **Date:** 2026-07-13.

---

## 1. Verdict

The *design* is genuinely strong: a single mutation spine, deterministic policy gate, plan-bound single-use approval, provider-200-is-not-success validation, explicit reverse-deploy rollback, and hash-chained signed audit are all real and behaviorally demonstrated. But as an **incident-safety proof it is materially incomplete and, at its core, low-fidelity.** The harness models executor "crashes" as *graceful caught exceptions that cleanly release the lease* — the exact opposite of a crash — so the load-bearing "never silently half-applied" guarantee (lease-expiry → reconciler → resolve) is asserted by construction, never exercised. Five of the failure classes an Incident Commander cares about most are **not modeled at all**: paging/notification outage, database restart, object-storage failure, unknown/ambiguous execution outcome, and quota exhaustion. The single most dangerous gap: a `MANUAL_INTERVENTION_REQUIRED` op "pages the human," but there is **no notification component, no delivery proof, and no detection if the page never arrives** — a frozen op is invisible to on-call.

## 2. Maturity: **3 / 5**

Design maturity ~4; proof/evidence maturity ~2.5. The demonstrations that exist pass and are auditable, but the failure suite's fidelity on the crash/reconciler spine is weak and the operationally scariest failures are absent. Not yet trustworthy as incident-safety evidence.

## 3. Unusually strong

- **Audit is real, not prose.** Hash-chained, signed, per-transition, one event per state change, reconstructable in a fresh process (`verify_audit_chain`, cross-process `show`). Cited: `operations.json` (12-event deploy chain, chain valid).
- **Plan-bound approval genuinely enforced.** Case 4 (`stale approval → APPROVAL_PENDING`, "approval expired") and case 5 (`pidA != pidB` signature mismatch → rejected) are actual rejections, not narration.
- **Idempotency and lease serialization are exercised, not claimed.** Case 3 (`same_op`, dup returns existing) and case 12 (`second_blocked` on worker lease).
- **Policy rejection is deterministic and specific.** Case 6 → `POLICY_REJECTED` naming rule `P4`.
- **AI-independence is proven.** Case 16 runs the full L2 loop via `tacctl` subprocess → `SUCCEEDED`. This is the correct and credible core claim.

## 4. Blocking findings

### R8-F1 — Notification/paging of `MANUAL_INTERVENTION_REQUIRED` is unmodeled and its failure is undetected
- **Severity:** Blocking
- **Affected component:** Alerting / on-call notification path; `rollback()` / manual-intervention transition.
- **Realistic scenario:** A deploy fails, rollback also fails (case 11 → `MANUAL_INTERVENTION_REQUIRED`), and the paging channel (email/PagerDuty/webhook) is down or misconfigured. The op freezes correctly, but no human is ever notified.
- **Business impact:** A staging worker (and, at production scale, a customer-facing analysis worker) is left broken with the incident invisible until someone happens to run `tacctl op show`. MTTD unbounded.
- **Technical impact:** The design (`OPENTOFU-ALGORITHMS §4`, `STATE-MACHINE §1`) says manual-intervention "pages the human," but there is no notification component in the topology, no delivery confirmation, no retry, and no fallback channel. `FAILURE-AND-THREAT.md` has no "notification outage" exercise at all.
- **Evidence:** My `failtest` run: case 11 → `MANUAL_INTERVENTION_REQUIRED` with recovery text "human via tacctl" — a **pull-only** recovery. No push. No email-outage case in the 16.
- **Required correction:** Add a notification abstraction with a delivery-failure fault switch; on delivery failure escalate to a second channel and record a signed `notification.failed` event; expose an unacknowledged-`MANUAL`/`FAILED` counter. Add a failtest case "paging outage → op still discoverable via a durable alert queue + audit, and delivery failure is itself audited."
- **Acceptance test:** `TestManualInterventionPaged`: inject notification outage; assert (a) op reaches `MANUAL_INTERVENTION_REQUIRED`, (b) a `notification.failed` signed event exists, (c) a fallback channel is attempted, (d) an "unacknowledged incident" metric is non-zero.
- **Recommended milestone:** Stage-2 (before any live-model exposure).

### R8-F2 — Executor "crash" is modeled as a graceful exception; lease-expiry → reconciler trigger is never exercised
- **Severity:** Blocking
- **Affected component:** `execute()` exception handling, `reconcile_after_crash()`, lease lifecycle, sweeper/reconciler loop (absent).
- **Realistic scenario:** The executor process is OOM-killed mid-apply. In reality the `except` block never runs: the lease stays held until TTL, the op is stuck in `EXECUTING`, and a *running* reconciler/sweeper must detect the expired lease and pick it up.
- **Business impact:** The platform's headline safety property ("never leaves infra silently half-applied") is unproven for the actual crash mode. If the real reconciler loop or lease-expiry scan has a bug, ops stick in `EXECUTING` forever with the worker lease permanently held — no further op can ever run on that worker.
- **Technical impact:** In the harness a "crash" is a caught `RuntimeError` that runs `release_lease()` + writes `FAILED` cleanly. The reconciler is then invoked **manually by the test** — not triggered by lease expiry, with no time advancement, no `busy_timeout`, no periodic job. The trigger mechanism (the hard part) is entirely bypassed.
- **Evidence:** My isolation repro of case 8: after the injected "crash," `lease rows after 'crash': []` (lease already cleanly released) and `state after execute: FAILED` — i.e. the process cleaned up perfectly, which a crashed process cannot do. `reconcile_after_crash` was then called directly.
- **Required correction:** Model crash as *process death with no cleanup*: leave the lease row present + state `EXECUTING`, advance a mock clock past lease TTL, and run a real reconciler/sweeper poll that discovers the stuck op by scanning expired leases. Prove detection, not just resolution.
- **Acceptance test:** `TestReconcilerDetectsStuckExecuting`: kill mid-apply (no cleanup), advance clock > TTL, run sweeper; assert the op is discovered *without being named*, provider truth read, and resolved.
- **Recommended milestone:** Stage-2.

### R8-F3 — Unknown / ambiguous execution outcome is unmodeled; the reconciler assumes provider truth is always cleanly readable
- **Severity:** Blocking
- **Affected component:** `MockProvider` (missing `slow`/timeout/ambiguous fault), `reconcile_after_crash()`.
- **Realistic scenario:** `tofu apply` hangs past timeout, or the provider is unreachable *during reconciliation*, so whether the mutation landed is genuinely unknown. This is the classic distributed-systems "in-doubt transaction."
- **Business impact:** An IC facing an in-doubt apply with no deterministic resolution must guess; a wrong guess either double-applies or abandons a half-applied change.
- **Technical impact:** `TESTING-AND-ACCEPTANCE §1` and `OPENTOFU-ALGORITHMS` list a `slow(>timeout)` fault, but `MockProvider` never implements timeout/hang, and `reconcile_after_crash` decides purely on `running_digest()==target` — a boolean that always resolves. There is no `UNKNOWN`/in-doubt branch and no path that itself escalates to `MANUAL_INTERVENTION_REQUIRED` when provider truth cannot be read.
- **Evidence:** `MockProvider.apply` (tac_proof.py:115–128) has no timeout/hang handling; no failtest case injects one. `reconcile_after_crash` (335–344) has only applied/not-applied.
- **Required correction:** Implement a `slow`/`provider_unreadable` fault; add a reconciler branch: provider truth unreadable within bound → `MANUAL_INTERVENTION_REQUIRED` (lease released, signed `reconcile.indeterminate`, paged), never a guess.
- **Acceptance test:** `TestReconcilerIndeterminateEscalates`: provider unreachable during reconcile → op → `MANUAL_INTERVENTION_REQUIRED` with `reconcile.indeterminate` audited.
- **Recommended milestone:** Stage-2.

## 5. High-priority

### R8-F4 — Crash-after recovery lands in a dead-end `VALIDATING` with no lease and no follow-through
- **Severity:** High
- **Affected component:** case 8 recovery path; validator hand-off.
- **Realistic scenario:** After crash-after-apply the reconciler flips the op to `VALIDATING`, but nothing runs validation and the lease is gone.
- **Business impact:** Op is stuck non-terminal; an IC sees `VALIDATING` forever with no owner.
- **Technical impact:** `STATE-MACHINE §2` requires the lease **HOLD** through `VALIDATING` (for possible rollback). In the harness the "crash" already released the lease, then reconcile set `VALIDATING`, and no `validate()` is invoked. The op never reaches a terminal state.
- **Evidence:** Isolation repro: `final state: VALIDATING`, `lease rows after reconcile: []`, event chain ends at `FAILED→VALIDATING` with no subsequent event.
- **Required correction:** Reconciler that resumes to `VALIDATING` must re-acquire the lease and drive validation to a terminal state within the same recovery.
- **Acceptance test:** `TestCrashAfterReachesTerminal`: case 8 must end in `SUCCEEDED` or `ROLLED_BACK`/`MANUAL`, lease consistent with state throughout.
- **Recommended milestone:** Stage-2.

### R8-F5 — Database restart / connection loss unmodeled; durability + idempotency claims untested under DB failure
- **Severity:** High
- **Affected component:** SQLite/Postgres layer; `db()` (`busy_timeout=15000`), transactional CAS.
- **Realistic scenario:** Postgres fails over or restarts mid-transition; a transition commit is lost or retried.
- **Business impact:** The entire "op state is durable" promise rests on the DB; an untested restart path risks lost transitions or duplicate applies on retry.
- **Technical impact:** No fault injects DB unavailability, mid-transaction restart, or connection reset. `busy_timeout` is set but never exercised. The "one transaction per transition" invariant (`STATE-MACHINE §3`) is proven only on a healthy single-process SQLite file.
- **Evidence:** No DB fault switch in `MockProvider`/`failtest`; README §6 explicitly disclaims "state-backend locking under contention."
- **Required correction:** Add a DB-restart/connection-drop fault; assert idempotency-key UNIQUE + version-CAS prevent double transitions across a reconnect.
- **Acceptance test:** `TestTransitionSurvivesDBRestart`: drop connection mid-transition, reconnect, retry with same idempotency_key → exactly one applied outcome.
- **Recommended milestone:** Stage-3/4 (needs real Postgres).

### R8-F6 — Object-storage / state-backend failure unmodeled; rollback-restorable (V9) and image-pull (R3) depend on it
- **Severity:** High
- **Affected component:** OpenTofu remote state backend + lock table; digest registry ("mock object storage"); validator V9; rollback R3.
- **Realistic scenario:** The state backend or digest registry is unavailable at apply, at V9, or at rollback R3 (previous image pull check).
- **Business impact:** Rollback may be blocked precisely when most needed; state-lock loss under contention risks concurrent apply.
- **Technical impact:** V9 checks only that a digest string is non-null (`validate()`:302); R3 availability is a test parameter (`previous_available`), not a real storage fault. State-backend locking is explicitly out of scope (README §6).
- **Evidence:** `rollback(previous_available=...)` (314) is a boolean flag; no storage-outage fault. V9 gate is a null-check, not a reachability check.
- **Required correction:** Model registry/state-backend outage; V9 and R3 must perform a real pullability/reachability check and escalate to `MANUAL` on outage.
- **Acceptance test:** `TestRollbackBlockedByStorageOutage` and `TestStateLockContention`.
- **Recommended milestone:** Stage-4.

## 6. Medium-priority

### R8-F7 — Quota exhaustion unmodeled; V7 hardcoded pass
- **Severity:** Medium
- **Affected component:** validator V7; quota-posture check; protective action `disable_new_bundle_uploads`.
- **Realistic scenario:** Free-tier quota crosses the hard limit during/after a deploy.
- **Business impact:** Ingest/apply may fail unpredictably; the documented protective fallback is unproven.
- **Technical impact:** `validate()` sets `g("V7_quota_ok", True)` unconditionally; no quota fault; `FAILURE-AND-THREAT.md §12`'s deterministic quota-enforcement fallback has no test.
- **Evidence:** tac_proof.py:301 (`V7_quota_ok` literal True); no quota case in the 16.
- **Required correction:** Add a quota fault; V7 reads a real posture; assert the L2 protective action fires without AI.
- **Acceptance test:** `TestQuotaHardLimitTriggersProtectiveAction`.
- **Recommended milestone:** Stage-3.

### R8-F8 — Sweeper (`EXPIRED`) and `CANCELLED` transitions are unexercised; no time-advancement expiry test
- **Severity:** Medium
- **Affected component:** sweeper job; `EXPIRED`/`CANCELLED` transitions.
- **Realistic scenario:** An op sits past `expires_at`; a user cancels mid-flight.
- **Business impact:** Stale approvals/ops could be actioned if the sweeper is buggy.
- **Technical impact:** `STATE-MACHINE §2` defines both, but `failtest` never advances a clock to trigger `EXPIRED`, and no case cancels. Stale-approval case 4 hand-sets an expired timestamp rather than exercising the sweeper.
- **Evidence:** No `EXPIRED`/`CANCELLED` state appears in `failure_matrix.md`; `create_op` sets `expires_at` +30m but nothing sweeps it.
- **Required correction:** Add a mock-clock sweeper test for `EXPIRED` and a `CANCELLED` case (both pre- and at-provider-boundary).
- **Acceptance test:** `TestSweeperExpiresStaleOp`, `TestCancelAtProviderBoundaryIsCooperative`.
- **Recommended milestone:** Stage-2.

### R8-F9 — TAC visibility is pull-only; no push alerting, metrics, or on-call surface
- **Severity:** Medium
- **Affected component:** observability / TAC console.
- **Realistic scenario:** IC needs to know *now* that ops are stuck in `FAILED`/`MANUAL`.
- **Business impact:** Detection depends on someone running `tacctl op show`.
- **Technical impact:** Rich audit exists, but there is no metric/alert surface (counts of `FAILED`, `MANUAL`, unacked incidents, reconciler lag). The audit sophistication (hash chain, signatures) outpaces the absent alerting.
- **Evidence:** Only `tacctl op show` reconstructs state; no metrics export in `evidence/` beyond timings.
- **Required correction:** Emit counters (stuck-op, unacked-`MANUAL`, reconciler-lag) and a console alert list.
- **Acceptance test:** `TestStuckOpSurfacedAsMetric`.
- **Recommended milestone:** Stage-3.

### R8-F10 — No executable IC runbook; referenced `tacctl op reconcile` verb is not implemented
- **Severity:** Medium
- **Affected component:** runbook docs; `tacctl` CLI.
- **Realistic scenario:** IC hits `MANUAL_INTERVENTION_REQUIRED` and needs step-by-step recovery.
- **Business impact:** Recovery quality depends on tribal knowledge; longer MTTR.
- **Technical impact:** Recovery text says "human runbook" / "tacctl op reconcile," but no runbook document exists in the reviewed set and the harness `tacctl` only implements `show`/`cli-restart` (not `reconcile`).
- **Evidence:** `OPENTOFU-ALGORITHMS §4` references `tacctl op reconcile`; `tac_proof.py` `main()` implements only `init/demo/failtest/show/cli-restart`.
- **Required correction:** Write a per-terminal-failure IC runbook; implement/`stub` the referenced verbs so procedures are executable.
- **Acceptance test:** Doc-linked `TestRunbookVerbsExist`.
- **Recommended milestone:** Stage-2.

## 7. Over-engineered

- **Audit cryptographic machinery vs. operational coverage.** Hash-chaining + per-event HMAC signatures + chain verification are excellent, but this rigor is spent proving *tamper-evidence* while the operationally decisive paths (paging delivery, crash detection, in-doubt resolution) have zero coverage. Evidence polish currently exceeds incident coverage — rebalance effort toward R8-F1/F2/F3.
- **Case 13 (prompt injection) is a hardcoded `return "inert"`** — not a test, just an assertion. It adds a matrix row without exercising anything; either make it a real "injected instruction reaches no mutating tool" assertion or drop the pretense of it being a failure-injection case.

## 8. Under-engineered

- The **crash/reconciler/lease-expiry spine** — the heart of "never silently half-applied" — is the least faithfully modeled part (R8-F2, R8-F4). This is inverted risk: the most important guarantee has the weakest proof.
- **No time in the model.** Every timing/expiry/lease-TTL property is either hand-set or bypassed. A mock clock is a small addition that would unlock R8-F2, F4, F8 honestly.
- **No notification tier at all** (R8-F1) despite three docs promising "pages the human."
- **Failure taxonomy is narrower than the design's own docs.** `FAILURE-AND-THREAT.md` enumerates 18 exercises; the harness models a subset and omits quota, storage, DB, and notification failures entirely.

## 9. Exact proposed changes

1. Add a **mock clock** (`advance(seconds)`); make lease TTL, `expires_at`, approval expiry, and heartbeats read it. (Enables 3, 4, 8 below honestly.)
2. Change crash faults to **skip cleanup**: leave lease row + `EXECUTING`; add a **reconciler/sweeper poll** that scans expired leases and picks up stuck ops *without the test naming them*. (R8-F2)
3. Add faults `slow`/`provider_unreadable`; add reconciler `UNKNOWN` branch → `MANUAL_INTERVENTION_REQUIRED` + `reconcile.indeterminate`. (R8-F3)
4. Make crash-after recovery **re-acquire the lease and run `validate()` to a terminal state**. (R8-F4)
5. Add a **notification component** with a delivery-failure fault, fallback channel, `notification.failed` audit event, and an unacked-incident counter. (R8-F1, R8-F9)
6. Add faults for **DB restart** and **object-storage/registry outage**; make V9/R3 real reachability checks. (R8-F5, R8-F6)
7. Add a **quota fault**; V7 reads real posture; prove the L2 protective action fires without AI. (R8-F7)
8. Add **`EXPIRED` (sweeper via mock clock)** and **`CANCELLED`** cases. (R8-F8)
9. Write **IC runbooks** for each terminal-failure state; implement `tacctl op reconcile`. (R8-F10)
10. Grow the matrix from 16 to cover the five unmodeled classes; replace the case-13 tautology with a real assertion.

## 10. Measurable acceptance criteria

- **Detection:** 100% of stuck-`EXECUTING`, `FAILED`, and `MANUAL` ops are surfaced by a running sweeper/reconciler within one poll interval **without a test naming the op**; unacked-`MANUAL` count is a metric.
- **Notification:** Every `MANUAL_INTERVENTION_REQUIRED` produces a delivery attempt; a delivery failure produces a `notification.failed` signed event **and** a fallback attempt; 0 silent freezes under an injected paging outage.
- **Crash fidelity:** Crash cases leave the lease held + state `EXECUTING` until TTL; the reconciler resolves every one to a **terminal** state (or `VALIDATING`→terminal) with lease state consistent throughout; in-doubt provider truth → `MANUAL`, never a guess.
- **Coverage:** Failure matrix ≥ 21 cases covering worker crash, DB restart, object-storage outage, unknown outcome, notification outage, quota exhaustion; each asserts persisted state + event chain + lease + reached-terminal.
- **Expiry:** A mock-clock sweeper test drives an op to `EXPIRED` and invalidates its approval; a `CANCELLED` test proves cooperative stop at the provider boundary.
- **Runbook:** Each terminal-failure state links to an executable runbook; `tacctl op reconcile` exists and is tested.

## 11. Go / No-go

**NO-GO for treating this as incident-safety evidence; GO only as a design demonstrator.** The staging proof credibly establishes the mutation spine, policy gate, plan-bound approval, validation, reverse-deploy rollback, audit, and AI-independence — sufficient to justify continued investment. It is **not** sufficient to expose the MCP surface to a live model or to run a real pilot, because the crash/reconciler core is low-fidelity (R8-F2, F4), in-doubt outcomes are unhandled (R8-F3), and the failures an IC most fears — a frozen op nobody is paged about (R8-F1), DB restart (R8-F5), and object-storage loss (R8-F6) — are entirely unmodeled. **Gate live-model exposure on closing all Blocking findings (R8-F1/F2/F3) and R8-F4/F8/F10.** Most dangerous unhandled failure: **`MANUAL_INTERVENTION_REQUIRED` with a failed/absent page — a silently frozen worker with unbounded MTTD (R8-F1).**

---

## Appendix — Per-failure detection / recovery / fallback table

Modeled = exercised by the harness I ran; ✗ = not modeled (design coverage assessed).

| Failure | Modeled? | Persisted state (my run) | Detection | Recovery | Manual fallback | Assessment |
|---|---|---|---|---|---|---|
| Worker crash | Partial (`restart_unhealthy` fault exists; not exercised in matrix) | — | Health gate V1 | Restart (L2); failed restart → `MANUAL` (no rollback) | `tacctl` restart | Restart remedy sound; crash *detection* untested |
| Database restart | ✗ | — | none | untested | — | **Gap R8-F5**; durability rests on untested DB path |
| Object-storage failure | ✗ (R3 is a bool flag) | — | none | untested | — | **Gap R8-F6**; V9/R3 depend on it |
| Duplicate operation | ✓ | `same_op` | UNIQUE idempotency_key | returns existing op | idem key | Solid |
| Stale approval | ✓ | `APPROVAL_PENDING` | `verify_approval` expiry | new approval required | re-approve | Solid |
| Executor crash after mutation | ✓ (but graceful, not a real crash) | `VALIDATING` (dead-end, no lease) | reconciler (manually invoked) | resume→VALIDATING (no follow-through) | reconciler/re-apply | **Low fidelity R8-F2/F4** |
| Unknown execution outcome | ✗ (`slow`/timeout unimplemented) | — | reconciler assumes clean truth | no in-doubt branch | — | **Gap R8-F3** (most technically dangerous) |
| Validation failure | ✓ | `ROLLED_BACK` | V1–V4 gates | auto reverse-deploy | `tacctl` rollback | Solid |
| Rollback failure | ✓ | `MANUAL_INTERVENTION_REQUIRED` | R6/R3 fail | freeze + page (unproven page) | human via `tacctl` | State correct; **paging unproven R8-F1** |
| Email / paging outage | ✗ | — | none | none | none | **Gap R8-F1** (most operationally dangerous) |
| AI outage | ✓ | `SUCCEEDED` | n/a | full loop via `tacctl` | `tacctl` | Excellent |
| Provider outage | ✓ | `FAILED` | apply error | retry saved plan | re-run apply | Solid |
| Quota exhaustion | ✗ (V7 hardcoded True) | — | none | untested | doc-only | **Gap R8-F7** |
