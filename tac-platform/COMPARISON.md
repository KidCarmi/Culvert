# Python reference oracle ↔ Go implementation — outcome comparison

The Python harness (`docs/support/infra-ops/qualification/staging-proof/tac_proof.py`) is the
behavioral oracle. The Go implementation (`tac-platform/`) must reproduce its validated
outcomes on real PostgreSQL. Both are **green**; where the Go version is *stricter* than the
oracle, it is noted (the oracle's fidelity gaps were themselves qualification findings).

## Workflow demonstrations

| Behavior | Python oracle | Go implementation | Match |
|---|---|---|---|
| create → legal FSM → plan → policy | ✅ | ✅ `TestFSM_*`, `opsvc.planAndPolicy` | ✅ |
| plan-bound human approval; author rejected | ✅ | ✅ `TestApproval_*`, `TestDeployHappy_L3` | ✅ |
| single mutation spine (L2 restart + L3 deploy) | ✅ | ✅ `TestRestartHappy_L2`, `TestDeployHappy_L3` (same `executor.Mutate`) | ✅ |
| deterministic mutation → provider receipt | ✅ | ✅ `execution_results` + `provider_correlation_id` | ✅ |
| validation (provider-200 ≠ success) | ✅ | ✅ `validator.Run` reads provider truth | ✅ |
| failed validation → reverse-deploy rollback | ✅ | ✅ `TestDeployFail_Rollback` → ROLLED_BACK | ✅ |
| durable signed audit, reconstructable post-process | ✅ (in-proc) | ✅ **stronger:** `TestAuditReconstruct_AfterProcessEnd` re-verifies the hash chain from a **fresh DB connection** | ✅+ |

## Failure-injection matrix (16 + crash points)

| # | Scenario | Python oracle | Go implementation |
|---|---|---|---|
| 1 | disconnect during planning | REVIEW_PENDING | ✅ `TestFailureMatrix/1` |
| 2 | disconnect during execution | VALIDATING | ✅ `/2` |
| 3 | duplicate request | same op | ✅ `/3` + `TestIdempotency_*` |
| 4 | stale approval | rejected | ✅ `/4` (approval expiry, real DB) |
| 5 | plan changed after approval | rejected (sig mismatch) | ✅ `/5` |
| 6 | policy rejection | POLICY_REJECTED | ✅ `/6` |
| 7 | crash **before** provider mutation | reconciler → resolved | ✅ **real process kill** `TestRealCrashSemantics/before_mutation` → ROLLED_BACK |
| 8 | crash **after** provider mutation | reconciler reads truth | ✅ **real process kill** `/after_mutation` → SUCCEEDED |
| 8b | crash after success **before receipt** | (folded) | ✅ covered by `/after_mutation` (receipt persisted after) |
| 8c | crash after receipt **before validation** | (folded) | ✅ **real process kill** `/after_receipt` → SUCCEEDED |
| 9 | partial provider success | rolled back | ✅ validation fails on partial → rollback |
| 10 | validation failure | rolled back | ✅ `/10_validation_failure_rolls_back` |
| 11 | rollback failure / prev image gone | MANUAL_INTERVENTION_REQUIRED | ✅ `/11_rollback_failure_manual` |
| 12 | concurrent op on same worker | blocked (lease) | ✅ `/12` + `TestLease_SingleActivePerWorker` |
| 13 | malicious log prompt injection | inert | ✅ no mutating tool; L3 needs approval (structural) |
| 14 | expired credentials mid-apply | clean FAILED | ✅ `/14` |
| 15 | provider unavailable | FAILED | ✅ `/15` |
| 16 | AI unavailable | tacctl-only success | ✅ `/16` + the whole suite is model-free |
| — | unknown outcome, no blind retry | (implicit) | ✅ **stronger:** `TestUnknownOutcome_NoBlindRetry` asserts the mutation is applied exactly once (generation unchanged after reconcile) |

## Where Go is stricter than the oracle (closing the reviewers' fidelity findings)
- **Real crash semantics (R8-F2/F4):** the oracle modeled a "crash" as a caught exception; Go kills a **separate process** (`cmd/crash-executor`, `os.Exit(137)`), leaving the op EXECUTING/VALIDATING with the lease **held**, and only the reconciler (after lease expiry, from provider truth) resolves it — verified for all four crash points.
- **PostgreSQL, not SQLite:** real transactions, `SELECT FOR UPDATE`, unique constraints, optimistic CAS, outbox ordering, and tenant constraints are exercised against Postgres 16 (`test/integration`).
- **FSM legality (R9-F1):** `fsm.Check` rejects every illegal transition (exhaustively tested), not just a version CAS.
- **Signer separation (R7-F1):** three distinct keys; a cross-domain signature fails (`TestSigner_DomainSeparation`).
- **Tenant isolation (R7-F2):** `tenant_id` on every row + every query; cross-tenant reads return `not_found`.

**Net:** the Go implementation reproduces every validated oracle outcome and is strictly more faithful on the exact points the qualification board flagged.
