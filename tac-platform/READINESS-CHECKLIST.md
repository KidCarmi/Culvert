# Acceptance Gate — Readiness Checklist

Implementation is accepted only when every item holds. Status verified in this session
against a real PostgreSQL 16 cluster (evidence in `evidence/`).

| Acceptance criterion | Status | Evidence |
|---|---|---|
| All unit tests pass | ✅ | `go test ./internal/{fsm,policy,audit,approval}` — ok |
| PostgreSQL transactional integration tests pass | ✅ | `test/integration` — CAS, `SELECT FOR UPDATE` lease, idempotency uniqueness, outbox order+atomicity, tenant isolation — ok |
| All qualification regression tests pass | ✅ | FSM legality (`TestFSM_*`), idempotency (`TestIdempotency_*`), tenant isolation, signature separation (`TestSigner_*`), approval integrity (`TestApproval_*`) — ok |
| All 16 failure-injection scenarios pass | ✅ | `TestFailureMatrix` (+ `TestRealCrashSemantics`, `TestUnknownOutcome_NoBlindRetry`) — ok |
| Works through `tacctl` with no AI | ✅ | `evidence/tacctl_e2e.txt` (init→restart→plan→approve→execute→validate→show, `audit_ok=true`) |
| restart and deploy use the same executor | ✅ | both call `executor.Mutate`; `TestRestartHappy_L2` + `TestDeployHappy_L3` |
| Process restarts lose no operation state | ✅ | `TestAuditReconstruct_AfterProcessEnd` (fresh connection re-verifies); crash tests resume via reconciler |
| Duplicate requests cannot duplicate mutations | ✅ | `UNIQUE(tenant_id, idempotency_key)`; `TestIdempotency_*`; `TestUnknownOutcome_NoBlindRetry` (generation unchanged) |
| Unknown outcomes never cause blind retries | ✅ | `TestUnknownOutcome_NoBlindRetry` — op left EXECUTING, reconciled from truth, applied once |
| Rollback failure reaches `MANUAL_INTERVENTION_REQUIRED` | ✅ | `TestFailureMatrix/11_rollback_failure_manual` |
| Audit verification succeeds after a full E2E run | ✅ | `VerifyAuditChain` true in E2E + tacctl `audit_ok=true` |
| No live MCP model has been connected yet | ✅ | no MCP/gateway package exists; only `tacctl` + tests |

## Required regression tests → permanent tests (every discovered qualification bug)
| Qualification bug | Permanent test |
|---|---|
| FSM legality (R9-F1) — illegal transition accepted | `internal/fsm/fsm_test.go` (exhaustive) |
| E2E idempotency (R9-F2) — dup re-executed | `TestIdempotency_ExactlyOnceCreate`, `TestIdempotency_ThroughService`, `TestFailureMatrix/3` |
| Real crash semantics (R8-F2/F4) | `TestRealCrashSemantics` (4 points, subprocess kill) |
| Tenant isolation (R7-F2) | `TestTenantIsolation` + `P0_tenant` policy rule |
| Signature separation (R7-F1) | `TestSigner_DomainSeparation`, `TestSigner_SharedKeyPanics` |
| Approval integrity (R7-F3) | `internal/approval/approval_test.go` (author, expiry, changed plan/commit/digest, forged sig) |

## PostgreSQL behavior exercised (not SQLite assumptions)
transactions · `SELECT FOR UPDATE` (lease) · uniqueness (idempotency) · concurrent CAS (stale-writer conflict) · isolation (aborted-tx handling) · outbox ordering + atomic-with-event · tenant constraints.

**Verdict: ACCEPTED for the deterministic spine.** MCP gateway remains gated (not connected), per the implementation order.
