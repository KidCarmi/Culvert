# Unresolved Implementation Findings (honest ledger)

The spine meets the acceptance gate, but this is a proof slice. Known limitations and
deliberate deferrals — each with the milestone that closes it. None is a hidden defect.

## Deliberate scope boundaries (by instruction)
- **No MCP gateway / no AI connected.** Correct per the implementation order (built only after all model-free tests pass). Next: add `internal/gateway` with the 9 typed tools + REST, then `cmd/tac-mcp`; idempotency/scope/audit already flow through `opsvc` so the gateway is a thin, typed front door.
- **No real cloud provider.** The provider is a deterministic DB-backed mock; `tac-infra` uses the `null` provider. Next: a real `provider.Adapter` (Fly.io Machines / k8s) behind the same interface + the `ActionConnector` generalization (R2-F1) before a second L2 action.

## Fidelity gaps vs production (documented, not shipped as done)
- **Signing is HMAC-SHA256 with distinct keys**, a stand-in for distinct **Ed25519/KMS** identities. The *separation* is real and tested; the *cryptography* is not production-grade. Milestone: G0 KMS integration (the `audit.Signer` interface is the seam).
- **Crash semantics = `os.Exit(137)` of a separate process.** This faithfully models a killed executor (no defers, lease held) but not power-loss/torn-write at the storage layer. Milestone: fault-inject at the DB (kill Postgres mid-tx) in the hardening suite.
- **Composite scope columns exist (`tenant/env/region`) but the slice is single-env/region.** Policy `P1` still hard-codes `staging`. Milestone: G0 multi-env/region policy + lease-key already carries the triple (`Scope.LeaseKey`).
- **`SELECT FOR UPDATE` lease + optimistic CAS are tested, but not under high real concurrency.** Milestone: a concurrency stress test (N goroutines racing execute on one worker) in hardening.

## Small/known items
- **Reconciler is invoked explicitly** (`opsvc.Reconcile`) — there is no background loop/scheduler yet. Milestone: a periodic reconciler + sweeper worker (the queries `StuckOps`/`ForceExpireLease` exist).
- **Outbox is written but not consumed** — no publisher drains it yet (ordering + atomicity are tested). Milestone: an outbox relay when the first async consumer (notifications, R8-F1) lands.
- **`MANUAL_INTERVENTION_REQUIRED` has no notification/dead-man's-switch** (R8-F1 remains open) — the state is reached and audited, but nothing pages. Milestone: notification connector + unacked-escalation.
- **Tests require `-p 1`** (shared database across packages). Acceptable for the slice; production CI would use a database-per-package or template DB. Documented in the README.
- **`tacctl` is a thin dev CLI** (hand-rolled flag parsing, no `--help` per subcommand). Adequate as the AI-independent fallback proof; not a polished operator CLI.
- **P4 accepts any allowlisted digest** (no vulnerable-digest deny-list; R7 design item). Milestone: digest deny-list + min-version.
- **Audit chain is per-op with no global anchor** (whole-op deletion is not yet cross-detectable; R7 design item). Milestone: periodic anchor (chain-of-chains).

## Explicitly closed in this implementation (were qualification blockers)
FSM legality (R9-F1), idempotency on all paths (R9-F2), real cross-process crash + reconciliation (R8-F2/F4), tenant isolation (R7-F2), purpose-separated signing (R7-F1), plan-bound approval + author rejection + single-use + expiry + changed-plan invalidation (R7-F3), provider-200 ≠ success, unknown-outcome no-blind-retry, rollback-failure → MANUAL. All have permanent tests.
