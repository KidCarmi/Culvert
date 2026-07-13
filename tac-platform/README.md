# tac-platform — deterministic infrastructure-operations spine (Go)

The **real implementation** of the approved proof slice (`docs/support/infra-ops/proof-slice/`).
The Python harness under `docs/support/infra-ops/qualification/staging-proof/` is the
**behavioral reference / test oracle** — it is not this implementation's foundation.

- **Runtime:** Go 1.25 · PostgreSQL 16 · a deterministic in-DB mock provider · `tacctl` CLI · **no live model dependency, no production cloud credentials, synthetic data only.**
- **Nested Go module** (own `go.mod`), so it is isolated from the Culvert product module — `go build ./...` at the Culvert repo root does not descend into it, and this slice makes **no changes to `culvert`**.

## Validated workflow (same executor spine for L2 and L3)
```
create operation → legal FSM transition → plan → policy → plan-bound approval →
execution lease → deterministic mutation → provider receipt → validation →
reconciliation → success or rollback → durable signed audit
```
`restart_stateless_worker` (L2, autonomous) and `deploy_new_worker_version` (L3, human-approved) both flow through the one executor.

## Run it (local, $0)
```bash
# Option A — Docker Compose (canonical):
docker compose up --build --abort-on-container-exit tests

# Option B — local PostgreSQL without a Docker daemon (used in the qualification sandbox):
sudo bash scripts/local-pg.sh            # prints the DSN to export
export TAC_DSN="postgres://postgres@127.0.0.1:5433/tac?sslmode=disable"
go test -count=1 -p 1 ./...              # unit + PG integration + E2E + failure-injection
go build -o /tmp/tacctl ./cmd/tacctl && /tmp/tacctl init && /tmp/tacctl restart --idem r1
```
Tests are serialized across packages (`-p 1`) because they share one database.

## Layout
```
migrations/0001_init.sql        schema (tenant on every table; hash-chained signed audit; outbox)
internal/domain                 types + stable error taxonomy
internal/fsm                    legal-transition authority (the only place legality is decided)
internal/store                  pgx store: atomic state+audit+outbox, SELECT FOR UPDATE leases, tenant-scoped
internal/audit                  purpose-separated signing (plan/approval/audit distinct keys) + canon/hash
internal/policy                 deterministic policy engine (the safety boundary)
internal/plan                   content-addressed, signed plan artifacts
internal/approval               plan-bound approval build + verify
internal/provider               Adapter + DB-backed deterministic mock (fault-injectable, cross-process truth)
internal/executor               THE only infrastructure mutator
internal/validator              V-gates (reads provider truth; provider-200 ≠ success)
internal/opsvc                  named domain operations orchestrating the FSM + executor + reconciler + rollback
cmd/tacctl                      human CLI fallback (no AI)
cmd/crash-executor              test helper: os.Exit at a named crash point (REAL crash semantics)
test/{integration,e2e,failure}  PG integration, E2E, and the 16-case + real-crash suites
```

## Mandatory transactional invariants (all enforced structurally)
- every state transition is a **named domain operation**; no caller passes an arbitrary target state (`opsvc` methods use literal targets; `fsm.Check` is the gate)
- operation state + audit event + outbox row commit in **one transaction** (`store.Transition`)
- idempotency applies through CLI/REST/(future) MCP — `operations UNIQUE(tenant_id, idempotency_key)`
- **one active mutation lease per worker** (`leases` + `SELECT … FOR UPDATE`)
- approval is **consumed atomically with execution start** (`ConsumeApproval` in the execute tx)
- the **executor is the only infrastructure mutator**; it **never replans during apply**
- **provider success is not operation success** (validator reads provider truth)
- **unknown outcomes are reconciled from provider truth**; **no blind retry** after a possibly-successful mutation
- **tenant scope required** on every persisted object and query (cross-tenant read → `not_found`)
- **signer identities separated by purpose** (a plan signature is invalid as an approval/audit signature)
- Claude / any model receives **no secrets or provider credentials** (there is no such path in this slice)

## Next (explicitly NOT in this slice)
The **MCP gateway is intentionally not built yet** — it is added only after all model-free tests pass (this gate is met). No AI is connected. No cloud deploy.
