# Proof Slice — Build Plan: Redeploy/Restart One Stateless TAC Analysis Worker (Staging)

- **Status:** Implementation-ready build plan (design). **Do not implement yet.**
- **Date:** 2026-07-13
- **Depends on:** the approved responsibility split (`../INFRA-OPS-ARCHITECTURE.md`, ADRs 0019–0022).
- **Goal:** prove the entire deterministic loop — read → operation → plan → policy → review → approval → executor apply → validate → persist → rollback → post-session audit — on the smallest reversible, data-free, $0 operation.

**Approved principle (verbatim, load-bearing):** Claude = conversational interface + reasoning; Git+OpenTofu = desired-state source of truth; Operation DB = durable workflow/execution state; Policy engine = structural safety authority; Human approval service = authorization for high-impact; Deterministic executor = the only component that changes infrastructure; Provider state = actual state. **Claude never becomes the source of truth, the executor, the approval authority, the credential holder, the rollback mechanism, or the only record of an operation.**

This doc is the index + component architecture + repo layout + sequence + complexity + files-to-change + **the strict go/no-go checklist (§10)**. Companion specs:

| Spec | Contents |
|---|---|
| [STATE-MACHINE.md](STATE-MACHINE.md) | 18-state operation FSM; per-transition actor/preconditions/txn/idempotency/lease/timeout/retry/audit/cancel/recovery; concurrency |
| [schema.sql](schema.sql) | Postgres DDL: operations, events(audit), plans, approvals, reviews, leases, worker_registry |
| [TOOL-AND-API-CONTRACTS.md](TOOL-AND-API-CONTRACTS.md) | 9 MCP tool schemas + REST API + CLI-fallback equivalents |
| [POLICY-IDENTITY.md](POLICY-IDENTITY.md) | Deterministic policy rules (code-ready) + identity matrix + $0-pilot credential minting |
| [ARTIFACTS-AND-AUDIT.md](ARTIFACTS-AND-AUDIT.md) | Plan artifact, approval artifact, audit schema, signing/binding |
| [OPENTOFU-ALGORITHMS.md](OPENTOFU-ALGORITHMS.md) | OpenTofu module design + deployment/validation/rollback algorithms |
| [TESTING-AND-ACCEPTANCE.md](TESTING-AND-ACCEPTANCE.md) | Local E2E topology, 16-case failure-injection suite, acceptance criteria |

---

## 1. Component architecture (proof slice)

```
┌── Claude operator agent ──┐        ┌── independent review agents (advisory) ──┐
│  (+ CLI fallback binary)  │        │  security-review · cost-review           │
└───────────┬───────────────┘        └───────────────────┬──────────────────────┘
            │ MCP (typed tools)                           │ (called by gateway during PLANNING)
┌───────────▼─────────────────────────────────────────────▼──────────────────────┐
│  GATEWAY  (tac-infra/services/gateway)                                           │
│  MCP server + REST; schema-validate → authn(session) → authz(policy scope) →     │
│  rate-limit → route to operation-service. Holds NO provider creds.               │
└───────────┬─────────────────────────────────────────────────────────────────────┘
            │ internal gRPC/HTTP
┌───────────▼───────────┐   ┌──────────────┐   ┌───────────────┐   ┌──────────────┐
│ OPERATION SERVICE      │──►│ POLICY ENGINE │   │ APPROVAL SVC   │   │ AUDIT SERVICE │
│ owns the FSM + op DB   │◄──│ (deterministic│   │ (single/dual,  │   │ (append-only, │
│ leases, idempotency    │   │  OPA-style)   │   │  plan-bound)   │   │  signed)      │
└───────┬────────────────┘   └──────────────┘   └───────────────┘   └──────────────┘
        │ enqueue APPROVED op (durable queue)
┌───────▼────────────────┐   ┌────────────────────────────────────────────────────┐
│ EXECUTOR               │   │ VALIDATOR                                          │
│ the ONLY infra mutator │   │ health + digest + synthetic-job + drift + audit    │
│ verifies plan sig+appr │   │ gates SUCCEEDED; never trusts provider-200 alone   │
│ short-lived creds only  │   └────────────────────────────────────────────────────┘
└───────┬────────────────┘
        │ OpenTofu apply <saved plan>  (deploy)  |  provider machine-restart API (restart)
┌───────▼──────────────────────────────────────────────────────────────────────────┐
│ PROVIDER (pilot: Fly.io Machines)  +  Git(desired state)  +  OpenTofu state         │
└───────────────────────────────────────────────────────────────────────────────────┘
```

Every arrow into the mutation path is deterministic. Claude touches only the top edge. Remove Claude → the CLI drives the identical gateway.

---

## 2. Repository layout & the product/infra split (decision)

**Decision: three repositories, not one.** Separate the TAC *product* from *infrastructure state* and from the *ops control plane's own state*.

| Repo | Owns | Why separate |
|---|---|---|
| `culvert` (existing) | the on-prem appliance | already exists; the appliance is Tier 1 and must never couple to cloud infra |
| `tac-platform` | TAC cloud *application* (ingestion, analysis-worker image, analyzers) | product code + the worker container image; ships an **image digest** consumed by infra |
| **`tac-infra`** (new) | OpenTofu desired-state **and** the ops control-plane services (gateway/operation/policy/approval/executor/validator/audit/mcp/cli) + migrations + tests | desired state must be independently reviewed (CODEOWNERS), independently CI'd, and a product commit must **not** be able to change infrastructure |

**Rationale:** (a) blast radius — a product bug/PR can't alter infra; (b) different review authority — infra PRs require infra CODEOWNERS + the security-review gate; (c) the worker *image digest* is the only coupling — `tac-platform` builds it, `tac-infra` references it as an immutable input, so a deploy is "point staging at digest X," fully declarative; (d) the control-plane services live in `tac-infra` because they ARE the infra tooling and are bootstrapped once, out-of-band, before the loop operates on workloads.

**Desired-state lives in `tac-infra`, not in the product repo and not in Claude.**

### `tac-infra` file layout (the repo the slice builds)
```
tac-infra/
├── environments/
│   └── staging/
│       ├── main.tf                     # module wiring for staging
│       ├── workers.tf                  # tac_analysis_worker module instance (image digest input)
│       ├── versions.tf                 # required_providers, pinned versions
│       ├── backend.tf                  # OpenTofu state backend (locking)
│       └── .terraform.lock.hcl         # provider lock (digest fed into plan artifact)
├── modules/
│   └── analysis_worker/
│       ├── main.tf variables.tf outputs.tf   # stateless worker: image digest, replicas, config
│       └── README.md
├── services/
│   ├── gateway/         # MCP + REST front door (Go)
│   ├── operation/       # FSM + op DB + leases + idempotency (Go)
│   ├── policy/          # deterministic policy engine (Go + rego bundle)
│   ├── approval/        # single/dual approval, plan-bound (Go)
│   ├── executor/        # the only mutator: tofu apply / restart API (Go)
│   ├── validator/       # post-deploy validation (Go)
│   ├── audit/           # append-only signed audit writer (Go)
│   └── identity/        # broker: mints short-lived scoped creds (Go)
├── cmd/
│   ├── tac-mcp/         # MCP server binary (wraps gateway)
│   └── tacctl/          # CLI fallback binary (same REST API)
├── migrations/          # SQL migrations (0001_init.sql = schema.sql)
├── policy/              # policy-as-code bundle (rego + typed tests)
├── deploy/              # bootstrap compose/manifests for the control plane itself
├── test/
│   ├── integration/     # component + contract tests
│   ├── e2e/             # local E2E (docker-compose topology)
│   └── failure/         # 16-case failure-injection suite
└── docs/                # links back to this build plan
```

---

## 3. Planning vs execution decision (both, by path)

| Path | Mechanism | Changes desired state? | Rollback |
|---|---|---|---|
| **L2 `restart_stateless_worker`** | **typed orchestration action** (provider machine-restart API via the executor) | **No** — runtime only | none needed (restart is idempotent, version-invariant); validated for health |
| **L3 `deploy_new_worker_version`** | **OpenTofu** (desired-state image-digest change → `tofu plan` → signed artifact → `tofu apply <saved plan>`) | **Yes** — Git commit is the change | explicit reverse-deploy to previous known-good digest (§7 / OPENTOFU-ALGORITHMS) |

So the slice uses **both**: OpenTofu for the version deploy (desired-state), a typed action for the restart (no desired-state change). Neither path lets Claude pass raw tofu args, image refs, or provider config — the deploy's image digest is chosen from the `worker_registry` allowlist server-side (POLICY-IDENTITY §allowlists).

---

## 4. Implementation sequence (order to build the slice)

1. **DB + migrations** (`schema.sql`) — operations/events/plans/approvals/reviews/leases/worker_registry.
2. **Operation service + FSM** — states, transitions, leases, idempotency, recovery; no external effects yet (in-memory provider stub).
3. **Audit service** — append-only signed event log (every transition writes an event).
4. **Policy engine** — the deterministic rule set + tests (POLICY-IDENTITY); wired into PLANNING→(POLICY_REJECTED|REVIEW_PENDING).
5. **Plan artifact + signing** (ARTIFACTS) — planner produces signed plans; approval binds to plan signature.
6. **Approval service** — single/dual, plan-bound, expiry.
7. **Identity broker** — mint short-lived executor creds post-approval (stubbed provider in local E2E).
8. **Executor** — restart action first (L2), then `tofu apply <saved plan>` (L3); verifies sig+approval+lease.
9. **Validator** — health/digest/synthetic-job/drift/audit gates.
10. **Rollback** — reverse-deploy algorithm + MANUAL_INTERVENTION_REQUIRED.
11. **Gateway + MCP tools** — the 9 typed tools; schema fitness tests.
12. **CLI fallback (`tacctl`)** — inspect/plan/approve/execute/validate/rollback over the same REST API.
13. **Local E2E topology + 16-case failure-injection suite** — the acceptance gate.

Build read/plan/policy before any mutator; the restart (L2) before the deploy (L3); the deploy before rollback; everything before the gateway/MCP surface — so the deterministic core is proven before the model can touch it.

---

## 5. Exact files expected to change / be created (all NEW in `tac-infra`)

The `culvert` repo changes **only** by adding these design docs (this slice creates no product code). The slice's code lives in the new `tac-infra` repo:

- `migrations/0001_init.sql` (= schema.sql)
- `services/operation/{fsm.go, store.go, lease.go, idempotency.go, recovery.go, *_test.go}`
- `services/policy/{engine.go, rules.rego, rules_test.go}`
- `services/approval/{approval.go, bind.go, *_test.go}`
- `services/executor/{executor.go, deploy_tofu.go, restart_action.go, verify.go, *_test.go}`
- `services/validator/{validator.go, synthetic_job.go, drift.go, *_test.go}`
- `services/audit/{audit.go, sign.go, *_test.go}`
- `services/identity/{broker.go, oidc.go, *_test.go}`
- `services/gateway/{server.go, tools.go, schemas.go, authz.go, *_test.go}`
- `cmd/tac-mcp/main.go`, `cmd/tacctl/main.go`
- `modules/analysis_worker/{main.tf, variables.tf, outputs.tf}`
- `environments/staging/{main.tf, workers.tf, versions.tf, backend.tf}`
- `policy/` bundle, `deploy/` bootstrap compose
- `test/integration/*`, `test/e2e/*`, `test/failure/*`

---

## 6. Estimated complexity by component

| Component | Complexity | Notes / risk |
|---|---|---|
| DB schema + migrations | **Low** | standard Postgres; the shape is fixed here |
| Operation service + FSM | **High** | the heart: transactions, leases, idempotency, recovery — most bug-prone |
| Policy engine | **Medium** | deterministic rules are simple; the rigor is in the test matrix |
| Plan artifact + signing | **Medium** | Ed25519 + digest binding; care in what's signed |
| Approval service | **Medium** | plan-binding + dual + expiry edge cases |
| Identity broker | **High** | short-lived cred minting via OIDC/workload identity; provider-specific |
| Executor | **High** | the only mutator; tofu apply saved-plan + restart API; partial-success handling |
| Validator | **Medium** | synthetic job + drift diff; provider-specific health |
| Rollback | **High** | explicit reverse-deploy + MANUAL_INTERVENTION_REQUIRED paths |
| Gateway + MCP | **Medium** | typed schemas + fitness tests; mostly plumbing |
| CLI fallback | **Low** | thin REST client |
| OpenTofu module | **Low–Medium** | one stateless worker; provider maturity is the variable |
| E2E + failure suite | **High** | the mock-provider fault matrix is where correctness is proven |

Highest-risk trio: **operation service, executor, rollback** — build and fault-test these first and hardest.

---

## 7. Concurrency guarantee (two chat sessions must not double-execute)

Three independent mechanisms (STATE-MACHINE §concurrency):
1. **`operations.idempotency_key` UNIQUE** — the same logical request (same op) is created once; a duplicate `create_*` returns the existing op.
2. **Per-worker apply lease** (`leases` row keyed `staging:<worker_id>`) — only one op can be in EXECUTING/VALIDATING against a worker; a second op waits or is rejected.
3. **Optimistic `operations.version`** — every state transition is a compare-and-set; a stale writer loses and re-reads.

---

## 8. What Claude may and may not do in this slice

- **May (autonomous):** `get_platform_health`, `get_worker_status`, `create_worker_restart_operation` (L2 — executes only if every structural precondition passes), `create_worker_deployment_plan` (L1 — produces a plan, executes nothing), `get_operation`, `validate_worker_deployment` (read), `cancel_operation`, request `rollback_operation`.
- **Must have human approval for:** `deploy_new_worker_version` (the L3 apply of a plan) and any data-affecting rollback.
- **Never:** pass shell/tofu-args/env/resource-address/image-registry/provider-config; hold creds; see secret values; approve its own plan; be the only record (the op DB + audit are authoritative).

---

## 9. Acceptance summary (full criteria in TESTING-AND-ACCEPTANCE)

The slice is accepted when: the happy path (restart L2 + deploy L3) works end-to-end; all 16 failure-injection cases land in the specified persisted state with the specified recovery; the CLI reproduces every step without Claude; a bundle/op is fully reconstructable from the audit after the chat ends; and the go/no-go checklist (§10) is all-green.

---

## 10. STRICT GO / NO-GO CHECKLIST FOR BEGINNING IMPLEMENTATION

Implementation may begin **only when every box is checked**. Any unchecked box = NO-GO.

**Authority & boundaries**
- [ ] `tac-infra` repo created; product/infra split enforced by CODEOWNERS; product repo cannot alter infra.
- [ ] Desired state lives in Git (OpenTofu); Claude holds no desired state.
- [ ] The executor is the only component with provider mutate creds; Claude and the gateway have none.
- [ ] No tool in the MCP catalog accepts shell/SQL/tofu-args/env/resource-address/registry/provider-config/secret (fitness test drafted).

**Deterministic spine**
- [ ] Postgres provisioned (Neon free tier); `0001_init.sql` reviewed.
- [ ] Operation FSM spec (STATE-MACHINE) reviewed; every transition has actor/precondition/txn/idempotency/lease/timeout/retry/audit/cancel/recovery defined.
- [ ] Idempotency-key UNIQUE + per-worker lease + optimistic-version concurrency design reviewed.
- [ ] Policy rule set (POLICY-IDENTITY) reviewed; staging-only + single-worker allowlist + digest allowlist + $0-delta + mandatory-health + mandatory-rollback-target + expiry encoded.
- [ ] Plan artifact + approval artifact + audit schema (ARTIFACTS) reviewed; signing keys provisioned in an HSM/KMS the executor (not Claude) reads.

**Safety gates**
- [ ] Approval binds cryptographically to the exact plan artifact (plan signature); a generic "yes" cannot approve.
- [ ] A changed commit / new plan invalidates prior approval (design confirmed).
- [ ] Dual-approval classes list agreed (none required for this slice, but the mechanism exists).
- [ ] MANUAL_INTERVENTION_REQUIRED path defined for partial-success and rollback-failure.

**Fallback & audit**
- [ ] `tacctl` CLI covers inspect/plan/approve/execute/validate/rollback over the same API.
- [ ] Audit record is understandable without the chat (schema reviewed).
- [ ] The whole slice is operable with Claude absent (fallback proven in E2E design).

**Verification**
- [ ] Local E2E topology (TESTING) with a fault-injectable mock provider defined.
- [ ] All 16 failure-injection cases have an expected-persisted-state + recovery-path.
- [ ] Acceptance criteria agreed and owned.

**Sign-off**
- [ ] Human owner approves the responsibility split for THIS slice.
- [ ] Security review of the policy + identity + signing design complete.
- [ ] Rollback/DR reviewer confirms the reverse-deploy + MANUAL_INTERVENTION_REQUIRED design.

When all boxes are green: implement in the order of §4, mock-provider first, real provider last, failure suite green before the gateway/MCP surface is exposed to any live model.
