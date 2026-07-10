# Culvert Release Platform — Execution Tracker

Single source of execution truth. Canonical spec:
`roadmap/CULVERT-RELEASE-PLATFORM-MASTER-DESIGN.md` (design branch
`claude/culvert-r2-migration-plan-1oh769`; pending doc-merge to `main`).
Updated after every material change.

---

## Phase 0 — Global Prerequisite Audit

Baseline: `main` @ `9b30c81`; repo builds (`go build ./...` OK); determinism +
gate tests green (`TestGenerateReleaseCatalog_Deterministic`,
`TestReleaseCatalogGate`). Working tree clean.

### Repository
| Item | Status | Notes |
|---|---|---|
| Canonical Master Design exists & consistent | **Ready** | On design branch; recommend a doc-only merge to `main` so engineering has it on the mainline. |
| Working tree clean | **Ready** | — |
| Branch/`main` state known | **Ready** | `main` @ `9b30c81`; M0 branch `claude/release-platform-m0-foundation` from it. |
| Prior migration/review docs are historical only | **Ready** | Superseded by the Master Design. |
| CI gates identified | **Ready** | Required merge checks: `✅ Fast PR Gate — APPROVED`, `✅ Deep PR Gate — APPROVED`. Plus Snyk/AegisDiff/Codex advisory bots seen on prior PRs. |
| Tag/release workflow mapped | **Ready** | `ci.yml`: `docker` (build+push+sign), `catalog-pipeline` (gen+gate+sign+attach), `auto-tag`, `release`, `provenance`. |
| Pages publishing workflow mapped | **Ready** | `publish-catalog-pages.yml` (workflow_run on `CI` success on tag → Pages). **Must remain unchanged until M3.** |
| Catalog generator + verifier mapped | **Ready** | `release_gen.go`, `release_catalog.go`, `release_catalog_verify.go`, `release_catalog_sigstore.go`, `release_catalog_http.go`, `release_catalog_freshness.go`. |
| Update client + agent paths mapped | **Ready** | `update.go` (legacy tag path), `release_dispatch*.go`, `cmd/culvert-maint`. |

### GitHub prerequisites (owner boundary)
| Item | Status |
|---|---|
| Protected `release` environment | **Missing — requires owner** (not verifiable from code) |
| Required reviewers | **Missing — requires owner** |
| Repository secrets (R2/CF) | **Missing — requires owner** |
| Protected `v*` tag ruleset | **Missing — requires owner** (real control per `CI-REDESIGN.md`; not in code) |
| Required status checks (add new) | **Requires owner** (existing Fast/Deep gates are Ready) |
| Create branches/PRs | **Ready** |
| Read CI/PR feedback | **Ready** (GitHub MCP + PR webhooks) |

### Cloudflare prerequisites (owner boundary — ALL)
Zone `culvertlabs.com`, R2 bucket, staging bucket/prefix, `catalog.culvertlabs.com`,
optional staging domain, R2 S3 creds, cache-purge token, zone ID, cache rules,
Smart Tiered Cache, disabled `r2.dev` → **all Missing — requires owner.**
**Do not block local work.** M0 builds against local mocks; the production R2 job
stays **dormant** (safe-skip when secrets absent).

### Local validation prerequisites
| Item | Status |
|---|---|
| Local HTTP/S3-compatible mock (served-catalog origin) | **Missing — implementable** (Go `httptest` file server over a staged dir) |
| Deterministic catalog fixtures | **Ready/extend** (`release_gen_test.go`) |
| Sigstore verification fixtures | **Ready** (`ca.NewVirtualSigstore` in tests) |
| Failure injection | **Implementable** |
| Concurrent version simulation | **Implementable** (Go test) |
| Served-catalog verification | **Implementable** (`TestReleaseCatalogServedVerify`) |
| `go test` / `-race` / `go vet` / linters | **Ready** |
| Workflow/schema validation | **Implementable** (actionlint or a YAML lint step) |

### Deferred by design (NOT M0)
Rings (beta/dev) + atomic CAS counter + graduation tooling; revoke workflow;
telemetry; Release Console; ed25519 second scheme; secondary origin; repo-private
cutover. → later milestones.

### Blocks execution?
**None block M0 local implementation.** Owner items block only the **live R2
activation** (kept dormant) and **M2** (repo-private, protected env/ruleset).

---

## Milestone status

| Milestone | Status | Branch | PR | Blocker |
|---|---|---|---|---|
| **M0 — Foundation & Safety** | **Planning** | `claude/release-platform-m0-foundation` (+ per-PR branches) | — | Planning-review findings pending |
| M1 — Dual-publish + refresh + detection | Not started | — | — | M0 |
| M2 — Default switch + repo-private | Not started | — | — | M1 + owner |
| M3 — Trust durability + Pages retirement | Not started | — | — | M2 + owner |
| M4 — Emergency ops + Console + telemetry | Not started | — | — | M2 |
| M5 — Onboarding hardening | Not started | — | — | M1 |
| M6 — Enterprise GA | Not started | — | — | M4, M5 |

### M0 PR plan
| PR | Scope | Status | Branch | Findings (design) | Findings (impl) | Tests | Evidence |
|---|---|---|---|---|---|---|---|
| M0-PR1 | Deterministic spec + version authority | Planning | `…-m0-foundation` | pending reviewers | — | — | — |
| M0-PR2 | Served-catalog verifier + local origin harness | Planned | — | — | — | — | — |
| M0-PR3 | Dormant R2 stage→verify→promote workflow | Planned | — | — | — | — | — |
| M0-PR4 | Legacy update-path retirement | Planned | — | — | — | — | — |
| M0-PR5 | IaC guardrails + activation docs | Planned | — | — | — | — | — |

### Owner prerequisites outstanding
Cloudflare (all), GitHub secrets, protected `release` env + reviewers, `v*`
ruleset, repo-private flip (M2). Activation steps documented in M0-PR5.

### Current blocker
None for M0 planning. Next action: resolve M0 planning-review findings, then
implement M0-PR1.
