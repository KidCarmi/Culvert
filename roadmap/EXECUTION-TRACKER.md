# Culvert Release Platform — Execution Tracker

> **Each PR is single-scope and belongs to exactly one milestone. A milestone may
> require multiple PRs.** PR-to-PR follow-up fixes stay in their own PR; milestone
> code is never mixed across PRs.

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
| **M0 — Foundation & Safety** | **✅ COMPLETE (impl + operational validation)** | 5 PRs merged (#628 #629 #630 #631 #632) + activation PRs #633 #634 | acceptance: `roadmap/M0-ACTIVATION-EVIDENCE.md` | — |
| M1 — Dual-publish + refresh + detection | **Unblocked — next** | — | — | — (M0 accepted 2026-07-10) |
| M2 — Default switch + repo-private | Not started | — | — | M1 + owner |
| M3 — Trust durability + Pages retirement | Not started | — | — | M2 + owner |
| M4 — Emergency ops + Console + telemetry | Not started | — | — | M2 |
| M5 — Onboarding hardening | Not started | — | — | M1 |
| M6 — Enterprise GA | Not started | — | — | M4, M5 |

### M0 PR plan
| PR | Scope | Status | Branch | Findings (design) | Findings (impl) | Tests | Evidence |
|---|---|---|---|---|---|---|---|
| M0-PR1 | Deterministic spec + version authority | PR open (babysitting) | `…-m0-foundation` | 4 reviews; 1 BLOCKING + 4 HIGH resolved in design v2 §14 (version→semver, vars-gate, baked-root gate, 2 modes, UTC-Z) | 3 reviews: security CLEAN; +1 MEDIUM floor-transition (→ 1e9 scheme-base), 2 MEDIUM validator-drift + gate-entrypoint-untested, edges — all fixed | version encoding (monotonic/collision/bounds/leading-zero/0.0.0), idempotency, UTC-Z, resign-identity, expired-guard, gate-parity, overrides; vet + -race clean, -count=2 -shuffle=on green | code core: release_spec.go + tests + gate rewire + ci.yml deterministic spec step |
| M0-PR2 | Served-catalog verification (drive real autoSeedCatalog over HTTP) | PR open (babysitting) | `…-m0-served-verify` (on merged main) | 3 reviews; HIGH (drive real autoSeedCatalog) + baked-root-fail-closed-local + artifact-owns-outcome-over-HTTP + no-seam + reuse-fixtures + SetStageBase — all in design v2 §11 | 3 reviews: MEDIUM baked-root-test-vacuous (→ present-but-invalid served .sigstore so verifyIndexBundle actually runs), MEDIUM freshness/rollback assert error-KIND (errCatalogExpired/errCatalogRollback via errors.Is), MEDIUM no-clobber-of-existing test, LOW two-phase manifestGET==0 — all fixed | Contract (valid installs; tamper→reject+manifestGET==0; expired→errCatalogExpired; rollback→errCatalogRollback; malformed→reject, dest untouched) + no-clobber-existing (good v5 survives tampered v6) + baked-root fail-closed (garbage .sigstore) + artifact-owns-outcome over HTTP; vet + race+shuffle x2 clean | release_catalog_served_test.go |

**M0-PR2 dependency decision (explicit):** PR2 is **independent of PR1** — it edits
`release_catalog_http_test.go` (+ a new served-verify test) with **zero file or
functional overlap** with PR1 (`release_spec.go`/`release_gen_test.go`/`ci.yml`).
**Strategy: prefer waiting for PR1 (#628) to merge, then (re)build PR2 from the
latest `main`.** Design + independent planning reviews proceed now while #628 is
pending; **implementation does not start until PR1 merges.** No stacked branch is
needed (no overlap); if PR1's merge is delayed and PR2 must start, PR2 branches
from current `main` and is rebased onto `main` after PR1 merges (dependency marked
here + in the PR body). PR1 follow-up fixes are **never** placed in PR2.
| M0-PR3 | Dormant R2 stage→verify→promote workflow | PR open (babysitting) | `…-m0-r2-publish` (from merged main) | 3 reviews (security/ops/test): 1 BLOCKING + 6 HIGH resolved in design v2 §12 (verify-fail-open→json-pass-proof, tag-glob-traversal→strict-regex+tag-ref-confirm, CDN/origin-TOCTOU→ETag-pinned-copy, pwn-request→default-branch-checkout, 412-idempotency→catch-and-continue, write-all-bypass→type-switch, absent-step-vacuous→existence-before-order) | 2 reviews (security/correctness): MED substitution/downgrade (412 trusts pre-existing obj → origin-sha==bundle gate before promote), HIGH promote-gate bypass via !cancelled()/failure() (→ reject always/cancelled/failure in promote if:), MED non-enforcing pass-proof (→ require jq -e + exit 1), LOW manifest list-objects None/cap (→ local staged set) — all fixed, design v2 §13 | TestWorkflowInvariants — proven non-vacuous vs SIX unsafe mutations; vet + full pkg + race+shuffle x2 clean | .github/workflows/publish-catalog-r2.yml + release_workflow_invariants_test.go |
| M0-PR4 | Legacy update-path retirement (checkGitHubLatestTag default-off) | PR open (babysitting) | `…-m0-legacy-retire` (from merged main) | 2 reviews (correctness/behavior): 2 HIGH resolved (package-init-freeze→resolve-at-startup w/ getenv seam; test var leak→save/restore) + MED discoverability→/api/update/status gate field + CLAUDE.md | 1 review, ship-as-is: MED snapshot() unmutexed read→atomic.Bool; ON path byte-identical, default no-dial, source-scan sound — confirmed | resolver table, default-no-dial (spy counter==0), enabled/short-circuit, env-wiring, source-scan guard (no direct GitHub call in checkUpdateNow); vet + race+shuffle x2 + golangci clean | update.go + update_legacy_fallback_test.go |
| M0-PR5 | IaC guardrails skeleton + terraform fmt/validate lane + activation docs | PR open (babysitting) | `…-m0-iac-docs` (from merged main) | 2 reviews (terraform-schema/CI+docs): HIGH aggregate-needs anti-rot + 3 HIGH provider-schema (ruleset nested shape, env dual-boolean, pin cloudflare v4.52) + MED 6-site classify wiring + MED runbook 6-secrets/allowlist-merged-edit — all resolved (design §7) | 1 review, ship-as-is: fmt-alignment scripted PASS + schemas validated vs pinned providers + wiring/self-validation/runbook confirmed | CI terraform fmt+validate lane (path-gated Deep-gate job, in aggregate needs); NOTE: HCL authored without local validate (egress policy) → CI lane is authoritative first validation | deploy/terraform/** + pr-deep-gate.yml + docs/operator/catalog-hosting-r2-activation.md |

### Owner prerequisites outstanding
Cloudflare (all), GitHub secrets, protected `release` env + reviewers, `v*`
ruleset, repo-private flip (M2). Activation steps documented in M0-PR5.

### Current blocker
None for M0 planning. Next action: resolve M0 planning-review findings, then
implement M0-PR1.
