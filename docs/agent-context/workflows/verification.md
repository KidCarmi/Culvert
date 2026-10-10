# Verify a Culvert change

Use this procedure for nontrivial code or behavior changes and for changes to agent instruction routing. A spelling-only edit does not need the runtime suite. Select checks from the changed contract, its callers, and the current workflow definitions; this is not a requirement to run every lane for every task.

This procedure grants no additional permission to install tools, use privileged resources, deploy, push, publish, or modify external systems. Keep verification within the authorized task and environment. Report missing prerequisites rather than changing security settings or weakening a check.

## Establish the verification boundary

1. Identify the base and candidate revision and inspect the complete diff, including additions, deletions, renames, and untracked task files. Preserve unrelated work. Record which behavior or instruction decision changed.
2. Read applicable root/scoped instructions and use the [context index](../README.md) to find the owning contract. Follow semantic dependencies across directories: root adapters often own integration even when an engine lives under `internal/`.
3. Read the relevant tests, build constraints, module manifests, and actual CI jobs before choosing commands. Source code, tests, and workflow definitions take precedence over old command examples or historical measurements.
4. Start with a focused reproducer and nearby tests. Broaden to affected integration, race, determinism, compatibility, and existing performance gates as the risk warrants. A passing selection must actually execute the intended tests; inspect the selected names and output, and do not count `no tests to run` or a prerequisite-driven skip as a pass.

## Toolchains and module boundaries

- The compiler pin is the root [`go.mod`](../../../go.mod) `toolchain` line, currently `go1.26.9`. Its `go 1.26.6` line is the minimum language version, not the compiler pin. Record `go env GOVERSION` and `go env GOTOOLCHAIN`. CI uses [setup-go-cache](../../../.github/actions/setup-go-cache/action.yml) to install and verify the exact compiler. Do not add a workflow-level `GOTOOLCHAIN` override; it can prevent setup-go from honoring the pin.
- [`cmd/culvert-maint/go.mod`](../../../cmd/culvert-maint/go.mod) defines a separate module. Its language minimum is currently Go 1.25, but CI builds it with the root compiler pin. Root `go test ./...` does not test this module; run its checks from `cmd/culvert-maint`.
- The frontend is a separate npm tree. Read [`frontend/.node-version`](../../../frontend/.node-version), [`frontend/package.json`](../../../frontend/package.json), and [`assert-toolchain.sh`](../../../frontend/scripts/assert-toolchain.sh); current pins are Node 24.19.0 and npm 11.17.0. Its OpenAPI generator has another npm tree at `frontend/tools/openapi-gen`. Preserve both trees' ignore-scripts policy.
- Re-read pins after rebasing. If the exact toolchain or required service is unavailable, record that check as blocked or not run, with the actual reason. A different compiler's result is not the pinned result.

## Choose existing checks by ownership

Commands below run from the repository root unless stated otherwise. They are supported entry points, not a substitute for reading a changed lane's current definition.

### Root Go module and application adapters

The [`Makefile`](../../../Makefile) provides `make build` (a `CGO_ENABLED=0` root binary) and `make test` (`go test ./...`). For normal Go changes, select relevant package/test checks first, then the applicable broader checks from [Fast PR Gate](../../../.github/workflows/pr-fast-gate.yml) and [Deep PR Gate](../../../.github/workflows/pr-deep-gate.yml):

```sh
go vet ./...
go mod tidy -diff
CGO_ENABLED=0 go build -ldflags="-s -w" -o culvert .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /dev/null .
TEST_SEED=20260421 go test -count=2 -shuffle=on -timeout=20m ./...
```

The shuffled double run is the existing Deep determinism command. Capture the printed shuffle seed on failure. Formatting and lint settings come from CI and [`.golangci.yml`](../../../.golangci.yml); Fast's root lint is diff-scoped with `--new-from-rev`, not a demand to fix unrelated legacy findings. Its currently pinned golangci-lint version is v2.5.0. Use the actual review base for that comparison.

For a local full-root race/coverage diagnostic, Fast's unsharded reference uses:

```sh
TEST_SEED=20260421 go test -race -count=1 -timeout=40m -coverprofile=coverage.out -v ./...
.github/scripts/coverage-floor.sh coverage.out
```

Preserve the test command's exit status if teeing logs. Only treat the profile as complete when the producing run succeeded. This diagnostic does not reproduce every property of CI's sharded evidence or the privileged mount-point regression. A focused package profile cannot prove the global coverage contract.

### Admission and root integration

Read [`internal/admission/doc.go`](../../../internal/admission/doc.go), its scoped instructions, and [ADR-0039](../../adr/0039-admission-engine-package.md) when touching the engine or root `admission.go`, `cluster_ratelimit*`, startup/snapshot adapters, or protocol callers. Run the package's race/determinism check and relevant root integration tests:

```sh
go test -race -shuffle=on -count=2 ./internal/admission
go test -race -count=1 -run 'TestAdmissionMigration_|TestDistributedAdmission_ProductionWiring' .
go test -tags benchgate -run 'TestBenchGate_' -count=1 -timeout=10m -v . ./internal/admission
```

The root selection is a starting point, not exhaustive coverage of changed HTTP/SOCKS5, persistence, or cluster behavior. Inspect those callers and add their existing tests. The tagged command must include both root and admission: package-only success misses root gates and root-only success misses the moved rate-window gates. Test names do not establish build-tag membership; inspect each file's `//go:build` header. `TestChaos61_` admission tests need no chaos tag.

[`coverage-floor.sh`](../../../.github/scripts/coverage-floor.sh) owns the existing global and per-file contracts: global 55%, plus its complete per-file table, including 70% for root `security.go`, admission `engine.go`, and `freshness.go`. Per-file values are averages of function coverage, not package coverage. Omitted floor files must fail. Do not replace this with a new package threshold.

### Other boundaries

- Shutdown engine changes: `go test -race -count=2 -shuffle=on ./internal/shutdown`, plus affected root production-wiring tests. Read [ADR-0037](../../adr/0037-shutdown-registry-package-isolation.md) and the package boundary tests.
- Maintenance agent: from `cmd/culvert-maint`, run `go build ./...`, `go vet ./...`, and `TEST_SEED=20260421 go test -race -count=1 -timeout=10m -v ./...`. Fast's maint job also owns its tidy-drift, lint, and staticcheck checks. Packaging, update, and backup E2E are separate workflows; consult them when the changed contract requires them.
- Admin handlers/API: inspect the route/auth baseline (`d0_*_test.go`), route/metadata parity (`ui_routes_meta_test.go`, `ui_routes_meta_audit_test.go`), and enforcement/observability tests (`ui_metadata_enforcement_test.go`, `ui_metadata_divergence_test.go`) as relevant. `make api-verify` is the existing local API contract gate. Schema changes may also require `make api-breaking-check` and `make api-client-generate`; inspect their scripts and PR API-governance prerequisites first. Regeneration targets modify tracked artifacts, so review their diff.
- Frontend and its root serving/OpenAPI adapters: from `frontend`, run `npm run verify`. The canonical [`verify.sh`](../../../frontend/scripts/verify.sh) asserts toolchains, clean installs, generated types and committed-dist drift, lint/format, types, tests, build, bundle checks, licenses, and vulnerability policy. The [frontend workflow](../../../.github/workflows/frontend-verify.yml) additionally runs `sh scripts/test-drift-gate.sh`, `sh scripts/verify-determinism.sh 2`, and `sh scripts/e2e-smoke.sh` with the required Go compiler/browser prerequisites. `npm test` alone covers none of those additional contracts. Type/build regeneration can change tracked files; inspect and retain only intended output.
- MCP design-document changes: `.github/scripts/mcp-doc-predicates.sh` is the existing path-gated check. Core IP/rate admission and MCP listener fairness/execution admission are different contracts; route MCP work to its owning packages and design documents rather than substituting the admission suite.
- Workflow, dependency, container, or deployment changes: inspect the matching path classifiers and jobs before choosing checks. Include source and destination of renames. A doc extension is not proof of a docs-only lane: some documents are executable test inputs. Do not substitute a smoke test for required security, license, packaging, or release-evidence checks.

## Test isolation and failure handling

Root tests share process-global state. Restore every value a new test mutates, including related policy/object stores; `setupProxyTest` resets at test start, not at cleanup. Respect `t.Cleanup`'s LIFO order. Test bounded audit rings by uniquely matching entry content, not length growth. Shuffled repeated runs catch leaks that an isolated reproducer can miss.

Keep the original failure, command, seed, and relevant log. Investigate whether it is introduced, pre-existing, environmental, or unresolved; support that classification with evidence. A later green retry does not erase a race, failed shard, missing coverage, or flaky result. Do not lower floors, add exclusions, update snapshots blindly, or weaken assertions just to make a gate green.

## Instruction-routing changes

For a nontrivial guidance change, verify references and anchors, applicable root/scoped routes, native skill paths and frontmatter, wrapper-to-canonical-document reads, and that history is not eagerly imported. A migration must also run its documented preservation/reconstruction and load-budget checks. Use realistic scenarios spanning a root adapter, package-local change, unrelated trivial edit, and a safe review counterexample. Obtain a fresh independent review of routing, conflicting authority, and scope.

Structural checks do not prove actual client loading. When exercising clients, record client/version, model/settings, working directory, revisions, and observed reads/decisions; test positive and negative skill triggers. If a client or hosted review is unavailable, label it not run. Do not claim behavioral improvement, token savings, or universal compatibility from link checks alone.

## Report verification accurately

Report the tested revision, scope, exact commands/toolchains/tags, results, relevant seeds/logs, and anything skipped, blocked, or still running. Distinguish focused tests, broad local checks, client-behavior trials, and CI results.

The required aggregate check names are `✅ Fast PR Gate — APPROVED` and `✅ Deep PR Gate — APPROVED`. Inspect their verdicts and triggered dependencies for the current PR revision, not an old run. Fast's race path uses the shared [sharded workflow](../../../.github/workflows/qa-race-shards.yml), including completeness checks and the required privileged regression; coverage floors consume its merged artifact. Deep's path-gated jobs may legitimately skip. A single green job, a pass-through QA/Security PR shell, or a local package pass is not aggregate CI approval. Readiness to merge and permission to merge or publish remain separate decisions.
