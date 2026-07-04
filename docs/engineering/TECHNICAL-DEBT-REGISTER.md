# Culvert Technical Debt Register

> **Owner:** Chief Engineering Advisor · **Status:** Living · **Last review:** 2026-07-04 (drift sync)
>
> Debt = a structural shortcut that raises the cost of future change. Runtime/supply-chain hazards
> live in the [Technical Risk Register](./TECHNICAL-RISK-REGISTER.md). Each item is framed as
> **principal** (the structural problem) and **interest** (the recurring cost you pay until it's
> fixed). Evidence is `file:line`. `HV` = hand-verified on the review date.

| ID | Sev | Title | Principal location |
|---|---|---|---|
| DEBT-001 | MEDIUM ↓ | Flat root namespace — engines extracted (ADR-0002 COMPLETE, 44 pkgs), root shims/globals remain | 172 root `.go` files (non-test) |
| DEBT-002 | ✅ CLOSED | `handleRequest` was ~497 lines / cyclo 73 on the hottest security path | `proxy.go` — decomposed 2026-06-28 |
| DEBT-003 | MEDIUM | God-files (3 over 1,800 LOC; `store.go` halved by extraction) | `controlplane.go` (2,236), `main.go` (1,990), `proxy.go` (1,901) |
| DEBT-004 | MEDIUM | `configBackup` god-struct with 3 divergent memberships | `ui_policy.go:736`, `configversion.go` |
| DEBT-005 | ✅ CLOSED | `main.go` was a 30-`init*` hand-wired DI container | startup-slice program complete (24 slices, contract-tested) |
| DEBT-006 | MEDIUM | `ConfigSnapshot` (33-field) CP→DP god-DTO | `controlplane.go:1508 applyConfigSnapshot` |
| DEBT-007 | ✅ CLOSED | No end-to-end SSL-inspection MITM data-path test | `mitm_inspect_e2e_test.go` — verified 2026-07-04 |
| DEBT-008 | LOW | Two parallel update mechanisms coexist | `updater/` + `release_dispatch*.go` |
| DEBT-009 | LOW | Three durability layers for config can drift | `config.go`, `admin_settings.go`, `configversion.go` |
| DEBT-010 | ✅ CLOSED | Coverage floor 55% (doc said 60%); delta gate non-blocking | resolved in tree by CI-REDESIGN step 7 — verified 2026-07-04 |

---

## DEBT-001 — Flat root namespace · HIGH → MEDIUM (2026-07-04)
- **Principal:** All 152 root source files share one namespace (1,950 top-level funcs, 187 exported
  types, ~359 package-level vars). Core runtime state (`cfg`, `bl`, `policyStore`, `ts`, …) are
  mutable globals reachable by both the proxy hot path and the admin write path; isolation is by
  mutex *convention*, not by language.
- **Interest paid per change:** whole-binary blast radius; high onboarding cost; a large data-race
  surface already evidenced by dedicated regression tests (`upstream_transport_race_test.go`,
  `controlplane_dp_conn_race_test.go`) and a hard CLAUDE.md rule about `upstreamTransport`.
- **Proof it's payable:** `cmd/culvert-maint/internal/{server,ops,runner,auth,config,audit,health}`
  already uses proper packages — the team can do this; it just hasn't back-ported it.
- **Direction:** ADR-0002 (Accepted). Incremental leaf-cluster extraction into `internal/`. **No rewrite.**
- **Progress (2026-06-28):** **three leaves + the shared seam shipped** — `internal/totp`,
  `internal/geoip` (ADR-0002 option F), the `internal/obs`+`internal/fileutil` seam (ADR-0003), and
  `internal/fileblock` (the file-type blocking engine, unblocked by the seam). All validated green
  (build/vet/test/-race/lint/cycle); `fileblock` additionally passed a `-count=2 -shuffle` determinism
  check on its integration-test isolation rewrites. `fileblock` was ~2× the mapped scope (test
  entanglement) and required one method beyond the approved export list (`FileProfileStore.SetPath`);
  recorded honestly in ADR-0002.
  Mapping `internal/scan` first showed it is a **hub** (logging/alerting/file/host coupling;
  ~20-file inbound) — recorded in ADR-0002. **Sequencing learned:** true leaves first (`totp`,
  `geoip` done), then a shared **logging + `atomicWriteFile` seam** (the gating prerequisite for
  `fileblock` and `scan`), then hubs. Score impact: two small leaves out of ~58K LOC do **not** yet
  move the Architecture/Maintainability score — the principal (flat namespace, ~359 globals) is
  essentially unchanged; this is proof-of-method (repeatable, safe boundaries), not a dent yet.
  **Recommended next foundational step:** design the shared seam layer rather than chase more leaves.
- **Progress (2026-07-04 drift sync, tree-verified):** the June snapshot above is history —
  **ADR-0002 is COMPLETE**: `internal/` holds **44 packages** (39 extracted engines + 4 seams +
  `halease`), engines own logic/state/persistence, and `main` is reduced to composition roots,
  shims, and aliases (per `CLAUDE.md`, corroborated by `ls internal`). `store.go` halved
  (2,313 → 1,171 LOC). What REMAINS of the principal: 172 root non-test `.go` files still share
  one namespace, and the shim/alias globals still bridge into the engines — the blast-radius and
  race-surface interest is much reduced but not zero. **Severity HIGH → MEDIUM.** Direction per
  `CLAUDE.md`: new engines go to `internal/` with a recorded design; do not re-inline shipped ones.

## DEBT-002 — `handleRequest` oversized · ✅ CLOSED 2026-06-28
- **Was:** the single most-exercised security function carried the entire auth + content-block +
  policy + dispatch + telemetry pipeline — ~497 lines, gocyclo **73**, behind a
  `//nolint:gocognit,cyclop,funlen` suppression (the lint gate was not protecting the code that
  most needed it; auth-bypass / SSRF-ordering bugs hide in nested branching).
- **Resolution — behaviour-preserving, test-guarded extraction (6 commits, each validated with
  build + `go vet` + full root-package suite + `-race` on the hot path + gocyclo):**
  | helper | gocyclo | suppression |
  |---|---|---|
  | `resolveRequestAuth` (Stage-1 adaptive auth) | 29 | retained — inherent, now isolated/testable |
  | `applyPolicyDecision` (drop/block/redirect/allow/default) | 15 | retains `funlen`+`nestif` (82-line switch) |
  | `preDispatchBlocked` (blocklist/threat/plugin/file) | 11 | **none** |
  | `recordRequestTelemetry` (latency + OTLP) | 6 | **none** |
  | `resolveSSLAction` | 5 | **none** |
  | `setupRequestTracing` | 3 | **none** |
  | `trackDestinationCountry` | 2 | **none** |
- **Result (evidence):** `handleRequest` gocyclo **73 → 11**, and **its `//nolint` suppression was
  removed entirely**. Authoritative `golangci-lint v2.5.0 --enable=cyclop,funlen,gocognit,nestif`
  reports **zero findings** for `handleRequest`. The 453 auth/proxy/policy tests (which drive
  `handleRequest` directly via `httptest`) pass unchanged — behaviour preserved.
- **Honest note:** extraction *relocated* the inherent auth/policy complexity into two isolated,
  independently-testable units that keep justified suppressions; it did not erase that complexity.
  The win: the **dispatcher is now readable and lint-clean**, and each stage is testable alone.
- **Follow-on (not DEBT-002):** the remaining pre-existing complexity suppressions in `proxy.go`
  (`handleHTTP` gocognit 32, `handleWebSocket` funlen, `handleTunnelInspect` 57) are separate
  functions, out of scope here; candidates for a future targeted pass if prioritised.

## DEBT-003 — God-files · MEDIUM
- **2026-07-04 (re-measured):** `controlplane.go` (2,236 — *grew* since June, now the largest),
  `main.go` (1,990, was 2,367), `proxy.go` (1,901, roughly flat), `store.go` (**1,171**, was
  2,313 — halved by the ADR-0002 blocklist/audit/reqlog extractions). Merge-conflict magnets;
  exceed reviewer working memory. `controlplane.go` is the one moving in the wrong direction —
  every cluster feature lands there (same force as DEBT-006); it should be the next split target.
  **Complexity L (staged).**

## DEBT-004 — `configBackup` god-struct · MEDIUM
- One 25-field struct (`ui_policy.go:736`) serves export/import, version rollback, and restart
  durability — each with a *different* intended field subset encoded only in prose (CLAUDE.md
  "Finding 10.3"). `RateLimitExempt` is already half-migrated, so the surfaces are out of sync.
- **Interest:** adding a config field means remembering to wire it into N hand-curated functions
  across 3 files. **Recommendation:** explicit per-surface types or a generated membership table.
  **Complexity M.**

## DEBT-005 — Hand-wired 30-init DI in `main.go` · ✅ CLOSED 2026-07-04
- **Was:** startup was 30 `init*` functions invoked in sequence with cross-dependencies expressed
  only by call order; ~11 slices extracted at the June review.
- **Resolution:** the startup-slice program is **COMPLETE — 24 slices shipped** (SAFE pilots +
  MEDIUM tranche + final sweep, per `CLAUDE.md`). Every fat `init*` is now a thin shim over a
  pure resolver + loader with per-slice tests; `startup_slice_contract_test.go` pins the
  convention (purity, determinism, no-fc-mutation) for every future slice.
- **Honest residual:** the call-*order* sequencing in `main()` still exists — but each step is
  now a thin, contract-tested shim rather than a fat opaque function, which was the interest this
  entry was charging. `startDataPlane` is deliberately not a slice (runtime wiring, not config
  resolution — recorded decision). Residual ordering risk is accepted as ordinary structure.

## DEBT-006 — `ConfigSnapshot` god-DTO · MEDIUM
- A 33-field struct is the CP→DP contract, applied by a 206-line `applyConfigSnapshot`
  (`controlplane.go:1508`). Every cluster-aware feature must thread a field through both. High
  coupling between unrelated subsystems and the distribution layer. **Complexity M.**

## DEBT-007 — No e2e MITM test · ✅ CLOSED 2026-07-04 (verified)
- **Was:** the flagship decrypt→scan→re-encrypt→block relay was tested only in pieces; no test
  drove a real TLS client through the inspecting CONNECT proxy.
- **Resolution (hand-verified 2026-07-04):** `mitm_inspect_e2e_test.go` drives a real TLS client
  through the inspect path with the **trust-asymmetry proof** — a client trusting ONLY the proxy
  CA completes the handshake on the inspect path and FAILS on the bypass path, which proves the
  MITM actually happened rather than merely that a request succeeded. Also covers identity-header
  scrubbing on the decrypted inner request, fail-closed on bad upstream cert, block-before-tunnel,
  large-body integrity, and leaf-cache hit/miss + rotation. Hermetic (in-process TLS upstream,
  in-memory CA, loopback-only). This is exactly the listener-level test this entry asked for.

## DEBT-008 — Two update mechanisms · LOW → **active removal**
- Legacy `updater/` sidecar and the new release-catalog dispatch both ship. Documented as a
  deliberate transition (the updater is the fallback until catalog-driven update succeeds in prod).
  **Track to actually remove the fallback** once superseded; don't let it become permanent.
- **2026-06-28:** This is now also the resolution path for **RISK-ACC-1** — the `updater/` module's
  `docker/docker v28.5.2` carries all 5 of the repo's open Dependabot alerts (2 HIGH + 1 MEDIUM
  Trivy-confirmed, 2 more in `.trivyignore`; no upstream fix). The maintainer is actively removing
  the updater. Removing `updater/go.mod` deletes the entire vulnerable dependency tree and closes
  all 5 alerts at once — the correct fix, vs. bumping deps in soon-deleted code. **Priority raised
  in practice** by the alert pressure, even though the structural debt itself is LOW.

## DEBT-009 — Three config durability layers · LOW
- CLI flags / YAML / `admin_settings.json` can hold different values for the same setting; which
  wins is non-obvious. Documented but operationally confusing. **Recommendation:** a single
  precedence doc + a diagnostics endpoint that shows effective-vs-source for each setting.

## DEBT-010 — Coverage floor / delta gate · ✅ CLOSED 2026-07-04 (drift sync)
- **Was:** global floor 55% while a `code-review.yml` comment said 60%; the coverage delta gate
  was `continue-on-error` and could not block.
- **Found already resolved in the tree:** the delta gate was **retired** by CI-REDESIGN step 7
  ("Superseded by the Fast PR Gate's single `-race` run") — both coverage contracts (55% global +
  per-file floors) are now enforced by ONE blocking script, `.github/scripts/coverage-floor.sh`
  (`GLOBAL_FLOOR=55` + a per-file floor table; the old 60% comment is gone with the retired job).
  Single enforcement point, no doc/impl split — the debt's premise no longer exists.

---

### Review log
- **2026-06-28** — Register created from the baseline audit. DEBT-002 hand-verified. ADR-0002 opened
  to govern the DEBT-001/002/003 decomposition direction.
- **2026-07-04** — **Drift sync (tree-verified, not prose-trusted).** DEBT-005 CLOSED (startup-slice
  program complete: 24 slices + contract test). DEBT-007 CLOSED (`mitm_inspect_e2e_test.go`
  hand-read: real TLS client, trust-asymmetry proof, fail-closed + scrub + block-before-tunnel).
  DEBT-001 HIGH → MEDIUM (ADR-0002 COMPLETE: 44 `internal/` packages; residual = 172-file flat
  root + shim globals). DEBT-003 re-measured: `store.go` halved to 1,171; `controlplane.go` grew
  to 2,236 and is now the largest file — flagged as next split target. DEBT-004/006/008/009/010
  unchanged and still real.
