# Culvert Technical Debt Register

> **Owner:** Chief Engineering Advisor · **Status:** Living · **Last review:** 2026-06-28
>
> Debt = a structural shortcut that raises the cost of future change. Runtime/supply-chain hazards
> live in the [Technical Risk Register](./TECHNICAL-RISK-REGISTER.md). Each item is framed as
> **principal** (the structural problem) and **interest** (the recurring cost you pay until it's
> fixed). Evidence is `file:line`. `HV` = hand-verified on the review date.

| ID | Sev | Title | Principal location |
|---|---|---|---|
| DEBT-001 | HIGH | Flat `package main` — no compiler-enforced boundaries | all 152 root `.go` files; see ADR-0002 |
| DEBT-002 | ✅ CLOSED | `handleRequest` was ~497 lines / cyclo 73 on the hottest security path | `proxy.go` — decomposed 2026-06-28 |
| DEBT-003 | MEDIUM | God-files (4 over 1,800 LOC) | `main.go`, `store.go`, `controlplane.go`, `proxy.go` |
| DEBT-004 | MEDIUM | `configBackup` god-struct with 3 divergent memberships | `ui_policy.go:736`, `configversion.go` |
| DEBT-005 | MEDIUM | `main.go` is a 30-`init*` hand-wired DI container | `main.go` (30 `initX` funcs) |
| DEBT-006 | MEDIUM | `ConfigSnapshot` (33-field) CP→DP god-DTO | `controlplane.go:1508 applyConfigSnapshot` |
| DEBT-007 | MEDIUM | No end-to-end SSL-inspection MITM data-path test | (absence) `proxy.go handleConnect` inspect branch |
| DEBT-008 | LOW | Two parallel update mechanisms coexist | `updater/` + `release_dispatch*.go` |
| DEBT-009 | LOW | Three durability layers for config can drift | `config.go`, `admin_settings.go`, `configversion.go` |
| DEBT-010 | LOW | Coverage floor 55% (doc says 60%); delta gate non-blocking | `security-release-gate.yml:344`; `code-review.yml:96` |

---

## DEBT-001 — Flat `package main` · HIGH
- **Principal:** All 152 root source files share one namespace (1,950 top-level funcs, 187 exported
  types, ~359 package-level vars). Core runtime state (`cfg`, `bl`, `policyStore`, `ts`, …) are
  mutable globals reachable by both the proxy hot path and the admin write path; isolation is by
  mutex *convention*, not by language.
- **Interest paid per change:** whole-binary blast radius; high onboarding cost; a large data-race
  surface already evidenced by dedicated regression tests (`upstream_transport_race_test.go`,
  `controlplane_dp_conn_race_test.go`) and a hard CLAUDE.md rule about `upstreamTransport`.
- **Proof it's payable:** `cmd/culvert-maint/internal/{server,ops,runner,auth,config,audit,health}`
  already uses proper packages — the team can do this; it just hasn't back-ported it.
- **Direction:** ADR-0002. Incremental leaf-cluster extraction into `internal/`. **No rewrite.**

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
- `main.go` (2,367), `store.go` (2,313, ≥5 unrelated stores behind one file's locks),
  `controlplane.go` (2,047), `proxy.go` (1,802). Merge-conflict magnets; exceed reviewer working
  memory. Natural targets for the ADR-0002 extraction. **Complexity L (staged).**

## DEBT-004 — `configBackup` god-struct · MEDIUM
- One 25-field struct (`ui_policy.go:736`) serves export/import, version rollback, and restart
  durability — each with a *different* intended field subset encoded only in prose (CLAUDE.md
  "Finding 10.3"). `RateLimitExempt` is already half-migrated, so the surfaces are out of sync.
- **Interest:** adding a config field means remembering to wire it into N hand-curated functions
  across 3 files. **Recommendation:** explicit per-surface types or a generated membership table.
  **Complexity M.**

## DEBT-005 — Hand-wired 30-init DI in `main.go` · MEDIUM
- Startup is 30 `init*` functions invoked in sequence with cross-dependencies expressed only by
  call order. The "startup slices" effort has extracted ~11; the MEDIUM-risk list
  (`initBlocklist`, `initObservability`, `initConnAndRateLimit`) remains. **Interest:** a reordered
  init silently breaks a dependency. Continue the existing slicing pattern. **Complexity M.**

## DEBT-006 — `ConfigSnapshot` god-DTO · MEDIUM
- A 33-field struct is the CP→DP contract, applied by a 206-line `applyConfigSnapshot`
  (`controlplane.go:1508`). Every cluster-aware feature must thread a field through both. High
  coupling between unrelated subsystems and the distribution layer. **Complexity M.**

## DEBT-007 — No e2e MITM test · MEDIUM
- The flagship decrypt→scan→re-encrypt→block relay is tested only in pieces (cert signing, TLS
  handshake, EICAR/YARA at the scanner level). No test drives a real TLS client through the
  inspecting CONNECT proxy. A regression in the assembled path passes CI. **Recommendation:** one
  listener-level test through `handleConnect`'s inspect branch. **Complexity M.** (Cross-listed:
  this is debt with a latent risk.)

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

## DEBT-010 — Coverage floor / delta gate · LOW
- Global floor is 55% (`security-release-gate.yml:344`) while a comment says 60%
  (`code-review.yml:91`) — doc/impl drift; the delta gate is `continue-on-error`
  (`code-review.yml:96`) so it cannot block. **Recommendation:** reconcile the number and make the
  delta gate blocking on a real regression. **Complexity S.**

---

### Review log
- **2026-06-28** — Register created from the baseline audit. DEBT-002 hand-verified. ADR-0002 opened
  to govern the DEBT-001/002/003 decomposition direction.
