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
| DEBT-003 | ✅ CLOSED | God-files split (2026-07-04): `controlplane.go` 2,240→341, `proxy.go` 1,901→727, `main.go` 1,990→1,211. No non-generated `.go` file > ~1,300 LOC | — |
| DEBT-004 | MEDIUM | `configBackup` god-struct with 3 divergent memberships | `ui_policy.go:736`, `configversion.go` |
| DEBT-005 | ✅ CLOSED | `main.go` was a 30-`init*` hand-wired DI container | startup-slice program complete (24 slices, contract-tested) |
| DEBT-006 | ✅ CLOSED | `ConfigSnapshot` (34-field) CP→DP god-DTO | walled by capture/apply/redaction/wire-wipe parity (2026-07-05); `config_surfaces_test.go` |
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
  **ADR-0002 is COMPLETE**: `internal/` holds **45 packages** (40 extracted engines — `upstream`
  added 2026-07-04 under the standing recorded-design rule — + 4 seams +
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

## DEBT-003 — God-files · ✅ CLOSED 2026-07-04
- **`controlplane.go` SPLIT (2026-07-04):** the flagged next target — 2,240 LOC, the one file
  *growing* (every cluster feature landed there) — decomposed into five cohesive same-package
  files along the CP/DP boundary the file's own header described: `controlplane.go` (341 — service
  def + the CP-side rate-limit/revocation/audit aggregators + enrollment rate-limiting),
  `controlplane_snapshot.go` (678 — ConfigSnapshot/ConfigStore + the applyConfigSnapshot / DP
  last-good / CurrentConfigSnapshot lifecycle), `controlplane_server.go` (677 — CP gRPC server +
  all RPC handlers), `controlplane_client.go` (439 — DP gRPC client + poll/gossip loops),
  `controlplane_tls.go` (147 — shared mTLS + cert-pool rebuild). **Pure move, zero behaviour
  change:** verified by an identical 102-declaration set before/after (no add/loss/dup);
  build/vet/gofmt clean; controlplane-adjacent suites green under `-race`. No file over 1,800 LOC
  references `controlplane.go` any more.
- **`proxy.go` SPLIT (2026-07-04):** the flagged next candidate — 1,901 LOC on the hot path —
  decomposed into four cohesive same-package files along the handler boundary: `proxy.go` (727 —
  the request-dispatch pipeline `handleRequest` + its DEBT-002 helpers, policy-action state,
  `scrubForwardedHeaders`, `sanitizeLog`; now the composition root only), `proxy_tunnel.go` (796 —
  CONNECT/WebSocket/tunnel relay: `relayBufPool`, `relayCounted`/`bidiRelayCounted`,
  `handleTunnel`/`handleTunnelBypass`/`handleTunnelInspect`, `handleWebSocket`, `applyUpstreamProxy`,
  hop-by-hop stripping), `proxy_http.go` (209 — plain-HTTP forward `handleHTTP` + request-body
  limits + SSL-inspect stall detection), `proxy_portal.go` (197 — captive/SSO portal resolution,
  proxy-auth parsing, safe-redirect validation). **Pure move, zero behaviour change:** verified by
  an identical 52-declaration set before/after (no add/loss/dup); build/vet/gofmt clean; the hot-path
  race suite (Proxy|Tunnel|WebSocket|Relay|HandleHTTP|HandleRequest|Mitm|Inspect|Policy|Auth|Scrub|
  HopHeader|Portal|SSO|Bypass) green under `-race`; `BenchmarkPolicyEvaluate_*` allocs/op unchanged.
- **`main.go` SPLIT (2026-07-04):** the last god-file — 1,990 LOC — decomposed into four cohesive
  same-package files along the lifecycle boundary: `main.go` (1,211 — composition root: entrypoint,
  flag parsing, the 24 `init*` startup shims, proxy-server wiring, signal handling), `main_shutdown.go`
  (241 — the graceful-shutdown sequence + shutdown-order constants + early/late hook registration +
  `drainActiveTunnels`), `healthcheck.go` (159 — `handleHealth`/`handleReady`/`configSnapshotValidatorOK`),
  `dp_enrollment.go` (385 — the DP-side enrollment client + `startDataPlane` + DP cert-renewal loop,
  distinct from the CP-side `enrollment.go`). **Pure move, zero behaviour change:** identical
  86-declaration set before/after (modulo one gofmt comment realignment); build/vet/gofmt clean;
  the enrollment/control-plane/health suites green.
- **DEBT-003 CLOSED.** All three flagged god-files split; no non-generated `.go` file exceeds ~1,300 LOC.
  **Follow-up (RESOLVED 2026-07-05):** the diff-scoped golangci gate had re-surfaced ~19 legacy
  findings on the *moved* lines (grandfathered under `--new-from-rev` while they sat in the origin
  files). Trivial ones were fixed in place with the split (errcheck `//nolint` explanations,
  `rangeValCopy` → index-range, `net.Listen` → `ListenConfig.Listen`, named results, unused-param
  `_`). The four handler-complexity findings (`handleHTTP` gocognit/cyclop/funlen, the `nestif`
  blocks in `proxy_tunnel.go`/`proxy_http.go`) were then retired by a dedicated
  **handler-decomposition pass** (deliberately its own change, not bundled into the mechanical
  split): `handleHTTP` → `blockedByResponseHeaders`/`serveHTTPFileBlock`/`scanHTTPResponseBody`;
  `handleTunnelInspect` → `inspectFileBlocked`/`inspectCDBlocked`/`scanInspectBody`/
  `inspectMagicBlock`. Semantic-equivalence refactor (not a pure move) — gated by a 3× pre-push
  review (equivalence, correctness, adversarial red-team; all clean; the one review note — a
  double-read of `globalRemoteScanner.Enabled()` — fixed by hoisting a single read), the De Morgan
  scan-guard truth-tabled, hot-path race suite + MITM e2e green, allocs/op unchanged. **All four
  complexity `//nolint` suppressions removed**; diff-scoped lint is 0 issues.

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

## DEBT-006 — `ConfigSnapshot` god-DTO · ✅ CLOSED 2026-07-05 (walled, not restructured)
- **Was:** a 34-field struct is the CP→DP contract, threaded by hand through FOUR places nothing
  forced to agree — the struct (+ `omitempty` choice), `CurrentConfigSnapshot` (capture),
  `validateConfigSnapshot` (H5 caps), and the `applySnapshot*` fan-out. A field added to
  struct+capture but not `apply` = a silently-unsynced setting; not `validate` = an uncapped
  memory-DoS; a capture/apply empty-semantics mismatch = a delete that doesn't replicate. All
  silent until a cluster misbehaves.
- **Resolution — parity wall (mirrors DEBT-004), design-reviewed then shipped in 3 slices:** the DTO
  is NOT restructured (it crosses the wire + ADR-0005 fence-epoch boundary; compat is frozen).
  Instead `config_surfaces_test.go` now enforces, via reflection + AST over `config_surfaces.go`:
  - **capture parity** — every field assigned in `CurrentConfigSnapshot` ∪ `ConfigStore.Update`;
  - **apply parity** — every field with a DP effect read in `applySnapshot*`/`fetchAndApply`, keyed
    on `Apply != semNA || AppliesOnDP` so `Epoch` (the `dpObserveEpoch` fence ratchet, `kindMeta`)
    is verified — the design-review gap where mislabeling a fence field would exempt it;
  - **redaction parity** — every `Sensitive` synced field zeroed in the `!callerIsEnrolledNode`
    GetConfig block (the `SessionHMAC`/`IdPProfiles` secret-leak guard);
  - **wire-wipe parity** — `WireWipeCapable` ⇔ no `omitempty` (only `RateLimitExempt` propagates an
    empty-slice clear; the other 12 `semNilSkipEmptyWipe` slices keep `omitempty`, so their
    `[]`-wipe is intentionally wire-dead — pinned, not surprising).
  Each wall proven to bite by negative test. **Known-unclosed, recorded not walled:** wrong-owner
  capture/apply wiring, `applySnapshot*` ordering, cap magnitude. Authority + audit trail:
  `roadmap/DEBT-006-configsnapshot-parity-plan.md` (incl. the 5 design-review corrections). Adding
  a synced field now fails CI until it is registered, captured, applied, capped, redacted (if
  secret), and wire-consistent.

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
