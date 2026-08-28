# Culvert Technical Debt Register

> **Owner:** Chief Engineering Advisor · **Status:** Living · **Last review:** 2026-07-05 (drift sync)
>
> Debt = a structural shortcut that raises the cost of future change. Runtime/supply-chain hazards
> live in the [Technical Risk Register](./TECHNICAL-RISK-REGISTER.md). Each item is framed as
> **principal** (the structural problem) and **interest** (the recurring cost you pay until it's
> fixed). Evidence is `file:line`. `HV` = hand-verified on the review date.

| ID | Sev | Title | Principal location |
|---|---|---|---|
| DEBT-001 | MEDIUM ↓ | Flat root namespace — engines extracted (ADR-0002 COMPLETE, 48 pkgs), root shims/globals remain | 184 root `.go` files (non-test) — ↑ from the DEBT-003 god-file splits (cohesion up, not new debt) |
| DEBT-002 | ✅ CLOSED | `handleRequest` was ~497 lines / cyclo 73 on the hottest security path | `proxy.go` — decomposed 2026-06-28 |
| DEBT-003 | ✅ CLOSED | God-files split (2026-07-04): `controlplane.go` 2,240→341, `proxy.go` 1,901→727, `main.go` 1,990→1,211. No non-generated `.go` file > ~1,300 LOC | — |
| DEBT-004 | ✅ CLOSED | `configBackup` god-struct with 3 divergent memberships | walled by the `config_surfaces.go` registry + `config_surfaces_test.go` reflection parity (the "membership table" this item recommended) |
| DEBT-005 | ✅ CLOSED | `main.go` was a 30-`init*` hand-wired DI container | startup-slice program complete (24 slices, contract-tested) |
| DEBT-006 | ✅ CLOSED | `ConfigSnapshot` (34-field) CP→DP god-DTO | walled by capture/apply/redaction/wire-wipe parity (2026-07-05); `config_surfaces_test.go` |
| DEBT-007 | ✅ CLOSED | No end-to-end SSL-inspection MITM data-path test | `mitm_inspect_e2e_test.go` — verified 2026-07-04 |
| DEBT-008 | ✅ CLOSED | Two parallel update mechanisms coexisted | legacy `updater/` removed 2026-07-11; `release_dispatch*.go` + maintenance agent is the sole path |
| DEBT-009 | LOW ↓ | Three durability layers for config can drift — ownership now registry-declared; effective-config visibility remains | `config.go`, `admin_settings.go`, `configversion.go` |
| DEBT-010 | ✅ CLOSED | Coverage floor 55% (doc said 60%); delta gate non-blocking | resolved in tree by CI-REDESIGN step 7 — verified 2026-07-04 |
| DEBT-011 | 🟡 PARTIAL | MCP has no anti-drift wall: designed-and-documented controls that the request path never invokes | Two walls landed 2026-08-24/25 — `internal/mcp/runtime/limits_ownership_test.go` (every Limits bound must DECLARE an enforcement owner; type-aware via go/types, so a same-named accessor on a different type cannot satisfy a row) and `mcp_execution_posture_test.go` (the disabled-execution posture is three ABSENCES no unit test observes; now executable facts). `internal/mcpacceptance/criterion_ids_test.go` applies the same idea to acceptance criterion ids in both directions. The class is NOT fully walled: policy fields, event fields and inspection controls have no equivalent ownership registry yet. |
| DEBT-012 | ✅ CLOSED | Five `runtime.Limits` knobs remain validated-but-unenforced at the MCP runtime layer | RESOLVED 2026-08-24: every bound now carries a declared enforcement status — `enforcedHere`, `delegated` (with the owning control named) or `reserved` (with a linked decision). `AdmissionBudget`, `MaxObservations` and `CleanupPerOp` are recorded as `reserved`, and the wall fails the build if a reserved bound is ever silently read, so none can quietly become load-bearing. `AdmissionBudget` remains tied to the still-open RISK-026. |
| DEBT-013 | 🟡 PARTIAL | MCP registry existence still leaks to an authenticated-shaped caller; upstream `MaxConnsPerServer` is per-call | Enumeration half CLOSED 2026-08-24 (OVN-08): `resolveServer` no longer consults the registry, so server identity is resolved only AFTER authentication and an invalid credential can no longer distinguish a known from an unknown server id. The per-call transport half stands and is now a recorded trade-off rather than an oversight — a per-call `http.Transport` is what makes cross-server connection, TLS-identity and credential inheritance structurally impossible, at the cost of a TLS handshake per call. Revisit only with a per-server transport whose isolation is proven. |

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
  (2,313 → 1,171 LOC). What REMAINS of the principal: 184 root non-test `.go` files still share
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

## DEBT-004 — `configBackup` god-struct · ✅ CLOSED 2026-07-05 (walled)
- **Was:** one struct (`ui_policy.go`) served export/import, version rollback, and restart
  durability — each with a *different* intended field subset encoded only in prose (CLAUDE.md
  "Finding 10.3"), so a field addition had to be hand-wired into N functions across 3 files and
  `RateLimitExempt` had already drifted half-migrated.
- **Resolution:** the recommended "generated membership table" shipped as the
  `config_surfaces.go` registry (its header comment explicitly names DEBT-004/006/009 as its
  charge). `config_surfaces_test.go` enforces it via reflection: forward/reverse parity (every
  field claimed by exactly one row, every binding resolves to a real field), diff-nil-guard ⇔
  apply-nil-skip parity, per-field diff coverage, Sensitive invariants, and a full-surface rollback
  round-trip. Adding a config field now fails CI until it is registered on the correct surfaces —
  the drift is a compile-adjacent test failure, not a prose hope. The CP→DP `ConfigSnapshot`
  surface was walled the same way under DEBT-006 (capture/apply/redaction/wire-wipe/owner parity).

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

## DEBT-008 — Two update mechanisms · ✅ CLOSED 2026-07-11 (updater removed)
- Legacy `updater/` sidecar and the new release-catalog dispatch both shipped. The transition is
  complete: catalog-driven update via the maintenance agent (Release Management → agent
  `/v1/upgrades/apply`) was proven E2E, and the legacy path was fully removed — `updater/` module,
  `Dockerfile.updater`, the compose sidecars, `update.go`/`update_cluster.go`, the 11 `/api/update/*`
  routes, the Updates admin-UI panel, and the `TriggerUpdate` RPC are all deleted. The maintenance
  agent is now the sole day-2 update path.
- **This also closes RISK-ACC-1.** Deleting `updater/go.mod` removed the entire `docker/docker`
  dependency tree that carried all 5 open Dependabot alerts; nothing in the remaining tree imports
  `docker/docker`, and the `.trivyignore` masks were retired with it.

## DEBT-009 — Three config durability layers · LOW ↓ (partially addressed)
- CLI flags / YAML / `admin_settings.json` can hold different values for the same setting; which
  wins is non-obvious. Documented but operationally confusing.
- **Partial (2026-07-05):** the *membership/ownership* half is now declared — the
  `config_surfaces.go` registry records which surface owns each setting (`AdminDurable`/`Rollback`
  flags + the `…Saved` sentinel semantics), and DEBT-004's parity tests enforce it. What REMAINS is
  the *precedence-visibility* half: no diagnostics endpoint shows effective-vs-source per setting at
  runtime, so an operator still can't see which layer won. **Recommendation (residual):** a single
  precedence doc + an effective-config diagnostics endpoint. **Complexity S.**

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

---

## DEBT-011 — MCP has no anti-drift wall · MEDIUM (2026-08-24)
- **Principal:** Culvert walls its cross-cutting contracts with executable parity tests —
  `uiRoutes` C1 forward/reverse parity for admin routes, `config_surfaces_test.go` reflection
  parity for config membership. `internal/mcp` has no equivalent. The consequence showed up as a
  *pattern*, not a one-off: six of the fifteen findings in the 2026-08-24 backend review were the
  same shape — a control designed, documented, validated at construction, unit-tested in
  isolation, and **never invoked by the request path**.
  - `RequestDeadline` bounded only admission (`ServeHTTP` built the ctx, used it for `admit()`,
    then cancelled it).
  - `AuthConcurrency`, `DPoPConcurrency`, `AdmissionBudget`, `MaxObservations`, `CleanupPerOp`
    had zero enforcement call sites.
  - `protocol.Adapter` / `AdapterFor` — the documented boundary keeping version out of downstream
    code — was declared and never called.
  - `mcperr.ReasonRequestDeadlineExceeded` was mapped into the rollout hard-failure table and
    never produced by any code path.
- **Interest paid per change:** every review has to re-derive reachability from the composition
  root by hand (this one did, for every dependency and every rollout mode), and package-level
  tests provide false assurance — they pass whether or not the control is wired.
- **Recommended shape:** a `mcp_surfaces_test.go` in the spirit of `config_surfaces_test.go`,
  declaring for each `Limits` field and each declared seam **where** it is enforced/invoked, and
  failing when a declared row has no call site. The three structural tests added by the
  2026-08-24 review (`TestContext_NoDetachedContextInTheRequestPath`,
  `TestSecurity_GuardedSingletonSetIsComplete`,
  `TestVersionAdapter_RequestPathInvokesTheSeam`) are the pattern, applied ad hoc; the wall
  generalizes them.
- **Evidence:** `docs/engineering/security-reviews/2026-08-24-mcp-backend-full-review.md` §1, §4.

## DEBT-012 — Validated-but-unenforced MCP limit knobs · LOW (2026-08-24)
- **Principal:** After `AuthConcurrency` and `DPoPConcurrency` were wired, five
  `runtime.Limits` fields remain validated, ceiling-checked, accessor-exposed and unread:
  `MaxObservations`, `CleanupPerOp`, `HandshakeTimeout`, `MaxOutstanding`, `MaxResponseBytes`.
  None is currently a hole — in-flight observations are bounded transitively by `MaxConcurrent`
  (the sink call is synchronous), the sweep is bounded by the live session set, `net/http` bounds
  the TLS handshake by `max(ReadHeaderTimeout, ReadTimeout)`, `limits.MaxOutstandingPerSession`
  is enforced in `session/ops.go`, and responses are generated internally today.
- **Interest:** each is a knob an operator can set and get nothing from, and
  `MaxResponseBytes` becomes load-bearing the moment guarded execution returns upstream content.
- **Fix:** wire or explicitly deprecate each, under DEBT-011's wall. (`AdmissionBudget` is
  *not* here — it is a live risk, RISK-026.)

## DEBT-013 — MCP residual oracle and per-call upstream pooling · LOW (2026-08-24)
- **Principal (a):** the credential *presence* pre-check now runs before registry resolution, so a
  credential-less caller can no longer distinguish a registered MCP server from an unknown id. A
  caller presenting a **syntactically valid but invalid** token still can, because step 8 still
  precedes token validation. Closing it fully means deferring the registry *existence* decision
  until after validation while still resolving the server id from the path for the audience
  binding.
- **Principal (b):** `upstreamclient.roundTrip` builds one `http.Transport` per call. The
  2026-08-24 fix releases its idle connections (closing an unbounded FD/goroutine leak), but
  `MaxConnsPerServer` / `MaxIdleConnsPerHost` are consequently per-call bounds, not per-server
  pools — no two upstream calls share a connection. Fixing it means holding a transport per
  server whose dialer reads the current pin, which the per-call pinning model makes non-trivial.
- **Interest:** (a) bounded information disclosure; (b) a TLS handshake per upstream tool call
  once execution is armed.

## PREREQ-MCP-KILL-1 — MCP kill switch not revalidated at the side-effect boundary · HARD CANARY PREREQUISITE (2026-08-25)
- **Principal:** `Executor.Execute` checks `State.Killed()` once at admission, but the
  irreversible boundary (`run.go` `callUpstream`) does NOT re-read the authoritative kill
  state before the upstream side effect. Between admission and the boundary the executor
  performs a durable decision commit, credential planning and credential materialization —
  all of which can block — so an emergency kill engaged during that window does not abort an
  in-flight live call. The OVN-09 tool-drift re-check already sits at that boundary; the kill
  re-check does not yet join it.
- **Status:** OPEN. This is a **blocking prerequisite**, not an ordinary debt item.
  **Canary/Production activation is PROHIBITED until the authoritative kill state is
  revalidated immediately before the irreversible side-effect boundary** (a kill during
  planning/materialization must yield `up.calls == 0`, block reason
  `rollout_emergency_active`). Compensating control today: no production executor is composed
  (arming hooks uncalled; AST posture wall), so the window is unreachable in production — but
  the prerequisite must be CLOSED before any live-capable mode is armed.
- **Interest:** the kill switch is the operator's only immediate stop; a stop that a slow
  commit/materialize window can outrun is not a stop. Purely a live-mode concern — Shadow
  already reflects the kill at admission (`WOULD_BLOCK` / `rollout_emergency_active`) and never
  reaches the boundary.
- **Fix:** add a `killEpoch` re-read to `callUpstream` alongside the tool-drift re-check; on a
  kill, abort before `Upstream.Call` and return the emergency block. Then invert
  `TestCanaryPrerequisite_KillStateNotRevalidatedAtSideEffectBoundary`
  (`internal/mcp/execution`) to assert `up.calls == 0` and check off the §12 exit criterion in
  `docs/design/mcp/SHADOW-ARCHITECTURE.md`.
- **Evidence:** `docs/design/mcp/SHADOW-ARCHITECTURE.md` §10 (PREREQ-MCP-KILL-1) + §12 exit
  criteria; non-vacuous gate `TestCanaryPrerequisite_KillStateNotRevalidatedAtSideEffectBoundary`.

## SHADOW-EVIDENCE-ROUTING-1 — Pre-dispatch fail-closed signals not routed into Shadow evidence · LOW (2026-08-25)
- **Principal:** Two failure classes are terminally handled by the runtime BEFORE the
  guarded executor/Shadow provider is invoked, so the ShadowEvaluator never records a
  `shadow_evaluated` event for them: (a) an inspection `HardFail` is rejected in
  `dispatchPolicy` (`internal/mcp/runtime/policy.go`) before the `p.executor != nil`
  delegation, for every rollout mode; (b) an initial (pre-dispatch) tool drift is refused
  by the OVN-09 `refuseOnToolDrift` at the top of `dispatchExecute`
  (`internal/mcp/runtime/execute.go`) before `p.executor.Execute`. The evaluator's
  `WOULD_FAIL_INSPECTION` and (initial) `WOULD_FAIL_STALE_DECISION` outcomes are therefore
  provider-level contracts (pinned by the differential test via direct invocation) but are
  not produced through the live pipeline. `WOULD_FAIL_STALE_DECISION` IS reached for drift
  detected at the side-effect boundary (the `ToolStillCurrent` re-check).
- **Status:** OPEN, deferred by design. Execution is disabled (no executor composed), so
  this is future-facing evidence completeness, not a live gap. Found by Codex review of
  `d0f747e` on PR #1226.
- **Interest:** for a future Shadow activation, an inspection-hard-fail or an
  already-stale tool produces the runtime's own rejection observation instead of a
  `shadow_evaluated` / `WOULD_FAIL_*` record, so a Canary-readiness analysis reading only
  `culvert_mcp_shadow_*` would undercount those refusals (they are still recorded, in a
  different evidence shape).
- **Fix (proposed):** in the reviewed Shadow-activation composition slice, route these
  signals into the executor when one is wired — gate the `dispatchPolicy` inspection-block
  and let the executor enforce (fail-closed for Canary/Production via `hardFailure()` →
  `EffectBlock`; evidence for Shadow via `EffectShadowEvaluate` → `WOULD_FAIL_INSPECTION`);
  for drift, make the OVN-09 narrowing Shadow-aware so it records `WOULD_FAIL_STALE_DECISION`
  in Shadow WITHOUT widening the TOCTOU window for enforcing modes. This modifies
  security-sensitive dispatch and changes the enforcing-mode rejection observation shape, so
  it is out of scope for the architecture-only PR #1226 and belongs with the executor-arming
  review.
- **Evidence:** `docs/design/mcp/SHADOW-ARCHITECTURE.md` §13 (limitation 3);
  `internal/mcp/runtime/policy.go` (inspection block), `internal/mcp/runtime/execute.go`
  (refuseOnToolDrift).

## SHADOW-EVIDENCE-ROUTING-1 addendum — Durable Shadow sub-facts need a v2 envelope (2026-08-25)
- **Principal:** The Shadow enforcement-prediction sub-facts (shadow_outcome/override,
  credential-plan status, request/response inspection readiness) are NOT persisted as new
  fields on the `schema_version:1` event envelope. Adding digest-covered fields in place is a
  binary-rollback hazard: a pre-change reader drops the unknown JSON fields on unmarshal,
  recomputes `CanonicalBytes` without them, and `VerifyDigest` misreports a valid shadow
  record as corrupted (the model fails closed on an unknown schema version, but the fields
  were added under v1, so it never gets that far). Found by Codex on PR #1226 (4bbf211).
- **Status:** **CLOSED (2026-08-28)** — the dedicated durable-Shadow-evidence follow-up shipped
  the `schema_version:2` envelope. This was the FIRST of the two hard prerequisites for a real
  Controlled Shadow activation; it is now satisfied. The SECOND (a usable scoped tool via the
  tool-approval / promotion slice) is now **CLOSED (2026-08-28)** by the MCP tool-trust approval /
  promotion slice (ADR-0034, branch `claude/mcp-tool-trust-approval`): a durable
  `internal/mcp/tooltrust` approval store is the source of truth and the catalog `Usable` state is
  a materialized projection of it (promote on approve, demote on revoke/expiry, re-derive on
  startup + read), so a scoped, human-approved tool now satisfies `evaluateShadowActivationPreflight`.
  With BOTH prerequisites closed, Controlled Shadow activation is mechanically reachable — it stays a
  deliberate, separately-reviewed operator action, and a `shadow_evaluation` approval structurally
  cannot arm the live-execution tier (purpose firewall). (Elevated from "deferred by design"
  to a hard prerequisite on PR #1234, the activation-plumbing slice; both prerequisites now closed.)
- **Fix (shipped):** `schema_version:2` is an ADDITIVE envelope carrying a typed
  `Event.Shadow *ShadowEvidence` sub-evidence (outcome, override, credential-plan, request/response
  inspection readiness; the raw evaluated action stays in `Decision.Action`). It is stamped ONLY on
  a Shadow decision event — every non-shadow event stays v1, so its canonical digest is byte-identical
  (proven by golden vectors). One source of truth: the transient JSON-RPC response and the durable
  event both derive from `execution.shadowEvidence(ShadowDecision)`, pinned by a field-by-field parity
  gate. `Validate` fails closed on schema/shadow consistency, enum membership and the architecturally
  impossible combinations; recovery re-checks `SupportedSchemaVersion` + `ValidateShadowEvidence` as
  defense-in-depth over Commit-time validation + the AEAD record chain.
- **v1/v2 reader contract + rollback semantics (§9):** a v2-capable build supports v1 AND v2
  (`model.SupportedSchemaVersion`); a v2 event carries facts a v1 event never did. A pre-v2 (v1-only)
  build **refuses v2 evidence** and never partially interprets it — `unmarshalEvent` uses
  `DisallowUnknownFields`, so the unknown `shadow` key fails the decode, and the record is rejected as
  corrupt (fail closed) rather than misverified. This is the accepted downgrade posture: **rolling a
  binary back across persisted v2 shadow evidence requires an operator procedure** — the concrete,
  surgical steps (archive the Gateway spool subtree, clear the Shadow-bearing `P-ORD` **and**
  `P-CRIT` partitions — a read-class shadow `tools/call` is ordinary→`P-ORD`, a write/destructive
  one is critical→`P-CRIT` — reset both export cursors, restart) are in
  `docs/operator/mcp-shadow-activation.md` §8, which explicitly preserves the `P-DEN` partition,
  the sealed DEK, and the `management/` subtree so an operator never deletes unrelated durable
  evidence. Arbitrary binary downgrade over v2 evidence is
  NOT silently safe, by design, and validation is not weakened to make it appear so. No historical v1
  event is rewritten or migrated in place; existing v1 evidence stays immutable.
- **Gates:** `internal/mcp/events/model/shadow_v2_compat_test.go` (golden v1 digest invariance),
  `shadow_v2_test.go` (v2 digest sensitivity + validation fail-closed + supported-version set),
  `shadow_v2_fuzz_test.go`; `internal/mcp/execution/shadow_evidence_parity_test.go` (response↔durable
  parity + real-manager v2 commit); `internal/mcp/events/spool/shadow_v2_recovery_test.go`
  (recover round-trip, mixed v1/v2, interior-corruption fail-closed, Commit rejects malformed);
  `internal/mcp/events/export/shadow_v2_export_test.go` (export read → marshal → re-read round-trip).
- **Evidence:** `internal/mcp/events/model/{model.go,validate.go,canonical.go}` (v2 envelope +
  ShadowEvidence + Validate), `internal/mcp/events/decide.go` (v2 stamping), `internal/mcp/events/spool/recovery.go`
  (recovery guard), `internal/mcp/execution/{responses.go,shadow_evaluator.go}` (single mapping),
  `docs/design/mcp/SHADOW-ARCHITECTURE.md` §9.

## SHADOW-PREDICTION-PARITY-1 — Pre-side-effect gates have no ownership wall · LOW (2026-08-25)
- **Principal:** `ShadowEvaluator.decide()` re-states, by hand, the sequence of refusals the
  live `Executor` performs before the side-effect boundary (hard control → policy class →
  allowance → upstream-server usability → credential readiness → boundary drift). Nothing
  structural couples the two: a gate added to `Execute`/`runExecute` without a matching step
  in `decide()` silently makes Shadow MORE PERMISSIVE than the enforcement it predicts, and
  the only thing that catches it is whether someone remembers to extend the differential
  test. Two such gaps existed in the shipped Layer-B split and were found by review, not by
  a failing build (SR-01 allowance-capacity, SR-02 upstream-server usability — both fixed
  and walled in `internal/mcp/execution/shadow_prediction_parity_test.go`).
- **Status:** OPEN, deferred. Execution is disabled, so the class is future-facing. The
  direction of the failure is what makes it worth recording: an over-permissive Shadow
  prediction is an input to the Canary promotion decision, so the defect is consumed as
  evidence rather than surfacing as a refusal.
- **Fix (proposed):** an ownership registry in the shape of
  `internal/mcp/runtime/limits_ownership_test.go` — enumerate the pre-side-effect refusal
  sites in `executor.go`/`run.go` (via `go/types`, so a same-named helper on another type
  cannot satisfy a row) and require each to DECLARE either a modelling step in `decide()`
  or an explicit `not-predicted` justification. Then a new live gate fails the build until
  Shadow models it.
- **Evidence:** `docs/engineering/security-reviews/2026-08-25-shadow-layerb-and-ldap-window.md`
  §§3–4 and §6 residual risk; `docs/design/mcp/SHADOW-ARCHITECTURE.md` §4 (the stage list
  that already named "server eligibility" as requiring proof); DEBT-011 is the same class
  one layer up.
