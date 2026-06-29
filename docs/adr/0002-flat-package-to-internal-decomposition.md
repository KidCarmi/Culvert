# ADR-0002: Decompose the flat `package main` into `internal/` packages, incrementally

- **Status:** Accepted (2026-06-28 — maintainer accepted the incremental direction)
- **Date:** 2026-06-28
- **Deciders:** Chief Engineering Advisor (proposed); project maintainer (accepted)
- **Proving PR:** `internal/totp` — ✅ extracted 2026-06-28 (see Notes); proves the strategy viable

## Notes / log

### 2026-06-28 — dependency mapping of the proposed first leaf (`internal/scan`)
The first attempted proving target, `internal/scan` (yara/clam/scanner), was **mapped before any
code move** (per the extraction execution rules) and found to be a **hub, not a leaf**:

- **Outbound coupling to 4 cross-cutting `package main` subsystems:** logging (`logger`,
  `logWarnf`, `sanitizeLog`), file util (`atomicWriteFile`), host util (`stripHostPort`), and
  alerting (`fireAlert`).
- **Large inbound surface (~20 files):** `dpiScanner` (10 files), `ClamAV` (15 files),
  `statDPIBlocked` (5), plus `globalYARA`, `dpiBlock`, `isTextContentType`, `yaraGet*/Set*` — most
  currently **unexported**, so a move forces exporting ~15 symbols and rewriting ~20 call sites.
- **Orchestrator entanglement:** the (out-of-scope) `security_scan.go` embeds `*ClamAV` and
  coordinates the cluster; it is the cluster's primary consumer and is itself not a leaf.

**Decision:** do NOT move `scan` first. It requires a foundational seam layer (logging/alerting
injection + a shared util package) and a large API-export pass — a multi-PR program, not a minimal
proving PR. **Re-target the proving PR to a genuinely clean leaf.** `totp.go` was verified clean
(stdlib-only imports, zero `package main` coupling, ~2–3 function inbound surface) and is the
recommended proving target. This finding is itself the first concrete payoff of the proving
process: it shows the decomposition must sequence *true* leaves first and build shared-foundation
seams before extracting hubs like `scan`.

### 2026-06-28 — proving PR shipped: `internal/totp` (✅ ADR-0002 validated)
The strategy is proven viable on a genuine leaf. `totp.go` was moved to `internal/totp` (package
`totp`) with the totp tests relocated as whitebox tests:

- **Minimal public API:** exactly ONE symbol exported (`VerifyTOTPReturnCounter`, the lone
  production caller in `ui_auth.go`); everything else stays unexported and is tested in-package.
- **Clean leaf, proven by tooling:** `go list -deps ./internal/totp` shows **no Culvert package**
  (stdlib-only) — no `package main` global leaks, no import cycle; `main` imports it.
- **Behaviour unchanged, validated:** full `go test ./...` green (main + totp), `go test -race`
  green on auth/totp paths, `go vet ./...` clean, `golangci-lint ./internal/totp` 0 issues,
  coverage 97.3% (CI floor for `totp.go` is 85%, satisfied via substring match on the new path).

**Dependency-direction rule established for the program:** `internal/*` packages MUST NOT import
`package main` (enforced naturally by Go — a back-import is a compile-time cycle). Cross-cutting
concerns a leaf needs (logging, alerting, utils) must be satisfied without importing main: a true
leaf has none (totp); a hub (scan) needs a shared-foundation seam layer first (see prior note).

**Next leaves (no foundation work needed, mappable now):** `geoip`, `fileblock` — candidates to
confirm the pattern repeats. Hubs (`scan`) wait for the logging/alerting/util seam. Per the
extraction protocol, do not start the next extraction until this one is reviewed.

### 2026-06-28 — dependency mapping: `geoip` vs `fileblock` (next-leaf selection, no code moved)

| Dimension | `geoip` | `fileblock` |
|---|---|---|
| Files | `geoip.go` (engine) + `geoip_startup*.go` (wiring, stays in main) | `fileblock.go` + `fileprofile.go` + `fileblock_startup*.go` (wiring) |
| Engine outbound coupling to `package main` | **NONE** (stdlib + `geoip2-golang` only) | **`logger`, `sanitizeLog`, `atomicWriteFile`** (fileblock.go:280,62; fileprofile.go:104,133) |
| Logging/config/metrics coupling | engine: none; wiring shim uses `logger`+`cfg` (stays in main) | yes — logging + file-util in the engine itself |
| Inbound API surface | `geo` global → 3 call sites (enrollment/policy/proxy) + `InitGeoDB` (startup) | `fileBlocker` → 7 files, `globalProfileStore` → 4 files |
| Export work | export `geo` (or provide pkg funcs) + `InitGeoDB`; ~3–4 call sites | export `fileBlocker`, `globalProfileStore`, types; ~10 call sites |
| File-cohesion snag | `geoip.go` also bundles `countryTraffic` + `activeConns` (NOT geoip; used by events/proxy/main) → must split, leaving those in main | `fileBlockConn` writes HTTP 403 (like `dpiBlock`) — response-writing in the leaf |
| Test movement | engine has no dedicated unit test today (only `geoip_startup_test.go`, stays in main); optionally add one | `fileblock_test.go`, `fileprofile.go` tests + `fileblock_replaceall_test.go` move with the engine |
| Import-cycle risk | none (engine imports no Culvert pkg) | none structurally, but the 3 cross-cutting deps would force main imports → solved only via seam/inject |
| Expected diff scope | medium: 1 file split + export 1 global + ~3–4 call sites + startup test tweak | large: seam layer first, then ~10 call sites + type exports + test moves |
| Behaviour risk | LOW (pure move + export) | MEDIUM (seam wiring touches a hot-path block + broad call-site churn) |
| Classification | **NEAR-LEAF** (engine is a true leaf; file bundles unrelated concerns) | **NEAR-HUB** (cross-cutting deps + 7-file inbound) |
| Recommendation | **EXTRACT NEXT** — no seam prerequisite | **DEFER** — needs the shared logging + `atomicWriteFile` seam first |

**Smallest seam fileblock needs (per the protocol):** the same logging seam every hub needs
(`logger`/`sanitizeLog`) PLUS an `atomicWriteFile` home (a shared `internal/util` or an injected
writer). That seam is the gating prerequisite for `fileblock`, `scan`, and most other hubs — it is
the natural *next foundational step* once a couple more clean leaves confirm the pattern.

**Decision: `geoip` is the safer next extraction** — its engine has zero cross-cutting coupling, so
it needs no seam. The only added work vs. `totp` is a file split (extract the GeoIP lookup engine;
leave `countryTraffic`/`activeConns` in main as their own file) and exporting the `geo` global for
~3–4 call sites. `fileblock` is deferred until the logging/util seam exists. *(Awaiting approval
before any code moves.)*
- **Related:** DEBT-001, DEBT-002, DEBT-003 (Technical Debt Register)

## Context

The entire root program is one flat `package main`: 152 source files, ~1,950 top-level functions,
187 exported types, and **~359 package-level mutable variables** in a single shared namespace.
Unrelated subsystems — TLS interception, the gRPC control plane, SAML/OIDC, YARA scanning, release
signing, the admin UI — all share that namespace and can read or mutate any global.

Evidence this is a real, paid cost (not a theoretical purity concern):

- Core runtime state is global singletons reachable by both the proxy hot path and the admin write
  path: `policy.go:391 policyStore`, `store.go:646 bl`, `store.go:1602 cfg`, `store.go:56 ts`.
  Safety is by *convention* (each struct's own `RWMutex`), not by language.
- The codebase already carries **dedicated data-race regression tests**:
  `upstream_transport_race_test.go`, `controlplane_cptlsconfig_race_test.go`,
  `controlplane_dp_conn_race_test.go`, `threatfeed_savetodisk_race_test.go`. `CLAUDE.md` devotes a
  hard rule to `upstreamTransport` ("direct field assignment is forbidden — it races against the
  proxy hot path") — institutional memory of a real race.
- The team's **newest** component, `cmd/culvert-maint/`, is already decomposed into
  `internal/{server,ops,runner,auth,config,audit,health}`. The flat root is recognized debt the
  newest code stopped accruing.

The flat layout is the root cause of several debt items (DEBT-001/002/003/005/006) and is the single
biggest drag on the Maintainability and Architecture scores in the Engineering Dashboard.

## Decision (proposed)

Migrate the root program from one flat `package main` to a thin `main` plus a set of `internal/`
packages, **incrementally and leaf-first**, reusing the structure `cmd/culvert-maint` already proves.

Sequencing principles:

1. **Leaf clusters first** — extract subsystems with no inbound dependencies and a clean surface:
   `internal/scan` (yara/clam/scanner), `internal/geoip`, `internal/fileblock`, `internal/totp`.
   These convert convention-boundaries into compiler-enforced boundaries at near-zero risk.
2. **One cluster per PR**, each behind green CI (including `-race`). No cluster moves until its tests
   move with it and pass.
3. **Globals become package-owned**, exposed through narrow constructors/accessors, killing the
   "any file can mutate any global" surface one cluster at a time.
4. **`handleRequest` decomposition (DEBT-002) is a prerequisite spike**, not part of this migration —
   it is done first, in `package main`, to de-risk touching the hot path.
5. **No big-bang rewrite.** The test suite (1.35× source LOC) is the project's greatest asset; a
   rewrite would discard it. This migration *moves* tests with their code.

## Consequences

- **Positive:** compiler-enforced encapsulation; smaller blast radius per change; a shrinking
  data-race surface; lower onboarding cost; the `cmd/culvert-maint` pattern becomes the whole repo's
  convention instead of an exception.
- **Cost:** sustained effort across quarters; import-cycle untangling will surface hidden coupling
  (which is the point — it makes coupling visible and forces it to be addressed).
- **Risk:** moving the proxy hot path is the highest-risk step; it is deliberately *last* and gated by
  the `handleRequest` spike and full `-race` CI.
- **If rejected:** the flat package stays, the registers keep DEBT-001 open as an accepted cost, and
  the Architecture/Maintainability scores stay capped at ~2.5. That is a legitimate choice if the
  maintainer judges the migration cost higher than the carried interest — but it should be a
  *decision*, recorded here, not a default.

## Alternatives considered

- **Status quo (accept the debt).** Viable; must be an explicit, recorded acceptance, not drift.
- **Big-bang re-architecture.** Rejected: discards the test suite and stops feature work for a long
  window with high regression risk.
- **`pkg/` public packages instead of `internal/`.** Rejected: Culvert ships as a single binary with
  no library consumers; `internal/` correctly prevents an accidental public API surface.

## Decision needed from the maintainer

Accept the incremental direction (and let the Advisor open the first leaf-extraction PR after the
`handleRequest` spike), or explicitly **accept DEBT-001 as carried debt** so the registers and scores
reflect a deliberate choice rather than an open question.
