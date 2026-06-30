# ADR-0002: Decompose the flat `package main` into `internal/` packages, incrementally

- **Status:** Accepted (2026-06-28 — maintainer accepted the incremental direction)
- **Date:** 2026-06-28
- **Deciders:** Chief Engineering Advisor (proposed); project maintainer (accepted)
- **Proving PR:** `internal/totp` — ✅ extracted 2026-06-28 (see Notes); proves the strategy viable
- **Leaves extracted:** `totp`, `geoip`, `fileblock`, `lockout`, `hashcache` (+ the `obs`/`fileutil` seam, ADR-0003)

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

### 2026-06-28 — CORRECTION during geoip execution: engine is NOT zero-coupling
While reading `geoip.go` to perform the split, found a coupling the mapping **missed**: the engine's
`resolveHost` (geoip-internal, no external callers) calls **`isPrivateIP`** (`proxy.go:108`), which
reads the **`privateCIDRs`** SSRF backbone and is **shared by 5 files** (proxy, security, threatfeed,
release_catalog_http, geoip). Root cause of the miss: the outbound grep checked `isPrivateHost`, not
`isPrivateIP`. **Lesson for the program:** symbol-name greps are necessary-but-insufficient for
mapping; read the source of the candidate before declaring it a leaf (the build would have caught it,
but the *mapping* should). `geoip` is therefore a **NEAR-LEAF with a security-critical dependency**,
not a true leaf. `isPrivateIP`/`privateCIDRs` cannot move (5 users, SSRF backbone) and must NOT be
duplicated (divergence risk in security code). Resolution options under review (no code moved):
- **(A) IP-based engine:** move `resolveHost` OUT to main; `internal/geoip` exposes IP-based lookup.
  Changes the lookup signature host→IP at call sites → an API redesign (constraint conflict).
- **(B) Inject an `IsPrivateIP` predicate** into `internal/geoip` (a minimal seam). Keeps the
  host-based API and behavior identical; cost is one injected func var wired by main at startup.
- **(F) Split `resolveHost` to main, keep a thin host-based wrapper in main** delegating to
  `internal/geoip.LookupByIP`. Callers' API preserved (main keeps `geo`-shaped wrappers); the package
  is a true IP→country leaf. No seam, no security-dup. Recommended.
Stopped for maintainer decision (the resolution touches the "no redesign / no seam yet" constraints).

### 2026-06-28 — shipped: `internal/geoip` via Option F (second leaf, ✅)
Maintainer chose **Option F**. The GeoIP IP→country engine moved to `internal/geoip`; `resolveHost`
(with the shared `isPrivateIP` SSRF check) stayed in `package main`, which keeps a thin host-based
`geo` wrapper so callers are unchanged.

- **`internal/geoip` public API (minimal):** `InitGeoDB`, `Enabled`, `LookupByIP(net.IP)`,
  `LookupCachedByIP(net.IP)`. The cache/`geoResult`/`geoDB` internals stay unexported.
- **True leaf, proven:** `go list -deps ./internal/geoip` imports **no Culvert package** (stdlib +
  `geoip2-golang`); `main` imports it; no cycle. `countryTraffic`/`activeConns` stayed in main.
- **Call sites unchanged:** `geo.LookupFull`/`LookupCached` in enrollment/policy/proxy untouched
  (main-side wrapper preserves the API); only `geoEnabled()`→`geoip.Enabled()` (main.go, ui_security.go)
  and `InitGeoDB`→`geoip.InitGeoDB` (startup) changed mechanically.
- **Behaviour preserved, validated:** `go build ./...`, `go vet ./...`, full `go test ./...` green,
  `-race` green on geoip/proxy paths, `golangci-lint ./internal/geoip` 0 issues. Engine coverage
  44.8% — the DB-read path needs a real `.mmdb` fixture (none shipped); tests are behaviour-based
  (disabled / nil-IP / bad-path / cache-hit), **not** padded. No CI coverage floor applies to this package.
- **Two diff-resurfaced findings handled** (same class as DEBT-002's nestif): a `geoCache` whitebox
  test retargeted to the `geo` wrapper, and a `//nolint:noctx` on `resolveHost`'s pre-existing
  `net.LookupHost` (moved verbatim; context-aware DNS is a separate out-of-scope change).

**Pattern now demonstrated twice** (`totp` true leaf, `geoip` near-leaf via a main-side wrapper that
keeps SSRF/host-resolution in main). Lesson reinforced: read the candidate's source before declaring
it clean. **Next:** `fileblock` still needs the shared logging + `atomicWriteFile` seam first — that
seam is the recommended next *foundational* step. Per protocol, stop here for review; do not start
`fileblock`.

### 2026-06-28 — fileblock re-mapped against the seam (ADR-0003 shipped); no code moved
Re-mapped `fileblock` now that `internal/obs` + `internal/fileutil` exist. **Read both source files
in full** (the geoip lesson): `fileblock.go` and `fileprofile.go` couple to `package main` ONLY via
`atomicWriteFile` (→`fileutil.AtomicWrite`), `logger.Printf` (→`obs.Printf`), and `sanitizeLog`
(→`obs.Sanitize`) — all now seam-covered. No other hidden dependency; the engine has no config/runtime
coupling (config is read by the startup wiring, which stays in main).

- **Now a TRUE LEAF** (coupling-wise). Imports would be: stdlib + `google/uuid` + `internal/obs` +
  `internal/fileutil`; no cycle (`main`→`fileblock`→leaves).
- **Inbound surface:** `fileBlocker` (7 files), `globalProfileStore` (3), `fileBlockConn`+
  `extractCDFilename` (proxy), `FileExtProfile` (controlplane), `defaultBlockedExts` (startup).
- **Low-churn plan (geoip pattern):** keep the singletons in main as vars of the internal types
  (`var fileBlocker = fileblock.NewBlocker()`, `var globalProfileStore = &fileblock.FileProfileStore{}`)
  so the ~10 method call sites stay UNCHANGED; only ~3–4 files change (the two free funcs in proxy,
  the `FileExtProfile` type ref in controlplane, `defaultBlockedExts` in startup). Export surface:
  `FileBlocker`/`FileProfileStore`/`FileExtProfile` types, `NewBlocker`, `BlockConn`,
  `ExtractCDFilename`, `DefaultBlockedExts`.
- **Tests:** move `fileblock_test.go`, `fileblock_replaceall_test.go`, `fileprofile_test.go`
  (whitebox) into the package; `fileblock_startup_test.go` stays in main.
- **Behaviour risk LOW** (verbatim move; logging via the sink → same logger; atomic-write identical).

**Recommendation: extract `fileblock` next.** Awaiting approval; no code moves until then.

### 2026-06-28 — fileblock extraction ATTEMPTED, reverted: test entanglement larger than mapped
Began the approved extraction. The **engine move is clean** (the package compiled: `internal/fileblock`
with `FileBlocker`/`FileProfileStore`/`FileExtProfile`/`NewBlocker`/`BlockConn`/`ExtractCDFilename`/
`DefaultBlockedExts`, using `obs`+`fileutil`; main keeps the singletons + transitional type aliases).
**Reverted** because reading the test sources in full (the recurring lesson) revealed the *test* surface
is materially larger and more entangled than the filename-based map implied:

1. **Two of the three "engine test files" are MIXED**, not pure engine:
   - `fileblock_test.go`: 7 engine unit tests + **3 proxy-integration tests** (`handleRequest`/
     `setupProxyTest`/`policyStore`) that must stay in main.
   - `fileblock_replaceall_test.go`: engine `ReplaceAll` tests + **`TestCL13_ApplyConfigSnapshot_…`**
     which calls `applyConfigSnapshot(ConfigSnapshot{…})` (controlplane) — must stay in main.
2. **Staying integration tests whitebox-manipulate the global's unexported state for isolation**
   (`snapshotFileBlocker` saves/restores `fileBlocker.path`+`.extensions`; the proxy tests seed
   `globalProfileStore.profiles`). Once the type moves, main can't touch those fields.
3. **Two shared test helpers** span the boundary: `assertNoTmpLeak` (`enroll_util_test.go`, used by
   ~10 files incl. moving tests) and `ensureFileblockTestLogger` (`fileblock_startup_test.go`).
4. **Inbound surface ~2× the map**: direct `&FileBlocker{…}` construction + `FileExtProfile` refs in
   `coverage_day3_test.go`, `cluster_apply_persist_test.go`, `cluster_features_test.go`,
   `edge_audit_test.go` — not just the ~3–4 files mapped.

**Good news — it IS doable with the APPROVED API (no API growth):** the staying integration tests can
be re-isolated via exported calls — `orig := fileBlocker.List()` + cleanup `fileBlocker.SetPath("")` +
`fileBlocker.ReplaceAll(orig)`; seed via `ReplaceAll`/`Add`; `globalProfileStore.ReplaceAll(...)`.
Moving tests drop `ensureFileblockTestLogger` (obs's default sink removes the nil-logger risk) and get
a local `assertNoTmpLeak` copy. Type aliases collapse `controlplane.go`/`cluster_features_test.go` to
zero changes.

**Revised scope to extract fileblock (now fully understood):** ~9 touched files —
`proxy.go` (BlockConn/ExtractCDFilename ×7, production), `fileblock_startup.go`+`_config.go`
(`DefaultBlockedExts`), split `fileblock_test.go` + `fileblock_replaceall_test.go` (engine→package,
integration→main with exported-API isolation), move `fileprofile_test.go`, adapt `coverage_day3_test.go`/
`cluster_apply_persist_test.go`/`edge_audit_test.go` constructions. Mechanical but broader than mapped;
behaviour risk LOW, **test-isolation-rewrite risk MEDIUM** (the determinism gate is the backstop).
**Decision pending: proceed with this larger-but-bounded scope, or defer.** No code is moved (reverted).

### 2026-06-28 — shipped: `internal/fileblock` (third leaf, ✅, larger scope)
Maintainer approved the larger scope. The file-type blocking engine moved to `internal/fileblock`
(uses `internal/obs` + `internal/fileutil`); `package main` keeps the singletons + transitional type
aliases. **Validated green:** build, `go vet`, full `go test ./...` (main + 5 internal packages),
`-race` (main + fileblock), **`-count=2 -shuffle=on` determinism on the fileblock/integration tests**
(the MEDIUM-risk isolation rewrites hold), `golangci-lint ./internal/fileblock` 0 issues, coverage
76.6%; `go list -deps` confirms no Culvert-package import (clean leaf, no cycle).

**Actual scope (~12 files, ~2× the original filename-map estimate) — honest record:**
- New: `internal/fileblock/{fileblock,fileprofile}.go` + 3 moved test files; `fileblock_vars.go`
  (singletons + 3 type aliases).
- Split two MIXED test files: engine tests → package; the proxy (`handleRequest`) and
  `applyConfigSnapshot` integration tests **stayed in main**, re-isolated via the exported API
  (`List()`/`SetPath("")`/`ReplaceAll`) instead of the prior whitebox field access.
- Adapted `proxy.go` (BlockConn/ExtractCDFilename ×8, production), `fileblock_startup*.go`
  (`DefaultBlockedExts`), and 3 more test files (`coverage_day3`, `cluster_apply_persist`,
  `edge_audit`) whose direct `&FileBlocker{…}` construction broke on the type move.
- Local `assertNoTmpLeak` copy in the package; dropped the `ensureFileblockTestLogger` call (obs's
  default sink removes the nil-logger risk).

**Two deviations from the approved plan, flagged for review:**
1. **Added one method beyond the approved export list:** `FileProfileStore.SetPath(p)` (symmetric
   with `FileBlocker.SetPath`). Required because the cluster integration test redirects persistence
   and there was no exported way to do so without `Load`'s seeding side-effects. Minimal, behaviour-
   preserving.
2. **Resolved diff-resurfaced lint on the moved code** (revive doc-comments, gocritic `equalFold`/
   `ifElseChain`, errcheck nolint-format). `equalFold` was applied as `strings.EqualFold` (behaviour-
   equivalent); the test if-else got a justified `//nolint:gocritic`. This nudged slightly past "no
   cleanup," but was required to pass the same lint gate as the rest of the tree.

**Lesson (third time): the *test* surface, not the engine, is the hard part of extraction** — mixed
files, shared test helpers, whitebox isolation, and direct type construction scatter far wider than a
filename map shows. Future near-hub mappings must read the test sources up front and budget for
integration-test isolation rewrites. **Three leaves done (`totp`, `geoip`, `fileblock`) + the seam.**
- **Related:** DEBT-001, DEBT-002, DEBT-003 (Technical Debt Register)

### 2026-06-29 — `internal/lockout` extracted (fourth leaf)
Moved `lockout.go` (login account-lockout `LoginLimiter` + admin-API `APIRateLimiter` + `LockoutMsg`
+ their constants) into `internal/lockout`. A **genuinely clean leaf**: stdlib-only, zero Culvert
coupling — needed **no new seam** (unlike the deferred `scan` hub, which still waits on an alerting
seam because `fireAlert` is a 16-file core primitive). Production surface was trivial: only
`ui_auth.go` (loginLimiter) and `ui_middleware.go` (apiLimiter), both unchanged via the alias shim.

`package main` keeps `lockout_vars.go` (alias pattern, as geoip/fileblock): type aliases
`LoginLimiter`/`APIRateLimiter`, the `loginLimiter`/`apiLimiter` singletons, `var LockoutMsg =
lockout.Msg`, and the legacy `lockout*`/`apiRate*` const names the test suite references.

**Test surface was again the hard part** (the lesson, fourth time), and the resolution is a **net
design improvement, not just churn**:
- Engine unit tests + `LockoutMsg` test → moved into `package lockout` (whitebox).
- The 3 `TestAPIRateLimiter_*` tests were **split out of `p5_test.go`** into the package (they need
  whitebox access to the now-internal `APIRateLimiter.entries`).
- The cross-cutting isolation helper `snapshotLoginLimiter` (used by `policy_misc_test.go`,
  `auth_password_change_no_versioning_test.go`) previously reached into `loginLimiter.mu`/`.entries`.
  It now delegates to a **single new exported method `(*LoginLimiter).SnapshotAndClear() func()`** —
  the *only* added API beyond a pure move. This is cleaner than the prior whitebox: the snapshot/
  restore is owned by the type that owns the mutex, instead of poked from a foreign package's tests.
- The pollution regression test no longer hand-constructs a locked `lockoutEntry`; it drives the
  pre-locked state through the production `RecordFailure` API (max failures ⇒ locked), which the
  test's own premise ("a prior test left the user locked") makes semantically exact.

**One added export, flagged for review:** `SnapshotAndClear` (test-support, but a legitimate
self-contained operation; named without a `ForTest` suffix because it is a real, reusable
snapshot/restore). Lint surfaced two findings on the new package lines (gocritic `unnamedResult` on
`Check`, revive repetitive-name on `LockoutMsg`); both fixed cleanly — named `Check`'s results to
match its doc comment, and renamed the package func to `Msg` (package-main name stays `LockoutMsg`
via the shim).

Validation: `go build ./...`, `go vet`, `golangci-lint` (0 issues on the new pkg + new lines),
`-race` on the package and the main lockout-path/auth-login tests, and the determinism gate
(`-count=2 -shuffle=on`) on every `snapshotLoginLimiter` consumer — all green. **Four leaves done
(`totp`, `geoip`, `fileblock`, `lockout`) + the seam.**

### 2026-06-29 — `internal/hashcache` extracted (fifth leaf)
Moved `hashcache.go` (the SHA-256 scan-result cache: `HashCache`, `ScanCacheResult`, `SHA256Hex`,
`newHashCache`) into `internal/hashcache`. **The cleanest extraction so far** — stdlib-only, zero
Culvert coupling, and crucially **zero whitebox test access**: every consumer (the sole production
field `SecurityScanner.cache *HashCache`, plus the `Stats`/`Clear`/`Evict` calls in
`metrics.go`/`otlp.go`/`ui_security.go`/`security_scan.go` and the `newHashCache` call in `main.go`)
goes through the **exported API**. So **no test had to move and no test-support API was added** —
the opposite of the lockout/fileblock test-surface tax.

`package main` keeps `hashcache_vars.go` (alias shim): type aliases `HashCache`/`ScanCacheResult`,
`var SHA256Hex = hashcache.SHA256Hex`, and a thin `newHashCache` wrapper over `hashcache.New` (the
constructor was renamed `newHashCache`→`New` for idiomatic `hashcache.New`). The existing black-box
tests across `misc_test.go`/`edge_audit_test.go`/`coverage_test.go`/`final_coverage_test.go` keep
passing unchanged through the shim. Note `cdr_proxy.go`'s `cdrHashCache` is an **unrelated** type
(CDR epoch cache), not a consumer — left untouched.

Added a focused co-located `hashcache_test.go` (as with geoip) so the leaf is self-testing
independent of package main, covering the paths the API-level tests don't: `evictLocked` capacity
overflow (drops ~maxSize/4) and expired-first eviction, plus defaults/TTL/Stats/SHA256Hex. Lint on
the new lines surfaced `unnamedResult` on `Stats` (named its results to match the doc comment) and
`builtinShadow` on a test `const max` (Go 1.21 builtin — renamed `capacity`); both fixed.

Validation: `go build`/`go vet ./...`, `golangci-lint` (0 issues), `-race` on the package and the
security-scan/hashcache consumer tests, determinism gate (`-count=2 -shuffle=on`) — all green.
**Five leaves done (`totp`, `geoip`, `fileblock`, `lockout`, `hashcache`) + the seam.**

### 2026-06-29 — `internal/hostutil` seam built (prerequisite for catdb + scan)
Mapping `catdb` for extraction surfaced that it is **not a pure leaf**: `CommunityDB.Lookup` calls
`normalizeHost`, a `package main` helper in `security.go`. Rather than inject or (worse) duplicate a
**security-relevant** normalizer (IDNA fail-open is tracked as RISK-013 — divergence across copies
would be dangerous), the right move is the small **pure** host-helper seam the ADR already flagged
the `scan` hub needs: `stripHostPort` lives right next to `normalizeHost`.

`internal/hostutil` now owns `NormalizeHost` + `StripHostPort` (stdlib + `golang.org/x/net/idna`,
zero Culvert coupling). `security.go` keeps two thin unqualified wrappers so every call site (policy,
store, catdb, scanner, security_scan) and the black-box tests (`misc_test.go`,
`scan_host_ipv6_test.go`) stay unchanged; the now-unused `idna` and `strings` imports were dropped
from `security.go`. A focused co-located `hostutil_test.go` covers IDN→punycode, the IP/ASCII fast
paths, and the bare-IPv6 preservation edge case. This seam unblocks **both** `catdb` (next) and the
deferred `scan` hub. Build/vet/lint/test all green. (Sibling to the ADR-0003 `obs`/`fileutil` seam.)

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
