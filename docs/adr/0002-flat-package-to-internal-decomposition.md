# ADR-0002: Decompose the flat `package main` into `internal/` packages, incrementally

- **Status:** Accepted (2026-06-28 — maintainer accepted the incremental direction)
- **Date:** 2026-06-28
- **Deciders:** Chief Engineering Advisor (proposed); project maintainer (accepted)
- **Proving PR:** `internal/totp` — ✅ extracted 2026-06-28 (see Notes); proves the strategy viable
- **Leaves extracted:** `totp`, `geoip`, `fileblock`, `lockout`, `hashcache`, `catdb`, `blockpage`, `rewrite`, `connlimit`, `syslog`, `clamav`, `yara`, `scanner`, `scanexcl`, `filemagic`, `clientclass`, `backupcrypt`, `bandwidth`, `nodegroup`, `secscan` (20th — the ADR-0006 composition root, via DI), `pac` (21st), `plugin` (22nd), `ocsp` (23rd), `uitls` (24th), `blocklistfeed` (25th), `feedsync` (26th), `saasfeed` (27th), `threatfeed` (28th), `alerts` delivery engine (29th — the seam grown into the full engine), `bootstrap` (30th), `sse` (31st), `logstore` (32nd), `blocklist` (33rd — store.go Phase A), `audit` (34th — store.go Phase B), `reqlog` (35th — store.go Phase C; **the store.go program is CLOSED**), `urlcat` (36th — policy.go Phase A), `sslbypass` (37th — policy.go Phase B; FQDN glob matcher promoted to `hostutil.MatchFQDN`) (+ the `obs`/`fileutil`, `hostutil`, `alerts`, and `ssrf` seams)
- **Leaf-extraction phase:** ✅ **COMPLETE** (2026-06-30) — 17 leaves + 3 seams; see "Decomposition Complete" below for the completion line and the categorisation of every root file that deliberately stays in `package main`.

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

### 2026-06-29 — `internal/catdb` extracted (sixth leaf, unblocked by hostutil)
Moved `catdb.go` (the Layer-2 community URL category store, `CommunityDB`) into `internal/catdb`,
now that `hostutil` exists: `Lookup` calls `hostutil.NormalizeHost` instead of the package-main
helper. **Architectural win beyond the boundary:** the leaf now **contains the BadgerDB dependency**
for the category path — `github.com/dgraph-io/badger/v4` no longer appears in the flat namespace for
URL categorisation (the audit-log stores `logguard.go`/`logstore.go` still use Badger; future
`internal/auditlog`-style candidates).

`package main` keeps `catdb_vars.go` (alias shim): `type CommunityDB = catdb.CommunityDB`, the
`communityDB` singleton, and an `openCommunityDB` wrapper over `catdb.Open` (constructor renamed
`openCommunityDB`→`Open`). All consumers stay unchanged — `policy.go` (Lookup), `feedsync.go`
(`*CommunityDB` field + BulkWrite), `main.go` (open/close + shutdown hook), `ui_policy.go` (nil
check). Like hashcache, **zero whitebox test access** — the 7 `CommunityDB` tests were a clean
black-box block, so they **moved** into `internal/catdb/catdb_test.go` (the feedsync tests in the
shared `catdb_feedsync_test.go` keep driving `openCommunityDB` via the shim).

Validation: `go build`/`go vet ./...`, `golangci-lint` (0 issues), `-race` on the package and the
main feedsync/category consumers, determinism gate (`-count=2 -shuffle=on`) — all green.
**Six leaves done (`totp`, `geoip`, `fileblock`, `lockout`, `hashcache`, `catdb`) + two seams
(`obs`/`fileutil`, `hostutil`).**

### 2026-06-29 — `internal/blockpage` extracted (seventh leaf)
Moved `blockpage.go` (the corporate "Access Denied" page: default HTML template, runtime override,
403 writer) into `internal/blockpage`. Pure stdlib (`html/template`, `net/http`, `bytes`, `sync`,
`time`), zero Culvert coupling, and — like hashcache/catdb — **zero whitebox test access**: every
consumer is black-box. `serveBlockPage`→`Serve`, `setBlockPageHTML`→`SetHTML`,
`getBlockPageHTML`→`GetHTML`; the default-template const and the mutable `state`/`pageData` are
package-internal (no external refs).

`package main` keeps `blockpage_vars.go` (thin wrappers) so the call sites stay unchanged —
`proxy.go` (`serveBlockPage` on every deny path), `admin_settings.go` (get/set for restart-durable
custom HTML), and the black-box tests in `edge_audit_test.go` / `policy_misc_test.go`. Added a
focused co-located `blockpage_test.go` (the file had none): default render, custom-template
round-trip, invalid-template rejection leaves the prior template installed, and the execute-error →
403 fallback path.

Validation: `go build`/`go vet ./...`, `golangci-lint` (0 issues), `-race` + determinism gate
(`-count=2 -shuffle=on`) on the package, main deny-path consumers green. **Seven leaves done
(`totp`, `geoip`, `fileblock`, `lockout`, `hashcache`, `catdb`, `blockpage`) + two seams.**

### 2026-06-29 — `internal/rewrite` extracted (eighth leaf)
Moved `rewrite.go` (per-host HTTP header rewrite: the rule DTO + the `Rewriter` engine) into
`internal/rewrite`. Pure stdlib (`net/http`, `strings`, `sync`), zero Culvert coupling. The DTO is a
config/API/cluster type threaded through `config.go`, `admin_settings.go`, `configversion.go`,
`controlplane.go`, `ui_config.go`, `ui_policy.go`; the `rewriter` singleton is driven by `main.go`,
`proxy.go` (both hot-path Apply calls), and the `rewrite_default_action` startup slice — all unchanged
via the `rewrite_vars.go` alias shim (`type RewriteRule = rewrite.Rule`, `var rewriter =
rewrite.NewRewriter()`).

**Lockout-class test surface** (not black-box like the last three): the dedicated `rewrite_test.go`
engine tests **moved** into the package (they use the unexported `matchesHost` + `&Rewriter{nextID}`),
and the two `matchesHost` tests living in the shared `rewrite_scanner_policy_test.go` moved with them.
The startup-slice isolation helper `resetRewriteDefaultGlobals` previously reached into
`rewriter.rules`/`.nextID`/`.mu`; it now delegates to **one new exported method
`(*Rewriter).Snapshot() func()`** (snapshot rules+nextID, return a restore closure) — the only added
API beyond a pure move, the same shape as lockout's `SnapshotAndClear`. Lint: revive flagged
`rewrite.RewriteRule` as repetitive, so the package type is `Rule` (package-main name stays
`RewriteRule` via the alias).

Validation: `go build`/`go vet ./...`, `golangci-lint` (0 issues), `-race` + determinism gate
(`-count=2 -shuffle=on`) on the package and the startup-slice/proxy consumers — all green.
**Eight leaves done (`totp`, `geoip`, `fileblock`, `lockout`, `hashcache`, `catdb`, `blockpage`,
`rewrite`) + two seams (`obs`/`fileutil`, `hostutil`).**

### 2026-06-29 — `internal/connlimit` extracted (ninth leaf)
Moved the per-IP `ConnLimiter` (proxy hot-path flood/slow-read guard) into `internal/connlimit`.
Pure stdlib (`sync`, `sync/atomic`), zero Culvert coupling. The two request-tracing helpers
(`generateRequestID`/`generateTraceparent`) **stayed** in the trimmed `connlimit.go` — they are
request-scoped tracing, not connection limiting, so labelling them under a `connlimit` package would
mislead. `connlimit_vars.go` shims the type alias + the `connLimiter` singleton + a `newConnLimiter`
constructor var.

This was the **most consumer-entangled leaf so far** but resolved without moving a single test. The
wrinkle: six **production** sites plus several tests reached into the unexported `enabled atomic.Bool`
via `connLimiter.enabled.Load()`. Added one exported accessor `(*ConnLimiter).Enabled() bool` and
rewrote those reads (`admin_settings.go`, `ui_config.go` ×5) — a genuine improvement (no more
whitebox in production). Every test built `ConnLimiter` with a struct literal over now-unexported
fields; all ten sites across four files (`connlimit_test.go`, `edge_audit_test.go`,
`security_audit_test.go`, `connlimit_startup_test.go` — incl. the S1 conn+rate-limit startup-slice
isolation reconstruction) switched to the `newConnLimiter()` constructor, leaving them black-box and
in place (the unrelated latency-histogram tests sharing `connlimit_test.go` were untouched). Added a
focused co-located `connlimit_test.go` covering New/Enable/Disable/Enabled, the acquire-limit/release
cleanup, and a `-race` reconfigure-under-load case. Lint: SA4000 on a doubled `Acquire` expression —
split into two statements.

Validation: `go build`/`go vet ./...`, `golangci-lint` (0 issues), `-race` + determinism gate
(`-count=2 -shuffle=on`) on the package and the startup-slice/proxy consumers — all green.
**Nine leaves done (`totp`, `geoip`, `fileblock`, `lockout`, `hashcache`, `catdb`, `blockpage`,
`rewrite`, `connlimit`) + two seams (`obs`/`fileutil`, `hostutil`).**

### 2026-06-29 — `internal/syslog` extracted (tenth leaf)
Moved the `syslogWriter` SIEM-forwarding engine into `internal/syslog` (→ `Writer`/`NewWriter`).
syslog was **not a pure leaf** — three couplings, each resolved cleanly:
- **`AuditEntry`/`LogEntry` types** (the `WriteAudit`/`WriteRequest` params): the writers only
  `json.Marshal` the entry, so the signatures changed to `any`. A syslog forwarder genuinely doesn't
  need the concrete struct shape; callers (`store.go`, a coverage test) pass the same values
  unchanged. This decouples the leaf from the store layer entirely.
- **`logger`/`sanitizeLog`** (in `InitSyslog`): `InitSyslog` **stayed** in `package main` (trimmed
  `syslog.go`) along with the `globalSyslog` global, a `syslogWriter` shim alias, and a
  `newSyslogWriter` constructor wrapper — so the obs coupling lives where it belongs and the package
  is pure stdlib.
- **`ui_config.go` calling the unexported `writeMsg`** (the connectivity "test message"): swapped to
  the already-exported `io.Writer` `Write` (same PRI=14 path), so no internal method had to leak.

The three `formatMsg`/`Format` unit tests (whitebox `&syslogWriter{…}` + unexported `formatMsg`)
moved out of the shared `distributed_rl_test.go` into the package; the integration test in
`coverage_boost_test.go` keeps using the `newSyslogWriter` shim + `WriteRequest` (now `any`). Lint on
the moved code surfaced two house-rule items now that the lines are "changed": `noctx` on
`net.DialTimeout` → rewrote to `(&net.Dialer{Timeout}).DialContext(context.Background(), …)` (the
CLAUDE.md-required form, behaviour-identical); and a bare `//nolint:errcheck` → added a reason.

Validation: `go build`/`go vet ./...`, `golangci-lint` (0 issues on the new pkg + new lines), `-race`
+ determinism gate (`-count=2 -shuffle=on`) on the package and the store/ui_config consumers — all
green. **Ten leaves done (`totp`, `geoip`, `fileblock`, `lockout`, `hashcache`, `catdb`, `blockpage`,
`rewrite`, `connlimit`, `syslog`) + two seams (`obs`/`fileutil`, `hostutil`).**

## Tier 2 — `internal/alerts` producer seam (unblocks the `scan` cluster)

The clean self-contained leaves are exhausted; the remaining subsystems are hubs. The first Tier-2
target is the `scan` cluster (yara/clam/scanner/security_scan), whose only blocker beyond the existing
`obs`/`fileutil`/`hostutil` seams was `fireAlert`. `fireAlert` lives in `alerts.go` — a 504-line hub
(webhook store + persistence, HMAC signing, SSRF-guarded HTTP delivery, retry queue) that must NOT
move wholesale.

### 2026-06-29 — `internal/alerts` seam built
Rather than move the delivery hub, built a minimal **producer seam** mirroring the `obs` sink pattern:
`internal/alerts` owns the `Payload` DTO and a publish-once `Fire`/`SetSink` indirection
(`atomic.Pointer[Sink]`). `package main` aliases `type AlertPayload = alerts.Payload` (every existing
producer/consumer unchanged) and installs the real dispatcher at package init:
`func init() { alerts.SetSink(fireAlert) }` — `fireAlert`'s signature already matches `alerts.Sink`.
The webhook/retry/SSRF code stays entirely in `package main`.

The scan cluster touches alerting at exactly three sites (`yara_scan.go` ×2 `yara_degraded`,
`security_scan.go` ×1 `scan_skipped`); all three were redirected from `fireAlert(…, AlertPayload{…})`
to `alerts.Fire(…, alerts.Payload{…})` — so they are already extraction-ready and no longer reference
the package-main symbol. `Fire` is a no-op when no sink is installed, so unit tests that never wire
alerting are unaffected. Added a co-located `alerts_test.go` (no-op-without-sink, deliver-intact,
publish-once-replace).

Validation: `go build`/`go vet ./...`, `golangci-lint` (0 issues), `-race` on the package plus the
alert/webhook/scan consumers (existing `yara_degraded`/`scan_skipped` delivery still works end-to-end
through the sink), determinism gate (`-count=2 -shuffle=on`) — all green. **Three seams now
(`obs`/`fileutil`, `hostutil`, `alerts`); the `scan` cluster is unblocked.**

### 2026-06-29 — `internal/clamav` extracted (first scan engine, eleventh leaf)
Moved `clam.go` (the ClamAV CLAMD INSTREAM client) into `internal/clamav` — the **first piece out of
the scan cluster**, and the cleanest: pure stdlib, **zero** Culvert coupling (no obs, no alerting, no
globals). Idiomatic rename `ClamAV`→`Client`, `NewClamAV`→`New` (revive: `clamav.ClamAV` is
repetitive); `clam_vars.go` aliases both back (`type ClamAV = clamav.Client`, `var NewClamAV =
clamav.New`) so the sole consumer — `SecurityScanner.clam` in `security_scan.go` — is unchanged.

The `parseClamResponse` unit tests (from the shared `logger_ca_clam_test.go`), the
`ScanConnectionRefused` test (whitebox `timeout` field), and `FuzzParseClamResponse` (from the shared
`fuzz_test.go`) all **moved** into the package (they use the unexported parser/field). Lint on the
moved code: `Ping` still used `net.DialTimeout` → rewrote to `DialContext` (CLAUDE.md form, matching
`Scan` which already used it); `unnamedResult` on `parseClamResponse` → named to match its doc; two
bare `//nolint:errcheck` on `SetDeadline` → added reasons.

Validation: `go build`/`go vet ./...`, `golangci-lint` (0 issues), `-race` + determinism gate
(`-count=2 -shuffle=on`) on the package and the `security_scan` consumer — all green. **Eleven leaves
done (… `clamav`) + three seams.** Scan cluster remaining: `yara_scan.go` (engine — needs the now-built
`alerts` seam), `scanner.go` (DPI coordinator), `security_scan.go` (orchestrator hub).

### 2026-06-29 — `internal/yara` extracted (YARA engine, twelfth leaf — the biggest single move)
Moved `yara_scan.go` (982 lines, the pure-Go YARA engine) into `internal/yara`. Coupling was clean —
only the `obs` and (just-built) `alerts` seams — so `logger.Printf`→`obs.Printf`, `logWarnf`→
`obs.Warnf`, `sanitizeLog`→`obs.Sanitize`; the three alert sites already used `alerts.Fire`. Renames:
`YARARuleSet`→`RuleSet`, the runtime config funcs `yaraGet*`/`yaraSet*`→`Get*`/`Set*`,
`ValidateYARASource`→`ValidateSource`, posture consts `yaraFailClosed`/`yaraFailOpenWithAlert`→
`FailClosed`/`FailOpenWithAlert` (revive). Added `NewRuleSet`, a `LoadSource(src)` test-support method
(directory-free rule install), and `Inflight()`.

`yara_vars.go` shims it all back to package main: `type YARARuleSet = yara.RuleSet`, the `globalYARA`
singleton, `var`-aliases for the 12 config funcs + `ValidateYARASource`, the posture consts, and a
`yaraInflightLoad()` wrapper — so the ~40 consumer sites across `admin_settings.go`, `diagnostics.go`,
`security_scan.go`, `ui_security.go`, `main.go` are unchanged. The one production whitebox
(`ui_security.go` reaching `globalYARA.mu`/`.dir`) became `globalYARA.Dir()`.

**Test surface (the bulk of the work).** The 502-line `yara_test.go` engine suite moved into the
package (with its `yaraRule` helper); a package-main `yaraRule` copy (`yara_testhelpers_test.go`)
serves the cross-subsystem tests. Whitebox tests of unexported internals moved into the package too:
`resolveRulePath` + `sanitizeYARAName` (out of `tier3_coverage_test.go`) and `FuzzParseYARALiteral`
(out of `fuzz_test.go`). The `SecurityScanner` tests in `final_coverage_test.go` /
`rewrite_scanner_policy_test.go` that built a rule set via `parseYARASrc`+`y.rules=` switched to the
exported `LoadSource`; the remaining tier3 RuleSet tests use the public API + `SetDir` and stayed.
Lint on the moved engine: doc comments on the 12 newly-exported config funcs; `max`→`limit`
(builtinShadow); named/`nolint`-documented results; `//nolint:cyclop,funlen` on the pre-existing
single-pass rule parser (verbatim move; decomposition is out of scope).

Validation: `go build`/`go vet ./...`, `golangci-lint` (0 issues on the new pkg + new lines), `-race`
+ determinism gate (`-count=2 -shuffle=on`) on the package and the scan/diagnostics/settings consumers
— all green. **Twelve leaves done (… `clamav`, `yara`) + three seams.** Scan cluster remaining:
`scanner.go` (DPI coordinator) and `security_scan.go` (the orchestrator hub).

### 2026-06-29 — `internal/scanner` extracted (DPI ContentScanner, thirteenth leaf)
Moved the DPI `ContentScanner` engine (regex signatures over inspected response bodies + per-host
bypass list + atomic persistence) into `internal/scanner`. Coupling was all seam: `atomicWriteFile`→
`fileutil.AtomicWrite`, `stripHostPort`→`hostutil.StripHostPort`, `logWarnf`/`sanitizeLog`→`obs`.
`matchDPIRegexWithTimeout`→exported `MatchRegexWithTimeout` (its only external user is a unit test).

**Split decision (like connlimit's tracing helpers):** the `dpiBlock` 403-writer, its `statDPIBlocked`
counter (read directly by `events`/`metrics`/`otlp`/`ui_config`/`ui_security`), and the pure
`isTextContentType` helper **stayed** in `package main` (trimmed `scanner.go`) — they are
response/observability concerns, not the scan engine, and keeping the counter in main avoided
threading an accessor through five reader sites. The shim there provides `type ContentScanner =
scanner.ContentScanner`, `dpiScanner = scanner.New(1<<20)`, a `newContentScanner` constructor var, and
a `matchDPIRegexWithTimeout` alias — so the consumers (controlplane, configversion, inspection_rules,
proxy, scan_svc, security_scan, ui) are unchanged. The one production whitebox
(`security_scan.go` reading `dpiScanner.maxBytes`) became `MaxBytes()`.

**Test surface:** persistence/cluster tests built `ContentScanner` with struct literals over the
unexported `path`/`raw`/`maxBytes`/`bypassHosts` fields across ~6 files; all switched to
`newContentScanner(...)` + the new exported `SetPath`/`Path`/`MaxBytes` accessors (reads of `.raw` →
existing `List()`). No test had to move — `matchDPIRegexWithTimeout`/`isTextContentType` tests work via
the shim. Added a focused co-located `scanner_test.go` (Set/Scan/Remove, bypass match+port-strip,
Save/Load envelope round-trip, fail-closed timeout). (Care: a too-broad sed briefly rewrote a
`CategoryStore` test's `cs.path` — reverted; that store stays in main and is legitimately whitebox.)

Validation: `go build`/`go vet ./...`, `golangci-lint` (0 issues), `-race` + determinism gate
(`-count=2 -shuffle=on`) on the package and the scan consumers — all green. **Thirteen leaves done
(… `yara`, `scanner`) + three seams. Only `security_scan.go` (the orchestrator hub) remains in the
scan cluster** — it embeds ClamAV, drives YARA + the DPI scanner + threat feed + hash cache, and is
the genuine integration point (deliberately last).

### 2026-06-29 — `internal/scanexcl` extracted; `security_scan.go` orchestrator stays in main
Mapping `security_scan.go` for extraction confirmed it is the **scan integration hub, not a leaf**:
`SecurityScanner` reaches package-main globals that are themselves *not* extracted — `globalThreatFeed`
(`threatfeed.go`) and `globalRemoteScanner` (`scan_remote.go`) — plus `globalYARA`, `dpiScanner`,
`globalScanExclusions`. Moving the orchestrator would require either cascading those two subsystems
out *or* a dependency-injection refactor (interfaces for the threat-checker / remote-scanner
collaborators). That is a real architectural initiative deserving its own ADR, **not** a mechanical
move — so the orchestrator (`SecurityScanner`, the `safe*` panic wrappers, `scanBlock`/`scanBlockConn`,
`decompressForScan`, the buffer-sizing helpers, `secScanStatusMap`, and the Prometheus counters)
**stays in `package main` as the composition-root layer**, by deliberate decision.

What *was* cleanly extractable: **`ScanExclusionStore`** — the admin-managed hash/host allowlist —
is a genuine self-contained leaf (only the `hostutil` seam + os/json). Moved to `internal/scanexcl`
as `Store` (revive-clean; `New()` constructor, `exclusionsFile` + `sortStrings` unexported). The trim
left `security_scan.go` at 549 lines (was 701). `security_scan.go` keeps the shim
(`type ScanExclusionStore = scanexcl.Store`, `globalScanExclusions = scanexcl.New()`) so the consumers
(`main.go` Load, `proxy.go` IsHostExcluded, `ui_security.go` Lists/Replace/Save, ScanBody's
IsHashExcluded) are unchanged. The whitebox tests (which built the store with `{hashes,hosts}` literals
and tested the unexported `sortStrings`) **moved** from `tier3_coverage_test.go` into the package;
`ui_security_coverage_test.go`'s isolation helper switched to `scanexcl.New()`.

Validation: `go build`/`go vet ./...`, `golangci-lint` (0 issues), `-race` + determinism gate
(`-count=2 -shuffle=on`) on the package and the scan consumers — all green. **Fourteen leaves done
(… `scanner`, `scanexcl`) + three seams.** The scan cluster's engines (`clamav`, `yara`), DPI scanner,
and exclusion store are all behind compiler-enforced boundaries; the `SecurityScanner` orchestrator
remains the recorded, deliberate composition-root integration point in `package main`.

### 2026-06-30 — three final clean leaves: `filemagic`, `clientclass`, `backupcrypt`
With the scan cluster closed at its composition root, a final sweep for *genuinely clean* leaves
(stdlib-only, no hub coupling, no whitebox-test entanglement that forces an interface refactor)
surfaced three, all extracted with the established alias-shim pattern:

- **`internal/filemagic`** (15th) — magic-byte detection (`Detect`, `CheckVsContentType` + the
  signature tables). Pure `strings`. `filemagic.go` keeps the two shim vars (`DetectMagic`,
  `CheckMagicVsContentType`); **`IsBlockedArchive` stays in main** because it consults the
  `fileBlocker` singleton (it is glue, not detection). Renames `fileMagicSig`→`Sig`,
  `DetectMagic`→`Detect`, `CheckMagicVsContentType`→`CheckVsContentType` (revive). The `filemagic_test.go`
  black-box tests stay in main via the shim; a co-located package test covers `Detect`/`CheckVsContentType`.
- **`internal/clientclass`** (16th) — the deterministic client classifier (browser / CONNECT /
  non-browser) governing captive-portal SSO eligibility. Pure `net/http`+`strings`. `client_class.go`
  keeps `type ClientClass = clientclass.Class`, the three `client*` consts, and the
  `classifyClient`/`browserRedirectEligibleLegacy` shim vars — so `proxy.go` and the auth-path tests
  are unchanged. The Plan-Freeze-#5 "no User-Agent in `Classify`" invariant moved verbatim into the
  package doc; the legacy UA heuristic stays quarantined in `BrowserRedirectEligibleLegacy`.
- **`internal/backupcrypt`** (17th) — the D1.4 AES-256-GCM + PBKDF2 backup-envelope crypto
  (`EncryptBlob`/`DecryptBlob`/`IsEncryptedBlob`/`ZeroBytes` + the AAD-bound 43-byte header). Pure
  stdlib + `x/crypto/pbkdf2`, zero hub coupling. `backup_encrypt.go` keeps the shim (consts
  `backupEncMagic`/`…MagicLen`/`…HdrLen`/`…KDFIters`/`backupPassphrase{Env,MinLen}`, the
  `errBackupDecryptOpaque` var, and the four crypto func vars) so `backup.go`/`restore.go`/
  `list_backups.go`/`main.go` and the integration test suite are unchanged. The opaque-error contract
  (wrong-passphrase and tamper are indistinguishable; header-level errors are specific because they
  leak no passphrase info) moved verbatim. The integration tests (`runBackupEncrypted`/`runRestoreDryRun`)
  **stay in main** — they exercise the crypto through the shim; a co-located package test covers the
  crypto layer directly (round-trip, opaque-on-wrong-key, ciphertext/header tamper → AAD failure,
  below-floor rejection, short-prefix sniff, `ZeroBytes`).

Each shipped one-per-commit behind the full gate (build/vet/`golangci-lint` 0-issues + diff-mode/
`-race`/determinism on the consumers). **Decision recorded — `identity.go` is deliberately NOT
extracted:** its `IdentityProvider` interface embeds `AuthProvider` (the auth-backend interface root
in `auth.go`, implemented across local/LDAP/OIDC/SAML), so moving it would drag the auth interface
graph out, and pulling *only* the `Identity` DTO would fragment a cohesive 49-line file for a 17-prod
+ 38-test alias churn at marginal benefit. It stays as a shared model in `package main` by design.

### 2026-07-02 — `internal/bandwidth` extracted (18th leaf, post-completion addendum)
With the startup-slice program finished, a re-sweep of the mid-size root files (which the original
completion sweep had only sampled) found `bandwidth.go` (403 ln) had become a **clean seam-covered
leaf**: its only couplings were `logger`/`sanitizeLog`/`atomicWriteFile` — all satisfied by
`obs`+`fileutil`. Moved the engine (token bucket, `Manager` with F10 overlap detection, D1.2-flag-F6
load validation, `HumanRate`) to `internal/bandwidth` (renames `BandwidthPolicy`→`Policy`,
`BandwidthManager`→`Manager`, `NewBandwidthManager`→`NewManager`, `humanRate`→`HumanRate`; revive).
The trimmed `bandwidth.go` keeps the alias shim + `globalBandwidth` + the `apiBandwidthPolicies`
handler (requireRole/auditEvent are main-owned); the handler's `PolicyInfo` composite literals updated
for the renamed embedded field. Test split (the recurring lesson): engine tests + the `TestSelectorsOverlap`
block (from `coverage_boost_test.go`) + the D1.2b cold-start table moved into the package (local
`assertNoTmpLeak` copy, as fileblock); the 5 handler tests stayed in main. `ConfigSnapshot`'s
`BandwidthPolicies []BandwidthPolicy` field is untouched via the alias. `go list -deps` proof: imports
only `obs`+`fileutil`. Same-sweep result for the siblings: `nodegroup.go` couples to `globalClusterStore`
(needs a nodes-view seam — candidate next), `configversion.go`/`events.go` are hubs (stay).

### 2026-07-02 — `internal/nodegroup` extracted (19th leaf)
The bandwidth-sweep sibling: `nodegroup.go`'s `globalClusterStore` coupling turned out to live in the
**API handlers**, not the engine — and the one `EnrolledNode`-typed engine method (`NodesInGroup`)
already took nodes as a parameter with no production caller. So the engine (Store, D1.2-flag-F6 load
validation, label-selector matching) moved to `internal/nodegroup` (`Group`/`Store`/`NewStore`/
`LabelsMatch`) **EnrolledNode-free by design**; `NodesInGroup` became a main-side `nodesInGroup` free
helper over the exported API (Get + LabelsMatch — behavior-identical). Handlers, `NodeGroupInfo`
(response DTO), and the singleton stay in the trimmed `nodegroup.go`; `ConfigSnapshot.NodeGroups`
untouched via the alias (embedding an alias keeps the field name, so `NodeGroupInfo{NodeGroup: g}`
still compiles). D1.2b cold-start table moved into the package; `nodegroup_test.go` stayed black-box in
main with its two `NodesInGroup` calls retargeted to the helper. Leaf proof: imports only
`obs`+`fileutil`.

### 2026-07-03 — `internal/secscan` extracted (20th; the ADR-0006 composition root)
The completion table below gated `security_scan.go` behind "a dependency-injection refactor with its
own ADR" — that is ADR-0006. Slice 1 built the injected-collaborator seams inside main; Slice 2 moved
the orchestrator (`Scanner`/`Result`/`Deps`/`New`, `DecompressForScan`, package-owned counters) to
`internal/secscan`. Key deltas vs the leaf playbook: constructor injection replaced Slice 1's
nil-fallback-to-globals (an internal package cannot read main's globals; safe because production never
reassigns `globalYARA`/`globalThreatFeed`/`globalScanExclusions` — in-place mutation only), and main
tests that swapped those globals now inject the instance explicitly (`newEnabledScanner` helper,
`newEnabledTestScanner` in-package). Main keeps the panic-safe wrappers, the remote-scanner fork, the
`yaraRuleSetMatcher` toggle adapter, HTTP block helpers, the status map, and the singleton wiring
(trimmed `security_scan.go`). Leaf proof: imports `clamav`+`hashcache`+`obs` (+`fileutil` transitive).
See `docs/adr/0006-security-scanner-di.md` for the full decision record.

### 2026-07-03 — `internal/pac` extracted (21st leaf)
The PAC engine (`Config`/`Store` with Load/Get/Set persistence, `GeneratePAC`, the CIDR helpers) moved
to `internal/pac`; the HTTP handlers (`apiPACConfig`, `servePACFile`), route registration, and the
`pacStore` singleton stay in the trimmed `pac.go` shim. Design improvement folded in (lesson 3): the
`pacDefaultProxyPort` package global became a Store field (`SetDefaultPort`/`DefaultPort`, set once by
the startup slice), and the startup test's mutex/field pokes were replaced by store-owned
`Snapshot`/`Restore` test support. `pac_test.go` moved wholesale (pure engine suite; the two
fallback-port tests now set the per-store default instead of the global). The exclusions loop was
extracted to a `writeExclusion` switch helper (nestif). Cluster PAC sync (`controlplane.go`) is
untouched — it uses `pacStore.Get`/`Set` through the alias. Leaf proof: stdlib-only (no internal deps).

### 2026-07-03 — `internal/plugin` extracted (22nd leaf)
The middleware plugin API (Middleware contract, Decision, the global chain, panic-safe Decide /
OnResponse dispatch) moved to `internal/plugin`; `plugin.go` is a pure alias shim (RegisterPlugin /
pluginDecision / pluginOnResponse for the proxy+SOCKS5 hot paths and external plugin authors). Tests
that assigned the `plugins` slice directly now go through the new `Replace(ps) []Middleware` swap API
(lesson 3 — the chain is package-owned; Replace is documented as test-support, not safe under
traffic, matching the pre-extraction lock-free-read contract). Leaf proof: imports `obs` only.

Same-sweep verdict for the sibling candidate: `blocklist_feed.go` needs TWO seams before it can move —
a domain-merger interface over the `Blocklist` hub and an SSRF-guard seam (`isPrivateHost` /
`ssrfSafeDialContext` are main-owned and under the CodeQL inline-guard convention in CLAUDE.md, so
relocating them needs a deliberate design pass, not a mechanical move). Deferred with this note as
the map.

### 2026-07-03 — `internal/ocsp` extracted (23rd leaf)
The OCSP revocation engine (`Checker` — renamed from `OCSPChecker` per revive — with the TTL'd verdict
cache, responder query pipeline, `VerifyPeerCertificate` callback, and `resolveIssuer`) moved to
`internal/ocsp` (the `golang.org/x/crypto/ocsp` import is aliased `cryptoocsp` inside). Deliberately
stays in main: `ConfigureTLSConfigOCSP`/`ConfigureTransportOCSP` — they are upstream-transport
ownership glue under the P5.3 / S6 contract (must only run inside `swapUpstreamTransport` closures)
and reference the `globalOCSP` singleton, now built via `ocsp.New()`. The whitebox engine tests moved
wholesale into the package; the two `ConfigureTransportOCSP` tests stayed in the trimmed main
`ocsp_test.go`; `edge_audit_test.go`'s literal-construction tests were retargeted (`ocsp.New()`; the
CacheLen-with-seeded-entries assertion relocated into the package suite rather than growing exported
test API). Leaf proof: imports `obs` + `x/crypto/ocsp` only.

### 2026-07-03 — `internal/uitls` extracted (24th leaf)
The admin-UI self-signed certificate generator (`SelfSigned` — baseline/interface/hostname SANs,
CULVERT_PUBLIC_IP, cloud-metadata public-IP detection with the IMDSv2→v1 fallback) moved to
`internal/uitls`. Design improvement folded in: the `uiExtraSANs` global is no longer read by the
engine — main's `selfSignedTLS()` wrapper passes it as a parameter (the ui_extras startup slice and
admin-settings persistence keep owning the var in the trimmed `tls.go`). Moved-code complexity paid
down by decomposition, not suppression: `collectSANs`, `appendEnvPublicIPs`, and `imdsv2Token` helpers
(gocognit/cyclop/nestif); metadata requests use `http.NoBody`. No SSRF-guard coupling — the IMDS
endpoints are deliberately link-local and use a dedicated 2s-timeout client. Leaf proof: imports `obs`
only.

### 2026-07-03 — `internal/ssrf` seam built (4th seam; unblocks blocklist_feed)
The SSRF guard moved out of `proxy.go`/`security.go` into `internal/ssrf`: the private-CIDR table,
`PrivateIP`/`PrivateHost` (with the 30s-TTL DNS verdict cache — negative results uncached, fail-closed),
the connect-time `Control` (DNS-rebinding TOCTOU closure), and `SafeDialContext`. package main keeps
thin wrappers so every call site is UNCHANGED: `isPrivateIP`/`isPrivateHost` funcs and the
test-swappable `ssrfSafeDialContext`/`ssrfControl` vars (security.go); the tick loop calls
`ssrf.CacheCleanup()` (connlimit_startup.go). Test pokes at `ssrfDNSCache.mu/.entries` were replaced by
`CacheStore`/`CacheDelete` test support (lesson 3); `qa_gate_test.go`'s direct `ssrfSafeDialer.Dial`
retargeted onto the DialContext var. **CodeQL contract note:** main call sites still see the
`url.Parse + scheme + isPrivateHost()` inline pattern — the wrapper adds one call level; the CI CodeQL
gate on this commit is the empirical verdict, and the follow-on `internal/blocklistfeed` extraction
waits for it. Package suite: 96% coverage (CIDR table incl. the IPv4-mapped-IPv6 case, cached verdicts,
Control fail-closed cases, cache cleanup).

### 2026-07-03 — `internal/blocklistfeed` extracted (25th leaf; the two-seam candidate)
The remote blocklist syncer moved to `internal/blocklistfeed` — the extraction ADR-0002 had deferred
pending TWO seams, both now in place. (1) The `Blocklist` hub coupling is inverted to a `Merger`
interface (`MergeFromLines`) that `*Blocklist` satisfies — the hub stays in main, the engine depends
only on the narrow contract. (2) The SSRF guard is the `internal/ssrf` seam (built in the prior
commit): `fetchFeedLines`/`feedCheckRedirect` call `ssrf.PrivateHost` + `ssrf.SafeDialContext`
inline — the same defense, now importable. main keeps the `blFeedSyncer` singleton (main.go), the
`newBlocklistSyncer` constructor + `blFeedDefaultInterval` alias, and the admin API handler
(ui_policy.go). **Test-seam consequence, recorded as a lesson:** the engine now calls the ssrf seam
directly instead of the swappable main-package `ssrfSafeDialContext` var, so two integration tests
that swapped that var broke — the loopback-allow helper was retargeted onto `ssrf.AllowLoopbackForTest()`
(drops loopback from the guard table, covering BOTH the host check and the connect-time control), the
redirect-block test now targets a non-loopback private IP (10.0.0.1, still caught), and the
dialer-wiring test became a direct `feedCheckRedirect` unit test in the package. Package suite (fake
Merger + httptest): 70% coverage. Leaf proof: imports `obs` + `ssrf` only.

### 2026-07-03 — `internal/feedsync` extracted (26th leaf) + ssrf-seam CI verdict recorded
**Seam verdict:** the CI code-scanning gates (CodeQL + gosec, both the code-scanning checks and the
SAST jobs) are GREEN on the `internal/ssrf` seam and the `internal/blocklistfeed` extraction — the
one-extra-call-level wrapper does NOT break the inline-guard recognition. The convention holds for
future extractions: engines call `ssrf.PrivateHost`/`ssrf.SafeDialContext` directly inline.

The UT1 URL-category syncer moved to `internal/feedsync` (`Syncer`/`New`, tarball download/parse,
the ingest map). Depends on `internal/catdb` (already extracted) + `obs`. Deltas: the UT1 sync-failure
counter is package-owned (`SyncFailures()`, read by `urlcat_metrics.go` — same pattern as secscan's
counters); `ut1CategoryMap` consumers (UI feed-backed badge, startup category seeding) go through the
exported `MappedCategories()` values accessor instead of the mutable map; the metrics test's
lastSync/totalDomains field pokes became `SeedStats` test support (lesson 3). The whole
`catdb_feedsync_test.go` engine suite moved in-package (84% coverage); `feedUserAgent` stays owned by
`threatfeed.go` with the package keeping its own copy of the value. Leaf proof: `catdb`+`obs` only.

### 2026-07-03 — `internal/saasfeed` extracted (27th; executed from the recorded design)
Executed post-#529 on the restarted branch, exactly per the five-seam map below: the catStore merge
became main's `mergeSaaSCategories` closure (additive semantics + Save-if-added pinned by a new main
test); the lifecycle provider is injected (`Deps.Lifecycle` = `resolveLifecycleCtx`, preserving the
P6.1 UC-3 Done() contract — the lifecycle regression test constructs via `saasfeed.New` and still
drives the real appLifecycleCtx path); the client is injected (main builds it on
`ssrf.SafeDialContext`); the SaaS sync-failure counter is package-owned (`SyncFailures()`); test
construction goes through `New`/`SeedStats`/`SetFeedURLForTest`. The engine suite moved in-package
(fetch/parse/dispatch, nil-merge safety); `TestCategoryStore_GetByName` + the category-groups API
tests stayed in main; `GetByName` itself stays in the shim (CategoryStore is policy-engine-owned).
Leaf proof: imports `obs` only.

### 2026-07-03 — `internal/sslbypass` extracted (37th; policy.go Phase B) + `hostutil` gains MatchFQDN
The open design point resolved first: the FQDN glob matcher has two engine consumers (policy rule
matching + the bypass matcher) with their agreement pinned by policy_bypass_security_test.go, so a
private copy was off the table — `matchFQDN`/`matchFQDNNorm` moved to **hostutil.MatchFQDN /
MatchFQDNNorm** (hostutil already owns NormalizeHost, their only dependency; Phase C's policy
engine will consume them from there too). main keeps them as thin wrapper FUNCTIONS — not func
vars — so the per-rule call in Evaluate's hot path stays direct and inlinable. The bypass engine
then moved verbatim to `internal/sslbypass`: `pattern` (compiled glob/`~`-regex), `Matcher`
(zero-value valid), Set/Load/Save (AtomicWrite durability)/Add/Remove/List/Matches (per-CONNECT
hot path, resolveSSLAction). main keeps: the `sslBypass` singleton via `SSLBypassMatcher =
sslbypass.Matcher` alias, /api/ssl-bypass handlers, the inspection-rules startup slice, cluster
sync, rollback. Test seams `Path()`/`SetPathForTest` replaced the `sslBypass.path` pokes
(Bucket-4 durability + cluster apply-persist tests); six engine tests consolidated in-package
(policy_test.go's glob/regex/Set/LoadInvalidJSON + rewrite_scanner_policy_test.go's
AddRemove/compile — the compile test grew an invalid-regex case). Gates: full suite, `-race`
over the proxy-e2e/policy/bypass scope, shuffled determinism ×2 (package + main), lint 0 issues,
leaf proof exactly `fileutil`+`hostutil`. Remaining in policy.go: the Phase C engine (PolicyStore/
Evaluate/matchers) — design + adversarial review required before execution, per the program note.

### 2026-07-03 — `internal/urlcat` extracted (36th; policy.go Phase A, executed from the design)
Executed exactly per the program design below. The engine moved verbatim: `Entry`/`Store` +
lowercase host index, `Load`/`Save` (fileutil.AtomicWrite durability comment preserved), `All`/
`ReplaceAll`/`Set`/`Delete`/`AddHost`/`RemoveHost`, `GetByName` (moved home from saas_feed.go),
`DefaultEntries` + the `default_categories.json` embed (file moved into the package), and the two
internals-reaching free functions became methods: `matchCategoryInStore` → `Store.MatchesHost`
(hot path — policy Evaluate's category check), the admin tier of `lookupHostCategory` →
`Store.LookupHost` (entry-scan preserved verbatim for the original-case matchedBy contract).
`Category` + constants moved (`urlcat.Social` …) with typed-const aliases (`CategorySocial` etc.);
`URLCategory`/`CategoryEntry`/`CategoryStore` are type aliases; `newCategoryStore = urlcat.New`
(the `defaultCategoryEntries` alias was dropped — its last user moved with the tests). The
TWO-TIER fusion (`matchCategory`/`lookupHostCategory` over catStore + communityDB) stays in main
as designed. Test seams: `Path()` accessor + `SetPathForTest` — snapshotCatStore, the Bucket-4
durability test, and the cluster apply-persist test dropped their `cs.path`/`rebuildIndex` field
pokes onto them. catstore_test.go moved in-package wholesale (+ GetByName's test; 76% coverage).
Moved-code lint (4 gocritic nestingReduce/equalFold) fixed by style, not suppression. Gates: full
suite, `-race` over policy/category/proxy-e2e scope, shuffled determinism ×2, leaf proof exactly
`fileutil`+`hostutil`. Next: Phase B (`internal/sslbypass`).

### 2026-07-03 — Core-hub survey (proxy / controlplane / policy) + the policy.go decomposition program (Phases A–C)
With store.go closed, the three remaining hubs were mapped BEFORE any move (sizes as of today):

- **proxy.go (1847 lines, 38 funcs) — request-path composition root. Extraction REJECTED.**
  Every handler (`handleRequest`/`handleHTTP`/`handleTunnel*`/`handleWebSocket`) orchestrates the
  auth resolver, policy evaluation, scanning, cert manager, relays, and telemetry singletons —
  that IS the composition. DEBT-002 already decomposed the mega-handlers into in-file stage
  functions (resolveRequestAuth, preDispatchBlocked, applyPolicyDecision, recordRequestTelemetry),
  which is the right structure for this file. The movable crumbs are pinned or worthless:
  `sanitizeLog` must stay call-site-recognisable for CodeQL (CLAUDE.md convention), the relay-buf
  pool and hop-header helpers are ~30 lines of stdlib. No slice meets the value bar.
- **controlplane.go (2102 lines, 65 funcs) — cluster-sync hub. Core extraction REJECTED.**
  `ConfigSnapshot` is the cluster sync CONTRACT: it references the DTOs of nearly every subsystem
  by design, so moving it just relocates the hub. The gRPC service methods and the DP client
  orchestrate main singletons (stores, HA state, cert manager) — composition, not engine. The
  three in-file aggregators (`rateLimitAggregator`, `revocationAggregator`, `clusterAuditLog`)
  are self-contained engines but small (~150 lines total) and bound to shared DTOs — **DEFERRED**
  (not worth a package today; revisit only if cluster work grows them).
- **policy.go (1374 lines, 57 funcs) — THREE engines in one file → phased program (mirrors
  store.go).** Order A → B → C, one slice per commit, full gates each:
  - **Phase A — `internal/urlcat` (CategoryStore, ~250 lines).** Package owns: `Entry`
    (CategoryEntry), the `Store` with its lowercase host index, `DefaultEntries()` + the
    `default_categories.json` embed (moves into the package), `GetByName` (currently defined in
    saas_feed.go — moves home), and two free functions that today reach into store internals
    become methods: `matchCategoryInStore` → `Store.MatchesHost`, the admin tier of
    `lookupHostCategory` → `Store.LookupHost` (returns the original-case name + matched pattern —
    move verbatim, it deliberately scans entries not the index). `URLCategory` + the `Category*`
    constants move with aliases. The TWO-TIER fusion (`matchCategory`, `lookupHostCategory` over
    catStore + communityDB) STAYS in main — it composes two singletons. Deps/leaf target:
    `hostutil` + `fileutil`. Test seam: `SetPathForTest` (snapshotCatStore needs an empty store
    with a tmp save path; `Load` would seed defaults). ~9 production files keep compiling via the
    `catStore` singleton alias.
  - **Phase B — `internal/sslbypass` (SSLBypassMatcher, ~150 lines).** compile/Set/Load/Save/
    Add/Remove/List/Matches. `Matches` sits on the per-CONNECT hot path (resolveSSLAction) →
    -race over proxy scope + traffic smoke, per the Phase A/C precedents. Open design point to
    settle at execution: glob patterns delegate to the policy engine's `matchFQDN` — either the
    FQDN glob matcher moves to `hostutil` as a shared primitive or the package keeps a local
    copy; decide by mapping matchFQDN's other callers.
  - **Phase C — `internal/policy` (PolicyStore + PolicyRule + Evaluate + matchers, ~900
    lines).** The real engine and the widest DTO in the repo (`PolicyRule` reaches 73 files —
    alias keeps source compat; 240-byte struct, index-based range convention preserved). FOUR
    runtime lookups need inversion seams: `geo.LookupCached` (fail-closed contract must move
    verbatim), `globalCategoryGroups.MatchesHost`, `globalProfileStore.GetByName` (dynamic
    profiles beat the legacy map), and the two-tier category match (one `SetCategoryMatcher`
    seam over the main-side fusion). Stage-1 coupling: `Evaluate` filters on `ruleTypeOf`
    (authpolicy.go — the frozen `defaultAuthOutcome` contract owns that vocabulary), so either
    the RuleType vocabulary moves with the rule or the filter becomes an injected predicate —
    **Phase C requires its own recorded design + adversarial review before execution** (store.go
    Phase C precedent). Per-rule `HitCount` is an atomic on the rule pointer and moves fine.
    Hot path per request → full hot-path gate.

### 2026-07-03 — `internal/reqlog` extracted (35th; store.go Phase C, executed from the design) — store.go program CLOSED
Executed exactly per the recorded design below, after PR #533 merged (sequencing verdict honoured).
The engine moved verbatim: ring (`MaxRing` 5000), persistent JSONL layer (`Init`/`Close`/the write
half of `Add` with the count-once-log-first contract), `ReadPersistent` + TTL read cache (the
serialised-parse trade moved untouched, per review verdict 2), `WriteErrors`/`SkippedLines`
accessors, `LevelForStatus`. `Entry = logstore.Entry` (alias, no DTO package). The single inversion
point `SetHistory` is wired in store.go's init — the closure performs the same
`globalLogStore.Load().Add(e)` atomic load the inline code did (logStore.Add is nil-receiver-safe),
so the hot path is behavior-identical. main keeps: `AuthLogFields`+`applyTo` (frozen AuthOutcome
contract), `persistLogEntry` + the recordRequest* fan-out, the API handlers, ts/stats, topHosts.
Aliases: `levelForStatus`/`logAdd`/`logGet`/`initRequestLog`/`requestLogReadPersistent`; the
`maxLogs`/`requestLogMaxPersistentReturn` const aliases were DROPPED (their last users moved with
the tests — callers use `reqlog.MaxRing`/`MaxPersistentReturn`). Counter reads in ui_config/ha/
events went through the accessors; the shutdown hook uses `reqlog.Close()`. Test seams as designed
(`SwapRingForTest`, `SetWriterForTest`, `SetFilePathForTest`, `SwapPersistenceForTest`,
`ResetForTest` with resetRequestLogState's exact no-restore semantics, `PinCacheForTest`/
`ExpireCacheForTest`, `PersistActive`/`FilePath`); main's `isolateLogRing`/`resetRequestLogState`
became thin wrappers, and the three remaining inline ring-poke sites (loguri, edge_audit,
coverage_boost) were rewired onto the helper. Twelve engine tests consolidated in-package (88%
coverage) — the ring order/capacity pair now exercises the REAL ring instead of store_test.go's
local reimplementation (`newTestLog`, deleted). Gates: full suite, `-race` over the proxy/record
scope + the proxy_traffic_e2e suite (hot-path verdict 1), shuffled determinism ×2, leaf proof
exactly `fileutil`+`logstore`+`obs`. **store.go is now a composition root by classification**
(stats/ts counters, auth `Config`, recordRequest* orchestration) — the store.go decomposition
program closes with Phases A (blocklist), B (audit), C (reqlog) shipped.

### 2026-07-03 — store.go Phase C (`reqlog`) DESIGNED + adversarially reviewed (execute after PR #533 merges)
The request-log layer (~230 lines) is the LAST decomposable slice of store.go; executing it closes
the store.go program. Recorded design for `internal/reqlog` (35th):
- **Package owns:** the in-memory ring (`maxLogs` 5000, `Add`/`Get`), the persistent JSONL layer
  (`Init(path, maxMB)` on fileutil.RotatingFile, `Close`, the write half of `Add` with the
  count-once-log-first write-error contract), `ReadPersistent` (bounded amortized parse, 1 MB
  scanner buffer, 20k cap, rotated-archive intentionally skipped) with its TTL read cache
  (path-keyed, serialised parse — pre-existing documented design, moves verbatim), the
  `WriteErrors()`/`SkippedLines()` counter accessors (read by /metrics, /api/stats, /healthz), and
  `LevelForStatus`.
- **Entry type:** `logstore.Entry` (import) — the history store owns the wire/SIEM contract; a
  neutral DTO micro-package was considered and REJECTED (churn without benefit). Leaf proof
  target: `fileutil` + `logstore` + `obs`.
- **One inversion point:** `SetHistory(func(Entry))` — main wires
  `func(e){ globalLogStore.Load().Add(e) }`, preserving the lock-free runtime enable/disable swap
  exactly (the closure performs the same atomic load the inline code does today).
- **Stays in main:** `AuthLogFields`+`applyTo` (writes exported alias fields; welded to the frozen
  `AuthOutcome` contract), the `recordRequest*`/`recordStats`/`persistLogEntry` fan-out
  (orchestrates stats globals + syslog `WriteRequest` + this layer), topHosts, the ts/stats
  counters.
- **Test seams:** `SwapRingForTest` (replaces `isolateLogRing`'s pokes), `SetWriterForTest`,
  `PinCacheForTest`/`ExpireCacheForTest` (replace the `reqLogReadCache.expires` pokes), and a
  `ResetForTest` matching `resetRequestLogState`'s exact semantics — verify each helper's
  snapshot-vs-clear behavior at execution before substituting.
- **Adversarial review (recorded verdicts):** (1) hot path — `logAdd` runs per request; the only
  change is the history hook replacing an inline atomic load with a closure doing the same load —
  gate with `-race` over the proxy scope + traffic smoke, per the Phase A precedent. (2) The
  serialised-parse read cache is a deliberate pre-existing trade (documented in code) — do NOT
  "improve" it mid-move. (3) SSE/C2c consumers are alias-covered (`logGet`). (4) Value is thinner
  than Phases A/B — justified as program completion, not standalone. (5) SEQUENCING: execute only
  after PR #533 merges; widening an open 17-commit PR trades review quality for nothing.
  After Phase C, store.go = stats/ts + auth `Config` + record* orchestration — composition root by
  classification; the store.go program CLOSES.

### 2026-07-03 — `internal/audit` extracted (34th; store.go Phase B) + fileutil gains RotatingFile
The audit engine moved to `internal/audit`: the bounded ring (`MaxRing` 500, saturation pitfall
preserved in the doc comment), append-only JSONL persistence with rotation, the paginated/
time-filtered reads (`Get`/`GetMemory`/`GetPersistent` — the memory/persistent filter+paginate
duplication collapsed into shared `filterByTime`/`paginate` helpers), and the DP→CP push queue
(`Drain`/`Requeue`, cap 1000). Two inversion points: **SetSIEM** (main's init wires a closure over
`globalSyslog` — runtime-configured, read at call time; `syslog.WriteAudit(any)` was already
decoupled) and **SetDPMode/DPMode** (replaces main's `clusterRoleIsDP` atomic; set by the cluster
wiring, read by diagnostics/ui_cluster). `fileutil` gained **RotatingFile** (moved from logger.go —
the audit engine and the system/request logs share it; logger.go keeps `rotatingFile`/
`newRotatingFile` aliases so its call sites are unchanged; the three rotating-writer tests moved
in-package). main keeps: `auditEvent`/`auditEventDiff` (actor enrichment), the C2c middleware
(observes the wrappers, untouched), the API handlers, the CP push loop, and `InitAuditLog`/
shutdown-close as thin wrappers. Whitebox test state pokes across ~10 main files were replaced by
five named seams (`ResetForTest`/`SwapRingForTest`/`SetPersistForTest`/`ClearPersistForTest`/
`PersistActive`); six engine tests consolidated in-package (77% coverage). Leaf proof:
`fileutil` only.

### 2026-07-03 — `internal/blocklist` extracted (33rd; store.go Phase A, executed from the design)
Executed exactly per the design below. The full engine moved verbatim (matcher, mode, Load/Save +
four sidecars, exceptions, manual/bulk durability paths, feed attribution, MergeFromLines +
`NormalizeLine`); `IsBlocked` is byte-identical under the same RWMutex. `New()` is the only
constructor; NO test-support methods were needed — every field-literal construction across the
~20 test files rebuilt on the public API (`New()` + `Add`/`Load(fixture)`/`MergeFromLines`), per
the design's stability preference. Five engine test files moved in-package wholesale
(blocklist_test, addmanual_persist, coldstart sidecars, normalize/attribution/cascade, the
MergeFromLines/mode set from totp_extra) at 85% package coverage; the API-handler tests
(cleanup-unattributed gate, bulk-add) and the CP snapshot-apply tests stayed in main on public
API. Two pre-existing comment misorders (Store/Entry docs, ClearAll/MergeFromLines) were
straightened as revive surfaced them. Leaf proof: `fileutil`+`hostutil`+`obs` only. Gate included
`-race` over proxy/socks5/blocklist and the traffic-e2e smoke per the hot-path plan.

### 2026-07-03 — store.go decomposition program OPENED; Phase A (`blocklist`) DESIGNED
`store.go` (2,324 lines) is five engines sharing a file: (1) uptime/stats/timeSeries hot-path
counters, (2) the request-log ring + JSONL persistent log + read cache, (3) the audit ring +
persistent log + DP→CP push queue, (4) the **Blocklist engine** (~830 lines), (5) the auth cache +
`Config` (UI users/TOTP/`defaultAuthOutcome` — the frozen contract, stays). Phase A extracts the
Blocklist; the ring/audit engines are later phases (their record* fan-out and DP-queue coupling
need their own passes); the counters stay hot-path-local.

**Phase A design — `internal/blocklist` (33rd), execute on next unit:**
- **Shape:** `Blocklist` → `blocklist.Store` (main alias `Blocklist = blocklist.Store`,
  `BlocklistEntry = blocklist.Entry`, `var bl = blocklist.New()`). `New()` returns the
  initialized-maps zero state (mode default "block"). The ENTIRE method set moves verbatim:
  mode (Mode/SetMode + sidecar), Load/Save (main file + .mode/.manual/.exceptions/.sources
  sidecars, fsynced via fileutil.AtomicWrite), the O(labels) exact/wildcard matcher
  (isListed/isExcepted/IsBlocked), Add/AddManual/AddManualBulk/Remove/ClearAll,
  ReplaceFeedEntries, the exceptions API, List/ListWithSource/Count, the feed-attribution API
  (SnapshotFeedSources/RestoreFeedSources/RemoveByFeedSource/CountByFeedSource/
  RemoveUnattributedFeedEntries), MergeFromLines + normalizeBlocklistLine (exported as
  `NormalizeLine`; hostsFileBoilerplate + looksLikeHostname move with it).
- **Deps:** `hostutil.NormalizeHost` (already a main wrapper — engine calls the package
  directly), `obs` (Printf/Sanitize; `logWarnf`→`obs.Warnf` under the accepted always-emit
  precedent), `fileutil.AtomicWrite`. Pure leaf; no inversion seams needed.
- **Hot path (the reason this is a design pass, not a casual slice):** `IsBlocked` is called from
  `proxy.go` and `socks5.go` per request. It moves VERBATIM — same RWMutex, same map probes; the
  package boundary adds nothing to the lock or allocation profile. Gate additions beyond the
  standard set: `-race` over the proxy/socks5 test scope and the traffic-e2e smoke suite.
- **Production construction sites: NONE beyond the singleton.** The CP snapshot apply already goes
  through `ReplaceFeedEntries` + `Save` (the P3.4 fix removed the wholesale `bl = newBL`
  construction), so no snapshot-constructor API is needed.
- **Consumers** (all method calls through `bl`, alias-covered): ui_policy (16), ui_config (12),
  configversion (9 — capture/apply, stays per the REJECTED verdict), controlplane (4),
  blocklist_startup (3), main/proxy/socks5/metrics/otlp (1–2 each). `blocklist_feed.go`'s
  blocklistfeed.Merger adapter is UNCHANGED in this slice (possible follow-up: blocklist.Store
  satisfying the Merger directly, both being internal packages — do NOT fold into Phase A).
- **Test surface (~20 files; the widest since ssrf):** engine suites move in-package
  (blocklist_test.go's matcher/exception/normalize cases, blocklist_normalize_test.go — its two
  `&Blocklist{...}` literals become `New()`+Load); integration tests stay in main on the alias,
  with the `&Blocklist{...}` field literals in blocklist_apply_persist_test.go (×3) and
  blocklist_feed_multi_test.go rebuilt on `New()` + `Load(tmpfile)` (both only seed maps + path —
  Load from a written fixture reproduces the state through the public API). 15 direct field pokes
  across main tests to rewire; count them at execution and prefer public-API rebuilds over new
  test-support methods (add `SetPathForTest` ONLY if a fixture-file rebuild is genuinely awkward).
- **Validation plan:** the standard full gate + `-race` on proxy/socks5/blocklist scopes +
  `proxy_traffic_e2e` smoke + shuffled determinism on main + package.

## Engine-Extraction Wave COMPLETE (second wave) — 2026-07-03

With `logstore` (32nd), the engine-extraction wave that followed the original leaf sweep is
**complete**: every root file that carries an extractable engine has been extracted, and every
remaining root file has a considered classification. A final survey (size-ordered, all root `*.go`
read or previously mapped) leaves four classes, none of which is a next "slice":

1. **Composition root by nature** — `configversion.go` (recorded REJECTED verdict below),
   `diagnostics.go` (viewer API handlers), `admin_settings.go`, the `ui_*.go` handler files, the
   `*_startup*.go` slices (shipped program, do not re-extract), the `*_vars.go`/shim files.
2. **Subsystem programs with their own roadmaps** — the CDR/Sluice cluster (`cdr*.go`,
   `cdrstore.go`; contains the Sluice gRPC dep but is a multi-file program wired into the proxy
   hot path), release management (`release_*.go`, D1.6d), backup/restore/cleanup (D1.3/D1.5),
   update/update_cluster (D1.6, DEBT-008).
3. **Security-sensitive low-value** — `session.go`/`auth*.go` (HMAC cookies, providers; welded to
   the frozen `defaultAuthOutcome` contract; extraction churn > boundary value today).
4. **The core four hubs + hot-path satellites** — `store.go`, `policy.go`, `proxy.go`,
   `controlplane.go`, plus `upstream.go`/`ha.go`/`enrollment.go` (the S6 upstreamTransport
   contract and ADR-0004 HA state live here). These need ADR-grade design passes each;
   `proxy.go` deliberately last, per the original decision.

**Wave tally: 32 packages + 4 seams** under `internal/`, every one behind the full validated gate
(build/vet, lint-vs-main 0, full suite, -race, shuffled determinism, leaf proof). Next
decomposition work starts with a design pass on `store.go` (the request-log ring / stats /
audit-ring hub) — a new program, not a continuation of this sweep.

### 2026-07-03 — `internal/logstore` extracted (32nd; executed from the recorded design)
Executed exactly per the design note below. The engine (open/TTL/encryption variants, key layout,
async writeLoop, Query/Stats/retention, PurgeAll, EncKey/ErrEncMismatch, the priority-aware
deletion passes from logguard.go as `CleanupBytes`+`deletePass`, the dropped/pruned counters with
`Dropped()`/`Pruned()` accessors) and the `Entry` DTO (main alias `LogEntry = logstore.Entry`;
`LowPriority` aliased too) moved to `internal/logstore`. The two designed inversion points shipped
as designed: the **minimal-mode hook** is an `OpenTTL` parameter (Add's emergency skip reads main's
logguard state through it; pinned in-package by `TestAdd_MinimalHook` and in main by the
minimal-mode integration test whose `newTestLogStore` wires the real `minimalMode`), and
**`RunRetention` returns (freed, count, levels)** so main's `runDiskGuard` records the
audit/pressure event — the engine owns deletion, main owns observability state.
`handleDiskCritical` became a function taking the store (methods can't live in main anymore),
reading `BytesUsed()`/calling `CleanupBytes`. main keeps the singleton + lifecycle
(enable/disable/purge, desired-retention memory, dir/passphrase startup state), the logguard
orchestrator, the retention API, and the health/usage/estimate views. Engine tests (9 from
logstore_test + the 2 deletion-pass tests + LowPriority) moved in-package (78% coverage);
lifecycle/API/guard tests stayed in main with `logstore.OpenTTL` retargets. Leaf proof: `obs` only
(BadgerDB contained — second Badger package after catdb).

### 2026-07-03 — `configversion.go` mapped; extraction REJECTED (deliberate keep)
Full design pass on the 819-line hub. Three layers: (1) the numbered-version file store
(`v{N}.json` naming, seq scan, prune-at-50, corrupt-file skip) — generically extractable; (2)
`captureConfigBackup`/`applyConfigBackup`/`validateConfigBackup` — composition-root logic by
NATURE: it reads/writes 12 main store singletons (`bl`, `policyStore`, `rewriter`, `sslBypass`,
`dpiScanner`, `fileBlocker`, `ipf`, `rl`, `pacStore`, `globalCategoryGroups`, `catStore`) under
the Finding 10.3 three-surface contract and the documented apply-order/nil-skip invariants; (3)
the diff engine — typed over policy-engine structs (`PolicyRule`, `RewriteRule`, `CategoryGroup`,
`CategoryEntry`). Verdict: **stays in main deliberately.** Layer 2/3 belong to the composition
root until the core-hub (store/policy) decomposition changes type ownership; layer 1's ~150-line
mechanical value is outweighed by its blast radius — **14 test files** swap the
`configVersionsDir`/`configVersionSeq` package vars directly and would all need rewiring onto new
seams. Re-evaluate layer 1 only if a second consumer of numbered-snapshot storage appears.

### 2026-07-03 — `logstore` mapped; extraction DESIGNED (next unit)
The Badger-backed request-log history (`logstore.go`, 769 lines) is the strongest remaining
candidate — same BadgerDB-containment rationale as `catdb`. Recorded design:
- **`internal/logstore`** owns: the store engine (`logStore` → `logstore.Store`: open/TTL/encrypted
  variants, key layout, async `writeLoop`, `Query`/`Stats`/`RunRetention`/`SetRetention`, purge,
  the pbkdf2/AES encryption-key handling), the **priority-aware deletion passes from logguard.go**
  (`cleanupBytes`/`deletePass` — pure Badger ops, move as methods), and the dropped/pruned
  counters (package-owned accessors; read by events.go's /metrics exposition — the feedsync
  counter pattern).
- **`LogEntry` moves INTO the package** as `logstore.Entry` with a main alias (`type LogEntry =
  logstore.Entry`) — it is a wire DTO (the alerts.Payload precedent), currently defined in
  store.go with ~90 uses across main that the alias covers unchanged. `logEntryLowPriority`
  moves with the deletion passes.
- **main keeps**: the `globalLogStore atomic.Pointer` singleton + enable/disable/purge
  orchestration (admin-settings + API wiring), the logguard ORCHESTRATOR (`runDiskGuard`,
  `handleDiskCritical`, the `logGuard` GUI-state struct, `diskUsage` syscall helper, minimal-mode
  + `SetLogLevel` coupling, `auditSystem` — audit ring is main-owned), the retention admin API,
  and the health/usage/estimate view helpers (they read main state).
- **Test surface**: logstore_test.go (engine → in-package), logguard_test.go (split: deletion-pass
  tests in-package, guard-orchestration in main), loguri/store_test LogEntry uses covered by the
  alias. Deps: obs + fileutil(?) + badger — a contained-dependency leaf like catdb.

### 2026-07-03 — `internal/sse` extracted (31st; second zero-dependency leaf)
The SSE client hub moved out of `events.go`: `sse.Hub` owns registration under the connection cap,
`Broadcast` with B21 slow-client eviction, and the observability counters. Deltas: the cap
(`sseMaxClients` package var) and both counters (`statSSEEvicted`/`statSSERejected`) became
**per-Hub** state — single production hub ⇒ identical behavior, and the cap accessor pair
(`SetMaxClients`/`MaxClients`) is the seam the planned admin-configurable limit will use; `Rejected`
stays handler-owned (`AddRejected` — the handler owns the 503, so it owns the count). main keeps the
dashboard broadcaster (payload assembly reads main's stats globals), `apiEvents` (auth, framing,
mid-stream revalidation), and the /metrics exposition (reads `Evicted()`/`Rejected()`). Test seams
`ClientsForTest`/`EvictForTest` replaced the handler test's `hub.mu`/`hub.clients` whitebox pokes;
the engine tests (coverage_test trio + eviction-counter) moved in-package (84% coverage) and the
cap test now sets the per-hub cap instead of the atomic package var. Leaf proof: **zero Culvert
imports** (second pure-stdlib leaf in a row).

### 2026-07-03 — `internal/bootstrap` extracted (30th; zero-dependency leaf)
The one-click DP-node bootstrap generators moved to `internal/bootstrap`: the shell-script and
docker-compose templates (`RenderScript`/`RenderCompose`), image-reference resolution
(`Image`/`UpdaterImage` take the registry-settings path + version as params — the file read moved
with them), and the pure request-derivation helpers (`ExtractToken`, `BaseURL`, `EnrollmentAddr` —
main's `trustForwardedHeaders` global becomes a parameter). The HTTP handlers stay in main: they
validate the single-use enrollment token against `globalClusterStore` and assemble the enrollment
URL from cluster state (`clusterRole`, `globalClusterCA`) — core-hub singletons. `ui_cluster.go`'s
enrollment-token handler retargets its `cpBaseURL` call onto `bootstrap.BaseURL`. Helper + image
tests moved in-package (no more `trustForwardedHeaders` global swaps — the param replaces them; the
registry-override and corrupt-settings branches gained coverage; 98% package coverage); handler
tests stayed in main. Leaf proof: **zero Culvert imports** — the first pure-stdlib extraction since
the early leaves.

### 2026-07-03 — RISK-017 closed (follow-up to the alerts extraction)
`globalAlertStore.Init(<dataDir>/alert_webhooks.json)` is now wired as step 4 of the
persistent-admin-state startup slice (resolver gains `AlertWebhooksPath`), and `Store.save()`
upgraded to `fileutil.AtomicWrite` now that the path is load-bearing. Deliberate behavior change,
shipped as its own commit after the behavior-preserving extraction. Details in the risk register.

### 2026-07-03 — `internal/alerts` grows into the full delivery engine (29th) + RISK-017 found
The webhook delivery implementation (alerts.go + alerts_secret.go, 670 lines) moved INTO the
existing `internal/alerts` producer seam — the seam's contract (`Payload`/`Sink`/`SetSink`/`Fire`)
is unchanged; what moved is what the installed sink delegates to: `Store` (webhook CRUD + delivery
history + RISK-003 AES-GCM secret encryption-at-rest), `(*Store).Dispatch` (Q17 dedup + bounded
fan-out + F16 retry enqueue), `(*Store).Deliver` (SSRF-guarded, HMAC-signed HTTP POST), the
persistent retry queue (`StartRetryLoop(ctx, current func() *Store)` — the store provider closure
preserves the read-global-each-tick test-reassignment tolerance), and `ValidateURL`. main keeps the
singleton + `fireAlert` wrapper (still installed as the sink at init). Deltas: the Q17 dedup map
became **per-Store** state (production has one store — behavior identical; tests that swap in a
fresh store get a fresh dedup window; `ResetDedupForTest` replaces the whitebox map wipe);
`processRetryQueue`'s inline hook scan became `GetByID` (same lock, copy semantics); the retry-queue
tests (coverage_boost + the tmp-leak guard) consolidated in-package; `Store.save()` keeps its
non-fsynced WriteFile+Rename verbatim (pre-Bucket-4 style — noted in RISK-017, not silently fixed).
**Dialer-swap retarget (same as blocklistfeed):** `Deliver` dials `ssrf.SafeDialContext` directly,
so the two webhook tests that swapped main's `ssrfSafeDialContext` var were retargeted onto
`ssrf.AllowLoopbackForTest()`. **Finding recorded as RISK-017:** `AlertStore.Init(path)` has NEVER
been wired in production (git-history verified) — webhooks don't survive restart and the RISK-003
machinery protects a file production never writes; the extraction stayed behavior-preserving and
the fix is a separate unit. Leaf proof: `fileutil`+`obs`+`ssrf` only.

### 2026-07-03 — `internal/threatfeed` extracted (28th) + obs facade gains `Debugf`
The local threat-feed manager (URLhaus/OpenPhish download, offline URL/domain lookups, the
admin-managed domain allowlist with its nil-vs-empty persistence contract, CP export/import) moved to
`internal/threatfeed` as a pure leaf — every dependency already had an internal home: `isPrivateIP` →
`ssrf.PrivateIP` (inline, per the recorded seam verdict), `atomicWriteFile` → `fileutil.AtomicWrite`,
`logger.Printf` → `obs.Printf`. `ThreatFeed` → `threatfeed.Feed` behind the usual alias;
`normaliseFeedURL` → exported `NormaliseURL` (main's fuzz target retargets); `fetchTextFeed` became a
method so its allowlist check reads the receiver instead of the `globalThreatFeed` singleton (only
caller is `Sync` on the same instance — behavior identical). Moved code got the house-rule fixes
(`NewRequestWithContext`+`http.NoBody`, named results). **Facade extension (ADR-0003):** the engine's
one `logDebugf` line required `obs.Debugf`/`obs.SetDebugEnabled` — main's `SetLogLevel` now mirrors
the debug-enabled boolean into obs on every level change (level state stays in main, same stance as
`obs.Warnf`). Three whitebox suites moved in-package (engine tests, the allowlist empty-clear
persistence regressions, the PR #247 saveToDisk race harness); main-side integration tests rewired
onto public API + two test-support methods (`SeedForTest` replacing map pokes in the secscan feed
tests, `SetDBPathForTest` replacing the dbPath/mu pokes in the cluster-apply persistence test); the
bucket-4 durability test now drives `Init`+`SeedForTest`+`Save` instead of whitebox `saveToDisk`.
Leaf proof: `fileutil`+`obs`+`ssrf` only.

### 2026-07-03 — `saas_feed.go` mapped; extraction DESIGNED (executed above)
The next unit is fully mapped and the design decided — recorded here so a fresh session (or the
post-#529 branch) executes it without re-discovery. `internal/saasfeed` needs FIVE seams, the widest
so far: (1) the `catStore` merge inverted to an injected `merge func([]Category) int` closure —
`CategoryStore`/`CategoryEntry` live in policy.go (core hub), so the package defines its own
`Category{name,hosts}` wire type (JSON-compatible; `builtIn` ignored) and main's closure keeps the
GetByName/Set/AddHost/Save additive-merge logic + the added>0 Save; (2) a lifecycle-context provider
injected via Deps — `Configure` currently parents the sync loop on main's `resolveLifecycleCtx()`
(P6.1 UC-3 contract, do not lose the Done()-channel semantics); (3) the client injected (the
singleton builds it with `ssrf.SafeDialContext`); (4) the SaaS sync-failure counter package-owned
(`SyncFailures()`, read by urlcat_metrics.go — the feedsync pattern); (5) test-construction support:
seven `&SaaSFeedSyncer{...}` field literals across saas_feed_test.go (engine tests move in-package
with a fake merge), saas_feed_lifecycle_test.go (stays in main — drives globals; needs Deps-based
construction), and urlcat_metrics_test.go (needs `SeedStats`, per feedsync).
`TestCategoryStore_GetByName` in saas_feed_test.go is a policy.go test and stays in main.

## Decomposition Complete (leaf-extraction phase) — 2026-06-30

The leaf-first extraction phase of ADR-0002 is **complete**. A final size-ordered sweep of every
remaining root `*.go` file confirmed no genuinely-clean leaf remains: the small files are either the
`*_vars.go` alias shims of already-extracted leaves, the shipped `*_startup*.go` wiring DTOs (the PR3
pilot, covered by `startup_slice_contract_test.go`), or hub glue coupled to a core singleton/interface
(`auth.go`'s `AuthProvider`, `ui_rbac.go`, `ca_metrics.go`, `identity.go`).

**17 leaves extracted** (stdlib-/x-only, compiler-enforced boundaries, no `package main` back-import):
`totp`, `geoip`, `fileblock`, `lockout`, `hashcache`, `catdb`, `blockpage`, `rewrite`, `connlimit`,
`syslog`, `clamav`, `yara`, `scanner`, `scanexcl`, `filemagic`, `clientclass`, `backupcrypt`.

**3 foundational seams built** (publish-once injection so a leaf never imports main):
`obs`/`fileutil` (ADR-0003), `hostutil`, `alerts`.

**What deliberately stays in `package main`, and why** (this is the recorded decision, not unfinished
work):

| Category | Representative files | Why it stays |
|---|---|---|
| **Composition roots / orchestrators** | `security_scan.go` (`SecurityScanner`), `proxy.go` | Wire multiple subsystems together (threat feed + remote scanner + YARA + DPI + hash cache); extracting needs a dependency-injection refactor with its own ADR, not a mechanical move. |
| **Core hubs (large inbound surface + shared mutable globals)** | `store.go`, `policy.go`, `controlplane.go`, `enrollment.go`, `upstream.go`, `ca.go`, the `release_*` cluster, the `ui_*` admin surface, the `auth_*` backends | Reachable by both the proxy hot path and the admin write path; moving them is the high-risk endgame, deliberately gated behind the leaf phase and a `-race`-covered hot-path spike. |
| **Auth interface graph** | `auth.go` (`AuthProvider`), `identity.go` (`Identity`/`IdentityProvider`) | Root interfaces implemented across every auth backend; a shared model, not a leaf. |
| **Startup-wiring DTOs** | `*_startup.go` / `*_startup_config.go` (the PR3 pilot) | Resolver + DTO seams that intentionally live next to `main.go`'s init shims; pinned by `startup_slice_contract_test.go`. |
| **Alias shims** | `*_vars.go`, `client_class.go`, `filemagic.go`, `backup_encrypt.go`, `clam_vars.go` | The thin `package main` faces of the extracted leaves — by design. |

**Lessons banked across the phase** (kept here so the hub-extraction program inherits them):
1. *The test surface, not the engine, is the hard part* — mixed engine/integration files, shared
   isolation helpers, whitebox global-state access, and direct struct construction scatter far wider
   than a filename map shows. Read the test sources up front.
2. *Symbol-name greps are necessary but insufficient* — read the candidate's full source before
   declaring it a leaf (the `geoip`/`isPrivateIP` miss).
3. *Test-support APIs should be owned by the type that owns the mutex* — `SnapshotAndClear`/`Snapshot`
   replaced foreign-package whitebox poking and are net design wins, not churn.
4. *Idiomatic renames at the boundary* (revive: drop the package-name prefix) keep the package face
   clean while the alias shim preserves every call site.

**Next program (separate, not part of this phase):** hub extraction starts from the
`roadmap/ARCH_DISCOVERY.md` MEDIUM-risk list (`initBlocklist`, `initObservability`,
`initConnAndRateLimit`, …) and the composition-root DI refactor for `security_scan.go`, each behind
its own ADR. The deferred BLOCKER **RISK-001** (HA split-brain) remains the top open item in the
Technical Risk Register and is the recommended next focus now that the migration runway is clear.

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
