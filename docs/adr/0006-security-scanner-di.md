# ADR-0006: SecurityScanner dependency injection (scan orchestrator refactor)

- **Status**: Accepted — Slice 1 shipped (2026-07-03); Slice 2 deferred, not committed
- **Date**: 2026-07-03
- **Deciders**: maintainer + engineering advisor session
- **Relates to**: ADR-0002 (flat-package decomposition), ADR-0003 (obs facade)

## Context

`security_scan.go` (549 ln) is the scan **orchestrator**: it ties ClamAV, YARA,
the threat feed, the hash cache, the exclusion store, and the remote-scan
sidecar into the single pipeline the proxy hot path calls (`safeScanBody`,
`bodyNeedsBuffering`, `maxScanBufferBytes`, `scanBlock*`).

The **engines** it coordinates are already extracted as leaves under ADR-0002:
`internal/clamav`, `internal/yara`, `internal/scanner` (DPI),
`internal/hashcache`, `internal/scanexcl`, plus the `internal/alerts` seam. The
orchestrator itself, however, still reaches sideways for package-main globals
instead of owning its collaborators:

| Global read inside `security_scan.go` | Owner file | Extracted? |
|---|---|---|
| `globalYARA`, `yaraGet*`, `yaraInflightLoad` | `yara_vars.go` | engine yes (`internal/yara`); the settings wrappers are main-side |
| `globalThreatFeed` | `threatfeed.go` | **no — hub** (feed sync, allowlist, persistence, admin API) |
| `globalRemoteScanner` | `scan_remote.go` | no (sidecar client, small) |
| `dpiScanner` | `scanner.go` | engine yes (`internal/scanner`) |
| `globalScanExclusions` | `security_scan.go` itself | engine yes (`internal/scanexcl`) |
| `globalSecScanner.cache` (poked directly by `scanning_startup.go:24`, `ui_security.go` ×7) | `security_scan.go` | engine yes (`internal/hashcache`) |
| `logger` / `logInfof` / `logWarnf` / `logErrorf` | `logger.go` | obs facade exists |
| `statClam/YARA/ThreatFeed/ScanTimeout/ScanSkipped/RemoteScanFail` counters | `security_scan.go`, read by `metrics.go`/`otlp.go` | main-side atomics |

23 references to those globals sit inside the orchestrator's methods. The
consequences we actually observe (not hypothetical):

1. **Untestable in isolation.** `ScanBody`'s branching (exclusion → cache →
   ClamAV → YARA → cache write, fail-closed timeout) can only be tested by
   mutating process-wide singletons; tests that forget to restore them bleed
   state (the audit-ring / obs-sink class of order-dependence we keep paying
   for — see the F6 observability incident on PR #529).
2. **Hidden coupling order.** `SecurityScanner.Init` half-initialises the
   struct while `scanning_startup.go` pokes `globalSecScanner.cache` from
   outside — two writers to one struct across two files.
3. **Blocks the ADR-0002 endgame.** The orchestrator cannot move under
   `internal/` while it reads main-owned hubs (`globalThreatFeed`,
   `globalRemoteScanner`) directly.

## Decision

Refactor `SecurityScanner` to **constructor-injected collaborators behind
narrow, orchestrator-owned interfaces**, in two slices. Slice 1 stays entirely
inside package main (no import-graph change, minimal diff surface); a possible
later Slice 2 (package move) is deliberately **not** committed to now.

### Slice 1 — inject collaborators, keep the singleton (this program)

Define the interfaces next to the consumer (Go convention — the orchestrator
owns the contracts it needs, engines stay interface-free):

```go
// security_scan.go (package main)
type clamScanner interface {
    Ping() error
    Scan(data []byte) (name string, found bool, err error)
}
type yaraMatcher interface {
    Loaded() bool  // rules present (BodyScanEnabled contract)
    Enabled() bool // runtime toggle AND rules present (scanBodyInner contract)
    Match(data []byte) []string
}
type threatChecker interface {
    Enabled() bool
    CheckURL(rawURL string) (bool, string)
    CheckDomain(domain string) (bool, string)
}
type hashExcluder interface{ IsHashExcluded(hash string) bool }
```

`SecurityScanner` gains fields `yara yaraMatcher`, `feed threatChecker`,
`excl hashExcluder` (the existing `clam *ClamAV` field becomes `clam
clamScanner`), each defaulting to the current global when nil so the
`globalSecScanner` singleton keeps today's behavior with **zero call-site
changes**:

- `NewSecurityScanner(deps secScannerDeps) *SecurityScanner` constructor for
  tests and future callers; `globalSecScanner` is built from it with the
  production deps (`globalYARA`, `globalThreatFeed`, `globalScanExclusions`).
- `scanBodyInner`, `ScanBody`, `CheckURL`, `CheckDomain`, `BodyScanEnabled`
  read `ss.yara` / `ss.feed` / `ss.excl` — never the globals.
- The `yaraGetEnabled()` runtime toggle folds into the `yaraMatcher` adapter's
  `Enabled()` (toggle AND rules loaded). `Loaded()` stays toggle-independent
  because `BodyScanEnabled` has never consulted the toggle — buffering
  behavior must not change in a behavior-preserving slice.
- `scanning_startup.go` stops poking `globalSecScanner.cache` directly:
  `Init` (or the constructor) takes the cache. `ui_security.go`'s seven
  `globalSecScanner.cache` touches move behind three small methods
  (`CacheStats`, `CacheClear`, `CacheEvict`) so the field can become private.
- Free functions (`safeScanBody`, `scanBlock*`, `bodyNeedsBuffering`,
  `maxScanBufferBytes`, `secScanStatusMap`, `decompressForScan`) are **out of
  scope**: they are main-side glue over the singleton and the remote-scanner
  fork, and they keep working unchanged.

**Non-goals for Slice 1** (recorded so scope cannot creep): no package move,
no change to `globalRemoteScanner` / `dpiScanner` / stat counters / logging
calls, no behavior change anywhere on the hot path — the diff must be
behavior-preserving and provable by the existing scan test suite plus new
fake-engine unit tests for `ScanBody` branch coverage.

### Slice 2 (deferred, not committed) — `internal/secscan`

Only worth doing after Slice 1 proves the seams: move the orchestrator +
interfaces to `internal/secscan`, main provides adapters for the threat feed
and remote scanner, counters become package-owned with exported snapshots for
`metrics.go`/`otlp.go`, logging via `obs`. Decide then, against the same
leaf-proof bar as ADR-0002 (no main import; `go list -deps` check).

## Alternatives considered

- **Move to `internal/` in one step.** Rejected: `globalThreatFeed` and the
  stat-counter/metrics coupling make that a multi-hub change; ADR-0002's
  sweep already classified the threat feed as a hub. One-step moves of
  hub-coupled code are where regressions have come from historically.
- **Interfaces in the engine packages** (e.g. `yara.Matcher`). Rejected:
  producers exporting interfaces inverts the Go dependency idiom and forces
  engines to know their consumers.
- **Leave as-is.** Rejected: every scan-path change currently requires
  whole-process singleton juggling in tests; the cost is recurring.

## Consequences

- `ScanBody`'s decision tree becomes unit-testable with in-memory fakes (no
  ClamAV socket, no YARA fixture files, no global mutation).
- The two-writers-to-one-struct startup wart (`scanning_startup.go` +
  `Init`) is eliminated; the cache becomes constructor-owned.
- Adds one indirection layer (interface dispatch) on the scan path; body
  scanning is already dominated by hashing + engine work, so this is noise.
- `ui_security.go` handlers get a slightly wider `SecurityScanner` method
  surface (`CacheStats`/`CacheClear`/`CacheEvict`) in exchange for field
  privacy.
