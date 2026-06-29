# ADR-0003: Shared-foundation seam for `internal/` packages (logging + atomic file write)

- **Status:** Proposed (2026-06-28) — design only, no code moved; awaiting maintainer approval
- **Deciders:** Chief Engineering Advisor (proposed); project maintainer (to decide)
- **Related:** ADR-0002 (incremental `internal/` decomposition), DEBT-001

## Context

Two leaves are extracted (`internal/totp`, `internal/geoip`). The next targets — `fileblock`
(near-hub) and later `scan` (hub) — are blocked on cross-cutting primitives that `internal/*`
packages cannot reach without illegally importing `package main`. The mapping (ADR-0002) identified
the universal blockers; this ADR designs the smallest seam that unblocks them **without touching the
hundreds of existing call sites** (the non-negotiable "don't destabilize the product" constraint).

Evidence (non-test call-sites, measured 2026-06-28):

| Primitive | Definition | Call-sites / files | Purity |
|---|---|---|---|
| `logger` (`*log.Logger`) | `main.go:42` | **623 / 83** | wired at startup (rotating file / JSON) |
| `sanitizeLog` | `proxy.go:1147` | **220 / 47** | pure (CWE-117 `strings.ReplaceAll` strip) |
| `logWarnf` | `logger.go:88` | 23 / 13 | wraps `logger` + level filter |
| `atomicWriteFile` | `main.go:2199` | **45 / 24** | pure stdlib (`os`/`filepath`) — verified |

`fileblock` needs `logger`+`sanitizeLog`+`atomicWriteFile`; `scan` additionally needs `fireAlert`
and `stripHostPort` (out of scope here — see "Deferred").

## Decision (proposed)

Introduce **two tiny, single-responsibility shared packages** that both `package main` and
`internal/*` import. `package main` keeps its existing identifiers as thin delegators, so **all 911
call-sites above stay byte-for-byte unchanged**.

### 1. `internal/obs` — logging facade
```
package obs
// sink is published once at startup (atomic; safe for the proxy hot path).
func SetSink(fn func(line string))           // main wires this to its logger
func Printf(format string, args ...any)       // formats, sends to sink (INFO)
func Warnf(format string, args ...any)        // formats with "WARN " prefix, sends to sink
func Sanitize(s string) string                // the canonical CWE-117 strip (moved here)
```
- **Default sink** (before `SetSink`): write to `os.Stderr`. So `internal/*` unit tests log
  visibly and never panic; production routes into the real logger.
- **Wiring (main, startup, once):** `obs.SetSink(func(l string){ logger.Print(l) })` — internal
  logs flow into the SAME rotating/JSON logger. Published before serving traffic; read via
  `atomic.Pointer` (mirrors the `upstreamTransport` publish-once pattern, no hot-path race).
- **`Sanitize` becomes canonical:** `proxy.go`'s `sanitizeLog` becomes a one-line
  `return obs.Sanitize(s)`. One function body changes; **220 call-sites unchanged**; no divergence
  risk (single implementation).
- **No auto-sanitize in Printf:** callers keep sanitizing specific values (`obs.Sanitize(x)` + `%q`),
  preserving the existing CWE-117 convention exactly.

### 2. `internal/fileutil` — atomic write
```
package fileutil
func AtomicWrite(path string, data []byte, perm os.FileMode) error  // impl moved from main.go:2199
```
- `main.go`'s `atomicWriteFile` becomes a one-line `return fileutil.AtomicWrite(...)`. One body
  changes; **45 call-sites unchanged**; single implementation.

### Why this shape
- **Zero call-site churn** in `package main` (delegators preserve every identifier).
- **No global logger move** — `logger` stays `*log.Logger` in main; the seam forwards into it.
  Moving `logger` itself (623 sites) is explicitly rejected as destabilizing.
- **Single source of truth** for `Sanitize`/`AtomicWrite` (delegation dedupes, prevents drift —
  important for the CWE-117 sanitiser).
- `internal/*` packages get a clean, importable logging + file-write path → `fileblock` becomes a
  straightforward extraction afterward.

## Consequences

- **Positive:** unblocks `fileblock` (and 2/4 of `scan`'s deps); establishes the seam pattern other
  hubs reuse; dedupes two primitives.
- **Cost:** two new micro-packages; startup wiring (one `SetSink` call); a minor behavior nuance —
  `internal/*` `Warnf` does not apply main's runtime log-level filter (the level state stays in
  main). Internal packages are few and warn rarely; acceptable, documented, and upgradeable later by
  exposing level state through `obs`.
- **Risk:** LOW. Pure functions moved + delegated; logging routed through a published sink. The 911
  call-sites are untouched; the full suite + `-race` is the backstop. Highest-care item is the sink
  publish/read on the hot path — handled with `atomic.Pointer` and publish-before-serve.

## Alternatives considered

- **One `internal/platform` package** (logging + fileutil + later util) instead of two. Rejected as
  the default: it trends toward a junk-drawer. Two single-responsibility packages are clearer.
  (Reconsider if the seam set stays tiny long-term.)
- **Per-package func-var injection** (each `internal/*` declares `var Logf func(...)` set by main).
  Rejected: doesn't scale — every leaf re-declares logging/util seams; more wiring, more mutable
  injected state, fragile ordering.
- **Move `logger`/`sanitizeLog`/`atomicWriteFile` wholesale into the shared package and rewrite all
  call sites to the new path.** Rejected: 911-site churn, exactly the destabilization the program
  exists to avoid.

## Deferred (NOT in this seam)

- `fireAlert` (alerting) and `stripHostPort` — needed by `scan`, not `fileblock`. Add an alerting
  seam + a host-util home when `scan` is tackled, reusing this pattern. Keeping this ADR scoped to
  what `fileblock` needs keeps the first seam small and reviewable.

## Validation plan (when implementation is approved)

`go build ./...`, `go vet ./...`, full `go test ./...`, `-race` on hot paths (proxy logs through the
sink), `golangci-lint` on the new packages + touched files, `go list -deps` cycle check, and a focused
unit test per new package. Each package lands as its own small commit; `fileblock` extraction is a
separate follow-up PR.

## Decision needed

Approve the two-package seam (`internal/obs` + `internal/fileutil`) as designed, or direct a
different shape (single `internal/platform`, or injection). No code moves until approved.
