# Preserved source: Conventions

Historical evidence from main `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`, not current architectural authority.
Read the [current task routes](../README.md) and [verified errata](../errata.md) first.
No benchmark, status, location or instruction in these blocks is independently revalidated by moving it here.
Links inside preserved text retain their original spelling and source-root context; use each pinned source link to follow original references.
Do not import this file into startup instructions.

## Topics

- [Code conventions; selectively promoted to root](#claude-main-l129-l154)

<a id="claude-main-l129-l154"></a>

## Code conventions; selectively promoted to root

[Original lines 129–154](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L129-L154) · `claude-main-L129-L154`

<!-- BEGIN preserved-block: claude-main-L129-L154 -->
## Code Conventions

- **Package ownership**: Put domain logic and its unit tests in a cohesive `internal/<domain>` package when it can own its mutable state and expose a narrow API. Keep process startup, concrete service wiring, HTTP/config adapters and cross-domain integration tests in `main`. Internal engines must not depend on main, application singletons, or a new generic common/app hub. Inject explicit dependencies at construction; document persistence, cancellation and shutdown ownership. Follow [the package-isolation roadmap](roadmap/PACKAGE-ISOLATION.md); ADR-0002 is complete and each new boundary needs a fresh recorded design.
- **Admission engine**: `internal/admission` owns IPFilter, RateLimiter, shared prefix matching, remote counts and derived freshness/episode state (ADR-0039). Put engine logic, white-box tests and hot-path benchmarks there; run `go test -race -shuffle=on -count=2 ./internal/admission`. Main owns persistence, gossip DTO/transport, cleanup cancellation, HTTP/SOCKS5 and diagnostic rendering. Use constructors for active admission; never export mutable internals to keep a root test. Run tagged gates in BOTH packages: `go test -tags benchgate -run 'TestBenchGate_' -count=1 . ./internal/admission`.
- **Shutdown engine**: `internal/shutdown` owns ordered hook execution and immutable per-registry timing/sink options. Main owns phase budgets and real hook registration. Test the engine with `go test -race -count=2 -shuffle=on ./internal/shutdown`; keep production-wiring tests in root. Do not restore package-global timing fixtures or move service imports into this package (ADR-0037; boundary tests enforce this).
- **Go version**: the build compiler is the root `go.mod` `toolchain` line (go1.26.8) — CI (setup-go reads it), the release binaries and every Docker builder stage (`golang:1.26.8-alpine@sha256:…`, pinned by digest) use exactly that compiler, each verifies it (the Dockerfile's post-build checks compare the binary's recorded compiler with the go.mod `toolchain` line, not the active compiler, and any GOTOOLCHAIN assignment other than the one `ENV GOTOOLCHAIN=local` is rejected), and `toolchain_consistency_test.go` fails any disagreement; the `go 1.26.6` line is the module's minimum language version (raised by the go.etcd.io/etcd/server/v3 v3.7.1 update), not the compiler. Never set `GOTOOLCHAIN` in a workflow (setup-go then ignores the toolchain line). Upgrade procedure: `roadmap/CI-REDESIGN.md` §20
- **Logging**: Use `logger.Printf()`, never `log.Printf()` or `fmt.Printf()`
- **User input in logs**: Wrap with `sanitizeLog(s)` and use `%q` format verb (CWE-117 prevention; sanitizeLog's leading `strings.ReplaceAll` is the sanitiser CodeQL recognises — it is the FIRST statement and therefore on every return path, and it must stay that way: see the single-pass note in Architecture Notes)
- **CodeQL compliance**: For values that flow through objects (e.g. `rl.Limit()`, `added.Priority`), inline `strings.ReplaceAll` or `fmt.Sprintf` + `strings.ReplaceAll` at the call site so CodeQL sees the sanitiser
- **SSRF guards**: Inline `url.Parse` + scheme check + `isPrivateHost()` before outbound HTTP requests so CodeQL can verify the guard; do not rely solely on wrapper functions like `validateExternalURL()`
- **HTTP contexts**: Use `http.NewRequestWithContext()`, never bare `http.NewRequest()`; use `HandshakeContext()` not `Handshake()`; use `DialContext()` not `DialTimeout()`
- **Errors**: Return `fmt.Errorf("context: %w", err)` for wrapping
- **Concurrency**: Use `sync.RWMutex` for read-heavy stores, `atomic` for counters
- **Security**: SSRF checks via `isPrivateHost()` before any outbound dial
- **Tests**: Test files use `_test.go` suffix, same package (whitebox)
- **Lint suppressions**: Use `//nolint:errcheck` with reason comment; `// #nosec G402` for gosec
- **GUI parity**: Every new CLI flag or config option MUST have a corresponding admin API endpoint AND a UI panel/section so the user can manage it from the GUI. CLI-only features are not acceptable — the admin must have full control from the web interface.
- **API pattern**: Admin API handlers follow `apiXxx(w, r)` naming, registered through `register*Routes` helpers and represented in `uiRoutes` metadata (`ui_routes_meta.go`). Use `requireRole(w, r, "admin")` for write operations, `requireRole(w, r, "viewer")` for reads — handler-level RBAC stays as defense-in-depth even with C2 active.
- **UI pattern**: SPA panels in `static/index.html` use `data-view="name"` attributes. New panels need a nav-item in the sidebar, a view div, and JS load/render functions.
- **Config versioning**: Config-mutating API handlers must call `saveConfigVersion(actor, action)` after `auditEvent()` to create automatic snapshots.
- **Range iteration**: Use index-based range (`for i := range slice`) for large structs (PolicyRule 240 bytes, EnrolledNode 176 bytes) to avoid `rangeValCopy` gocritic warnings.
- **gosec G117**: Avoid struct field names or JSON tags matching secret patterns (e.g. `secret`, `password`, `token`). Rename to non-matching names (e.g. `SessionHMAC` instead of `SessionSecret`).
- **gosec G124**: When cookies use dynamic `Secure` flag (e.g. `isSecureRequest(r)`), suppress with `// #nosec G124 -- dynamic Secure flag`.
- **Cyclomatic complexity**: Keep functions under cyclop threshold of 15. Extract helpers for complex switch/if chains.
- **`upstreamTransport` is read-only after publication**: the shared upstream `*http.Transport` is owned by `upstream_transport.go` (P5.3 / S6). Read via `getUpstreamTransport()`. Mutate via `swapUpstreamTransport(update)` only — the update closure builds a NEW `*http.Transport` (use `cloneTransport` + `cloneTLSConfig`) and MUST NOT mutate its input. Direct field assignment on a loaded transport (`getUpstreamTransport().Proxy = …`, including the local-variable bind form `t := getUpstreamTransport(); t.Proxy = …`) is forbidden — it races against the proxy hot path's reads.

<!-- END preserved-block: claude-main-L129-L154 -->
