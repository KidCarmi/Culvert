# Claim-Evidence Ledger — "PAC traffic steering"

Article: [`pac-traffic-steering.md`](pac-traffic-steering.md). Verified against
repo revision `ca60d83`.

| Claim | Type | Evidence |
|---|---|---|
| PAC compiled from config; only `PROXY`/`DIRECT` emitted (WinINET-compatible) | src | `internal/pac/compile.go:13` |
| DNS resolved at most once per evaluation | src | `internal/pac/compile.go:14` |
| Domain + CIDR exclusions steer to `DIRECT` | src | `internal/pac/compile.go:154-164` |
| Fail-open to `DIRECT` in the degenerate no-host case | src | `internal/pac/compile.go:86-87` |
| Served at `/proxy.pac`, unauthenticated; on proxy + UI ports | src | `pac.go:162-166`; `main.go:899` (proxy port) |
| PAC config route | src | `pac.go:167` (`/api/pac-config`) |
| Config: proxy host (empty = request-derived), port (0 = startup listener), exclusions | src | `internal/pac/compile.go:64-77,123-126` |

## Notes

- The unauthenticated `/proxy.pac` is by design (Windows PAC fetchers cannot
  present credentials); the article states plainly that it is a routing hint, not
  access control, and that exclusions bypass all policy/inspection.
