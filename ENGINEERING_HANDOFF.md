# Overnight Engineering — Handoff Report

**Branch:** `claude/overnight-engineering-uc5sld` (based on `main` @ `64363b8`)
**Status:** review-ready. NOT merged, NOT rebased. 8 commits, each one logical
improvement. Per-commit rationale/risks in `ENGINEERING_LOG.md`.

---

## Executive Summary

Eight focused, independently-reviewable improvements, biased toward the top of
the engineering-priority ladder (reliability, security, observability). Two
adversarial audits (unbounded-map DoS; goroutine/resource leaks) drove the
back half of the work: the map audit produced three fixes and is now fully
closed; the leak audit found no genuine leaks (a strong quality signal) and
surfaced the one remaining observability gap that became iteration 8.

Net: +1,916 / −124 across 31 files. Every commit builds, passes the full test
suite, passes `-race`, and is clean under `golangci-lint --new-from-rev=main`.
No test was disabled or weakened; three tests were updated because the code
they pinned was itself the bug being fixed.

## Commits (recommended merge order = chronological, oldest first)

The commits are independent and can merge in any order, but chronological
order is cleanest because iterations 2 and 8 share the tunnel-accounting
surface, and iterations 5–7 share the "bound an unbounded map" janitor.

| # | Commit | Type | Priority | Blast radius |
|---|--------|------|----------|--------------|
| 1 | `f851bb8` persist GUI upstream proxies | fix | Reliability | Upstream pool restart durability |
| 2 | `b6438c7` record raw tunnels (WS/CONNECT/SOCKS5) | feat | Observability/Security | All raw-relay traffic now in the log |
| 3 | `4ea7e6f` surface ClamAV engine/definition version | feat | Security-ops | AV-currency visibility |
| 4 | `7b95f94` IP filter fails closed on corrupt mode | fix | Security | IP filter never silently disabled |
| 5 | `409259b` bound top-hosts counter | fix | Reliability/Security | Memory-DoS closed |
| 6 | `f7de291` bound login-lockout + admin-API maps | fix | Security | Unauth memory-DoS closed |
| 7 | `8cc4fbb` bound enrollment rate-limiter map | fix | Reliability | CP memory growth closed |
| 8 | `8bde322` account non-TLS inspect-fallback tunnels | feat | Observability | Last raw-relay path now logged |

## Themes

**Unbounded-map DoS class — fully closed (iters 5–7).** An audit for maps keyed
by attacker-controllable input with no eviction found four: top-hosts
(hostname), login-lockout (username, unauthenticated — most severe), admin-API
rate limiter (IP), and cluster enrollment (IP). All four are now bounded (cap +
decay for top-hosts; a wired, always-on 5-minute janitor for the other three).
Every other per-request/per-IP/per-host map in the tree was verified to already
have a cap/TTL/LRU/removal.

**Raw-tunnel observability — complete (iters 2, 8).** WebSocket, CONNECT-bypass,
SOCKS5, and the SSL-inspect non-TLS fallback now each emit a `TUNNEL_CLOSED`
request-log entry with per-direction byte counts + connection lifetime, feeding
the Live Feed, JSONL export, syslog SIEM, history store, and the global byte
counters. A latent `X-User-Identity` leak to WebSocket upstreams was closed in
passing.

**Security hardening (iters 3, 4, 6).** Fail-closed IP-filter mode, ClamAV
definition visibility, and the unauthenticated login-lockout memory-DoS.

## Tests executed (every iteration, all green)

- `go build ./...`, `go vet ./...`
- Full `go test .` (~47 s) + affected `internal/...` packages
- `go test -race` on the touched surface each iteration; full cumulative
  `-race` suite (main package) passed on the post-iteration-5 and
  post-iteration-7 states; a full `-race ./...` pass across every package on
  the final iteration-8 state was the last validation run.
- `golangci-lint run --new-from-rev=main` — 0 new issues on every commit
- `-count=2 -shuffle=on` on touched test surfaces (determinism-gate proxy)

New/updated tests: 8 (upstream persistence) + 6 (tunnel accounting) + 9 (ClamAV
version) + 2 (IP-filter fail-closed) + 4 (top-hosts bound) + 4 (lockout bounds)
+ 1 (enrollment bound) + 1 (non-TLS fallback accounting). Three pre-existing
tests updated to match corrected behavior (they had pinned the bug).

## Coverage impact

Net increase. Each fix ships regression tests; three previously-untested paths
gained coverage: the login-lockout sweep, the enrollment sweep, and the
SSL-inspect non-TLS fallback relay (which had no test at all before iteration
8). No coverage removed.

## Performance impact

Negligible and net-positive where measurable. The security janitor is one
5-minute goroutine (already ran in rate-limit-enabled deployments; now always).
The top-hosts decay is amortized O(1) per record. Raw-tunnel accounting adds
one log entry per connection close (gated by the per-rule "log traffic" flag)
and folds already-copied byte counts into existing counters — no extra copies.

## Security impact

Strongly positive. Closed one unauthenticated memory-exhaustion DoS
(login-lockout), three more unbounded-map growth vectors, one fail-open
IP-filter regression, and a header-identity leak to WebSocket upstreams; added
AV-definition-currency visibility. No security control was weakened.

## Remaining technical debt / recommended next steps

Ranked by value; all are larger or behavior-changing, hence deliberately NOT
attempted autonomously:

1. **Config-version rollback: reject hard-invalid snapshots** (reliability).
   `applyConfigBackup` applies even when pre-flight validation warns; the
   flagged values are now all coerced safely (see iter 4), but making the
   apply *reject* rather than *warn* is cleaner. Behavior change to a
   heavily-speced subsystem — needs a spec update.
2. **Per-user traffic summary endpoint** (observability). Now well-supported by
   iteration 2's per-identity byte data. Multi-surface (endpoint + `uiRoutes`
   metadata + RBAC + UI panel + C1/C1.5 parity tests) — follow the admin-UI
   invariants in CLAUDE.md carefully.
3. **Tunnel idle timeout** (defense-in-depth). Established tunnels terminate
   only on client TCP death; a configurable idle cap would bound stuck
   connections. GUI-parity feature.
4. **Cluster-wide request-log aggregation** (reliability/incident-response).
   Metrics and audit aggregate to the CP; request logs do not.
5. **SOCKS5 auth-identity plumbing** — the SOCKS5 `TUNNEL_CLOSED` entry has an
   empty identity because SOCKS5 has no identity path.
6. **Remote-scan-sidecar ClamAV version** — iteration 3 surfaces the version in
   local mode only; the sidecar `Status()` map would need to include it.

## Merge safety

- No merges, rebases, squashes, or force-pushes were performed on any shared
  branch. All work is isolated on `claude/overnight-engineering-uc5sld` and
  pushed to `origin`.
- `main` was never modified.
- Each commit is self-contained and green; they can be cherry-picked or
  reviewed individually.
