# Culvert Proxy Quality Engineering — CI Architecture

Status: **PR-1 (foundation)** — this document plus the first real traffic-plane
E2E tests. Load / stress / benchmark tiers are defined here but land in later PRs.

Culvert is a forward proxy / secure-access platform, not a generic web app. Its
production risk is not "do the APIs work" — it is **does the traffic plane behave
correctly, securely, and predictably under real client traffic, concurrency,
tunnels, policy evaluation, upstream failure, and long-running connections.**
This document is the reference for the CI that proves that.

---

## 1. Current CI inventory (what exists today)

Eleven workflows in `.github/workflows/`:

| Workflow | Purpose | Blocks |
|---|---|---|
| `ci.yml` | Build, multi-arch Docker, release-catalog gen, Sigstore signing, SLSA L3 | tag release; PR smoke |
| `qa-gate.yml` | Hard QA gate: logic / determinism / coverage / compose / OS / contract / agent | **PR + release** (required `qa-gate-approved`) |
| `security-release-gate.yml` | 10-check security gate (gosec, govulncheck, trivy×2, gitleaks, staticcheck, hadolint, race, license, SBOM) | **PR + release** (required `release-approved`) |
| `codeql.yml` | SAST (security-and-quality suite) | PR + weekly |
| `code-review.yml` | golangci-lint (reviewdog), PR size, coverage delta, go mod tidy | PR |
| `catalog-e2e.yml` | Catalog serve/upgrade/anti-rollback/tamper (real binary + container) | PR/main/tag |
| `install-lifecycle-e2e.yml` | Installer fresh/migrate/upgrade + agent systemd lifecycle | PR/main/tag |
| `maint-agent-backup-upgrade-e2e.yml` | Agent encrypted backup + backup-gated upgrade | PR/main/tag |
| `maint-agent-update-e2e.yml` | Agent image pull/retag/replace upgrade | PR/main/tag |
| `auth-idp-interop.yml` | Keycloak OIDC + SimpleSAMLphp SAML interop | nightly/manual |
| `publish-catalog-pages.yml` | Publish signed catalog to GitHub Pages | release |

**Strengths (preserve):** supply-chain maturity (Sigstore keyless + pinned
identity, SLSA L3, deterministic catalog, dual CVE scan, gitleaks full history,
license gate, SBOM); a determinism gate (`-count=2 -shuffle=on`); layer-isolated
QA gate; real upgrade/rollback/tamper E2E; coverage floors on security-critical
files (totp 85 %, security 70 %, session 75 %, lockout 80 %).

**The gap this program closes:** across all eleven workflows, **not a single
HTTP forward request, CONNECT tunnel, SOCKS5 connection, or WebSocket frame is
sent through a running Culvert at concurrency.** Every "E2E" hits `/health`,
`/ready`, `/api/releases`, or the agent UDS. In addition: **zero benchmarks**
(`grep "func Benchmark"` = 0), **zero performance-regression gate**, and the
entire README sizing table (500 users, 1 Gbps, 1000–5000 conns, ~138 KB/active
conn, p95 latency) is **unvalidated by CI**.

The existing Go tests are a solid *unit* foundation — `proxy_test.go` exercises
the real proxy via `startTestProxy`, header stripping is well covered
(`TestScrubForwardedHeaders_*`), `socks5_test.go` covers the protocol, `pac_test.go`
covers generation — but everything is **sequential**, there is no CONNECT byte
relay, no WebSocket frame relay, no upstream-failure path, and no load.

---

## 2. Target architecture — layered execution tiers

```
PR Gate       (existing + new fast proxy smoke)  → correctness, deterministic, < 8 min
Nightly Gate  (new)                              → traffic matrix + policy-size matrix + load smoke
Weekly Gate   (new)                              → soak / spike / chaos / leak detection / churn
Release Gate  (extend existing)                  → benchstat regression + traffic-plane conformance
```

Principle: the PR gate stays fast and deterministic; load and stress live in
nightly/weekly so they never slow developers; the release gate is the only place
a performance regression *blocks*. Every test must answer a production question
(e.g. "does default deny hold under concurrency?"), not inflate a count.

### Workflow matrix (target)

| Workflow | Trigger | Blocks | Scope |
|---|---|---|---|
| `proxy-pr-gate.yml` | PR, dispatch | non-blocking (PR-1), promote later | HTTP+CONNECT smoke, 10-client concurrency, allow/block/default-deny through proxy |
| `proxy-nightly-e2e.yml` | nightly cron, dispatch | nightly | full traffic matrix, k6/vegeta load smoke (100 clients), policy size 10/100/1000, log+metric assertions, pprof |
| `proxy-weekly-stress.yml` | weekly cron, dispatch | weekly | soak, spike, chaos, 500 clients, policy 5000–10000, tunnel churn, leak detection, restart-under-traffic |
| `proxy-release-performance.yml` | tag `v*`, dispatch | **release** | benchstat regression vs baseline, traffic-plane conformance, sizing-claim band check |

---

## 3. Honesty about capacity (risk R1)

GitHub-hosted runners cannot prove "1 Gbps / 5000 concurrent connections." We
therefore keep **four separate capacity tiers** and never conflate them:

- **CI smoke capacity** — what the PR gate proves (≈10 clients).
- **Lab benchmark capacity** — what nightly/weekly prove on bigger runners.
- **Release benchmark capacity** — what the release gate measures for regression.
- **Documented sizing claim** — the README table, validated in its own labeled
  job, never silently implied by a smoke test.

If a number is not measured, CI does not claim it.

---

## 4. Proxy traffic test matrix (target)

- **HTTP forward**: GET/POST, large req/resp, chunked, keep-alive/reuse, timeout,
  upstream 200/301/302/403/500, broken/slow upstream, client disconnect, header
  preservation, forbidden-header + XFF/X-Real-IP/X-User-Identity strip, request-ID
  propagation, log + metric correctness.
- **CONNECT**: success, denied, malformed, blocked host, allow/default-deny, auth
  required/invalid, idle timeout, **active byte relay**, half-close both
  directions, many parallel tunnels, graceful shutdown with active tunnels, byte
  counters + metrics + logs.
- **HTTPS / SSL inspect**: bypass vs inspect, leaf-cert gen, cache hit, handshake
  latency, bad/expired/self-signed upstream cert, large download, fail-closed.
- **SOCKS5**: no-auth, user/pass, blocked dest, auth fail, concurrency,
  IPv4/IPv6/FQDN, upstream failure.
- **WebSocket**: over HTTP proxy + over CONNECT, long-lived, push, idle timeout,
  restart behavior, policy block.
- **PAC**: endpoint availability, syntax validity, direct-vs-proxy decisions,
  bypass/exclusions, output stability across config change.

Each test asserts the **full chain**: proxy response + upstream-reached(y/n) +
selected rule + action + log entry + monitor event + metric counter + audit event
(when a mutation occurred).

### Auth-vs-authz invariant

Authentication outcome **never** implies authorization. Dedicated matrix:
`Exempt × {allow, block, deny}`, `CredentialRequired × {valid, invalid} × {allow,
block, deny}`, `SSORequired × {valid, expired, wrong-group}`, identity-header
spoof, malformed `Proxy-Authorization`, session replay/logout.

---

## 5. Load / benchmark / security methodology (target)

- **Load**: k6 (HTTP) + a custom Go raw-TCP CONNECT harness (k6 cannot drive raw
  CONNECT relay) + vegeta for fixed-rate latency bands. Capture RPS, concurrent
  conns/tunnels, p50/p95/p99/max, throughput, bytes, CPU, RSS, goroutines, FDs,
  policy-eval time, error/block/allow rate.
- **Benchmarks** (`*_bench_test.go`, in-package because the codebase is flat
  `package main`): policy eval, FQDN/wildcard match, category lookup, session
  decode, proxy hot path, header scrub, CONNECT relay setup, metrics update, rule
  lookup at 10/100/1000/10000 rules. `go test -bench -benchmem` → `benchstat` vs
  committed baseline → **fail if p50 +20 % or allocs/op +20 %**.
- **Security regression** (proxy-specific): SSRF via admin APIs, DNS rebinding,
  Host-header abuse, XFF/X-Real-IP/X-User-Identity spoof, Proxy-Authorization
  confusion, request smuggling, malformed absolute/authority-form, encoded /
  trailing-dot / mixed-case / punycode / IPv6-bracket host bypass, CRLF/log
  injection, path traversal in config import/export, IDOR, CSRF, XSS in
  monitor/report. Each becomes a fail-closed regression test.

---

## 6. Observability / artifacts (target)

Every proxy E2E/load/stress run uploads on failure: proxy/request/audit logs,
docker logs, pprof (cpu+heap+goroutine+mutex), benchmark + k6/vegeta output,
metrics snapshot, failed-request samples, the policy snapshot used, Playwright
screenshots/videos, flamegraphs where practical, and a **GitHub step summary with
interpretation** — what failed, which layer, which proxy path, what profile, was
upstream reached, what policy matched, what was the latency/error rate, where to
debug first.

---

## 7. Recommended repo structure (grows incrementally)

```
tests/e2e/{proxy,connect,socks5,websocket,ssl,pac,policy,authz}/
tests/load/{k6,vegeta,harness}/
tests/fixtures/{policies,certs,upstreams,pac}/
tests/chaos/
benchmarks/                 # external harness; in-package benches stay as *_bench_test.go
scripts/ci/{run-proxy-smoke.sh,run-connect-smoke.sh,run-k6-proxy.sh,collect-pprof.sh,check-bench-regression.sh}
docs/ci/{proxy-quality-architecture,traffic-test-matrix,performance-methodology,stress-methodology,release-gates}.md
```

The codebase is flat `package main`. Benchmarks of unexported functions must stay
in-package (`*_bench_test.go` at repo root); `tests/` and `benchmarks/` host the
external harnesses and fixtures.

---

## 8. PR roadmap

- **PR-1 (this PR):** this doc + first real traffic-plane E2E — HTTP forward
  (POST + identity strip), **CONNECT byte relay against an in-process loopback
  echo fixture**, 10-client concurrency smoke (default-deny holds + allow holds),
  policy-through-proxy allow/block/default-deny. Non-blocking
  `proxy-pr-gate.yml` (PR + `workflow_dispatch`), artifacts on failure. **Does
  not touch `qa-gate.yml`.**
- **PR-2:** k6 HTTP load smoke + Go CONNECT-tunnel harness, pprof capture,
  latency/error thresholds, `proxy-nightly-e2e.yml`, policy-size matrix
  10/100/1000, log + metric assertions.
- **PR-3:** `proxy-weekly-stress.yml` — long-lived tunnel churn, slow/broken
  upstream, restart-under-traffic, policy churn, goroutine-leak + RSS-growth
  detection, benchstat regression gate.

### How PR-1 reaches a loopback upstream without weakening SSRF

The CONNECT path enforces SSRF at two layers (`isPrivateHost` DNS pre-check and
`ssrfControl` on dial), both of which reject loopback by design. The byte-relay
test exercises the **real** `handleTunnelBypass` / `isPrivateHost` / `ssrfControl`
/ relay code unchanged; it only temporarily removes the loopback CIDRs
(`127.0.0.0/8`, `::1/128`) from the package-level `privateCIDRs` slice for the
duration of the test and restores them on cleanup. No production code is
modified, and the SSRF logic itself is untouched — only the deliberately-relaxed
loopback entry differs, which is the controlled relaxation required to point the
real tunnel at a `127.0.0.1` fixture. The negative tests (`SSRFBlocksLoopback`,
already present) continue to assert the guard rejects loopback when *not* relaxed.

---

## 9. Production-readiness acceptance criteria

Culvert CI is enterprise-grade only when it can answer: max safe PR-smoke
concurrency; max validated nightly concurrency; largest validated policy set;
p95/p99 under policy load; memory per active HTTP request and per active CONNECT
tunnel; does default deny hold under concurrency; does first-match-wins hold at
scale; can policy change safely while traffic flows; do active tunnels drain on
shutdown; do blocked/allowed/auth-failed flows appear across logs + metrics +
monitor + reports; where are the README sizing claims validated; are release
artifacts blocked on performance/security regressions; can an operator debug a
failed run from artifacts alone.
