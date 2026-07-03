# Engineering Log — overnight engineering branch

Branch: `claude/overnight-engineering-uc5sld` (based on `main` @ 64363b8).
Newest entry first.

---

## 3. ClamAV engine + signature-database version surfaced to operators

**What changed**
Operators had no way to see the ClamAV engine version or how fresh the virus
definitions are (roadmap-day2 Finding 4.3) — only a reachable/unreachable
ping. Stale definitions are a silent security gap.

- `clamav.Client.Version()` (internal/clamav): sends the CLAMD `VERSION`
  command and parses the `ClamAV <engine>/<db-counter>/<db-date>` reply into
  `{Engine, DBVersion, DBDate, Raw}`. Tolerant of engine-only and
  engine+db-only replies.
- `secscan.Scanner.ClamAVVersion()`: queries via an OPTIONAL capability
  interface (`clamVersioner`, type-asserted) so existing test fakes are not
  forced to implement it. Cached for 10 min (definitions change rarely;
  errors cached only 30 s so a down daemon recovers quickly) and invalidated
  on `Init`, mirroring the existing `ClamAVStatus` ping cache.
- `/api/security-scan/status` gains a `clamav_version` object (local mode).
- UI: the ClamAV card in the Scanning panel shows `engine · defs <date>`
  under the status line, full reply on hover.

**Why**
AV currency is a first-order security signal. Surfacing engine + definition
date lets an operator confirm freshclam is working without shelling into the
container.

**Risks**
- One extra short-lived TCP connection to ClamAV per 10 min per admin poll
  window (cached); negligible, and gated behind the same daemon the scanner
  already uses.
- `clamav_version` is absent from the status payload when ClamAV is disabled
  or the daemon doesn't answer VERSION — the UI degrades to showing nothing,
  never a stale value.

**Validation**
`go build`, full `go test .` + `internal/clamav` + `internal/secscan` green,
race on both internal packages green, `--new-from-rev=main` lint 0 issues.
9 new tests: VERSION reply parsing (full / engine-only / engine+db), a mock
CLAMD daemon round-trip, connection-refused, and the secscan caching /
capability-absent / disabled / error-not-cached contracts.

**Remaining work / follow-ups**
- Remote-scan-sidecar mode (`scan_svc_mode=remote`) does not surface the
  sidecar's ClamAV version — the sidecar `Status()` map would need to include
  it. Local mode only for now.
- No active freshness ALERT yet (e.g. warn when `DBDate` is older than N
  days); the data is now available for a future alerts rule.

---

## 2. Raw-tunnel observability: WebSocket / CONNECT / SOCKS5 in the request log

**What changed**
Raw relays (WebSocket upgrades, CONNECT bypass tunnels, SOCKS5) emitted only
`logger.Printf` system lines — no `LogEntry` ever reached the Live Feed, JSONL
export, syslog SIEM, or history store, and their relayed bytes never fed the
global byte counters (only SSL-inspected bodies did). roadmap-day2 Finding
11.1.

- New `TUNNEL_CLOSED` request-log status (INFO level): a per-connection
  accounting entry written when a raw relay drains, carrying both byte
  directions, a new `DurationMs` field (connection lifetime), the matched
  rule, and the authenticated identity.
- `recordTunnelClose` (store.go) adds the relayed bytes to
  `statBytesSent`/`statBytesRecv` and persists the entry through the existing
  `persistLogEntry` fan-out (ring + JSONL + syslog + history). Log-only: the
  connection was already stats-counted at allow time, so the fan-out does not
  double-count. `recordTunnelCloseGated` applies the per-rule "log traffic
  off" gate, mirroring the OK-entry gate.
- Both raw relays now count bytes per direction. Extracted a shared
  `relayCounted` / `bidiRelayCounted` helper — dedups the previously
  copy-pasted two-goroutine bridge in `handleWebSocket` and
  `handleTunnelBypass` (B2 CloseWrite EOF semantics preserved).
- `handleWebSocket` now calls `scrubForwardedHeaders` before forwarding —
  closing a real leak: it re-writes the client request to the target via
  `r.Write`, so a client-supplied (or internally-set) `X-User-Identity`
  previously reached WS upstreams. Now stripped like every other forward path.
- UI: new `TUNNEL` badge, byte↑↓ + duration subline in the log row, and a
  "Tunnel Closed" status-filter option (`static/index.html`).

**Why**
WebSocket and tunneled traffic is a large, previously-invisible slice of what
the proxy carries. Incident investigation, per-connection byte accounting, and
SIEM export now cover it. The identity-header leak fix is a defense-in-depth
bonus surfaced while wiring identity into the accounting entry.

**Risks**
- One extra request-log entry per raw connection (at close). Volume is bounded
  by the per-rule "log traffic" gate; INFO-level so it lands in the LOW
  storage-priority tier that the history-store janitor evicts first.
- `LogEntry`/`Entry` gained `DurationMs` (omitempty) — wire-compatible; absent
  on every non-tunnel entry.
- Byte counts are best-effort: `io.Copy(Buffer)` returns the bytes copied
  before any relay error, which is the correct accounting value.

**Validation**
`go build`, `go vet`, full `go test .` (47s) + all `internal/...` green, race
suite on the relay paths green, `--new-from-rev=main` golangci-lint 0 issues,
`-count=2 -shuffle=on` on the touched surface green. 6 new tests
(`proxy_tunnel_accounting_test.go`) driving REAL WS + CONNECT traffic through
the real proxy listener and asserting the `TUNNEL_CLOSED` entry, plus the
log-traffic gate and global-counter contracts.

**Remaining work / follow-ups**
- SSL-inspected CONNECT tunnels already log per-inner-request; they do not get
  a `TUNNEL_CLOSED` summary (their bytes are counted per inner request). Could
  add a tunnel-lifetime summary for symmetry if desired.
- SOCKS5 identity is always empty (the SOCKS5 path has no auth-identity plumb);
  the accounting entry reflects that. Wiring SOCKS5 auth identity is separate.
- A cluster-wide request-log aggregation RPC (Finding 7.2) would let these
  entries roll up to the Control Plane; still per-node today.

---

## 1. Upstream pool durability: GUI/API changes survive restart

**What changed**
- `UpstreamPool` now retains the raw accepted entries (`Entries()`) and the
  circuit-breaker parameters from the last `Configure`; new `SetProxies`
  replaces the proxy list while keeping those CB params.
- `admin_settings.json` gains `upstream_proxies_saved` (sentinel, mirrors
  `BlocklistFeedsSaved`) + `upstream_proxies`; `applyAdminNetwork` restores the
  pool on startup — including the authoritative empty-list wipe.
- `POST /api/upstream` and the config-import path now call
  `SetProxies` (previously hardcoded CB params `5, 60s`) and persist via
  `adminSettingsSave()`. `apiConfigImport` also gained a single
  `adminSettingsSave()` so ALL imported admin-settings-layer values (rate
  limit, IP filter, block page, conn limit, …) survive restart — import was
  previously runtime-only for that layer.
- `initUpstreamProxy` no longer gated on a non-empty YAML proxy list, so CB
  params and the health-check loop are wired for GUI-added proxies. The
  SIGHUP reload path keeps the non-empty gate (a YAML reload must not wipe
  GUI state) and now shares `resolveUpstreamPoolStartupConfig` instead of
  duplicating the CB-timeout parsing inline.
- `setProxiesLocked` rejects host-less URLs (`parent:3128` without a scheme
  parses opaque and can never be dialed) instead of silently accepting them.

**Why**
Reliability gap logged in `roadmap/CATEGORY-B-PRIME-FINDING-10.3-SPEC.md` §5:
upstream changes made in the admin GUI were lost on every container
restart/update, and the API path silently discarded the operator's
circuit-breaker configuration.

**Risks**
- Proxy URLs may embed credentials; they now persist raw in
  admin_settings.json. Deliberate: the file is 0600 and already carries
  secrets (`metrics_token`); display paths keep using redacted `List()`.
- Once any admin API mutation runs, the persisted upstream list becomes
  authoritative over later YAML edits (same semantics as blocklist feeds /
  YARA settings — consistent with the established sentinel design).
- Health-check loop now starts with an empty pool when `health_interval` is
  set (no-op ticks; negligible).

**Validation**
`go build`, `go vet`, full `go test .` (46s) green, full `-race` suite green
(386s), new-issue-scoped golangci-lint (`--new-from-rev=main`) 0 issues,
`-count=2 -shuffle=on` on the touched test surface green. 8 new tests in
`admin_settings_upstream_test.go`.

**Remaining work / follow-ups**
- Cluster `ConfigSnapshot` does not propagate upstream pool config to DP
  nodes (pre-existing; separate design question).
- `apiUpstreamSettings` (GET-only) still exposes no way to edit CB params
  from the GUI — CB stays YAML-owned for now; a GUI-parity endpoint would
  need `saveConfigVersion` + UI panel work.
- Export/import of `UpstreamProxies` remains URL-only and lossy for webhook
  secrets per Finding 10.3 (unchanged surface).
