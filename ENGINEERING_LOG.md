# Engineering Log — overnight engineering branch

Branch: `claude/overnight-engineering-uc5sld` (based on `main` @ 64363b8).
Newest entry first.

---

## 7. Bound the cluster-enrollment rate-limiter map

**What changed**
`enrollRateLimit.attempts` (controlplane.go), keyed by client IP, prunes an
IP's timestamp slice only on that IP's NEXT enrollment attempt. An IP that
attempts once and never returns leaves a permanent entry — unbounded growth
keyed by source IP (third and last of the maps the audit found).

- Added `enrollRateLimitCleanup`: drops entries whose timestamps have all aged
  out of the window, prunes stale timestamps from surviving entries. Wired into
  the shared security-limiter janitor (now: `rl` + SSRF DNS + login-lockout +
  admin-API + enrollment). No-op on non-control-plane nodes (empty map).
- Factored the window into `enrollRateLimitWindow` so the hot path and the
  sweep agree on staleness.

**Why**
Completes the unbounded-map cleanup surfaced by the audit. Lower cardinality
than the login map (enrollment is a cluster control-plane endpoint), but still
unbounded over a long uptime.

**Validation**
`go build`, full `go test .` (47s) green, race on the enrollment / janitor /
cluster paths green, `--new-from-rev=main` lint 0 issues. New test: single
one-shot, all-stale, in-window, and mixed entries — evicts the stale, keeps and
prunes the live.

**Audit closure**
All three genuinely-unbounded maps from the untrusted-key audit are now
bounded (login-lockout #6, admin-API #6, enrollment #7); the top-hosts map was
#5. Every other per-request/per-IP/per-host map in the codebase was verified to
already have a cap, TTL, LRU, or removal-on-release.

---

## 6. Bound the login-lockout and admin-API rate-limiter maps (auth-path DoS)

**What changed**
Two more unbounded maps in the auth/security path (same bug class as #5,
higher severity because one is unauthenticated and keyed by fully
attacker-controlled input):

- `LoginLimiter.entries` (internal/lockout) is keyed by the **username** from
  the unauthenticated login POST body. It had NO `Cleanup` method and no
  janitor — an entry created with 1–4 failures has a zero `lockedUntil` and is
  never swept, so one failed login per distinct random username leaks a
  permanent entry (memory-exhaustion DoS, no credentials required).
- `APIRateLimiter.Cleanup` (internal/lockout, keyed by client IP) already
  existed but was **never wired** to any janitor.
- The shared 5-minute cleanup janitor (`rateLimitCleanupLoop`) only spawned
  when `RateLimitRPM > 0` — but the lockout and API limiters are ALWAYS active,
  so with the optional IP rate limit disabled nothing swept them.

Fix:
- Added `LoginLimiter.Cleanup`: evicts entries whose lock has expired or whose
  unlocked failure-window has elapsed (behavior-identical to the lazy reset
  both hot paths already do — changes no decision), keeping in-window and
  actively-locked entries.
- The security janitor now spawns UNCONDITIONALLY and ticks
  `loginLimiter.Cleanup()` + `apiLimiter.Cleanup()` alongside `rl.Cleanup()` +
  `ssrf.CacheCleanup()`. `rl.Cleanup` on an unconfigured limiter is a harmless
  empty walk. (Side benefit: the SSRF DNS cache is now also swept when rate
  limiting is off — it wasn't before.)

**Why**
An unauthenticated username-keyed map with no eviction is a textbook
memory-exhaustion DoS. Wiring the janitor unconditionally is the correct
lifetime for limiters that don't depend on the rate-limit toggle.

**Risks**
- Very low. `Cleanup` only removes entries a future hot-path call would have
  reset/deleted anyway. The janitor always running is one cheap 5-minute
  goroutine (it already ran in every rate-limit-enabled deployment).
- Two loader tests pinned the old "returns nil cancel when rate limit
  disabled" behavior; updated to assert the janitor now always spawns (the old
  behavior was the bug) and that the IP limiter stays unconfigured.

**Validation**
`go build`, full `go test .` (48s) green, race on `internal/lockout` green,
full cumulative `-race` suite (through iter 5) green, `--new-from-rev=main`
lint 0 issues. New tests: `LoginLimiter.Cleanup` evicts the two stale classes
and keeps the two live ones, and a behavior-preservation test (post-cleanup
failure starts a fresh window). Loader tests updated for the always-on janitor.

**Remaining work / follow-ups**
- The enrollment rate limiter (`controlplane.go` `enrollRateLimit.attempts`,
  keyed by client IP) writes back empty slices but never deletes the map key —
  a slower unbounded growth. Next iteration.

---

## 5. Bound the top-hosts counter (unbounded-memory DoS)

**What changed**
`topHosts` was a `map[string]int64` keyed by hostname, incremented on every
allowed request and NEVER evicted. The hostname is attacker-controllable, so a
client requesting arbitrarily many distinct hosts (`random-N.example.com`) grew
the map without limit — a memory-exhaustion DoS — and it also grows unbounded
on any proxy serving naturally diverse traffic over a long uptime.

- The counter is now hard-capped at `topHostsMaxEntries` (10,000 distinct
  hosts). At capacity, a new host triggers a decay pass (halve every count,
  drop those that reach zero) that evicts cold entries — including
  high-cardinality count-1 flood junk — while continuously-reinforced heavy
  hitters survive (a host that goes silent correctly ages out). Decay is O(n)
  but amortized to at most once per `topHostsMaxEntries` new-host drops, so
  each `Record` is amortized O(1). Already-tracked hosts always increment,
  never gated.

**Why**
Unbounded memory keyed by untrusted input is a latent DoS. The decay design
also resists top-N poisoning: a flood of one-off hosts (count 1) is exactly
what decays out first, so the dashboard keeps showing the real heavy hitters
even under a cardinality flood.

**Risks**
- Counts become approximate lower bounds once the cap is first hit (standard
  for a bounded frequent-items counter). The RANKING — what "top hosts" is
  for — stays correct. Below 10k distinct hosts (the overwhelming common
  case) behavior is unchanged and counts are exact.

**Validation**
`go build`, full `go test .` (47s) green, race on the counter + record paths
green, `--new-from-rev=main` lint 0 issues. 4 new tests: memory strictly
bounded under a 50k-host flood, heavy hitters survive an interleaved flood
(no poisoning), already-tracked hosts keep counting at capacity, and Top()
ordering.

---

## 4. IP filter fails closed on a corrupt mode (was: silent fail-open)

**What changed**
`IPFilter.SetMode` stored any string verbatim, and `IPFilter.Allowed()` treats
an unrecognized mode as "allow all" (filter disabled). The validated admin API
rejects bad modes, but SIX persistence/snapshot callers pass the value raw:
config reload (main.go), `admin_settings.json` restore, config-version
rollback (`applyConfigBackup`), cluster `ConfigSnapshot` apply
(controlplane.go), and connlimit startup. A corrupt or hand-edited persisted
value therefore silently disabled IP filtering — a fail-OPEN security
regression, flagged only as a dry-run warning that the apply path ignored.

- `SetMode` now coerces an unrecognized non-empty mode to the restrictive
  `"block"` (fail closed). The `""` disabled sentinel and the two valid modes
  pass through unchanged, so the validated API path is unaffected.

**Why**
Defense-in-depth at the root cause: every unvalidated persistence/snapshot
path becomes fail-closed instead of fail-open, without touching the six call
sites individually. A restrictive (over-block) failure is the correct security
default over a silent filter-disable.

**Risks**
- Extremely low. Only affects inputs that are already invalid (not "",
  "allow", or "block"). One existing test used `"deny"` as a placeholder mode
  and asserted it round-tripped through a cluster snapshot; updated to the
  valid `"block"` (its round-trip intent is preserved — it was never testing
  invalid-mode handling).

**Validation**
`go build`, full `go test .` (47s) green, race on the IPFilter / config-version
/ cluster-snapshot paths green, `--new-from-rev=main` lint 0 issues. 2 new
tests: invalid modes coerce to block AND actually filter (proving not
fail-open); valid modes + "" pass through unchanged.

**Remaining work / follow-ups**
- `applyConfigBackup` still applies a config-version snapshot even when
  pre-flight `validateConfigBackup` returns warnings (the non-dry-run path
  reports them but proceeds). Most flagged values are now coerced safely
  (blocklist mode → block, default action → deny, IP filter mode → block,
  negative rate limit → skipped), so no unsafe state results, but making the
  apply reject hard-invalid snapshots (vs. only warning) is a reasonable
  follow-up. Logged, not addressed here (behavior change to a heavily-speced
  subsystem).

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
