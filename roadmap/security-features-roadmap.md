# YARA & ClamAV Deep Dive: Edge Cases and Admin Friction Fixes

Technical audit of Culvert's security scanning subsystem (YARA, ClamAV, scan orchestration).
Identifies edge cases that silently degrade scanning effectiveness and operational friction
that makes it hard for admins to manage the scanning pipeline.

---

## Design Decisions

### Q1: CRUD Persistence for YARA Rules via GUI

Currently YARA rules are **files on disk** at `/app/yara/` (`Dockerfile:68`). `LoadDir()` at
`yara_scan.go:73-101` globs `*.yar`/`*.yara` files and loads them. In Docker, rules are
bundled at build time (`COPY yara/ ./yara/`); admins can override by mounting a volume
over `/app/yara` (`docker-compose.yml:89`).

**For GUI-based CRUD**: Write rules to `/data/yara/` (persistent volume, survives restarts)
rather than `/app/yara/` (read-only image layer). Implementation:
1. `POST /api/security-scan/yara/rules` — accepts `{name, source}`, writes to
   `/data/yara/{name}.yar` (validate with `parseYARASrc()` BEFORE writing)
2. `PUT /api/security-scan/yara/rules/{name}` — updates existing file
3. `DELETE /api/security-scan/yara/rules/{name}` — removes file
4. After each write, call `globalYARA.LoadDir(dir)` to reload atomically
5. `LoadDir()` already handles the reload safely (mutex swap at line 90-93)

Persistence is guaranteed because `/data/` is a Docker volume (`docker-compose.yml:124`).
The DPI content scanner (`scanner.go`) already follows this exact pattern: `Add()`, `Remove()`,
`Save()` (atomic tmp+rename at line 95-108) — reuse that approach.

### Q2: Global Scan Exclusion List (Hash/Path Whitelist)

No unified scan exclusion exists today. The hash cache only caches scan results, not exemptions.

**Design**: Add a `ScanExclusionStore` in `security_scan.go` with two maps:
- `excludedHashes map[string]bool` — SHA-256 hashes that skip all scanning
- `excludedHosts map[string]bool` — hostnames that bypass body scanning

**Concurrency**: Use `sync.RWMutex` (not `sync.Mutex`). The read:write ratio is extreme —
`IsExcluded()` is called on every request (thousands/sec), writes happen rarely (admin updates).
`RLock` for reads avoids serialization in the hot path. This matches every read-heavy store
in the codebase: `HashCache`, `SecurityScanner`, `YARARuleSet`, `ContentScanner` all use
`sync.RWMutex`, and CLAUDE.md mandates it for read-heavy stores.

Check in `ScanBody()` BEFORE the hash cache lookup (line 231):
```go
if ss.IsExcluded(hash) { return nil }  // skip scan entirely
```
Check in the proxy pipeline BEFORE buffering (around `proxy.go:612`):
```go
if ss.IsHostExcluded(r.Host) { scanActive = false }
```

This is NOT a new middleware layer — it's two map lookups injected at existing decision points.
Persist to `/data/scan_exclusions.json`. Expose via `GET/PUT /api/security-scan/exclusions`.

Follows the same pattern as rate-limit exemptions (`security.go:247-316`): a `sync.RWMutex`-protected
map with `Add`, `Remove`, `List`, `IsExempt` methods.

### Q3: DPI Runtime Configuration

The DPI content scanner already has a **full CRUD API** at `ui.go:3133-3200`:
- `GET /api/content-scan` — list patterns + blocked count
- `POST /api/content-scan` — add pattern(s), validates with `regexp.Compile` before adding
- `DELETE /api/content-scan?pattern=X` — remove a pattern

It also has `Set()` (atomic swap, `scanner.go:55-68`), `Add()` (line 112), `Remove()` (line 126),
`Save()` (atomic write, line 95), and `Load()` (line 73). All runtime-modifiable, no restart needed.

What's **missing** is DPI bypass/exclusion per host or IP. Currently DPI applies to ALL
SSL-inspected traffic. To add bypass:
1. Add `dpiBypassHosts map[string]bool` to `ContentScanner` (mutex-protected)
2. Check before `Scan()` in the inspect handler (`proxy.go:1144-1152`)
3. Expose via `GET/PUT /api/content-scan/bypass` endpoint
4. Persist alongside patterns in the same JSON file

### Q4: Atomic Rule Swapping (Race Prevention)

`LoadDir()` at `yara_scan.go:73-101` is already designed to prevent races:
1. **Parsing phase** (lines 80-88): reads and parses all files into a local `[]yaraCompiledRule`
   slice. This happens WITHOUT holding any lock — in-flight scans continue uninterrupted.
2. **Swap phase** (lines 90-93): acquires write lock, replaces `y.rules` with the new slice,
   releases lock. This is a pointer swap — takes nanoseconds.

The risk is: what if an admin writes a `.yar` file and calls `LoadDir()` simultaneously, and
`LoadDir()` reads a partially-written file? Two mitigations:
1. **Atomic file write** (same pattern as DPI `Save()` at `scanner.go:95-108`): write to
   `{name}.yar.tmp`, then `os.Rename()` to `{name}.yar`. Rename is atomic on POSIX.
2. **Parse-before-persist**: When adding a rule via the API, validate with `parseYARASrc()`
   BEFORE writing to disk. If parsing fails, the file is never created.

A staging directory is unnecessary — atomic rename + parse-before-write achieves the same
safety without the complexity of a two-phase commit.

### Q5: Cache Coherency & Rule Propagation

Hash cache is atomically invalidated on YARA reload by calling
`globalSecScanner.cache.Clear()` (holds write lock, replaces entire map). In-flight scans
that already resolved a cache hit complete with the old verdict — harmless since they
committed to old rules for that request. All subsequent requests trigger fresh scans.

### Q6: Silent Failure Visibility

5 new metrics needed: `stat_scan_timeout`, `stat_scan_skipped`, `stat_remote_scan_fail`,
`yara_inflight`, `yara_inflight_max`. Note: timeouts are fail-CLOSED (block), goroutine
exhaustion is fail-OPEN (skip), remote sidecar is fail-OPEN by design.

### Q7: Hot-Reload Mechanism

YARA already supports hot-reload via `POST /api/security-scan/yara/reload` using
`sync.RWMutex` atomic swap (`yara_scan.go:90-93`). DPI patterns (`scanner.go:55-68`)
have `Set()` with atomic swap and full CRUD API at `ui.go:3133-3200`.

### Q8: Contextual Attribution

Beyond counters, add a ring buffer of last N scan events (host, client IP, hash, reason)
exposed via API, similar to the existing request log pattern in `store.go`.

### Q9: Sidecar Resiliency

Three-layer approach: atomic failure counter, debounced webhook alert via existing
`fireAlert()` + dedup mechanism (`alerts.go:44-49`, 30s TTL), and health probe with
`degraded` field in status map.

---

## Tier 1 — Must-Have (correctness bugs)

### 1.1 Cache not invalidated after YARA rule reload

**Problem**: When an admin reloads YARA rules via `POST /api/security-scan/yara/reload`,
the hash cache retains old "clean" verdicts from the previous rule set. Content that was
scanned and cached as clean under old rules won't be re-scanned with new rules for up to
1 hour (cache TTL). This makes rule updates effectively delayed.

**Files**:
- `ui.go:3686-3693` — `apiSecYARAReload()` handler
- `hashcache.go:122-126` — `Clear()` method already exists

**Fix**: After successful `LoadDir()` in `apiSecYARAReload`, call `globalSecScanner.cache.Clear()`.
Add audit event and `"cache_cleared": true` to the JSON response.

### 1.2 Missing scan statistics for timeouts and skipped scans

**Problem**: When body scans time out (10s deadline) or are skipped (response > 5 MiB),
there are no counters visible in the status API. Admins must grep logs to discover these events.
The `secScanStatusMap()` function only reports `stat_clam_blocked`, `stat_yara_blocked`, and
`stat_feed_blocked` — nothing for timeouts or size-skips.

**Files**:
- `security_scan.go:47-51` — existing stat counters (add two more here)
- `security_scan.go:257` — timeout path (increment `statScanTimeout`)
- `security_scan.go:415-456` — `secScanStatusMap()` (expose new counters)
- `proxy.go:613-615` — scan skip path (increment `statScanSkipped`)

**Fix**: Add two new `int64` atomic counters:
```go
var statScanTimeout  int64
var statScanSkipped  int64
```
Increment `statScanTimeout` at `security_scan.go:257` (timeout branch).
Increment `statScanSkipped` at `proxy.go:615` (size skip) and the equivalent in the
CONNECT/tunnel inspect handler.
Add both to `secScanStatusMap()` as `"stat_scan_timeout"` and `"stat_scan_skipped"`.

### 1.3 YARA regex goroutine exhaustion is invisible

**Problem**: When 50+ regex goroutines time out (ReDoS), all subsequent regex matches are
silently skipped (return `false` = no match). Effectively, YARA rules stop working with
no visibility in the admin UI. The only signal is a log message.

**Files**:
- `yara_scan.go:177-189` — `yaraInflight` counter and skip logic
- `security_scan.go:415-456` — `secScanStatusMap()` (expose inflight count)

**Fix**: Expose in `secScanStatusMap()`:
```go
"yara_inflight":     yaraInflight.Load(),
"yara_inflight_max": int64(maxYARAInflight),
```
Fire `fireAlert("yara_degraded", ...)` when goroutines reach 80% of max (40/50).
Alert dedup (`alerts.go:44-49`, 30s TTL) prevents storms.

---

## Tier 2 — Should-Have (admin friction reduction)

### 2.1 YARA rule listing and parse error visibility

**Problem**: Admins can't see which rules are loaded. The reload endpoint only returns
a count. If a rule file has parse errors, the rule is silently skipped (`yara_scan.go:82-87`).
No way to verify which rules are actually active.

**Files**:
- `yara_scan.go` — add `Names()` method, `loadWarnings` field
- `yara_scan.go:70-98` — `LoadDir()` — capture parse warnings
- `ui.go` — add `GET /api/security-scan/yara/rules` endpoint
- `ui.go:113` — register new route in `startUI()`

**Fix**:
1. Add `Names() []string` method returning rule names under read lock.
2. Add `loadWarnings []string` field populated during `LoadDir()` for skipped rules.
3. Add `GET /api/security-scan/yara/rules` (viewer role): `{"rules": [...], "warnings": [...]}`.
4. Include `"yara_warnings"` count in `secScanStatusMap()`.
5. Include warnings in reload response.

### 2.2 Remote scan sidecar failure alerting

**Problem**: When the remote scan sidecar is down, `scan_remote.go` returns `nil` (fail-open)
with only a log line. Traffic passes through completely unscanned with no admin visibility.

**Files**:
- `scan_remote.go:66-125` — `ScanBody()` fail-open paths (lines 85, 95, 101, 107, 113)
- `security_scan.go:47-51` — counter declarations
- `security_scan.go:415-456` — `secScanStatusMap()`
- `alerts.go:246` — `fireAlert()` function

**Fix** (three-layer approach):
1. **Counter**: Add `var statRemoteScanFail int64`. Increment at each `return nil` fail-open
   path. Expose as `"stat_remote_scan_fail"` in `secScanStatusMap()`.
2. **Alert**: Fire `fireAlert("scan_svc_down", ...)` on first failure, debounced via existing
   alert dedup mechanism (30s TTL).
3. **Degraded flag**: Add `"scan_svc_degraded": true` to status map when failures exceed
   threshold, giving the UI a persistent warning indicator.

### 2.3 ClamAV status ping caching

**Problem**: Every `GET /api/security-scan/status` call triggers a synchronous `clam.Ping()`
which opens a TCP connection to ClamAV. Admin dashboard auto-refresh creates steady churn.
If ClamAV is slow/down, the status endpoint blocks.

**Files**:
- `security_scan.go:126-135` — `ClamAVStatus()` method

**Fix**: Cache the `ClamAVStatus()` result for 30 seconds using fields on `SecurityScanner`
(protected by existing `ss.mu`). On cache miss, run `Ping()` and store result + expiry.
Invalidate cache when `Init()` is called.

---

## Tier 3 — Future Enhancements

### 3.1 YARA rule test/validate endpoint

**Problem**: No dry-run mode. Admins must deploy rules to the filesystem, reload, and watch
logs. A bad rule is silently skipped.

**Files**:
- `yara_scan.go` — add `ValidateYARASource(src string) ([]string, error)` using existing
  `parseYARASrc()` at line 317 (stateless, no global mutation)
- `ui.go` — add `POST /api/security-scan/yara/validate` endpoint

**Fix**: Parse-only endpoint that validates a YARA rule string without loading it into the
engine. Returns `{"valid": true, "rule_names": [...]}` or `{"valid": false, "error": "..."}`.

### 3.2 YARA rule CRUD via GUI (file persistence)

**Problem**: Admins must SSH into the server, edit `.yar` files, and call the reload API.
No way to manage rules from the admin UI.

**Files**:
- `yara_scan.go` — add `ValidateYARASource()`, atomic file write helper
- `ui.go` — add `POST/PUT/DELETE /api/security-scan/yara/rules` CRUD endpoints
- `static/index.html` — YARA rules editor panel

**Fix**: See Design Decision Q1. Write to `/data/yara/`, validate before persisting,
atomic tmp+rename write. Auto-reload after each mutation.

### 3.3 Global scan exclusion list (hash/host whitelist)

**Problem**: No way to exempt known-good content from ClamAV + YARA scanning. False positives
require cache eviction each time, with no permanent exemption.

**Files**:
- `security_scan.go` — add `ScanExclusionStore` with `sync.RWMutex`-protected hash/host maps
- `ui.go` — add `GET/PUT /api/security-scan/exclusions` endpoint
- `proxy.go` — check host exclusion before buffering
- `static/index.html` — exclusion management panel

**Fix**: See Design Decision Q2. Two map lookups at existing decision points,
persisted to `/data/scan_exclusions.json`. Use `sync.RWMutex` for the extreme read:write ratio.

### 3.4 DPI bypass per host/IP

**Problem**: DPI applies to ALL SSL-inspected traffic with no per-host exemptions.

**Files**:
- `scanner.go` — add `dpiBypassHosts` map to `ContentScanner`
- `ui.go` — add `GET/PUT /api/content-scan/bypass` endpoint
- `proxy.go` — check bypass before DPI scan in inspect handler

**Fix**: See Design Decision Q3. Mutex-protected map, persisted with patterns.

### 3.5 Expose scan pipeline info in UI Security panel

**File**: `static/index.html` — Security Scanning panel

**Fix**: Add cards/rows for new counters and YARA rule list:
- Scan timeout count (red when > 0)
- Scan skipped count (yellow)
- YARA inflight goroutines (red warning if > 40)
- Remote scan failure count (if remote mode)
- YARA rule names (collapsible list)
- YARA load warnings (yellow alert banner)

---

## Implementation Sequence

1. **1.1** (cache clear on reload) — one-line fix, highest security impact
2. **1.2** (timeout + skip counters) — trivial atomic counters, same pattern as existing stats
3. **1.3** (YARA inflight visibility) — expose existing counter + fire alert
4. **2.2** (remote sidecar alerting) — counter + alert, same pattern
5. **2.3** (ClamAV ping cache) — self-contained refactor
6. **2.1** (YARA rule listing) — new endpoint + `LoadDir()` return type change
7. **3.1** (YARA validate) — new endpoint, reuses parser
8. **3.2** (YARA CRUD) — file persistence + API endpoints + UI editor
9. **3.3** (scan exclusions) — hash/host whitelist with persistence
10. **3.4** (DPI bypass) — per-host/IP exemption
11. **3.5** (UI updates) — aggregate all new metrics into Security panel

## Files to modify

| File | Changes |
|------|---------|
| `security_scan.go` | Add `statScanTimeout`, `statScanSkipped` counters; ClamAV ping cache; scan exclusion store (`sync.RWMutex`); extend `secScanStatusMap()` |
| `yara_scan.go` | Add `Names()`, `loadWarnings`, `ValidateYARASource()`, atomic file write for CRUD |
| `scan_remote.go` | Add `statRemoteScanFail` counter; increment on fail-open paths; debounced alert |
| `scanner.go` | Add `dpiBypassHosts` map to `ContentScanner` for per-host DPI bypass |
| `ui.go` | Clear cache on YARA reload; YARA CRUD + validate + listing; scan exclusions; DPI bypass endpoint |
| `proxy.go` | Increment `statScanSkipped`; check scan exclusion and DPI bypass at decision points |
| `static/index.html` | Extend Security panel: metrics, YARA rule editor, exclusion manager, DPI bypass |

## Verification

```bash
# Build and run tests
go build -o culvert .
go test -race -count=1 ./...

# Start the stack
docker compose up -d --build

# 1. Verify cache clear on YARA reload
curl -X POST https://localhost:9090/api/security-scan/yara/reload -k
# -> response should include "cache_cleared": true

# 2. Verify new status fields
curl https://localhost:9090/api/security-scan/status -k
# -> should include stat_scan_timeout, stat_scan_skipped, yara_inflight, yara_inflight_max

# 3. Verify YARA rule listing
curl https://localhost:9090/api/security-scan/yara/rules -k
# -> should return rule names array and warnings

# 4. Verify YARA validate endpoint
curl -X POST https://localhost:9090/api/security-scan/yara/validate -k \
  -d '{"rule": "rule test { strings: $a = \"test\" condition: $a }"}'
# -> should return {"valid": true, "rule_names": ["test"]}

# 5. Check UI — Security Scanning panel should show new metrics
```
