# Docker Self-Update System Design

> **⚠️ Status: SUPERSEDED — DEPRECATED.** This document is preserved for historical context and is no longer the active design. It is **superseded by [`D1.6-maintenance-agent-design.md`](./D1.6-maintenance-agent-design.md)** (Maintenance Agent / Host Operations).
>
> **Why deprecated:** the architecture below assumes the GUI/CP container drives Docker via a mounted `/var/run/docker.sock`. That trust posture is too broad for the production deployments we want to support. D1.6 redraws the boundary so the GUI/CP **never** speaks to Docker directly; a scoped, host-side Maintenance Agent does.
>
> **Important:** the update *capability* is **not** being deleted — only this specific design is. New work targets D1.6.

---

Enterprise-grade GUI-driven update system for Culvert Docker deployments.
Supports standalone and multi-node cluster modes with zero-downtime rolling updates.

---

## Architecture

```
┌─────────────────────────────────────────────┐
│ Docker Host                                  │
│                                              │
│  ┌──────────┐  HTTP :7123  ┌──────────────┐ │
│  │ Culvert  │─────────────▶│   Updater    │ │
│  │ (proxy)  │              │  (~5MB idle)  │ │
│  │ no sock  │              │  docker.sock  │ │
│  └──────────┘              └──────┬───────┘ │
│                                   │         │
│                          Docker Engine API   │
└─────────────────────────────────────────────┘
```

**Always-on updater service** (`culvert-updater`) — a tiny Go HTTP server in docker-compose
that mounts `/var/run/docker.sock` and does nothing until Culvert calls it. The main
Culvert container never touches the Docker socket. The updater is idle 99.99% of the
time (~4MB RSS).

A container can't spawn another container without Docker API access. The always-on
updater is the minimal shim that enables GUI-driven updates without shell access.

---

## New Files

### `updater/main.go` (~300 lines) — Updater service binary

Separate Go module (`updater/go.mod`) with `github.com/docker/docker/client` dependency.

HTTP server on `:7123`, exposed to host for GUI resilience during CP updates.

**Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | GET | `{"ok": true}` |
| `/api/update/check` | GET | Query registry for latest tag, return `{current, latest, updateAvailable}` |
| `/api/update/preview` | POST | Pull image if needed, return diff of current vs new container config (env, volumes, ports, CMD). Secrets masked. |
| `/api/update/apply` | POST | Pull → stop → rename → create → start → health check → rollback on failure. Returns SSE progress stream. |
| `/api/update/rollback` | POST | Restore rollback container (during grace period only) |
| `/api/update/rollback/status` | GET | `{available, expiresAt, rollbackTag}` |
| `/api/update/session` | GET | Active update state for SSE re-attachment |
| `/api/update/load` | POST | Accept `docker save` tarball for air-gapped environments |
| `/api/self-update` | POST | Update the updater itself via "reaper" container pattern |

**Auth:** Bearer token read from `/data/updater_token.txt` on every request (no startup race).

### `updater/go.mod` — Separate module

```
module culvert-updater
go 1.25
require github.com/docker/docker v...
```

### `Dockerfile.updater` — Minimal image

```dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY updater/ .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o culvert-updater .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/culvert-updater /usr/local/bin/culvert-updater
ENTRYPOINT ["culvert-updater"]
```

### `update.go` (~250 lines) — Culvert-side update logic

- **Version check goroutine**: Runs every 6h via `time.NewTicker` + `appLifecycleCtx`. Queries registry tags, compares semver, stores in `updateInfo` (sync.RWMutex-protected).
- **Updater client**: `checkForUpdate()`, `triggerLocalUpdate(targetTag) (<-chan UpdateEvent, error)`.
- **Token generation**: On first boot, writes random 32-byte hex to `/data/updater_token.txt`.
- **API handlers**: `apiUpdateStatus`, `apiUpdateCheck`, `apiUpdateApply`, `apiUpdateReports`.

```go
type updateInfo struct {
    mu              sync.RWMutex
    currentVersion  string
    latestVersion   string
    updateAvailable bool
    lastChecked     time.Time
}

type UpdateEvent struct {
    Step    string `json:"step"`    // "pulling", "stopping", "starting", "health_check", "complete", "rolled_back", "error"
    Detail  string `json:"detail"`
    Percent int    `json:"percent"`
}
```

### `update_cluster.go` (~350 lines) — Cluster rolling update orchestration

```go
type ClusterUpdateState struct {
    mu           sync.Mutex
    Active       bool                          `json:"active"`
    TargetTag    string                        `json:"target_tag"`
    PreviousTag  string                        `json:"previous_tag"`
    Initiator    string                        `json:"initiator"`
    StartedAt    time.Time                     `json:"started_at"`
    Nodes        map[string]*NodeUpdateStatus  `json:"nodes"`
    Phase        string                        `json:"phase"` // "updating_dps", "updating_cp", "complete", "failed", "halted", "cp_rolled_back"
    ErrorBudget  ErrorBudgetConfig             `json:"error_budget"`
    Failures     int                           `json:"failures"`
    ConsecFails  int                           `json:"consec_fails"`
}

type NodeUpdateStatus struct {
    NodeID     string `json:"node_id"`
    Status     string `json:"status"` // "pending", "draining", "updating", "verifying", "complete", "failed", "unknown"
    OldVersion string `json:"old_version"`
    NewVersion string `json:"new_version"`
    Detail     string `json:"detail"`
    DurationS  int    `json:"duration_s"`
}

type ErrorBudgetConfig struct {
    MaxConsecutive int `json:"max_consecutive"` // default 3
    MaxPercent     int `json:"max_percent"`     // default 20
}
```

**New gRPC method:** `TriggerUpdate` — CP sends to DP, DP calls its local updater.

**DP progress reporting:** Extend `PushMetrics` with optional `UpdateProgress` field.

**Persistent state:** Written to `/data/cluster_update.json` on every transition.

---

## Modified Files

### `main.go`
- Add `-updater-url` flag (default `http://culvert-updater:7123`)
- Start version check goroutine with `appLifecycleCtx`
- Generate updater token on first run
- On startup: read `/data/cluster_update.json` for interrupted updates

### `ui.go`
Register new routes in `startUI()`:
```go
mux.HandleFunc("/api/update/status", apiUpdateStatus)                // GET, viewer
mux.HandleFunc("/api/update/check", apiUpdateCheck)                  // POST, admin
mux.HandleFunc("/api/update/apply", apiUpdateApply)                  // POST, admin
mux.HandleFunc("/api/update/cluster", apiClusterUpdate)              // POST, admin
mux.HandleFunc("/api/update/cluster/status", apiClusterUpdateStatus) // GET, viewer
mux.HandleFunc("/api/update/reports", apiUpdateReports)              // GET, viewer
```

### `controlplane.go`
- Register `TriggerUpdate` gRPC method handler (DP-side)
- Extend `MetricsReport` with optional `UpdateProgress` field
- CP reads update progress from DP metrics pushes

### `events.go`
Add to `DashboardPayload`:
```go
UpdateAvailable bool   `json:"updateAvailable,omitempty"`
LatestVersion   string `json:"latestVersion,omitempty"`
```

### `alerts.go`
Add event types: `"cluster_updated"`, `"cluster_update_halted"`.

### `config.go`
Add `UpdaterURL` field to config struct.

### `static/index.html`
New `data-view="updates"` panel with sections:
- **Version Status** — cards: Current Version, Latest Available, Last Checked, Updater Status
- **Config Preview** — diff-style two-column view (current vs new). Secrets masked. Added=green, removed=red, changed=yellow
- **Update Progress** — live progress bar + step labels + "Verifying health (2/3)..."
- **Cluster Rolling Update** (CP only) — node table with status dots, error budget selector, "Update Cluster" button
- **Registry Settings** (admin-only) — custom registry URL + credentials for enterprise/air-gapped
- **Update Reports** — list of past update reports with "Download JSON" button

### `docker-compose.yml`
```yaml
updater:
  build:
    context: .
    dockerfile: Dockerfile.updater
  container_name: culvert-updater
  restart: unless-stopped
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock:ro
    - proxy-data:/data:ro
  ports:
    - "7123:7123"  # GUI resilience during CP update (bearer auth required)
  environment:
    - UPDATER_REGISTRY=${UPDATER_REGISTRY:-ghcr.io/kidcarmi/culvert}
    - UPDATER_REGISTRY_AUTH=${UPDATER_REGISTRY_AUTH:-}
    - UPDATER_HEALTH_CHECKS=${UPDATER_HEALTH_CHECKS:-3}
    - UPDATER_HEALTH_INTERVAL=${UPDATER_HEALTH_INTERVAL:-5s}
    - UPDATER_ROLLBACK_TTL=${UPDATER_ROLLBACK_TTL:-1h}
    - UPDATER_KEEP_IMAGES=${UPDATER_KEEP_IMAGES:-3}
```

### `docker-compose.ha.yml`
Same updater service, available to both CP and DP profiles.

---

## Update Flows

### Standalone
```
1. Admin opens Updates panel → sees "v2.1.0 available"
2. Clicks "Preview Changes" → sees config diff (env, volumes, ports)
3. Reviews diff → clicks "Confirm Update"
4. POST /api/update/apply → Culvert calls updater
5. Updater: pull → inspect → stop (30s drain) → rename to rollback → create → start
6. Health: 5s boot wait → 3 consecutive 200s at 5s intervals → PASS
7. GUI shows "Update complete! Rollback available (59m)"
8. After 1h: rollback container + old image auto-cleaned
```

### Cluster (multi-node)
```
1. Admin clicks "Update Cluster" on CP GUI
2. Selects error budget: Conservative (2/10%) | Normal (3/20%) | Aggressive (5/50%)
3. POST /api/update/cluster → CP starts rolling update

Phase 1 — Update DPs (one at a time):
  For each DP:
    a. Set node "draining" → 10s grace period
    b. Send TriggerUpdate gRPC → DP calls its local updater
    c. Wait for DP health (3/3 checks, 120s timeout)
    d. Success → mark complete, un-drain, next DP
    e. Failure → mark failed, un-drain, check error budget
    f. Error budget exceeded → HALT, alert admin

Phase 2 — Update CP:
  If HA enabled:
    a. Update standby first (via its local updater)
    b. 30s settling period + final HASync + version verification
    c. Leader hands off → standby promotes
    d. Old leader (now standby) updates itself
    e. Old leader comes back → cluster fully updated
  If no HA (single CP):
    a. CP calls its local updater → container restarts (~10s)
    b. DPs retry with backoff, reconnect when CP is back
    c. GUI shows "CP Updating" overlay polling updater on :7123

Phase 3 — Complete:
  Generate update report → /data/update_reports/<ts>.json
  Fire "cluster_updated" webhook alert with full report
  GUI shows summary with per-node results
  "Download Update Report" button available
```

---

## Edge Cases & Robustness

### 1. Image Pull Timeouts
SSE streaming with chunked transfer encoding — no overall timeout. Docker SDK's `ImagePull`
is a streaming reader; updater emits progress events with percentage. GUI shows live
progress bar.

### 2. Disk Space Pre-Flight
Before pulling, updater checks `DiskUsage` via Docker API. Accounts for shared layers
(Docker dedup). Rejects if <500MB free after pull estimate.

### 3. Old Image Cleanup
After successful update: prune dangling images. Keep current + 2 previous tags (configurable
via `UPDATER_KEEP_IMAGES`). Disk usage shown in GUI.

### 4. Schema/Config Compatibility (Mixed Versions)
- `ConfigSnapshot` uses JSON `omitempty` — old nodes ignore unknown fields, new nodes use defaults
- New gRPC methods return `Unimplemented` on old nodes — CP handles gracefully
- Max 1 minor version skew enforced with GUI warnings
- State files use forward-compatible JSON; migration runs on startup before traffic

### 5. Private Registry / Air-Gapped
- `UPDATER_REGISTRY` env var overrides default `ghcr.io/kidcarmi/culvert`
- `UPDATER_REGISTRY_AUTH` for X-Registry-Auth header on pull
- GUI "Registry Settings" section stores config in `/data/updater_config.json`
- Air-gapped: `POST /api/update/load` accepts `docker save` tarball

### 6. Forward Skew (CP Rollback After DPs Updated)
- CP never rejects newer DPs — warns in GUI only
- gRPC backward compat: DPs handle `Unimplemented` from old CP gracefully
- Phase set to `"cp_rolled_back"` with clear GUI warning and options
- No auto-rollback of working DPs — admin decides

### 7. Compose "Truth" Problem
Updater captures **running container config** via `ContainerInspect`, not `docker-compose.yml`.
Runtime state preserved, uncommitted compose changes not applied. GUI shows captured config
before confirmation. Documented in panel.

### 8. Token Sync (Race-Free)
Updater reads `/data/updater_token.txt` on every request (not at startup). If file doesn't
exist: 503 with `retry_after: 5`. Token rotation takes effect on next request — no restart.

### 9. GUI Resilience During CP Update
Frontend stores updater address in `localStorage`. On connection loss: shows "CP Updating"
overlay that polls updater on `:7123` for progress. Auto-reloads when CP is back.

### 10. Failure Log Capture
Before removing failed container: `docker logs --tail 200` saved to
`/data/update_failures/<timestamp>.log`. Rollback SSE event includes last 50 lines.
GUI shows expandable failure logs. Auto-pruned after 7 days.

### 11. Multi-Network Recreation
`ContainerInspect` captures all attached networks. Container created on first network,
then `NetworkConnect` called for each additional network (preserving aliases + fixed IPs).
Warning logged if any connect fails — not rollback-worthy.

### 12. Updating the Updater
Updater exposes `/api/self-update` which spawns a **"reaper" container** (`--rm`) that
outlives the updater, swaps it, then self-destructs. In practice updater updates are rare
(~yearly). Manual alternative: `docker compose pull updater && docker compose up -d updater`.

### 13. SSE Re-attachment
`GET /api/update/session` returns active update state. GUI checks on load — if active
update found, shows progress overlay pre-populated with current state and re-attaches
to SSE stream. Update runs server-side regardless of browser connection.

### 14. Cluster Error Budget
Default: stop after 3 consecutive failures OR >20% total failures. Configurable:
Conservative (2/10%), Normal (3/20%), Aggressive (5/50%). On halt: webhook alert,
GUI shows Resume/Rollback options.

### 15. Crash Recovery
CP persists `ClusterUpdateState` to `/data/cluster_update.json` on every transition.
On restart: reads file, waits for DP heartbeats to reconcile versions, shows
"Update interrupted" with Resume/Abort. Updater checks for orphaned rollback containers.

### 16. HA Settling Period
After standby health (3/3): 30s settling + final HASync + version verification.
Leader retries sync up to 3 times if mismatch. Handoff only after versions match.
DPs see at most one missed 5s poll.

### 17. Update Audit Report
Structured JSON report on every update (complete or halted). Contains: initiator,
timestamps, per-node results, error budget, failure references. Persisted to
`/data/update_reports/`, logged to audit, sent via webhook. GUI "Download Report" button.
90-day retention (configurable).

### 18. Health Verification
Not a single check — **3 consecutive 200 responses** over 15s (5s boot grace + 5s intervals).
Total timeout: 120s. Configurable checks/interval. Single check is insufficient — container
may pass one then crash during CA decryption, ClamAV connect, or policy load.

---

## Implementation Phases

### Phase 1 — Updater Service
Files: `updater/main.go`, `updater/go.mod`, `Dockerfile.updater`
- Docker SDK integration (pull, inspect, stop, rename, create, start, remove, logs)
- Health verification loop, rollback logic, disk check, image prune
- Multi-network recreation, token auth, SSE streaming
- Air-gapped image load endpoint

### Phase 2 — Standalone Update
Files: `update.go`, `ui.go`, `static/index.html`, `config.go`, `main.go`, `docker-compose.yml`
- Version check goroutine + updater client
- API endpoints (status, check, apply, reports)
- GUI panel (version cards, config preview diff, progress bar, registry settings)
- CP blind-spot overlay with updater fallback polling
- Token generation on first boot

### Phase 3 — Cluster Rolling Update
Files: `update_cluster.go`, `controlplane.go`, `docker-compose.ha.yml`, `alerts.go`
- Rolling update state machine with persistent state
- `TriggerUpdate` gRPC method + DP handler
- Error budget enforcement + crash recovery
- DP progress reporting via PushMetrics
- Cluster GUI section with per-node status table
- Update audit reports + webhook integration

### Phase 4 — HA-Aware CP Update
Files: `update_cluster.go`, `ha.go`
- Standby-first-then-leader orchestration
- 30s settling period + sync verification before handoff
- Forward skew handling (CP rollback with newer DPs)

---

## Estimated Effort

| Phase | Effort |
|-------|--------|
| Updater service (pull, recreate, rollback, disk, prune, multi-net, logs, self-update) | ~2.5 days |
| Standalone update (Go + GUI + preview diff + blind-spot overlay + SSE re-attach) | ~2 days |
| Cluster rolling update (state machine + error budget + crash recovery + reports) | ~2.5 days |
| HA-aware CP update (settling + sync + forward skew) | ~1 day |
| **Total** | **~8 days** |
