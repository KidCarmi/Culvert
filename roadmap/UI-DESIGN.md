# UI Panel Design — Unmapped Features

## Navigation Structure (Updated Sidebar)

```
MONITOR
  Dashboard
  Live Feed

ACCESS CONTROL
  Blocklist
  Security
  Policy Rules
  URL Categories
  File Blocking

NETWORK
  Header Rewrite
  Upstream Proxies        ← NEW
  PAC File

IDENTITY
  Identity Providers
  Users

SECURITY SCANNING
  Scan Engine             (existing, expanded)
  Threat Feeds            (existing)

CERTIFICATES
  SSL / TLS               (existing, expanded)
  CA Management           ← NEW sub-section

INFRASTRUCTURE                ← NEW SECTION
  Cluster Nodes           ← NEW
  Observability           ← NEW

TOOLS
  Policy Tester
  Audit Log
  Settings
```

---

## 1. Cluster Nodes Panel

**Purpose**: Deploy, monitor, and manage multi-node proxy deployments.

### Layout

```
┌─────────────────────────────────────────────────────────┐
│ Cluster Nodes                                    [Role] │
│                                                         │
│ ┌─ This Node ─────────────────────────────────────────┐ │
│ │ Role: Control Plane      Status: ● Active           │ │
│ │ gRPC Listen: :50051      mTLS: Enabled              │ │
│ │ Node ID: cp-primary      Uptime: 14d 6h             │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─ Connected Data Plane Nodes ────────────────────────┐ │
│ │                                                     │ │
│ │ Node ID    │ Status │ Last Sync │ Reqs  │ Blocked  │ │
│ │ dp-east-1  │ ● Up   │ 12s ago   │ 45.2k │ 312     │ │
│ │ dp-east-2  │ ● Up   │ 8s ago    │ 38.1k │ 287     │ │
│ │ dp-west-1  │ ○ Down │ 5m ago    │ 12.0k │ 91      │ │
│ │                                                     │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─ Enrollment ────────────────────────────────────────┐ │
│ │ New Data Plane node connection command:              │ │
│ │ ┌──────────────────────────────────────────────┐    │ │
│ │ │ ./culvert -dp-cp-addr 10.0.1.5:50051 \      │    │ │
│ │ │   -dp-node-id dp-new \                       │    │ │
│ │ │   -dp-cert /certs/dp.crt \                   │    │ │
│ │ │   -dp-key /certs/dp.key \                    │    │ │
│ │ │   -dp-ca /certs/ca.crt                [Copy] │    │ │
│ │ └──────────────────────────────────────────────┘    │ │
│ │                                                     │ │
│ │ mTLS Certificates:                                  │ │
│ │ [Download CA Cert]  [Download Sample dp.crt/key]    │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─ Config Sync Status ────────────────────────────────┐ │
│ │ Policy Version: v47      Blocklist: 12,847 entries  │ │
│ │ Last Push: 12s ago       IP Filter: block (23 IPs)  │ │
│ │ Rate Limit: 500 rpm      Auth: Enabled              │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### API Endpoints (New)

```
GET  /api/cluster/status        — This node's role + gRPC status
GET  /api/cluster/nodes         — List connected Data Plane nodes + metrics
GET  /api/cluster/config-sync   — Current ConfigSnapshot version + summary
POST /api/cluster/force-sync    — Force push config to all nodes
```

### Backend: `controlplane.go` changes
- Expose `nodeMetrics` map via new API handler
- Add node last-seen timestamp tracking
- Add config version to status response

---

## 2. Upstream Proxies Panel

**Purpose**: Configure parent proxy chaining, failover, circuit breaker.

### Layout

```
┌─────────────────────────────────────────────────────────┐
│ Upstream Proxies                          [+ Add Proxy] │
│                                                         │
│ Chaining Mode: [Failover ▾]  (Failover / Round-Robin)  │
│                                                         │
│ ┌─ Priority Order (drag to reorder) ─────────────────┐ │
│ │                                                     │ │
│ │ 1. ● http://proxy-east.corp:8080                   │ │
│ │    Health: OK (32ms)  Circuit: Closed               │ │
│ │    Reqs: 145,201  Errors: 12  [Edit] [Remove]      │ │
│ │                                                     │ │
│ │ 2. ● http://proxy-west.corp:8080                   │ │
│ │    Health: OK (89ms)  Circuit: Closed               │ │
│ │    Reqs: 2,301    Errors: 0   [Edit] [Remove]      │ │
│ │                                                     │ │
│ │ 3. ○ socks5://backup.corp:1080                     │ │
│ │    Health: FAIL    Circuit: Open (resets in 45s)    │ │
│ │    Reqs: 0        Errors: 5   [Edit] [Remove]      │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─ Circuit Breaker Settings ──────────────────────────┐ │
│ │ Failure threshold:  [5  ]  consecutive failures     │ │
│ │ Open duration:      [60 ] seconds                   │ │
│ │ Health check:       [30 ] seconds interval          │ │
│ │ Health check path:  [/   ]                          │ │
│ │                                        [Save]       │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─ Client mTLS (for upstream auth) ───────────────────┐ │
│ │ Client Certificate: proxy-client.crt     [Upload]   │ │
│ │ Client Key:         proxy-client.key     [Upload]   │ │
│ │ Status: ● Loaded (expires 2027-01-15)               │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### API Endpoints (New)

```
GET    /api/upstream              — List upstream proxies + health + circuit state
POST   /api/upstream              — Add upstream proxy
PUT    /api/upstream/reorder      — Reorder priority
PUT    /api/upstream/{id}         — Update proxy config
DELETE /api/upstream/{id}         — Remove proxy
POST   /api/upstream/health-check — Force health check now
GET    /api/upstream/settings     — Circuit breaker settings
PUT    /api/upstream/settings     — Update circuit breaker settings
```

### Backend: `upstream.go` changes
- Add API handlers exposing pool state
- Make circuit breaker settings runtime-configurable
- Persist upstream config to JSON file

---

## 3. CA Management (expand Certificates panel)

**Purpose**: CA lifecycle, rotation, HSM/KMS, OCSP.

### Layout

```
┌─────────────────────────────────────────────────────────┐
│ CA Management                                           │
│                                                         │
│ ┌─ Root CA ───────────────────────────────────────────┐ │
│ │ Subject: Culvert Proxy CA                           │ │
│ │ Serial:  a1b2c3d4e5f6...                            │ │
│ │ Issued:  2026-01-15          Expires: 2036-01-15    │ │
│ │ Key:     ECDSA P-256         Bundle: AES-256-GCM    │ │
│ │                                                     │ │
│ │ Auto-Rotation: ● Enabled (30 days before expiry)    │ │
│ │ Next check: 2026-04-06 00:00 UTC                    │ │
│ │                                                     │ │
│ │ [Download CA Cert (PEM)]  [Force Rotate Now]        │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─ Leaf Certificate Cache ────────────────────────────┐ │
│ │ Cached: 1,247 / 10,000      TTL: 1 hour            │ │
│ │ Leaf Validity: 24 hours      Eviction: LRU (10%)    │ │
│ │                                     [Clear Cache]   │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─ OCSP / CRL Revocation Checking ───────────────────┐ │
│ │ OCSP Check:    [Toggle ON/OFF]     Status: Enabled  │ │
│ │ Stapled:       12,847 certs checked                 │ │
│ │ Revoked found: 3                                    │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─ Key Provider ──────────────────────────────────────┐ │
│ │ Provider: [Local (in-memory) ▾]                     │ │
│ │                                                     │ │
│ │ Options:                                            │ │
│ │  ○ Local — Private key in encrypted bundle on disk  │ │
│ │  ○ AWS KMS — Key ARN: [arn:aws:kms:...]             │ │
│ │  ○ Azure Key Vault — Vault URL: [https://...]       │ │
│ │  ○ GCP Cloud KMS — Key name: [projects/...]         │ │
│ │  ○ PKCS#11 HSM — Module path: [/usr/lib/...]        │ │
│ │                                        [Save]       │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### API Endpoints (New)

```
GET  /api/ca/status            — CA cert info, rotation status, cache stats
POST /api/ca/rotate            — Force CA rotation now
GET  /api/ca/download          — Download current CA cert as PEM
GET  /api/ca/cache-stats       — Leaf cert cache stats
POST /api/ca/cache-clear       — Clear leaf cert cache
GET  /api/ocsp/status          — OCSP checking status + stats
PUT  /api/ocsp/toggle          — Enable/disable OCSP checking
GET  /api/ca/key-provider      — Current key provider config
PUT  /api/ca/key-provider      — Update key provider (Local/KMS/HSM)
```

### Backend changes
- `ca.go`: Add API handlers, expose cert metadata, cache stats
- `ca.go`: Make KeyProvider configurable at runtime
- `ocsp.go`: Add enable/disable API, stats counters

---

## 4. Observability Panel

**Purpose**: Logging, metrics, syslog, GeoIP — all observability config in one place.

### Layout

```
┌─────────────────────────────────────────────────────────┐
│ Observability                                           │
│                                                         │
│ ┌─ Syslog Forwarding ────────────────────────────────┐ │
│ │ Status: ● Connected                                 │ │
│ │ Address:  [udp://10.0.1.50:514    ]                 │ │
│ │ Format:   [RFC 3164 (BSD) ▾]                        │ │
│ │ Protocol: UDP                                       │ │
│ │                              [Test]  [Save]         │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─ Prometheus Metrics ────────────────────────────────┐ │
│ │ Endpoint: /metrics                                  │ │
│ │ Auth:     [Bearer token ▾]  Token: [••••••••]       │ │
│ │ Scrape hint:                                        │ │
│ │   scrape_configs:                                   │ │
│ │     - job_name: culvert                             │ │
│ │       static_configs:                               │ │
│ │         - targets: ['proxy:9090']          [Copy]   │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─ Logging ───────────────────────────────────────────┐ │
│ │ Format: [JSON ▾]    (Text / JSON)                   │ │
│ │ Path:   /var/log/culvert.log                        │ │
│ │ Rotation: 50 MB            Status: 12.3 MB used     │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─ GeoIP Database ────────────────────────────────────┐ │
│ │ Status:    ● Loaded                                 │ │
│ │ Database:  GeoLite2-Country (2026-03-15)            │ │
│ │ Countries: 251 mapped                               │ │
│ │ Cache:     8,412 / 50,000 entries                   │ │
│ │                              [Upload New .mmdb]     │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─ Alert Webhooks ────────────────────────────────────┐ │
│ │ (moved here from Security Scanning for consistency) │ │
│ │ webhook-1: https://hooks.slack.com/...   ● Active   │ │
│ │   Events: threat_blocked, scan_blocked              │ │
│ │ webhook-2: https://siem.corp/api/...     ● Active   │ │
│ │   Events: * (all)                                   │ │
│ │                           [+ Add Webhook]           │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### API Endpoints (New)

```
GET  /api/logging/status       — Current log format, path, size, rotation
PUT  /api/logging/format       — Switch text/JSON (requires restart note)
GET  /api/geoip/status         — DB loaded, version, cache stats
POST /api/geoip/upload         — Upload new .mmdb file
GET  /api/metrics/config       — Metrics endpoint config
PUT  /api/metrics/config       — Update metrics token
```

### Existing endpoints already mapped:
```
GET/POST /api/syslog           — Already exists
GET/POST /api/alerts/webhooks  — Already exists
```

---

## 5. Expanded Security Panel

**Purpose**: Add connection limits and scan tuning to existing security panel.

### Additional sections to add:

```
┌─ Connection Limits ───────────────────────────────────┐
│ Max connections per IP: [1024]                         │
│ Status: Enabled        Active IPs: 47                 │
│                                           [Save]      │
└───────────────────────────────────────────────────────┘

┌─ Content Scan Limits ─────────────────────────────────┐
│ Max scan buffer:     [5  ] MB                         │
│ Scan cache size:     [10000] entries                  │
│ Scan cache TTL:      [1h  ]                           │
│ ClamAV concurrency:  [4   ] max parallel scans        │
│                                           [Save]      │
└───────────────────────────────────────────────────────┘

┌─ Block Page ──────────────────────────────────────────┐
│ Template: [Custom HTML editor / textarea]              │
│                                                        │
│ Available variables:                                   │
│   {{.Host}} {{.Reason}} {{.RequestID}} {{.Timestamp}} │
│                              [Preview]  [Save]         │
└────────────────────────────────────────────────────────┘
```

### API Endpoints (New)

```
GET  /api/connlimit            — Current limit + active IP count
PUT  /api/connlimit            — Update max connections per IP
GET  /api/security-scan/config — Scan limits (maxBytes, cacheTTL, cacheSize)
PUT  /api/security-scan/config — Update scan limits
GET  /api/blockpage            — Current block page HTML template
PUT  /api/blockpage            — Update block page template
```

---

## Implementation Priority

### Phase 1 — Quick Wins (API + minimal UI)
1. **CA Management** — `/api/ca/status`, `/api/ca/download`, cache stats
2. **Connection limit API** — `/api/connlimit` GET/PUT
3. **Block page API** — `/api/blockpage` GET/PUT
4. **OCSP toggle API** — `/api/ocsp/toggle`
5. Wire `cert_expiry` webhook alert

### Phase 2 — Upstream Proxies
1. Full CRUD API for upstream proxy pool
2. Circuit breaker runtime config
3. Health check status exposure
4. UI panel with drag-to-reorder

### Phase 3 — Cluster / Multi-Node
1. Node list API from existing `nodeMetrics` map
2. Enrollment command generator
3. Config sync status view
4. Per-node metrics dashboard

### Phase 4 — Observability
1. GeoIP upload endpoint
2. Log format toggle
3. Metrics token management
4. OpenTelemetry (future)

### Phase 5 — HSM / KMS
1. KeyProvider runtime configuration
2. AWS KMS / Azure KV / GCP KMS integration
3. PKCS#11 HSM support
