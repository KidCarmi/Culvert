# Deployment Guide

Culvert supports three deployment modes. Choose the one that fits your scale.

---

## 1. Standalone (Single Node)

Everything runs in one process — proxy, admin UI, policy engine, scanning.
This is the default and works for most deployments.

### Docker Compose

```yaml
# docker-compose.yml
services:
  culvert:
    image: culvert:latest
    ports:
      - "8080:8080"   # HTTP/HTTPS proxy
      - "1080:1080"   # SOCKS5 (optional)
      - "9090:9090"   # Admin Web UI
    environment:
      CULVERT_CA_PASSPHRASE: "${CULVERT_CA_PASSPHRASE}"
    volumes:
      - culvert-data:/data
    command: >
      -port 8080
      -ui-port 9090
      -socks5-port 1080
      -ca-path /data/ca.bundle
      -ui-users-file /data/ui_users.json
      -policy /data/policy.json
      -blocklist /data/blocklist.txt
      -audit-log /data/audit.jsonl
      -threat-feed-db /data/threatfeeds.json
      -logfile /data/culvert.log

volumes:
  culvert-data:
```

```bash
export CULVERT_CA_PASSPHRASE="your-strong-passphrase"
docker compose up -d
```

Open `https://localhost:9090` to complete the setup wizard.

### Binary

```bash
export CULVERT_CA_PASSPHRASE="your-strong-passphrase"

./culvert \
  -port 8080 \
  -ui-port 9090 \
  -socks5-port 1080 \
  -ca-path /data/ca.bundle \
  -ui-users-file /data/ui_users.json \
  -policy /data/policy.json \
  -audit-log /data/audit.jsonl \
  -threat-feed-db /data/threatfeeds.json
```

### What you get

| Endpoint | URL |
|----------|-----|
| HTTP/HTTPS Proxy | `http://proxy-host:8080` |
| SOCKS5 Proxy | `socks5://proxy-host:1080` |
| Admin Web UI | `https://proxy-host:9090` |
| PAC File | `http://proxy-host:9090/proxy.pac` |
| Prometheus Metrics | `http://proxy-host:8080/metrics` |
| Health Check | `http://proxy-host:8080/health` |

---

## 2. Multi-Node (Control Plane + Data Plane)

For high-traffic deployments, separate the admin UI / config management
(Control Plane) from the proxy workers (Data Plane). Data Plane nodes
poll the Control Plane every 30 seconds for config updates and push
metrics back.

```
                    ┌──────────────────────────┐
                    │      Control Plane        │
                    │   :9090 Admin UI/API      │
                    │   :50051 gRPC (mTLS)      │
                    │                           │
                    │   Config management       │
                    │   Metrics aggregation     │
                    │   Audit log               │
                    └─────────┬────────────────┘
                              │ gRPC (mTLS)
               ┌──────────────┼──────────────┐
               │              │              │
        ┌──────▼─────┐ ┌─────▼──────┐ ┌─────▼──────┐
        │  DP Node 1 │ │  DP Node 2 │ │  DP Node 3 │
        │  :8080     │ │  :8080     │ │  :8080     │
        │  Proxy     │ │  Proxy     │ │  Proxy     │
        │  traffic   │ │  traffic   │ │  traffic   │
        └────────────┘ └────────────┘ └────────────┘
               ▲              ▲              ▲
               │              │              │
          ─────┴──────────────┴──────────────┴─────
                      Load Balancer
```

### Step 1: Generate mTLS Certificates

The Control Plane and Data Plane nodes authenticate each other using
mutual TLS (mTLS). You need:

- A CA certificate (`ca.crt`)
- A Control Plane certificate + key (`cp.crt`, `cp.key`)
- A Data Plane certificate + key per node (`dp.crt`, `dp.key`)

```bash
# Generate CA
openssl ecparam -genkey -name prime256v1 -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 \
  -subj "/CN=Culvert Cluster CA"

# Generate Control Plane cert
openssl ecparam -genkey -name prime256v1 -out cp.key
openssl req -new -key cp.key -out cp.csr -subj "/CN=culvert-control-plane"
openssl x509 -req -in cp.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out cp.crt -days 365

# Generate Data Plane cert (repeat per node)
openssl ecparam -genkey -name prime256v1 -out dp.key
openssl req -new -key dp.key -out dp.csr -subj "/CN=culvert-data-plane"
openssl x509 -req -in dp.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out dp.crt -days 365

# Clean up CSRs
rm -f cp.csr dp.csr
```

### Step 2: Start the Control Plane

The Control Plane runs the Admin Web UI and serves config to Data Plane nodes.

```bash
export CULVERT_CA_PASSPHRASE="your-strong-passphrase"

./culvert \
  -ui-port 9090 \
  -cp-grpc-addr :50051 \
  -cp-grpc-cert /certs/cp.crt \
  -cp-grpc-key /certs/cp.key \
  -cp-grpc-ca /certs/ca.crt \
  -ca-path /data/ca.bundle \
  -ui-users-file /data/ui_users.json \
  -policy /data/policy.json \
  -audit-log /data/audit.jsonl \
  -threat-feed-db /data/threatfeeds.json
```

> **Note:** The Control Plane can also proxy traffic itself (if you set `-port`).
> Omit `-port` to run it as a config-only node.

### Step 3: Add Data Plane Nodes (GUI Enrollment)

The easiest way to add nodes is through the Admin UI enrollment system.
No manual certificate management needed.

1. Open the Admin UI at `https://control-plane:9090`
2. Navigate to **Infrastructure > Cluster**
3. Click **+ Enroll Node**
4. Configure optional constraints (node ID prefix, allowed CIDR, TTL)
5. Click **Generate Token**
6. Copy the enrollment command

On the new server:

```bash
# Download the Culvert binary (same binary used everywhere)
# Then paste the enrollment command from the GUI:

./culvert -enroll "culvert://enroll/control-plane.corp:50051/TOKEN?ca-fp=sha256:..."
```

The node will:
- Generate an ECDSA P-256 keypair
- Send a CSR to the Control Plane
- Receive a signed certificate + cluster CA
- Save certs locally (`dp-node.crt`, `dp-node.key`, `cluster-ca.crt`)

Then start the node normally:

```bash
export CULVERT_CA_PASSPHRASE="your-strong-passphrase"

./culvert \
  -port 8080 \
  -socks5-port 1080 \
  -dp-cp-addr control-plane.corp:50051 \
  -dp-node-id $(hostname) \
  -dp-cert dp-node.crt \
  -dp-key dp-node.key \
  -dp-ca cluster-ca.crt \
  -ca-path /data/ca.bundle \
  -logfile /data/culvert.log
```

> **Enrollment tokens are one-time use and expire** (default: 24 hours).
> Generate a new token for each node.

### Step 3b: Manual Data Plane Setup (without enrollment)

If you prefer to manage certificates manually:

```bash
export CULVERT_CA_PASSPHRASE="your-strong-passphrase"

./culvert \
  -port 8080 \
  -socks5-port 1080 \
  -dp-cp-addr control-plane.corp:50051 \
  -dp-node-id dp-east-1 \
  -dp-cert /certs/dp.crt \
  -dp-key /certs/dp.key \
  -dp-ca /certs/ca.crt \
  -ca-path /data/ca.bundle \
  -logfile /data/culvert.log
```

Repeat for each node, changing `-dp-node-id` to a unique identifier
(e.g. `dp-east-2`, `dp-west-1`).

### Node Management

From the Admin UI cluster panel you can:
- **View all enrolled nodes** with their status (connected/disconnected/revoked)
- **Revoke nodes** instantly — the node is immediately rejected on the next gRPC heartbeat
- **Monitor heartbeats** — nodes missing 3 consecutive polls (90s) are marked "disconnected"
- **Manage enrollment tokens** — view active/consumed/expired tokens

### Docker Compose (multi-node)

```yaml
# docker-compose.multi.yml
services:
  control-plane:
    image: culvert:latest
    ports:
      - "9090:9090"    # Admin UI
      - "50051:50051"  # gRPC
    environment:
      CULVERT_CA_PASSPHRASE: "${CULVERT_CA_PASSPHRASE}"
    volumes:
      - cp-data:/data
      - ./certs:/certs:ro
    command: >
      -ui-port 9090
      -cp-grpc-addr :50051
      -cp-grpc-cert /certs/cp.crt
      -cp-grpc-key /certs/cp.key
      -cp-grpc-ca /certs/ca.crt
      -ca-path /data/ca.bundle
      -ui-users-file /data/ui_users.json
      -policy /data/policy.json
      -audit-log /data/audit.jsonl
      -threat-feed-db /data/threatfeeds.json

  data-plane-1:
    image: culvert:latest
    ports:
      - "8080:8080"
      - "1080:1080"
    environment:
      CULVERT_CA_PASSPHRASE: "${CULVERT_CA_PASSPHRASE}"
    volumes:
      - dp1-data:/data
      - ./certs:/certs:ro
    command: >
      -port 8080
      -socks5-port 1080
      -dp-cp-addr control-plane:50051
      -dp-node-id dp-1
      -dp-cert /certs/dp.crt
      -dp-key /certs/dp.key
      -dp-ca /certs/ca.crt
      -ca-path /data/ca.bundle
      -logfile /data/culvert.log
    depends_on:
      - control-plane

  data-plane-2:
    image: culvert:latest
    ports:
      - "8081:8080"
      - "1081:1080"
    environment:
      CULVERT_CA_PASSPHRASE: "${CULVERT_CA_PASSPHRASE}"
    volumes:
      - dp2-data:/data
      - ./certs:/certs:ro
    command: >
      -port 8080
      -socks5-port 1080
      -dp-cp-addr control-plane:50051
      -dp-node-id dp-2
      -dp-cert /certs/dp.crt
      -dp-key /certs/dp.key
      -dp-ca /certs/ca.crt
      -ca-path /data/ca.bundle
      -logfile /data/culvert.log
    depends_on:
      - control-plane

volumes:
  cp-data:
  dp1-data:
  dp2-data:
```

```bash
export CULVERT_CA_PASSPHRASE="your-strong-passphrase"
docker compose -f docker-compose.multi.yml up -d
```

### Step 4: Verify Cluster

1. Open the Admin UI at `https://control-plane:9090`
2. Navigate to **Infrastructure > Cluster Nodes**
3. You should see both Data Plane nodes with their metrics

### What Syncs Between Nodes

| Synced (via gRPC) | NOT Synced (per-node) |
|---|---|
| Blocklist entries | Rate limit counters |
| IP filter list + mode | Session cookies |
| Rate limit config (RPM) | Connection counters |
| Auth enabled / unauth mode | Leaf cert cache |
| OIDC/SAML IdP profiles | SAML AuthnRequest RelayState |
| External auth base URL | OIDC PKCE login state |
| Session HMAC signing key | Browser cookies (client-held) |
| Policy version | Scan result cache |

Browser sessions are designed to survive DP load balancing: once a DP
successfully completes OIDC or SAML login, the browser stores a signed
session cookie and any DP can verify it with the synced Session HMAC key.
The login callback itself still needs affinity while it is in flight:
SAML RelayState and OIDC PKCE state are node-local replay protections, so
`/auth/saml/callback` and `/auth/oidc/callback` should return to the DP that
started that login.

Each DP also persists the last successfully applied control-plane
`ConfigSnapshot` to its data directory as `dp_last_config_snapshot.json`
with `0600` permissions. On restart, the DP applies that snapshot before
its first CP poll. If the CP is temporarily down, the DP can continue
serving with the last-known-good local policy/auth configuration. Existing
browser sessions continue to validate as long as the cached snapshot
contains the shared session HMAC. New OIDC/SAML logins still require the
external IdP to be reachable, and in-flight callbacks still need load
balancer affinity to the DP that initiated the login.

### Load Balancer Setup

Place a TCP/HTTP load balancer in front of the Data Plane nodes.
Any load balancer works (HAProxy, Nginx, AWS ALB/NLB, etc.).

**HAProxy example:**

```
frontend proxy_frontend
    bind *:8080
    mode tcp
    default_backend proxy_nodes

backend proxy_nodes
    mode tcp
    balance roundrobin
    server dp1 10.0.1.11:8080 check
    server dp2 10.0.1.12:8080 check
    server dp3 10.0.1.13:8080 check
```

> **Tip:** Use sticky sessions (source IP affinity) for best performance,
> since each node maintains its own rate limit counters, cert cache, and
> short-lived IdP login state.

---

## 3. Upstream Proxy Chaining

Culvert can forward traffic through one or more parent proxies instead
of connecting directly to the internet. This is useful for:

- Corporate environments with mandatory egress proxies
- Geographically distributed proxy tiers
- Adding Culvert's scanning/policy in front of an existing proxy

### Configuration

Via Admin UI: **Network > Upstream Proxies > Add Proxy**

Via `config.yaml`:

```yaml
upstream:
  proxies:
    - url: http://parent-proxy-east:3128
    - url: http://parent-proxy-west:3128
    - url: socks5://backup-proxy:1080
  health_interval: 30s
  circuit_breaker:
    threshold: 5       # failures before circuit opens
    timeout: 60s       # how long circuit stays open
```

Via CLI:

```bash
./culvert -config config.yaml   # upstream section in YAML
```

### Failover Behavior

1. Culvert tries the first proxy in the list
2. If it fails, the circuit breaker records the failure
3. After `threshold` consecutive failures, the circuit **opens** — Culvert
   stops trying that proxy for `timeout` seconds
4. Traffic automatically fails over to the next proxy in the list
5. After `timeout`, the circuit enters **half-open** — one test request is
   sent. If it succeeds, the circuit closes and the proxy is back in rotation.

### Client mTLS

If the upstream proxy requires client certificate authentication:

```yaml
proxy:
  client_cert_file: /certs/client.crt
  client_key_file: /certs/client.key
```

Or upload via Admin UI: **Certificates > SSL / TLS > Upload Client Certificate**

---

## SSL Inspection — CA Distribution

When SSL inspection is enabled, every client behind the proxy needs
the Culvert Root CA in its trust store. After deployment:

### Download the CA Certificate

```bash
# From the API
curl -k https://control-plane:9090/api/ca/download -o culvert-ca.pem

# Or from Admin UI → Certificates → CA Management → Download CA Cert (PEM)
```

### Distribute to Endpoints

| Platform | Command |
|----------|---------|
| **Linux (Debian/Ubuntu)** | `cp culvert-ca.pem /usr/local/share/ca-certificates/culvert-ca.crt && update-ca-certificates` |
| **Linux (RHEL/CentOS)** | `cp culvert-ca.pem /etc/pki/ca-trust/source/anchors/ && update-ca-trust` |
| **macOS** | `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain culvert-ca.pem` |
| **Windows (GPO)** | Deploy via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Trusted Root CAs |
| **Windows (PowerShell)** | `Import-Certificate -FilePath culvert-ca.pem -CertStoreLocation Cert:\LocalMachine\Root` |
| **Chrome/Firefox** | Import via browser settings > Privacy > Manage Certificates > Authorities > Import |
| **MDM (Intune/Jamf)** | Upload as a Trusted Root Certificate profile |

### CA Auto-Rotation

Culvert checks the CA expiry daily and auto-rotates **30 days before
expiry**. When rotation happens:

1. A `cert_expiry` webhook alert fires (configure under Security > Alert Webhooks)
2. The new CA is saved to the bundle path (`-ca-path`)
3. All cached leaf certs are invalidated
4. **You must distribute the new CA cert to endpoints before the old leaf certs expire (24h)**

Recommended workflow:
- Set up a webhook alert for `cert_expiry`
- When notified, download the new CA cert and push via MDM/GPO
- Leaf certs are valid 24 hours, so you have up to 24h to distribute

---

## Health Checks

```bash
# Proxy health (returns JSON)
curl http://proxy-host:8080/health

# Response:
# {"status":"ok","uptime":"14d 6h 23m","version":"1.0.0"}
```

For load balancers, use `/health` as the health check endpoint with
expected HTTP 200 response.

---

## Monitoring

### Prometheus + Grafana

```bash
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
# Grafana → http://localhost:3000 (admin / culvert)
```

### Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: culvert
    metrics_path: /metrics
    bearer_token: "your-metrics-token"   # if -metrics-token is set
    static_configs:
      - targets:
          - "proxy-host:8080"            # standalone
          # or for multi-node:
          - "dp-east-1:8080"
          - "dp-east-2:8080"
          - "dp-west-1:8080"
```

### Syslog (SIEM Integration)

Configure via Admin UI: **Settings > Syslog Forwarding**

Or CLI:

```bash
./culvert -syslog udp://splunk.corp:514
./culvert -syslog tcp://elastic.corp:601
```

Supported SIEMs: Splunk, Elasticsearch, QRadar, rsyslog, syslog-ng.
