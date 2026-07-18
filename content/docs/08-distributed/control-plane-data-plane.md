# Distributed deployment: Control Plane / Data Plane

A single Culvert process runs the proxy, admin UI, and control plane together.
To scale horizontally or separate duties, split it into a **Control Plane** that
owns configuration and stateless **Data Plane** nodes that serve proxy traffic.
This guide covers the roles, the enrollment flow, mutual-TLS trust, config
snapshot sync, node grouping, and per-node bandwidth policies.

Prerequisite reading: [Architecture → Control Plane / Data Plane](../01-overview/architecture.md#control-plane--data-plane).

---

## Purpose

- Scale proxy capacity by adding stateless Data Plane nodes.
- Centralize configuration, enrollment, and the admin console on a Control Plane
  that carries no user traffic.
- Keep every node's policy, blocklist, threat feed, and keys in sync.

## When to split

| Deployment | Use when |
|---|---|
| Single node | One site, modest volume, simplest operations |
| Control Plane / Data Plane | Multiple sites/PoPs, horizontal scale, or separation of the admin plane from traffic |

## Roles

- **Control Plane (CP):** config-snapshot authority, node enrollment, admin UI +
  dashboard. Carries no proxy traffic. Enabled with `-cp-grpc-addr`
  (`main.go:238`).
- **Data Plane (DP):** stateless proxy. On connect it receives the entire config
  snapshot and begins serving. Replace a node and it re-enrolls in seconds. DP
  points at the CP with `-dp-cp-addr` (comma-separated for HA failover,
  `main.go:250`).

## Enrollment flow

```mermaid
sequenceDiagram
    participant A as Admin (CP)
    participant CP as Control Plane
    participant DP as Data Plane node
    A->>CP: POST /api/cluster/tokens (create enrollment token)
    CP-->>A: token + CA fingerprint
    Note over DP: start with<br/>-enroll culvert://enroll/host:50051/TOKEN?ca-fp=sha256:...
    DP->>CP: Enroll (token, CSR) over gRPC
    Note over DP,CP: DP pins CP CA by fingerprint;<br/>CP issues the node cert
    CP-->>DP: node certificate + first config snapshot
    loop every 30s
        DP->>CP: heartbeat
        CP-->>DP: config snapshot (on change)
    end
```

1. On the CP, create an enrollment token: `POST /api/cluster/tokens`
   (`ui_cluster.go:580`).
2. Start the DP with the `-enroll` URL, which carries the token and a CA
   fingerprint to pin (`culvert://enroll/host:50051/TOKEN?ca-fp=sha256:...`,
   `main.go:277`). The DP verifies the CP's CA against that fingerprint before
   trusting it.
3. The DP receives its node certificate and the full config snapshot, then
   heartbeats (the CP pushes updated snapshots on change).

A **bootstrap** endpoint serves a ready-made script/compose for a new node,
token-authenticated (`/api/cluster/bootstrap/`, `ui_cluster.go:596`).

## Mutual TLS

All CP↔DP gRPC is mutually authenticated:

| Side | Flags |
|---|---|
| CP | `-cp-grpc-cert`, `-cp-grpc-key`, `-cp-grpc-ca` (`main.go:239-241`) |
| DP | `-dp-cert`, `-dp-key`, `-dp-ca` (`main.go:252-254`) |

The CP verifies enrolled-node certificates on every RPC (`verifyNode`); the
enrollment RPC itself uses `VerifyClientCertIfGiven` so a brand-new node can call
`Enroll` before it holds a certificate (`controlplane_tls.go:91`).

> **`-cluster-insecure` is development-only.** It permits non-TLS gRPC and must
> never be used in production (`main.go:279`).

## Config snapshot sync

The CP pushes a single `ConfigSnapshot` to each DP containing policy rules,
blocklist, PAC exclusions, threat-feed data, the session HMAC key, bandwidth
policies, and node groups (`controlplane_snapshot.go`). The snapshot is a
**walled surface**: sensitive fields (session key, IdP secrets) are redacted
before being sent to a non-enrolled caller (`controlplane_server.go:91-100`).

## Node groups, labels, and drain

- **Labels & groups:** DP nodes carry label selectors; groups match nodes by
  label. GeoIP labels (`geo:country`, `geo:country_name`) are assigned
  automatically on enrollment (`enrollment.go:351-364`). Manage via
  `/api/cluster/labels` and `/api/cluster/node-groups` (`ui_cluster.go:583-584`).
- **Drain:** toggle a node into drain mode to stop new traffic before
  maintenance (`/api/cluster/drain`, `ui_cluster.go:586`).

## Bandwidth / QoS

Per-group token-bucket bandwidth policies are enforced **per-DP**, so limits
scale with node count (`bandwidth.go`). Manage at `/api/cluster/bandwidth`
(`ui_cluster.go:595`).

## Cluster operations surface

| Route | Purpose |
|---|---|
| `/api/cluster/status` | This node + connected nodes |
| `/api/cluster/nodes` | Enrolled nodes |
| `/api/cluster/revoke` | Revoke a node |
| `/api/cluster/metrics` | Aggregated cluster metrics |
| `/api/cluster/audit` | Centralized audit log |
| `/api/cluster/revocations` | Session-revocation sync status |
| `/api/cluster/rate-limits` | Distributed rate-limit status |
| `/api/cluster/rotation` | CA rotation progress |
| `/api/cluster/ha` · `/api/cluster/ha/promote` | HA status / manual promotion |

(`ui_cluster.go:578-596`.)

## Configuration procedure

**On the Control Plane:**

```bash
./culvert -cp-grpc-addr :50051 \
  -cp-grpc-cert /data/cp.crt -cp-grpc-key /data/cp.key -cp-grpc-ca /data/ca.crt \
  -cluster-db /data/cluster.json
# then: POST /api/cluster/tokens to mint an enrollment token
```

**On each Data Plane node:**

```bash
./culvert -port 8080 \
  -dp-cp-addr cp-host:50051 \
  -enroll 'culvert://enroll/cp-host:50051/<TOKEN>?ca-fp=sha256:<FINGERPRINT>' \
  -dp-cert /data/dp.crt -dp-key /data/dp.key -dp-ca /data/ca.crt
```

## Validation steps

```bash
# On the CP: confirm the node enrolled
curl -sk https://<cp-host>:9090/api/cluster/nodes
# Cluster health / connected nodes
curl -sk https://<cp-host>:9090/api/cluster/status
```

## Failure modes

| Condition | Behavior |
|---|---|
| DP cannot reach the CP | DP retries; with a comma-separated `-dp-cp-addr` it fails over to the next CP |
| Enrollment token invalid/expired | Enrollment rejected |
| CA fingerprint mismatch | DP refuses to trust the CP (pinning) |
| Node revoked | Its certificate is rejected on subsequent RPCs |
| Non-enrolled caller reads config | Secrets are redacted from the snapshot |

## Security implications

- Protect the CP gRPC endpoint and the enrollment tokens; a token plus the CA
  fingerprint is what admits a node.
- Keep mTLS on — never `-cluster-insecure` outside a lab.
- The session HMAC key and IdP secrets are synced but redacted to non-enrolled
  callers; treat the CP as the trust root for the cluster.

## Known limitations

- **Rolling upgrades are node-level, not orchestrated cluster-wide.** Culvert
  provides per-node drain and (in HA mode) leadership handoff, but does not ship
  a cluster-wide rolling-upgrade orchestrator — sequence node upgrades yourself
  using drain. (Recorded as content-factory finding G-03.)
- Node-group and bandwidth policy management is CP-side; DP nodes apply what the
  snapshot carries.

## Related documentation

- [Architecture → CP/DP](../01-overview/architecture.md#control-plane--data-plane).
- [High availability](high-availability.md) — etcd fencing lease & failover.
- In-repo: [`../../../docs/operator/support-bundles-and-diagnostics.md`](../../../docs/operator/support-bundles-and-diagnostics.md).

## Source evidence

Claim-evidence ledger: [`control-plane-data-plane.evidence.md`](control-plane-data-plane.evidence.md).
