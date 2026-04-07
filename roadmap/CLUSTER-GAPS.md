# Cluster Feature Gap Analysis

Enterprise proxy cluster comparison (vs. Zscaler, Palo Alto Prisma, McAfee/Skyhigh, Blue Coat, F5).

## Current State — What Culvert Has

| Feature | Status |
|---|---|
| Token-based node enrollment with mTLS | ✅ Done |
| Config sync (blocklist, IP filter, rate limit) | ✅ Done |
| Distributed rate limiting (gossip) | ✅ Done |
| Cluster-wide session revocation | ✅ Done |
| Centralized audit log | ✅ Done |
| Node heartbeat + health monitoring | ✅ Done |
| Zero-touch CA rotation | ✅ Done |
| Cert auto-renewal | ✅ Done |
| Dual-CA overlap | ✅ Done |
| CA rotation progress tracking + UI | ✅ Done |

## Gaps — Ranked by Impact

### Tier 1: Expected in Any Enterprise Cluster

| # | Feature | Description | Effort | Status |
|---|---|---|---|---|
| 1 | **Full policy sync** | Sync ALL policies cluster-wide — not just blocklist. Missing: policy rules, SSL bypass, file profiles, URL categories, rewrite rules, scan settings | Medium | 🔧 In Progress |
| 2 | **CP high availability** | Active/passive or active/active CP. Single-CP today — if it dies, DPs keep running but no config updates, enrollments, or audit | Hard | ⏳ Deferred |
| 3 | **Node labels/groups** | Assign nodes to groups (e.g. `region:us-east`, `tier:dmz`), push different policies per group | Medium | 🔧 In Progress |
| 4 | **Cluster-wide PAC distribution** | Push PAC files and browser config cluster-wide, not just per-node | Easy | ⏳ Planned |

### Tier 2: Differentiators in Enterprise Market

| # | Feature | Description | Effort | Status |
|---|---|---|---|---|
| 5 | **Rolling upgrade orchestration** | CP tracks DP versions, staged rollouts (canary → 10% → 100%), block incompatible versions | Medium | ⏳ Planned |
| 6 | **Config versioning / rollback** | History of config snapshots, one-click rollback to previous known-good | Medium | ⏳ Planned |
| 7 | **DP → CP failover / reconnect** | DP tries backup CPs when primary goes down, reconciles state on reconnect | Medium | ⏳ Planned |
| 8 | **Cluster-wide metrics aggregation** | Unified dashboard: cluster-wide request rates, latency percentiles, error rates | Easy | 🔧 In Progress |
| 9 | **Node drain / maintenance mode** | Mark node "draining" — stops new connections, finishes existing, signals ready | Easy | 🔧 In Progress |

### Tier 3: Advanced / Nice-to-Have

| # | Feature | Description | Effort | Status |
|---|---|---|---|---|
| 10 | Geo-aware node grouping | Route users to nearest DP by GeoIP, failover to next-closest | Hard | ⏳ Planned |
| 11 | Bandwidth / QoS across nodes | Per-group bandwidth caps, traffic prioritization | Hard | ⏳ Planned |
| 12 | Secrets sync | Session keys, LDAP passwords synced cluster-wide | Easy | ⏳ Planned |
| 13 | Cluster-wide threat feed | Sync threat feed from CP instead of each DP fetching independently | Easy | ⏳ Planned |
| 14 | Config diff / change audit | Show what changed between config versions, who changed it | Medium | ⏳ Planned |

## Architecture Notes

### CP HA (Deferred)
The pragmatic short-term alternative: put CP behind a load balancer with health checks.
Real HA requires consensus (Raft or similar) for cluster state. Consider:
- etcd/embedded Raft for CP state replication
- Active/passive with shared storage (simpler but less resilient)
- CP state is small (cluster.json) — could use file-based replication

### Policy Sync Design
Extend `ConfigSnapshot` to include full policy state:
- Policy rules (ordered list with match criteria + actions)
- SSL inspection bypass patterns
- File blocking profiles
- URL category overrides
- Rewrite rules
- Scanner settings (ClamAV, YARA toggle + rules)

### Node Groups Design
- `EnrolledNode` gets `Labels map[string]string` field
- Policies can target groups via label selectors
- ConfigSnapshot becomes per-group (CP builds different snapshots per label set)
- UI: label management on nodes, policy → group assignment
