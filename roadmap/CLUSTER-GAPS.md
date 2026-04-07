# Cluster Feature Gap Analysis

Enterprise proxy cluster comparison (vs. Zscaler, Palo Alto Prisma, McAfee/Skyhigh, Blue Coat, F5).

## Current State — What Culvert Has

| Feature | Status |
|---|---|
| Token-based node enrollment with mTLS | ✅ Done |
| Config sync (blocklist, IP filter, rate limit) | ✅ Done |
| Full policy sync (rules, SSL bypass, file profiles, URL categories, rewrite, scan) | ✅ Done |
| Distributed rate limiting (gossip) | ✅ Done |
| Cluster-wide session revocation | ✅ Done |
| Centralized audit log | ✅ Done |
| Node heartbeat + health monitoring | ✅ Done |
| Zero-touch CA rotation | ✅ Done |
| Cert auto-renewal | ✅ Done |
| Dual-CA overlap | ✅ Done |
| CA rotation progress tracking + UI | ✅ Done |
| CP high availability (leader election + auto-failover) | ✅ Done |
| Node labels/groups with per-group policy targeting | ✅ Done |
| DP → CP failover (auto-discovers all CPs from config sync) | ✅ Done |
| Cluster-wide metrics aggregation (node health dashboard) | ✅ Done |
| Node drain / maintenance mode | ✅ Done |

## Remaining Gaps — Ranked by Impact

### Tier 1: Expected in Any Enterprise Cluster

| # | Feature | Description | Effort | Status |
|---|---|---|---|---|
| 1 | **Cluster-wide PAC distribution** | Push PAC files and browser config cluster-wide, not just per-node | Easy | ⏳ Planned |

### Tier 2: Differentiators in Enterprise Market

| # | Feature | Description | Effort | Status |
|---|---|---|---|---|
| 2 | **Rolling upgrade orchestration** | CP tracks DP versions, staged rollouts (canary → 10% → 100%), block incompatible versions | Medium | ⏳ Planned |
| 3 | **Config versioning / rollback** | History of config snapshots, one-click rollback to previous known-good | Medium | ⏳ Planned |

### Tier 3: Advanced / Nice-to-Have

| # | Feature | Description | Effort | Status |
|---|---|---|---|---|
| 4 | Geo-aware node grouping | Route users to nearest DP by GeoIP, failover to next-closest | Hard | ⏳ Planned |
| 5 | Bandwidth / QoS across nodes | Per-group bandwidth caps, traffic prioritization | Hard | ⏳ Planned |
| 6 | Secrets sync | Session keys, LDAP passwords synced cluster-wide | Easy | ⏳ Planned |
| 7 | Cluster-wide threat feed | Sync threat feed from CP instead of each DP fetching independently | Easy | ⏳ Planned |
| 8 | Config diff / change audit | Show what changed between config versions, who changed it | Medium | ⏳ Planned |
