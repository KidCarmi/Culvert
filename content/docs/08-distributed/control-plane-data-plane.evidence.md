# Claim-Evidence Ledger — "Distributed deployment: Control Plane / Data Plane"

Article: [`control-plane-data-plane.md`](control-plane-data-plane.md). Verified
against repo revision `ca60d83`.

| Claim | Type | Evidence |
|---|---|---|
| CP enabled via `-cp-grpc-addr`; carries no proxy traffic | src | `main.go:238`; `docs/architecture.md` §3 |
| CP mTLS flags: cert/key/ca | src | `main.go:239-241` |
| DP points at CP via `-dp-cp-addr` (comma-separated = HA failover) | src | `main.go:250` |
| DP mTLS flags: cert/key/ca; node id | src | `main.go:251-254` |
| Enrollment URL `-enroll culvert://enroll/host/TOKEN?ca-fp=sha256:…` | src | `main.go:277` |
| `-cluster-db` persistence; `-cluster-insecure` dev-only (never prod) | src | `main.go:278-279` |
| Enrolled-node RPCs cert-verified; Enroll open via `VerifyClientCertIfGiven` | src | `controlplane_tls.go:91`; `verifyNode` |
| ConfigSnapshot push (policy/blocklist/PAC/threat/session key/QoS/groups) | src | `controlplane_snapshot.go`; `docs/architecture.md` §3 |
| Snapshot redacts secrets to non-enrolled callers | src | `controlplane_server.go:91-100` |
| Auto GeoIP labels on enrollment | src | `enrollment.go:351-364` |
| Cluster routes: status/mode/tokens/nodes/revoke/labels/node-groups/drain/metrics/ca/rate-limits/audit/revocations/rotation/ha(+promote)/bandwidth/bootstrap | src | `ui_cluster.go:578-596` |
| Per-group token-bucket bandwidth enforced per-DP | src | `bandwidth.go`; `ui_cluster.go:595` |
| Bootstrap script/compose, token-authed | src | `ui_cluster.go:596` (`/api/cluster/bootstrap/`) |

## Gap verification (G-03)

Searched for a cluster-wide rolling-upgrade orchestrator: found per-node drain
(`/api/cluster/drain`, `ui_cluster.go:586`) and HA leadership handoff, but no
orchestrator that sequences upgrades across the fleet. The article documents
rolling upgrades as node-level (drain + handoff), consistent with finding G-03.
The etcd fencing-lease integration (G-02) is deferred to the HA article (M-023),
which reads `ha_lease.go`/`ha_failover.go` directly.
