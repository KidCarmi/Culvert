# Documentation governance review 2026-11-13

Scope: checked-out `main` at `feb11e8`, focused on product changes merged since the
2026-11-12 review (`3b09cff..feb11e8`). Point-in-time record; not a source of truth for
behavior.

## Finding (High): no operator runbook for a damaged `cluster.json`

- **Problem.** The cluster state file has four damage outcomes with different operator
  actions (quarantine, failed quarantine, dropped null records, unreadable file), plus a
  replicated variant on an HA standby. No operator page described any of them. The only
  operator text was the `state_file_<kind>` row in the `/ready` table of `docs/OPERATIONS.md`,
  which correctly covers the quarantine case for `/ready` and nothing else.
- **What changed since the last review.** The 2026-11-12 review judged that the null-record
  fix (CHAOS-117) needed no operator page. `a783870` and `98068d6` then added operator-facing
  consequences: a dropped record makes its certificate serial permanently unrevocable, and a
  later enrollment under that node ID writes the `cluster.node.reenroll-dropped` audit entry
  and the `cluster_node_reenrolled` alert, whose text asks the operator to confirm the
  enrollment. That request had no documentation behind it.
- **Implementation evidence.** `ClusterStore.Load`, `normalizeClusterState` and
  `ImportFullState` (`enrollment.go`); `quarantineCorruptStateFile`,
  `noteStateFileEntriesDropped`, `noteResidualQuarantinePaths` and `checkStateFileIntegrity`
  (`state_corruption.go`); `appendStateFileChecks` (`healthcheck.go`); `verifyNodeCert` and
  `recordDroppedNodeReenrollment` (`controlplane_server.go`);
  `culvert_cluster_state_nil_entries_dropped_total` (`cluster_metrics.go`).
- **Why it matters.** The affected node IDs appear only in a log line. The Diagnostics row and
  the dropped-ID record are process-local and disappear after the next save and restart. An
  operator who misses that window cannot tell which nodes to re-enroll or which
  re-enrollments to verify.
- **Who is affected.** Operators of a Control Plane or an HA standby.
- **Canonical source.** New page `docs/operator/cluster-state-recovery.md`, indexed in
  `docs/operator/README.md`. It links to the existing enrollment, backup and `/ready` text
  and does not restate it.
- **Change.** One new runbook and one index line. Effort: small. Risk: low (prose only).

## Observations recorded, not changed

- An unreadable `cluster.json` (permissions, I/O error) produces one startup log line and no
  alert, Diagnostics row or `/ready` row. `admin_settings` reports the same condition through
  `noteStateFileUnreadable`. The runbook states the current behavior; whether the cluster
  store should report it is a product question.
- The alert-subscription checkbox in `static/index.html` labels `cluster_node_reenrolled` as
  "Node re-enrolled (expired cert)", and the event comment in `internal/alerts/store.go` says
  the same. The event now also fires for a re-enrollment over a dropped record. This is
  product text, outside a documentation-only change.

## Not assessed / documentation debt

- Carried from 2026-11-12: no catalog lists Diagnostics row codes. The new `upstream_egress`
  row (`3cbabd6`) joins `upstream_pool_config` as undocumented in
  `docs/operator/upstream-proxies.md`.
- The sourceIP and auth-subject bare-IP matching changes (`47c12ac`, `a783870`) are recorded
  in `CHANGELOG.md`; no operator page contradicts them.
- Per-option configuration-reference completeness was not re-audited.
