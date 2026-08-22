// FE-4 Overview — SNAPSHOT-only appliance dashboard (ADR-FE-002). One
// snapshot fetch set on load, explicit Refresh, visible freshness. No SSE,
// no EventSource, no live append, no polling. Hierarchy (§10): management
// health → traffic summary → allowed/blocked → threats → rule activity →
// persistence warnings → freshness.
import type { JSX } from "react";
import { PageHeader } from "../../layouts/AppShell";
import {
  getDashboardHealth,
  getDashboardThreats,
  getStats,
  getTimeseries,
  getTopRules,
} from "../../api/ops";
import type {
  DashboardHealth,
  DashboardThreats,
  Stats,
  Timeseries,
  TopRule,
} from "../../api/ops";
import { DonutChart, LineChart } from "../../design-system/charts";
import { DataTable } from "../../design-system/table";
import {
  Callout,
  Card,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import styles from "./overview.module.css";

interface OverviewSnapshot {
  stats: Stats;
  timeseries: Timeseries;
  health: DashboardHealth;
  threats: DashboardThreats;
  topRules: readonly TopRule[];
}

// ONE snapshot fetch set (§9): the five bounded reads travel together so the
// page carries a single honest freshness timestamp.
async function fetchOverview(): Promise<OverviewSnapshot> {
  const [stats, timeseries, health, threats, topRules] = await Promise.all([
    getStats(),
    getTimeseries(),
    getDashboardHealth(),
    getDashboardThreats(),
    getTopRules(),
  ]);
  return { stats, timeseries, health, threats, topRules };
}

function PersistenceWarnings({ s }: { s: Stats }): JSX.Element | null {
  const rows: string[] = [];
  if (s.auditLogConfigured && !s.auditLogPersisted) {
    rows.push(
      "Audit log persistence is configured but INACTIVE — admin actions are only in volatile memory.",
    );
  }
  if (s.requestLogConfigured && !s.requestLogPersisted) {
    rows.push(
      "Request log persistence is configured but INACTIVE — request history is only in volatile memory.",
    );
  }
  if (s.auditLogWriteErrors > 0) {
    rows.push(
      `Audit-log write errors: ${String(s.auditLogWriteErrors)} — the durable compliance record is incomplete.`,
    );
  }
  if (s.logWriteErrors > 0) {
    rows.push(`Request-log write errors: ${String(s.logWriteErrors)}.`);
  }
  if (s.configPublishRejected !== "") {
    rows.push(
      `Cluster config publish rejected: ${s.configPublishRejected} — the fleet is frozen on the last valid snapshot.`,
    );
  }
  if (rows.length === 0) return null;
  return (
    <Callout
      variant="critical"
      title="Persistence / degraded state"
      role="alert"
    >
      <ul className={styles.warnList}>
        {rows.map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>
    </Callout>
  );
}

export function OverviewPage(): JSX.Element {
  const q = useSnapshot(["ops", "overview"], fetchOverview);
  const snap = q.data;
  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="Appliance snapshot — explicit refresh, no background streaming"
        actions={
          <SnapshotBar
            updatedAt={q.dataUpdatedAt}
            fetching={q.isFetching}
            error={q.isError}
            hasData={snap !== undefined}
            onRefresh={() => {
              void q.refetch();
            }}
          />
        }
      />
      {snap === undefined && q.isPending && (
        <Skeleton>Loading snapshot…</Skeleton>
      )}
      {snap === undefined && q.isError && (
        <ErrorState title="Snapshot unavailable">
          The appliance snapshot could not be loaded. Use Refresh to retry.
        </ErrorState>
      )}
      {snap !== undefined && (
        <>
          <PersistenceWarnings s={snap.stats} />
          <div className={styles.grid}>
            <Card title="Management health">
              <KeyValue
                items={[
                  ["Uptime", snap.stats.uptime],
                  [
                    "RBAC enforcement",
                    snap.stats.c2Mode === "enforce" ? (
                      <StatusBadge status="ok">enforce</StatusBadge>
                    ) : (
                      <StatusBadge status="warn">shadow (log-only)</StatusBadge>
                    ),
                  ],
                  [
                    "Request history store",
                    snap.health.logStoreEnabled ? (
                      <StatusBadge status="ok">enabled</StatusBadge>
                    ) : (
                      <StatusBadge status="neutral">disabled</StatusBadge>
                    ),
                  ],
                  ["Goroutines", String(snap.health.goroutines)],
                  ["Memory (alloc)", `${snap.health.memAllocMB.toFixed(1)} MB`],
                  ["Blocklist entries", String(snap.stats.blocklistSz)],
                  [
                    "Server time",
                    <Mono key="st">{snap.stats.serverTime}</Mono>,
                  ],
                ]}
              />
            </Card>
            <Card title="Traffic — last hour">
              <div className={styles.statRow}>
                <div className={styles.stat}>
                  <span className={styles.statValue}>{snap.stats.total}</span>
                  <span className={styles.statLabel}>total requests</span>
                </div>
                <div className={styles.stat}>
                  <span className={styles.statValue}>{snap.stats.allowed}</span>
                  <span className={styles.statLabel}>allowed</span>
                </div>
                <div className={styles.stat}>
                  <span className={styles.statValue}>{snap.stats.blocked}</span>
                  <span className={styles.statLabel}>blocked</span>
                </div>
                <div className={styles.stat}>
                  <span className={styles.statValue}>
                    {snap.stats.authFail}
                  </span>
                  <span className={styles.statLabel}>auth failures</span>
                </div>
              </div>
              <LineChart
                title="Requests per minute (snapshot window)"
                points={snap.timeseries.data}
                unit="req/min"
              />
            </Card>
            <Card title="Verdicts">
              <DonutChart
                title="Allowed vs blocked (lifetime counters)"
                segments={[
                  { label: "Allowed", value: snap.stats.allowed, status: "ok" },
                  {
                    label: "Blocked",
                    value: snap.stats.blocked,
                    status: "critical",
                  },
                  {
                    label: "Auth failed",
                    value: snap.stats.authFail,
                    status: "warn",
                  },
                ]}
              />
            </Card>
            <Card title="Threat engines (blocked)">
              <KeyValue
                items={[
                  ["ClamAV", String(snap.threats.clamav)],
                  ["YARA", String(snap.threats.yara)],
                  ["DPI", String(snap.threats.dpi)],
                  ["Threat feed", String(snap.threats.threatFeed)],
                ]}
              />
            </Card>
            <Card title="Top policy rules by hits">
              <DataTable
                caption="Top policy rules by hit count"
                columns={[
                  {
                    key: "name",
                    header: "Rule",
                    render: (r: TopRule) => r.name,
                  },
                  {
                    key: "action",
                    header: "Action",
                    render: (r: TopRule) => r.action,
                  },
                  {
                    key: "hits",
                    header: "Hits",
                    numeric: true,
                    render: (r: TopRule) => String(r.hits),
                  },
                ]}
                rows={snap.topRules}
                rowKey={(r) => r.name}
                empty="No rule hits recorded yet."
              />
            </Card>
          </div>
        </>
      )}
    </>
  );
}
