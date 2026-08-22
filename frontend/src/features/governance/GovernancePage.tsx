// FE-4 Governance (§15): admin-only snapshot of the C3 control-plane
// surface. Operator-oriented presentation of the security truths — route
// enforcement mode, route-metadata coverage posture, and the C2 counters —
// not a dump of the raw structure. On-demand only; no polling.
import type { JSX } from "react";
import { getGovernance } from "../../api/ops";
import { PageHeader } from "../../layouts/AppShell";
import {
  Card,
  Callout,
  ErrorState,
  KeyValue,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { DataTable } from "../../design-system/table";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import { governanceHealthBadgeStatus } from "./health";
import styles from "../diagnostics/diagnostics.module.css";

export function GovernancePage(): JSX.Element {
  const q = useSnapshot(["ops", "governance"], getGovernance);
  const snap = q.data;
  return (
    <>
      <PageHeader
        title="Governance"
        subtitle="Admin-API control-plane posture — enforcement, coverage, counters"
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
        <Skeleton>Loading governance snapshot…</Skeleton>
      )}
      {snap === undefined && q.isError && (
        <ErrorState title="Governance snapshot unavailable">
          This surface requires the admin role; if you are an admin, use Refresh
          to retry.
        </ErrorState>
      )}
      {snap !== undefined && (
        <div className={styles.stack}>
          {snap.mode !== "enforce" && (
            <Callout
              variant="warning"
              title="RBAC metadata gate is in SHADOW mode"
              role="alert"
            >
              The metadata-driven role gate is log-only and does not block
              requests{snap.killSwitchActive ? " (kill switch active)" : ""}.
              Handler-level checks remain the backstop.
            </Callout>
          )}
          <Card title="Enforcement posture">
            <KeyValue
              items={[
                [
                  "C2 mode",
                  snap.mode === "enforce" ? (
                    <StatusBadge status="ok">enforce (fail-closed)</StatusBadge>
                  ) : (
                    <StatusBadge status="warn">{snap.mode}</StatusBadge>
                  ),
                ],
                [
                  "Governance health",
                  <StatusBadge
                    key="gh"
                    status={governanceHealthBadgeStatus(snap.healthStatus)}
                  >
                    {snap.healthStatus}
                  </StatusBadge>,
                ],
                [
                  "Routes (total / public)",
                  `${String(snap.routesTotal)} / ${String(snap.routesPublic)}`,
                ],
                ["Method policies", String(snap.methodEntries)],
                ["Snapshot generated", snap.generatedAt],
              ]}
            />
          </Card>
          {snap.issues.length > 0 && (
            <Card title="Findings">
              <DataTable
                caption="Governance findings"
                columns={[
                  { key: "sev", header: "Severity", render: (i) => i.severity },
                  { key: "code", header: "Code", render: (i) => i.code },
                  {
                    key: "count",
                    header: "Count",
                    numeric: true,
                    render: (i) => (i.count > 0 ? String(i.count) : "—"),
                  },
                  {
                    key: "hint",
                    header: "What it means",
                    render: (i) => i.hint,
                  },
                ]}
                rows={snap.issues}
                rowKey={(i) => i.code}
              />
            </Card>
          )}
          <Card title="Enforcement counters (since start)">
            <DataTable
              caption="C2 enforcement counters"
              columns={[
                { key: "k", header: "Counter", render: (c) => c.key },
                {
                  key: "v",
                  header: "Value",
                  numeric: true,
                  render: (c) => String(c.value),
                },
              ]}
              rows={snap.counters}
              rowKey={(c) => c.key}
            />
          </Card>
        </div>
      )}
    </>
  );
}
