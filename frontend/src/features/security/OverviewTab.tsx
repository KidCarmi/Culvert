// 2E-A Overview: the factual engine snapshot — scan mode, ClamAV, YARA, DPI,
// threat-feed facts, scan-service connectivity, cache summary. Three bounded
// reads (status / svc / cache) behind ONE manual Refresh; every value is a
// reported field, never an inferred health statement.
import type { JSX } from "react";
import {
  Card,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import {
  getScanCache,
  getScanSvc,
  getSecScanStatus,
} from "../../api/contentsec";
import styles from "../policy/policy.module.css";

/** Renders a server posture string; the two documented values get a badge,
 * anything else renders VERBATIM as unrecognized (never coerced). */
export function PostureBadge({ value }: { value: string }): JSX.Element {
  if (value === "fail_closed")
    return <StatusBadge status="ok">fail_closed</StatusBadge>;
  if (value === "fail_open_with_alert")
    return <StatusBadge status="warn">fail_open_with_alert</StatusBadge>;
  return (
    <StatusBadge status="warn">
      unrecognized: {value === "" ? "(empty)" : value}
    </StatusBadge>
  );
}

export function OverviewTab(): JSX.Element {
  const status = useSnapshot(
    ["security", "content", "status"],
    getSecScanStatus,
  );
  const svc = useSnapshot(["security", "content", "svc"], getScanSvc);
  const cache = useSnapshot(["security", "content", "cache"], getScanCache);
  const s = status.data;

  const refreshAll = (): void => {
    void status.refetch();
    void svc.refetch();
    void cache.refetch();
  };

  return (
    <div>
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={status.dataUpdatedAt}
          fetching={status.isFetching || svc.isFetching || cache.isFetching}
          error={status.isError || svc.isError || cache.isError}
          hasData={s !== undefined}
          onRefresh={refreshAll}
        />
      </div>

      {s === undefined && status.isPending && (
        <Skeleton>Loading scan-engine status…</Skeleton>
      )}
      {s === undefined && status.isError && (
        <ErrorState title="Engine status unavailable">
          The appliance&apos;s scan-engine status could not be loaded. Refresh
          to try again.
        </ErrorState>
      )}

      {s !== undefined && (
        <>
          <Card title="Scan engine">
            <KeyValue
              items={[
                ["Body scanning", s.enabled ? "enabled" : "not enabled"],
                [
                  "Scan mode",
                  s.scanSvcMode === "local" || s.scanSvcMode === "remote" ? (
                    s.scanSvcMode
                  ) : (
                    <StatusBadge status="warn">
                      unrecognized: {s.scanSvcMode}
                    </StatusBadge>
                  ),
                ],
                ...(s.clamavStatus !== undefined
                  ? ([["ClamAV", s.clamavStatus]] as const)
                  : []),
                ...(s.clamavVersion !== undefined
                  ? ([["ClamAV signatures", s.clamavVersion]] as const)
                  : []),
                ...(s.yaraRules !== undefined
                  ? ([
                      [
                        "YARA rules loaded",
                        `${String(s.yaraRules)}${
                          s.yaraWarnings !== undefined && s.yaraWarnings > 0
                            ? ` (${String(s.yaraWarnings)} parser warning${s.yaraWarnings === 1 ? "" : "s"})`
                            : ""
                        }`,
                      ],
                    ] as const)
                  : []),
                ...(s.yaraEnabled !== undefined
                  ? ([
                      ["YARA engine", s.yaraEnabled ? "enabled" : "disabled"],
                    ] as const)
                  : []),
                ...(s.statScanTimeout !== undefined
                  ? ([["Scan timeouts", String(s.statScanTimeout)]] as const)
                  : []),
              ]}
            />
          </Card>

          <Card title="Threat feeds">
            <KeyValue
              items={[
                [
                  "Entries",
                  s.threatFeedEntries !== undefined
                    ? String(s.threatFeedEntries)
                    : "not reported",
                ],
                [
                  "Last sync attempt",
                  s.threatFeedLastSync !== undefined &&
                  s.threatFeedLastSync !== ""
                    ? s.threatFeedLastSync
                    : "never",
                ],
                [
                  "Last successful sync",
                  s.threatFeedLastSuccess !== undefined &&
                  s.threatFeedLastSuccess !== ""
                    ? s.threatFeedLastSuccess
                    : "never",
                ],
                [
                  "Last sync result",
                  s.threatFeedSyncOk === true ? (
                    "succeeded"
                  ) : s.threatFeedSyncError !== undefined ? (
                    <StatusBadge status="warn">
                      failed: {s.threatFeedSyncError}
                    </StatusBadge>
                  ) : (
                    "not reported"
                  ),
                ],
                ...(s.statFeedBlocked !== undefined
                  ? ([
                      ["Requests blocked by feeds", String(s.statFeedBlocked)],
                    ] as const)
                  : []),
              ]}
            />
            <p className={styles.refDetail}>
              A failed sync means this attempt did not complete — the previously
              synced feed data keeps enforcing until a sync succeeds.
            </p>
          </Card>

          <Card title="Scan service">
            {svc.data === undefined ? (
              svc.isError ? (
                <p className={styles.refDetail}>
                  The scan-service state could not be loaded.
                </p>
              ) : (
                <Skeleton>Loading…</Skeleton>
              )
            ) : (
              <KeyValue
                items={[
                  [
                    "Remote sidecar",
                    svc.data.remoteEnabled ? "configured" : "not configured",
                  ],
                  ...(svc.data.remoteEnabled
                    ? ([
                        ["URL", <Mono key="u">{svc.data.remoteUrl}</Mono>],
                        [
                          "Probe",
                          svc.data.remoteStatus === "connected" ? (
                            <StatusBadge status="ok">connected</StatusBadge>
                          ) : (
                            <StatusBadge status="critical">
                              {svc.data.remoteStatus ?? "not reported"}
                            </StatusBadge>
                          ),
                        ],
                      ] as const)
                    : []),
                ]}
              />
            )}
          </Card>

          <Card title="Scan verdict cache">
            {cache.data === undefined ? (
              cache.isError ? (
                <p className={styles.refDetail}>
                  The cache state could not be loaded.
                </p>
              ) : (
                <Skeleton>Loading…</Skeleton>
              )
            ) : cache.data.enabled ? (
              <KeyValue
                items={[
                  ["Entries", String(cache.data.cacheSize ?? 0)],
                  ["Hits", String(cache.data.cacheHits ?? 0)],
                  ["Misses", String(cache.data.cacheMisses ?? 0)],
                ]}
              />
            ) : (
              <p className={styles.refDetail}>
                The scan verdict cache is not enabled on this appliance.
              </p>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
