// Slice 2A-M — Monitor → History & Storage (FE-V02 residue): the persistent
// traffic-history management surface. Snapshot-driven per ADR-FE-002 (one
// GET, manual Refresh, no polling/SSE); the retention view answers, in
// order: enabled? encrypted? how much retained? what policy? disk pressure?
// projected growth? available actions.
//
// RBAC: viewer/operator get the full READ surface plus the recent-memory
// export; ONLY admin mounts the mutation controls (uiRoutes truth:
// GET /api/logs/retention + GET /api/export are viewer; PUT retention and
// POST purge are admin). No decorative disabled buttons.
//
// Mutation doctrine: explicit edit state, one explicit Save, retry=false,
// no optimistic update — a success renders ONLY the server's returned
// retention view. A network/timeout outcome is STATE UNKNOWN: the prior
// snapshot stays, the outcome is declared unconfirmed, and further
// mutations are blocked until an explicit refresh confirms server truth.
// Purge is a T2 destructive ceremony (FE-2 ConfirmationDialog).
import { useEffect, useRef, useState, type JSX } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "../../layouts/AppShell";
import {
  Button,
  Callout,
  Card,
  ErrorState,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { InputField, SelectField } from "../../design-system/forms";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import {
  getRetention,
  purgeHistory,
  putRetention,
  RETENTION_BOUNDS,
} from "../../api/retention";
import type { RetentionView } from "../../api/retention";
import { ApiError, apiDownloadRequest } from "../../api/client";
import { createRequestRunOwner } from "../../shared/runOwner";
import { createDownloadOwner } from "../../shared/blobOwner";
import { registerAuthCleanup } from "../../auth/teardown";
import { useAuth } from "../../auth/AuthProvider";
import { hasRole } from "../../auth/rbac";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import styles from "./monitor.module.css";

const RETENTION_KEY = ["monitor", "retention"] as const;

function fmtBytes(n: number | undefined): string {
  if (n === undefined) return "—";
  if (n < 1024) return `${String(n)} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function fmtMs(ms: number | undefined): string {
  if (ms === undefined || ms === 0) return "—";
  return new Date(ms).toISOString();
}

function exportFilename(format: "json" | "csv"): string {
  const d = new Date();
  const p = (n: number): string => String(n).padStart(2, "0");
  const ts = `${String(d.getFullYear())}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
  return `culvert-recent-traffic-${ts}.${format}`;
}

interface EditState {
  enabled: boolean;
  days: string;
  maxGB: string;
  criticalDiskPct: string;
}

function seedEdit(v: RetentionView): EditState {
  return {
    enabled: v.enabled,
    days: String(v.retentionDays),
    maxGB: String(v.retentionMaxGB),
    criticalDiskPct: String(v.guard.criticalDiskPct),
  };
}

// Client-side mirror of the server bounds — UX only, server authoritative.
function validateEdit(e: EditState): string {
  const days = Number(e.days);
  if (
    !Number.isInteger(days) ||
    days < RETENTION_BOUNDS.days.min ||
    days > RETENTION_BOUNDS.days.max
  ) {
    return `Retention days must be an integer between ${String(RETENTION_BOUNDS.days.min)} and ${String(RETENTION_BOUNDS.days.max)}.`;
  }
  const gb = Number(e.maxGB);
  if (
    !Number.isFinite(gb) ||
    gb < RETENTION_BOUNDS.maxGB.min ||
    gb > RETENTION_BOUNDS.maxGB.max
  ) {
    return `Max storage GB must be between ${String(RETENTION_BOUNDS.maxGB.min)} and ${String(RETENTION_BOUNDS.maxGB.max)}.`;
  }
  const pct = Number(e.criticalDiskPct);
  if (
    !Number.isInteger(pct) ||
    pct < RETENTION_BOUNDS.criticalDiskPct.min ||
    pct > RETENTION_BOUNDS.criticalDiskPct.max
  ) {
    return `Critical disk threshold must be an integer between ${String(RETENTION_BOUNDS.criticalDiskPct.min)} and ${String(RETENTION_BOUNDS.criticalDiskPct.max)}.`;
  }
  return "";
}

export function HistoryPage(): JSX.Element {
  const q = useSnapshot(RETENTION_KEY, (signal) => getRetention(signal));
  const view: RetentionView | undefined = q.data;
  const qc = useQueryClient();
  const { state } = useAuth();
  const isAdmin = hasRole(state.role ?? "viewer", "admin");

  // Request owners: mutations are not owned by cancelQueries, and a purge
  // must never be aborted by superseding a save — separate owners, both
  // wired to unmount + the FE-3 authentication boundary.
  const saveOwner = useRef(createRequestRunOwner());
  const purgeOwner = useRef(createRequestRunOwner());
  const downloads = useRef(createDownloadOwner());
  useEffect(() => {
    const s = saveOwner.current;
    const p = purgeOwner.current;
    const d = downloads.current;
    const unregister = registerAuthCleanup(() => {
      s.abort();
      p.abort();
      d.abortAndRevoke();
    });
    return () => {
      unregister();
      s.abort();
      p.abort();
      d.abortAndRevoke();
    };
  }, []);

  // ── edit state (admin) ───────────────────────────────────────────────────
  const [edit, setEdit] = useState<EditState | null>(null);
  const [editError, setEditError] = useState("");
  // STATE UNKNOWN latch (§8/§11): a mutation whose outcome the client never
  // observed blocks further mutations until an explicit refresh confirms
  // server truth. Cleared ONLY by a successful GET.
  const [unknown, setUnknown] = useState<null | "save" | "purge">(null);
  const [purgeOpen, setPurgeOpen] = useState(false);
  const [purgeResult, setPurgeResult] = useState<ConfirmResult>("idle");
  const [purgeError, setPurgeError] = useState("");
  const [purgedAck, setPurgedAck] = useState(false);

  const adoptServerView = (v: RetentionView): void => {
    qc.setQueryData(RETENTION_KEY, v);
  };

  const refreshToResolve = (): void => {
    // Uncertainty resolves ONLY on a fresh successful GET. `res.data` alone
    // is NOT proof: a failed refetch deliberately keeps the previous snapshot
    // in the cache (SnapshotBar's stale truth), and a cancelled refetch
    // reverts to the pre-refetch success state — so require the refetch to
    // have SUCCEEDED and the success stamp to have ADVANCED past the one we
    // started from.
    const before = q.dataUpdatedAt;
    void q.refetch().then((res) => {
      if (res.isSuccess && res.dataUpdatedAt > before) setUnknown(null);
    });
  };

  const save = useMutation<RetentionView, unknown, EditState>({
    retry: false,
    mutationFn: (e) => {
      const owner = saveOwner.current;
      const signal = owner.begin();
      return putRetention(
        {
          enabled: e.enabled,
          retentionDays: Number(e.days),
          retentionMaxGB: Number(e.maxGB),
          criticalDiskPct: Number(e.criticalDiskPct),
        },
        signal,
      ).finally(() => {
        owner.settle(signal);
      });
    },
    onSuccess: (v) => {
      adoptServerView(v); // ONLY the returned server view — never form echo
      setEdit(null);
      setEditError("");
    },
    onError: (err) => {
      if (unknownOutcome(err)) {
        setEdit(null);
        setUnknown("save");
        return;
      }
      setEditError(serverErrorText(err, "Saving history settings failed."));
    },
  });

  const purge = useMutation<RetentionView, unknown, void>({
    retry: false,
    mutationFn: () => {
      const owner = purgeOwner.current;
      const signal = owner.begin();
      setPurgeResult("pending");
      return purgeHistory(signal).finally(() => {
        owner.settle(signal);
      });
    },
    onSuccess: (v) => {
      adoptServerView(v);
      setPurgeOpen(false); // closed only after a confirmed server response
      setPurgeResult("idle");
      setPurgeError("");
      setPurgedAck(true);
    },
    onError: (err) => {
      if (unknownOutcome(err)) {
        setPurgeOpen(false);
        setPurgeResult("idle");
        setUnknown("purge");
        return;
      }
      setPurgeResult("failed");
      setPurgeError(serverErrorText(err, "Purge failed."));
    },
  });

  // ── export (viewer+) ─────────────────────────────────────────────────────
  const [exporting, setExporting] = useState<null | "json" | "csv">(null);
  const [exportError, setExportError] = useState("");
  const runExport = (format: "json" | "csv"): void => {
    const owner = downloads.current;
    const signal = owner.begin(); // a second format choice supersedes the first
    setExporting(format);
    setExportError("");
    const mediaType = format === "csv" ? "text/csv" : "application/json";
    apiDownloadRequest(`/api/export?format=${format}`, [mediaType], { signal })
      .then((res) => {
        owner.deliver(signal, res.blob, exportFilename(format));
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError && err.kind === "aborted") return;
        setExportError(
          serverErrorText(err, "Export failed. It can simply be retried."),
        );
      })
      .finally(() => {
        owner.settle(signal);
        setExporting((cur) => (cur === format ? null : cur));
      });
  };

  const mutationsBlocked = unknown !== null;

  return (
    <>
      <PageHeader
        title="History & Storage"
        subtitle="Persistent traffic-history retention, storage usage, and the recent-memory export."
        actions={
          <SnapshotBar
            updatedAt={q.dataUpdatedAt}
            fetching={q.isFetching}
            error={q.isError}
            hasData={view !== undefined}
            onRefresh={refreshToResolve}
          />
        }
      />

      {unknown !== null && (
        <div className={styles.historySection}>
          <Callout
            variant="unknown"
            title={
              unknown === "purge"
                ? "Purge outcome unconfirmed"
                : "Save outcome unconfirmed"
            }
            role="alert"
          >
            {unknown === "purge"
              ? "The appliance may have completed the purge before the connection was lost. Refresh History & Storage before taking another destructive action."
              : "The server may have applied the settings before the connection was lost. Refresh to load the current server state before saving again."}
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={refreshToResolve}>
                Refresh current state
              </Button>
            </div>
          </Callout>
        </div>
      )}

      {view === undefined && q.isPending && <Skeleton>Loading…</Skeleton>}
      {view === undefined && q.isError && (
        <ErrorState title="History status unavailable">
          The retention snapshot could not be loaded. Refresh to try again.
        </ErrorState>
      )}

      {view !== undefined && (
        <>
          {view.guard.minimalMode && (
            <div className={styles.historySection}>
              <Callout
                variant="critical"
                title="Emergency minimal logging active"
                role="alert"
              >
                Disk protection has switched logging to Minimal mode.
                {view.guard.lastCleanupReason !== "" &&
                  ` Last cleanup: ${view.guard.lastCleanupReason}.`}
              </Callout>
            </div>
          )}
          {view.guard.warning !== "" && (
            <div className={styles.historySection}>
              <Callout variant="warning" title="Disk pressure warning">
                {view.guard.warning}
              </Callout>
            </div>
          )}
          {!view.enabled && !view.configurable && (
            <div className={styles.historySection}>
              <Callout variant="warning" title="History store not configurable">
                No history-store location is configured on this appliance, so
                persistent Traffic history cannot be enabled from this console.
              </Callout>
            </div>
          )}

          <div className={styles.historyGrid}>
            <Card title="Posture">
              <dl className={styles.historyKV}>
                <div>
                  <dt>Persistent history</dt>
                  <dd>
                    {view.enabled ? (
                      <StatusBadge status="ok">Enabled</StatusBadge>
                    ) : (
                      <StatusBadge status="neutral">Disabled</StatusBadge>
                    )}
                  </dd>
                </div>
                <div>
                  <dt>Encryption</dt>
                  <dd>
                    {view.enabled ? (
                      view.encrypted ? (
                        <StatusBadge status="ok">Encrypted</StatusBadge>
                      ) : (
                        <StatusBadge status="neutral">Unencrypted</StatusBadge>
                      )
                    ) : (
                      "— (store disabled)"
                    )}
                  </dd>
                </div>
                <div>
                  <dt>Encryption key available</dt>
                  <dd>{view.encryptionAvailable ? "yes" : "no"}</dd>
                </div>
                <div>
                  <dt>Retention days</dt>
                  <dd>{view.retentionDays}</dd>
                </div>
                <div>
                  <dt>Max storage</dt>
                  <dd>{view.retentionMaxGB} GB</dd>
                </div>
              </dl>
              {!view.enabled && (
                <p className={styles.historyNote}>
                  Persistent history is not being written. Existing retained
                  history remains on disk until it expires or is purged.
                </p>
              )}
            </Card>

            <Card title="Usage">
              {view.usage.enabled ? (
                <dl className={styles.historyKV}>
                  <div>
                    <dt>Stored size</dt>
                    <dd>{fmtBytes(view.usage.bytes)}</dd>
                  </div>
                  <div>
                    <dt>Entries</dt>
                    <dd>
                      {view.usage.count === undefined
                        ? "—"
                        : `${String(view.usage.count)}${view.usage.capped === true ? " (approximate — scan capped)" : ""}`}
                    </dd>
                  </div>
                  <div>
                    <dt>Oldest entry</dt>
                    <dd>{fmtMs(view.usage.oldestMs)}</dd>
                  </div>
                  <div>
                    <dt>Dropped</dt>
                    <dd>{view.usage.dropped ?? "—"}</dd>
                  </div>
                  <div>
                    <dt>Pruned</dt>
                    <dd>{view.usage.pruned ?? "—"}</dd>
                  </div>
                </dl>
              ) : (
                <p className={styles.historyNote}>
                  No live usage data — the persistent store is not running.
                  Retained data may still exist on disk.
                </p>
              )}
            </Card>

            <Card title="Projected growth">
              <dl className={styles.historyKV}>
                <div>
                  <dt>Avg entry size</dt>
                  <dd>{fmtBytes(view.estimate.avgEntryBytes)}</dd>
                </div>
                <div>
                  <dt>Requests / min</dt>
                  <dd>{view.estimate.reqPerMin.toFixed(1)}</dd>
                </div>
                <div>
                  <dt>Per day</dt>
                  <dd>{fmtBytes(view.estimate.bytesPerDay)}</dd>
                </div>
                <div>
                  <dt>Per week</dt>
                  <dd>{fmtBytes(view.estimate.bytesPerWeek)}</dd>
                </div>
                <div>
                  <dt>Per month</dt>
                  <dd>{fmtBytes(view.estimate.bytesPerMonth)}</dd>
                </div>
              </dl>
            </Card>

            <Card title="Disk guard">
              <dl className={styles.historyKV}>
                <div>
                  <dt>Logging mode</dt>
                  <dd>{view.guard.loggingMode}</dd>
                </div>
                <div>
                  <dt>Critical threshold</dt>
                  <dd>{view.guard.criticalDiskPct}%</dd>
                </div>
                <div>
                  <dt>Disk used</dt>
                  <dd>
                    {view.guard.diskUsedPct === undefined
                      ? "—"
                      : `${view.guard.diskUsedPct.toFixed(1)}%`}
                  </dd>
                </div>
                <div>
                  <dt>Disk free</dt>
                  <dd>{fmtBytes(view.guard.diskFreeBytes)}</dd>
                </div>
                <div>
                  <dt>Last cleanup</dt>
                  <dd>
                    {fmtMs(view.guard.lastCleanupMs)}
                    {view.guard.lastCleanupReason !== "" &&
                      ` (${view.guard.lastCleanupReason})`}
                  </dd>
                </div>
              </dl>
            </Card>
          </div>

          {purgedAck && (
            <div className={styles.historySection}>
              <Callout variant="success" title="Retained history purged">
                The appliance confirmed the purge and returned the state shown
                above.
              </Callout>
            </div>
          )}

          {isAdmin && (
            <Card
              title="History settings"
              actions={
                edit === null ? (
                  <Button
                    size="sm"
                    disabled={mutationsBlocked || !view.configurable}
                    onClick={() => {
                      setEdit(seedEdit(view));
                      setEditError("");
                      setPurgedAck(false);
                    }}
                  >
                    Edit history settings
                  </Button>
                ) : undefined
              }
            >
              {edit === null ? (
                <p className={styles.historyNote}>
                  Retention, storage cap, disk threshold, and enable/disable are
                  changed through an explicit edit and one Save.
                </p>
              ) : (
                <form
                  className={styles.historyForm}
                  onSubmit={(e) => {
                    e.preventDefault();
                    const msg = validateEdit(edit);
                    setEditError(msg);
                    if (msg === "" && !save.isPending) save.mutate(edit);
                  }}
                >
                  <SelectField
                    label="Persistent history"
                    value={edit.enabled ? "enabled" : "disabled"}
                    onChange={(e) => {
                      setEdit({
                        ...edit,
                        enabled: e.target.value === "enabled",
                      });
                    }}
                  >
                    <option value="enabled">Enabled</option>
                    <option value="disabled">Disabled</option>
                  </SelectField>
                  <InputField
                    label="Retention days"
                    inputMode="numeric"
                    value={edit.days}
                    onChange={(e) => {
                      setEdit({ ...edit, days: e.target.value });
                    }}
                  />
                  <InputField
                    label="Max storage GB"
                    inputMode="decimal"
                    value={edit.maxGB}
                    onChange={(e) => {
                      setEdit({ ...edit, maxGB: e.target.value });
                    }}
                  />
                  <InputField
                    label="Critical disk threshold %"
                    inputMode="numeric"
                    value={edit.criticalDiskPct}
                    onChange={(e) => {
                      setEdit({ ...edit, criticalDiskPct: e.target.value });
                    }}
                  />
                  <div className={styles.queryActions}>
                    <Button
                      type="submit"
                      variant="primary"
                      disabled={save.isPending || mutationsBlocked}
                    >
                      {save.isPending ? "Saving…" : "Save history settings"}
                    </Button>
                    <Button
                      variant="ghost"
                      disabled={save.isPending}
                      onClick={() => {
                        setEdit(null);
                        setEditError("");
                      }}
                    >
                      Cancel
                    </Button>
                  </div>
                  {!edit.enabled && view.enabled && (
                    <Callout
                      variant="info"
                      title="Disabling keeps retained data"
                    >
                      Disabling stops new persistent traffic-history writes.
                      Existing retained history remains on disk until it expires
                      or is purged.
                    </Callout>
                  )}
                  {edit.enabled && !view.enabled && (
                    <Callout
                      variant="info"
                      title={
                        view.encryptionAvailable
                          ? "Store will be encrypted"
                          : "Store will be unencrypted"
                      }
                    >
                      {view.encryptionAvailable
                        ? "An encryption key is available — new history will be written encrypted at rest."
                        : "No encryption key is configured — history will be written unencrypted, which is a supported configuration."}
                    </Callout>
                  )}
                  {editError !== "" && (
                    <Callout variant="critical" role="alert">
                      {editError.includes("different encryption key") ? (
                        <>
                          Saved history was created with a different encryption
                          key. You may purge retained history below and then
                          enable again — two deliberate actions; nothing is
                          purged automatically. Server said: {editError}
                        </>
                      ) : (
                        editError
                      )}
                    </Callout>
                  )}
                </form>
              )}
            </Card>
          )}

          {isAdmin && (
            <Card title="Purge retained history">
              <p className={styles.historyNote}>
                Permanently deletes all retained persistent Traffic history on
                this appliance — including on-disk history retained while saving
                is disabled. It does not touch in-memory recent Traffic, the
                Audit Log, configuration history, or support bundles.
              </p>
              <Button
                variant="danger"
                disabled={purge.isPending || mutationsBlocked}
                onClick={() => {
                  setPurgedAck(false);
                  setPurgeError("");
                  setPurgeResult("idle");
                  setPurgeOpen(true);
                }}
              >
                Purge retained history…
              </Button>
            </Card>
          )}

          <Card title="Export recent memory">
            <p className={styles.historyNote}>
              Exports the appliance&apos;s current in-memory traffic ring (the
              newest requests held in memory). It does not export the full
              persistent history store.
            </p>
            <div className={styles.queryActions}>
              <Button
                disabled={exporting === "json"}
                onClick={() => {
                  runExport("json");
                }}
              >
                {exporting === "json"
                  ? "Preparing…"
                  : "Export recent memory — JSON"}
              </Button>
              <Button
                disabled={exporting === "csv"}
                onClick={() => {
                  runExport("csv");
                }}
              >
                {exporting === "csv"
                  ? "Preparing…"
                  : "Export recent memory — CSV"}
              </Button>
            </div>
            {exportError !== "" && (
              <Callout variant="critical" role="alert">
                {exportError}
              </Callout>
            )}
          </Card>
        </>
      )}

      {isAdmin && (
        <ConfirmationDialog
          open={purgeOpen}
          tier={2}
          title="Purge persistent traffic history"
          body={
            <>
              This permanently deletes all retained Traffic history from this
              appliance. If history saving is disabled, stored history on disk
              is still deleted. This cannot be undone.
            </>
          }
          impact="All retained persistent Traffic history is deleted. In-memory recent Traffic, the Audit Log, configuration history, and support bundles are NOT affected."
          rollback="None — this cannot be undone."
          confirmLabel="Purge retained history"
          destructive
          result={purge.isPending ? "pending" : purgeResult}
          errorText={purgeError}
          onConfirm={() => {
            if (!purge.isPending) purge.mutate();
          }}
          onCancel={() => {
            if (!purge.isPending) {
              setPurgeOpen(false);
              setPurgeResult("idle");
              setPurgeError("");
            }
          }}
        />
      )}
    </>
  );
}
