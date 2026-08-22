// FE-4 Monitor → Audit (ADR-FE-002): bounded time-windowed queries over the
// existing /api/audit contract (offset pagination — audit volume is a
// different scale class from per-request traffic, the backend read is a
// bounded newest-first scan, and page sizes stay small). Sources are
// truthful: "Recent (memory)" is the 500-entry ring; "Persistent file" is
// the durable JSONL. Manual Refresh; no polling; before/after snapshots are
// expandable TEXT (never rendered as HTML).
import { useMemo, useState } from "react";
import type { FormEvent, JSX } from "react";
import { useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { getAudit } from "../../api/ops";
import type { AuditRecord } from "../../api/ops";
import { PageHeader } from "../../layouts/AppShell";
import {
  Button,
  Callout,
  EmptyState,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
} from "../../design-system/primitives";
import { InputField, SelectField } from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import { TIME_PRESETS, isTimePreset, resolveWindow } from "./timeRange";
import type { TimePreset } from "./timeRange";
import styles from "./monitor.module.css";

const PAGE_SIZE = 100;

interface AuditQuery {
  preset: TimePreset;
  customFrom: string;
  customTo: string;
  source: "memory" | "file";
  epoch: number;
}

export function AuditPage(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [applied, setApplied] = useState<AuditQuery>(() => {
    const rawPreset = searchParams.get("range") ?? "24h";
    return {
      preset: isTimePreset(rawPreset) ? rawPreset : "24h",
      customFrom: searchParams.get("from") ?? "",
      customTo: searchParams.get("to") ?? "",
      source: searchParams.get("source") === "file" ? "file" : "memory",
      epoch: 0,
    };
  });
  const [draft, setDraft] = useState<AuditQuery>(applied);
  const [formError, setFormError] = useState("");
  const [pageIndex, setPageIndex] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);

  // Frozen per applied query (same contract as TrafficPage): page N of a
  // window must be page N of the SAME window, not of a newer "now".
  const win = useMemo(
    () =>
      resolveWindow(
        applied.preset,
        applied.customFrom,
        applied.customTo,
        Date.now(),
      ),
    [applied],
  );
  const windowError = typeof win === "string" ? win : "";

  const query = useQuery({
    queryKey: ["ops", "audit", applied, pageIndex],
    // Consumes TanStack's AbortSignal so the FE-3 auth boundary
    // (cancelQueries) aborts the underlying request (§9).
    queryFn: ({ signal }) => {
      if (typeof win === "string") throw new Error(win);
      return getAudit(
        {
          offset: pageIndex * PAGE_SIZE,
          limit: PAGE_SIZE,
          fromMs: win.fromSec * 1000,
          toMs: win.toSec * 1000 + 999,
          source: applied.source,
        },
        signal,
      );
    },
    enabled: windowError === "",
    staleTime: Infinity,
    retry: false,
  });

  const apply = (ev: FormEvent): void => {
    ev.preventDefault();
    const check = resolveWindow(
      draft.preset,
      draft.customFrom,
      draft.customTo,
      Date.now(),
    );
    if (typeof check === "string") {
      setFormError(check);
      return;
    }
    setFormError("");
    const next = { ...draft, epoch: applied.epoch + 1 };
    setApplied(next);
    setPageIndex(0);
    setExpanded(null);
    const sp = new URLSearchParams();
    if (next.preset !== "24h") sp.set("range", next.preset);
    if (next.preset === "custom") {
      sp.set("from", next.customFrom);
      sp.set("to", next.customTo);
    }
    if (next.source === "file") sp.set("source", "file");
    setSearchParams(sp, { replace: true });
  };

  const page = query.data;
  const totalPages =
    page !== undefined ? Math.max(1, Math.ceil(page.total / PAGE_SIZE)) : 1;

  return (
    <>
      <PageHeader
        title="Audit Log"
        subtitle="Administrative actions — bounded queries over the audited record"
        actions={
          <SnapshotBar
            updatedAt={query.dataUpdatedAt}
            fetching={query.isFetching}
            error={query.isError}
            hasData={page !== undefined}
            onRefresh={() => {
              setApplied((a) => ({ ...a, epoch: a.epoch + 1 }));
              setPageIndex(0);
              setExpanded(null);
            }}
          />
        }
      />
      <form className={styles.queryBar} onSubmit={apply} noValidate>
        <SelectField
          label="Time range"
          value={draft.preset}
          onChange={(e) => {
            const v = e.target.value;
            if (isTimePreset(v)) setDraft((d) => ({ ...d, preset: v }));
          }}
        >
          {TIME_PRESETS.map((p) => (
            <option key={p} value={p}>
              {p === "custom" ? "Custom" : `Last ${p}`}
            </option>
          ))}
        </SelectField>
        {draft.preset === "custom" && (
          <>
            <InputField
              label="From"
              type="datetime-local"
              value={draft.customFrom}
              onChange={(e) => {
                setDraft((d) => ({ ...d, customFrom: e.target.value }));
              }}
            />
            <InputField
              label="To"
              type="datetime-local"
              value={draft.customTo}
              onChange={(e) => {
                setDraft((d) => ({ ...d, customTo: e.target.value }));
              }}
            />
          </>
        )}
        <SelectField
          label="Source"
          help="Recent = 500-entry volatile ring; Persistent = durable JSONL file"
          value={draft.source}
          onChange={(e) => {
            setDraft((d) => ({
              ...d,
              source: e.target.value === "file" ? "file" : "memory",
            }));
          }}
        >
          <option value="memory">Recent (memory)</option>
          <option value="file">Persistent file</option>
        </SelectField>
        <div className={styles.queryActions}>
          <Button type="submit" variant="primary">
            Apply
          </Button>
        </div>
      </form>
      {(formError !== "" || windowError !== "") && (
        <Callout variant="critical" role="alert">
          {formError !== "" ? formError : windowError}
        </Callout>
      )}

      {query.isPending && windowError === "" && (
        <Skeleton>Running query…</Skeleton>
      )}
      {query.isError && page === undefined && (
        <ErrorState title="Audit query failed">
          The audit query could not be completed. Use Refresh to retry.
        </ErrorState>
      )}

      {page !== undefined &&
        (page.entries.length === 0 ? (
          <EmptyState title="No audit entries">
            No administrative actions were recorded in this window for this
            source.
          </EmptyState>
        ) : (
          <>
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <caption className="sr-only">Audit log entries</caption>
                <thead>
                  <tr>
                    <th scope="col">
                      <span className="sr-only">Detail</span>
                    </th>
                    <th scope="col">Time</th>
                    <th scope="col">Actor</th>
                    <th scope="col">Action</th>
                    <th scope="col">Object</th>
                    <th scope="col">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {page.entries.map((e, i) => (
                    <AuditRow
                      key={`${String(e.ts)}-${String(i)}`}
                      e={e}
                      open={expanded === i}
                      onToggle={() => {
                        setExpanded(expanded === i ? null : i);
                      }}
                    />
                  ))}
                </tbody>
              </table>
            </div>
            <div className={styles.pager}>
              <span className={styles.pagerInfo}>
                Page {String(pageIndex + 1)} of {String(totalPages)} ·{" "}
                {String(page.total)} matching entries
              </span>
              <Button
                size="sm"
                disabled={pageIndex === 0 || query.isFetching}
                onClick={() => {
                  setPageIndex((p) => Math.max(0, p - 1));
                  setExpanded(null);
                }}
              >
                Previous
              </Button>
              <Button
                size="sm"
                disabled={pageIndex + 1 >= totalPages || query.isFetching}
                onClick={() => {
                  setPageIndex((p) => p + 1);
                  setExpanded(null);
                }}
              >
                Next
              </Button>
            </div>
          </>
        ))}
    </>
  );
}

function AuditRow({
  e,
  open,
  onToggle,
}: {
  e: AuditRecord;
  open: boolean;
  onToggle: () => void;
}): JSX.Element {
  return (
    <>
      <tr>
        <td>
          <button
            type="button"
            className={styles.expandBtn}
            aria-expanded={open}
            aria-label={`Details for ${e.action} at ${e.time}`}
            onClick={onToggle}
          >
            {open ? "▾" : "▸"}
          </button>
        </td>
        <td className={styles.mono}>{e.time}</td>
        <td>{e.actor}</td>
        <td className={styles.mono}>{e.action}</td>
        <td className={styles.hostCell}>{e.object}</td>
        <td className={styles.ruleCell}>{e.detail}</td>
      </tr>
      {open && (
        <tr className={styles.detailRow}>
          <td colSpan={6}>
            <div className={styles.rowDetail}>
              <KeyValue
                items={[
                  [
                    "Object ID",
                    e.objectId === "" ? (
                      "—"
                    ) : (
                      <Mono key="oid">{e.objectId}</Mono>
                    ),
                  ],
                  ["Detail", e.detail === "" ? "—" : e.detail],
                ]}
              />
              {e.before !== "" && (
                <>
                  <h3 className="sr-only">Before snapshot</h3>
                  <pre className={styles.beforeAfter}>{e.before}</pre>
                </>
              )}
              {e.after !== "" && (
                <>
                  <h3 className="sr-only">After snapshot</h3>
                  <pre className={styles.beforeAfter}>{e.after}</pre>
                </>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
