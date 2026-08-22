// FE-4 Monitor → Traffic (ADR-FE-002): an operational QUERY console over the
// keyset-cursor history contract. Explicit time range, server-side filters,
// draft→Apply execution (no per-keystroke queries), Previous/Next cursor
// paging with an in-memory cursor stack, truthful history availability, and
// visible snapshot freshness. Safe query state (preset/window/filters) lives
// in the URL for bookmarking; the opaque cursor stays in memory — a reload
// starts at page 1 (documented choice, §22). Full URIs are shown only in row
// detail and never placed in persistent browser storage.
import { useMemo, useState } from "react";
import type { FormEvent, JSX } from "react";
import { useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { getTrafficHistory, getTrafficMemory } from "../../api/ops";
import type { TrafficEntry } from "../../api/ops";
import { PageHeader } from "../../layouts/AppShell";
import {
  Button,
  Callout,
  EmptyState,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import type { Status } from "../../design-system/primitives";
import { InputField, SelectField } from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import {
  DEFAULT_PRESET,
  TIME_PRESETS,
  isTimePreset,
  resolveWindow,
} from "./timeRange";
import type { TimePreset } from "./timeRange";
import styles from "./monitor.module.css";

interface AppliedQuery {
  preset: TimePreset;
  customFrom: string;
  customTo: string;
  filter: string;
  status: string;
  method: string;
  identity: string;
  /** bumped on Apply/Refresh so presets re-resolve "now" */
  epoch: number;
}

function fromSearch(sp: URLSearchParams): AppliedQuery {
  const rawPreset = sp.get("range") ?? DEFAULT_PRESET;
  return {
    preset: isTimePreset(rawPreset) ? rawPreset : DEFAULT_PRESET,
    customFrom: sp.get("from") ?? "",
    customTo: sp.get("to") ?? "",
    filter: sp.get("filter") ?? "",
    status: sp.get("status") ?? "",
    method: sp.get("method") ?? "",
    identity: sp.get("identity") ?? "",
    epoch: 0,
  };
}

function statusBadge(s: string): JSX.Element {
  const map: Record<string, Status> = {
    OK: "ok",
    BLOCKED: "critical",
    POLICY_BLOCK: "critical",
    POLICY_DEFAULT_DENY: "critical",
    AUTH_FAIL: "warn",
    RATE_LIMITED: "warn",
    IP_BLOCKED: "critical",
  };
  return <StatusBadge status={map[s] ?? "neutral"}>{s}</StatusBadge>;
}

function fmtBytes(n: number): string {
  if (n <= 0) return "—";
  if (n < 1024) return `${String(n)} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function RowDetail({ e }: { e: TrafficEntry }): JSX.Element {
  const items: Array<readonly [string, JSX.Element | string]> = [
    ["Rule", e.ruleMatched === "" ? "—" : e.ruleMatched],
    ["Rule ID", e.ruleId === "" ? "—" : <Mono key="rid">{e.ruleId}</Mono>],
    ["Action", e.actionTaken === "" ? "—" : e.actionTaken],
    [
      "Full URI",
      e.uri === "" ? (
        "— (not logged for this rule)"
      ) : (
        <Mono key="uri">{e.uri}</Mono>
      ),
    ],
    ["TLS", e.sslAction === "" ? "—" : e.sslAction],
    ["Auth source", e.authSource === "" ? "—" : e.authSource],
    ["Auth outcome", e.authOutcome === "" ? "—" : e.authOutcome],
    [
      "Bytes sent / received",
      `${fmtBytes(e.bytesSent)} / ${fmtBytes(e.bytesRecv)}`,
    ],
    ["Duration", e.durationMs > 0 ? `${String(e.durationMs)} ms` : "—"],
  ];
  if (e.dec !== null) {
    items.push(
      ["Decryption outcome", e.dec.outcome],
      ["Decryption decision source", e.dec.decisionSource],
    );
    if (e.dec.failCategory !== "")
      items.push(["Decryption failure category", e.dec.failCategory]);
    if (e.dec.profileId !== "") {
      items.push([
        "Decryption profile",
        <Mono key="dp">{e.dec.profileId}</Mono>,
      ]);
    }
  }
  return (
    <div className={styles.rowDetail}>
      <KeyValue items={items} />
    </div>
  );
}

export function TrafficPage(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [applied, setApplied] = useState<AppliedQuery>(() =>
    fromSearch(searchParams),
  );
  const [draft, setDraft] = useState<AppliedQuery>(applied);
  const [formError, setFormError] = useState("");
  // In-memory cursor stack (§7/§22): cursors[i] reaches page i+2; reload ⇒ page 1.
  const [cursors, setCursors] = useState<readonly string[]>([]);
  const [memoryFallback, setMemoryFallback] = useState(false);
  const cursor = cursors.at(-1) ?? "";

  // The window is resolved ONCE per applied query (Apply/Refresh bump
  // `epoch`) and FROZEN across renders — pagination renders must not
  // re-resolve "now": the cursor is fingerprint-bound to the exact from/to
  // it was minted under, and a per-render drifting window would 400 every
  // continuation (and make "page 2" of a moving window incoherent).
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
    queryKey: ["ops", "traffic", applied, cursor],
    queryFn: ({ signal }) => {
      if (typeof win === "string") throw new Error(win);
      return getTrafficHistory(
        {
          fromSec: win.fromSec,
          toSec: win.toSec,
          filter: applied.filter,
          status: applied.status,
          method: applied.method,
          identity: applied.identity,
          cursor,
        },
        signal,
      );
    },
    enabled: windowError === "",
    staleTime: Infinity,
    retry: false,
  });

  const memQuery = useQuery({
    queryKey: ["ops", "traffic-memory", applied],
    queryFn: ({ signal }) => {
      if (typeof win === "string") throw new Error(win);
      return getTrafficMemory(
        {
          fromSec: win.fromSec,
          toSec: win.toSec,
          filter: applied.filter,
          status: applied.status,
          method: applied.method,
          identity: applied.identity,
          limit: 100,
        },
        signal,
      );
    },
    enabled: memoryFallback && windowError === "",
    staleTime: Infinity,
    retry: false,
  });

  const [expanded, setExpanded] = useState<number | null>(null);

  const applyDraft = (ev: FormEvent): void => {
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
    // Changing the applied query cancels the old request (key change +
    // AbortSignal), resets the cursor stack, and starts at page 1 (§6).
    const next = { ...draft, epoch: applied.epoch + 1 };
    setApplied(next);
    setCursors([]);
    setExpanded(null);
    setMemoryFallback(false);
    const sp = new URLSearchParams();
    if (next.preset !== DEFAULT_PRESET) sp.set("range", next.preset);
    if (next.preset === "custom") {
      sp.set("from", next.customFrom);
      sp.set("to", next.customTo);
    }
    if (next.filter !== "") sp.set("filter", next.filter);
    if (next.status !== "") sp.set("status", next.status);
    if (next.method !== "") sp.set("method", next.method);
    if (next.identity !== "") sp.set("identity", next.identity);
    setSearchParams(sp, { replace: true });
  };

  const refresh = (): void => {
    // Refresh re-resolves the window (presets are relative to "now") and
    // restarts at page 1 — a moving window plus a deep cursor is dishonest.
    setApplied((a) => ({ ...a, epoch: a.epoch + 1 }));
    setCursors([]);
    setExpanded(null);
  };

  const page = query.data;
  const set = (patch: Partial<AppliedQuery>): void => {
    setDraft((d) => ({ ...d, ...patch }));
  };

  return (
    <>
      <PageHeader
        title="Traffic"
        subtitle="Query-driven history console — server-side filters, bounded pages"
        actions={
          <SnapshotBar
            updatedAt={query.dataUpdatedAt}
            fetching={query.isFetching}
            error={query.isError}
            hasData={page !== undefined}
            onRefresh={refresh}
          />
        }
      />
      <form className={styles.queryBar} onSubmit={applyDraft} noValidate>
        <SelectField
          label="Time range"
          value={draft.preset}
          onChange={(e) => {
            const v = e.target.value;
            if (isTimePreset(v)) set({ preset: v });
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
              onChange={(e) => set({ customFrom: e.target.value })}
            />
            <InputField
              label="To"
              type="datetime-local"
              value={draft.customTo}
              onChange={(e) => set({ customTo: e.target.value })}
            />
          </>
        )}
        <InputField
          label="Host / IP contains"
          value={draft.filter}
          onChange={(e) => set({ filter: e.target.value })}
        />
        <SelectField
          label="Status"
          value={draft.status}
          onChange={(e) => set({ status: e.target.value })}
        >
          <option value="">Any</option>
          {[
            "OK",
            "BLOCKED",
            "POLICY_BLOCK",
            "POLICY_DEFAULT_DENY",
            "AUTH_FAIL",
            "RATE_LIMITED",
            "IP_BLOCKED",
          ].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </SelectField>
        <SelectField
          label="Method"
          value={draft.method}
          onChange={(e) => set({ method: e.target.value })}
        >
          <option value="">Any</option>
          {["GET", "POST", "PUT", "DELETE", "CONNECT", "HEAD"].map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </SelectField>
        <InputField
          label="Identity contains"
          value={draft.identity}
          onChange={(e) => set({ identity: e.target.value })}
        />
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

      {page !== undefined && !page.history && (
        <Callout
          variant="warning"
          title="Persistent history is disabled"
          role="status"
        >
          The request-history store is not enabled on this appliance, so
          retained history cannot be searched (Settings → request-log retention
          governs it). You can query the small in-memory ring of RECENT requests
          instead — a different, volatile data source.
          <div className={styles.fallbackAction}>
            <Button
              size="sm"
              onClick={() => {
                setMemoryFallback(true);
              }}
            >
              Query recent memory instead
            </Button>
          </div>
        </Callout>
      )}

      {query.isPending && windowError === "" && (
        <Skeleton>Running query…</Skeleton>
      )}
      {query.isError && page === undefined && (
        <ErrorState title="Query failed">
          The history query could not be completed. Adjust the query or use
          Refresh to retry.
        </ErrorState>
      )}

      {memoryFallback && memQuery.data !== undefined && (
        <>
          <Callout variant="info" role="status">
            Showing the in-memory RECENT ring (
            {String(memQuery.data.logs.length)} of {String(memQuery.data.total)}{" "}
            matches) — not retained history.
          </Callout>
          <TrafficTable
            rows={memQuery.data.logs}
            expanded={expanded}
            onToggle={setExpanded}
          />
        </>
      )}

      {page !== undefined && page.history && (
        <>
          {page.logs.length === 0 && !page.hasMore ? (
            // TRUE terminal: the server exhausted the requested window.
            <EmptyState title="No matching requests">
              Nothing in retained history matches this filter and time range.
            </EmptyState>
          ) : (
            <>
              {page.logs.length === 0 ? (
                // Scan-limited empty segment (§3): the bounded search found
                // no match IN THIS SEGMENT but has not exhausted the window
                // — never rendered as a terminal empty result. Continuation
                // stays an explicit, bounded operator action (no
                // auto-chaining of scan segments).
                <Callout
                  variant="info"
                  title="No matches in this scanned segment"
                  role="status"
                >
                  More retained history remains to search — this query scanned a
                  bounded segment of history without finding a match in it. Use
                  “Continue search” to search the next segment.
                </Callout>
              ) : (
                <TrafficTable
                  rows={page.logs}
                  expanded={expanded}
                  onToggle={setExpanded}
                />
              )}
              <div className={styles.pager}>
                <span className={styles.pagerInfo}>
                  {page.scanLimited && page.hasMore
                    ? `${String(page.logs.length)} results in this scan segment — more retained history remains to search`
                    : `${String(page.logs.length)} results${
                        page.hasMore ? " — more results available" : ""
                      }`}
                  {cursors.length > 0
                    ? ` (page ${String(cursors.length + 1)})`
                    : ""}
                </span>
                <Button
                  size="sm"
                  disabled={cursors.length === 0 || query.isFetching}
                  onClick={() => {
                    setCursors((c) => c.slice(0, -1));
                    setExpanded(null);
                  }}
                >
                  Previous
                </Button>
                <Button
                  size="sm"
                  disabled={
                    !page.hasMore || page.nextCursor === "" || query.isFetching
                  }
                  onClick={() => {
                    setCursors((c) => [...c, page.nextCursor]);
                    setExpanded(null);
                  }}
                >
                  {page.scanLimited && page.hasMore
                    ? "Continue search"
                    : "Next"}
                </Button>
              </div>
            </>
          )}
        </>
      )}
    </>
  );
}

function TrafficTable({
  rows,
  expanded,
  onToggle,
}: {
  rows: readonly TrafficEntry[];
  expanded: number | null;
  onToggle: (i: number | null) => void;
}): JSX.Element {
  return (
    <div className={styles.tableWrap}>
      <table className={styles.table}>
        <caption className="sr-only">Traffic history query results</caption>
        <thead>
          <tr>
            <th scope="col">
              <span className="sr-only">Detail</span>
            </th>
            <th scope="col">Time</th>
            <th scope="col">Source IP</th>
            <th scope="col">Identity</th>
            <th scope="col">Method</th>
            <th scope="col">Destination</th>
            <th scope="col">Status</th>
            <th scope="col">Rule</th>
            <th scope="col" className={styles.numeric}>
              Bytes
            </th>
            <th scope="col" className={styles.numeric}>
              Duration
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((e, i) => (
            <TrafficRow
              key={`${String(e.ts)}-${String(i)}`}
              e={e}
              open={expanded === i}
              onToggle={() => {
                onToggle(expanded === i ? null : i);
              }}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TrafficRow({
  e,
  open,
  onToggle,
}: {
  e: TrafficEntry;
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
            aria-label={`Details for ${e.host} at ${e.time}`}
            onClick={onToggle}
          >
            {open ? "▾" : "▸"}
          </button>
        </td>
        <td className={styles.mono}>{e.time}</td>
        <td className={styles.mono}>{e.ip}</td>
        <td>{e.identity === "" ? "—" : e.identity}</td>
        <td className={styles.mono}>{e.method}</td>
        <td className={styles.hostCell}>{e.host}</td>
        <td>{statusBadge(e.status)}</td>
        <td className={styles.ruleCell}>
          {e.ruleMatched === "" ? "—" : e.ruleMatched}
        </td>
        <td className={styles.numeric}>
          {fmtBytes(e.bytesSent + e.bytesRecv)}
        </td>
        <td className={styles.numeric}>
          {e.durationMs > 0 ? `${String(e.durationMs)} ms` : "—"}
        </td>
      </tr>
      {open && (
        <tr className={styles.detailRow}>
          <td colSpan={10}>
            <RowDetail e={e} />
          </td>
        </tr>
      )}
    </>
  );
}
