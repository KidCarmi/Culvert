// FE-4 snapshot-freshness infrastructure (ADR-FE-002 §17). One hook + one
// bar implement the freshness contract for every operational surface:
//   loading → fresh snapshot → refreshing (old snapshot visible) →
//   error-with-previous-snapshot → error-with-no-snapshot → empty.
// "Updated" advances ONLY on a successful response (TanStack dataUpdatedAt);
// a failed refresh keeps the previous snapshot on screen behind an explicit
// stale indicator and never fakes freshness. Manual Refresh is the default —
// no polling, no window-focus refetch, no reconnect refetch (query profile).
import type { JSX } from "react";
import { useQuery } from "@tanstack/react-query";
import type { UseQueryResult } from "@tanstack/react-query";
import { Button, StatusBadge } from "../design-system/primitives";
import styles from "./snapshot.module.css";

export function useSnapshot<T>(
  key: readonly unknown[],
  fetcher: () => Promise<T>,
): UseQueryResult<T> {
  return useQuery({
    queryKey: key,
    queryFn: fetcher,
    // Snapshots never refetch on their own; Refresh is the operator's action.
    staleTime: Infinity,
    retry: false,
  });
}

function clock(ms: number): string {
  const d = new Date(ms);
  const p = (n: number): string => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export function SnapshotBar({
  updatedAt,
  fetching,
  error,
  hasData,
  onRefresh,
}: {
  /** dataUpdatedAt of the LAST SUCCESSFUL response (0 = never) */
  updatedAt: number;
  fetching: boolean;
  error: boolean;
  hasData: boolean;
  onRefresh: () => void;
}): JSX.Element {
  return (
    <div className={styles.bar}>
      {updatedAt > 0 && (
        <span className={styles.updated} aria-live="polite">
          Updated {clock(updatedAt)}
        </span>
      )}
      {fetching && hasData && (
        <StatusBadge status="info">Refreshing…</StatusBadge>
      )}
      {error && hasData && (
        <StatusBadge status="warn">
          Refresh failed — showing previous snapshot
        </StatusBadge>
      )}
      <Button size="sm" onClick={onRefresh} disabled={fetching}>
        Refresh
      </Button>
    </div>
  );
}
