// 2D-A — shared page state for the object-management surfaces (Category
// Groups, Decryption Profiles): the manual snapshot query (ADR-FE-002 — no
// polling), the single active mutation request owner, the page-level STATE
// UNKNOWN latch (2A-M doctrine: an unconfirmed mutation blocks every further
// mutation until a FRESH successful refetch), and the auth-boundary cleanup
// registration. Mirrors useAuthPolicyWrites; no cross-page global stores.
import { useEffect, useRef, useState } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { useSnapshot } from "../../shared/snapshot";
import { createRequestRunOwner } from "../../shared/runOwner";
import type { RequestRunOwner } from "../../shared/runOwner";
import { registerAuthCleanup } from "../../auth/teardown";

export type ObjectUnknownOp = "create" | "edit" | "rename" | "delete";

export interface ObjectPageState<T> {
  q: UseQueryResult<T>;
  owner: RequestRunOwner;
  unknown: ObjectUnknownOp | null;
  latchUnknown: (op: ObjectUnknownOp) => void;
  /** resolves the latch ONLY when the refetch genuinely succeeded with an
   * advanced success stamp (2A-M correction). */
  refreshToResolve: () => void;
  setBoundaryCleanup: (fn: () => void) => void;
}

export function useObjectPage<T>(
  key: readonly string[],
  fetcher: (signal: AbortSignal) => Promise<T>,
): ObjectPageState<T> {
  const q = useSnapshot(key, fetcher);
  const ownerRef = useRef(createRequestRunOwner());
  const [unknown, setUnknown] = useState<ObjectUnknownOp | null>(null);
  const extraCleanup = useRef<() => void>(() => undefined);

  useEffect(() => {
    const owner = ownerRef.current;
    const runCleanups = (): void => {
      owner.abort();
      extraCleanup.current();
      setUnknown(null);
    };
    const unregister = registerAuthCleanup(runCleanups);
    return () => {
      unregister();
      runCleanups();
    };
  }, []);

  const refreshToResolve = (): void => {
    const before = q.dataUpdatedAt;
    void q.refetch().then((res) => {
      if (res.isSuccess && res.dataUpdatedAt > before) setUnknown(null);
    });
  };

  return {
    q,
    owner: ownerRef.current,
    unknown,
    latchUnknown: (op) => {
      setUnknown(op);
    },
    refreshToResolve,
    setBoundaryCleanup: (fn) => {
      extraCleanup.current = fn;
    },
  };
}
