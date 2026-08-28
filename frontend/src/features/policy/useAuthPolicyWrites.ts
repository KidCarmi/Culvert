// 2C.2 — the Authentication Rules WRITE controller: one hook owning the
// auth-policy snapshot (RUNNING domain), the draft-state snapshot (for the §9
// pre-save warning — an auth mutation stales an active Access-Policy Draft's
// baseline), the single active mutation request owner, and the page-level
// STATE UNKNOWN latch (2A-M doctrine: an unconfirmed mutation blocks every
// further mutation until a FRESH successful refetch of BOTH surfaces).
import { useEffect, useRef, useState } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { useSnapshot } from "../../shared/snapshot";
import { getAuthPolicy, getIdPProviders } from "../../api/policyAuth";
import type { AuthPolicySnapshot, IdPProviderList } from "../../api/policyAuth";
import { getDraftState } from "../../api/policyDraft";
import type { DraftState } from "../../api/policyDraft";
import { createRequestRunOwner } from "../../shared/runOwner";
import type { RequestRunOwner } from "../../shared/runOwner";
import { registerAuthCleanup } from "../../auth/teardown";

export type AuthUnknownOp =
  "create" | "edit" | "delete" | "reorder" | "default outcome change";

export interface AuthPolicyWrites {
  authQ: UseQueryResult<AuthPolicySnapshot>;
  draftQ: UseQueryResult<DraftState>;
  providersQ: UseQueryResult<IdPProviderList>;
  owner: RequestRunOwner;
  unknown: AuthUnknownOp | null;
  latchUnknown: (op: AuthUnknownOp) => void;
  /** resolves the latch ONLY when both auth + draft refetches genuinely
   * succeeded with advanced success stamps (2A-M correction). */
  refreshToResolve: () => void;
  refetchAll: () => void;
  setBoundaryCleanup: (fn: () => void) => void;
}

export function useAuthPolicyWrites(): AuthPolicyWrites {
  const authQ = useSnapshot(["authpolicy", "snapshot"], (signal) =>
    getAuthPolicy(signal),
  );
  const draftQ = useSnapshot(["policy", "draft"], (signal) =>
    getDraftState(signal),
  );
  const providersQ = useSnapshot(["idp", "providers"], (signal) =>
    getIdPProviders(signal),
  );
  const ownerRef = useRef(createRequestRunOwner());
  const [unknown, setUnknown] = useState<AuthUnknownOp | null>(null);
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
    const beforeAuth = authQ.dataUpdatedAt;
    const beforeDraft = draftQ.dataUpdatedAt;
    void Promise.all([authQ.refetch(), draftQ.refetch()]).then(
      ([aRes, dRes]) => {
        const authFresh = aRes.isSuccess && aRes.dataUpdatedAt > beforeAuth;
        const draftFresh = dRes.isSuccess && dRes.dataUpdatedAt > beforeDraft;
        if (authFresh && draftFresh) setUnknown(null);
      },
    );
  };

  return {
    authQ,
    draftQ,
    providersQ,
    owner: ownerRef.current,
    unknown,
    latchUnknown: (op) => {
      setUnknown(op);
    },
    refreshToResolve,
    refetchAll: () => {
      void authQ.refetch();
      void draftQ.refetch();
      void providersQ.refetch();
    },
    setBoundaryCleanup: (fn) => {
      extraCleanup.current = fn;
    },
  };
}
