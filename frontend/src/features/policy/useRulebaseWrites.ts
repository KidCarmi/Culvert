// 2B.2 — the Access Rules WRITE controller: one hook owning the policy +
// draft snapshots, the single active policy-mutation request owner (§26),
// and the page-level STATE UNKNOWN latch (2A-M doctrine transposed to the
// rulebase: an unconfirmed mutation blocks every further mutation until a
// FRESH successful refetch of BOTH /api/policy and /api/policy/draft).
import { useEffect, useRef, useState } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { useSnapshot } from "../../shared/snapshot";
import { getPolicy } from "../../api/policy";
import type { PolicySnapshot } from "../../api/policy";
import { getDraftState } from "../../api/policyDraft";
import type { DraftState } from "../../api/policyDraft";
import { createRequestRunOwner } from "../../shared/runOwner";
import type { RequestRunOwner } from "../../shared/runOwner";
import { registerAuthCleanup } from "../../auth/teardown";

export type UnknownOp =
  | "create"
  | "edit"
  | "delete"
  | "reorder"
  | "commit mode change"
  | "commit"
  | "revert";

export interface RulebaseWrites {
  policyQ: UseQueryResult<PolicySnapshot>;
  draftQ: UseQueryResult<DraftState>;
  /** the single active policy-mutation owner for this surface */
  owner: RequestRunOwner;
  /** non-null ⇒ a mutation's outcome is unconfirmed; all writes are blocked */
  unknown: UnknownOp | null;
  latchUnknown: (op: UnknownOp) => void;
  /** refetch policy + draft; resolves the latch ONLY when BOTH refetches
   * genuinely succeeded with an advanced success stamp (2A-M correction). */
  refreshToResolve: () => void;
  /** refetch both snapshots after a CONFIRMED mutation (no latch involved) */
  refetchAll: () => void;
  /** installs THE page cleanup run at the auth boundary / unmount (single
   * slot — call every render with the latest closure) */
  setBoundaryCleanup: (fn: () => void) => void;
}

export function useRulebaseWrites(): RulebaseWrites {
  const policyQ = useSnapshot(["policy", "snapshot"], (signal) =>
    getPolicy(signal),
  );
  const draftQ = useSnapshot(["policy", "draft"], (signal) =>
    getDraftState(signal),
  );
  const ownerRef = useRef(createRequestRunOwner());
  const [unknown, setUnknown] = useState<UnknownOp | null>(null);
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
    // Both surfaces must confirm fresh server truth: `data` presence is NOT
    // proof (a failed refetch keeps the previous snapshot; a cancelled one
    // reverts to the pre-refetch success state), so require SUCCESS and an
    // ADVANCED success stamp on each query independently.
    const beforePolicy = policyQ.dataUpdatedAt;
    const beforeDraft = draftQ.dataUpdatedAt;
    void Promise.all([policyQ.refetch(), draftQ.refetch()]).then(
      ([pRes, dRes]) => {
        const policyFresh = pRes.isSuccess && pRes.dataUpdatedAt > beforePolicy;
        const draftFresh = dRes.isSuccess && dRes.dataUpdatedAt > beforeDraft;
        if (policyFresh && draftFresh) setUnknown(null);
      },
    );
  };

  return {
    policyQ,
    draftQ,
    owner: ownerRef.current,
    unknown,
    latchUnknown: (op) => {
      setUnknown(op);
    },
    refreshToResolve,
    refetchAll: () => {
      void policyQ.refetch();
      void draftQ.refetch();
    },
    setBoundaryCleanup: (fn) => {
      extraCleanup.current = fn;
    },
  };
}
