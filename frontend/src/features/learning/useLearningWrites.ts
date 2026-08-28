// 2C.4 — the Policy Learning WRITE controller: snapshots for status, config,
// sessions, and recommendations (ADR-FE-002 — snapshot + explicit refresh,
// no polling), a single mutation owner, and the page-level unknown latch
// (2A-M doctrine): an unconfirmed mutation blocks every further learning
// mutation until a FRESH successful refetch of ALL FOUR surfaces — which is
// also the §34 rule that an unconfirmed Accept is never blindly repeated:
// resolution goes through fresh recommendation + draft-arming truth first.
import { useEffect, useRef, useState } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { useSnapshot } from "../../shared/snapshot";
import {
  getLearningConfig,
  getLearningRecommendations,
  getLearningSessions,
  getLearningStatus,
} from "../../api/policyLearning";
import type {
  LearningConfig,
  LearningStatus,
  RecommendationList,
  SessionList,
} from "../../api/policyLearning";
import { createRequestRunOwner } from "../../shared/runOwner";
import type { RequestRunOwner } from "../../shared/runOwner";
import { registerAuthCleanup } from "../../auth/teardown";

export type LearningUnknownOp =
  | "config change"
  | "session start"
  | "session complete"
  | "session cancel"
  | "generate"
  | "accept"
  | "reject";

export interface LearningWrites {
  statusQ: UseQueryResult<LearningStatus>;
  configQ: UseQueryResult<LearningConfig>;
  sessionsQ: UseQueryResult<SessionList>;
  recsQ: UseQueryResult<RecommendationList>;
  owner: RequestRunOwner;
  unknown: LearningUnknownOp | null;
  latchUnknown: (op: LearningUnknownOp) => void;
  refreshToResolve: () => void;
  refetchAll: () => void;
  setBoundaryCleanup: (fn: () => void) => void;
}

export function useLearningWrites(): LearningWrites {
  const statusQ = useSnapshot(["learning", "status"], (signal) =>
    getLearningStatus(signal),
  );
  const configQ = useSnapshot(["learning", "config"], (signal) =>
    getLearningConfig(signal),
  );
  const sessionsQ = useSnapshot(["learning", "sessions"], (signal) =>
    getLearningSessions(signal),
  );
  const recsQ = useSnapshot(["learning", "recommendations"], (signal) =>
    getLearningRecommendations(signal),
  );
  const ownerRef = useRef(createRequestRunOwner());
  const [unknown, setUnknown] = useState<LearningUnknownOp | null>(null);
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
    const before = [
      statusQ.dataUpdatedAt,
      configQ.dataUpdatedAt,
      sessionsQ.dataUpdatedAt,
      recsQ.dataUpdatedAt,
    ];
    void Promise.all([
      statusQ.refetch(),
      configQ.refetch(),
      sessionsQ.refetch(),
      recsQ.refetch(),
    ]).then((results) => {
      const allFresh = results.every(
        (res, i) => res.isSuccess && res.dataUpdatedAt > (before[i] ?? 0),
      );
      if (allFresh) setUnknown(null);
    });
  };

  return {
    statusQ,
    configQ,
    sessionsQ,
    recsQ,
    owner: ownerRef.current,
    unknown,
    latchUnknown: (op) => {
      setUnknown(op);
    },
    refreshToResolve,
    refetchAll: () => {
      void statusQ.refetch();
      void configQ.refetch();
      void sessionsQ.refetch();
      void recsQ.refetch();
    },
    setBoundaryCleanup: (fn) => {
      extraCleanup.current = fn;
    },
  };
}
