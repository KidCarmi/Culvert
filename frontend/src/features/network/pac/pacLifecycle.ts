// 2F-E — the pure lifecycle decision helpers of the PAC surface: how a
// dispatch outcome is classified, how a decoded result is VERIFIED against
// the dispatched operation, and how an UNRESOLVED operation is resolved
// AUTHORITATIVELY from the lifecycle GET. No I/O, no React.
//
// Recovery truth (2F-B, C1/C8, corrected in the 2F-E correction round):
// the appliance persists the operation INTENT before the authoritative
// commit and records every decided operationId in the profile's decided
// ring. But the lifecycle GET LISTS only the 20 most recent decisions, the
// appliance RETAINS only `operationsCap` (64), a history reset EMPTIES the
// ring, and a request the appliance has not received yet is absent while
// it can still commit. Absence is therefore evidence of nothing on its
// own. The classifier below:
//   - takes the appliance's word when it has it — the `?operationId=`
//     lookup over the FULL retained ring, the decided ring, the revision
//     history (revisions carry the operationId that produced them), the
//     pending intent and the ambiguity record;
//   - declares NON-COMMIT only with authoritative evidence: the retained
//     ring is COMPLETE (nothing evicted), no reset touched it, the
//     operation is absent, AND the reviewed fence moved (the appliance can
//     no longer commit it — active revisions are monotonic);
//   - keeps everything else UNRESOLVED, naming why (not observed yet,
//     history bounded, history reset, history missing), so the operation
//     identity is retained and the operator resolves it deliberately
//     (re-send of the SAME operation, or a typed abandon).
// It never guesses from timestamps or artifact digests (§8.D13); "committed
// historically" (a history revision exists) is distinguished from
// "currently active" (that revision is activeN).
import type {
  PacLifecycle,
  PacOperationResult,
  PacOpState,
} from "../../../api/pac";
import {
  asPacAmbiguous,
  asPacChallenge,
  asPacFence,
  asPacHistoryReset,
  asPacIssues,
  asPacOperationPending,
  asPacServerOutcome,
} from "../../../api/pac";
import type {
  PacAmbiguousRefusal,
  PacChallenge,
  PacFenceRefusal,
  PacHistoryResetRefusal,
  PacIssuesRefusal,
  PacOperationPending,
  PacServerOutcome,
} from "../../../api/pac";
import { ApiError } from "../../../api/client";
import { serverErrorText } from "../../../shared/mutationOutcome";
import type { PacRecoveryMarker } from "./pacRecovery";

/** The lifecycle GET lists at most this many decided operations. */
export const PAC_OPERATIONS_SHOWN = 20;
/** Clock-skew tolerance when ordering a server-stamped history reset
 * against the browser-stamped dispatch: a reset that might have happened
 * after the dispatch counts as touching it (errs toward UNRESOLVED). */
export const PAC_RESET_SKEW_MS = 15 * 60 * 1000;

export type PacUnresolvedReason =
  "not_observed" | "history_bounded" | "history_reset" | "history_missing";

export type PacRecoveryResolution =
  | {
      kind: "landed";
      state: PacOpState;
      status: number;
      /** the candidate REACHED the active store (recorded/committed) */
      committed: boolean;
      /** the history revision the operation produced (0 when none) */
      revisionN: number;
      /** that revision is the one served right now (activeN) */
      currentlyActive: boolean;
    }
  | { kind: "pending" }
  | { kind: "ambiguous" }
  | { kind: "not_landed"; proof: "fence_moved" }
  | { kind: "unresolved"; reason: PacUnresolvedReason };

type Marker = Pick<
  PacRecoveryMarker,
  | "operationId"
  | "expectedActiveRevision"
  | "expectedActiveSpecDigest"
  | "startedAt"
>;

function landedFrom(
  lc: PacLifecycle,
  state: PacOpState,
  status: number,
  revisionN: number,
): PacRecoveryResolution {
  const committed = landedStateCommitted(state);
  return {
    kind: "landed",
    state,
    status,
    committed,
    revisionN: committed ? revisionN : 0,
    currentlyActive: committed && revisionN !== 0 && lc.activeN === revisionN,
  };
}

/** Did a history reset touch the window this operation could have been
 * decided in? Unacknowledged ⇒ yes; otherwise only when the reset is not
 * provably OLDER than the dispatch (skew-tolerant; unparseable ⇒ yes). */
function resetTouches(lc: PacLifecycle, marker: Marker): boolean {
  if (lc.historyState === "history_reset") return true;
  const reset = lc.historyReset;
  if (reset === undefined) return false;
  const at = Date.parse(reset.at);
  if (Number.isNaN(at)) return true;
  return at >= marker.startedAt - PAC_RESET_SKEW_MS;
}

/** classifyRecovery: total over the lifecycle GET (with or without the
 * `?operationId=` lookup). */
export function classifyRecovery(
  marker: Marker,
  lc: PacLifecycle,
): PacRecoveryResolution {
  const id = marker.operationId;
  const revision = lc.revisions.find((r) => r.operationId === id);
  const revisionN = revision?.n ?? 0;
  // 1. the appliance's own answer for THIS id (full retained ring)
  const lookup = lc.operation;
  if (lookup !== undefined && lookup.operationId === id && lookup.found) {
    return landedFrom(
      lc,
      lookup.state ?? "recorded",
      lookup.status ?? 200,
      lookup.revisionN !== 0 ? lookup.revisionN : revisionN,
    );
  }
  // 2. the listed decisions / the revision history
  const decided = lc.operations.find((o) => o.operationId === id);
  if (decided !== undefined)
    return landedFrom(lc, decided.state, decided.status, revisionN);
  if (revision !== undefined) return landedFrom(lc, "recorded", 200, revisionN);
  // 3. still on the appliance's books
  if (lc.pendingOp?.operationId === id) return { kind: "pending" };
  if (lc.ambiguous?.op.operationId === id) return { kind: "ambiguous" };
  // 4. absence — evidence only when the history is intact and complete
  if (resetTouches(lc, marker))
    return { kind: "unresolved", reason: "history_reset" };
  const retained = lc.operationsRetained ?? lc.operations.length;
  if (
    marker.expectedActiveRevision > 0 &&
    (!lc.activeExists ||
      (lc.activeN === 0 && lc.revisions.length === 0 && retained === 0))
  )
    return { kind: "unresolved", reason: "history_missing" };
  const complete =
    lookup !== undefined && lookup.operationId === id
      ? lc.operationsCap !== undefined && retained < lc.operationsCap
      : lc.operations.length < PAC_OPERATIONS_SHOWN;
  if (!complete) return { kind: "unresolved", reason: "history_bounded" };
  const baseMoved =
    lc.activeRevision !== marker.expectedActiveRevision ||
    lc.activeSpecDigest !== marker.expectedActiveSpecDigest;
  if (baseMoved) return { kind: "not_landed", proof: "fence_moved" };
  return { kind: "unresolved", reason: "not_observed" };
}

/** The decided operation states that mean the candidate REACHED the
 * active store (recorded/committed) vs never did (aborted). */
export function landedStateCommitted(state: PacOpState): boolean {
  return state === "committed" || state === "recorded";
}

/** Verify a DECODED 2xx result against the dispatched operation: it must
 * name the same operationId and carry the action's positive commit flag
 * (`published:true` / `rolledBack:true`). Anything else is NOT a proven
 * commit — the caller keeps the marker and resolves authoritatively. */
export type PacResultVerdict =
  | { ok: true; pendingReconciliation: boolean }
  | { ok: false; reason: "identity" | "no_commit_evidence" };

export function verifyOperationResult(
  res: PacOperationResult,
  dispatched: { operationId: string; action: "publish" | "rollback" },
): PacResultVerdict {
  if (res.operationId !== dispatched.operationId)
    return { ok: false, reason: "identity" };
  const committed =
    dispatched.action === "publish" ? res.published : res.rolledBack;
  if (!committed) return { ok: false, reason: "no_commit_evidence" };
  return {
    ok: true,
    pendingReconciliation: res.historyState === "pending_reconciliation",
  };
}

export type PacDispatchFailure =
  | { kind: "fence"; fence: PacFenceRefusal }
  | { kind: "challenge"; challenge: PacChallenge }
  | { kind: "history_reset"; reset: PacHistoryResetRefusal }
  | { kind: "operation_pending"; pending: PacOperationPending }
  | { kind: "ambiguous"; ambiguous: PacAmbiguousRefusal }
  | { kind: "server_outcome"; outcome: PacServerOutcome }
  | { kind: "issues"; issues: PacIssuesRefusal }
  | { kind: "unknown"; reason: "transport" | "undecodable" | "intermediary" }
  | { kind: "refused"; text: string };

/** Is this error one where NO authoritative decision reached the page? */
export function dispatchOutcomeUnresolved(
  err: unknown,
): PacDispatchFailure | null {
  if (!(err instanceof ApiError)) return null;
  switch (err.kind) {
    case "network":
    case "timeout":
    case "aborted":
      return { kind: "unknown", reason: "transport" };
    case "decode":
    case "contenttype":
      // a 2xx the page cannot read: the appliance may well have committed
      return { kind: "unknown", reason: "undecodable" };
    case "http":
      // a 5xx without a structured PAC decision is an intermediary or a
      // crashed handler — never a verdict
      if (err.status !== undefined && err.status >= 500)
        return { kind: "unknown", reason: "intermediary" };
      return null;
    default:
      return null;
  }
}

/** classifyDispatchFailure: every structured refusal the lifecycle endpoint
 * can answer, in the order the appliance decides them; transport death,
 * an undecodable 2xx and an unstructured 5xx are UNKNOWN (never a
 * confirmed failure); anything else is a bounded refusal. */
export function classifyDispatchFailure(err: unknown): PacDispatchFailure {
  const fence = asPacFence(err);
  if (fence !== null) return { kind: "fence", fence };
  const challenge = asPacChallenge(err);
  if (challenge !== null) return { kind: "challenge", challenge };
  const reset = asPacHistoryReset(err);
  if (reset !== null) return { kind: "history_reset", reset };
  const pending = asPacOperationPending(err);
  if (pending !== null) return { kind: "operation_pending", pending };
  const ambiguous = asPacAmbiguous(err);
  if (ambiguous !== null) return { kind: "ambiguous", ambiguous };
  const outcome = asPacServerOutcome(err);
  if (outcome !== null) return { kind: "server_outcome", outcome };
  const issues = asPacIssues(err);
  if (issues !== null) return { kind: "issues", issues };
  const unresolved = dispatchOutcomeUnresolved(err);
  if (unresolved !== null) return unresolved;
  return {
    kind: "refused",
    text: serverErrorText(err, "The appliance refused the request."),
  };
}

/** A failure that leaves an operation UNRESOLVED (no authoritative decision
 * reached the page, or the appliance itself reports outcome_unknown) — the
 * marker must be kept. */
export function failureKeepsMarker(f: PacDispatchFailure): boolean {
  return (
    f.kind === "unknown" ||
    (f.kind === "server_outcome" && f.outcome.code === "outcome_unknown")
  );
}

/** Short display form of a `sha256:…` digest. */
export function shortDigest(d: string): string {
  const body = d.startsWith("sha256:") ? d.slice(7) : d;
  return body.length > 12 ? `${body.slice(0, 12)}…` : body;
}
