// 2F-E — the pure lifecycle decision helpers of the PAC surface: how a
// dispatch outcome is classified, how a decoded result is VERIFIED against
// the dispatched operation, and how an UNRESOLVED operation is resolved
// AUTHORITATIVELY from the lifecycle GET. No I/O, no React.
//
// Recovery truth (2F-B, C1/C8; corrected in the 2F-E correction rounds 1–2):
// the appliance persists the operation INTENT before the authoritative
// commit and records every decided operationId in the profile's decided
// ring. But the lifecycle GET LISTS only the 20 most recent decisions, the
// appliance RETAINS only `operationsCap` (64), a history reset EMPTIES the
// ring, a profile DELETE discards it (and a recreate under the same id
// restarts revision numbers at 1), and a request the appliance has not
// received yet is absent while it can still commit. Absence is therefore
// evidence of nothing on its own. The classifier below:
//   - takes the appliance's word when it has it — the `?operationId=`
//     lookup over the FULL retained ring, the decided ring, the revision
//     history (revisions carry the operationId that produced them), the
//     pending intent and the ambiguity record;
//   - requires HISTORY CONTINUITY before reading anything into absence
//     (round 2): the appliance's durable history-epoch identity
//     (`historyIncarnation`) must be the one the operation was dispatched
//     in — it rotates on delete/recreate and on a reset, so a different
//     epoch (or an unknown one) means the decision record may simply be
//     gone. Never a clock comparison, never a revision-number comparison:
//     clocks skew and revision numbers restart;
//   - declares NON-COMMIT only with authoritative evidence: same epoch, no
//     unacknowledged reset, the retained ring COMPLETE (nothing evicted),
//     the operation absent, AND the reviewed fence moved (the appliance can
//     no longer commit it — active revisions are monotonic within an epoch);
//   - keeps everything else UNRESOLVED, naming why (not observed yet,
//     history bounded, history reset, history missing, history
//     discontinuity), so the operation identity is retained and the
//     operator resolves it deliberately (re-send of the SAME operation —
//     only within the same epoch — or a typed abandon);
//   - distinguishes "committed historically" (a history revision exists)
//     from "currently active" by the COMMITTED IDENTITY (the spec digest +
//     store revision the commit produced) against the AUTHORITATIVE active
//     store (activeSpecDigest / activeRevision) — never by the history
//     pointer `activeN` alone, which a direct profile PUT does not move.
// It never guesses from timestamps or artifact digests (§8.D13).
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

export type PacUnresolvedReason =
  | "not_observed"
  | "history_bounded"
  | "history_reset"
  | "history_missing"
  | "history_discontinuity";

export type PacRecoveryResolution =
  | {
      kind: "landed";
      state: PacOpState;
      status: number;
      /** the candidate REACHED the active store (recorded/committed) */
      committed: boolean;
      /** the history revision the operation produced (0 when none) */
      revisionN: number;
      /** the authoritative active store still serves exactly what this
       * commit produced (its spec digest AND store revision) */
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
  | "historyIncarnation"
>;

/** The COMMITTED identity of a history revision: what its commit put into
 * the authoritative active store. */
interface CommittedIdentity {
  specDigest: string;
  storeRevision: number;
}

/** Is the committed revision `revisionN` (identity `id`) what the active
 * store serves RIGHT NOW? The spec digest must match the authoritative
 * active digest; the store revision must match the authoritative active
 * revision (a direct profile PUT re-saving an IDENTICAL spec still moves
 * it). A revision recorded before the store revision existed (0) falls back
 * to the history pointer for the revision half only. */
function currentlyActiveFrom(
  lc: PacLifecycle,
  revisionN: number,
  id: CommittedIdentity,
): boolean {
  if (revisionN === 0 || !lc.activeExists) return false;
  if (id.specDigest === "" || lc.activeSpecDigest !== id.specDigest)
    return false;
  return id.storeRevision !== 0
    ? lc.activeRevision === id.storeRevision
    : lc.activeN === revisionN;
}

function landedFrom(
  lc: PacLifecycle,
  state: PacOpState,
  status: number,
  revisionN: number,
  id: CommittedIdentity,
): PacRecoveryResolution {
  const committed = landedStateCommitted(state);
  return {
    kind: "landed",
    state,
    status,
    committed,
    revisionN: committed ? revisionN : 0,
    currentlyActive: committed && currentlyActiveFrom(lc, revisionN, id),
  };
}

/** Does the appliance's history still have CONTINUITY with the epoch the
 * operation was dispatched in? Only an exact, known identity on both sides
 * does — an unknown epoch on either side proves nothing. */
export function historyContinuous(marker: Marker, lc: PacLifecycle): boolean {
  return (
    marker.historyIncarnation !== "" &&
    lc.historyIncarnation !== undefined &&
    lc.historyIncarnation !== "" &&
    lc.historyIncarnation === marker.historyIncarnation
  );
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
  const revisionIdentity: CommittedIdentity = {
    specDigest: revision?.specDigest ?? "",
    storeRevision: revision?.storeRevision ?? 0,
  };
  // 1. the appliance's own answer for THIS id (full retained ring)
  const lookup = lc.operation;
  if (lookup !== undefined && lookup.operationId === id && lookup.found) {
    const identity: CommittedIdentity =
      lookup.specDigest !== ""
        ? { specDigest: lookup.specDigest, storeRevision: lookup.storeRevision }
        : revisionIdentity;
    return landedFrom(
      lc,
      lookup.state ?? "recorded",
      lookup.status ?? 200,
      lookup.revisionN !== 0 ? lookup.revisionN : revisionN,
      identity,
    );
  }
  // 2. the listed decisions / the revision history
  const decided = lc.operations.find((o) => o.operationId === id);
  if (decided !== undefined)
    return landedFrom(
      lc,
      decided.state,
      decided.status,
      revisionN,
      revisionIdentity,
    );
  if (revision !== undefined)
    return landedFrom(lc, "recorded", 200, revisionN, revisionIdentity);
  // 3. still on the appliance's books
  if (lc.pendingOp?.operationId === id) return { kind: "pending" };
  if (lc.ambiguous?.op.operationId === id) return { kind: "ambiguous" };
  // 4. absence — evidence only when the history is CONTINUOUS, intact and
  //    complete
  if (lc.historyState === "history_reset")
    return { kind: "unresolved", reason: "history_reset" };
  if (!historyContinuous(marker, lc)) {
    // no history at all for this profile any more (deleted, never recreated)
    if (!lc.activeExists && (lc.historyIncarnation ?? "") === "")
      return { kind: "unresolved", reason: "history_missing" };
    return { kind: "unresolved", reason: "history_discontinuity" };
  }
  const retained = lc.operationsRetained ?? lc.operations.length;
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

/** Why a re-send of the SAME operation is not replay-safe against this
 * lifecycle (null when it is): the appliance decides an operationId at most
 * once ONLY within one history epoch — in another epoch the decision record
 * is gone and the operation would run AGAIN. */
export function resendContinuityRefusal(
  marker: Marker,
  lc: PacLifecycle,
): string | null {
  if (lc.historyState === "history_reset")
    return "the node-local history was reset — acknowledge it first";
  if (marker.historyIncarnation === "")
    return "the history epoch this operation was dispatched in is unknown (a marker from an earlier build); at-most-once cannot be established";
  if (lc.historyIncarnation === undefined || lc.historyIncarnation === "")
    return "the appliance reports no history epoch identity; at-most-once cannot be established";
  if (lc.historyIncarnation !== marker.historyIncarnation)
    return "the appliance's history epoch changed since the dispatch (the profile was deleted and recreated, or its history was reset); the operation would run again as a new one";
  return null;
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
