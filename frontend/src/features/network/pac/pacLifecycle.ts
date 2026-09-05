// 2F-E — the pure lifecycle decision helpers of the PAC surface: how a
// dispatch outcome is classified, and how an UNRESOLVED operation is
// resolved AUTHORITATIVELY from the lifecycle GET. No I/O, no React.
//
// Recovery truth (2F-B, C1/C8): the appliance persists the operation
// INTENT before the authoritative commit and records every decided
// operationId in the profile's decided ring (listed by the lifecycle GET),
// so an id that is absent from the ring, the pending op and the ambiguity
// record was NEVER committed — the store cannot change without an intent.
// The classifier therefore never guesses from timestamps or artifact
// digests (§8.D13): only identity and the (activeRevision, specDigest)
// pair the candidate was reviewed against decide.
import type { PacLifecycle, PacOpState } from "../../../api/pac";
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
import {
  unknownOutcome,
  serverErrorText,
} from "../../../shared/mutationOutcome";
import type { PacRecoveryMarker } from "./pacRecovery";

export type PacRecoveryResolution =
  | { kind: "landed"; state: PacOpState; status: number }
  | { kind: "pending" }
  | { kind: "ambiguous" }
  | { kind: "not_landed"; baseMoved: boolean };

/** classifyRecovery: total over the lifecycle GET. */
export function classifyRecovery(
  marker: Pick<
    PacRecoveryMarker,
    "operationId" | "expectedActiveRevision" | "expectedActiveSpecDigest"
  >,
  lc: PacLifecycle,
): PacRecoveryResolution {
  const decided = lc.operations.find(
    (o) => o.operationId === marker.operationId,
  );
  if (decided !== undefined) {
    return { kind: "landed", state: decided.state, status: decided.status };
  }
  if (lc.pendingOp?.operationId === marker.operationId)
    return { kind: "pending" };
  if (lc.ambiguous?.op.operationId === marker.operationId)
    return { kind: "ambiguous" };
  const baseMoved =
    lc.activeRevision !== marker.expectedActiveRevision ||
    lc.activeSpecDigest !== marker.expectedActiveSpecDigest;
  return { kind: "not_landed", baseMoved };
}

/** The decided operation states that mean the candidate REACHED the
 * active store (recorded/committed) vs never did (aborted). */
export function landedStateCommitted(state: PacOpState): boolean {
  return state === "committed" || state === "recorded";
}

export type PacDispatchFailure =
  | { kind: "fence"; fence: PacFenceRefusal }
  | { kind: "challenge"; challenge: PacChallenge }
  | { kind: "history_reset"; reset: PacHistoryResetRefusal }
  | { kind: "operation_pending"; pending: PacOperationPending }
  | { kind: "ambiguous"; ambiguous: PacAmbiguousRefusal }
  | { kind: "server_outcome"; outcome: PacServerOutcome }
  | { kind: "issues"; issues: PacIssuesRefusal }
  | { kind: "unknown" }
  | { kind: "refused"; text: string };

/** classifyDispatchFailure: every structured refusal the lifecycle endpoint
 * can answer, in the order the appliance decides them; transport death is
 * UNKNOWN (never a confirmed failure); anything else is a bounded refusal. */
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
  if (unknownOutcome(err)) return { kind: "unknown" };
  return {
    kind: "refused",
    text: serverErrorText(err, "The appliance refused the request."),
  };
}

/** A server outcome that leaves an operation UNRESOLVED on the appliance
 * side (intent retained, reconciled later) — the marker must be kept. */
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
