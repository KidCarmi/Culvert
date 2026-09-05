// 2F-E — the durable PAC lifecycle recovery marker.
//
// A publish or rollback is a non-idempotent commit against the authoritative
// profile store, bound to a client-minted UUID operationId the appliance
// decides AT MOST ONCE (a retry with the same id replays the recorded
// decision byte-for-byte; the lifecycle GET lists every decided id). When
// the RESPONSE is lost, the only honest posture is UNKNOWN: this module
// keeps the operation identity — and the tokens the candidate was reviewed
// against — so the operator can RESOLVE the outcome authoritatively from
// the lifecycle GET instead of guessing or re-dispatching.
//
// Storage: sessionStorage (per-tab; survives reload; dies with the tab —
// the established session lifecycle, same as the 2E-B rotation and the
// 2E-C enrollment markers). Contents are strictly NON-SECRET: {version,
// operationId, action, profileId, expectedActiveRevision,
// expectedActiveSpecDigest, candidateSpecDigest, targetN, startedAt,
// subject}. NEVER a draft body, NEVER a challenge token (pinned by
// pac-2fe-red.test.ts).
//
// Lifecycle rules (load-bearing):
//  - WRITE happens BEFORE the network dispatch and is VERIFIED by read-back;
//    NO DURABLE MARKER ⇒ NO DISPATCH.
//  - CLEAR happens only on a terminal outcome: a confirmed response, an
//    authoritative refusal (the appliance answered — nothing pending), a
//    proven LANDED / NOT-LANDED resolution, the explicit typed abandon
//    ceremony, or an authentication boundary. NEVER on component unmount.
//  - READ is subject-bound: a marker written under a different authenticated
//    identity is discarded, never inherited.
import { isRecord } from "../../../api/decode";
import { isPacOperationId } from "../../../api/pac";
import { registerAuthCleanup } from "../../../auth/teardown";

/** The storage contract key — pinned literally by the lifecycle tests. */
export const PAC_RECOVERY_KEY = "culvert.pac.lifecycle-recovery.v1";

export type PacRecoveryAction = "publish" | "rollback";

export interface PacRecoveryMarker {
  operationId: string;
  action: PacRecoveryAction;
  profileId: string;
  expectedActiveRevision: number;
  expectedActiveSpecDigest: string;
  candidateSpecDigest: string;
  targetN: number;
  startedAt: number;
}

export type PacRecoveryRead =
  | { kind: "none" }
  | { kind: "valid"; marker: PacRecoveryMarker }
  | { kind: "unavailable" }
  | { kind: "unreadable" };

function grammarValid(m: PacRecoveryMarker, subject: string): boolean {
  return (
    isPacOperationId(m.operationId) &&
    (m.action === "publish" || m.action === "rollback") &&
    m.profileId.trim() !== "" &&
    Number.isFinite(m.expectedActiveRevision) &&
    Number.isFinite(m.targetN) &&
    Number.isFinite(m.startedAt) &&
    subject.trim() !== ""
  );
}

function sameMarker(a: PacRecoveryMarker, b: PacRecoveryMarker): boolean {
  return (
    a.operationId === b.operationId &&
    a.action === b.action &&
    a.profileId === b.profileId &&
    a.expectedActiveRevision === b.expectedActiveRevision &&
    a.expectedActiveSpecDigest === b.expectedActiveSpecDigest &&
    a.candidateSpecDigest === b.candidateSpecDigest &&
    a.targetN === b.targetN &&
    a.startedAt === b.startedAt
  );
}

/** Persist + VERIFY the marker for one about-to-be-dispatched operation.
 * Called BEFORE the network dispatch; false ⇒ the caller must NOT send. */
export function writePacRecovery(
  subject: string,
  m: PacRecoveryMarker,
): boolean {
  if (!grammarValid(m, subject)) return false;
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2F-E lifecycle recovery): the single NON-SECRET PAC operation-identity marker; field allowlist pinned by pac-2fe-red.test.ts.
    sessionStorage.setItem(
      PAC_RECOVERY_KEY,
      JSON.stringify({
        version: 1,
        operationId: m.operationId,
        action: m.action,
        profileId: m.profileId,
        expectedActiveRevision: m.expectedActiveRevision,
        expectedActiveSpecDigest: m.expectedActiveSpecDigest,
        candidateSpecDigest: m.candidateSpecDigest,
        targetN: m.targetN,
        startedAt: m.startedAt,
        subject,
      }),
    );
    // The read-back must match EVERY written field — a lying or corrupting
    // storage must fail the write, not the recovery that depends on it.
    const back = readPacRecovery(subject);
    return back.kind === "valid" && sameMarker(back.marker, m);
  } catch {
    return false;
  }
}

/** Inspect the recovery store for the CURRENT subject — TYPED: "cannot
 * read" and "cannot interpret" are NOT "absent". A well-formed marker bound
 * to a DIFFERENT subject is discarded (never inherited) and reads "none". */
export function readPacRecovery(subject: string): PacRecoveryRead {
  let raw: string | null;
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2F-E lifecycle recovery): the single NON-SECRET PAC operation-identity marker; field allowlist pinned by pac-2fe-red.test.ts.
    raw = sessionStorage.getItem(PAC_RECOVERY_KEY);
  } catch {
    return { kind: "unavailable" };
  }
  if (raw === null) return { kind: "none" };
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return { kind: "unreadable" };
  }
  if (
    !isRecord(v) ||
    v["version"] !== 1 ||
    typeof v["operationId"] !== "string" ||
    (v["action"] !== "publish" && v["action"] !== "rollback") ||
    typeof v["profileId"] !== "string" ||
    typeof v["expectedActiveRevision"] !== "number" ||
    typeof v["expectedActiveSpecDigest"] !== "string" ||
    typeof v["candidateSpecDigest"] !== "string" ||
    typeof v["targetN"] !== "number" ||
    typeof v["startedAt"] !== "number" ||
    typeof v["subject"] !== "string"
  ) {
    return { kind: "unreadable" };
  }
  const marker: PacRecoveryMarker = {
    operationId: v["operationId"],
    action: v["action"],
    profileId: v["profileId"],
    expectedActiveRevision: v["expectedActiveRevision"],
    expectedActiveSpecDigest: v["expectedActiveSpecDigest"],
    candidateSpecDigest: v["candidateSpecDigest"],
    targetN: v["targetN"],
    startedAt: v["startedAt"],
  };
  if (!grammarValid(marker, v["subject"])) return { kind: "unreadable" };
  if (v["subject"] !== subject) {
    try {
      // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2F-E lifecycle recovery): the single NON-SECRET PAC operation-identity marker; field allowlist pinned by pac-2fe-red.test.ts.
      sessionStorage.removeItem(PAC_RECOVERY_KEY);
    } catch {
      // the foreign marker cannot be ours either way
    }
    return { kind: "none" };
  }
  return { kind: "valid", marker };
}

/** Terminal clear — confirmed outcome, authoritative refusal, proven
 * resolution, or the explicit abandon ceremony. */
export function clearPacRecovery(): void {
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2F-E lifecycle recovery): the single NON-SECRET PAC operation-identity marker; field allowlist pinned by pac-2fe-red.test.ts.
    sessionStorage.removeItem(PAC_RECOVERY_KEY);
  } catch {
    // nothing to clear if storage is unavailable
  }
}

// Auth-boundary rule: logout / session expiry / identity change clears the
// marker (module-level registration — NOT tied to any component unmount).
registerAuthCleanup(() => {
  clearPacRecovery();
});
