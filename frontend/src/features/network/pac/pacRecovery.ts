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
// collectionEtag, historyIncarnation, subject}. NEVER a draft body, NEVER a
// challenge token (pinned by pac-2fe-red.test.ts).
//
// Version 2 (2F-E correction round 2) adds the two CONTINUITY bindings: the
// collection fence the candidate was reviewed against and the identity of
// the appliance's history EPOCH it was reviewed in (the lifecycle GET's
// historyIncarnation). A version-1 marker still reads (it names a real
// unresolved operation) with both empty — an unknown epoch, which the
// classifier never resolves to "not landed" and the page never re-sends.
//
// Lifecycle rules (load-bearing):
//  - WRITE happens BEFORE the network dispatch and is VERIFIED by read-back;
//    NO DURABLE MARKER ⇒ NO DISPATCH.
//  - ONE outstanding operation across the whole PAC surface (2F-E correction
//    finding 2): a write NEVER overwrites a marker of a different operation,
//    and NEVER succeeds over storage that cannot be read (unreadable /
//    unavailable) — an unreadable marker may be somebody's unresolved
//    operation. Only the same operation may be re-persisted (a re-send),
//    and ONLY with IDENTICAL bindings (round 2): a marker's operation
//    identity, candidate digest, fences, epoch and dispatch time are
//    immutable evidence about the earlier attempt; a later attempt under
//    the same operationId can never rebind or restamp them.
//  - CLEAR is OWNERSHIP-MATCHED: it removes the marker only when it carries
//    the operation the caller resolved, so a late completion of one
//    operation can never erase another's marker. It happens only on a
//    terminal outcome: a VERIFIED response, an authoritative refusal, a
//    proven LANDED / NOT-LANDED resolution, the explicit typed abandon
//    ceremony (also ownership-matched), or an authentication boundary (the
//    one unconditional purge). NEVER on component unmount.
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
  /** the collection fence reviewed (the first-publish fence) */
  collectionEtag: string;
  /** the history epoch the candidate was reviewed in ("" = unknown) */
  historyIncarnation: string;
}

/** The persisted marker version this build writes. */
export const PAC_RECOVERY_VERSION = 2;

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
    a.startedAt === b.startedAt &&
    a.collectionEtag === b.collectionEtag &&
    a.historyIncarnation === b.historyIncarnation
  );
}

/** Persist + VERIFY the marker for one about-to-be-dispatched operation.
 * Called BEFORE the network dispatch; false ⇒ the caller must NOT send. */
export function writePacRecovery(
  subject: string,
  m: PacRecoveryMarker,
): boolean {
  if (!grammarValid(m, subject)) return false;
  // Single outstanding operation: refuse over a different operation's
  // marker and over any store that cannot be read.
  const existing = readPacRecovery(subject);
  if (existing.kind === "unavailable" || existing.kind === "unreadable")
    return false;
  if (existing.kind === "valid") {
    if (existing.marker.operationId !== m.operationId) return false;
    // Same operation: its bindings are immutable evidence of the earlier
    // attempt — an identical re-persist is a no-op, anything else is refused.
    return sameMarker(existing.marker, m);
  }
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2F-E lifecycle recovery): the single NON-SECRET PAC operation-identity marker; field allowlist pinned by pac-2fe-red.test.ts.
    sessionStorage.setItem(
      PAC_RECOVERY_KEY,
      JSON.stringify({
        version: PAC_RECOVERY_VERSION,
        operationId: m.operationId,
        action: m.action,
        profileId: m.profileId,
        expectedActiveRevision: m.expectedActiveRevision,
        expectedActiveSpecDigest: m.expectedActiveSpecDigest,
        candidateSpecDigest: m.candidateSpecDigest,
        targetN: m.targetN,
        startedAt: m.startedAt,
        collectionEtag: m.collectionEtag,
        historyIncarnation: m.historyIncarnation,
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
  // No authenticated identity yet (the auth state is still hydrating):
  // nothing may be read, and above all nothing may be DISCARDED as
  // "foreign" — the marker must survive a reload. Fail closed.
  if (subject.trim() === "") return { kind: "unavailable" };
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
  const version = isRecord(v) ? v["version"] : undefined;
  if (
    !isRecord(v) ||
    (version !== 1 && version !== PAC_RECOVERY_VERSION) ||
    typeof v["operationId"] !== "string" ||
    (v["action"] !== "publish" && v["action"] !== "rollback") ||
    typeof v["profileId"] !== "string" ||
    typeof v["expectedActiveRevision"] !== "number" ||
    typeof v["expectedActiveSpecDigest"] !== "string" ||
    typeof v["candidateSpecDigest"] !== "string" ||
    typeof v["targetN"] !== "number" ||
    typeof v["startedAt"] !== "number" ||
    typeof v["subject"] !== "string" ||
    (version === PAC_RECOVERY_VERSION &&
      (typeof v["collectionEtag"] !== "string" ||
        typeof v["historyIncarnation"] !== "string"))
  ) {
    return { kind: "unreadable" };
  }
  const collectionEtag = v["collectionEtag"];
  const historyIncarnation = v["historyIncarnation"];
  const marker: PacRecoveryMarker = {
    operationId: v["operationId"],
    action: v["action"],
    profileId: v["profileId"],
    expectedActiveRevision: v["expectedActiveRevision"],
    expectedActiveSpecDigest: v["expectedActiveSpecDigest"],
    candidateSpecDigest: v["candidateSpecDigest"],
    targetN: v["targetN"],
    startedAt: v["startedAt"],
    // a version-1 marker carries neither: an UNKNOWN epoch
    collectionEtag: typeof collectionEtag === "string" ? collectionEtag : "",
    historyIncarnation:
      typeof historyIncarnation === "string" ? historyIncarnation : "",
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

/** Terminal, OWNERSHIP-MATCHED clear — confirmed outcome, authoritative
 * refusal, proven resolution, or the explicit abandon ceremony of exactly
 * `operationId`. Returns whether a marker of that operation was removed; a
 * marker of another operation (or an unreadable store) is left untouched. */
export function clearPacRecovery(operationId: string): boolean {
  let raw: string | null;
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2F-E lifecycle recovery): the single NON-SECRET PAC operation-identity marker; field allowlist pinned by pac-2fe-red.test.ts.
    raw = sessionStorage.getItem(PAC_RECOVERY_KEY);
  } catch {
    return false;
  }
  if (raw === null) return false;
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return false;
  }
  if (!isRecord(v) || v["operationId"] !== operationId) return false;
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2F-E lifecycle recovery): the single NON-SECRET PAC operation-identity marker; field allowlist pinned by pac-2fe-red.test.ts.
    sessionStorage.removeItem(PAC_RECOVERY_KEY);
    return true;
  } catch {
    return false;
  }
}

/** The one UNCONDITIONAL purge — the authentication boundary only. */
function purgePacRecovery(): void {
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2F-E lifecycle recovery): the single NON-SECRET PAC operation-identity marker; field allowlist pinned by pac-2fe-red.test.ts.
    sessionStorage.removeItem(PAC_RECOVERY_KEY);
  } catch {
    // nothing to purge if storage is unavailable
  }
}

// Auth-boundary rule: logout / session expiry / identity change purges the
// marker (module-level registration — NOT tied to any component unmount).
registerAuthCleanup(() => {
  purgePacRecovery();
});
