// 2E-B FINAL lifecycle closure — the durable T3 rotation-recovery marker.
//
// One narrow record, NOT a general browser-state framework: once a pseudonym
// key rotation has been DISPATCHED and its outcome is unconfirmed, its
// recovery identity must survive ordinary route navigation and page reload
// until it reaches an explicit terminal/recovery decision — otherwise a
// remount forgets the operation, Rotate re-arms, and an operation that had
// actually landed can be followed by a second continuity-breaking rotation
// that backend idempotency cannot stop (a NEW operation id is a NEW
// operation).
//
// Storage: sessionStorage (per-tab browser session; survives reload and
// route changes, dies with the tab — matching the established session
// lifecycle). Contents are strictly NON-SECRET: {version, operationId,
// preSeq, startedAt, subject}. The operation id is explicitly non-secret,
// preSeq is the public rotation sequence anchor, and the subject binding is
// the authenticated username — never key material, key ids, or
// configuration drafts (pinned by the lifecycle test's field allowlist).
//
// Lifecycle rules (load-bearing):
//  - WRITE happens BEFORE the network dispatch — a crash between dispatch
//    and a later write would recreate the forgotten-operation defect.
//  - CLEAR happens only on a terminal outcome: confirmed success, an
//    authoritative server error (the appliance answered — nothing landed),
//    a proven LANDED/NOT-LANDED resolution, the explicit ambiguous-abandon
//    ceremony, or an authentication boundary (below). NEVER on component
//    unmount.
//  - READ is subject-bound: a marker written under a different
//    authenticated identity is discarded, never inherited.
import { isRecord } from "../../api/decode";
import { registerAuthCleanup } from "../../auth/teardown";

/** The storage contract key — pinned literally by the lifecycle tests. */
export const ROTATION_RECOVERY_KEY = "culvert.decryption.rotation-recovery.v1";

export interface RotationRecoveryMarker {
  operationId: string;
  /** rotation_seq observed when the operation was reviewed — the
   * NOT-LANDED proof anchor of the accepted server matrix. */
  preSeq: number;
}

/** Persist the recovery identity for one dispatched-but-unconfirmed
 * rotation, VERIFIED: the marker is written and then read back through the
 * strict reader; only an exactly-recoverable marker returns true. Called
 * BEFORE the network dispatch, and its result is LOAD-BEARING (TRUE FINAL
 * closure, Blocker 2): NO DURABLE RECOVERY MARKER ⇒ NO T3 ROTATION
 * DISPATCH. There is deliberately no memory-only or localStorage fallback —
 * this is a fail-closed safety dependency for one irreversible operation. */
export function writeRotationRecovery(
  subject: string,
  m: RotationRecoveryMarker,
): boolean {
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2E-B lifecycle closure): the single NON-SECRET T3 rotation-recovery marker; field allowlist pinned by decryption-rotation-lifecycle.test.tsx.
    sessionStorage.setItem(
      ROTATION_RECOVERY_KEY,
      JSON.stringify({
        version: 1,
        operationId: m.operationId,
        preSeq: m.preSeq,
        startedAt: Date.now(),
        subject,
      }),
    );
    // Read-back through the strict subject-bound reader: a silently-failing
    // or lying storage (quota, privacy mode, extension interference) must
    // fail the write, not the recovery that would later depend on it.
    const back = readRotationRecovery(subject);
    return (
      back !== null &&
      back.operationId === m.operationId &&
      back.preSeq === m.preSeq
    );
  } catch {
    return false;
  }
}

/** Load the pending recovery identity for the CURRENT authenticated
 * subject. A malformed, foreign-version, or foreign-subject marker is
 * discarded (removed) — a pending operation is never inherited across
 * authenticated identities. */
export function readRotationRecovery(
  subject: string,
): RotationRecoveryMarker | null {
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2E-B lifecycle closure): the single NON-SECRET T3 rotation-recovery marker; field allowlist pinned by decryption-rotation-lifecycle.test.tsx.
    const raw = sessionStorage.getItem(ROTATION_RECOVERY_KEY);
    if (raw === null) return null;
    const v: unknown = JSON.parse(raw);
    if (
      !isRecord(v) ||
      v["version"] !== 1 ||
      typeof v["operationId"] !== "string" ||
      v["operationId"] === "" ||
      typeof v["preSeq"] !== "number" ||
      !Number.isFinite(v["preSeq"]) ||
      v["subject"] !== subject
    ) {
      // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2E-B lifecycle closure): the single NON-SECRET T3 rotation-recovery marker; field allowlist pinned by decryption-rotation-lifecycle.test.tsx.
      sessionStorage.removeItem(ROTATION_RECOVERY_KEY);
      return null;
    }
    return { operationId: v["operationId"], preSeq: v["preSeq"] };
  } catch {
    return null;
  }
}

/** Terminal clear — confirmed outcome, proven resolution, or the explicit
 * abandon ceremony. */
export function clearRotationRecovery(): void {
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2E-B lifecycle closure): the single NON-SECRET T3 rotation-recovery marker; field allowlist pinned by decryption-rotation-lifecycle.test.tsx.
    sessionStorage.removeItem(ROTATION_RECOVERY_KEY);
  } catch {
    // nothing to clear if storage is unavailable
  }
}

// Auth-boundary rule: logout / session expiry / identity change clears the
// marker (module-level registration — deliberately NOT tied to any
// component's unmount, which must NOT clear it).
registerAuthCleanup(() => {
  clearRotationRecovery();
});
