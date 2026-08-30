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

/** The result of inspecting the recovery store (storage-read fail-closed
 * closure). "none" is the ONLY state meaning "no pending marker" — storage
 * was readable and the key was absent. Everything else keeps the T3
 * rotation blocked: "unavailable" = storage access threw (the record — if
 * any — cannot currently be inspected; nothing is deleted); "unreadable" =
 * the key EXISTS but its recovery meaning cannot be safely interpreted
 * (malformed JSON, schema-invalid, or an unsupported version — nothing is
 * silently deleted; only the explicit typed DISCARD ceremony may retire it). */
export type RotationRecoveryRead =
  | { kind: "none" }
  | { kind: "valid"; marker: RotationRecoveryMarker }
  | { kind: "unavailable" }
  | { kind: "unreadable" };

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
    // Read-back through the strict subject-bound TYPED reader: a
    // silently-failing or lying storage (quota, privacy mode, extension
    // interference) must fail the write, not the recovery that would later
    // depend on it. Success requires the exact marker to read back VALID.
    const back = readRotationRecovery(subject);
    return (
      back.kind === "valid" &&
      back.marker.operationId === m.operationId &&
      back.marker.preSeq === m.preSeq
    );
  } catch {
    return false;
  }
}

/** VERIFIED removal for the explicit DISCARD ceremony: the record is
 * removed and then proven absent by a read-back. False (marker may remain)
 * keeps the rotation surface blocked. */
export function clearRotationRecoveryVerified(): boolean {
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2E-B lifecycle closure): the single NON-SECRET T3 rotation-recovery marker; field allowlist pinned by decryption-rotation-lifecycle.test.tsx.
    sessionStorage.removeItem(ROTATION_RECOVERY_KEY);
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2E-B lifecycle closure): the single NON-SECRET T3 rotation-recovery marker; field allowlist pinned by decryption-rotation-lifecycle.test.tsx.
    return sessionStorage.getItem(ROTATION_RECOVERY_KEY) === null;
  } catch {
    return false;
  }
}

/** Inspect the recovery store for the CURRENT authenticated subject —
 * TYPED, never `Marker | null`: "cannot read" and "cannot interpret" are
 * NOT "absent" (an irreversible T3 action must stay blocked until recovery
 * state is provably absent, valid, or explicitly discarded). The ONE
 * deliberate deletion here is the established subject-isolation contract:
 * a clearly WELL-FORMED v1 marker bound to a DIFFERENT authenticated
 * subject is discarded (never inherited) and reads as "none". */
export function readRotationRecovery(subject: string): RotationRecoveryRead {
  let raw: string | null;
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2E-B lifecycle closure): the single NON-SECRET T3 rotation-recovery marker; field allowlist pinned by decryption-rotation-lifecycle.test.tsx.
    raw = sessionStorage.getItem(ROTATION_RECOVERY_KEY);
  } catch {
    return { kind: "unavailable" }; // storage cannot be inspected — NOT absent
  }
  if (raw === null) return { kind: "none" }; // proven absent
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return { kind: "unreadable" }; // exists but uninterpretable — keep it
  }
  if (
    !isRecord(v) ||
    v["version"] !== 1 ||
    typeof v["operationId"] !== "string" ||
    v["operationId"] === "" ||
    typeof v["preSeq"] !== "number" ||
    !Number.isFinite(v["preSeq"]) ||
    typeof v["subject"] !== "string"
  ) {
    // Schema-invalid or unsupported version: never silently discarded (no
    // migration logic here) — the explicit DISCARD ceremony owns retirement.
    return { kind: "unreadable" };
  }
  if (v["subject"] !== subject) {
    try {
      // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2E-B lifecycle closure): the single NON-SECRET T3 rotation-recovery marker; field allowlist pinned by decryption-rotation-lifecycle.test.tsx.
      sessionStorage.removeItem(ROTATION_RECOVERY_KEY);
    } catch {
      // the foreign marker cannot be ours either way
    }
    return { kind: "none" };
  }
  return {
    kind: "valid",
    marker: { operationId: v["operationId"], preSeq: v["preSeq"] },
  };
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
