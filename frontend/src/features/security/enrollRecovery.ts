// 2E-C trust-lifecycle correction (R8) — the durable enrollment-recovery
// marker.
//
// Enrollment consumes a SINGLE-USE token and issues a credential in one
// exchange, so a lost response used to leave nothing to resolve the
// outcome from. The appliance now binds every dispatch to a 128-bit
// OPERATION ID (persisted in a server-side receipt before the RPC, bound by
// Sluice to the issued fingerprint). This module keeps the browser-side
// half: the operation identity of a dispatched-but-unconfirmed enrollment
// must survive route navigation and reload until it reaches a terminal
// decision, so the operator can RESOLVE it (POST …/enroll/recover) instead
// of guessing or retrying.
//
// Storage: sessionStorage (per-tab; survives reload; dies with the tab —
// the established session lifecycle, same as the 2E-B rotation marker).
// Contents are strictly NON-SECRET: {version, operationId, name, endpoint,
// serverFingerprint, startedAt, subject}. NEVER the token, NEVER key
// material (pinned by cdr-enroll-recovery.test.tsx).
//
// Lifecycle rules (load-bearing):
//  - WRITE happens BEFORE the network dispatch and is VERIFIED by read-back;
//    NO DURABLE MARKER ⇒ NO ENROLLMENT DISPATCH.
//  - CLEAR happens only on a terminal outcome: confirmed success, an
//    authoritative refusal that names no operation (nothing was issued), a
//    proven LANDED / NOT_ISSUED / REVOKED resolution, the explicit abandon
//    ceremony, or an authentication boundary. NEVER on component unmount.
//  - READ is subject-bound: a marker written under a different
//    authenticated identity is discarded, never inherited.
import { isRecord } from "../../api/decode";
import { registerAuthCleanup } from "../../auth/teardown";

/** The storage contract key — pinned literally by the lifecycle tests. */
export const ENROLL_RECOVERY_KEY = "culvert.cdr.enroll-recovery.v1";

export interface EnrollRecoveryMarker {
  operationId: string;
  name: string;
  endpoint: string;
  serverFingerprint: string;
  startedAt: number;
}

export type EnrollRecoveryRead =
  | { kind: "none" }
  | { kind: "valid"; marker: EnrollRecoveryMarker }
  | { kind: "unavailable" }
  | { kind: "unreadable" };

/** Mint the client-side operation identity: 128 bits, hex — the grammar
 * Sluice binds (16–64 chars of [A-Za-z0-9._-]). */
export function mintEnrollOperationId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Persist + VERIFY the marker for one about-to-be-dispatched enrollment.
 * Called BEFORE the network dispatch; false ⇒ the caller must NOT send. */
export function writeEnrollRecovery(
  subject: string,
  m: EnrollRecoveryMarker,
): boolean {
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2E-C trust-lifecycle correction): the single NON-SECRET enrollment-recovery marker; field allowlist pinned by cdr-enroll-recovery.test.tsx.
    sessionStorage.setItem(
      ENROLL_RECOVERY_KEY,
      JSON.stringify({
        version: 1,
        operationId: m.operationId,
        name: m.name,
        endpoint: m.endpoint,
        serverFingerprint: m.serverFingerprint,
        startedAt: m.startedAt,
        subject,
      }),
    );
    const back = readEnrollRecovery(subject);
    return (
      back.kind === "valid" &&
      back.marker.operationId === m.operationId &&
      back.marker.name === m.name
    );
  } catch {
    return false;
  }
}

/** Inspect the recovery store for the CURRENT subject — TYPED: "cannot
 * read" and "cannot interpret" are NOT "absent". A well-formed marker bound
 * to a DIFFERENT subject is discarded (never inherited) and reads "none". */
export function readEnrollRecovery(subject: string): EnrollRecoveryRead {
  let raw: string | null;
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2E-C trust-lifecycle correction): the single NON-SECRET enrollment-recovery marker; field allowlist pinned by cdr-enroll-recovery.test.tsx.
    raw = sessionStorage.getItem(ENROLL_RECOVERY_KEY);
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
    v["operationId"] === "" ||
    typeof v["name"] !== "string" ||
    typeof v["endpoint"] !== "string" ||
    typeof v["serverFingerprint"] !== "string" ||
    typeof v["startedAt"] !== "number" ||
    typeof v["subject"] !== "string"
  ) {
    return { kind: "unreadable" };
  }
  if (v["subject"] !== subject) {
    try {
      // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2E-C trust-lifecycle correction): the single NON-SECRET enrollment-recovery marker; field allowlist pinned by cdr-enroll-recovery.test.tsx.
      sessionStorage.removeItem(ENROLL_RECOVERY_KEY);
    } catch {
      // the foreign marker cannot be ours either way
    }
    return { kind: "none" };
  }
  return {
    kind: "valid",
    marker: {
      operationId: v["operationId"],
      name: v["name"],
      endpoint: v["endpoint"],
      serverFingerprint: v["serverFingerprint"],
      startedAt: v["startedAt"],
    },
  };
}

/** Terminal clear — confirmed outcome, proven resolution, refusal that
 * names no operation, or the explicit abandon ceremony. */
export function clearEnrollRecovery(): void {
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (2E-C trust-lifecycle correction): the single NON-SECRET enrollment-recovery marker; field allowlist pinned by cdr-enroll-recovery.test.tsx.
    sessionStorage.removeItem(ENROLL_RECOVERY_KEY);
  } catch {
    // nothing to clear if storage is unavailable
  }
}

// Auth-boundary rule: logout / session expiry / identity change clears the
// marker (module-level registration — NOT tied to any component unmount).
registerAuthCleanup(() => {
  clearEnrollRecovery();
});
