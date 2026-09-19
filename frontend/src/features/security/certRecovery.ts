// FE-6B.2 — the certificate OPERATION RECOVERY MARKER.
//
// Every certificate mutation (rotate, import, UI replace, UI delete, OCSP
// set) is dispatched with a client-minted UUID operationId the appliance
// records in its durable operation ledger BEFORE it writes. If the answer is
// lost or cannot be verified, the ONLY authoritative source of the outcome
// is GET /api/ca/operations/{operationId}; the browser therefore persists a
// NON-SECRET, SUBJECT-BOUND marker BEFORE dispatch, verifies it by read-back,
// and clears it only on a proven, ownership-matched outcome or at the auth
// boundary (contract §G C5 / D15 — the IdP, PAC and CDR precedent).
//
// The marker carries the operation identity, the intent, the fence the
// write carried, the candidate's PUBLIC identity (the certificate fingerprint
// an import reviewed, the digest of the certificate bytes a replace sent, the
// posture word an OCSP set targets), the CA identity a rotation replaces and
// a timestamp. It NEVER carries the rotation challenge, a PEM, a private key,
// a passphrase or the request body — the field allowlist is pinned by
// fe6b2-red-recovery.test.ts.
//
// Rules:
//   • an EMPTY subject is `unresolved`: nothing is classified, dispatched,
//     resolved or deleted while the authenticated identity is not known;
//   • a marker stored under another subject is never inherited (discarded);
//   • ONE outstanding operation per browser: a different operationId cannot
//     be written while one is unresolved; the same operationId may be
//     re-written only field-for-field (immutable evidence);
//   • an unavailable or unreadable store means NO dispatch (write ⇒ false);
//   • clearing is ownership-matched (the operationId must match);
//   • the auth boundary purges unconditionally;
//   • a ledger record is THIS marker's operation only when operationId,
//     action, fence AND (import / replace) the candidate identity all match;
//   • an operation the lookup answers 404 for is ABSENT and therefore
//     UNKNOWN — never "never recorded" and never a licence to re-dispatch.
//     A decided ledger record can be evicted (256 slots) and a
//     content-derived fence is re-armed by an identical reinstall, so the
//     three protections a re-send relied on (replay by id, 409 stale,
//     409 candidate_duplicate) can all be absent at once and the re-sent
//     operation executes a second time (proved on the real handlers by
//     fe6b2c_red_test.go; review blocker 6B2C-B1). The marker is kept and the
//     typed Abandon is the only exit; a re-send would need an explicitly
//     labelled backend durable identity / continuity contract, which does
//     not exist. Nothing the node holds now is evidence about an absent
//     operation.
import { registerAuthCleanup } from "../../auth/teardown";
import { isRecord } from "../../api/decode";
import type {
  CertOperation,
  CertOperationAction,
  CertLookupRefusalCode,
} from "../../api/certificates";

export const CERT_RECOVERY_KEY = "culvert.cert.operation-recovery.v1";
export const CERT_RECOVERY_VERSION = 1;

export type CertRecoveryAction =
  "rotate" | "import" | "replace" | "delete" | "ocsp";
const ACTIONS: readonly CertRecoveryAction[] = [
  "rotate",
  "import",
  "replace",
  "delete",
  "ocsp",
];

export interface CertRecoveryMarker {
  operationId: string;
  action: CertRecoveryAction;
  /** the revision token the write carried (car1:… / uic1:… / ocr1:…) */
  fence: string;
  /** import: hex64 fingerprint of the reviewed CA; replace: hex64 sha256 of
   * the certificate PEM bytes sent; ocsp: "enabled" | "disabled";
   * rotate / delete: "" */
  candidate: string;
  /** rotate: hex64 fingerprint of the CA the challenge showed; else "" */
  previousFingerprint: string;
  startedAt: number;
}

export type CertRecoveryRead =
  | { kind: "none" }
  | { kind: "valid"; marker: CertRecoveryMarker }
  | { kind: "unavailable" }
  | { kind: "unreadable" }
  | { kind: "unresolved" };

/** The ledger action each marker action names. */
export const CERT_MARKER_ACTION: Record<
  CertRecoveryAction,
  CertOperationAction
> = {
  rotate: "ca.rotate",
  import: "ca.import",
  replace: "cert.ui.replace",
  delete: "cert.ui.delete",
  ocsp: "ocsp.set",
};

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX64_RE = /^[0-9a-f]{64}$/;
const CA_FENCE = /^car1:([0-9a-f]{64}|none)$/;
const UI_FENCE = /^uic1:([0-9a-f]{64}|none|incomplete)$/;
const OCSP_FENCE = /^ocr1:[0-9a-f]{64}$/;
const FIELDS = [
  "action",
  "candidate",
  "fence",
  "operationId",
  "previousFingerprint",
  "startedAt",
] as const;

function grammarValid(m: CertRecoveryMarker): boolean {
  if (!UUID_RE.test(m.operationId)) return false;
  if (!ACTIONS.includes(m.action)) return false;
  if (!Number.isFinite(m.startedAt) || m.startedAt < 0) return false;
  if (typeof m.fence !== "string" || typeof m.candidate !== "string")
    return false;
  if (typeof m.previousFingerprint !== "string") return false;
  switch (m.action) {
    case "rotate":
      return (
        CA_FENCE.test(m.fence) &&
        m.candidate === "" &&
        HEX64_RE.test(m.previousFingerprint)
      );
    case "import":
      return (
        CA_FENCE.test(m.fence) &&
        HEX64_RE.test(m.candidate) &&
        m.previousFingerprint === ""
      );
    case "replace":
      return (
        UI_FENCE.test(m.fence) &&
        HEX64_RE.test(m.candidate) &&
        m.previousFingerprint === ""
      );
    case "delete":
      return (
        UI_FENCE.test(m.fence) &&
        m.candidate === "" &&
        m.previousFingerprint === ""
      );
    case "ocsp":
      return (
        OCSP_FENCE.test(m.fence) &&
        (m.candidate === "enabled" || m.candidate === "disabled") &&
        m.previousFingerprint === ""
      );
  }
}

function sameMarker(a: CertRecoveryMarker, b: CertRecoveryMarker): boolean {
  return FIELDS.every((k) => a[k] === b[k]);
}

/** Only the allowlisted fields ever leave this function. */
function strip(m: CertRecoveryMarker): CertRecoveryMarker {
  return {
    operationId: m.operationId,
    action: m.action,
    fence: m.fence,
    candidate: m.candidate,
    previousFingerprint: m.previousFingerprint,
    startedAt: m.startedAt,
  };
}

type Stored = CertRecoveryMarker & { version: number; subject: string };

function store(): Storage | null {
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (FE-6B.2): the single NON-SECRET, subject-bound certificate operation recovery marker; field allowlist pinned by fe6b2-red-recovery.test.ts
    return sessionStorage;
  } catch {
    return null;
  }
}

type RawRead =
  | { kind: "none" }
  | { kind: "unavailable" }
  | { kind: "unreadable" }
  | { kind: "stored"; stored: Stored };

function readRaw(): RawRead {
  const st = store();
  if (st === null) return { kind: "unavailable" };
  let raw: string | null;
  try {
    raw = st.getItem(CERT_RECOVERY_KEY);
  } catch {
    return { kind: "unavailable" };
  }
  if (raw === null) return { kind: "none" };
  try {
    const v: unknown = JSON.parse(raw);
    if (!isRecord(v)) return { kind: "unreadable" };
    const action = ACTIONS.find((a) => a === v["action"]);
    if (action === undefined) return { kind: "unreadable" };
    const stored: Stored = {
      version: typeof v["version"] === "number" ? v["version"] : -1,
      subject: typeof v["subject"] === "string" ? v["subject"] : "",
      operationId: typeof v["operationId"] === "string" ? v["operationId"] : "",
      action,
      fence: typeof v["fence"] === "string" ? v["fence"] : "",
      candidate: typeof v["candidate"] === "string" ? v["candidate"] : "",
      previousFingerprint:
        typeof v["previousFingerprint"] === "string"
          ? v["previousFingerprint"]
          : "",
      startedAt: typeof v["startedAt"] === "number" ? v["startedAt"] : -1,
    };
    if (
      stored.version !== CERT_RECOVERY_VERSION ||
      stored.subject === "" ||
      !grammarValid(stored)
    )
      return { kind: "unreadable" };
    return { kind: "stored", stored };
  } catch {
    return { kind: "unreadable" };
  }
}

/** Persist the marker BEFORE dispatch. false ⇒ NOTHING may be sent. */
export function writeCertRecovery(
  subject: string,
  m: CertRecoveryMarker,
): boolean {
  if (subject === "" || !grammarValid(m)) return false;
  const st = store();
  if (st === null) return false;
  const prev = readRaw();
  if (prev.kind === "unavailable" || prev.kind === "unreadable") return false;
  const clean = strip(m);
  if (prev.kind === "stored") {
    if (prev.stored.subject !== subject) return false;
    if (prev.stored.operationId !== clean.operationId) return false; // one outstanding operation
    if (!sameMarker(strip(prev.stored), clean)) return false; // immutable evidence
  }
  const stored: Stored = {
    ...clean,
    version: CERT_RECOVERY_VERSION,
    subject,
  };
  try {
    st.setItem(CERT_RECOVERY_KEY, JSON.stringify(stored));
  } catch {
    return false;
  }
  const back = readRaw();
  return (
    back.kind === "stored" &&
    back.stored.subject === subject &&
    sameMarker(strip(back.stored), clean)
  );
}

export function readCertRecovery(subject: string): CertRecoveryRead {
  if (subject === "") return { kind: "unresolved" };
  const r = readRaw();
  switch (r.kind) {
    case "none":
    case "unavailable":
    case "unreadable":
      return r;
    case "stored":
      if (r.stored.subject !== subject) {
        // never inherited — discarded, not preserved for anyone
        try {
          store()?.removeItem(CERT_RECOVERY_KEY);
        } catch {
          /* nothing to do: the next read will see it again */
        }
        return { kind: "none" };
      }
      return { kind: "valid", marker: strip(r.stored) };
  }
}

/** Ownership-matched clear: only the named operation's marker is removed. */
export function clearCertRecovery(operationId: string): boolean {
  const r = readRaw();
  if (r.kind !== "stored" || r.stored.operationId !== operationId) return false;
  try {
    store()?.removeItem(CERT_RECOVERY_KEY);
    return true;
  } catch {
    return false;
  }
}

/** The auth boundary: unconditional. */
export function purgeCertRecovery(): void {
  try {
    store()?.removeItem(CERT_RECOVERY_KEY);
  } catch {
    /* an unavailable store holds nothing */
  }
}

registerAuthCleanup(() => {
  purgeCertRecovery();
});

// ── Binding a ledger record to the marker ────────────────────────────────

/** A ledger record is THIS marker's operation only when the operation
 * identity, the action, the fence the write carried and — where the ledger
 * publishes one — the candidate identity all agree. A rotation's candidate
 * is server-minted (unbound by construction); a delete and an OCSP set
 * publish none. */
export function operationBoundToCertMarker(
  op: CertOperation,
  m: CertRecoveryMarker,
): boolean {
  if (op.operationId.toLowerCase() !== m.operationId.toLowerCase())
    return false;
  if (op.action !== CERT_MARKER_ACTION[m.action]) return false;
  if (op.fence !== m.fence) return false;
  if (m.action === "import" || m.action === "replace")
    return op.candidateFingerprint === m.candidate;
  return true;
}

export type CertRecoveryView =
  | { kind: "none" }
  | { kind: "looking" }
  | { kind: "op"; op: CertOperation }
  /** the record under this operationId is NOT the dispatched intent */
  | { kind: "unbound"; op: CertOperation }
  /** the authoritative lookup answered 404: the node retains no record —
   * UNKNOWN (an evicted record and a never-started write are the same 404) */
  | { kind: "absent" }
  | { kind: "refused"; code: CertLookupRefusalCode }
  | { kind: "unproven" };
