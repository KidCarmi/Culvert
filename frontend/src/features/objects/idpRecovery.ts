// FE-6A.2 — the Identity Provider OPERATION RECOVERY MARKER.
//
// A provider create or an operation-identified update (a cutover through PUT)
// is dispatched with a client-minted UUID operationId the appliance records
// in its operation ledger. If the response is lost, the ONLY authoritative
// source of the outcome is GET /api/idp/operations/{operationId}; the browser
// therefore persists a NON-SECRET, SUBJECT-BOUND marker BEFORE dispatch,
// verifies it by read-back, and clears it only on a proven, ownership-matched
// terminal outcome or at the auth boundary (contract §G C5 / D15, the PAC and
// CDR precedent).
//
// The marker carries the operation identity, the intent (create | update +
// target id), the candidate's NON-SECRET canonical identity (candidateDigest —
// public facts + secret POSTURE, never a value), the fence the write carried,
// whether it carried the cutover, and a timestamp. It NEVER carries the client
// secret, the bind password, the SAML metadata, a test credential or the
// request body — the field allowlist is pinned by fe6a2-red-recovery.test.ts.
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
//   • the auth boundary purges unconditionally.
import { registerAuthCleanup } from "../../auth/teardown";
import { IDP_TYPES } from "../../api/idp";
import { isRecord } from "../../api/decode";
import type { IdPType } from "../../api/idp";

export const IDP_RECOVERY_KEY = "culvert.idp.operation-recovery.v1";
export const IDP_RECOVERY_VERSION = 1;

export type IdPRecoveryAction = "create" | "update";

export interface IdPRecoveryMarker {
  operationId: string;
  action: IdPRecoveryAction;
  /** "" for a create (the appliance mints the id); the target id for an update */
  profileId: string;
  name: string;
  type: IdPType;
  /** candidateDigest(spec) — the non-secret canonical candidate identity */
  candidateDigest: string;
  /** the fence the write carried: documentRevision (create) / entry revision (update) */
  fence: string;
  cutover: boolean;
  startedAt: number;
}

export type IdPRecoveryRead =
  | { kind: "none" }
  | { kind: "valid"; marker: IdPRecoveryMarker }
  | { kind: "unavailable" }
  | { kind: "unreadable" }
  | { kind: "unresolved" };

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DIGEST_RE = /^[0-9a-f]{16,64}$/;
const FIELDS = [
  "action",
  "candidateDigest",
  "cutover",
  "fence",
  "name",
  "operationId",
  "profileId",
  "startedAt",
  "type",
] as const;

function grammarValid(m: IdPRecoveryMarker): boolean {
  return (
    UUID_RE.test(m.operationId) &&
    (m.action === "create" || m.action === "update") &&
    typeof m.profileId === "string" &&
    m.profileId.length <= 128 &&
    typeof m.name === "string" &&
    m.name.length > 0 &&
    m.name.length <= 200 &&
    IDP_TYPES.includes(m.type) &&
    DIGEST_RE.test(m.candidateDigest) &&
    typeof m.fence === "string" &&
    m.fence.length > 0 &&
    m.fence.length <= 128 &&
    typeof m.cutover === "boolean" &&
    Number.isFinite(m.startedAt) &&
    m.startedAt >= 0
  );
}

function sameMarker(a: IdPRecoveryMarker, b: IdPRecoveryMarker): boolean {
  return FIELDS.every((k) => a[k] === b[k]);
}

interface Stored extends IdPRecoveryMarker {
  version: number;
  subject: string;
}

function store(): Storage | null {
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned narrow exception to contract §9.B1 (FE-6A.2): the single NON-SECRET, subject-bound IdP operation recovery marker; field allowlist pinned by fe6a2-red-recovery.test.ts
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
    raw = st.getItem(IDP_RECOVERY_KEY);
  } catch {
    return { kind: "unavailable" };
  }
  if (raw === null) return { kind: "none" };
  try {
    const v: unknown = JSON.parse(raw);
    if (!isRecord(v)) return { kind: "unreadable" };
    const o = v;
    const stored: Stored = {
      version: typeof o["version"] === "number" ? o["version"] : -1,
      subject: typeof o["subject"] === "string" ? o["subject"] : "",
      operationId: typeof o["operationId"] === "string" ? o["operationId"] : "",
      action: o["action"] === "update" ? "update" : "create",
      profileId: typeof o["profileId"] === "string" ? o["profileId"] : "",
      name: typeof o["name"] === "string" ? o["name"] : "",
      type: IDP_TYPES.find((t) => t === o["type"]) ?? "oidc",
      candidateDigest:
        typeof o["candidateDigest"] === "string" ? o["candidateDigest"] : "",
      fence: typeof o["fence"] === "string" ? o["fence"] : "",
      cutover: o["cutover"] === true,
      startedAt: typeof o["startedAt"] === "number" ? o["startedAt"] : -1,
    };
    if (o["action"] !== "create" && o["action"] !== "update")
      return { kind: "unreadable" };
    if (
      stored.version !== IDP_RECOVERY_VERSION ||
      stored.subject === "" ||
      !grammarValid(stored)
    )
      return { kind: "unreadable" };
    return { kind: "stored", stored };
  } catch {
    return { kind: "unreadable" };
  }
}

function strip(s: Stored): IdPRecoveryMarker {
  return {
    operationId: s.operationId,
    action: s.action,
    profileId: s.profileId,
    name: s.name,
    type: s.type,
    candidateDigest: s.candidateDigest,
    fence: s.fence,
    cutover: s.cutover,
    startedAt: s.startedAt,
  };
}

/** Persist the marker BEFORE dispatch. false ⇒ NOTHING may be sent. */
export function writeIdPRecovery(
  subject: string,
  m: IdPRecoveryMarker,
): boolean {
  if (subject === "" || !grammarValid(m)) return false;
  const st = store();
  if (st === null) return false;
  const prev = readRaw();
  if (prev.kind === "unavailable" || prev.kind === "unreadable") return false;
  if (prev.kind === "stored") {
    if (prev.stored.subject !== subject) return false;
    if (prev.stored.operationId !== m.operationId) return false; // one outstanding operation
    if (!sameMarker(strip(prev.stored), m)) return false; // immutable evidence
  }
  const stored: Stored = { ...m, version: IDP_RECOVERY_VERSION, subject };
  try {
    st.setItem(IDP_RECOVERY_KEY, JSON.stringify(stored));
  } catch {
    return false;
  }
  const back = readRaw();
  return (
    back.kind === "stored" &&
    back.stored.subject === subject &&
    sameMarker(strip(back.stored), m)
  );
}

export function readIdPRecovery(subject: string): IdPRecoveryRead {
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
          store()?.removeItem(IDP_RECOVERY_KEY);
        } catch {
          /* nothing to do: the next read will see it again */
        }
        return { kind: "none" };
      }
      return { kind: "valid", marker: strip(r.stored) };
  }
}

/** Ownership-matched clear: only the named operation's marker is removed. */
export function clearIdPRecovery(operationId: string): boolean {
  const r = readRaw();
  if (r.kind !== "stored" || r.stored.operationId !== operationId) return false;
  try {
    store()?.removeItem(IDP_RECOVERY_KEY);
    return true;
  } catch {
    return false;
  }
}

/** The auth boundary: unconditional. */
export function purgeIdPRecovery(): void {
  try {
    store()?.removeItem(IDP_RECOVERY_KEY);
  } catch {
    /* an unavailable store holds nothing */
  }
}

registerAuthCleanup(() => {
  purgeIdPRecovery();
});
