// 2E-C CDR / Sluice integration API: runtime config (one runtime-mutable
// boolean), the enrolled-instance TRUST registry, CDR policy rules, the
// cached engine health snapshot, and the admin test upload.
//
// Contract highlights (2E-C inventory + backend corrections):
//   - NODE-LOCAL: every CDR surface lives on THIS appliance only — outside
//     export/import, config rollback, and CP→DP sync (recorded backend
//     posture; mutations are audited but never create config versions).
//   - CONFIG: only `enabled` is runtime-mutable (an absolute-state,
//     idempotent boolean persisted to a sentinel file); everything else is
//     YAML/CLI + restart and is rendered read-only. fail_mode is
//     security-critical: "closed" blocks files when Sluice is unavailable,
//     ANY other configured value fails open — the UI renders the configured
//     string verbatim plus the server-derived failOpen boolean, never a
//     normalized guess.
//   - TRUST IDENTITY: an instance's registry key is its immutable enrollment
//     name, but its SECURITY identity is the client-cert SHA-256 fingerprint
//     (the only key Sluice accepts for revocation) — recorded durably by the
//     2E-C backend and surfaced on every trust ceremony. DELETE is LOCAL
//     (Sluice keeps trusting the credential; the response echoes the orphaned
//     fingerprint); REVOKE actually retires it on the Sluice side and needs a
//     second enrolled instance (Sluice refuses self-revocation → 503).
//   - UNKNOWN OUTCOMES: enrollment is NON-idempotent (single-use
//     consume-and-delete token) — never blindly retried; a lost response can
//     leave an issued certificate in Sluice's ledger that this appliance
//     never stored. Revocation IS idempotent on the Sluice side (proven) —
//     a retry after an unknown outcome is safe. The one-time token is
//     INPUT-only: it exists in form state until dispatch and appears in no
//     read DTO, no storage, and no log.
//   - POLICIES: the rule name is the identity (unique since 2E-C; duplicates
//     are 409) and the only DELETE key. Rules match first-by-priority;
//     unknown mode strings are rendered verbatim (the engine treats unknown
//     as ENFORCE — fail-safe — but the UI never relabels them).
import { ApiError, apiRequest } from "./client";
import {
  DecodeError,
  field,
  readArray,
  readBoolean,
  readNumber,
  readOptional,
  readRecord,
  readString,
  type Decoder,
} from "./decode";

function opt<T>(
  o: Record<string, unknown>,
  key: string,
  read: Decoder<T>,
  path: string,
): T | undefined {
  return readOptional(read)(o[key], `${path}.${key}`);
}

// ── Config (GET/PUT /api/cdr/config) ────────────────────────────────────────

export interface CDRConfig {
  enabled: boolean;
  endpoint: string;
  /** Configured verbatim ("open"/"closed" are the validated values; anything
   * else renders as-is — the derived truth is `failOpen`). */
  failMode: string;
  defaultProfile: string;
  defaultMode: string;
  timeoutSec: number;
  maxFileSizeMB: number;
  chunkSizeKB: number;
  serverFingerprint: string;
  certsDir: string;
  /** Whether a live pooled client currently exists. */
  clientActive: boolean;
  /** Server-derived: true unless failMode is exactly "closed". */
  failOpen: boolean;
}

export const decodeCDRConfig: Decoder<CDRConfig> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    enabled: field(o, "enabled", readBoolean, path),
    endpoint: opt(o, "endpoint", readString, path) ?? "",
    failMode: field(o, "failMode", readString, path),
    defaultProfile: opt(o, "defaultProfile", readString, path) ?? "",
    defaultMode: opt(o, "defaultMode", readString, path) ?? "",
    timeoutSec: opt(o, "timeoutSec", readNumber, path) ?? 0,
    maxFileSizeMB: opt(o, "maxFileSizeMB", readNumber, path) ?? 0,
    chunkSizeKB: opt(o, "chunkSizeKB", readNumber, path) ?? 0,
    serverFingerprint: opt(o, "serverFingerprint", readString, path) ?? "",
    certsDir: opt(o, "certsDir", readString, path) ?? "",
    clientActive: field(o, "clientActive", readBoolean, path),
    failOpen: field(o, "failOpen", readBoolean, path),
  };
};

export function getCDRConfig(signal?: AbortSignal): Promise<CDRConfig> {
  return apiRequest(
    "/api/cdr/config",
    decodeCDRConfig,
    signal !== undefined ? { signal } : {},
  );
}

export interface CDRToggleResult {
  enabled: boolean;
  clientActive: boolean;
}

/** Absolute-state runtime toggle (the ONLY runtime-mutable config field).
 * Idempotent by design — the body declares the full desired state, so there
 * is no read-modify-write to fence. Persisted to the /data/cdr_enabled
 * sentinel on 2xx (a 500 means neither durable nor runtime state changed). */
export function toggleCDR(
  enabled: boolean,
  signal?: AbortSignal,
): Promise<CDRToggleResult> {
  return apiRequest(
    "/api/cdr/config",
    (v, path = "$") => {
      const o = readRecord(v, path);
      return {
        enabled: field(o, "enabled", readBoolean, path),
        clientActive: field(o, "clientActive", readBoolean, path),
      };
    },
    {
      method: "PUT",
      body: { enabled },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

// ── Instances (GET/DELETE /api/cdr/instances, POST …/enroll, …/revoke) ──────

export interface CDRInstance {
  name: string;
  endpoint: string;
  /** TOFU pin of the SLUICE server certificate. */
  serverFingerprint: string;
  /** SHA-256 of OUR issued client cert — the Sluice-side revocation key.
   * "" on entries enrolled before the fingerprint was recorded durably. */
  clientCertFingerprint: string;
  enrolledAt: string;
  version: string;
  lastHealth: string;
  enabled: boolean;
  /** Cert-expiry enrichment; absent when the cert cannot be read. */
  clientCertNotAfter?: string;
  clientCertDaysRemaining?: number;
  /** Live pool enrichment; absent when the instance is not pooled. */
  cbState?: string;
  cbConsecFails?: number;
  cbTotalOpens?: number;
  cbTotalTrips?: number;
  poolHealthy?: boolean;
  /** 2E-C R7: the bounded durable credential LINEAGE — every generation
   * Sluice issued for this instance with its own state. Sluice keeps
   * trusting every LIVE generation (not revoked, not expired) until it
   * expires or is revoked there; a renewal never retires its predecessor. */
  credentials: readonly CDRCredentialGeneration[];
  /** Every fingerprint Sluice may still trust (active first). */
  liveFingerprints: readonly string[];
}

export interface CDRCredentialGeneration {
  seq: number;
  fingerprint: string;
  notAfterUnix: number;
  /** renewing | staged | active | superseded | orphaned | revoked —
   * rendered verbatim. */
  state: string;
  issuedAt: string;
  operationId: string;
  /** enroll | renewal | legacy */
  source: string;
}

function readGeneration(v: unknown, path: string): CDRCredentialGeneration {
  const o = readRecord(v, path);
  return {
    seq: field(o, "seq", readNumber, path),
    fingerprint: opt(o, "fingerprint", readString, path) ?? "",
    notAfterUnix: opt(o, "notAfterUnix", readNumber, path) ?? 0,
    state: field(o, "state", readString, path),
    issuedAt: opt(o, "issuedAt", readString, path) ?? "",
    operationId: opt(o, "operationId", readString, path) ?? "",
    source: opt(o, "source", readString, path) ?? "",
  };
}

function readInstance(v: unknown, path: string): CDRInstance {
  const o = readRecord(v, path);
  const rawCreds = o["credentials"];
  const credentials: CDRCredentialGeneration[] = [];
  if (rawCreds !== undefined && rawCreds !== null) {
    for (const [i, item] of readArray((x, p) => readRecord(x, p))(
      rawCreds,
      `${path}.credentials`,
    ).entries()) {
      credentials.push(readGeneration(item, `${path}.credentials[${i}]`));
    }
  }
  const rawLive = o["liveFingerprints"];
  const clientCertFingerprint =
    opt(o, "clientCertFingerprint", readString, path) ?? "";
  const liveFingerprints =
    rawLive === undefined || rawLive === null
      ? clientCertFingerprint === ""
        ? []
        : [clientCertFingerprint]
      : field(o, "liveFingerprints", readArray(readString), path);
  const out: CDRInstance = {
    name: field(o, "name", readString, path),
    endpoint: field(o, "endpoint", readString, path),
    serverFingerprint: field(o, "serverFingerprint", readString, path),
    clientCertFingerprint,
    enrolledAt: field(o, "enrolledAt", readString, path),
    version: opt(o, "version", readString, path) ?? "",
    lastHealth: opt(o, "lastHealth", readString, path) ?? "",
    enabled: opt(o, "enabled", readBoolean, path) ?? true,
    credentials,
    liveFingerprints,
  };
  const notAfter = opt(o, "clientCertNotAfter", readString, path);
  if (notAfter !== undefined) out.clientCertNotAfter = notAfter;
  const days = opt(o, "clientCertDaysRemaining", readNumber, path);
  if (days !== undefined) out.clientCertDaysRemaining = days;
  const cbState = opt(o, "cbState", readString, path);
  if (cbState !== undefined) out.cbState = cbState;
  const cbFails = opt(o, "cbConsecFails", readNumber, path);
  if (cbFails !== undefined) out.cbConsecFails = cbFails;
  const cbOpens = opt(o, "cbTotalOpens", readNumber, path);
  if (cbOpens !== undefined) out.cbTotalOpens = cbOpens;
  const cbTrips = opt(o, "cbTotalTrips", readNumber, path);
  if (cbTrips !== undefined) out.cbTotalTrips = cbTrips;
  const healthy = opt(o, "poolHealthy", readBoolean, path);
  if (healthy !== undefined) out.poolHealthy = healthy;
  return out;
}

export interface CDRInstances {
  instances: readonly CDRInstance[];
  count: number;
  version: number;
  updatedAt: string;
}

export const decodeCDRInstances: Decoder<CDRInstances> = (v, path = "$") => {
  const o = readRecord(v, path);
  const raw = o["instances"];
  const instances: CDRInstance[] = [];
  if (raw !== undefined && raw !== null) {
    for (const [i, item] of readArray((x, p) => readRecord(x, p))(
      raw,
      `${path}.instances`,
    ).entries()) {
      instances.push(readInstance(item, `${path}.instances[${i}]`));
    }
  }
  return {
    instances,
    count: field(o, "count", readNumber, path),
    version: field(o, "version", readNumber, path),
    updatedAt: opt(o, "updatedAt", readString, path) ?? "",
  };
};

export function getCDRInstances(signal?: AbortSignal): Promise<CDRInstances> {
  return apiRequest(
    "/api/cdr/instances",
    decodeCDRInstances,
    signal !== undefined ? { signal } : {},
  );
}

export interface CDRDeleteResult {
  removed: string;
  /** The ACTIVE orphaned trust identity — Sluice keeps trusting this
   * fingerprint until it expires or is revoked on the Sluice side. "" =
   * unknown (legacy entry whose cert could not be read before the shred). */
  clientCertFingerprint: string;
  /** EVERY still-valid generation Sluice keeps trusting (active first) —
   * the full lineage the local removal orphans. */
  clientCertFingerprints: readonly string[];
}

/** LOCAL-only removal: prunes this appliance's registry and shreds its copy
 * of the credential. Does NOT revoke anything on the Sluice side — after
 * this call the fingerprints in the result are the only remaining handles
 * for revoking the still-trusted credentials there. */
export function deleteCDRInstance(
  name: string,
  signal?: AbortSignal,
): Promise<CDRDeleteResult> {
  return apiRequest(
    `/api/cdr/instances?name=${encodeURIComponent(name)}`,
    (v, path = "$") => {
      const o = readRecord(v, path);
      return {
        removed: field(o, "removed", readString, path),
        clientCertFingerprint: field(
          o,
          "clientCertFingerprint",
          readString,
          path,
        ),
        clientCertFingerprints: field(
          o,
          "clientCertFingerprints",
          readArray(readString),
          path,
        ),
      };
    },
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

export interface CDREnrollInput {
  name: string;
  endpoint: string;
  serverFingerprint: string;
  /** SINGLE-USE secret. Consumed (deleted) by Sluice on a successful
   * exchange — an unknown-outcome enrollment must NEVER be blindly retried
   * with the same token. Never echoed by any read DTO. */
  token: string;
  /** 2E-C R8: the client-minted 128-bit recovery identity, persisted in the
   * browser marker BEFORE dispatch and bound by the appliance + Sluice to
   * the outcome, so a lost response is RESOLVED (recoverCDREnrollment),
   * never guessed. */
  operationId: string;
}

/** Enroll result (R13): the stored registry entry PLUS the actual
 * post-operation facts — CDR enabled or not, a client active or not, and
 * whether the auto-enable was attempted / succeeded / failed. The UI
 * renders conditional copy from these facts; it never assumes. */
export interface CDREnrollResult {
  instance: CDRInstance;
  stored: boolean;
  operationId: string;
  /** stored, or dispatched when the receipt transition could not be
   * persisted (receiptRecorded=false; recovery still classifies LANDED). */
  receiptState: string;
  receiptRecorded: boolean;
  receiptError: string;
  cdrEnabled: boolean;
  clientActive: boolean;
  clientInitError: string;
  autoEnable: { attempted: boolean; succeeded: boolean; error: string };
}

const decodeEnrollResult: Decoder<CDREnrollResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  const auto = readRecord(o["autoEnable"], `${path}.autoEnable`);
  return {
    instance: readInstance(o["instance"], `${path}.instance`),
    stored: field(o, "stored", readBoolean, path),
    operationId: field(o, "operationId", readString, path),
    receiptState: field(o, "receiptState", readString, path),
    receiptRecorded: field(o, "receiptRecorded", readBoolean, path),
    receiptError: opt(o, "receiptError", readString, path) ?? "",
    cdrEnabled: field(o, "cdrEnabled", readBoolean, path),
    clientActive: field(o, "clientActive", readBoolean, path),
    clientInitError: opt(o, "clientInitError", readString, path) ?? "",
    autoEnable: {
      attempted: field(auto, "attempted", readBoolean, `${path}.autoEnable`),
      succeeded: field(auto, "succeeded", readBoolean, `${path}.autoEnable`),
      error: opt(auto, "error", readString, `${path}.autoEnable`) ?? "",
    },
  };
};

/** NON-idempotent trust establishment. The operation id is bound
 * IMMUTABLY by the appliance: a second POST with the same id (any name or
 * endpoint) performs no RPC and is refused (409 naming the recovery
 * path). */
export function enrollCDRInstance(
  input: CDREnrollInput,
  signal?: AbortSignal,
): Promise<CDREnrollResult> {
  return apiRequest("/api/cdr/instances/enroll", decodeEnrollResult, {
    method: "POST",
    body: {
      name: input.name,
      endpoint: input.endpoint,
      serverFingerprint: input.serverFingerprint,
      token: input.token,
      operationId: input.operationId,
    },
    // The Enroll RPC has a 30s server-side deadline; expire after it so a
    // slow-but-successful exchange is not misread as unknown.
    timeoutMs: 35_000,
    ...(signal !== undefined ? { signal } : {}),
  });
}

/** An enrollment failure whose Sluice-side outcome is NOT settled — the
 * appliance names the operation in the body (unknown outcome, an
 * already-issued duplicate, or a local commit failure after issuance) so it
 * can be resolved. A refusal that names no operation issued nothing. */
export function enrollFailureIsUnresolved(
  err: unknown,
  operationId: string,
): boolean {
  return (
    err instanceof ApiError &&
    err.kind === "http" &&
    err.bodyText !== undefined &&
    err.bodyText.includes(operationId)
  );
}

export interface CDRRevokeResult {
  revoked: string;
  fingerprint: string;
  /** Every fingerprint Sluice PROVED a durable deny for. */
  fingerprints: readonly string[];
  /** Per-fingerprint proven outcome: revoked | already_revoked | tombstoned. */
  outcomes: Readonly<Record<string, string>>;
  localPruned: boolean;
}

const decodeRevokeResult: Decoder<CDRRevokeResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  const rawOutcomes = readRecord(o["outcomes"], `${path}.outcomes`);
  const outcomes: Record<string, string> = {};
  for (const [k, val] of Object.entries(rawOutcomes)) {
    outcomes[k] = readString(val, `${path}.outcomes.${k}`);
  }
  return {
    revoked: field(o, "revoked", readString, path),
    fingerprint: field(o, "fingerprint", readString, path),
    fingerprints: field(o, "fingerprints", readArray(readString), path),
    outcomes,
    localPruned: field(o, "localPruned", readBoolean, path),
  };
};

/** Revoke EVERY live credential of the instance ON THE SLUICE SIDE
 * (RevokeClient by fingerprint, one per generation); the appliance prunes
 * locally ONLY after Sluice PROVES a durable deny for each (a response that
 * proves nothing is a 502 and prunes nothing). Per-generation progress is
 * durable, so a retry after a failure or unknown outcome is safe. Requires
 * a second enrolled, reachable instance (self-revocation is refused → 503). */
export function revokeCDRInstance(
  name: string,
  reason: string,
  signal?: AbortSignal,
): Promise<CDRRevokeResult> {
  return apiRequest("/api/cdr/instances/revoke", decodeRevokeResult, {
    method: "POST",
    body: { name, reason },
    timeoutMs: 20_000,
    ...(signal !== undefined ? { signal } : {}),
  });
}

/** Revoke ONE orphaned credential by fingerprint (issued-but-not-stored
 * enrollment, lost renewal). Same proof rule; 503 with the Sluice-host CLI
 * instruction when no pooled client can issue the call. */
export function revokeCDRFingerprint(
  fingerprint: string,
  reason: string,
  signal?: AbortSignal,
): Promise<CDRRevokeResult> {
  return apiRequest("/api/cdr/instances/revoke", decodeRevokeResult, {
    method: "POST",
    body: { fingerprint, reason },
    timeoutMs: 20_000,
    ...(signal !== undefined ? { signal } : {}),
  });
}

// ── Enrollment recovery (POST …/enroll/recover, GET/DELETE …/enroll/receipts) ─

export type CDRRecoveryClassification =
  "LANDED_AND_STORED" | "ISSUED_BUT_NOT_STORED" | "NOT_ISSUED" | "AMBIGUOUS";

export interface CDREnrollRecovery {
  operationId: string;
  classification: CDRRecoveryClassification;
  /** Issued client-cert fingerprint when Sluice reports ISSUED. */
  fingerprint: string;
  /** Sluice already denies the issued fingerprint. */
  revoked: boolean;
  name: string;
  endpoint: string;
  receiptState: string;
  hasReceipt: boolean;
  retryable: boolean;
  error: string;
  /** false when the classification is authoritative but the local receipt
   * transition could not be persisted (the previous durable state is kept;
   * resolve again later). */
  receiptUpdated: boolean;
  receiptError: string;
  /** Exact revocation path for ISSUED_BUT_NOT_STORED. */
  revocation?: { apiAvailable: boolean; cli: string };
}

const decodeRecovery: Decoder<CDREnrollRecovery> = (v, path = "$") => {
  const o = readRecord(v, path);
  const cls = field(o, "classification", readString, path);
  if (
    cls !== "LANDED_AND_STORED" &&
    cls !== "ISSUED_BUT_NOT_STORED" &&
    cls !== "NOT_ISSUED" &&
    cls !== "AMBIGUOUS"
  ) {
    throw new DecodeError(
      `${path}.classification`,
      "a recovery classification",
      cls,
    );
  }
  const out: CDREnrollRecovery = {
    operationId: field(o, "operationId", readString, path),
    classification: cls,
    fingerprint: opt(o, "fingerprint", readString, path) ?? "",
    revoked: field(o, "revoked", readBoolean, path),
    name: opt(o, "name", readString, path) ?? "",
    endpoint: opt(o, "endpoint", readString, path) ?? "",
    receiptState: opt(o, "receiptState", readString, path) ?? "",
    hasReceipt: field(o, "hasReceipt", readBoolean, path),
    retryable: field(o, "retryable", readBoolean, path),
    error: opt(o, "error", readString, path) ?? "",
    receiptUpdated: opt(o, "receiptUpdated", readBoolean, path) ?? true,
    receiptError: opt(o, "receiptError", readString, path) ?? "",
  };
  const rev = o["revocation"];
  if (rev !== undefined && rev !== null) {
    const r = readRecord(rev, `${path}.revocation`);
    out.revocation = {
      apiAvailable: field(r, "apiAvailable", readBoolean, `${path}.revocation`),
      cli: field(r, "cli", readString, `${path}.revocation`),
    };
  }
  return out;
};

/** Fresh authoritative resolution of one enrollment operation through
 * Sluice's EnrollStatus. Mutates only the local receipt; never mints,
 * stores or revokes anything. When a receipt exists its BOUND endpoint and
 * pin are authoritative (a conflicting value is refused with 409 before any
 * network activity); endpoint/pin are consulted only for a receipt-less
 * recovery. */
export function recoverCDREnrollment(
  input: { operationId: string; endpoint?: string; serverFingerprint?: string },
  signal?: AbortSignal,
): Promise<CDREnrollRecovery> {
  return apiRequest("/api/cdr/instances/enroll/recover", decodeRecovery, {
    method: "POST",
    body: {
      operationId: input.operationId,
      ...(input.endpoint !== undefined ? { endpoint: input.endpoint } : {}),
      ...(input.serverFingerprint !== undefined
        ? { serverFingerprint: input.serverFingerprint }
        : {}),
    },
    timeoutMs: 20_000,
    ...(signal !== undefined ? { signal } : {}),
  });
}

export interface CDREnrollReceipt {
  operationId: string;
  name: string;
  endpoint: string;
  serverFingerprint: string;
  /** dispatched | stored | issued_not_stored | not_issued | revoked */
  state: string;
  fingerprint: string;
  actor: string;
  startedAt: string;
  updatedAt: string;
  note: string;
}

/** R12.8: the receipt file's integrity truth — ok=false means the store is
 * DEGRADED (duplicate ids, bad grammar, impossible states, missing identity
 * fields, or more than the cap): no new enrollment is created until the
 * offending records are repaired by position. */
export interface CDREnrollReceiptIntegrity {
  ok: boolean;
  issues: readonly {
    kind: string;
    operationId: string;
    positions: readonly number[];
  }[];
}

export interface CDREnrollReceipts {
  receipts: readonly CDREnrollReceipt[];
  count: number;
  unresolved: number;
  integrity: CDREnrollReceiptIntegrity;
}

export const decodeCDREnrollReceipts: Decoder<CDREnrollReceipts> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const raw = o["receipts"];
  const receipts: CDREnrollReceipt[] = [];
  if (raw !== undefined && raw !== null) {
    for (const [i, item] of readArray((x, p) => readRecord(x, p))(
      raw,
      `${path}.receipts`,
    ).entries()) {
      const p = `${path}.receipts[${i}]`;
      receipts.push({
        operationId: field(item, "operationId", readString, p),
        name: field(item, "name", readString, p),
        endpoint: field(item, "endpoint", readString, p),
        serverFingerprint: field(item, "serverFingerprint", readString, p),
        state: field(item, "state", readString, p),
        fingerprint: opt(item, "fingerprint", readString, p) ?? "",
        actor: opt(item, "actor", readString, p) ?? "",
        startedAt: field(item, "startedAt", readString, p),
        updatedAt: field(item, "updatedAt", readString, p),
        note: opt(item, "note", readString, p) ?? "",
      });
    }
  }
  const integ = readRecord(o["integrity"], `${path}.integrity`);
  const rawIssues = integ["issues"];
  const issues: {
    kind: string;
    operationId: string;
    positions: readonly number[];
  }[] = [];
  if (rawIssues !== undefined && rawIssues !== null) {
    for (const [i, item] of readArray((x, p) => readRecord(x, p))(
      rawIssues,
      `${path}.integrity.issues`,
    ).entries()) {
      const p = `${path}.integrity.issues[${i}]`;
      issues.push({
        kind: field(item, "kind", readString, p),
        operationId: opt(item, "operationId", readString, p) ?? "",
        positions: field(item, "positions", readArray(readNumber), p),
      });
    }
  }
  return {
    receipts,
    count: field(o, "count", readNumber, path),
    unresolved: field(o, "unresolved", readNumber, path),
    integrity: {
      ok: field(integ, "ok", readBoolean, `${path}.integrity`),
      issues,
    },
  };
};

export function getCDREnrollReceipts(
  signal?: AbortSignal,
): Promise<CDREnrollReceipts> {
  return apiRequest(
    "/api/cdr/instances/enroll/receipts",
    decodeCDREnrollReceipts,
    signal !== undefined ? { signal } : {},
  );
}

export function deleteCDREnrollReceipt(
  operationId: string,
  signal?: AbortSignal,
): Promise<{ removed: string }> {
  return apiRequest(
    `/api/cdr/instances/enroll/receipts?operationId=${encodeURIComponent(operationId)}`,
    (v, path = "$") => {
      const o = readRecord(v, path);
      return { removed: field(o, "removed", readString, path) };
    },
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

// ── Policies (GET/POST/DELETE /api/cdr/policies) ────────────────────────────

export interface CDRPolicyRule {
  priority: number;
  name: string;
  enabled: boolean;
  sourceIP: string;
  sourceIdentity: string;
  sourceGroup: string;
  authSource: string;
  destFQDN: string;
  destCategory: string;
  destCategoryGroup: string;
  destCountry: readonly string[];
  profileName: string;
  /** Rendered verbatim — unknown strings are NOT normalized (the engine
   * treats unknown as ENFORCE, fail-safe, but the UI shows the truth). */
  mode: string;
  hitCount: number;
}

function readRule(v: unknown, path: string): CDRPolicyRule {
  const o = readRecord(v, path);
  const dc = o["destCountry"];
  return {
    priority: field(o, "priority", readNumber, path),
    name: field(o, "name", readString, path),
    enabled: opt(o, "enabled", readBoolean, path) ?? true,
    sourceIP: opt(o, "sourceIP", readString, path) ?? "",
    sourceIdentity: opt(o, "sourceIdentity", readString, path) ?? "",
    sourceGroup: opt(o, "sourceGroup", readString, path) ?? "",
    authSource: opt(o, "authSource", readString, path) ?? "",
    destFQDN: opt(o, "destFQDN", readString, path) ?? "",
    destCategory: opt(o, "destCategory", readString, path) ?? "",
    destCategoryGroup: opt(o, "destCategoryGroup", readString, path) ?? "",
    destCountry:
      dc === undefined || dc === null
        ? []
        : field(o, "destCountry", readArray(readString), path),
    profileName: opt(o, "profileName", readString, path) ?? "",
    mode: opt(o, "mode", readString, path) ?? "",
    hitCount: opt(o, "hitCount", readNumber, path) ?? 0,
  };
}

/** 2E-C R10: identity truth of the durable policy store. ok=false means
 * the file on disk carries duplicate or empty rule names (loaded verbatim —
 * nothing silently chosen); while degraded, adding is refused, deleting by
 * an ambiguous name is refused, and the operator repairs BY POSITION. */
export interface CDRPolicyIntegrity {
  ok: boolean;
  issues: readonly {
    kind: string;
    name: string;
    positions: readonly number[];
  }[];
}

export interface CDRPolicies {
  rules: readonly CDRPolicyRule[];
  count: number;
  version: number;
  epoch: number;
  updatedAt: string;
  integrity: CDRPolicyIntegrity;
}

export const decodeCDRPolicies: Decoder<CDRPolicies> = (v, path = "$") => {
  const o = readRecord(v, path);
  const raw = o["rules"];
  const rules: CDRPolicyRule[] = [];
  if (raw !== undefined && raw !== null) {
    for (const [i, item] of readArray((x, p) => readRecord(x, p))(
      raw,
      `${path}.rules`,
    ).entries()) {
      rules.push(readRule(item, `${path}.rules[${i}]`));
    }
  }
  const integ = readRecord(o["integrity"], `${path}.integrity`);
  const rawIssues = integ["issues"];
  const issues: {
    kind: string;
    name: string;
    positions: readonly number[];
  }[] = [];
  if (rawIssues !== undefined && rawIssues !== null) {
    for (const [i, item] of readArray((x, p) => readRecord(x, p))(
      rawIssues,
      `${path}.integrity.issues`,
    ).entries()) {
      const p = `${path}.integrity.issues[${i}]`;
      issues.push({
        kind: field(item, "kind", readString, p),
        name: opt(item, "name", readString, p) ?? "",
        positions: field(item, "positions", readArray(readNumber), p),
      });
    }
  }
  return {
    rules,
    count: field(o, "count", readNumber, path),
    version: field(o, "version", readNumber, path),
    epoch: field(o, "epoch", readNumber, path),
    updatedAt: opt(o, "updatedAt", readString, path) ?? "",
    integrity: {
      ok: field(integ, "ok", readBoolean, `${path}.integrity`),
      issues,
    },
  };
};

export function getCDRPolicies(signal?: AbortSignal): Promise<CDRPolicies> {
  return apiRequest(
    "/api/cdr/policies",
    decodeCDRPolicies,
    signal !== undefined ? { signal } : {},
  );
}

export interface CDRPolicyInput {
  name: string;
  priority: number;
  mode: string;
  profileName: string;
  sourceIP: string;
  sourceIdentity: string;
  sourceGroup: string;
  destFQDN: string;
  destCategory: string;
}

/** Adds one rule. The (unique) name is the rule's identity — a duplicate is
 * a 409 conflict, not a validation error. */
export function addCDRPolicy(
  input: CDRPolicyInput,
  signal?: AbortSignal,
): Promise<CDRPolicyRule> {
  return apiRequest("/api/cdr/policies", (v, path = "$") => readRule(v, path), {
    method: "POST",
    body: input,
    ...(signal !== undefined ? { signal } : {}),
  });
}

export function deleteCDRPolicy(
  name: string,
  signal?: AbortSignal,
): Promise<{ removed: string }> {
  return apiRequest(
    `/api/cdr/policies?name=${encodeURIComponent(name)}`,
    (v, path = "$") => {
      const o = readRecord(v, path);
      return { removed: field(o, "removed", readString, path) };
    },
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

/** Degraded-store repair: delete the rule at `position` (0-based, current
 * order), fenced on its VERBATIM name. Available ONLY while the store is
 * degraded (409 otherwise). */
export function deleteCDRPolicyAt(
  position: number,
  verbatimName: string,
  signal?: AbortSignal,
): Promise<{ removed: string; integrity: CDRPolicyIntegrity }> {
  return apiRequest(
    `/api/cdr/policies?name=${encodeURIComponent(verbatimName)}&position=${String(position)}`,
    (v, path = "$") => {
      const o = readRecord(v, path);
      const integ = readRecord(o["integrity"], `${path}.integrity`);
      return {
        removed: field(o, "removed", readString, path),
        integrity: {
          ok: field(integ, "ok", readBoolean, `${path}.integrity`),
          issues: [],
        },
      };
    },
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

// ── Health (GET /api/cdr/health) ────────────────────────────────────────────

export interface CDRHealthProfile {
  name: string;
  description: string;
  capabilities: readonly string[];
  maxFileSizeBytes: number;
}

export interface CDRHealth {
  healthy: boolean;
  version: string;
  supportedTypes: readonly string[];
  activeWorkers: number;
  maxWorkers: number;
  queueDepth: number;
  filesProcessed: number;
  threatsRemoved: number;
  profiles: readonly CDRHealthProfile[];
  /** When the CACHED snapshot was captured; "" for an on-demand probe. */
  lastSeen: string;
  /** Live poller view — non-zero means the snapshot above may be stale
   * reassurance (the cache is served for up to 3 failed 15s polls). */
  consecutiveFailures: number;
  liveHealthy: boolean;
}

export const decodeCDRHealth: Decoder<CDRHealth> = (v, path = "$") => {
  const o = readRecord(v, path);
  const profRaw = o["profiles"];
  const profiles: CDRHealthProfile[] = [];
  if (profRaw !== undefined && profRaw !== null) {
    for (const [i, item] of readArray((x, p) => readRecord(x, p))(
      profRaw,
      `${path}.profiles`,
    ).entries()) {
      const p = `${path}.profiles[${i}]`;
      const caps = item["capabilities"];
      profiles.push({
        name: field(item, "name", readString, p),
        description: opt(item, "description", readString, p) ?? "",
        capabilities:
          caps === undefined || caps === null
            ? []
            : field(item, "capabilities", readArray(readString), p),
        maxFileSizeBytes: opt(item, "maxFileSizeBytes", readNumber, p) ?? 0,
      });
    }
  }
  const types = o["supportedTypes"];
  return {
    healthy: field(o, "healthy", readBoolean, path),
    version: opt(o, "version", readString, path) ?? "",
    supportedTypes:
      types === undefined || types === null
        ? []
        : field(o, "supportedTypes", readArray(readString), path),
    activeWorkers: opt(o, "activeWorkers", readNumber, path) ?? 0,
    maxWorkers: opt(o, "maxWorkers", readNumber, path) ?? 0,
    queueDepth: opt(o, "queueDepth", readNumber, path) ?? 0,
    filesProcessed: opt(o, "filesProcessed", readNumber, path) ?? 0,
    threatsRemoved: opt(o, "threatsRemoved", readNumber, path) ?? 0,
    profiles,
    lastSeen: opt(o, "lastSeen", readString, path) ?? "",
    consecutiveFailures: opt(o, "consecutiveFailures", readNumber, path) ?? 0,
    liveHealthy: opt(o, "liveHealthy", readBoolean, path) ?? false,
  };
};

export function getCDRHealth(signal?: AbortSignal): Promise<CDRHealth> {
  return apiRequest(
    "/api/cdr/health",
    decodeCDRHealth,
    signal !== undefined ? { signal } : {},
  );
}

// ── Admin test (POST /api/cdr/test) ─────────────────────────────────────────

export interface CDRThreat {
  type: string;
  location: string;
  description: string;
  severity: string;
}

export interface CDRTestResult {
  /** Engine status string, verbatim (CLEAN / SANITIZED / BLOCKED /
   * UNSUPPORTED / ERROR — unknown values render as-is). */
  status: string;
  originalType: string;
  originalSize: number;
  sanitizedSize: number;
  durationMs: number;
  threats: readonly CDRThreat[];
  errorMessage: string;
  sanitizedSha256: string;
}

const decodeTestResult: Decoder<CDRTestResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  const raw = o["threats"];
  const threats: CDRThreat[] = [];
  if (raw !== undefined && raw !== null) {
    for (const [i, item] of readArray((x, p) => readRecord(x, p))(
      raw,
      `${path}.threats`,
    ).entries()) {
      const p = `${path}.threats[${i}]`;
      const t = readRecord(item, p);
      threats.push({
        type:
          opt(t, "Type", readString, p) ?? opt(t, "type", readString, p) ?? "",
        location:
          opt(t, "Location", readString, p) ??
          opt(t, "location", readString, p) ??
          "",
        description:
          opt(t, "Description", readString, p) ??
          opt(t, "description", readString, p) ??
          "",
        severity:
          opt(t, "Severity", readString, p) ??
          opt(t, "severity", readString, p) ??
          "",
      });
    }
  }
  return {
    status: field(o, "status", readString, path),
    originalType: opt(o, "originalType", readString, path) ?? "",
    originalSize: opt(o, "originalSize", readNumber, path) ?? 0,
    sanitizedSize: opt(o, "sanitizedSize", readNumber, path) ?? 0,
    durationMs: opt(o, "durationMs", readNumber, path) ?? 0,
    threats,
    errorMessage: opt(o, "errorMessage", readString, path) ?? "",
    sanitizedSha256: opt(o, "sanitizedSha256", readString, path) ?? "",
  };
};

/** IMPERATIVE admin test: the file runs through Sluice in REPORT_ONLY mode
 * (original bytes are never replaced). Success means only that THIS file
 * was processed by A pooled instance — it is not a claim about production
 * traffic health. Never auto-retried. */
export function testCDRFile(
  file: File,
  signal?: AbortSignal,
): Promise<CDRTestResult> {
  return apiRequest(
    `/api/cdr/test?filename=${encodeURIComponent(file.name)}`,
    decodeTestResult,
    {
      method: "POST",
      rawBody: file,
      rawContentType: file.type !== "" ? file.type : "application/octet-stream",
      // The server bounds the Sanitize call at 60s; expire after it so a
      // slow-but-completed run is not misread as unknown.
      timeoutMs: 65_000,
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}
