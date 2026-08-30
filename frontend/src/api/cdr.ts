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
import { apiRequest } from "./client";
import {
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
}

function readInstance(v: unknown, path: string): CDRInstance {
  const o = readRecord(v, path);
  const out: CDRInstance = {
    name: field(o, "name", readString, path),
    endpoint: field(o, "endpoint", readString, path),
    serverFingerprint: field(o, "serverFingerprint", readString, path),
    clientCertFingerprint:
      opt(o, "clientCertFingerprint", readString, path) ?? "",
    enrolledAt: field(o, "enrolledAt", readString, path),
    version: opt(o, "version", readString, path) ?? "",
    lastHealth: opt(o, "lastHealth", readString, path) ?? "",
    enabled: opt(o, "enabled", readBoolean, path) ?? true,
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
  /** The orphaned trust identity — Sluice keeps trusting this fingerprint
   * until it expires or is revoked on the Sluice side. "" = unknown (legacy
   * entry whose cert could not be read before the shred). */
  clientCertFingerprint: string;
}

/** LOCAL-only removal: prunes this appliance's registry and shreds its copy
 * of the credential. Does NOT revoke anything on the Sluice side — after
 * this call the fingerprint in the result is the only remaining handle for
 * revoking the still-trusted credential there. */
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
        clientCertFingerprint: field(o, "clientCertFingerprint", readString, path),
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
}

/** Enroll response: the stored registry entry (struct-tag JSON keys — same
 * names as the list entries; no token, no key material). */
const decodeEnrollResult: Decoder<CDRInstance> = (v, path = "$") =>
  readInstance(v, path);

/** NON-idempotent trust establishment. First successful enrollment
 * auto-enables CDR (persisted sentinel) — the ceremony copy says so. */
export function enrollCDRInstance(
  input: CDREnrollInput,
  signal?: AbortSignal,
): Promise<CDRInstance> {
  return apiRequest("/api/cdr/instances/enroll", decodeEnrollResult, {
    method: "POST",
    body: {
      name: input.name,
      endpoint: input.endpoint,
      serverFingerprint: input.serverFingerprint,
      token: input.token,
    },
    // The Enroll RPC has a 30s server-side deadline; expire after it so a
    // slow-but-successful exchange is not misread as unknown.
    timeoutMs: 35_000,
    ...(signal !== undefined ? { signal } : {}),
  });
}

export interface CDRRevokeResult {
  revoked: string;
  fingerprint: string;
}

/** Revoke the instance's credential ON THE SLUICE SIDE (RevokeClient by
 * fingerprint), then prune locally. Idempotent at Sluice (an
 * already-revoked/unknown fingerprint still succeeds), so a retry after an
 * unknown outcome is safe. Requires a second enrolled, reachable instance
 * (self-revocation is refused → 503). */
export function revokeCDRInstance(
  name: string,
  reason: string,
  signal?: AbortSignal,
): Promise<CDRRevokeResult> {
  return apiRequest(
    "/api/cdr/instances/revoke",
    (v, path = "$") => {
      const o = readRecord(v, path);
      return {
        revoked: field(o, "revoked", readString, path),
        fingerprint: field(o, "fingerprint", readString, path),
      };
    },
    {
      method: "POST",
      body: { name, reason },
      timeoutMs: 20_000,
      ...(signal !== undefined ? { signal } : {}),
    },
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

export interface CDRPolicies {
  rules: readonly CDRPolicyRule[];
  count: number;
  version: number;
  epoch: number;
  updatedAt: string;
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
  return {
    rules,
    count: field(o, "count", readNumber, path),
    version: field(o, "version", readNumber, path),
    epoch: field(o, "epoch", readNumber, path),
    updatedAt: opt(o, "updatedAt", readString, path) ?? "",
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
  return apiRequest(
    "/api/cdr/policies",
    (v, path = "$") => readRule(v, path),
    {
      method: "POST",
      body: input,
      ...(signal !== undefined ? { signal } : {}),
    },
  );
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
        type: opt(t, "Type", readString, p) ?? opt(t, "type", readString, p) ?? "",
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
