// 2E-B Decryption Operations API: the read-only decryption health aggregate,
// the NODE-LOCAL destination-privacy posture (incl. pseudonym-key rotation),
// and the volatile auto-exclusion cache + its durable tunables.
//
// Contract highlights (2E-B backend hardening):
//   - DESTINATION PRIVACY is about what destination information is retained in
//     logs/observability — NOT whether traffic is decrypted, and the pseudonym
//     key is NOT the TLS inspection Root CA. Node-local (outside
//     export/import, rollback, and CP→DP sync).
//   - FENCES: the privacy PUT and the tunables PUT assert the server's
//     content-derived revision (body ifRevision / query ?ifRevision=); a
//     mismatch is the shared structured 409. This client ALWAYS asserts.
//   - ROTATION OPERATION IDENTITY (2E-B correction): every rotation carries a
//     client-minted opaque operation_id; the appliance records a bounded
//     durable NON-SECRET receipt {operation_id, key_id, seq} atomically with
//     the rotation plus a monotonic rotation_seq. An unknown-outcome rotation
//     is resolved against fresh GET truth PER OPERATION: our receipt present
//     = landed exactly once; sequence unchanged = did not land; sequence
//     advanced without our receipt = AMBIGUOUS (another admin may have
//     rotated) — never "landed because key_id changed", never a blind retry.
//     A replay of the same operation_id is answered idempotently
//     (already_applied) and cannot rotate twice. No key material ever
//     reaches this client.
//   - AUTO-EXCLUSIONS are VOLATILE runtime state (drop-and-relearn): eviction
//     and clear-all carry no fence and no durability claim; the response
//     truthfully reports removed/cleared. Reads are bounded via ?limit=.
//   - HEALTH counters are process-lifetime (reset on restart); the trend is
//     per-minute deltas over the last 6h. Unknown taxonomy keys are rendered
//     verbatim — never coerced to a healthy value.
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

// ── Decryption health (GET /api/decryption/health) ──────────────────────────

/** String-keyed counter map (taxonomy keys are server-owned; unknown keys are
 * preserved verbatim). */
export type CounterMap = Readonly<Record<string, number>>;

function readCounterMap(v: unknown, path: string): CounterMap {
  if (v === undefined || v === null) return {};
  const o = readRecord(v, path);
  const out: Record<string, number> = {};
  for (const k of Object.keys(o)) {
    out[k] = readNumber(o[k], `${path}.${k}`);
  }
  return out;
}

export interface DecTopFailure {
  category: string;
  stage: string;
  count: number;
}

export interface DecTrendSample {
  ts: number;
  inspected: number;
  bypassed: number;
  failed: number;
  ratio: number;
}

export interface DecryptionHealth {
  sessionsTotal: number;
  byOutcome: CounterMap;
  byDecisionSource: CounterMap;
  byTLSVersion: CounterMap;
  failuresTotal: number;
  byCategory: CounterMap;
  byStage: CounterMap;
  topFailures: readonly DecTopFailure[];
  inspected: number;
  bypassed: number;
  failed: number;
  inspectedRatio: number;
  trend: readonly DecTrendSample[];
  autoexcludeActive: number;
  autoexcludePending: number;
  autoexcludeHits: number;
  autoexcludeRescues: number;
  failOpenProfiles: number;
  failOpenRules: number;
}

export const decodeDecryptionHealth: Decoder<DecryptionHealth> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const sessions = readRecord(o["sessions"], `${path}.sessions`);
  const failures = readRecord(o["failures"], `${path}.failures`);
  const coverage = readRecord(o["coverage"], `${path}.coverage`);
  const ae = readRecord(o["autoexclude"], `${path}.autoexclude`);
  const topRaw = failures["top"];
  const top: DecTopFailure[] = [];
  if (topRaw !== undefined && topRaw !== null) {
    for (const [i, item] of readArray((x, p) => readRecord(x, p))(
      topRaw,
      `${path}.failures.top`,
    ).entries()) {
      top.push({
        category: field(item, "category", readString, `${path}.top[${i}]`),
        stage: field(item, "stage", readString, `${path}.top[${i}]`),
        count: field(item, "count", readNumber, `${path}.top[${i}]`),
      });
    }
  }
  const trendRaw = o["trend"];
  const trend: DecTrendSample[] = [];
  if (trendRaw !== undefined && trendRaw !== null) {
    for (const [i, item] of readArray((x, p) => readRecord(x, p))(
      trendRaw,
      `${path}.trend`,
    ).entries()) {
      trend.push({
        ts: field(item, "ts", readNumber, `${path}.trend[${i}]`),
        inspected: field(item, "inspected", readNumber, `${path}.trend[${i}]`),
        bypassed: field(item, "bypassed", readNumber, `${path}.trend[${i}]`),
        failed: field(item, "failed", readNumber, `${path}.trend[${i}]`),
        ratio: field(item, "ratio", readNumber, `${path}.trend[${i}]`),
      });
    }
  }
  return {
    sessionsTotal: field(sessions, "total", readNumber, `${path}.sessions`),
    byOutcome: readCounterMap(sessions["by_outcome"], `${path}.by_outcome`),
    byDecisionSource: readCounterMap(
      sessions["by_decision_source"],
      `${path}.by_decision_source`,
    ),
    byTLSVersion: readCounterMap(
      sessions["by_tls_version"],
      `${path}.by_tls_version`,
    ),
    failuresTotal: field(failures, "total", readNumber, `${path}.failures`),
    byCategory: readCounterMap(failures["by_category"], `${path}.by_category`),
    byStage: readCounterMap(failures["by_stage"], `${path}.by_stage`),
    topFailures: top,
    inspected: field(coverage, "inspected", readNumber, `${path}.coverage`),
    bypassed: field(coverage, "bypassed", readNumber, `${path}.coverage`),
    failed: field(coverage, "failed", readNumber, `${path}.coverage`),
    inspectedRatio: field(
      coverage,
      "inspected_ratio",
      readNumber,
      `${path}.coverage`,
    ),
    trend,
    autoexcludeActive: field(ae, "active", readNumber, `${path}.autoexclude`),
    autoexcludePending: field(ae, "pending", readNumber, `${path}.autoexclude`),
    autoexcludeHits: field(ae, "hit_total", readNumber, `${path}.autoexclude`),
    autoexcludeRescues: field(
      ae,
      "rescue_total",
      readNumber,
      `${path}.autoexclude`,
    ),
    failOpenProfiles: field(
      ae,
      "fail_open_profiles",
      readNumber,
      `${path}.autoexclude`,
    ),
    failOpenRules: field(
      ae,
      "fail_open_rules",
      readNumber,
      `${path}.autoexclude`,
    ),
  };
};

export function getDecryptionHealth(
  signal?: AbortSignal,
): Promise<DecryptionHealth> {
  return apiRequest(
    "/api/decryption/health",
    decodeDecryptionHealth,
    signal !== undefined ? { signal } : {},
  );
}

// ── Destination privacy (GET/PUT /api/decryption/redaction) ─────────────────

/** NON-SECRET durable record of ONE landed rotation operation. */
export interface RotationReceipt {
  operationId: string;
  keyId: string;
  seq: number;
}

export interface DestinationPrivacy {
  redactHosts: boolean;
  scope: string;
  scopeFields: readonly string[];
  keyProvisioned: boolean;
  /** NON-SECRET pseudonym generation; "" when no key is installed. Changes
   * iff a new key installs — display truth, NOT operation attribution. */
  keyId: string;
  /** Durable monotonic key-generation sequence: unchanged ⇒ no rotation
   * landed in between (the NOT-LANDED half of unknown-outcome truth). */
  rotationSeq: number;
  /** Bounded receipts of client-identified rotations — a lost-response
   * rotation is LANDED iff OUR operation id appears here. */
  receipts: readonly RotationReceipt[];
  revision: string;
}

export const decodeDestinationPrivacy: Decoder<DestinationPrivacy> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const sf = o["scope_fields"];
  const receiptsRaw = field(
    o,
    "rotation_receipts",
    readArray((x, p) => readRecord(x, p)),
    path,
  );
  const receipts: RotationReceipt[] = [];
  for (const [i, r] of receiptsRaw.entries()) {
    const p = `${path}.rotation_receipts[${i}]`;
    receipts.push({
      operationId: field(r, "operation_id", readString, p),
      keyId: field(r, "key_id", readString, p),
      seq: field(r, "seq", readNumber, p),
    });
  }
  return {
    redactHosts: field(o, "redact_hosts", readBoolean, path),
    scope: opt(o, "scope", readString, path) ?? "",
    scopeFields:
      sf === undefined || sf === null
        ? []
        : field(o, "scope_fields", readArray(readString), path),
    keyProvisioned: field(o, "key_provisioned", readBoolean, path),
    keyId: field(o, "key_id", readString, path),
    rotationSeq: field(o, "rotation_seq", readNumber, path),
    receipts,
    revision: field(o, "revision", readString, path),
  };
};

export interface PrivacyWriteResult {
  redactHosts: boolean;
  keyRotated: boolean;
  keyId: string;
  rotationSeq: number;
  /** Rotation responses only: true when this operation had already landed
   * and the appliance answered from its receipt (nothing was mutated). */
  alreadyApplied: boolean;
  /** Rotation responses only: echo of the operation identity. */
  operationId: string;
  revision: string;
}

const decodePrivacyWriteResult: Decoder<PrivacyWriteResult> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    redactHosts: field(o, "redact_hosts", readBoolean, path),
    keyRotated: field(o, "key_rotated", readBoolean, path),
    keyId: field(o, "key_id", readString, path),
    rotationSeq: field(o, "rotation_seq", readNumber, path),
    alreadyApplied: opt(o, "already_applied", readBoolean, path) ?? false,
    operationId: opt(o, "operation_id", readString, path) ?? "",
    revision: field(o, "revision", readString, path),
  };
};

/** Mints a fresh opaque rotation operation id (16 hex chars, browser
 * entropy). One id names ONE operation: minted when a rotation ceremony
 * opens, retired with it — never reused for a later rotation. */
export function mintRotationOperationId(): string {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function getDestinationPrivacy(
  signal?: AbortSignal,
): Promise<DestinationPrivacy> {
  return apiRequest(
    "/api/decryption/redaction",
    decodeDestinationPrivacy,
    signal !== undefined ? { signal } : {},
  );
}

/** Fenced posture write. Never rotates a key. */
export function putDestinationPrivacy(
  redactHosts: boolean,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<PrivacyWriteResult> {
  return apiRequest("/api/decryption/redaction", decodePrivacyWriteResult, {
    method: "PUT",
    body: { redact_hosts: redactHosts, ifRevision },
    ...(signal !== undefined ? { signal } : {}),
  });
}

/** Fenced, operation-identified pseudonym-key rotation (T3). The appliance
 * records a durable receipt for operationId atomically with the rotation, so
 * a lost response is resolved from fresh GET truth per operation; a replay of
 * the same id is idempotent (already_applied) and cannot rotate twice, and a
 * DIFFERENT operation on stale truth is a structured 409. NEVER dispatch
 * this from a generic retry path. */
export function rotatePseudonymKey(
  operationId: string,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<PrivacyWriteResult> {
  return apiRequest("/api/decryption/redaction", decodePrivacyWriteResult, {
    method: "PUT",
    body: { rotate_key: true, operation_id: operationId, ifRevision },
    ...(signal !== undefined ? { signal } : {}),
  });
}

// ── Auto-exclusions (GET/DELETE /api/decryption-exclusions) ─────────────────

export interface AutoExclusionEntry {
  scopeId: string;
  scopeName: string;
  host: string;
  reason: string;
  learnedAt: string;
  expiresAt: string;
  hits: number;
  clientCount: number;
}

export interface AutoExcludeStats {
  active: number;
  pending: number;
  confirmN: number;
  ttlSecs: number;
  pinnedTtlSecs: number;
  windowSecs: number;
  maxEntries: number;
}

export interface AutoExclusions {
  exclusions: readonly AutoExclusionEntry[];
  truncated: boolean;
  stats: AutoExcludeStats;
  /** The fence the tunables PUT asserts — derived from the SAME stats
   * snapshot as the current values above (coherent pair). */
  tunablesRevision: string;
  failOpenProfiles: number;
  failOpenRules: number;
  /** scope_id → current profile display name; a missing id means the owning
   * profile was deleted (render the entry's cached scopeName + a badge). */
  scopeNames: Readonly<Record<string, string>>;
  scopeRuleCounts: Readonly<Record<string, number>>;
}

export const decodeAutoExclusions: Decoder<AutoExclusions> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const stats = readRecord(o["stats"], `${path}.stats`);
  const entriesRaw = o["exclusions"];
  const entries: AutoExclusionEntry[] = [];
  if (entriesRaw !== undefined && entriesRaw !== null) {
    for (const [i, item] of readArray((x, p) => readRecord(x, p))(
      entriesRaw,
      `${path}.exclusions`,
    ).entries()) {
      const p = `${path}.exclusions[${i}]`;
      entries.push({
        scopeId: field(item, "scope_id", readString, p),
        scopeName: field(item, "scope_name", readString, p),
        host: field(item, "host", readString, p),
        reason: field(item, "reason", readString, p),
        learnedAt: field(item, "learned_at", readString, p),
        expiresAt: field(item, "expires_at", readString, p),
        hits: field(item, "hits", readNumber, p),
        clientCount: field(item, "client_count", readNumber, p),
      });
    }
  }
  const strMap = (key: string): Record<string, string> => {
    const raw = o[key];
    const out: Record<string, string> = {};
    if (raw === undefined || raw === null) return out;
    const m = readRecord(raw, `${path}.${key}`);
    for (const k of Object.keys(m))
      out[k] = readString(m[k], `${path}.${key}.${k}`);
    return out;
  };
  const numMap = (key: string): Record<string, number> => {
    const raw = o[key];
    const out: Record<string, number> = {};
    if (raw === undefined || raw === null) return out;
    const m = readRecord(raw, `${path}.${key}`);
    for (const k of Object.keys(m))
      out[k] = readNumber(m[k], `${path}.${key}.${k}`);
    return out;
  };
  return {
    exclusions: entries,
    truncated: opt(o, "truncated", readBoolean, path) ?? false,
    stats: {
      active: field(stats, "active", readNumber, `${path}.stats`),
      pending: field(stats, "pending", readNumber, `${path}.stats`),
      confirmN: field(stats, "confirm_n", readNumber, `${path}.stats`),
      ttlSecs: field(stats, "ttl_secs", readNumber, `${path}.stats`),
      pinnedTtlSecs: field(
        stats,
        "pinned_ttl_secs",
        readNumber,
        `${path}.stats`,
      ),
      windowSecs: field(stats, "window_secs", readNumber, `${path}.stats`),
      maxEntries: field(stats, "max_entries", readNumber, `${path}.stats`),
    },
    tunablesRevision: field(o, "tunables_revision", readString, path),
    failOpenProfiles: field(o, "fail_open_profiles", readNumber, path),
    failOpenRules: field(o, "fail_open_rules", readNumber, path),
    scopeNames: strMap("scope_names"),
    scopeRuleCounts: numMap("scope_rule_counts"),
  };
};

/** Bounded management read: the v2 UI always passes a limit. */
export function getAutoExclusions(
  limit: number,
  signal?: AbortSignal,
): Promise<AutoExclusions> {
  return apiRequest(
    `/api/decryption-exclusions?limit=${String(limit)}`,
    decodeAutoExclusions,
    signal !== undefined ? { signal } : {},
  );
}

/** VOLATILE eviction — no fence, no durability claim; removed=false means the
 * entry was already gone (both outcomes are success; refresh shows truth). */
export function evictAutoExclusion(
  scope: string,
  host: string,
  signal?: AbortSignal,
): Promise<{ removed: boolean }> {
  return apiRequest(
    `/api/decryption-exclusions?scope=${encodeURIComponent(scope)}&host=${encodeURIComponent(host)}`,
    (v, path = "$") => {
      const o = readRecord(v, path);
      return { removed: field(o, "removed", readBoolean, path) };
    },
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

/** VOLATILE clear-all. Affected destinations may be attempted for decryption
 * again and can be re-learned; no policy object is deleted. */
export function clearAutoExclusions(
  signal?: AbortSignal,
): Promise<{ cleared: number }> {
  return apiRequest(
    "/api/decryption-exclusions",
    (v, path = "$") => {
      const o = readRecord(v, path);
      return { cleared: field(o, "cleared", readNumber, path) };
    },
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

// ── Tunables (GET/PUT /api/decryption-exclusions/tunables) ──────────────────

export interface TunableBounds {
  min: number;
  max: number;
}

export interface TunablesMeta {
  defaults: AutoExcludeTunablesValues;
  bounds: Readonly<Record<string, TunableBounds>>;
}

export interface AutoExcludeTunablesValues {
  confirmN: number;
  ttlSecs: number;
  pinnedTtlSecs: number;
  windowSecs: number;
  maxEntries: number;
}

function readTunableValues(
  o: Record<string, unknown>,
  path: string,
): AutoExcludeTunablesValues {
  return {
    confirmN: field(o, "confirm_n", readNumber, path),
    ttlSecs: field(o, "ttl_secs", readNumber, path),
    pinnedTtlSecs: field(o, "pinned_ttl_secs", readNumber, path),
    windowSecs: field(o, "window_secs", readNumber, path),
    maxEntries: field(o, "max_entries", readNumber, path),
  };
}

export const decodeTunablesMeta: Decoder<TunablesMeta> = (v, path = "$") => {
  const o = readRecord(v, path);
  const defaults = readRecord(o["defaults"], `${path}.defaults`);
  const boundsRaw = readRecord(o["bounds"], `${path}.bounds`);
  const bounds: Record<string, TunableBounds> = {};
  for (const k of Object.keys(boundsRaw)) {
    const b = readRecord(boundsRaw[k], `${path}.bounds.${k}`);
    bounds[k] = {
      min: field(b, "min", readNumber, `${path}.bounds.${k}`),
      max: field(b, "max", readNumber, `${path}.bounds.${k}`),
    };
  }
  return { defaults: readTunableValues(defaults, `${path}.defaults`), bounds };
};

export function getTunablesMeta(signal?: AbortSignal): Promise<TunablesMeta> {
  return apiRequest(
    "/api/decryption-exclusions/tunables",
    decodeTunablesMeta,
    signal !== undefined ? { signal } : {},
  );
}

export interface TunablesWriteResult extends AutoExcludeTunablesValues {
  revision: string;
}

/** Fenced full replacement (durable + applied on 2xx). */
export function putTunables(
  values: AutoExcludeTunablesValues,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<TunablesWriteResult> {
  return apiRequest(
    `/api/decryption-exclusions/tunables?ifRevision=${encodeURIComponent(ifRevision)}`,
    (v, path = "$") => {
      const o = readRecord(v, path);
      return {
        ...readTunableValues(o, path),
        revision: field(o, "revision", readString, path),
      };
    },
    {
      method: "PUT",
      body: {
        confirm_n: values.confirmN,
        ttl_secs: values.ttlSecs,
        pinned_ttl_secs: values.pinnedTtlSecs,
        window_secs: values.windowSecs,
        max_entries: values.maxEntries,
      },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}
