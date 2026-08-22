// FE-4 operational API surface + runtime decoders (ADR-FE-002: snapshots and
// bounded queries ONLY — no /api/events, no EventSource, no streams). Every
// payload crosses a runtime decoder; unknown fields are ignored, missing or
// invalid required fields fail closed into the standard surface error, and
// decoder work on log/audit pages is bounded by the server page size.
import { apiRequest } from "./client";
import {
  field,
  readArray,
  readBoolean,
  readNumber,
  readOptional,
  readRecord,
  readString,
} from "./decode";
import { DecodeError } from "./decode";
import type { Decoder } from "./decode";

// Every FE-4 GET accepts the caller's AbortSignal so the FE-3 §6.4 boundary
// (QueryClient.cancelQueries) — and any owner teardown — propagates to the
// network layer. TanStack only aborts fetches whose queryFn CONSUMED the
// signal, so consuming it here is load-bearing, not optional.
const sigOpts = (signal?: AbortSignal): { signal?: AbortSignal } =>
  signal !== undefined ? { signal } : {};

// ── /api/stats ─────────────────────────────────────────────────────────────

export interface Stats {
  total: number;
  allowed: number;
  blocked: number;
  authFail: number;
  blocklistSz: number;
  uptime: string;
  serverTime: string;
  c2Mode: string;
  logWriteErrors: number;
  auditLogWriteErrors: number;
  processLogWriteErrors: number;
  auditLogConfigured: boolean;
  auditLogPersisted: boolean;
  requestLogConfigured: boolean;
  requestLogPersisted: boolean;
  configPublishRejected: string;
}

export const decodeStats: Decoder<Stats> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    total: field(o, "total", readNumber, path),
    allowed: field(o, "allowed", readNumber, path),
    blocked: field(o, "blocked", readNumber, path),
    authFail: field(o, "authFail", readNumber, path),
    blocklistSz: field(o, "blocklistSz", readNumber, path),
    uptime: field(o, "uptime", readString, path),
    serverTime: field(o, "serverTime", readString, path),
    c2Mode: field(o, "c2Mode", readString, path),
    logWriteErrors: field(o, "logWriteErrors", readNumber, path),
    auditLogWriteErrors: field(o, "auditLogWriteErrors", readNumber, path),
    processLogWriteErrors: field(o, "processLogWriteErrors", readNumber, path),
    auditLogConfigured: field(o, "auditLogConfigured", readBoolean, path),
    auditLogPersisted: field(o, "auditLogPersisted", readBoolean, path),
    requestLogConfigured: field(o, "requestLogConfigured", readBoolean, path),
    requestLogPersisted: field(o, "requestLogPersisted", readBoolean, path),
    configPublishRejected: field(o, "configPublishRejected", readString, path),
  };
};

export function getStats(signal?: AbortSignal): Promise<Stats> {
  return apiRequest("/api/stats", decodeStats, sigOpts(signal));
}

// ── /api/timeseries (60 one-minute buckets) ────────────────────────────────

export interface Timeseries {
  data: readonly number[];
  allowed: readonly number[];
  blocked: readonly number[];
}

export const decodeTimeseries: Decoder<Timeseries> = (v, path = "$") => {
  const o = readRecord(v, path);
  const nums = readArray(readNumber);
  return {
    data: field(o, "data", nums, path),
    allowed: field(o, "allowed", nums, path),
    blocked: field(o, "blocked", nums, path),
  };
};

export function getTimeseries(signal?: AbortSignal): Promise<Timeseries> {
  return apiRequest("/api/timeseries", decodeTimeseries, sigOpts(signal));
}

// ── /api/dashboard/health ──────────────────────────────────────────────────

export interface DashboardHealth {
  memAllocMB: number;
  goroutines: number;
  blocklistSize: number;
  logStoreEnabled: boolean;
}

export const decodeDashboardHealth: Decoder<DashboardHealth> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const ls = field(o, "logStore", readRecord, path);
  return {
    memAllocMB: field(o, "memAllocMB", readNumber, path),
    goroutines: field(o, "goroutines", readNumber, path),
    blocklistSize: field(o, "blocklistSize", readNumber, path),
    logStoreEnabled: field(ls, "enabled", readBoolean, `${path}.logStore`),
  };
};

export function getDashboardHealth(
  signal?: AbortSignal,
): Promise<DashboardHealth> {
  return apiRequest(
    "/api/dashboard/health",
    decodeDashboardHealth,
    sigOpts(signal),
  );
}

// ── /api/dashboard/threats ─────────────────────────────────────────────────

export interface DashboardThreats {
  clamav: number;
  yara: number;
  dpi: number;
  threatFeed: number;
}

export const decodeDashboardThreats: Decoder<DashboardThreats> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    clamav: field(o, "clamav", readNumber, path),
    yara: field(o, "yara", readNumber, path),
    dpi: field(o, "dpi", readNumber, path),
    threatFeed: field(o, "threatFeed", readNumber, path),
  };
};

export function getDashboardThreats(
  signal?: AbortSignal,
): Promise<DashboardThreats> {
  return apiRequest(
    "/api/dashboard/threats",
    decodeDashboardThreats,
    sigOpts(signal),
  );
}

// ── /api/dashboard/top-rules ───────────────────────────────────────────────

export interface TopRule {
  name: string;
  action: string;
  hits: number;
}

export const decodeTopRules: Decoder<readonly TopRule[]> = (v, path = "$") => {
  const o = readRecord(v, path);
  return field(
    o,
    "rules",
    readArray((rv, rp = "$") => {
      const r = readRecord(rv, rp);
      return {
        name: field(r, "name", readString, rp),
        action: field(r, "action", readString, rp),
        hits: field(r, "hits", readNumber, rp),
      };
    }),
    path,
  );
};

export function getTopRules(signal?: AbortSignal): Promise<readonly TopRule[]> {
  return apiRequest(
    "/api/dashboard/top-rules",
    decodeTopRules,
    sigOpts(signal),
  );
}

// ── /api/logs (Monitor cursor contract, ADR-FE-002) ────────────────────────

export interface TrafficDec {
  outcome: string;
  decisionSource: string;
  failCategory: string;
  profileId: string;
}

export interface TrafficEntry {
  ts: number;
  time: string;
  ip: string;
  identity: string;
  method: string;
  host: string;
  uri: string;
  status: string;
  level: string;
  ruleMatched: string;
  ruleId: string;
  actionTaken: string;
  bytesSent: number;
  bytesRecv: number;
  sslAction: string;
  durationMs: number;
  authSource: string;
  authOutcome: string;
  dec: TrafficDec | null;
}

const optStr = readOptional(readString);
const optNum = readOptional(readNumber);

/** The legacy Go handlers (`/api/logs` memory mode, `/api/audit`) encode an
 * EMPTY result set as JSON `null` (Go nil slice). Tolerate exactly that —
 * null means "no rows", anything else still fails closed. */
function readArrayOrNull<T>(decode: Decoder<T>): Decoder<readonly T[]> {
  const arr = readArray(decode);
  return (v, path = "$") => (v === null ? [] : arr(v, path));
}

export const decodeTrafficEntry: Decoder<TrafficEntry> = (v, path = "$") => {
  const o = readRecord(v, path);
  const decRaw = field(o, "dec", readOptional(readRecord), path);
  let dec: TrafficDec | null = null;
  if (decRaw !== undefined) {
    const dp = `${path}.dec`;
    dec = {
      outcome: field(decRaw, "outcome", readString, dp),
      decisionSource: field(decRaw, "decision_source", readString, dp),
      failCategory: field(decRaw, "fail_category", optStr, dp) ?? "",
      profileId: field(decRaw, "profile_id", optStr, dp) ?? "",
    };
  }
  return {
    ts: field(o, "ts", readNumber, path),
    time: field(o, "time", readString, path),
    ip: field(o, "ip", readString, path),
    identity: field(o, "identity", optStr, path) ?? "",
    method: field(o, "method", readString, path),
    host: field(o, "host", readString, path),
    uri: field(o, "uri", optStr, path) ?? "",
    status: field(o, "status", readString, path),
    level: field(o, "level", readString, path),
    ruleMatched: field(o, "ruleMatched", optStr, path) ?? "",
    ruleId: field(o, "ruleId", optStr, path) ?? "",
    actionTaken: field(o, "actionTaken", optStr, path) ?? "",
    bytesSent: field(o, "bytesSent", optNum, path) ?? 0,
    bytesRecv: field(o, "bytesRecv", optNum, path) ?? 0,
    sslAction: field(o, "sslAction", optStr, path) ?? "",
    durationMs: field(o, "durationMs", optNum, path) ?? 0,
    authSource: field(o, "auth_source", optStr, path) ?? "",
    authOutcome: field(o, "auth_outcome", optStr, path) ?? "",
    dec,
  };
};

export interface TrafficPage {
  logs: readonly TrafficEntry[];
  nextCursor: string;
  /** more results exist (scanLimited=false: a further MATCH is proven;
   * scanLimited=true: more HISTORY remains to be SEARCHED) */
  hasMore: boolean;
  /** the server's raw-scan budget stopped this walk before the window was
   * exhausted; nextCursor continues the bounded search (issued even when
   * zero rows were returned — forward progress is guaranteed) */
  scanLimited: boolean;
  history: boolean;
  snapshotAt: string;
  limit: number;
}

export const decodeTrafficPage: Decoder<TrafficPage> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    logs: field(o, "logs", readArray(decodeTrafficEntry), path),
    nextCursor: field(o, "next_cursor", readString, path),
    hasMore: field(o, "has_more", readBoolean, path),
    scanLimited: field(o, "scan_limited", readBoolean, path),
    history: field(o, "history", readBoolean, path),
    snapshotAt: field(o, "snapshot_at", readString, path),
    limit: field(o, "limit", readNumber, path),
  };
};

export interface TrafficQuery {
  fromSec: number;
  toSec: number;
  filter?: string;
  status?: string;
  method?: string;
  identity?: string;
  cursor?: string;
  limit?: number;
}

/** History (Badger store) traffic query — the ADR-FE-002 cursor contract.
 * The `cursor` parameter is always present (empty = first page). */
export function getTrafficHistory(
  q: TrafficQuery,
  signal?: AbortSignal,
): Promise<TrafficPage> {
  const p = new URLSearchParams();
  p.set("source", "store");
  p.set("from", String(q.fromSec));
  p.set("to", String(q.toSec));
  p.set("cursor", q.cursor ?? "");
  if (q.filter !== undefined && q.filter !== "") p.set("filter", q.filter);
  if (q.status !== undefined && q.status !== "") p.set("status", q.status);
  if (q.method !== undefined && q.method !== "") p.set("method", q.method);
  if (q.identity !== undefined && q.identity !== "")
    p.set("identity", q.identity);
  if (q.limit !== undefined) p.set("limit", String(q.limit));
  const opts = signal !== undefined ? { signal } : {};
  return apiRequest(`/api/logs?${p.toString()}`, decodeTrafficPage, opts);
}

/** Recent-memory fallback (in-memory ring) — a DIFFERENT, clearly-labelled
 * data source, used only when persistent history is disabled. Bounded. */
export function getTrafficMemory(
  q: Omit<TrafficQuery, "cursor">,
  signal?: AbortSignal,
): Promise<{ logs: readonly TrafficEntry[]; total: number }> {
  const p = new URLSearchParams();
  p.set("from", String(q.fromSec));
  p.set("to", String(q.toSec));
  p.set("limit", String(q.limit ?? 100));
  if (q.filter !== undefined && q.filter !== "") p.set("filter", q.filter);
  if (q.status !== undefined && q.status !== "") p.set("status", q.status);
  if (q.method !== undefined && q.method !== "") p.set("method", q.method);
  if (q.identity !== undefined && q.identity !== "")
    p.set("identity", q.identity);
  const opts = signal !== undefined ? { signal } : {};
  return apiRequest(
    `/api/logs?${p.toString()}`,
    (v, path = "$") => {
      const o = readRecord(v, path);
      return {
        logs: field(o, "logs", readArrayOrNull(decodeTrafficEntry), path),
        total: field(o, "total", readNumber, path),
      };
    },
    opts,
  );
}

// ── /api/audit ─────────────────────────────────────────────────────────────

export interface AuditRecord {
  ts: number;
  time: string;
  actor: string;
  action: string;
  object: string;
  objectId: string;
  detail: string;
  before: string;
  after: string;
}

export const decodeAuditRecord: Decoder<AuditRecord> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    ts: field(o, "ts", readNumber, path),
    time: field(o, "time", readString, path),
    actor: field(o, "actor", readString, path),
    action: field(o, "action", readString, path),
    object: field(o, "object", readString, path),
    objectId: field(o, "objectId", optStr, path) ?? "",
    detail: field(o, "detail", readString, path),
    before: field(o, "before", optStr, path) ?? "",
    after: field(o, "after", optStr, path) ?? "",
  };
};

export interface AuditPage {
  entries: readonly AuditRecord[];
  total: number;
  offset: number;
  limit: number;
}

export function getAudit(
  q: {
    offset: number;
    limit: number;
    fromMs: number;
    toMs: number;
    source: "memory" | "file";
  },
  signal?: AbortSignal,
): Promise<AuditPage> {
  const p = new URLSearchParams();
  p.set("offset", String(q.offset));
  p.set("limit", String(q.limit));
  p.set("from", String(q.fromMs));
  p.set("to", String(q.toMs));
  if (q.source === "file") p.set("source", "file");
  return apiRequest(
    `/api/audit?${p.toString()}`,
    (v, path = "$") => {
      const o = readRecord(v, path);
      return {
        entries: field(o, "entries", readArrayOrNull(decodeAuditRecord), path),
        total: field(o, "total", readNumber, path),
        offset: field(o, "offset", readNumber, path),
        limit: field(o, "limit", readNumber, path),
      };
    },
    sigOpts(signal),
  );
}

// ── /api/diagnostics (operator contract snapshot) ──────────────────────────

export interface ContractCheck {
  code: string;
  status: "ok" | "warn" | "fail";
  message: string;
  operatorAction: string;
}

export interface OperatorContract {
  verdict: "ok" | "warn" | "fail";
  generatedAt: string;
  checks: readonly ContractCheck[];
}

const readVerdict = (v: unknown, path = "$"): "ok" | "warn" | "fail" => {
  const s = readString(v, path);
  if (s === "ok" || s === "warn" || s === "fail") return s;
  throw new DecodeError(path, "ok|warn|fail", v);
};

export const decodeOperatorContract: Decoder<OperatorContract> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    verdict: field(o, "verdict", readVerdict, path),
    generatedAt: field(o, "generated_at", readString, path),
    checks: field(
      o,
      "checks",
      readArray((cv, cp = "$") => {
        const c = readRecord(cv, cp);
        return {
          code: field(c, "code", readString, cp),
          status: field(c, "status", readVerdict, cp),
          message: field(c, "message", readString, cp),
          operatorAction: field(c, "operator_action", optStr, cp) ?? "",
        };
      }),
      path,
    ),
  };
};

export function getDiagnostics(
  signal?: AbortSignal,
): Promise<OperatorContract> {
  return apiRequest(
    "/api/diagnostics",
    decodeOperatorContract,
    sigOpts(signal),
  );
}

// ── /api/governance/control-plane (admin) ──────────────────────────────────

export interface GovernanceIssue {
  code: string;
  severity: string;
  count: number;
  hint: string;
}

export interface GovernanceSnapshot {
  generatedAt: string;
  mode: string;
  killSwitchActive: boolean;
  routesTotal: number;
  routesPublic: number;
  methodEntries: number;
  counters: ReadonlyArray<{ key: string; value: number }>;
  healthStatus: string;
  issues: readonly GovernanceIssue[];
}

export const decodeGovernance: Decoder<GovernanceSnapshot> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const routes = field(o, "routes", readRecord, path);
  const c2 = field(o, "c2", readRecord, path);
  const counters = field(o, "counters", readRecord, path);
  const health = field(o, "governance_health", readRecord, path);
  const counterRows: Array<{ key: string; value: number }> = [];
  for (const [k, val] of Object.entries(counters)) {
    if (typeof val === "number") counterRows.push({ key: k, value: val });
  }
  counterRows.sort((a, b) => (a.key < b.key ? -1 : 1));
  return {
    generatedAt: field(o, "generated_at", readString, path),
    mode: field(c2, "mode", readString, `${path}.c2`),
    killSwitchActive: field(
      c2,
      "kill_switch_active",
      readBoolean,
      `${path}.c2`,
    ),
    routesTotal: field(routes, "total", readNumber, `${path}.routes`),
    routesPublic: field(routes, "public", readNumber, `${path}.routes`),
    methodEntries: field(
      routes,
      "method_entries",
      readNumber,
      `${path}.routes`,
    ),
    counters: counterRows,
    healthStatus: field(
      health,
      "status",
      readString,
      `${path}.governance_health`,
    ),
    issues: field(
      health,
      "issues",
      readArray((iv, ip = "$") => {
        const i = readRecord(iv, ip);
        return {
          code: field(i, "code", readString, ip),
          severity: field(i, "severity", readString, ip),
          count: field(i, "count", readOptional(readNumber), ip) ?? 0,
          hint: field(i, "hint", readString, ip),
        };
      }),
      `${path}.governance_health`,
    ),
  };
};

export function getGovernance(
  signal?: AbortSignal,
): Promise<GovernanceSnapshot> {
  return apiRequest(
    "/api/governance/control-plane",
    decodeGovernance,
    sigOpts(signal),
  );
}
