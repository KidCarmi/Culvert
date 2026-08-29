// 2E-A Content Security API: scan-engine status, threat intelligence, YARA,
// DPI, scan exclusions, and the scan verdict cache.
//
// Contract highlights (2E-A backend hardening + FRONTEND-SECURITY-CONTRACT):
//   - CANONICAL PATHS ONLY: this module speaks /api/dpi and /api/dpi/bypass.
//     The /api/content-scan aliases are deprecated compatibility surfaces and
//     are never requested by the v2 frontend (pinned by unit test).
//   - FENCES: every whole-set configuration write (domain allowlist, YARA
//     settings, scan exclusions, DPI bypass) and per-file YARA rule write
//     asserts `ifRevision` in the request BODY against the content-derived
//     `revision` served by the matching GET; a mismatch is the shared
//     structured 409 ({error, currentRevision, yourRevision}). A fenced YARA
//     CREATE asserts the literal sentinel "new" (refused when the file
//     already exists). This client ALWAYS asserts the fence.
//   - DURABILITY TRUTH: a 2xx configuration write is durable. A persist
//     failure is a 500 — for the fail-safe surfaces the change is applied in
//     memory only (server-audited as *_unpersisted) and this client surfaces
//     that exact truth; the YARA settings PUT is persist-before-apply, so its
//     500 means the live engine posture is UNCHANGED.
//   - IMPERATIVE ACTIONS (feed sync, YARA reload, cache clear/evict, YARA
//     validate) carry no fence — they are not configuration writes. Validate
//     is VALIDATION ONLY: a `valid:true` answer proves nothing was saved or
//     loaded.
//   - TRUTHFULNESS: enum-ish server strings (scan_svc_mode, on_timeout,
//     on_saturation, clamav_status) are preserved VERBATIM — never coerced to
//     a healthy default; the page renders unrecognized values as-is with an
//     "unrecognized" posture rather than pretending health.
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

// ── Engine status (GET /api/security-scan/status) ───────────────────────────

/** Factual scan-engine status snapshot. Every field is exactly what the
 * appliance reported; absent fields stay undefined (never defaulted to a
 * healthy value). The map varies between local and remote scan modes. */
export interface SecScanStatus {
  enabled: boolean;
  /** "local" | "remote" | anything the server says (verbatim). */
  scanSvcMode: string;
  scanSvcUrl?: string;
  scanSvcDegraded?: boolean;
  scanSvcStatus?: string;
  clamavStatus?: string;
  clamavVersion?: string;
  yaraRules?: number;
  yaraWarnings?: number;
  yaraEnabled?: boolean;
  yaraTimeoutSecs?: number;
  yaraOnTimeout?: string;
  yaraOnSaturation?: string;
  threatFeedEntries?: number;
  threatFeedLastSync?: string;
  threatFeedInterval?: string;
  threatFeedSyncOk?: boolean;
  threatFeedLastSuccess?: string;
  threatFeedSyncError?: string;
  cacheSize?: number;
  cacheHits?: number;
  cacheMisses?: number;
  statClamBlocked?: number;
  statYaraBlocked?: number;
  statFeedBlocked?: number;
  statScanTimeout?: number;
  statScanSkipped?: number;
}

function opt<T>(
  o: Record<string, unknown>,
  key: string,
  read: Decoder<T>,
  path: string,
): T | undefined {
  return readOptional(read)(o[key], `${path}.${key}`);
}

export const decodeSecScanStatus: Decoder<SecScanStatus> = (v, path = "$") => {
  const o = readRecord(v, path);
  const out: SecScanStatus = {
    enabled: field(o, "enabled", readBoolean, path),
    scanSvcMode: field(o, "scan_svc_mode", readString, path),
  };
  const set = <K extends keyof SecScanStatus>(
    k: K,
    val: SecScanStatus[K] | undefined,
  ): void => {
    if (val !== undefined) out[k] = val;
  };
  set("scanSvcUrl", opt(o, "scan_svc_url", readString, path));
  set("scanSvcDegraded", opt(o, "scan_svc_degraded", readBoolean, path));
  set("scanSvcStatus", opt(o, "scan_svc_status", readString, path));
  set("clamavStatus", opt(o, "clamav_status", readString, path));
  set("clamavVersion", opt(o, "clamav_version", readString, path));
  set("yaraRules", opt(o, "yara_rules", readNumber, path));
  set("yaraWarnings", opt(o, "yara_warnings", readNumber, path));
  set("yaraEnabled", opt(o, "yara_enabled", readBoolean, path));
  set("yaraTimeoutSecs", opt(o, "yara_timeout_secs", readNumber, path));
  set("yaraOnTimeout", opt(o, "yara_on_timeout", readString, path));
  set("yaraOnSaturation", opt(o, "yara_on_saturation", readString, path));
  set("threatFeedEntries", opt(o, "threat_feed_entries", readNumber, path));
  set("threatFeedLastSync", opt(o, "threat_feed_last_sync", readString, path));
  set("threatFeedInterval", opt(o, "threat_feed_interval", readString, path));
  set("threatFeedSyncOk", opt(o, "threat_feed_sync_ok", readBoolean, path));
  set(
    "threatFeedLastSuccess",
    opt(o, "threat_feed_last_success", readString, path),
  );
  set(
    "threatFeedSyncError",
    opt(o, "threat_feed_sync_error", readString, path),
  );
  set("cacheSize", opt(o, "cache_size", readNumber, path));
  set("cacheHits", opt(o, "cache_hits", readNumber, path));
  set("cacheMisses", opt(o, "cache_misses", readNumber, path));
  set("statClamBlocked", opt(o, "stat_clam_blocked", readNumber, path));
  set("statYaraBlocked", opt(o, "stat_yara_blocked", readNumber, path));
  set("statFeedBlocked", opt(o, "stat_feed_blocked", readNumber, path));
  set("statScanTimeout", opt(o, "stat_scan_timeout", readNumber, path));
  set("statScanSkipped", opt(o, "stat_scan_skipped", readNumber, path));
  return out;
};

export function getSecScanStatus(signal?: AbortSignal): Promise<SecScanStatus> {
  return apiRequest(
    "/api/security-scan/status",
    decodeSecScanStatus,
    signal !== undefined ? { signal } : {},
  );
}

/** Manual threat-feed sync (IMPERATIVE, admin). Runs synchronously on the
 * appliance and answers with the refreshed status snapshot. A failure does
 * NOT imply the last-known-good feed stopped enforcing. */
export function syncThreatFeeds(signal?: AbortSignal): Promise<SecScanStatus> {
  return apiRequest("/api/security-scan/feeds/sync", decodeSecScanStatus, {
    method: "POST",
    ...(signal !== undefined ? { signal } : {}),
  });
}

// ── Fleet publication truth (2E-A-2 §4) ─────────────────────────────────────

/** Outcome of the fleet config publish a cluster-synced write triggers.
 * `publishRejected` (server field cluster_publish_rejected) is present ONLY
 * when the LOCAL durable mutation succeeded but the fleet publish was
 * REJECTED at commit — two distinct facts: this node enforces the new state,
 * the fleet stays on the last valid snapshot. */
export interface FleetPublication {
  publishRejected?: string;
}

function readPublishRejected(
  o: Record<string, unknown>,
  path: string,
): string | undefined {
  return opt(o, "cluster_publish_rejected", readString, path);
}

/** Ownership signal: false on a managed Data Plane node, where the surface is
 * control-plane managed and local writes are refused with 409. Absent on
 * pre-2E-A-2 responses ⇒ treated as editable (the pre-signal behavior). */
function readEditable(o: Record<string, unknown>, path: string): boolean {
  const e = opt(o, "editable", readBoolean, path);
  return e === undefined ? true : e;
}

// ── Threat-feed domain allowlist ────────────────────────────────────────────

export interface DomainAllowlist {
  domains: readonly string[];
  revision: string;
  /** false ⇒ control-plane managed on this node (writes are refused). */
  editable: boolean;
}

export const decodeDomainAllowlist: Decoder<DomainAllowlist> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const raw = o["domains"];
  return {
    domains:
      raw === undefined || raw === null
        ? []
        : field(o, "domains", readArray(readString), path),
    revision: field(o, "revision", readString, path),
    editable: readEditable(o, path),
  };
};

export function getDomainAllowlist(
  signal?: AbortSignal,
): Promise<DomainAllowlist> {
  return apiRequest(
    "/api/security-scan/feeds/domain-allowlist",
    decodeDomainAllowlist,
    signal !== undefined ? { signal } : {},
  );
}

export interface AllowlistPutResult extends FleetPublication {
  count: number;
  revision: string;
}

const decodeAllowlistPutResult: Decoder<AllowlistPutResult> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const out: AllowlistPutResult = {
    count: field(o, "count", readNumber, path),
    revision: field(o, "revision", readString, path),
  };
  const rej = readPublishRejected(o, path);
  if (rej !== undefined) out.publishRejected = rej;
  return out;
};

export function putDomainAllowlist(
  domains: readonly string[],
  ifRevision: string,
  signal?: AbortSignal,
): Promise<AllowlistPutResult> {
  return apiRequest(
    "/api/security-scan/feeds/domain-allowlist",
    decodeAllowlistPutResult,
    {
      method: "PUT",
      body: { domains, ifRevision },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

// ── YARA ────────────────────────────────────────────────────────────────────

export interface YaraInventory {
  directory: string;
  /** File stems — the CRUD addresses. */
  files: readonly string[];
  /** file stem → rule identifiers inside that file. */
  fileRules: Readonly<Record<string, readonly string[]>>;
  /** Compiled rule names (display only). */
  rules: readonly string[];
  warnings: readonly string[];
  count: number;
}

export const decodeYaraInventory: Decoder<YaraInventory> = (v, path = "$") => {
  const o = readRecord(v, path);
  const arr = (key: string): readonly string[] => {
    const raw = o[key];
    return raw === undefined || raw === null
      ? []
      : field(o, key, readArray(readString), path);
  };
  const frRaw = o["file_rules"];
  const fileRules: Record<string, readonly string[]> = {};
  if (frRaw !== undefined && frRaw !== null) {
    const fr = readRecord(frRaw, `${path}.file_rules`);
    for (const k of Object.keys(fr)) {
      const rv = fr[k];
      fileRules[k] =
        rv === null ? [] : readArray(readString)(rv, `${path}.file_rules.${k}`);
    }
  }
  return {
    directory: field(o, "directory", readString, path),
    files: arr("files"),
    fileRules,
    rules: arr("rules"),
    warnings: arr("warnings"),
    count: field(o, "count", readNumber, path),
  };
};

export function getYaraInventory(signal?: AbortSignal): Promise<YaraInventory> {
  return apiRequest(
    "/api/security-scan/yara/rules",
    decodeYaraInventory,
    signal !== undefined ? { signal } : {},
  );
}

export interface YaraRule {
  name: string;
  source: string;
  /** Content-derived revision — the ifRevision a fenced update asserts. */
  revision: string;
}

export const decodeYaraRule: Decoder<YaraRule> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    name: field(o, "name", readString, path),
    source: field(o, "source", readString, path),
    revision: field(o, "revision", readString, path),
  };
};

export function getYaraRule(
  name: string,
  signal?: AbortSignal,
): Promise<YaraRule> {
  return apiRequest(
    `/api/security-scan/yara/rules/${encodeURIComponent(name)}`,
    decodeYaraRule,
    signal !== undefined ? { signal } : {},
  );
}

export interface YaraWriteResult {
  name: string;
  warnings: readonly string[];
  yaraRules: number;
  cacheCleared: boolean;
}

const decodeYaraWriteResult: Decoder<YaraWriteResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  const w = o["warnings"];
  return {
    name: field(o, "name", readString, path),
    warnings:
      w === undefined || w === null
        ? []
        : field(o, "warnings", readArray(readString), path),
    yaraRules: field(o, "yara_rules", readNumber, path),
    cacheCleared: field(o, "cache_cleared", readBoolean, path),
  };
};

/** Fenced CREATE — asserts the "new" sentinel so an existing rule file is a
 * structured 409, never a silent replace. */
export function createYaraRule(
  name: string,
  source: string,
  signal?: AbortSignal,
): Promise<YaraWriteResult> {
  return apiRequest("/api/security-scan/yara/rules", decodeYaraWriteResult, {
    method: "POST",
    body: { name, source, ifRevision: "new" },
    ...(signal !== undefined ? { signal } : {}),
  });
}

/** Fenced UPDATE — asserts the content revision of the source being edited. */
export function updateYaraRule(
  name: string,
  source: string,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<YaraWriteResult> {
  return apiRequest(
    `/api/security-scan/yara/rules/${encodeURIComponent(name)}`,
    decodeYaraWriteResult,
    {
      method: "PUT",
      body: { source, ifRevision },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

/** Fenced DELETE (2E-A-2 §3): asserts the content revision of the rule source
 * the admin reviewed in the delete ceremony. A stale token is the structured
 * 409 with NOTHING deleted; a missing target is a truthful 404. This client
 * ALWAYS asserts the fence. */
export function deleteYaraRule(
  name: string,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    `/api/security-scan/yara/rules/${encodeURIComponent(name)}?ifRevision=${encodeURIComponent(ifRevision)}`,
    () => undefined,
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

export interface YaraValidateResult {
  valid: boolean;
  error?: string;
  ruleNames: readonly string[];
  warnings: readonly string[];
}

export const decodeYaraValidateResult: Decoder<YaraValidateResult> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const arr = (key: string): readonly string[] => {
    const raw = o[key];
    return raw === undefined || raw === null
      ? []
      : field(o, key, readArray(readString), path);
  };
  const out: YaraValidateResult = {
    valid: field(o, "valid", readBoolean, path),
    ruleNames: arr("rule_names"),
    warnings: arr("warnings"),
  };
  const e = opt(o, "error", readString, path);
  if (e !== undefined) out.error = e;
  return out;
};

/** DRY-RUN validation only — never saves, loads, or activates anything. */
export function validateYaraSource(
  source: string,
  signal?: AbortSignal,
): Promise<YaraValidateResult> {
  return apiRequest(
    "/api/security-scan/yara/validate",
    decodeYaraValidateResult,
    {
      method: "POST",
      body: { source },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

export interface YaraReloadResult {
  yaraRules: number;
  directory: string;
  cacheCleared: boolean;
  warnings: readonly string[];
}

const decodeYaraReloadResult: Decoder<YaraReloadResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  const w = o["warnings"];
  return {
    yaraRules: field(o, "yara_rules", readNumber, path),
    directory: field(o, "directory", readString, path),
    cacheCleared: field(o, "cache_cleared", readBoolean, path),
    warnings:
      w === undefined || w === null
        ? []
        : field(o, "warnings", readArray(readString), path),
  };
};

/** IMPERATIVE reload from the configured rules directory (admin). Also clears
 * the scan verdict cache so old-clean content is re-scanned. */
export function reloadYaraRules(
  signal?: AbortSignal,
): Promise<YaraReloadResult> {
  return apiRequest("/api/security-scan/yara/reload", decodeYaraReloadResult, {
    method: "POST",
    ...(signal !== undefined ? { signal } : {}),
  });
}

export interface YaraSettings {
  enabled: boolean;
  timeoutSecs: number;
  maxInflight: number;
  /** Verbatim server posture strings ("fail_closed" / "fail_open_with_alert"
   * today); unrecognized values are preserved and rendered as unrecognized. */
  onTimeout: string;
  onSaturation: string;
  alertDegraded: boolean;
  revision: string;
}

export const decodeYaraSettings: Decoder<YaraSettings> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    enabled: field(o, "enabled", readBoolean, path),
    timeoutSecs: field(o, "timeout_secs", readNumber, path),
    maxInflight: field(o, "max_inflight", readNumber, path),
    onTimeout: field(o, "on_timeout", readString, path),
    onSaturation: field(o, "on_saturation", readString, path),
    alertDegraded: field(o, "alert_degraded", readBoolean, path),
    revision: field(o, "revision", readString, path),
  };
};

export function getYaraSettings(signal?: AbortSignal): Promise<YaraSettings> {
  return apiRequest(
    "/api/security-scan/yara/settings",
    decodeYaraSettings,
    signal !== undefined ? { signal } : {},
  );
}

/** Write DTO — deliberately excludes the server-owned `revision` (the fence
 * travels separately as `ifRevision`). */
export interface YaraSettingsWrite {
  enabled: boolean;
  timeoutSecs: number;
  maxInflight: number;
  onTimeout: string;
  onSaturation: string;
  alertDegraded: boolean;
}

/** Persist-before-apply on the appliance: a 2xx means durable AND live; a 500
 * means the live engine posture is UNCHANGED. */
export function putYaraSettings(
  write: YaraSettingsWrite,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<YaraSettings> {
  return apiRequest("/api/security-scan/yara/settings", decodeYaraSettings, {
    method: "PUT",
    body: {
      enabled: write.enabled,
      timeout_secs: write.timeoutSecs,
      max_inflight: write.maxInflight,
      on_timeout: write.onTimeout,
      on_saturation: write.onSaturation,
      alert_degraded: write.alertDegraded,
      ifRevision,
    },
    ...(signal !== undefined ? { signal } : {}),
  });
}

// ── Scan exclusions ─────────────────────────────────────────────────────────

export interface ScanExclusions {
  hashes: readonly string[];
  hosts: readonly string[];
  revision: string;
}

export const decodeScanExclusions: Decoder<ScanExclusions> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const arr = (key: string): readonly string[] => {
    const raw = o[key];
    return raw === undefined || raw === null
      ? []
      : field(o, key, readArray(readString), path);
  };
  return {
    hashes: arr("hashes"),
    hosts: arr("hosts"),
    revision: field(o, "revision", readString, path),
  };
};

export function getScanExclusions(
  signal?: AbortSignal,
): Promise<ScanExclusions> {
  return apiRequest(
    "/api/security-scan/exclusions",
    decodeScanExclusions,
    signal !== undefined ? { signal } : {},
  );
}

export function putScanExclusions(
  hashes: readonly string[],
  hosts: readonly string[],
  ifRevision: string,
  signal?: AbortSignal,
): Promise<ScanExclusions> {
  return apiRequest("/api/security-scan/exclusions", decodeScanExclusions, {
    method: "PUT",
    body: { hashes, hosts, ifRevision },
    ...(signal !== undefined ? { signal } : {}),
  });
}

// ── Scan service + cache ────────────────────────────────────────────────────

export interface ScanSvc {
  remoteEnabled: boolean;
  /** Userinfo-redacted by the appliance — never carries embedded creds. */
  remoteUrl: string;
  remoteStatus?: string;
}

export const decodeScanSvc: Decoder<ScanSvc> = (v, path = "$") => {
  const o = readRecord(v, path);
  const out: ScanSvc = {
    remoteEnabled: field(o, "remote_enabled", readBoolean, path),
    remoteUrl: field(o, "remote_url", readString, path),
  };
  const s = opt(o, "remote_status", readString, path);
  if (s !== undefined) out.remoteStatus = s;
  return out;
};

export function getScanSvc(signal?: AbortSignal): Promise<ScanSvc> {
  return apiRequest(
    "/api/security-scan/svc",
    decodeScanSvc,
    signal !== undefined ? { signal } : {},
  );
}

export interface ScanCache {
  enabled: boolean;
  cacheHits?: number;
  cacheMisses?: number;
  cacheSize?: number;
}

export const decodeScanCache: Decoder<ScanCache> = (v, path = "$") => {
  const o = readRecord(v, path);
  const out: ScanCache = {
    enabled: field(o, "enabled", readBoolean, path),
  };
  const set = <K extends keyof ScanCache>(
    k: K,
    val: ScanCache[K] | undefined,
  ): void => {
    if (val !== undefined) out[k] = val;
  };
  set("cacheHits", opt(o, "cache_hits", readNumber, path));
  set("cacheMisses", opt(o, "cache_misses", readNumber, path));
  set("cacheSize", opt(o, "cache_size", readNumber, path));
  return out;
};

export function getScanCache(signal?: AbortSignal): Promise<ScanCache> {
  return apiRequest(
    "/api/security-scan/cache",
    decodeScanCache,
    signal !== undefined ? { signal } : {},
  );
}

/** DESTRUCTIVE: clears the ENTIRE scan verdict cache — previously-clean
 * content is re-scanned on next access. Volatile runtime state (no restart
 * durability question; the cache rebuilds from traffic). */
export function clearScanCache(signal?: AbortSignal): Promise<void> {
  return apiRequest("/api/security-scan/cache", () => undefined, {
    method: "DELETE",
    ...(signal !== undefined ? { signal } : {}),
  });
}

// ── DPI (canonical /api/dpi — never the deprecated /api/content-scan) ───────

export interface DpiConfig {
  patterns: readonly string[];
  count: number;
  blockedTotal: number;
  /** false ⇒ control-plane managed on this node (writes are refused). */
  editable: boolean;
}

export const decodeDpiConfig: Decoder<DpiConfig> = (v, path = "$") => {
  const o = readRecord(v, path);
  const raw = o["patterns"];
  return {
    patterns:
      raw === undefined || raw === null
        ? []
        : field(o, "patterns", readArray(readString), path),
    count: field(o, "count", readNumber, path),
    blockedTotal: field(o, "blocked_total", readNumber, path),
    editable: readEditable(o, path),
  };
};

export function getDpi(signal?: AbortSignal): Promise<DpiConfig> {
  return apiRequest(
    "/api/dpi",
    decodeDpiConfig,
    signal !== undefined ? { signal } : {},
  );
}

/** DPI patterns are cluster-synced: a successful mutation publishes a fresh
 * config snapshot; a rejected publish comes back as publishRejected. */
const decodeFleetPublication: Decoder<FleetPublication> = (v, path = "$") => {
  if (v === undefined || v === null) return {}; // 204 — full success
  const o = readRecord(v, path);
  const out: FleetPublication = {};
  const rej = readPublishRejected(o, path);
  if (rej !== undefined) out.publishRejected = rej;
  return out;
};

export function addDpiPattern(
  pattern: string,
  signal?: AbortSignal,
): Promise<FleetPublication> {
  return apiRequest("/api/dpi", decodeFleetPublication, {
    method: "POST",
    body: { pattern },
    ...(signal !== undefined ? { signal } : {}),
  });
}

export function removeDpiPattern(
  pattern: string,
  signal?: AbortSignal,
): Promise<FleetPublication> {
  return apiRequest(
    `/api/dpi?pattern=${encodeURIComponent(pattern)}`,
    decodeFleetPublication,
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

export interface DpiBypass {
  hosts: readonly string[];
  revision: string;
}

export const decodeDpiBypass: Decoder<DpiBypass> = (v, path = "$") => {
  const o = readRecord(v, path);
  const raw = o["hosts"];
  return {
    hosts:
      raw === undefined || raw === null
        ? []
        : field(o, "hosts", readArray(readString), path),
    revision: field(o, "revision", readString, path),
  };
};

export function getDpiBypass(signal?: AbortSignal): Promise<DpiBypass> {
  return apiRequest(
    "/api/dpi/bypass",
    decodeDpiBypass,
    signal !== undefined ? { signal } : {},
  );
}

export function putDpiBypass(
  hosts: readonly string[],
  ifRevision: string,
  signal?: AbortSignal,
): Promise<DpiBypass> {
  return apiRequest("/api/dpi/bypass", decodeDpiBypass, {
    method: "PUT",
    body: { hosts, ifRevision },
    ...(signal !== undefined ? { signal } : {}),
  });
}
