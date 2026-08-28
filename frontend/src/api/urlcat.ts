// 2D-B — URL Categories + signed SaaS taxonomy API.
//
// Contract highlights (2D-B directive):
//   - URL Category NAME is the authoritative identity (deliberate
//     architecture): no IDs, no rename. The v2 read is GET /api/urlcat/state
//     ({categories, revision}); the legacy raw-array GET is untouched.
//   - The revision is the SERVER-owned restart-stable semantic fingerprint —
//     the browser never computes it, only echoes it via ?ifRevision= on every
//     mutation. A stale token is the structured 409
//     ({error, currentRevision, yourRevision}). Create is STRICT (409 on an
//     existing name — never a silent upsert).
//   - MAX_HOSTS_PER_CATEGORY mirrors the server/store bound for UX only; the
//     store boundary is authoritative.
//   - Signed SaaS status: server truth rendered verbatim. Nulls stay null
//     (never fabricated zeros/epochs); an unknown state string is surfaced as
//     the "unknown" degraded bucket, never coerced to fresh/healthy. `stale`
//     means a previously valid signed generation (LKG) is SERVED past its
//     manifest expiry — not "no taxonomy".
//   - Settings/overrides carry their own server-owned revisions with the same
//     ?ifRevision= fence. cluster_publish_rejected on a 200 means LOCAL SAVE
//     SUCCEEDED but the fleet snapshot was rejected — a distinct state.
import { ApiError, apiRequest } from "./client";
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

/** UX mirror of urlcat.MaxHostsPerCategory — the server/store bound is
 * authoritative on every write path. */
export const MAX_HOSTS_PER_CATEGORY = 10000;

const optStr = readOptional(readString);
const optNum = readOptional(readNumber);
const optBool = readOptional(readBoolean);

// ── Structured revision conflicts (shared shape across 2D-B fences) ────────

export interface RevisionConflict {
  error: string;
  currentRevision: string;
  yourRevision: string;
}

/** Recognizes the 2D-B structured revision 409 ({error, currentRevision,
 * yourRevision} — strings). Returns null for any other error. */
export function asRevisionConflict(err: unknown): RevisionConflict | null {
  if (!(err instanceof ApiError)) return null;
  if (err.status !== 409 || err.bodyText === undefined) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(err.bodyText);
  } catch {
    return null;
  }
  try {
    const o = readRecord(parsed, "$");
    return {
      error: field(o, "error", readString, "$"),
      currentRevision: field(o, "currentRevision", readString, "$"),
      yourRevision: field(o, "yourRevision", readString, "$"),
    };
  } catch {
    return null;
  }
}

// ── URL category state (v2 read) ───────────────────────────────────────────

export interface UrlCategoryRow {
  name: string;
  hosts: readonly string[];
  builtIn: boolean;
  /** UT1 community-feed name mapping — NOT the signed SaaS corpus. */
  feedBacked: boolean;
}

export interface UrlCategoryState {
  categories: readonly UrlCategoryRow[];
  /** Server-owned restart-stable semantic taxonomy revision. */
  revision: string;
}

const decodeCategoryRow: Decoder<UrlCategoryRow> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    name: field(o, "name", readString, path),
    hosts:
      o["hosts"] === undefined || o["hosts"] === null
        ? []
        : field(o, "hosts", readArray(readString), path),
    builtIn: field(o, "builtIn", optBool, path) ?? false,
    feedBacked: field(o, "feedBacked", optBool, path) ?? false,
  };
};

export const decodeUrlCategoryState: Decoder<UrlCategoryState> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    categories:
      o["categories"] === undefined || o["categories"] === null
        ? []
        : field(o, "categories", readArray(decodeCategoryRow), path),
    revision: field(o, "revision", readString, path),
  };
};

export function getUrlCategoryState(
  signal?: AbortSignal,
): Promise<UrlCategoryState> {
  return apiRequest(
    "/api/urlcat/state",
    decodeUrlCategoryState,
    signal !== undefined ? { signal } : {},
  );
}

// ── Fenced category mutations (confirmed 2xx = restart-durable) ────────────

function fencedRev(path: string, ifRevision: string): string {
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}ifRevision=${encodeURIComponent(ifRevision)}`;
}

const decodeNamedMutation: Decoder<{ name: string; revision: string }> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    name: field(o, "name", readString, path),
    revision: field(o, "revision", readString, path),
  };
};

const decodeNoContent: Decoder<void> = (v) => {
  if (v === undefined || v === null) return;
  // A 200 with a body is also accepted (fenced host ops return revision).
};

/** STRICT create — the server refuses an existing (case-insensitive) name
 * with a 409; it never silently updates. */
export function createUrlCategory(
  name: string,
  hosts: readonly string[],
  ifRevision: string,
  signal?: AbortSignal,
): Promise<{ name: string; revision: string }> {
  return apiRequest(fencedRev("/api/urlcat", ifRevision), decodeNamedMutation, {
    method: "POST",
    body: { name, hosts },
    ...(signal !== undefined ? { signal } : {}),
  });
}

export function replaceUrlCategoryHosts(
  name: string,
  hosts: readonly string[],
  ifRevision: string,
  signal?: AbortSignal,
): Promise<{ name: string; revision: string }> {
  return apiRequest(
    fencedRev(`/api/urlcat?name=${encodeURIComponent(name)}`, ifRevision),
    decodeNamedMutation,
    {
      method: "PUT",
      body: { hosts },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

export function deleteUrlCategory(
  name: string,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fencedRev(`/api/urlcat?name=${encodeURIComponent(name)}`, ifRevision),
    decodeNoContent,
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

export function addUrlCategoryHost(
  category: string,
  host: string,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fencedRev("/api/urlcat/host", ifRevision),
    decodeNoContent,
    {
      method: "POST",
      body: { category, host },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

export function removeUrlCategoryHost(
  category: string,
  host: string,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fencedRev(
      `/api/urlcat/host?category=${encodeURIComponent(category)}&host=${encodeURIComponent(host)}`,
      ifRevision,
    ),
    decodeNoContent,
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

// ── Lookup (manual Run only — never per keystroke, never persisted) ────────

export interface UrlCategoryLookup {
  host: string;
  category: string;
  tier: string;
  matchedBy: string;
  blocked: boolean;
  blockSource: string;
}

export const decodeUrlCategoryLookup: Decoder<UrlCategoryLookup> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    host: field(o, "host", readString, path),
    category: field(o, "category", optStr, path) ?? "",
    tier: field(o, "tier", optStr, path) ?? "",
    matchedBy: field(o, "matchedBy", optStr, path) ?? "",
    blocked: field(o, "blocked", optBool, path) ?? false,
    blockSource: field(o, "blockSource", optStr, path) ?? "",
  };
};

export function lookupUrlCategory(
  host: string,
  signal?: AbortSignal,
): Promise<UrlCategoryLookup> {
  return apiRequest(
    `/api/urlcat/lookup?host=${encodeURIComponent(host)}`,
    decodeUrlCategoryLookup,
    signal !== undefined ? { signal } : {},
  );
}

// ── Compact feed status (UT1 + signed SaaS summary) ────────────────────────

export interface Ut1Status {
  configured: boolean;
  /** Full corpus count from the LAST SYNC (never a SaaS activation delta). */
  entries: number | null;
  lastSync: string | null;
  intervalSeconds: number | null;
  syncFailures: number | null;
}

export interface SaasCompactStatus {
  configured: boolean;
  enabled: boolean;
  state: string;
  activeFeedVersion: number | null;
  provenance: string;
  lastSuccess: string | null;
  syncFailures: number;
  stale: boolean;
}

export interface UrlCatFeedStatus {
  ut1: Ut1Status;
  saas: SaasCompactStatus;
}

export const decodeUrlCatFeedStatus: Decoder<UrlCatFeedStatus> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const u = field(o, "ut1", readRecord, path);
  const s = field(o, "saas", readRecord, path);
  const emptyToNull = (x: string | undefined): string | null =>
    x === undefined || x === "" ? null : x;
  return {
    ut1: {
      configured: field(u, "configured", readBoolean, `${path}.ut1`),
      entries: field(u, "entries", optNum, `${path}.ut1`) ?? null,
      lastSync: emptyToNull(field(u, "lastSync", optStr, `${path}.ut1`)),
      intervalSeconds:
        field(u, "intervalSeconds", optNum, `${path}.ut1`) ?? null,
      syncFailures: field(u, "syncFailures", optNum, `${path}.ut1`) ?? null,
    },
    saas: {
      configured: field(s, "configured", readBoolean, `${path}.saas`),
      enabled: field(s, "enabled", readBoolean, `${path}.saas`),
      state: field(s, "state", readString, `${path}.saas`),
      activeFeedVersion:
        field(s, "activeFeedVersion", optNum, `${path}.saas`) ?? null,
      provenance: field(s, "provenance", optStr, `${path}.saas`) ?? "",
      lastSuccess: emptyToNull(field(s, "lastSuccess", optStr, `${path}.saas`)),
      syncFailures: field(s, "syncFailures", optNum, `${path}.saas`) ?? 0,
      stale: field(s, "stale", optBool, `${path}.saas`) ?? false,
    },
  };
};

export function getUrlCatFeedStatus(
  signal?: AbortSignal,
): Promise<UrlCatFeedStatus> {
  return apiRequest(
    "/api/urlcat/feed-status",
    decodeUrlCatFeedStatus,
    signal !== undefined ? { signal } : {},
  );
}

// ── Signed SaaS status (full) ──────────────────────────────────────────────

/** The server's bounded state vocabulary. Anything else renders as the
 * degraded "unknown" bucket — never coerced to a healthy state. */
export const SAAS_FEED_STATES = [
  "disabled",
  "waiting_for_authority",
  "recovering",
  "embedded",
  "fresh",
  "stale",
  "syncing",
  "degraded",
  "critical",
] as const;
export type SaasFeedKnownState = (typeof SAAS_FEED_STATES)[number];

export function isKnownSaasState(s: string): s is SaasFeedKnownState {
  return SAAS_FEED_STATES.some((known) => known === s);
}

export interface SaasFeedStatus {
  state: string;
  configured: boolean;
  enabled: boolean;
  managed: boolean;
  authority: string;
  protocol: string;
  url: string;
  activeSource: string;
  provenance: string;
  signatureStatus: string;
  compiledTrusted: boolean;
  stale: boolean;
  hostCount: number;
  categoryCount: number;
  overrideCount: number;
  notModified: boolean;
  failuresSinceStart: number;
  consecutiveFailures: number;
  neverSucceeded: boolean;
  syncing: boolean;
  waitingForAuthority: boolean;
  recovering: boolean;
  critical: boolean;
  criticalReason: string;
  detail: string;
  // Nullable server facts — absence is NEVER rendered as zero (§29).
  activeFeedVersion: number | null;
  configRevision: string | null;
  overrideRevision: string | null;
  generatedAt: string | null;
  manifestExpiresAt: string | null;
  expiresInDays: number | null;
  lastAttempt: string | null;
  lastSuccessfulCheck: string | null;
  lastSuccessfulActivation: string | null;
  nextAttempt: string | null;
  lastOutcome: string | null;
  lastErrorClass: string | null;
  lastHttpStatus: number | null;
  lastActivationDelta: {
    hostsAdded: number;
    hostsRemoved: number;
    hostsChanged: number;
  } | null;
}

export const decodeSaasFeedStatus: Decoder<SaasFeedStatus> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const nullNum = (k: string): number | null => {
    const raw = o[k];
    if (raw === undefined || raw === null) return null;
    return readNumber(raw, `${path}.${k}`);
  };
  const nullStr = (k: string): string | null => {
    const raw = o[k];
    if (raw === undefined || raw === null) return null;
    return readString(raw, `${path}.${k}`);
  };
  const deltaRaw = o["last_activation_delta"];
  let delta: SaasFeedStatus["lastActivationDelta"] = null;
  if (deltaRaw !== undefined && deltaRaw !== null) {
    const d = readRecord(deltaRaw, `${path}.last_activation_delta`);
    delta = {
      hostsAdded: field(d, "hosts_added", readNumber, path),
      hostsRemoved: field(d, "hosts_removed", readNumber, path),
      hostsChanged: field(d, "hosts_changed", readNumber, path),
    };
  }
  return {
    state: field(o, "state", readString, path),
    configured: field(o, "configured", readBoolean, path),
    enabled: field(o, "enabled", readBoolean, path),
    managed: field(o, "managed", readBoolean, path),
    authority: field(o, "authority", readString, path),
    protocol: field(o, "protocol", optStr, path) ?? "",
    url: field(o, "url", optStr, path) ?? "",
    activeSource: field(o, "active_source", optStr, path) ?? "",
    provenance: field(o, "provenance", optStr, path) ?? "",
    signatureStatus: field(o, "signature_status", optStr, path) ?? "",
    compiledTrusted: field(o, "compiled_trusted", optBool, path) ?? false,
    stale: field(o, "stale", optBool, path) ?? false,
    hostCount: field(o, "host_count", optNum, path) ?? 0,
    categoryCount: field(o, "category_count", optNum, path) ?? 0,
    overrideCount: field(o, "override_count", optNum, path) ?? 0,
    notModified: field(o, "not_modified", optBool, path) ?? false,
    failuresSinceStart: field(o, "failures_since_start", optNum, path) ?? 0,
    consecutiveFailures: field(o, "consecutive_failures", optNum, path) ?? 0,
    neverSucceeded: field(o, "never_succeeded", optBool, path) ?? false,
    syncing: field(o, "syncing", optBool, path) ?? false,
    waitingForAuthority:
      field(o, "waiting_for_authority", optBool, path) ?? false,
    recovering: field(o, "recovering", optBool, path) ?? false,
    critical: field(o, "critical", optBool, path) ?? false,
    criticalReason: field(o, "critical_reason", optStr, path) ?? "",
    detail: field(o, "detail", optStr, path) ?? "",
    activeFeedVersion: nullNum("active_feed_version"),
    configRevision: nullStr("config_revision"),
    overrideRevision: nullStr("override_revision"),
    generatedAt: nullStr("generated_at"),
    manifestExpiresAt: nullStr("manifest_expires_at"),
    expiresInDays: nullNum("expires_in_days"),
    lastAttempt: nullStr("last_attempt"),
    lastSuccessfulCheck: nullStr("last_successful_check"),
    lastSuccessfulActivation: nullStr("last_successful_activation"),
    nextAttempt: nullStr("next_attempt"),
    lastOutcome: nullStr("last_outcome"),
    lastErrorClass: nullStr("last_error_class"),
    lastHttpStatus: nullNum("last_http_status"),
    lastActivationDelta: delta,
  };
};

export function getSaasFeedStatus(
  signal?: AbortSignal,
): Promise<SaasFeedStatus> {
  return apiRequest(
    "/api/saas-feed/status",
    decodeSaasFeedStatus,
    signal !== undefined ? { signal } : {},
  );
}

// ── SaaS settings ──────────────────────────────────────────────────────────

export interface SaasFeedSettingsView {
  managed: boolean;
  enabled: boolean;
  url: string;
  protocol: string;
  refreshSeconds: number;
  officialUrl: string;
  editable: boolean;
  revision: string;
  resolved: {
    url: string;
    protocol: string;
    enabled: boolean;
    refreshSeconds: number;
  } | null;
  resolveError: string | null;
  clusterPublishRejected: string | null;
}

export const decodeSaasFeedSettings: Decoder<SaasFeedSettingsView> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const resolvedRaw = o["resolved"];
  let resolved: SaasFeedSettingsView["resolved"] = null;
  if (resolvedRaw !== undefined && resolvedRaw !== null) {
    const r = readRecord(resolvedRaw, `${path}.resolved`);
    resolved = {
      url: field(r, "url", readString, path),
      protocol: field(r, "protocol", readString, path),
      enabled: field(r, "enabled", readBoolean, path),
      refreshSeconds: field(r, "refresh_seconds", readNumber, path),
    };
  }
  return {
    managed: field(o, "managed", readBoolean, path),
    enabled: field(o, "enabled", readBoolean, path),
    url: field(o, "url", optStr, path) ?? "",
    protocol: field(o, "protocol", optStr, path) ?? "",
    refreshSeconds: field(o, "refresh_seconds", optNum, path) ?? 0,
    officialUrl: field(o, "official_url", readString, path),
    editable: field(o, "editable", readBoolean, path),
    revision: field(o, "revision", readString, path),
    resolved,
    resolveError: field(o, "resolve_error", optStr, path) ?? null,
    clusterPublishRejected:
      field(o, "cluster_publish_rejected", optStr, path) ?? null,
  };
};

export function getSaasFeedSettings(
  signal?: AbortSignal,
): Promise<SaasFeedSettingsView> {
  return apiRequest(
    "/api/saas-feed/settings",
    decodeSaasFeedSettings,
    signal !== undefined ? { signal } : {},
  );
}

export interface SaasFeedSettingsWrite {
  managed: boolean;
  enabled: boolean;
  /** Go duration string ("24h"); "" = server default. */
  refresh: string;
}

export function putSaasFeedSettings(
  write: SaasFeedSettingsWrite,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<SaasFeedSettingsView> {
  return apiRequest(
    fencedRev("/api/saas-feed/settings", ifRevision),
    decodeSaasFeedSettings,
    {
      method: "PUT",
      body: {
        managed: write.managed,
        enabled: write.enabled,
        ...(write.refresh !== "" ? { refresh: write.refresh } : {}),
      },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

// ── Overrides ──────────────────────────────────────────────────────────────

export interface SaasOverridesView {
  added: Readonly<Record<string, string>>;
  recategorized: Readonly<Record<string, string>>;
  tombstones: readonly string[];
  editable: boolean;
  revision: string;
  clusterPublishRejected: string | null;
}

function readStringMap(
  v: unknown,
  path: string,
): Readonly<Record<string, string>> {
  if (v === undefined || v === null) return {};
  const o = readRecord(v, path);
  const out: Record<string, string> = {};
  for (const [k, raw] of Object.entries(o)) {
    out[k] = readString(raw, `${path}.${k}`);
  }
  return out;
}

export const decodeSaasOverrides: Decoder<SaasOverridesView> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const ov = readRecord(o["overrides"] ?? {}, `${path}.overrides`);
  return {
    added: readStringMap(ov["added"], `${path}.overrides.added`),
    recategorized: readStringMap(
      ov["recategorized"],
      `${path}.overrides.recategorized`,
    ),
    tombstones:
      ov["tombstones"] === undefined || ov["tombstones"] === null
        ? []
        : field(ov, "tombstones", readArray(readString), `${path}.overrides`),
    editable: field(o, "editable", optBool, path) ?? true,
    revision: field(o, "revision", optStr, path) ?? "",
    clusterPublishRejected:
      field(o, "cluster_publish_rejected", optStr, path) ?? null,
  };
};

export function getSaasFeedOverrides(
  signal?: AbortSignal,
): Promise<SaasOverridesView> {
  return apiRequest(
    "/api/saas-feed/overrides",
    decodeSaasOverrides,
    signal !== undefined ? { signal } : {},
  );
}

export interface SaasOverridesWrite {
  added: Readonly<Record<string, string>>;
  recategorized: Readonly<Record<string, string>>;
  tombstones: readonly string[];
}

/** FULL-SET replacement — an empty set is a deliberate clear-all. Always
 * fenced by the override revision from the GET. */
export function putSaasFeedOverrides(
  write: SaasOverridesWrite,
  ifRevision: string,
  signal?: AbortSignal,
): Promise<SaasOverridesView> {
  const body: Record<string, unknown> = {};
  if (Object.keys(write.added).length > 0) body["added"] = write.added;
  if (Object.keys(write.recategorized).length > 0)
    body["recategorized"] = write.recategorized;
  if (write.tombstones.length > 0) body["tombstones"] = write.tombstones;
  return apiRequest(
    fencedRev("/api/saas-feed/overrides", ifRevision),
    decodeSaasOverrides,
    {
      method: "PUT",
      body,
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

// ── Manual refresh ─────────────────────────────────────────────────────────

export interface SaasRefreshResult {
  refreshed: boolean;
  /** activated / no_change / skipped / failed / canceled / in_progress /
   * unavailable — server vocabulary, rendered verbatim. */
  status: string;
  state: string | null;
  /** true when the runtime answered 202 — a refresh is ALREADY running. */
  inProgress: boolean;
  /** true when the runtime is unavailable (503). */
  unavailable: boolean;
}

const decodeRefreshBody: Decoder<{
  refreshed: boolean;
  status: string;
  state: string | null;
}> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    refreshed: field(o, "refreshed", readBoolean, path),
    status: field(o, "status", readString, path),
    state: field(o, "state", optStr, path) ?? null,
  };
};

/** POST /api/saas-feed/refresh (admin; operational action — changes no
 * configuration; allowed on a managed DP). `refreshed=true` means a NEW
 * generation ACTIVATED — a 200 with no_change/skipped/failed does not. */
export async function postSaasFeedRefresh(
  signal?: AbortSignal,
): Promise<SaasRefreshResult> {
  try {
    const body = await apiRequest("/api/saas-feed/refresh", decodeRefreshBody, {
      method: "POST",
      ...(signal !== undefined ? { signal } : {}),
    });
    return {
      ...body,
      inProgress: body.status === "in_progress",
      unavailable: false,
    };
  } catch (err) {
    if (err instanceof ApiError && err.status === 503) {
      return {
        refreshed: false,
        status: "unavailable",
        state: null,
        inProgress: false,
        unavailable: true,
      };
    }
    throw err;
  }
}
