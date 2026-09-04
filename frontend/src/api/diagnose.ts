// FE-4 active-diagnostics surface (/api/diagnose/{verb}) — per-verb runtime
// decoders (hardening §6). The backend's fixed verb registry is mirrored
// exactly; EVERY verb has an explicit runtime contract for its
// schema_version=1 shape derived from the Go response structs (diagnose.go)
// and the OpenAPI spec — a bare {"schema_version":1} is NOT a valid result
// for any verb. Missing or mistyped REQUIRED fields fail closed into
// DecodeError; unknown future fields are ignored; fields the backend marks
// omitempty are optional with explicit defaults. Validated results are
// normalized into a small presentation model (summary rows + tables +
// nested sub-results) so nested information — storage checks, upstream
// proxy status, config utilization, "all" sub-results — renders
// deliberately instead of disappearing or being dumped as raw JSON.
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

// The backend's fixed verb registry (ui_routes_meta.go — all RoleOperator).
export const DIAGNOSE_VERBS = [
  "storage",
  "upstream",
  "dns",
  "tls",
  "cluster",
  "etcd",
  "config",
  "support",
  "all",
] as const;
export type DiagnoseVerb = (typeof DIAGNOSE_VERBS)[number];

export const SUPPORTED_DIAGNOSE_SCHEMA = 1;

// ── Presentation model (§7): deliberate rendering, never a raw dump ────────

export interface DiagnoseKV {
  readonly label: string;
  readonly value: string;
  readonly status?: "ok" | "warn" | "critical";
}

export interface DiagnoseTable {
  readonly title: string;
  readonly headers: readonly string[];
  readonly rows: ReadonlyArray<readonly string[]>;
}

export interface DiagnoseView {
  /** verb (or nested sub-result name for "all") — the section identity */
  readonly verb: string;
  readonly generatedAt: string;
  readonly ok: boolean;
  readonly summary: readonly DiagnoseKV[];
  readonly tables: readonly DiagnoseTable[];
  readonly sub: readonly DiagnoseView[];
}

// ── Shared decode helpers ──────────────────────────────────────────────────

const optStr = readOptional(readString);
const optNum = readOptional(readNumber);
const optBool = readOptional(readBoolean);

/** Go encodes an empty non-omitempty slice as null; required-present arrays
 * therefore tolerate exactly null-as-empty (absent still fails closed). */
function reqArray<T>(decode: Decoder<T>): Decoder<readonly T[]> {
  const arr = readArray(decode);
  return (v, path = "$") => (v === null ? [] : arr(v, path));
}

/** Validates the schema_version=1 envelope + generated_at; returns the
 * record for the verb decoder. Every verb goes through this first. */
function v1Envelope(
  v: unknown,
  path: string,
): { o: Record<string, unknown>; generatedAt: string } {
  const o = readRecord(v, path);
  const schema = field(o, "schema_version", readNumber, path);
  if (schema !== SUPPORTED_DIAGNOSE_SCHEMA) {
    throw new DecodeError(
      `${path}.schema_version`,
      `supported version ${String(SUPPORTED_DIAGNOSE_SCHEMA)}`,
      schema,
    );
  }
  return { o, generatedAt: field(o, "generated_at", readString, path) };
}

const yesNo = (b: boolean): string => (b ? "yes" : "no");

function okBadge(
  ok: boolean,
  okLabel = "OK",
  badLabel = "DEGRADED",
): DiagnoseKV {
  return ok
    ? { label: "Result", value: okLabel, status: "ok" }
    : { label: "Result", value: badLabel, status: "critical" };
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${String(n)} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

// storageCheck — shared by storage + support (diagnose.go storageCheck).
const decodeStorageCheck = (
  v: unknown,
  path = "$",
): { name: string; path: string; ok: boolean; detail: string } => {
  const c = readRecord(v, path);
  return {
    name: field(c, "name", readString, path),
    path: field(c, "path", readString, path),
    ok: field(c, "ok", readBoolean, path),
    detail: field(c, "detail", optStr, path) ?? "",
  };
};

function checksTable(
  title: string,
  checks: ReadonlyArray<{
    name: string;
    path: string;
    ok: boolean;
    detail: string;
  }>,
): DiagnoseTable {
  return {
    title,
    headers: ["Check", "Path", "Status", "Detail"],
    rows: checks.map((c) => [c.name, c.path, c.ok ? "ok" : "FAILED", c.detail]),
  };
}

// ── storage ────────────────────────────────────────────────────────────────

const decodeStorage: Decoder<DiagnoseView> = (v, path = "$") => {
  const { o, generatedAt } = v1Envelope(v, path);
  const ok = field(o, "ok", readBoolean, path);
  const checks = field(o, "checks", reqArray(decodeStorageCheck), path);
  return {
    verb: "storage",
    generatedAt,
    ok,
    summary: [
      okBadge(ok),
      {
        label: "Data directory",
        value: field(o, "data_dir", readString, path),
      },
      {
        label: "Free",
        value: fmtBytes(field(o, "free_bytes", readNumber, path)),
      },
      {
        label: "Total",
        value: fmtBytes(field(o, "total_bytes", readNumber, path)),
      },
      {
        label: "Used",
        value: `${field(o, "used_pct", readNumber, path).toFixed(1)}%`,
      },
    ],
    tables: [checksTable("Storage checks", checks)],
    sub: [],
  };
};

// ── upstream ───────────────────────────────────────────────────────────────

const decodeUpstreamProxy = (v: unknown, path = "$"): readonly string[] => {
  const p = readRecord(v, path);
  const retry = field(p, "retry_after_ms", optNum, path) ?? 0;
  return [
    field(p, "url", readString, path),
    yesNo(field(p, "healthy", readBoolean, path)),
    field(p, "circuit", readString, path),
    String(field(p, "failures", readNumber, path)),
    retry > 0 ? `${String(retry)} ms` : "—",
  ];
};

const decodeUpstream: Decoder<DiagnoseView> = (v, path = "$") => {
  const { o, generatedAt } = v1Envelope(v, path);
  const ok = field(o, "ok", readBoolean, path);
  const enabled = field(o, "enabled", readBoolean, path);
  const proxies = field(o, "proxies", reqArray(decodeUpstreamProxy), path);
  return {
    verb: "upstream",
    generatedAt,
    ok,
    summary: [
      okBadge(ok),
      {
        label: "Upstream pool",
        value: enabled ? "enabled" : "disabled (direct egress)",
      },
      { label: "Proxies", value: String(field(o, "count", readNumber, path)) },
      {
        label: "Healthy",
        value: String(field(o, "healthy_count", readNumber, path)),
      },
      {
        label: "Usable (healthy + circuit not open)",
        value: String(field(o, "usable_count", readNumber, path)),
      },
    ],
    tables:
      proxies.length > 0
        ? [
            {
              title: "Proxies",
              headers: ["Proxy", "Healthy", "Circuit", "Failures", "Retry in"],
              rows: proxies,
            },
          ]
        : [],
    sub: [],
  };
};

// ── dns ────────────────────────────────────────────────────────────────────

const decodeDNS: Decoder<DiagnoseView> = (v, path = "$") => {
  const { o, generatedAt } = v1Envelope(v, path);
  const ok = field(o, "ok", readBoolean, path);
  const blocked = field(o, "blocked", readBoolean, path);
  const addresses =
    field(o, "addresses", readOptional(reqArray(readString)), path) ?? [];
  const errText = field(o, "error", optStr, path) ?? "";
  const summary: DiagnoseKV[] = [
    okBadge(ok, "OK", blocked ? "REFUSED" : "FAILED"),
    { label: "Host", value: field(o, "host", readString, path) },
    {
      label: "Resolved",
      value: yesNo(field(o, "resolved", readBoolean, path)),
    },
    {
      label: "Duration",
      value: `${String(field(o, "duration_ms", readNumber, path))} ms`,
    },
  ];
  if (blocked) {
    summary.push({
      label: "Blocked",
      value: "resolved to a private/internal address — refused (SSRF guard)",
      status: "warn",
    });
  }
  if (addresses.length > 0)
    summary.push({ label: "Addresses", value: addresses.join(", ") });
  if (errText !== "")
    summary.push({ label: "Error", value: errText, status: "warn" });
  return { verb: "dns", generatedAt, ok, summary, tables: [], sub: [] };
};

// ── tls ────────────────────────────────────────────────────────────────────

const decodeTLS: Decoder<DiagnoseView> = (v, path = "$") => {
  const { o, generatedAt } = v1Envelope(v, path);
  const ok = field(o, "ok", readBoolean, path);
  const blocked = field(o, "blocked", readBoolean, path);
  const leafRaw = field(o, "leaf", readOptional(readRecord), path);
  const errText = field(o, "error", optStr, path) ?? "";
  const summary: DiagnoseKV[] = [
    okBadge(ok, "OK", blocked ? "REFUSED" : "FAILED"),
    {
      label: "Target",
      value: `${field(o, "host", readString, path)}:${field(o, "port", readString, path)}`,
    },
    {
      label: "Handshake",
      value: yesNo(field(o, "handshake_ok", readBoolean, path)),
    },
    {
      label: "Chain verified",
      value: yesNo(field(o, "chain_verified", readBoolean, path)),
    },
    { label: "Expired", value: yesNo(field(o, "expired", readBoolean, path)) },
    {
      label: "Days until expiry",
      value: String(field(o, "days_until_expiry", readNumber, path)),
    },
    {
      label: "Duration",
      value: `${String(field(o, "duration_ms", readNumber, path))} ms`,
    },
  ];
  const version = field(o, "version", optStr, path) ?? "";
  if (version !== "") summary.push({ label: "Version", value: version });
  const cipher = field(o, "cipher_suite", optStr, path) ?? "";
  if (cipher !== "") summary.push({ label: "Cipher suite", value: cipher });
  if (blocked) {
    summary.push({
      label: "Blocked",
      value: "private/internal target — refused (SSRF guard)",
      status: "warn",
    });
  }
  if (errText !== "")
    summary.push({ label: "Error", value: errText, status: "warn" });
  const tables: DiagnoseTable[] = [];
  if (leafRaw !== undefined) {
    const lp = `${path}.leaf`;
    tables.push({
      title: "Leaf certificate",
      headers: ["Field", "Value"],
      rows: [
        ["Subject", field(leafRaw, "subject", readString, lp)],
        ["Issuer", field(leafRaw, "issuer", readString, lp)],
        ["Not before", field(leafRaw, "not_before", readString, lp)],
        ["Not after", field(leafRaw, "not_after", readString, lp)],
        [
          "DNS names",
          (
            field(
              leafRaw,
              "dns_names",
              readOptional(reqArray(readString)),
              lp,
            ) ?? []
          ).join(", "),
        ],
      ],
    });
  }
  return { verb: "tls", generatedAt, ok, summary, tables, sub: [] };
};

// ── cluster ────────────────────────────────────────────────────────────────

const decodeCluster: Decoder<DiagnoseView> = (v, path = "$") => {
  const { o, generatedAt } = v1Envelope(v, path);
  const ok = field(o, "ok", readBoolean, path);
  const summary: DiagnoseKV[] = [
    okBadge(ok),
    { label: "Role", value: field(o, "role", readString, path) },
    {
      label: "HA enabled",
      value: yesNo(field(o, "ha_enabled", readBoolean, path)),
    },
    {
      label: "Auto failover",
      value: yesNo(field(o, "auto_failover", readBoolean, path)),
    },
    { label: "Lease mode", value: field(o, "lease_mode", readString, path) },
    {
      label: "Write authority",
      value: yesNo(field(o, "write_authority", readBoolean, path)),
    },
    {
      label: "Nodes (connected / total)",
      value: `${String(field(o, "nodes_connected", readNumber, path))} / ${String(field(o, "nodes_total", readNumber, path))}`,
    },
  ];
  const leaseValid = field(o, "lease_valid", optBool, path);
  if (leaseValid !== undefined)
    summary.push({ label: "Lease valid", value: yesNo(leaseValid) });
  const epoch = field(o, "epoch", optNum, path);
  if (epoch !== undefined)
    summary.push({ label: "Epoch", value: String(epoch) });
  const syncFail = field(o, "sync_fail_count", optNum, path) ?? 0;
  if (syncFail > 0)
    summary.push({
      label: "Sync failures",
      value: String(syncFail),
      status: "warn",
    });
  // Sync rounds contained by the CHAOS-25 panic guard deliberately do NOT
  // advance sync_fail_count (a panicking standby must not auto-promote on
  // its own fault), so this is the only signal that replication has stalled.
  const syncPanics = field(o, "sync_panics", optNum, path) ?? 0;
  if (syncPanics > 0)
    summary.push({
      label: "Sync faults (contained)",
      value: `${String(syncPanics)} — replication stalled, auto-failover suppressed`,
      status: "warn",
    });
  const lastSync = field(o, "last_sync_ok", optStr, path) ?? "";
  if (lastSync !== "") summary.push({ label: "Last sync OK", value: lastSync });
  const detail = field(o, "detail", optStr, path) ?? "";
  if (detail !== "") summary.push({ label: "Detail", value: detail });
  return { verb: "cluster", generatedAt, ok, summary, tables: [], sub: [] };
};

// ── etcd ───────────────────────────────────────────────────────────────────

const decodeEtcd: Decoder<DiagnoseView> = (v, path = "$") => {
  const { o, generatedAt } = v1Envelope(v, path);
  const ok = field(o, "ok", readBoolean, path);
  const status = field(o, "status", readString, path);
  const summary: DiagnoseKV[] = [
    ok
      ? {
          label: "Result",
          value: status === "n/a" ? "not applicable" : "OK",
          status: "ok",
        }
      : { label: "Result", value: "UNREACHABLE", status: "critical" },
    {
      label: "Fencing lease configured",
      value: yesNo(field(o, "configured", readBoolean, path)),
    },
    { label: "Status", value: status },
  ];
  const holder = field(o, "holder", optStr, path) ?? "";
  if (holder !== "") summary.push({ label: "Lease holder", value: holder });
  const epoch = field(o, "epoch", optNum, path);
  if (epoch !== undefined)
    summary.push({ label: "Epoch", value: String(epoch) });
  const validFor = field(o, "valid_for_ms", optNum, path);
  if (validFor !== undefined)
    summary.push({ label: "Lease valid for", value: `${String(validFor)} ms` });
  const latency = field(o, "latency_ms", optNum, path);
  if (latency !== undefined)
    summary.push({ label: "Probe latency", value: `${String(latency)} ms` });
  const errText = field(o, "error", optStr, path) ?? "";
  if (errText !== "")
    summary.push({ label: "Error", value: errText, status: "warn" });
  const note = field(o, "note", optStr, path) ?? "";
  if (note !== "") summary.push({ label: "Note", value: note });
  return { verb: "etcd", generatedAt, ok, summary, tables: [], sub: [] };
};

// ── config ─────────────────────────────────────────────────────────────────

const decodeConfig: Decoder<DiagnoseView> = (v, path = "$") => {
  const { o, generatedAt } = v1Envelope(v, path);
  const ok = field(o, "ok", readBoolean, path);
  const status = field(o, "status", readString, path);
  const sizes = field(
    o,
    "sizes",
    reqArray((sv, sp = "$") => {
      const s = readRecord(sv, sp);
      return [
        field(s, "name", readString, sp),
        String(field(s, "size", readNumber, sp)),
      ] as const;
    }),
    path,
  );
  const utilization = field(
    o,
    "utilization",
    reqArray((uv, up = "$") => {
      const u = readRecord(uv, up);
      const size = field(u, "size", readNumber, up);
      const cap = field(u, "cap", readNumber, up);
      const pct = cap > 0 ? `${String(Math.round((size / cap) * 100))}%` : "—";
      return [
        field(u, "name", readString, up),
        String(size),
        String(cap),
        pct,
      ] as const;
    }),
    path,
  );
  const summary: DiagnoseKV[] = [
    ok && status === "ok"
      ? { label: "Result", value: "OK", status: "ok" }
      : {
          label: "Result",
          value: status.toUpperCase(),
          status: ok ? "warn" : "critical",
        },
    {
      label: "Participates in config sync",
      value: yesNo(field(o, "syncing", readBoolean, path)),
    },
    {
      label: "Policy version",
      value: String(field(o, "policy_version", readNumber, path)),
    },
    { label: "Epoch", value: String(field(o, "epoch", readNumber, path)) },
    {
      label: "Max slice utilization",
      value: `${String(field(o, "max_util_percent", readNumber, path))}%${
        (field(o, "max_util_slice", optStr, path) ?? "") !== ""
          ? ` (${String(field(o, "max_util_slice", optStr, path))})`
          : ""
      }`,
    },
  ];
  const errText = field(o, "error", optStr, path) ?? "";
  if (errText !== "")
    summary.push({
      label: "Cap violation",
      value: errText,
      status: "critical",
    });
  const note = field(o, "note", optStr, path) ?? "";
  if (note !== "") summary.push({ label: "Note", value: note });
  const rejected = field(o, "publish_rejected", optStr, path) ?? "";
  if (rejected !== "") {
    const at = field(o, "publish_rejected_at", optStr, path) ?? "";
    summary.push({
      label: "Config publish rejected",
      value: at !== "" ? `${rejected} (at ${at})` : rejected,
      status: "critical",
    });
  }
  return {
    verb: "config",
    generatedAt,
    ok,
    summary,
    tables: [
      {
        title: "Collection sizes",
        headers: ["Collection", "Size"],
        rows: sizes,
      },
      {
        title: "Slice utilization vs sync cap",
        headers: ["Slice", "Size", "Cap", "Used"],
        rows: utilization,
      },
    ],
    sub: [],
  };
};

// ── support ────────────────────────────────────────────────────────────────

const decodeSupport: Decoder<DiagnoseView> = (v, path = "$") => {
  const { o, generatedAt } = v1Envelope(v, path);
  const ok = field(o, "ok", readBoolean, path);
  const checks = field(o, "checks", reqArray(decodeStorageCheck), path);
  const summary: DiagnoseKV[] = [
    okBadge(ok),
    {
      label: "Bundles",
      value: String(field(o, "bundle_count", readNumber, path)),
    },
    {
      label: "Pending approval",
      value: String(field(o, "pending_count", readNumber, path)),
    },
    {
      label: "Total size",
      value: fmtBytes(field(o, "total_bytes", readNumber, path)),
    },
    {
      label: "Retention",
      value: `keep ${String(field(o, "retention_keep", readNumber, path))}, max age ${String(field(o, "retention_max_age_days", readNumber, path))}d`,
    },
    {
      label: "Evicted by retention",
      value: String(field(o, "retention_evicted_total", readNumber, path)),
    },
  ];
  const oldest = field(o, "oldest_age_hours", optNum, path);
  const newest = field(o, "newest_age_hours", optNum, path);
  if (oldest !== undefined || newest !== undefined) {
    summary.push({
      label: "Bundle age (newest / oldest)",
      value: `${newest !== undefined ? String(newest) : "—"}h / ${oldest !== undefined ? String(oldest) : "—"}h`,
    });
  }
  const sweep = field(o, "retention_last_sweep", optStr, path) ?? "";
  if (sweep !== "")
    summary.push({ label: "Last retention sweep", value: sweep });
  return {
    verb: "support",
    generatedAt,
    ok,
    summary,
    tables: [checksTable("Support-store checks", checks)],
    sub: [],
  };
};

// ── all (aggregate; nested full sub-results) ───────────────────────────────

const decodeAll: Decoder<DiagnoseView> = (v, path = "$") => {
  const { o, generatedAt } = v1Envelope(v, path);
  const ok = field(o, "ok", readBoolean, path);
  const sub = [
    decodeStorage(o["storage"], `${path}.storage`),
    decodeUpstream(o["upstream"], `${path}.upstream`),
    decodeCluster(o["cluster"], `${path}.cluster`),
    decodeConfig(o["config"], `${path}.config`),
  ];
  return {
    verb: "all",
    generatedAt,
    ok,
    summary: [
      okBadge(ok, "ALL OK", "DEGRADED"),
      {
        label: "Verbs aggregated",
        value: "storage, upstream, cluster, config (dns/tls need a target)",
      },
    ],
    tables: [],
    sub,
  };
};

// ── Registry + runner ──────────────────────────────────────────────────────

const diagnoseDecoders: Record<DiagnoseVerb, Decoder<DiagnoseView>> = {
  storage: decodeStorage,
  upstream: decodeUpstream,
  dns: decodeDNS,
  tls: decodeTLS,
  cluster: decodeCluster,
  etcd: decodeEtcd,
  config: decodeConfig,
  support: decodeSupport,
  all: decodeAll,
};

export function decodeDiagnose(verb: DiagnoseVerb): Decoder<DiagnoseView> {
  return diagnoseDecoders[verb];
}

/** One explicit active-diagnostic run. The AbortSignal is owned by the
 * caller (the diagnostic run owner) — abort cancels the client request and
 * releases client state; it cannot undo a server probe that already ran. */
export function runDiagnose(
  verb: DiagnoseVerb,
  body?: unknown,
  signal?: AbortSignal,
): Promise<DiagnoseView> {
  const opts: { method: "POST"; body?: unknown; signal?: AbortSignal } = {
    method: "POST",
  };
  if (body !== undefined) opts.body = body;
  if (signal !== undefined) opts.signal = signal;
  return apiRequest(`/api/diagnose/${verb}`, diagnoseDecoders[verb], opts);
}
