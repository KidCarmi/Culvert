// Slice 2A-M history-retention API adapter (FE-V02 residue). ONE runtime
// decoder for the retention view — GET /api/logs/retention, the PUT mutation
// response, and the POST /api/logs/purge response all return the same
// logStoreRetentionView() shape and are decoded identically (never separate
// GET/PUT interpretations).
//
// Shape truth (logstore.go logStoreRetentionView/logStoreUsage/
// logStoreDiskEstimate, logguard.go diskGuardStatus):
//   top level: 9 required keys in BOTH branches (enabled/disabled).
//   usage: {enabled:false} alone when the store is off; when on, bytes/
//     dropped/pruned/count/capped/oldestMs are all set. Optional fields
//     decode to undefined — never invented zeros (absent and 0 differ).
//   estimate: always avgEntryBytes/reqPerMin/bytesPerDay/Week/Month.
//   guard: 8 always-present fields; diskUsedPct/diskFreeBytes/diskTotalBytes
//     appear only when statfs succeeded.
import { apiRequest } from "./client";
import type { RequestOptions } from "./client";
import {
  field,
  readBoolean,
  readNumber,
  readOptional,
  readRecord,
  readString,
} from "./decode";
import type { Decoder } from "./decode";

export interface RetentionUsage {
  enabled: boolean;
  bytes: number | undefined;
  dropped: number | undefined;
  pruned: number | undefined;
  count: number | undefined;
  capped: boolean | undefined;
  oldestMs: number | undefined;
}

export interface RetentionEstimate {
  avgEntryBytes: number;
  reqPerMin: number;
  bytesPerDay: number;
  bytesPerWeek: number;
  bytesPerMonth: number;
}

export interface RetentionGuard {
  criticalDiskPct: number;
  minimalMode: boolean;
  loggingMode: string;
  lastCleanupMs: number;
  lastCleanupReason: string;
  pressureBytes: number;
  pressureCount: number;
  warning: string;
  diskUsedPct: number | undefined;
  diskFreeBytes: number | undefined;
  diskTotalBytes: number | undefined;
}

export interface RetentionView {
  enabled: boolean;
  configurable: boolean;
  retentionDays: number;
  retentionMaxGB: number;
  encrypted: boolean;
  encryptionAvailable: boolean;
  usage: RetentionUsage;
  estimate: RetentionEstimate;
  guard: RetentionGuard;
}

const optNum = readOptional(readNumber);
const optBool = readOptional(readBoolean);

const decodeUsage: Decoder<RetentionUsage> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    enabled: field(o, "enabled", readBoolean, path),
    bytes: field(o, "bytes", optNum, path),
    dropped: field(o, "dropped", optNum, path),
    pruned: field(o, "pruned", optNum, path),
    count: field(o, "count", optNum, path),
    capped: field(o, "capped", optBool, path),
    oldestMs: field(o, "oldestMs", optNum, path),
  };
};

const decodeEstimate: Decoder<RetentionEstimate> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    avgEntryBytes: field(o, "avgEntryBytes", readNumber, path),
    reqPerMin: field(o, "reqPerMin", readNumber, path),
    bytesPerDay: field(o, "bytesPerDay", readNumber, path),
    bytesPerWeek: field(o, "bytesPerWeek", readNumber, path),
    bytesPerMonth: field(o, "bytesPerMonth", readNumber, path),
  };
};

const decodeGuard: Decoder<RetentionGuard> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    criticalDiskPct: field(o, "criticalDiskPct", readNumber, path),
    minimalMode: field(o, "minimalMode", readBoolean, path),
    loggingMode: field(o, "loggingMode", readString, path),
    lastCleanupMs: field(o, "lastCleanupMs", readNumber, path),
    lastCleanupReason:
      field(o, "lastCleanupReason", readOptional(readString), path) ?? "",
    pressureBytes: field(o, "pressureBytes", readNumber, path),
    pressureCount: field(o, "pressureCount", readNumber, path),
    warning: field(o, "warning", readOptional(readString), path) ?? "",
    diskUsedPct: field(o, "diskUsedPct", optNum, path),
    diskFreeBytes: field(o, "diskFreeBytes", optNum, path),
    diskTotalBytes: field(o, "diskTotalBytes", optNum, path),
  };
};

export const decodeRetentionView: Decoder<RetentionView> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    enabled: field(o, "enabled", readBoolean, path),
    configurable: field(o, "configurable", readBoolean, path),
    retentionDays: field(o, "retentionDays", readNumber, path),
    retentionMaxGB: field(o, "retentionMaxGB", readNumber, path),
    encrypted: field(o, "encrypted", readBoolean, path),
    encryptionAvailable: field(o, "encryptionAvailable", readBoolean, path),
    usage: field(o, "usage", decodeUsage, path),
    estimate: field(o, "estimate", decodeEstimate, path),
    guard: field(o, "guard", decodeGuard, path),
  };
};

export function getRetention(signal?: AbortSignal): Promise<RetentionView> {
  return apiRequest(
    "/api/logs/retention",
    decodeRetentionView,
    signal !== undefined ? { signal } : {},
  );
}

// Server validation truth (ui_config.go): retentionDays 0..3650,
// retentionMaxGB 0..10000, criticalDiskPct 50..99. Mirrored client-side for
// UX only — the server stays authoritative.
export const RETENTION_BOUNDS = {
  days: { min: 0, max: 3650 },
  maxGB: { min: 0, max: 10000 },
  criticalDiskPct: { min: 50, max: 99 },
} as const;

export interface RetentionUpdate {
  enabled: boolean;
  retentionDays: number;
  retentionMaxGB: number;
  criticalDiskPct: number;
}

export function putRetention(
  update: RetentionUpdate,
  signal?: AbortSignal,
): Promise<RetentionView> {
  const opts: RequestOptions = { method: "PUT", body: update };
  if (signal !== undefined) opts.signal = signal;
  return apiRequest("/api/logs/retention", decodeRetentionView, opts);
}

export function purgeHistory(signal?: AbortSignal): Promise<RetentionView> {
  const opts: RequestOptions = { method: "POST" };
  if (signal !== undefined) opts.signal = signal;
  return apiRequest("/api/logs/purge", decodeRetentionView, opts);
}
