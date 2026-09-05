// 2F-E — the PAC (proxy auto-config) admin API boundary: profiles, pools,
// the node-local publish lifecycle (draft / active / history), the bound
// DIRECT challenge, DIRECT-exception governance, the legacy default PAC and
// the simulator. Every response crosses the boundary through a total
// decoder (contract §7.T3 names "policy draft + version-fencing responses"
// as mandatory-decoder paths); every refusal the page must act on is
// decoded STRUCTURALLY from the server body (§8.D7/D12) — never from prose.
//
// Fence dialect (2F-A, C3): absent token ⇒ 428 {code:"precondition_required",
// current}; mismatch ⇒ 409 {code:"stale", current}; vanished ⇒ 404. Tokens:
// profile `revision`, pool `etag`, listing `collectionEtag`, draft
// `draftRevision`, lifecycle `expectedActiveRevision` (refused under the
// key `revision`). DELETEs carry their token in the QUERY only.
//
// Lifecycle dialect (2F-B, C1/C2/C8): the client mints the UUID
// `operationId` BEFORE dispatch and reuses it on every retry (the appliance
// replays a decided operation byte-for-byte); the bound DIRECT challenge is
// echoed VERBATIM as {challenge, value, binding} under `confirm`; the
// retired `confirmDirect` is never sent.
import { ApiError, apiRequest } from "./client";
import {
  DecodeError,
  field,
  isRecord,
  readArray,
  readBoolean,
  readEnum,
  readNumber,
  readOptional,
  readRecord,
  readString,
} from "./decode";
import type { Decoder } from "./decode";

function opt<T>(
  o: Record<string, unknown>,
  key: string,
  read: Decoder<T>,
  path: string,
): T | undefined {
  return readOptional(read)(o[key], `${path}.${key}`);
}

// ── Model ───────────────────────────────────────────────────────────────────

export const PAC_RULE_KINDS = [
  "domain",
  "suffix",
  "wildcard",
  "cidr4",
] as const;
export type PacRuleKind = (typeof PAC_RULE_KINDS)[number];
export const PAC_RULE_ACTIONS = ["use_pool", "direct"] as const;
export type PacRuleAction = (typeof PAC_RULE_ACTIONS)[number];
export const PAC_PRIVATE_NETWORKS = ["direct", "proxy"] as const;
export type PacPrivateNetworks = (typeof PAC_PRIVATE_NETWORKS)[number];
export const PAC_AVAILABILITY_MODES = [
  "secure",
  "balanced",
  "availability",
] as const;
export type PacAvailabilityMode = (typeof PAC_AVAILABILITY_MODES)[number];

/** A client-authored rule (what an editor or a reviewed draft carries);
 * the appliance validates it (400 issues). Optional keys are omitted on
 * the wire when empty — the strict server decoder tolerates absence only. */
export interface PacRuleInput {
  kind: string;
  pattern: string;
  action: string;
  scheme?: string;
  port?: number;
  poolId?: string;
}

/** A server-decoded rule: the enums are proven. */
export interface PacRule extends PacRuleInput {
  kind: PacRuleKind;
  action: PacRuleAction;
}

/** A client-authored profile (draft/candidate) — see PacRuleInput. */
export interface PacProfileInput {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  poolId: string;
  rules: readonly PacRuleInput[];
  privateNetworks: string;
  availabilityMode: string;
  revision: number;
}

/** A server-decoded profile: the enums are proven. */
export interface PacProfile extends PacProfileInput {
  rules: readonly PacRule[];
  privateNetworks: PacPrivateNetworks;
  availabilityMode: PacAvailabilityMode;
}

export interface PacPoolEndpoint {
  host: string;
  port: number;
}

export interface PacPool {
  id: string;
  name: string;
  endpoints: readonly PacPoolEndpoint[];
}

export interface PacPoolView extends PacPool {
  etag: string;
}

export interface PacDefaultProfile {
  id: string;
  name: string;
  enabled: boolean;
  legacyManaged: boolean;
  availabilityMode: string;
  privateNetworks: string;
  proxyHost: string;
  proxyPort: number;
  exclusions: number;
  pacPath: string;
}

export interface PacProfilesListing {
  defaultProfile: PacDefaultProfile;
  profiles: readonly PacProfile[];
  pools: readonly PacPool[];
  collectionEtag: string;
  poolEtags: Readonly<Record<string, string>>;
}

export const decodePacRule: Decoder<PacRule> = (v, path = "$") => {
  const o = readRecord(v, path);
  const scheme = opt(o, "scheme", readString, path);
  const port = opt(o, "port", readNumber, path);
  const poolId = opt(o, "poolId", readString, path);
  return {
    kind: field(o, "kind", readEnum(PAC_RULE_KINDS), path),
    pattern: field(o, "pattern", readString, path),
    action: field(o, "action", readEnum(PAC_RULE_ACTIONS), path),
    ...(scheme !== undefined && scheme !== "" ? { scheme } : {}),
    ...(port !== undefined && port !== 0 ? { port } : {}),
    ...(poolId !== undefined && poolId !== "" ? { poolId } : {}),
  };
};

export const decodePacProfile: Decoder<PacProfile> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    id: opt(o, "id", readString, path) ?? "",
    name: opt(o, "name", readString, path) ?? "",
    description: opt(o, "description", readString, path) ?? "",
    enabled: opt(o, "enabled", readBoolean, path) ?? false,
    poolId: opt(o, "poolId", readString, path) ?? "",
    rules: opt(o, "rules", readArray(decodePacRule), path) ?? [],
    privateNetworks:
      opt(o, "privateNetworks", readEnum(PAC_PRIVATE_NETWORKS), path) ??
      "proxy",
    availabilityMode:
      opt(o, "availabilityMode", readEnum(PAC_AVAILABILITY_MODES), path) ??
      "secure",
    revision: opt(o, "revision", readNumber, path) ?? 0,
  };
};

const decodePoolEndpoint: Decoder<PacPoolEndpoint> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    host: field(o, "host", readString, path),
    port: field(o, "port", readNumber, path),
  };
};

export const decodePacPool: Decoder<PacPool> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    id: field(o, "id", readString, path),
    name: opt(o, "name", readString, path) ?? "",
    endpoints: opt(o, "endpoints", readArray(decodePoolEndpoint), path) ?? [],
  };
};

export const decodePacPoolView: Decoder<PacPoolView> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    ...decodePacPool(o, path),
    etag: field(o, "etag", readString, path),
  };
};

const decodeDefaultProfile: Decoder<PacDefaultProfile> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    id: field(o, "id", readString, path),
    name: field(o, "name", readString, path),
    enabled: field(o, "enabled", readBoolean, path),
    legacyManaged: field(o, "legacyManaged", readBoolean, path),
    availabilityMode: field(o, "availabilityMode", readString, path),
    privateNetworks: field(o, "privateNetworks", readString, path),
    proxyHost: field(o, "proxyHost", readString, path),
    proxyPort: field(o, "proxyPort", readNumber, path),
    exclusions: field(o, "exclusions", readNumber, path),
    pacPath: field(o, "pacPath", readString, path),
  };
};

function readStringMap(
  v: unknown,
  path = "$",
): Readonly<Record<string, string>> {
  const o = readRecord(v, path);
  const out: Record<string, string> = {};
  for (const k of Object.keys(o)) out[k] = readString(o[k], `${path}.${k}`);
  return out;
}

export const decodePacProfilesListing: Decoder<PacProfilesListing> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    defaultProfile: field(o, "defaultProfile", decodeDefaultProfile, path),
    profiles: opt(o, "profiles", readArray(decodePacProfile), path) ?? [],
    pools: opt(o, "pools", readArray(decodePacPool), path) ?? [],
    collectionEtag: field(o, "collectionEtag", readString, path),
    poolEtags: opt(o, "poolEtags", readStringMap, path) ?? {},
  };
};

// ── Lifecycle ───────────────────────────────────────────────────────────────

export const PAC_LIFECYCLE_STATES = ["idle", "pending", "ambiguous"] as const;
export type PacLifecycleState = (typeof PAC_LIFECYCLE_STATES)[number];
export const PAC_HISTORY_STATES = [
  "recorded",
  "pending_reconciliation",
  "ambiguous",
  "history_reset",
] as const;
export type PacHistoryState = (typeof PAC_HISTORY_STATES)[number];
export const PAC_OP_STATES = [
  "pending",
  "committed",
  "recorded",
  "aborted",
  "ambiguous",
] as const;
export type PacOpState = (typeof PAC_OP_STATES)[number];

export interface PacRevision {
  n: number;
  spec: PacProfile;
  digest: string;
  author: string;
  reason: string;
  ts: string;
  operationId: string;
  specDigest: string;
  poolDigest: string;
  repaired: boolean;
}

export interface PacProfileDiff {
  /** Rule DESCRIPTIONS (server-rendered strings, e.g. "rule 3: direct
   * domain intranet.example"), never rule objects — `internal/pac`
   * ProfileDiff. */
  rulesAdded: readonly string[];
  rulesRemoved: readonly string[];
  rulesReordered: boolean;
  poolChanged: boolean;
  oldPool: string;
  newPool: string;
  availabilityChange: string;
  privateNetChange: string;
  newDirectPaths: readonly string[];
  removedDirectPaths: readonly string[];
  securitySensitive: boolean;
}

export interface PacOpProgress {
  history: boolean;
  configVersion: boolean;
  cluster: boolean;
}

export interface PacPendingOp {
  operationId: string;
  action: string;
  state: PacOpState;
  expectedActiveRevision: number;
  candidateSpecDigest: string;
  ts: string;
  progress: PacOpProgress;
}

export interface PacDecidedOp {
  operationId: string;
  action: string;
  state: PacOpState;
  ts: string;
  status: number;
}

export interface PacOperationLookup {
  operationId: string;
  found: boolean;
  state: PacOpState | undefined;
  status: number | undefined;
  ts: string;
  /** the history revision the operation produced (0 when none / unknown) */
  revisionN: number;
}

const decodeOperationLookup: Decoder<PacOperationLookup> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    operationId: field(o, "operationId", readString, path),
    found: field(o, "found", readBoolean, path),
    state: opt(o, "state", readEnum(PAC_OP_STATES), path),
    status: opt(o, "status", readNumber, path),
    ts: opt(o, "ts", readString, path) ?? "",
    revisionN: opt(o, "revisionN", readNumber, path) ?? 0,
  };
};

export interface PacAmbiguousOp {
  op: PacPendingOp;
  observedRevision: number;
  observedSpecDigest: string;
  observedAt: string;
}

export interface PacHistoryResetAck {
  operationId: string;
  by: string;
  at: string;
  activeRevision: number;
  activeSpecDigest: string;
}

export interface PacHistoryReset {
  at: string;
  quarantinedTo: string;
  cause: string;
  scoped: boolean;
  activeAtReset: readonly string[];
  acknowledgedProfiles: number;
  ackAction: string;
  acknowledged: PacHistoryResetAck | undefined;
}

export interface PacLifecycle {
  profileId: string;
  activeExists: boolean;
  /** Absent when the profile has no active spec on this node
   * (`activeExists:false` — the backend serialises a zero Profile there). */
  active: PacProfile | undefined;
  /** Absent until a draft has ever been saved (`draftRevision` 0 — the
   * backend serialises a zero Profile there, not the active spec). */
  draft: PacProfile | undefined;
  draftDirty: boolean;
  activeN: number;
  revisions: readonly PacRevision[];
  draftDiff: PacProfileDiff | undefined;
  draftRevision: number;
  activeRevision: number;
  collectionEtag: string;
  state: PacLifecycleState;
  historyState: PacHistoryState;
  pendingOp: PacPendingOp | undefined;
  ambiguous: PacAmbiguousOp | undefined;
  operations: readonly PacDecidedOp[];
  activeSpecDigest: string;
  /** Digest of the SAVED draft ("" when no draft was ever saved) — the
   * identity a publish binds its marker to (2F-E correction). */
  draftSpecDigest: string;
  /** Recovery-evidence limits (2F-E correction): how many decided
   * operations the appliance retains against its cap. `operations` lists
   * only the 20 most recent; absence there proves nothing unless the
   * retained ring is complete. Absent on a pre-correction appliance. */
  operationsRetained: number | undefined;
  operationsCap: number | undefined;
  /** The answer to `?operationId=` — one operation looked up in the FULL
   * retained ring and the revision history. */
  operation: PacOperationLookup | undefined;
  poolChangedSince: boolean;
  scope: string;
  historyReset: PacHistoryReset | undefined;
  previousRevision: number | undefined;
}

const decodeRevision: Decoder<PacRevision> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    n: field(o, "n", readNumber, path),
    spec: field(o, "spec", decodePacProfile, path),
    digest: opt(o, "digest", readString, path) ?? "",
    author: opt(o, "author", readString, path) ?? "",
    reason: opt(o, "reason", readString, path) ?? "",
    ts: opt(o, "ts", readString, path) ?? "",
    operationId: opt(o, "operationId", readString, path) ?? "",
    specDigest: opt(o, "specDigest", readString, path) ?? "",
    poolDigest: opt(o, "poolDigest", readString, path) ?? "",
    repaired: opt(o, "repaired", readBoolean, path) ?? false,
  };
};

const readStrings = readArray(readString);

export const decodePacProfileDiff: Decoder<PacProfileDiff> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    rulesAdded: opt(o, "rulesAdded", readStrings, path) ?? [],
    rulesRemoved: opt(o, "rulesRemoved", readStrings, path) ?? [],
    rulesReordered: opt(o, "rulesReordered", readBoolean, path) ?? false,
    poolChanged: opt(o, "poolChanged", readBoolean, path) ?? false,
    oldPool: opt(o, "oldPool", readString, path) ?? "",
    newPool: opt(o, "newPool", readString, path) ?? "",
    availabilityChange: opt(o, "availabilityChange", readString, path) ?? "",
    privateNetChange: opt(o, "privateNetChange", readString, path) ?? "",
    newDirectPaths: opt(o, "newDirectPaths", readStrings, path) ?? [],
    removedDirectPaths: opt(o, "removedDirectPaths", readStrings, path) ?? [],
    securitySensitive: opt(o, "securitySensitive", readBoolean, path) ?? false,
  };
};

const decodeProgress: Decoder<PacOpProgress> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    history: opt(o, "history", readBoolean, path) ?? false,
    configVersion: opt(o, "configVersion", readBoolean, path) ?? false,
    cluster: opt(o, "cluster", readBoolean, path) ?? false,
  };
};

const decodePendingOp: Decoder<PacPendingOp> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    operationId: field(o, "operationId", readString, path),
    action: opt(o, "action", readString, path) ?? "",
    state: opt(o, "state", readEnum(PAC_OP_STATES), path) ?? "pending",
    expectedActiveRevision:
      opt(o, "expectedActiveRevision", readNumber, path) ?? 0,
    candidateSpecDigest: opt(o, "candidateSpecDigest", readString, path) ?? "",
    ts: opt(o, "ts", readString, path) ?? "",
    progress: opt(o, "progress", decodeProgress, path) ?? {
      history: false,
      configVersion: false,
      cluster: false,
    },
  };
};

const decodeDecidedOp: Decoder<PacDecidedOp> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    operationId: field(o, "operationId", readString, path),
    action: opt(o, "action", readString, path) ?? "",
    state: field(o, "state", readEnum(PAC_OP_STATES), path),
    ts: opt(o, "ts", readString, path) ?? "",
    status: opt(o, "status", readNumber, path) ?? 0,
  };
};

const decodeAmbiguous: Decoder<PacAmbiguousOp> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    op: field(o, "op", decodePendingOp, path),
    observedRevision: opt(o, "observedRevision", readNumber, path) ?? 0,
    observedSpecDigest: opt(o, "observedSpecDigest", readString, path) ?? "",
    observedAt: opt(o, "observedAt", readString, path) ?? "",
  };
};

const decodeAck: Decoder<PacHistoryResetAck> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    operationId: opt(o, "operationId", readString, path) ?? "",
    by: opt(o, "by", readString, path) ?? "",
    at: opt(o, "at", readString, path) ?? "",
    activeRevision: opt(o, "activeRevision", readNumber, path) ?? 0,
    activeSpecDigest: opt(o, "activeSpecDigest", readString, path) ?? "",
  };
};

export const decodePacHistoryReset: Decoder<PacHistoryReset> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    at: opt(o, "at", readString, path) ?? "",
    quarantinedTo: opt(o, "quarantinedTo", readString, path) ?? "",
    cause: opt(o, "cause", readString, path) ?? "",
    scoped: opt(o, "scoped", readBoolean, path) ?? false,
    activeAtReset: opt(o, "activeAtReset", readStrings, path) ?? [],
    acknowledgedProfiles: opt(o, "acknowledgedProfiles", readNumber, path) ?? 0,
    ackAction: opt(o, "ackAction", readString, path) ?? "",
    acknowledged: opt(o, "acknowledged", decodeAck, path),
  };
};

export const decodePacLifecycle: Decoder<PacLifecycle> = (v, path = "$") => {
  const o = readRecord(v, path);
  const activeExists = field(o, "activeExists", readBoolean, path);
  const draftRevision = field(o, "draftRevision", readNumber, path);
  return {
    profileId: field(o, "profileId", readString, path),
    activeExists,
    active: activeExists
      ? field(o, "active", decodePacProfile, path)
      : undefined,
    draft:
      draftRevision > 0 ? field(o, "draft", decodePacProfile, path) : undefined,
    draftDirty: field(o, "draftDirty", readBoolean, path),
    activeN: field(o, "activeN", readNumber, path),
    revisions: opt(o, "revisions", readArray(decodeRevision), path) ?? [],
    draftDiff: opt(o, "draftDiff", decodePacProfileDiff, path),
    draftRevision,
    activeRevision: field(o, "activeRevision", readNumber, path),
    collectionEtag: field(o, "collectionEtag", readString, path),
    state: field(o, "state", readEnum(PAC_LIFECYCLE_STATES), path),
    historyState: field(o, "historyState", readEnum(PAC_HISTORY_STATES), path),
    pendingOp: opt(o, "pendingOp", decodePendingOp, path),
    ambiguous: opt(o, "ambiguous", decodeAmbiguous, path),
    operations: opt(o, "operations", readArray(decodeDecidedOp), path) ?? [],
    activeSpecDigest: opt(o, "activeSpecDigest", readString, path) ?? "",
    draftSpecDigest: opt(o, "draftSpecDigest", readString, path) ?? "",
    operationsRetained: opt(o, "operationsRetained", readNumber, path),
    operationsCap: opt(o, "operationsCap", readNumber, path),
    operation: opt(o, "operation", decodeOperationLookup, path),
    poolChangedSince: opt(o, "poolChangedSince", readBoolean, path) ?? false,
    scope: opt(o, "scope", readString, path) ?? "",
    historyReset: opt(o, "historyReset", decodePacHistoryReset, path),
    previousRevision: opt(o, "previousRevision", readNumber, path),
  };
};

export interface PacOperationResult {
  operationId: string;
  activeRevision: number;
  activeSpecDigest: string;
  digest: string;
  draftRevision: number;
  historyState: PacHistoryState;
  scope: string;
  published: boolean;
  rolledBack: boolean;
  revision: number;
  toRevision: number;
  newRevision: number;
}

export const decodePacOperationResult: Decoder<PacOperationResult> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    operationId: field(o, "operationId", readString, path),
    activeRevision: field(o, "activeRevision", readNumber, path),
    activeSpecDigest: opt(o, "activeSpecDigest", readString, path) ?? "",
    digest: opt(o, "digest", readString, path) ?? "",
    draftRevision: opt(o, "draftRevision", readNumber, path) ?? 0,
    historyState: field(o, "historyState", readEnum(PAC_HISTORY_STATES), path),
    scope: opt(o, "scope", readString, path) ?? "",
    published: opt(o, "published", readBoolean, path) ?? false,
    rolledBack: opt(o, "rolledBack", readBoolean, path) ?? false,
    revision: opt(o, "revision", readNumber, path) ?? 0,
    toRevision: opt(o, "toRevision", readNumber, path) ?? 0,
    newRevision: opt(o, "newRevision", readNumber, path) ?? 0,
  };
};

export interface PacSaveDraftResult {
  draftDirty: boolean;
  draft: PacProfile;
  draftRevision: number;
}

const decodeSaveDraft: Decoder<PacSaveDraftResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    draftDirty: field(o, "draftDirty", readBoolean, path),
    draft: field(o, "draft", decodePacProfile, path),
    draftRevision: field(o, "draftRevision", readNumber, path),
  };
};

export interface PacRepairResult {
  repaired: boolean;
  operationId: string;
  revision: number;
  activeRevision: number;
  activeSpecDigest: string;
  historyState: PacHistoryState;
}

const decodeRepair: Decoder<PacRepairResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    repaired: field(o, "repaired", readBoolean, path),
    operationId: opt(o, "operationId", readString, path) ?? "",
    revision: opt(o, "revision", readNumber, path) ?? 0,
    activeRevision: opt(o, "activeRevision", readNumber, path) ?? 0,
    activeSpecDigest: opt(o, "activeSpecDigest", readString, path) ?? "",
    historyState: field(o, "historyState", readEnum(PAC_HISTORY_STATES), path),
  };
};

export interface PacAckResult {
  acknowledged: boolean;
  operationId: string;
  historyState: PacHistoryState;
  activeRevision: number;
  activeSpecDigest: string;
  replayed: boolean;
}

const decodeAckResult: Decoder<PacAckResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    acknowledged: field(o, "acknowledged", readBoolean, path),
    operationId: opt(o, "operationId", readString, path) ?? "",
    historyState: field(o, "historyState", readEnum(PAC_HISTORY_STATES), path),
    activeRevision: opt(o, "activeRevision", readNumber, path) ?? 0,
    activeSpecDigest: opt(o, "activeSpecDigest", readString, path) ?? "",
    replayed: opt(o, "replayed", readBoolean, path) ?? false,
  };
};

// ── Exceptions / posture ────────────────────────────────────────────────────

export interface PacExceptionRecord {
  profileId: string;
  owner: string;
  reason: string;
  businessApp: string;
  ticket: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  reviewCadenceDays: number;
  lastReviewedAt: string;
  revision: number;
}

export const PAC_EXCEPTION_STATUSES = [
  "",
  "ungoverned",
  "expired",
  "review_due",
  "governed",
] as const;
export type PacExceptionStatus = (typeof PAC_EXCEPTION_STATUSES)[number];

export interface PacExceptionView {
  profileId: string;
  name: string;
  serving: boolean;
  directCapable: boolean;
  status: PacExceptionStatus;
  record: PacExceptionRecord | undefined;
}

export const decodePacExceptionRecord: Decoder<PacExceptionRecord> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    profileId: opt(o, "profileId", readString, path) ?? "",
    owner: opt(o, "owner", readString, path) ?? "",
    reason: opt(o, "reason", readString, path) ?? "",
    businessApp: opt(o, "businessApp", readString, path) ?? "",
    ticket: opt(o, "ticket", readString, path) ?? "",
    createdBy: opt(o, "createdBy", readString, path) ?? "",
    createdAt: opt(o, "createdAt", readString, path) ?? "",
    updatedAt: opt(o, "updatedAt", readString, path) ?? "",
    expiresAt: opt(o, "expiresAt", readString, path) ?? "",
    reviewCadenceDays: opt(o, "reviewCadenceDays", readNumber, path) ?? 0,
    lastReviewedAt: opt(o, "lastReviewedAt", readString, path) ?? "",
    revision: opt(o, "revision", readNumber, path) ?? 0,
  };
};

const decodeExceptionView: Decoder<PacExceptionView> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    profileId: field(o, "profileId", readString, path),
    name: opt(o, "name", readString, path) ?? "",
    serving: opt(o, "serving", readBoolean, path) ?? false,
    directCapable: opt(o, "directCapable", readBoolean, path) ?? false,
    status: field(o, "status", readEnum(PAC_EXCEPTION_STATUSES), path),
    record: opt(o, "record", decodePacExceptionRecord, path),
  };
};

const decodeExceptionsListing: Decoder<readonly PacExceptionView[]> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return opt(o, "exceptions", readArray(decodeExceptionView), path) ?? [];
};

export interface PacDirectEntry {
  kind: string;
  detail: string;
  ruleIndex: number;
  pattern: string;
  broad: boolean;
}

export interface PacProfileInventory {
  profileId: string;
  name: string;
  serving: boolean;
  availabilityMode: string;
  directCapable: boolean;
  directPaths: readonly PacDirectEntry[];
}

export interface PacInventory {
  evidenceClass: string;
  profiles: readonly PacProfileInventory[];
  totalProfiles: number;
  directCapableProfiles: number;
  servingDirectProfiles: number;
  totalDirectPaths: number;
  broadDirectPaths: number;
}

const decodeDirectEntry: Decoder<PacDirectEntry> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    kind: opt(o, "kind", readString, path) ?? "",
    detail: opt(o, "detail", readString, path) ?? "",
    ruleIndex: opt(o, "ruleIndex", readNumber, path) ?? -1,
    pattern: opt(o, "pattern", readString, path) ?? "",
    broad: opt(o, "broad", readBoolean, path) ?? false,
  };
};

const decodeProfileInventory: Decoder<PacProfileInventory> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    profileId: field(o, "profileId", readString, path),
    name: opt(o, "name", readString, path) ?? "",
    serving: opt(o, "serving", readBoolean, path) ?? false,
    availabilityMode: opt(o, "availabilityMode", readString, path) ?? "",
    directCapable: opt(o, "directCapable", readBoolean, path) ?? false,
    directPaths:
      opt(o, "directPaths", readArray(decodeDirectEntry), path) ?? [],
  };
};

export const decodePacInventory: Decoder<PacInventory> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    evidenceClass: opt(o, "evidenceClass", readString, path) ?? "",
    profiles: opt(o, "profiles", readArray(decodeProfileInventory), path) ?? [],
    totalProfiles: opt(o, "totalProfiles", readNumber, path) ?? 0,
    directCapableProfiles:
      opt(o, "directCapableProfiles", readNumber, path) ?? 0,
    servingDirectProfiles:
      opt(o, "servingDirectProfiles", readNumber, path) ?? 0,
    totalDirectPaths: opt(o, "totalDirectPaths", readNumber, path) ?? 0,
    broadDirectPaths: opt(o, "broadDirectPaths", readNumber, path) ?? 0,
  };
};

// ── Legacy default PAC + simulator ──────────────────────────────────────────

export interface PacConfig {
  proxyHost: string;
  proxyPort: number;
  exclusions: readonly string[];
  revision: number;
}

export interface PacValidationIssue {
  field: string;
  entry: string;
  code: string;
  message: string;
}

export const decodePacValidationIssue: Decoder<PacValidationIssue> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    field: opt(o, "field", readString, path) ?? "",
    entry: opt(o, "entry", readString, path) ?? "",
    code: opt(o, "code", readString, path) ?? "",
    message: opt(o, "message", readString, path) ?? "",
  };
};

export interface PacConfigSaveResult extends PacConfig {
  warnings: readonly PacValidationIssue[];
}

export const decodePacConfig: Decoder<PacConfig> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    proxyHost: opt(o, "proxyHost", readString, path) ?? "",
    proxyPort: opt(o, "proxyPort", readNumber, path) ?? 0,
    exclusions: opt(o, "exclusions", readStrings, path) ?? [],
    revision: opt(o, "revision", readNumber, path) ?? 0,
  };
};

const decodePacConfigSave: Decoder<PacConfigSaveResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    ...decodePacConfig(o, path),
    warnings:
      opt(o, "warnings", readArray(decodePacValidationIssue), path) ?? [],
  };
};

export interface PacSimResult {
  directive: string;
  outcome: string;
  matchedRule:
    | { index: number; kind: string; pattern: string; action: string }
    | undefined;
  reason: string;
  poolId: string;
  chain: readonly string[];
  directPossible: boolean;
  warnings: readonly string[];
  compilerVersion: string;
  revision: number;
}

const decodeMatchedRule: Decoder<{
  index: number;
  kind: string;
  pattern: string;
  action: string;
}> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    index: opt(o, "index", readNumber, path) ?? -1,
    kind: opt(o, "kind", readString, path) ?? "",
    pattern: opt(o, "pattern", readString, path) ?? "",
    action: opt(o, "action", readString, path) ?? "",
  };
};

export const decodePacSimResult: Decoder<PacSimResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    directive: opt(o, "directive", readString, path) ?? "",
    outcome: opt(o, "outcome", readString, path) ?? "",
    matchedRule: opt(o, "matchedRule", decodeMatchedRule, path),
    reason: opt(o, "reason", readString, path) ?? "",
    poolId: opt(o, "poolId", readString, path) ?? "",
    chain: opt(o, "chain", readStrings, path) ?? [],
    directPossible: opt(o, "directPossible", readBoolean, path) ?? false,
    warnings: opt(o, "warnings", readStrings, path) ?? [],
    compilerVersion: opt(o, "compilerVersion", readString, path) ?? "",
    revision: opt(o, "revision", readNumber, path) ?? 0,
  };
};

// ── Structured refusals ─────────────────────────────────────────────────────

function parsedBody(
  err: unknown,
  statuses: readonly number[],
): Record<string, unknown> | null {
  if (!(err instanceof ApiError)) return null;
  if (err.status === undefined || !statuses.includes(err.status)) return null;
  if (err.bodyText === undefined) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(err.bodyText);
  } catch {
    return null;
  }
  return isRecord(parsed) ? parsed : null;
}

export interface PacFenceRefusal {
  status: 428 | 409;
  code: "precondition_required" | "stale";
  current: Readonly<Record<string, unknown>>;
  message: string;
}

/** The 2F-A fence: 428 precondition_required / 409 stale with the
 * server-owned `current` token (never parsed from prose). */
export function asPacFence(err: unknown): PacFenceRefusal | null {
  const o = parsedBody(err, [428, 409]);
  if (o === null || !(err instanceof ApiError)) return null;
  const code = o["code"];
  if (code !== "precondition_required" && code !== "stale") return null;
  const current = o["current"];
  return {
    status: err.status === 428 ? 428 : 409,
    code,
    current: isRecord(current) ? current : {},
    message: typeof o["error"] === "string" ? o["error"] : "",
  };
}

/** The numeric token the fence reports under `current` (revision,
 * draftRevision) — or undefined when the token is a string (etag). */
export function fenceCurrentNumber(
  f: PacFenceRefusal,
  key: string,
): number | undefined {
  const v = f.current[key];
  return typeof v === "number" ? v : undefined;
}

export interface PacChallenge {
  code: "confirm_required" | "challenge_stale";
  challenge: string;
  confirmValue: string;
  /** the server-issued binding, preserved VERBATIM for the echo */
  binding: Readonly<Record<string, unknown>>;
  newDirectPaths: readonly string[];
  changed: readonly string[];
  message: string;
}

/** A best-effort string list from a refusal body: absent or malformed
 * reads as empty — a refusal is never rejected for a decorative field. */
function stringsOrEmpty(v: unknown): readonly string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string");
}

/** The bound DIRECT challenge (C2): confirm_required on issue,
 * challenge_stale when any bound field moved (the `changed` list). */
export function asPacChallenge(err: unknown): PacChallenge | null {
  const o = parsedBody(err, [409]);
  if (o === null) return null;
  const code = o["code"];
  if (code !== "confirm_required" && code !== "challenge_stale") return null;
  const binding = isRecord(o["binding"]) ? o["binding"] : {};
  const paths = stringsOrEmpty(binding["newDirectPaths"]);
  const changed = stringsOrEmpty(o["changed"]);
  return {
    code,
    challenge: typeof o["challenge"] === "string" ? o["challenge"] : "",
    confirmValue:
      typeof o["confirmValue"] === "string" ? o["confirmValue"] : "",
    binding,
    newDirectPaths: paths,
    changed,
    message: typeof o["error"] === "string" ? o["error"] : "",
  };
}

export interface PacHistoryResetRefusal {
  activeRevision: number;
  activeSpecDigest: string;
  reset: PacHistoryReset;
  message: string;
}

/** 409 history_reset: the node-local history was quarantined; publish and
 * rollback are withheld until the admin acknowledges against the reviewed
 * active revision + spec digest. */
export function asPacHistoryReset(err: unknown): PacHistoryResetRefusal | null {
  const o = parsedBody(err, [409]);
  if (o === null || o["code"] !== "history_reset") return null;
  const current = isRecord(o["current"]) ? o["current"] : {};
  let reset: PacHistoryReset;
  try {
    reset = decodePacHistoryReset(o["historyReset"], "$.historyReset");
  } catch {
    return null;
  }
  return {
    activeRevision:
      typeof current["revision"] === "number" ? current["revision"] : 0,
    activeSpecDigest:
      typeof current["activeSpecDigest"] === "string"
        ? current["activeSpecDigest"]
        : "",
    reset,
    message: typeof o["error"] === "string" ? o["error"] : "",
  };
}

export interface PacOperationPending {
  operationId: string;
  state: string;
  message: string;
}

export function asPacOperationPending(
  err: unknown,
): PacOperationPending | null {
  const o = parsedBody(err, [409]);
  if (o === null || o["code"] !== "operation_pending") return null;
  const current = isRecord(o["current"]) ? o["current"] : {};
  return {
    operationId:
      typeof current["operationId"] === "string" ? current["operationId"] : "",
    state: typeof current["state"] === "string" ? current["state"] : "",
    message: typeof o["error"] === "string" ? o["error"] : "",
  };
}

export interface PacAmbiguousRefusal {
  operationId: string;
  observedRevision: number;
  observedSpecDigest: string;
  message: string;
}

/** 503 lifecycle_ambiguous: the appliance cannot tell what happened; only
 * the admin repair ceremony (accept_active) resolves it. */
export function asPacAmbiguous(err: unknown): PacAmbiguousRefusal | null {
  const o = parsedBody(err, [503]);
  if (o === null || o["code"] !== "lifecycle_ambiguous") return null;
  const observed = isRecord(o["observed"]) ? o["observed"] : {};
  return {
    operationId: typeof o["operationId"] === "string" ? o["operationId"] : "",
    observedRevision:
      typeof observed["revision"] === "number" ? observed["revision"] : 0,
    observedSpecDigest:
      typeof observed["specDigest"] === "string" ? observed["specDigest"] : "",
    message: typeof o["error"] === "string" ? o["error"] : "",
  };
}

export interface PacServerOutcome {
  code: "outcome_unknown" | "active_write_failed";
  operationId: string;
  message: string;
}

/** 500 outcome_unknown (intent retained, reconciled later) / 500
 * active_write_failed (proven abort, nothing changed). */
export function asPacServerOutcome(err: unknown): PacServerOutcome | null {
  const o = parsedBody(err, [500]);
  if (o === null) return null;
  const code = o["code"];
  if (code !== "outcome_unknown" && code !== "active_write_failed") return null;
  return {
    code,
    operationId: typeof o["operationId"] === "string" ? o["operationId"] : "",
    message: typeof o["error"] === "string" ? o["error"] : "",
  };
}

export interface PacIssuesRefusal {
  error: string;
  issues: readonly PacValidationIssue[];
}

/** 400 {error, issues[]} — validation or guardrail refusal. */
export function asPacIssues(err: unknown): PacIssuesRefusal | null {
  const o = parsedBody(err, [400]);
  if (o === null || !Array.isArray(o["issues"])) return null;
  try {
    return {
      error: typeof o["error"] === "string" ? o["error"] : "refused",
      issues: readArray(decodePacValidationIssue)(o["issues"], "$.issues"),
    };
  } catch {
    return null;
  }
}

// ── Operation identity ──────────────────────────────────────────────────────

/** Mint the client-side operation identity: an RFC 4122 UUID — the grammar
 * the lifecycle endpoint requires for publish/rollback/repair/ack. */
export function mintPacOperationId(): string {
  return crypto.randomUUID();
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isPacOperationId(v: string): boolean {
  return UUID_RE.test(v);
}

// ── Requests ────────────────────────────────────────────────────────────────

function sig(
  signal: AbortSignal | undefined,
): { signal: AbortSignal } | Record<never, never> {
  return signal !== undefined ? { signal } : {};
}

function profilePath(id: string, sub = ""): string {
  return `/api/pac/profiles/${encodeURIComponent(id)}${sub}`;
}

export function getPacProfiles(
  signal?: AbortSignal,
): Promise<PacProfilesListing> {
  return apiRequest("/api/pac/profiles", decodePacProfilesListing, sig(signal));
}

export function getPacPools(
  signal?: AbortSignal,
): Promise<readonly PacPoolView[]> {
  return apiRequest(
    "/api/pac/pools",
    readArray(decodePacPoolView),
    sig(signal),
  );
}

/** The wire form of a profile — exactly the keys the strict decoder
 * accepts (DisallowUnknownFields). */
export function profileWire(p: PacProfileInput): Record<string, unknown> {
  return {
    id: p.id,
    name: p.name,
    description: p.description,
    enabled: p.enabled,
    poolId: p.poolId,
    rules: p.rules.map(ruleWire),
    privateNetworks: p.privateNetworks,
    availabilityMode: p.availabilityMode,
    revision: p.revision,
  };
}

function ruleWire(r: PacRuleInput): Record<string, unknown> {
  const w: Record<string, unknown> = {
    kind: r.kind,
    pattern: r.pattern,
    action: r.action,
  };
  if (r.scheme !== undefined && r.scheme !== "") w["scheme"] = r.scheme;
  if (r.port !== undefined && r.port !== 0) w["port"] = r.port;
  if (r.poolId !== undefined && r.poolId !== "") w["poolId"] = r.poolId;
  return w;
}

export interface PacConfirmEcho {
  challenge: string;
  value: string;
  binding: Readonly<Record<string, unknown>>;
}

function confirmWire(c: PacConfirmEcho | undefined): Record<string, unknown> {
  return c === undefined
    ? {}
    : {
        confirm: { challenge: c.challenge, value: c.value, binding: c.binding },
      };
}

export function createPacProfile(
  p: PacProfileInput,
  collectionEtag: string,
  confirm?: PacConfirmEcho,
  signal?: AbortSignal,
): Promise<PacProfile> {
  return apiRequest("/api/pac/profiles", decodePacProfile, {
    method: "POST",
    body: {
      ...profileWire({ ...p, revision: 1 }),
      collectionEtag,
      ...confirmWire(confirm),
    },
    ...sig(signal),
  });
}

export function updatePacProfile(
  id: string,
  p: PacProfileInput,
  revision: number,
  confirm?: PacConfirmEcho,
  signal?: AbortSignal,
): Promise<PacProfile> {
  return apiRequest(profilePath(id), decodePacProfile, {
    method: "PUT",
    body: { ...profileWire({ ...p, id, revision }), ...confirmWire(confirm) },
    ...sig(signal),
  });
}

export function deletePacProfile(
  id: string,
  revision: number,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    `${profilePath(id)}?revision=${String(revision)}`,
    () => undefined,
    {
      method: "DELETE",
      ...sig(signal),
    },
  );
}

function poolWire(p: PacPool): Record<string, unknown> {
  return {
    id: p.id,
    name: p.name,
    endpoints: p.endpoints.map((e) => ({ host: e.host, port: e.port })),
  };
}

export function createPacPool(
  p: PacPool,
  collectionEtag: string,
  signal?: AbortSignal,
): Promise<PacPool> {
  return apiRequest("/api/pac/pools", decodePacPool, {
    method: "POST",
    body: { ...poolWire(p), collectionEtag },
    ...sig(signal),
  });
}

export function updatePacPool(
  id: string,
  p: PacPool,
  etag: string,
  signal?: AbortSignal,
): Promise<PacPool> {
  return apiRequest(`/api/pac/pools/${encodeURIComponent(id)}`, decodePacPool, {
    method: "PUT",
    body: { ...poolWire({ ...p, id }), etag },
    ...sig(signal),
  });
}

export function deletePacPool(
  id: string,
  etag: string,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    `/api/pac/pools/${encodeURIComponent(id)}?etag=${encodeURIComponent(etag)}`,
    () => undefined,
    { method: "DELETE", ...sig(signal) },
  );
}

export interface PacLifecycleReadOptions {
  /** ask the appliance to look ONE operation up in its full retained ring */
  operationId?: string;
}

export function getPacLifecycle(
  id: string,
  signal?: AbortSignal,
  opts?: PacLifecycleReadOptions,
): Promise<PacLifecycle> {
  const q =
    opts?.operationId !== undefined
      ? `?operationId=${encodeURIComponent(opts.operationId)}`
      : "";
  return apiRequest(
    `${profilePath(id, "/lifecycle")}${q}`,
    decodePacLifecycle,
    sig(signal),
  );
}

export function savePacDraft(
  id: string,
  draft: PacProfileInput,
  draftRevision: number,
  signal?: AbortSignal,
): Promise<PacSaveDraftResult> {
  return apiRequest(profilePath(id, "/lifecycle"), decodeSaveDraft, {
    method: "POST",
    body: {
      action: "save_draft",
      draft: profileWire({ ...draft, id }),
      draftRevision,
    },
    ...sig(signal),
  });
}

export interface PacPublishArgs {
  operationId: string;
  draft: PacProfileInput;
  expectedActiveRevision: number;
  collectionEtag: string;
  reason: string;
  confirm?: PacConfirmEcho;
}

export function publishPacProfile(
  id: string,
  a: PacPublishArgs,
  signal?: AbortSignal,
): Promise<PacOperationResult> {
  return apiRequest(profilePath(id, "/lifecycle"), decodePacOperationResult, {
    method: "POST",
    body: {
      action: "publish",
      operationId: a.operationId,
      draft: profileWire({ ...a.draft, id }),
      expectedActiveRevision: a.expectedActiveRevision,
      collectionEtag: a.collectionEtag,
      reason: a.reason,
      ...confirmWire(a.confirm),
    },
    ...sig(signal),
  });
}

export interface PacRollbackArgs {
  operationId: string;
  targetN: number;
  expectedActiveRevision: number;
  collectionEtag: string;
  reason: string;
  confirm?: PacConfirmEcho;
}

export function rollbackPacProfile(
  id: string,
  a: PacRollbackArgs,
  signal?: AbortSignal,
): Promise<PacOperationResult> {
  return apiRequest(profilePath(id, "/lifecycle"), decodePacOperationResult, {
    method: "POST",
    body: {
      action: "rollback",
      operationId: a.operationId,
      targetN: a.targetN,
      expectedActiveRevision: a.expectedActiveRevision,
      collectionEtag: a.collectionEtag,
      reason: a.reason,
      ...confirmWire(a.confirm),
    },
    ...sig(signal),
  });
}

export function repairPacProfile(
  id: string,
  operationId: string,
  signal?: AbortSignal,
): Promise<PacRepairResult> {
  return apiRequest(profilePath(id, "/lifecycle"), decodeRepair, {
    method: "POST",
    body: { action: "repair", operationId, resolution: "accept_active" },
    ...sig(signal),
  });
}

export function acknowledgePacHistoryReset(
  id: string,
  a: {
    operationId: string;
    expectedActiveRevision: number;
    expectedActiveSpecDigest: string;
  },
  signal?: AbortSignal,
): Promise<PacAckResult> {
  return apiRequest(profilePath(id, "/lifecycle"), decodeAckResult, {
    method: "POST",
    body: {
      action: "acknowledge_history_reset",
      operationId: a.operationId,
      expectedActiveRevision: a.expectedActiveRevision,
      expectedActiveSpecDigest: a.expectedActiveSpecDigest,
    },
    ...sig(signal),
  });
}

export function getPacExceptions(
  signal?: AbortSignal,
): Promise<readonly PacExceptionView[]> {
  return apiRequest(
    "/api/pac/posture/exceptions",
    decodeExceptionsListing,
    sig(signal),
  );
}

export interface PacExceptionInput {
  owner: string;
  reason: string;
  businessApp: string;
  ticket: string;
  expiresAt: string;
  reviewCadenceDays: number;
  lastReviewedAt: string;
}

export function putPacException(
  id: string,
  input: PacExceptionInput,
  revision: number | undefined,
  signal?: AbortSignal,
): Promise<PacExceptionRecord> {
  const body: Record<string, unknown> = {
    profileId: id,
    owner: input.owner,
    reason: input.reason,
  };
  if (input.businessApp !== "") body["businessApp"] = input.businessApp;
  if (input.ticket !== "") body["ticket"] = input.ticket;
  if (input.expiresAt !== "") body["expiresAt"] = input.expiresAt;
  if (input.reviewCadenceDays !== 0)
    body["reviewCadenceDays"] = input.reviewCadenceDays;
  if (input.lastReviewedAt !== "")
    body["lastReviewedAt"] = input.lastReviewedAt;
  if (revision !== undefined) body["revision"] = revision;
  return apiRequest(
    `/api/pac/posture/exceptions/${encodeURIComponent(id)}`,
    decodePacExceptionRecord,
    {
      method: "PUT",
      body,
      ...sig(signal),
    },
  );
}

export function deletePacException(
  id: string,
  revision: number,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    `/api/pac/posture/exceptions/${encodeURIComponent(id)}?revision=${String(revision)}`,
    () => undefined,
    { method: "DELETE", ...sig(signal) },
  );
}

export function getPacInventory(signal?: AbortSignal): Promise<PacInventory> {
  return apiRequest(
    "/api/pac/posture/inventory",
    decodePacInventory,
    sig(signal),
  );
}

export function getPacConfig(signal?: AbortSignal): Promise<PacConfig> {
  return apiRequest("/api/pac-config", decodePacConfig, sig(signal));
}

export function savePacConfig(
  cfg: { proxyHost: string; proxyPort: number; exclusions: readonly string[] },
  revision: number,
  signal?: AbortSignal,
): Promise<PacConfigSaveResult> {
  return apiRequest("/api/pac-config", decodePacConfigSave, {
    method: "POST",
    body: {
      proxyHost: cfg.proxyHost,
      proxyPort: cfg.proxyPort,
      exclusions: cfg.exclusions,
      revision,
    },
    ...sig(signal),
  });
}

export function simulatePac(
  profileId: string,
  input: { url: string },
  signal?: AbortSignal,
): Promise<PacSimResult> {
  return apiRequest("/api/pac/simulate", decodePacSimResult, {
    method: "POST",
    body: { profileId, input: { url: input.url } },
    ...sig(signal),
  });
}

export { DecodeError };
