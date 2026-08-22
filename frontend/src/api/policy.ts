// Slice 2A policy read/explainability API adapters (FRONTEND-SECURITY-CONTRACT
// §7): GET /api/policy (the effective rulebase envelope), POST /api/policy/test
// (the viewer dry-run simulator), GET /api/objects/references (where-used).
// Generated types are compile-time only — every response passes through these
// runtime decoders. Decoders are total: unknown fields are ignored, required
// fields with invalid types fail closed (DecodeError), and Go `omitempty` /
// nil-slice (`null`) absences decode to explicit defaults.
import { apiRequest } from "./client";
import type { RequestOptions } from "./client";
import {
  DecodeError,
  field,
  readArray,
  readBoolean,
  readEnum,
  readNumber,
  readOptional,
  readRecord,
  readString,
} from "./decode";
import type { Decoder } from "./decode";

// ── rule-type classification (directive §4) ────────────────────────────────
// The effective rulebase mixes Stage-2 access rules (ruleType "" | "access")
// with Stage-1 auth rules (ruleType "auth"). An UNKNOWN future rule type must
// never be treated as an Access Rule — it decodes into an explicit "unknown"
// kind that the surface counts and reports instead of rendering as policy.
export type RuleKind = "access" | "auth" | "unknown";

export function classifyRuleType(ruleType: string): RuleKind {
  if (ruleType === "" || ruleType === "access") return "access";
  if (ruleType === "auth") return "auth";
  return "unknown";
}

export interface PolicySchedule {
  days: readonly string[];
  timeStart: string;
  timeEnd: string;
  timezone: string;
}

export interface PolicyRuleView {
  priority: number;
  id: string;
  ruleType: string;
  kind: RuleKind;
  name: string;
  enabled: boolean; // backend *bool: absent/null ⇒ enabled
  sourceIP: string;
  sourceIdentity: string;
  sourceGroup: string;
  authSource: string;
  destFQDN: string;
  destCategory: string;
  destCategoryGroup: string;
  destCategoryGroupId: string;
  destCountry: readonly string[];
  schedule: PolicySchedule | undefined;
  sslAction: string;
  fileFiltering: boolean;
  fileProfile: string;
  decryptionProfile: string;
  decryptionProfileId: string;
  action: string;
  redirectURL: string;
  logFullUri: boolean;
  hitCount: number;
  lastHit: string;
  createdAt: string;
  modifiedAt: string;
  modifiedBy: string;
  comment: string;
}

const optStr = readOptional(readString);
const optNum = readOptional(readNumber);
const optBool = readOptional(readBoolean);

// nullable string array: Go nil slices serialize as JSON null.
function readStringsOrNull(v: unknown, path = "$"): readonly string[] {
  if (v === undefined || v === null) return [];
  return readArray(readString)(v, path);
}

const decodeSchedule: Decoder<PolicySchedule> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    days: readStringsOrNull(o["days"], `${path}.days`),
    timeStart: field(o, "timeStart", optStr, path) ?? "",
    timeEnd: field(o, "timeEnd", optStr, path) ?? "",
    timezone: field(o, "timezone", optStr, path) ?? "",
  };
};

export const decodePolicyRule: Decoder<PolicyRuleView> = (v, path = "$") => {
  const o = readRecord(v, path);
  const ruleType = field(o, "ruleType", optStr, path) ?? "";
  return {
    priority: field(o, "priority", readNumber, path),
    id: field(o, "id", optStr, path) ?? "",
    ruleType,
    kind: classifyRuleType(ruleType),
    name: field(o, "name", readString, path),
    enabled: field(o, "enabled", optBool, path) ?? true,
    sourceIP: field(o, "sourceIP", optStr, path) ?? "",
    sourceIdentity: field(o, "sourceIdentity", optStr, path) ?? "",
    sourceGroup: field(o, "sourceGroup", optStr, path) ?? "",
    authSource: field(o, "authSource", optStr, path) ?? "",
    destFQDN: field(o, "destFQDN", optStr, path) ?? "",
    destCategory: field(o, "destCategory", optStr, path) ?? "",
    destCategoryGroup: field(o, "destCategoryGroup", optStr, path) ?? "",
    destCategoryGroupId: field(o, "destCategoryGroupId", optStr, path) ?? "",
    destCountry: readStringsOrNull(o["destCountry"], `${path}.destCountry`),
    schedule: field(o, "schedule", readOptional(decodeSchedule), path),
    sslAction: field(o, "sslAction", optStr, path) ?? "",
    fileFiltering: field(o, "fileFiltering", optBool, path) ?? false,
    fileProfile: field(o, "fileProfile", optStr, path) ?? "",
    decryptionProfile: field(o, "decryptionProfile", optStr, path) ?? "",
    decryptionProfileId: field(o, "decryptionProfileId", optStr, path) ?? "",
    action: field(o, "action", readString, path),
    redirectURL: field(o, "redirectURL", optStr, path) ?? "",
    logFullUri: field(o, "logFullUri", optBool, path) ?? false,
    hitCount: field(o, "hitCount", optNum, path) ?? 0,
    lastHit: field(o, "lastHit", optStr, path) ?? "",
    createdAt: field(o, "createdAt", optStr, path) ?? "",
    modifiedAt: field(o, "modifiedAt", optStr, path) ?? "",
    modifiedBy: field(o, "modifiedBy", optStr, path) ?? "",
    comment: field(o, "comment", optStr, path) ?? "",
  };
};

// ── GET /api/policy envelope ───────────────────────────────────────────────
export interface PolicySnapshot {
  /** every decoded rule, server priority order, all kinds */
  rules: readonly PolicyRuleView[];
  /** Stage-2 access rules only (ruleType ""|"access"), server order */
  accessRules: readonly PolicyRuleView[];
  /** Stage-1 auth rules present in the envelope but excluded from this surface */
  authRuleCount: number;
  /** rules whose ruleType is not a known value — reported, never rendered as access */
  unknownKindCount: number;
  /** server-reported count — NOT asserted equal to rules.length */
  count: number;
  version: number;
  updatedAt: string;
  /** true ⇒ the returned rulebase is the staged draft candidate, not running */
  draft: boolean;
}

export const decodePolicySnapshot: Decoder<PolicySnapshot> = (v, path = "$") => {
  const o = readRecord(v, path);
  const rules = field(o, "rules", readArray(decodePolicyRule), path);
  const accessRules = rules.filter((r) => r.kind === "access");
  return {
    rules,
    accessRules,
    authRuleCount: rules.filter((r) => r.kind === "auth").length,
    unknownKindCount: rules.filter((r) => r.kind === "unknown").length,
    count: field(o, "count", readNumber, path),
    version: field(o, "version", readNumber, path),
    updatedAt: field(o, "updatedAt", readString, path),
    draft: field(o, "draft", readBoolean, path),
  };
};

export function getPolicy(signal?: AbortSignal): Promise<PolicySnapshot> {
  return apiRequest(
    "/api/policy",
    decodePolicySnapshot,
    signal !== undefined ? { signal } : {},
  );
}

// ── POST /api/policy/test ──────────────────────────────────────────────────
export interface TesterInput {
  host: string; // required by the server
  sourceIP?: string;
  identity?: string;
  authSource?: string;
  groups?: readonly string[];
  protocol?: "http" | "connect";
  method?: string;
}

export interface TesterTraceRow {
  priority: number;
  name: string;
  skipReason: string; // "" = evaluated/matched terminus, not skipped
}

export interface TesterHostCategory {
  category: string;
  tier: string;
  matchedBy: string;
}

export interface TesterAuthRuleRef {
  id: string;
  name: string;
  owner: string;
}

// Stage-1 simulation block, shaped exactly from simulateAuthOutcome
// (ui_authpolicy.go) — every field the backend always sets is required.
export interface TesterAuthBlock {
  outcome: string;
  runtimeOutcome: string;
  defaultAuthOutcome: string;
  fromDefault: boolean;
  killSwitch: boolean;
  credentialsPresented: boolean;
  stage2AuthSource: string;
  stage2Reached: boolean;
  stage2Note: string;
  note: string;
  rule: TesterAuthRuleRef | undefined;
}

export type TesterRulebase = "running" | "draft";

export interface TesterResultBase {
  trace: readonly TesterTraceRow[];
  hostCategory: TesterHostCategory;
  auth: TesterAuthBlock;
  rulebase: TesterRulebase;
}

export interface TesterMatched extends TesterResultBase {
  matched: true;
  rule: PolicyRuleView;
  action: string;
}

export interface TesterNoMatch extends TesterResultBase {
  matched: false;
  defaultAction: string;
}

export type TesterResult = TesterMatched | TesterNoMatch;

const decodeTraceRow: Decoder<TesterTraceRow> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    priority: field(o, "priority", readNumber, path),
    name: field(o, "name", readString, path),
    skipReason: field(o, "skipReason", optStr, path) ?? "",
  };
};

const decodeHostCategory: Decoder<TesterHostCategory> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    category: field(o, "category", readString, path),
    tier: field(o, "tier", readString, path),
    matchedBy: field(o, "matchedBy", readString, path),
  };
};

const decodeAuthRuleRef: Decoder<TesterAuthRuleRef> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    id: field(o, "id", optStr, path) ?? "",
    name: field(o, "name", readString, path),
    owner: field(o, "owner", optStr, path) ?? "",
  };
};

const decodeAuthBlock: Decoder<TesterAuthBlock> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    outcome: field(o, "outcome", readString, path),
    runtimeOutcome: field(o, "runtimeOutcome", readString, path),
    defaultAuthOutcome: field(o, "defaultAuthOutcome", readString, path),
    fromDefault: field(o, "fromDefault", readBoolean, path),
    killSwitch: field(o, "killSwitch", readBoolean, path),
    credentialsPresented: field(o, "credentialsPresented", readBoolean, path),
    stage2AuthSource: field(o, "stage2AuthSource", readString, path),
    stage2Reached: field(o, "stage2Reached", readBoolean, path),
    stage2Note: field(o, "stage2Note", optStr, path) ?? "",
    note: field(o, "note", optStr, path) ?? "",
    rule: field(o, "rule", readOptional(decodeAuthRuleRef), path),
  };
};

const decodeRulebase = readEnum<TesterRulebase>(["running", "draft"]);

export const decodeTesterResult: Decoder<TesterResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  const base: TesterResultBase = {
    trace: field(o, "trace", readArray(decodeTraceRow), path),
    hostCategory: field(o, "hostCategory", decodeHostCategory, path),
    auth: field(o, "auth", decodeAuthBlock, path),
    rulebase: field(o, "rulebase", decodeRulebase, path),
  };
  const matched = field(o, "matched", readBoolean, path);
  if (matched) {
    return {
      ...base,
      matched: true,
      rule: field(o, "rule", decodePolicyRule, path),
      action: field(o, "action", readString, path),
    };
  }
  return {
    ...base,
    matched: false,
    defaultAction: field(o, "defaultAction", readString, path),
  };
};

export function runPolicyTest(
  input: TesterInput,
  signal?: AbortSignal,
): Promise<TesterResult> {
  const body: Record<string, unknown> = { host: input.host };
  if (input.sourceIP !== undefined && input.sourceIP !== "")
    body["sourceIP"] = input.sourceIP;
  if (input.identity !== undefined && input.identity !== "")
    body["identity"] = input.identity;
  if (input.authSource !== undefined && input.authSource !== "")
    body["authSource"] = input.authSource;
  if (input.groups !== undefined && input.groups.length > 0)
    body["groups"] = input.groups;
  if (input.protocol !== undefined) body["protocol"] = input.protocol;
  if (input.method !== undefined && input.method !== "")
    body["method"] = input.method;
  const opts: RequestOptions = { method: "POST", body };
  if (signal !== undefined) opts.signal = signal;
  return apiRequest("/api/policy/test", decodeTesterResult, opts);
}

// ── GET /api/objects/references ────────────────────────────────────────────
// Known shared-object types (policy_refs.go objectRefTypes). The set is a
// server contract; an unsupported type is a 400 from the server, so the
// client only ever asks for these.
export const OBJECT_REF_TYPES = [
  "category",
  "category-group",
  "file-profile",
  "decryption-profile",
] as const;
export type ObjectRefType = (typeof OBJECT_REF_TYPES)[number];

export interface ObjectRefConsumer {
  /** server vocabulary: access-rule | auth-rule | category-group | future */
  consumerType: string;
  id: string;
  name: string;
  detail: string;
  /** legacy/product view identifier — NEVER used as a client route (§17);
   * navigation goes through the explicit reviewed mapping in the component. */
  view: string;
}

export interface ObjectReferences {
  object: { type: string; name: string };
  referencedBy: readonly ObjectRefConsumer[];
}

const decodeRefConsumer: Decoder<ObjectRefConsumer> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    consumerType: field(o, "consumerType", readString, path),
    id: field(o, "id", optStr, path) ?? "",
    name: field(o, "name", readString, path),
    detail: field(o, "detail", optStr, path) ?? "",
    view: field(o, "view", optStr, path) ?? "",
  };
};

export const decodeObjectReferences: Decoder<ObjectReferences> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const obj = readRecord(o["object"], `${path}.object`);
  return {
    object: {
      type: field(obj, "type", readString, `${path}.object`),
      name: field(obj, "name", readString, `${path}.object`),
    },
    referencedBy: field(o, "referencedBy", readArray(decodeRefConsumer), path),
  };
};

export function getObjectReferences(
  type: ObjectRefType,
  name: string,
  signal?: AbortSignal,
): Promise<ObjectReferences> {
  const qs = new URLSearchParams({ type, name });
  return apiRequest(
    `/api/objects/references?${qs.toString()}`,
    decodeObjectReferences,
    signal !== undefined ? { signal } : {},
  );
}

// ── deep-link parameter hygiene (directive §10) ────────────────────────────
// The ?rule= query value is resolved through DATA EQUALITY against decoded
// rule IDs only — it never becomes a selector or HTML. Bound + shape-check it
// so an oversized/garbage value is classified before any lookup runs. Real
// IDs are 26-char Crockford-base32 ULIDs; the check is deliberately looser
// (alphanumeric, bounded) so a historical or foreign-but-plausible ID still
// reaches the honest "not present in this snapshot" state rather than being
// conflated with malformed input.
export const MAX_RULE_LINK_ID_LENGTH = 40;

export function isPlausibleRuleID(raw: string): boolean {
  if (raw.length === 0 || raw.length > MAX_RULE_LINK_ID_LENGTH) return false;
  return /^[0-9A-Za-z]+$/.test(raw);
}

export { DecodeError };
