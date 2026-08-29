// 2B.1 — Policy WRITE contract: an explicit AccessRuleWrite DTO, its
// serializer, the fenced mutation client, and the structured version-conflict
// decoder.
//
// The write DTO is deliberately SEPARATE from the read DTO (PolicyRuleView):
// PUT /api/policy is FULL REPLACEMENT, so the editor submits exactly the
// client-authoritative fields and nothing else. Server-owned data (stable id,
// hitCount/lastHit, createdAt/modifiedAt/modifiedBy, the authoritative
// object-link IDs destCategoryGroupId/decryptionProfileId) is NEVER
// serialized back — ids are stamped server-side from the selected names, the
// stable rule ID is an ADDRESS (?id= query param), and metadata stamping is
// server-side only. Stage-1 fields (ruleType:"auth", auth, subjectMatch) are
// structurally unrepresentable in this DTO.
//
// Tri-state preservation: `enabled`, `logTraffic`, and `stripAlpn` are *bool
// on the wire — ABSENT is a distinct value the backend treats presence-aware
// (stripAlpn) or byte-distinct in draft no-op detection. `undefined` here
// serializes as ABSENT; the editor only materializes an explicit boolean when
// the operator deliberately changes the control.
import type { Decoder } from "./decode";
import {
  DecodeError,
  field,
  readArray,
  readBoolean,
  readNumber,
  readRecord,
  readString,
} from "./decode";
import { ApiError, apiRequest } from "./client";
import type { PolicyRuleView, PolicySchedule } from "./policy";
import { decodePolicyRule } from "./policy";
import { decodeFileProfileState } from "./dcobjects";

// ── Write DTO ───────────────────────────────────────────────────────────────

export const RULE_ACTIONS = [
  "Allow",
  "Drop",
  "Block_Page",
  "Redirect",
] as const;
export type RuleAction = (typeof RULE_ACTIONS)[number];
export const SSL_ACTIONS = ["Inspect", "Bypass"] as const;
export type RuleSSLAction = (typeof SSL_ACTIONS)[number];

export function isRuleAction(v: string): v is RuleAction {
  return RULE_ACTIONS.some((a) => a === v);
}
export function isRuleSSLAction(v: string): v is RuleSSLAction {
  return SSL_ACTIONS.some((a) => a === v);
}

/** The client-authoritative Access Rule definition — the ONLY thing the v2
 * editor ever submits. See the field matrix in FRONTEND-MIGRATION-PLAN.md. */
export interface AccessRuleWrite {
  name: string;
  /** create only: requested priority slot (0 ⇒ server assigns); never sent on edit */
  priority: number;
  /** tri-state: undefined = absent on wire (backend treats nil as enabled) */
  enabled: boolean | undefined;
  sourceIP: string;
  sourceIdentity: string;
  sourceGroup: string;
  authSource: string;
  destFQDN: string;
  destCategory: string;
  /** group NAME — the authoritative id is stamped server-side */
  destCategoryGroup: string;
  destCountry: readonly string[];
  schedule: PolicySchedule | undefined;
  sslAction: RuleSSLAction;
  fileFiltering: boolean;
  fileProfile: string;
  logFullUri: boolean;
  /** tri-state: undefined = absent (log); false = stats only */
  logTraffic: boolean | undefined;
  /** tri-state: undefined = absent (HTTP/1.1 downgrade); false = native H2 */
  stripAlpn: boolean | undefined;
  tlsSkipVerify: boolean;
  /** profile NAME — the authoritative id is stamped server-side */
  decryptionProfile: string;
  action: RuleAction;
  redirectURL: string;
  comment: string;
  /** pass-through of the loaded value; only ""/"access" are representable */
  ruleType: "" | "access";
}

/** Builds the editor's seed from a decoded rule. Refuses non-access rules —
 * auth rules (2C) and unknown ruleTypes are not editable on this surface. */
export function writeSeedFromView(view: PolicyRuleView): AccessRuleWrite {
  if (view.kind !== "access") {
    throw new Error(`rule ${view.id} is not an access rule (${view.ruleType})`);
  }
  if (!isRuleAction(view.action) || !isRuleSSLAction(view.sslAction)) {
    throw new Error(
      `rule ${view.id} carries an unsupported action (${view.action}/${view.sslAction}) — edit refused rather than rewriting it`,
    );
  }
  return {
    name: view.name,
    priority: view.priority,
    enabled: view.enabledWire,
    sourceIP: view.sourceIP,
    sourceIdentity: view.sourceIdentity,
    sourceGroup: view.sourceGroup,
    authSource: view.authSource,
    destFQDN: view.destFQDN,
    destCategory: view.destCategory,
    destCategoryGroup: view.destCategoryGroup,
    destCountry: view.destCountry,
    schedule: view.schedule,
    sslAction: view.sslAction,
    fileFiltering: view.fileFiltering,
    fileProfile: view.fileProfile,
    logFullUri: view.logFullUri,
    logTraffic: view.logTraffic,
    stripAlpn: view.stripAlpn,
    tlsSkipVerify: view.tlsSkipVerify,
    decryptionProfile: view.decryptionProfile,
    action: view.action,
    redirectURL: view.redirectURL,
    comment: view.comment,
    ruleType: view.ruleType === "access" ? "access" : "",
  };
}

/** Serializes EXACTLY the client-authoritative fields. Tri-states serialize
 * as absent when undefined. Never emits id/hitCount/metadata/object-link ids. */
export function serializeAccessRuleWrite(
  w: AccessRuleWrite,
  forEdit: boolean,
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    name: w.name,
    sourceIP: w.sourceIP,
    sourceIdentity: w.sourceIdentity,
    sourceGroup: w.sourceGroup,
    authSource: w.authSource,
    destFQDN: w.destFQDN,
    destCategory: w.destCategory,
    destCategoryGroup: w.destCategoryGroup,
    destCountry: w.destCountry,
    sslAction: w.sslAction,
    fileFiltering: w.fileFiltering,
    fileProfile: w.fileProfile,
    logFullUri: w.logFullUri,
    tlsSkipVerify: w.tlsSkipVerify,
    decryptionProfile: w.decryptionProfile,
    action: w.action,
    redirectURL: w.redirectURL,
    comment: w.comment,
  };
  // Position is managed by reorder/move: the server preserves the stored
  // priority on an id-addressed edit, so only a CREATE carries the hint.
  if (!forEdit && w.priority > 0) out["priority"] = w.priority;
  if (w.enabled !== undefined) out["enabled"] = w.enabled;
  if (w.logTraffic !== undefined) out["logTraffic"] = w.logTraffic;
  if (w.stripAlpn !== undefined) out["stripAlpn"] = w.stripAlpn;
  if (w.schedule !== undefined) out["schedule"] = w.schedule;
  if (w.ruleType === "access") out["ruleType"] = "access";
  return out;
}

// ── Structured version conflict (409) ───────────────────────────────────────

export interface PolicyConflict {
  error: string;
  currentVersion: number;
  yourVersion: number;
}

const decodeConflictBody: Decoder<PolicyConflict> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    error: field(o, "error", readString, path),
    currentVersion: field(o, "currentVersion", readNumber, path),
    yourVersion: field(o, "yourVersion", readNumber, path),
  };
};

/** Recognizes the structured policy 409. Returns null for anything else —
 * a 409 whose body is not the structured shape stays a generic ApiError. */
export function asPolicyConflict(err: unknown): PolicyConflict | null {
  if (!(err instanceof ApiError)) return null;
  if (err.status !== 409 || err.bodyText === undefined) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(err.bodyText);
  } catch {
    return null;
  }
  try {
    return decodeConflictBody(parsed, "$");
  } catch (e) {
    if (e instanceof DecodeError) return null;
    throw e;
  }
}

// ── Mutation client ─────────────────────────────────────────────────────────
// Every v2 policy mutation sends ifVersion (FRONTEND-SECURITY-CONTRACT):
// the server guarantees comparison + mutation are atomic when it is present.

function fenced(path: string, ifVersion: number): string {
  return `${path}${path.includes("?") ? "&" : "?"}ifVersion=${String(ifVersion)}`;
}

const decodeOkBody: Decoder<void> = (v, path = "$") => {
  // {ok:true} bodies and 204 responses both mean confirmed success.
  if (v === undefined) return;
  const o = readRecord(v, path);
  field(o, "ok", readBoolean, path);
};

export function createRule(
  write: AccessRuleWrite,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<PolicyRuleView> {
  return apiRequest(fenced("/api/policy", ifVersion), decodePolicyRule, {
    method: "POST",
    body: serializeAccessRuleWrite(write, false),
    ...(signal !== undefined ? { signal } : {}),
  });
}

export function updateRule(
  id: string,
  write: AccessRuleWrite,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fenced(`/api/policy?id=${encodeURIComponent(id)}`, ifVersion),
    decodeOkBody,
    {
      method: "PUT",
      body: serializeAccessRuleWrite(write, true),
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

export function deleteRule(
  id: string,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fenced(`/api/policy?id=${encodeURIComponent(id)}`, ifVersion),
    decodeOkBody,
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

export function reorderRules(
  priorities: readonly number[],
  ifVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(fenced("/api/policy/reorder", ifVersion), decodeOkBody, {
    method: "POST",
    body: { priorities },
    ...(signal !== undefined ? { signal } : {}),
  });
}

// ── Default action (LIVE mutation — never part of the draft) ────────────────

export type DefaultAction = "allow" | "deny";

const decodeDefaultAction: Decoder<DefaultAction> = (v, path = "$") => {
  const o = readRecord(v, path);
  const a = field(o, "defaultAction", readString, path);
  if (a !== "allow" && a !== "deny") {
    throw new DecodeError(`${path}.defaultAction`, '"allow"|"deny"', a);
  }
  return a;
};

export function getDefaultAction(signal?: AbortSignal): Promise<DefaultAction> {
  return apiRequest(
    "/api/default-action",
    decodeDefaultAction,
    signal !== undefined ? { signal } : {},
  );
}

export function setDefaultAction(
  action: DefaultAction,
  signal?: AbortSignal,
): Promise<DefaultAction> {
  return apiRequest("/api/default-action", decodeDefaultAction, {
    method: "POST",
    body: { action },
    ...(signal !== undefined ? { signal } : {}),
  });
}

// ── Reference option sources (§12 — read-only; management stays legacy) ─────

const decodeNameList: Decoder<readonly string[]> = (v, path = "$") => {
  const o = readRecord(v, path);
  return field(o, "names", readArray(readString), path);
};

/** Named records ({name: string, ...}) → sorted unique name list. */
const decodeNamedObjectList: Decoder<readonly string[]> = (v, path = "$") => {
  const arr = readArray((x, p) => {
    const o = readRecord(x, p);
    return field(o, "name", readString, p);
  })(v, path);
  return [...new Set(arr)].sort((a, b) => a.localeCompare(b));
};

export function getCategoryGroupNames(
  signal?: AbortSignal,
): Promise<readonly string[]> {
  return apiRequest(
    "/api/category-groups",
    decodeNameList,
    signal !== undefined ? { signal } : {},
  );
}

export function getDecryptionProfileNames(
  signal?: AbortSignal,
): Promise<readonly string[]> {
  return apiRequest(
    "/api/decryption-profiles",
    decodeNameList,
    signal !== undefined ? { signal } : {},
  );
}

// 2D-C §32: the Access Rule File Profile selector reads the coherent v2
// state endpoint (one committed snapshot; names in a rule stay INTENT — the
// server stamps name → stable fileProfileId at rule save).
export function getFileProfileNames(
  signal?: AbortSignal,
): Promise<readonly string[]> {
  return apiRequest(
    "/api/fileblock/profiles/state",
    (v, path = "$") => decodeFileProfileState(v, path).profiles.map((p) => p.name),
    signal !== undefined ? { signal } : {},
  );
}

export function getURLCategoryNames(
  signal?: AbortSignal,
): Promise<readonly string[]> {
  return apiRequest(
    "/api/urlcat",
    decodeNamedObjectList,
    signal !== undefined ? { signal } : {},
  );
}
