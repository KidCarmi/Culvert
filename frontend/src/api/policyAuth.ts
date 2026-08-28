// 2C.1 — Stage-1 Authentication Policy API adapters (GET/POST/PUT/DELETE
// /api/authpolicy + /api/authpolicy/reorder, the global default-auth-outcome,
// and the IdP provider read surface for SSORequired references).
//
// Domain doctrine (2C §2): authentication rules are ADMIN-managed and take
// effect in the RUNNING rulebase immediately — they are never staged into the
// Access-Policy Draft, and Require Commit does not govern them. The version
// every mutation fences on is therefore the RUNNING generation served by
// GET /api/authpolicy (2C.0a), never the draft candidate's.
//
// Schema fidelity (§11): the AuthRuleSpec/SubjectMatch shapes below are
// derived from the Go source (authpolicy.go — AuthRuleSpec, SubjectMatch,
// SubjectPredicate; only the "cidr" predicate type is implemented). Unknown
// predicate types and unknown outcomes FAIL CLOSED: they decode into explicit
// unknown markers, the rule renders degraded, and the editor refuses to seed a
// write from it (a full-replacement PUT built from a misunderstood rule would
// destroy semantics the client cannot represent).
import { apiRequest } from "./client";
import { decodePolicyRule } from "./policy";
import type { PolicyRuleView, PolicySchedule } from "./policy";
import {
  DecodeError,
  field,
  readArray,
  readBoolean,
  readNumber,
  readOptional,
  readRecord,
  readString,
} from "./decode";
import type { Decoder } from "./decode";

const optStr = readOptional(readString);
const optBool = readOptional(readBoolean);

function readStringsOrNull(v: unknown, path: string): readonly string[] {
  if (v === undefined || v === null) return [];
  return readArray(readString)(v, path);
}

// ── Outcome / predicate vocabulary (authpolicy.go, FROZEN enum) ────────────
export const AUTH_OUTCOMES = [
  "Exempt",
  "CredentialRequired",
  "SSORequired",
] as const;
export type AuthOutcome = (typeof AUTH_OUTCOMES)[number];

export function isAuthOutcome(v: string): v is AuthOutcome {
  return AUTH_OUTCOMES.some((o) => o === v);
}

/** The only implemented subject-predicate type (Phase 0 schema). Reserved
 * future types (directory_group, tag, …) are validation-rejected server-side
 * and decode here as known=false — never silently treated as CIDR. */
export const SUBJECT_PREDICATE_CIDR = "cidr";

export const AUTH_PROTOCOLS = ["", "http", "connect"] as const;
export type AuthProtocol = (typeof AUTH_PROTOCOLS)[number];

export function isAuthProtocol(v: string): v is AuthProtocol {
  return AUTH_PROTOCOLS.some((p) => p === v);
}

// ── Read model ─────────────────────────────────────────────────────────────

export interface SubjectPredicateView {
  /** wire value, verbatim */
  type: string;
  /** type is the implemented "cidr" predicate */
  known: boolean;
  op: string;
  values: readonly string[];
}

export interface SubjectMatchView {
  schemaVersion: number;
  all: readonly SubjectPredicateView[];
  /** any predicate of a type this client does not implement (fail closed) */
  hasUnknownPredicates: boolean;
}

export interface AuthSpecView {
  /** wire outcome, verbatim (rendered raw when unknown) */
  outcome: string;
  /** null = outcome outside the known enum — fail closed (no editing) */
  outcomeKnown: AuthOutcome | null;
  protocol: string;
  method: string;
  owner: string;
  reason: string;
  expiresAt: string;
  broadExemption: boolean;
  providerRefs: readonly string[];
}

export interface AuthRuleView extends PolicyRuleView {
  subjectMatch: SubjectMatchView | undefined;
  /** undefined = stored rule with no auth spec (malformed) — degraded */
  authSpec: AuthSpecView | undefined;
  /** server validateAuthRule warnings, verbatim (§14 — server truth) */
  warnings: readonly string[];
}

const decodeSubjectPredicate: Decoder<SubjectPredicateView> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const type = field(o, "type", readString, path);
  return {
    type,
    known: type === SUBJECT_PREDICATE_CIDR,
    op: field(o, "op", optStr, path) ?? "",
    values: readStringsOrNull(o["values"], `${path}.values`),
  };
};

const decodeSubjectMatch: Decoder<SubjectMatchView> = (v, path = "$") => {
  const o = readRecord(v, path);
  const all = field(o, "all", readArray(decodeSubjectPredicate), path);
  return {
    schemaVersion: field(o, "schemaVersion", readNumber, path),
    all,
    hasUnknownPredicates: all.some((p) => !p.known),
  };
};

const decodeAuthSpec: Decoder<AuthSpecView> = (v, path = "$") => {
  const o = readRecord(v, path);
  const outcome = field(o, "outcome", readString, path);
  return {
    outcome,
    outcomeKnown: isAuthOutcome(outcome) ? outcome : null,
    protocol: field(o, "protocol", optStr, path) ?? "",
    method: field(o, "method", optStr, path) ?? "",
    owner: field(o, "owner", optStr, path) ?? "",
    reason: field(o, "reason", optStr, path) ?? "",
    expiresAt: field(o, "expiresAt", optStr, path) ?? "",
    broadExemption: field(o, "broadExemption", optBool, path) ?? false,
    providerRefs: readStringsOrNull(o["providerRefs"], `${path}.providerRefs`),
  };
};

export const decodeAuthRule: Decoder<AuthRuleView> = (v, path = "$") => {
  const base = decodePolicyRule(v, path);
  const o = readRecord(v, path);
  return {
    ...base,
    subjectMatch: field(o, "subjectMatch", readOptional(decodeSubjectMatch), path),
    authSpec: field(o, "auth", readOptional(decodeAuthSpec), path),
    warnings: readStringsOrNull(o["warnings"], `${path}.warnings`),
  };
};

/** A rule this client can faithfully re-serialize for a full-replacement PUT:
 * a known outcome, a spec present, and only implemented predicate types. A
 * degraded rule renders read-only (fail closed — §11). */
export function authRuleEditable(rule: AuthRuleView): boolean {
  return (
    rule.authSpec !== undefined &&
    rule.authSpec.outcomeKnown !== null &&
    rule.subjectMatch !== undefined &&
    !rule.subjectMatch.hasUnknownPredicates
  );
}

// ── GET /api/authpolicy envelope ───────────────────────────────────────────

export interface AuthPolicySnapshot {
  rules: readonly AuthRuleView[];
  count: number;
  defaultAction: string;
  /** the server's Exempt-is-not-Allow contract statement — rendered verbatim */
  note: string;
  /** RUNNING PolicyStore generation — the ifVersion every mutation asserts */
  version: number;
  updatedAt: string;
}

export const decodeAuthPolicySnapshot: Decoder<AuthPolicySnapshot> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    rules: field(o, "rules", readArray(decodeAuthRule), path),
    count: field(o, "count", readNumber, path),
    defaultAction: field(o, "defaultAction", readString, path),
    note: field(o, "note", readString, path),
    version: field(o, "version", readNumber, path),
    updatedAt: field(o, "updatedAt", readString, path),
  };
};

export function getAuthPolicy(signal?: AbortSignal): Promise<AuthPolicySnapshot> {
  return apiRequest(
    "/api/authpolicy",
    decodeAuthPolicySnapshot,
    signal !== undefined ? { signal } : {},
  );
}

// ── Write model (2C §11 field classification) ──────────────────────────────
// AUTH-EDITABLE: name, enabled, destination selectors, schedule, comment,
//   subject predicates (cidr), and the AuthRuleSpec fields below.
// SERVER-OWNED (never serialized): id, priority (position is reorder's job;
//   UpdateByID preserves the stored slot), hitCount/lastHit, createdAt/
//   modifiedAt/modifiedBy, warnings.
// STAGE-2 ONLY (never valid here): action/sslAction/redirectURL/fileFiltering/
//   fileProfile/decryptionProfile/logTraffic/stripAlpn/tlsSkipVerify/
//   logFullUri, sourceIP/sourceIdentity/sourceGroup/authSource — an auth rule
//   scopes by SubjectMatch, and its decision is auth.outcome, not an action.

export interface AuthPredicateWrite {
  type: typeof SUBJECT_PREDICATE_CIDR;
  values: readonly string[];
}

export interface AuthRuleWrite {
  name: string;
  /** tri-state: undefined = absent on the wire (server default enabled) */
  enabled: boolean | undefined;
  outcome: AuthOutcome;
  protocol: AuthProtocol;
  method: string;
  owner: string;
  reason: string;
  expiresAt: string;
  broadExemption: boolean;
  providerRefs: readonly string[];
  predicates: readonly AuthPredicateWrite[];
  destFQDN: string;
  destCategory: string;
  destCategoryGroup: string;
  schedule: PolicySchedule | undefined;
  comment: string;
}

/** Seed a write DTO from a decoded rule. Returns null for a rule this client
 * cannot faithfully rebuild (unknown outcome / unknown predicate / missing
 * spec) — the editor must refuse instead of guessing (§11 fail closed). */
export function writeSeedFromAuthView(view: AuthRuleView): AuthRuleWrite | null {
  if (!authRuleEditable(view)) return null;
  const spec = view.authSpec;
  const sm = view.subjectMatch;
  if (spec === undefined || spec.outcomeKnown === null || sm === undefined)
    return null;
  const protocol = spec.protocol;
  if (!isAuthProtocol(protocol)) return null;
  return {
    name: view.name,
    enabled: view.enabledWire,
    outcome: spec.outcomeKnown,
    protocol,
    method: spec.method,
    owner: spec.owner,
    reason: spec.reason,
    expiresAt: spec.expiresAt,
    broadExemption: spec.broadExemption,
    providerRefs: spec.providerRefs,
    predicates: sm.all.map((p) => ({
      type: SUBJECT_PREDICATE_CIDR,
      values: p.values,
    })),
    destFQDN: view.destFQDN,
    destCategory: view.destCategory,
    destCategoryGroup: view.destCategoryGroup,
    schedule: view.schedule,
    comment: view.comment,
  };
}

/** Serialize for POST/PUT. Only real PolicyRule JSON keys (the server decodes
 * with DisallowUnknownFields) and only auth-editable fields — server-owned
 * and Stage-2-only keys are never emitted. */
export function serializeAuthRuleWrite(w: AuthRuleWrite): Record<string, unknown> {
  const auth: Record<string, unknown> = {
    outcome: w.outcome,
    owner: w.owner,
    reason: w.reason,
  };
  if (w.protocol !== "") auth["protocol"] = w.protocol;
  if (w.method !== "") auth["method"] = w.method;
  if (w.expiresAt !== "") auth["expiresAt"] = w.expiresAt;
  if (w.broadExemption) auth["broadExemption"] = true;
  if (w.providerRefs.length > 0) auth["providerRefs"] = w.providerRefs;
  const body: Record<string, unknown> = {
    name: w.name,
    ruleType: "auth",
    subjectMatch: {
      schemaVersion: 1,
      all: w.predicates.map((p) => ({ type: p.type, values: p.values })),
    },
    auth,
    destFQDN: w.destFQDN,
    destCategory: w.destCategory,
    destCategoryGroup: w.destCategoryGroup,
    comment: w.comment,
  };
  if (w.enabled !== undefined) body["enabled"] = w.enabled;
  if (w.schedule !== undefined) body["schedule"] = w.schedule;
  return body;
}

// ── Fenced mutations (always assert ifVersion — contract D7) ───────────────

function fencedAuth(path: string, ifVersion: number): string {
  return `${path}${path.includes("?") ? "&" : "?"}ifVersion=${String(ifVersion)}`;
}

const decodeOkBody: Decoder<void> = (v, path = "$") => {
  if (v === undefined) return; // 204
  const o = readRecord(v, path);
  field(o, "ok", readBoolean, path);
};

/** POST /api/authpolicy?ifVersion= — returns the created rule (with the
 * server-assigned id/priority and its warnings). */
export function createAuthRule(
  w: AuthRuleWrite,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<AuthRuleView> {
  return apiRequest(fencedAuth("/api/authpolicy", ifVersion), decodeAuthRule, {
    method: "POST",
    body: serializeAuthRuleWrite(w),
    ...(signal !== undefined ? { signal } : {}),
  });
}

/** PUT /api/authpolicy?id=<ULID>&ifVersion= — stable-ID addressing only (v2
 * never addresses by priority; §15). */
export function updateAuthRule(
  id: string,
  w: AuthRuleWrite,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  const qs = new URLSearchParams({ id });
  return apiRequest(
    fencedAuth(`/api/authpolicy?${qs.toString()}`, ifVersion),
    decodeOkBody,
    {
      method: "PUT",
      body: serializeAuthRuleWrite(w),
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

/** DELETE /api/authpolicy?id=<ULID>&ifVersion= (204). */
export function deleteAuthRule(
  id: string,
  ifVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  const qs = new URLSearchParams({ id });
  return apiRequest(
    fencedAuth(`/api/authpolicy?${qs.toString()}`, ifVersion),
    decodeOkBody,
    {
      method: "DELETE",
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

/** POST /api/authpolicy/reorder?ifVersion= with {ids:[...]} — every auth rule
 * exactly once, stable-ID shape (§16). */
export function reorderAuthRules(
  ids: readonly string[],
  ifVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  return apiRequest(
    fencedAuth("/api/authpolicy/reorder", ifVersion),
    decodeOkBody,
    {
      method: "POST",
      body: { ids },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

// ── Global default authentication outcome (§17–§19) ────────────────────────

export type DefaultAuthOutcome = "Default" | "Exempt";

const decodeDefaultAuthOutcome: Decoder<DefaultAuthOutcome> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const raw = field(o, "defaultAuthOutcome", readString, path);
  if (raw === "Default" || raw === "Exempt") return raw;
  // Unknown outcome (§19): fail closed — the caller blocks further change
  // until fresh truth arrives; never coerce to a guessed value.
  throw new DecodeError(
    `${path}.defaultAuthOutcome`,
    `"Default" | "Exempt"`,
    raw,
  );
};

/** GET /api/security — the read surface carrying the global default. */
export function getDefaultAuthOutcome(
  signal?: AbortSignal,
): Promise<DefaultAuthOutcome> {
  return apiRequest(
    "/api/security",
    decodeDefaultAuthOutcome,
    signal !== undefined ? { signal } : {},
  );
}

/** PUT /api/settings/default-auth-outcome (admin, LIVE immediately;
 * durable-or-nothing since 2C.0c — a 2xx means persisted). */
export function putDefaultAuthOutcome(
  outcome: DefaultAuthOutcome,
  signal?: AbortSignal,
): Promise<DefaultAuthOutcome> {
  return apiRequest(
    "/api/settings/default-auth-outcome",
    decodeDefaultAuthOutcome,
    {
      method: "PUT",
      body: { defaultAuthOutcome: outcome },
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

// ── IdP provider references (SSORequired option source, §13) ───────────────
// Authoritative read API: GET /api/idp (viewer; secrets are server-redacted).
// The full profile list is returned so a DANGLING ref (deleted/disabled
// provider) can be rendered degraded instead of silently dropped.

export interface IdPProviderRef {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
  /** OIDC/SAML — the only types that can satisfy SSORequired */
  interactive: boolean;
}

const decodeIdPProviderRef: Decoder<IdPProviderRef> = (v, path = "$") => {
  const o = readRecord(v, path);
  const type = field(o, "type", readString, path);
  return {
    id: field(o, "id", readString, path),
    name: field(o, "name", optStr, path) ?? "",
    type,
    enabled: field(o, "enabled", readBoolean, path),
    interactive: type === "oidc" || type === "saml",
  };
};

export interface IdPProviderList {
  persisted: boolean;
  profiles: readonly IdPProviderRef[];
}

const decodeIdPProviderList: Decoder<IdPProviderList> = (v, path = "$") => {
  const o = readRecord(v, path);
  const raw = o["profiles"];
  return {
    persisted: field(o, "persisted", readBoolean, path),
    profiles:
      raw === undefined || raw === null
        ? []
        : readArray(decodeIdPProviderRef)(raw, `${path}.profiles`),
  };
};

export function getIdPProviders(signal?: AbortSignal): Promise<IdPProviderList> {
  return apiRequest(
    "/api/idp",
    decodeIdPProviderList,
    signal !== undefined ? { signal } : {},
  );
}
