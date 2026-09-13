// FE-6A.1 — Identity Providers READ client: fail-closed runtime decoders
// over the frozen FE-6A.0 read models (ui_auth.go idpListReadModel /
// publicIdPProfile / idpClusterReadModel, idp_operations.go lookupReadModel
// / readModel, ui_auth_ldap.go apiIdPLegacyLDAP) and the where-used walk
// (policy_refs.go, type `idp`), plus — FE-6A.2 — the WRITE client: every
// mutation of the registry (create / update / delete / test / discover /
// legacy import / repair) as an action-bound, fence-carrying, never-retrying
// call whose 2xx is a verdict ONLY when it proves the action's own identity,
// revision and durability facts (the 2F-F rule), and whose refusal is a
// verdict ONLY inside the closed IDP_REFUSAL_CONTRACT (status + typed facts).
//
// Secret boundary. The backend read models are secret-free BY CONSTRUCTION
// (publicIdPProfile rebuilds every sub-config from named non-secret fields;
// only the derived *Configured indicators survive). The browser enforces the
// same boundary independently: a response carrying a secret-bearing key at
// ANY depth (clientSecret, bindPassword, metadataXml, password, secret,
// ciphertext, sealed …) is a DECODE FAILURE — never rendered, never cached.
//
// Bounded vocabularies (FE-6A.1 correction, blocker 1). Every server CLASS
// the surface renders is decoded against the AUTHORITATIVE closed set the
// contract declares (api/openapi/openapi.yaml, mirrored from the Go
// constants) and REFUSED when unknown — a raw dependency error can never
// ride a "reason" or "code" field into the DOM:
//   • fleet rejection class      — controlplane_snapshot.go publishReject*
//   • ledger degradation reason  — idp_operations.go newIdPOperationStore
//   • operation action           — idp.create
//   • operation code             — the refusal codes writeIdPRefusal records
//                                  on an aborted / outcome_unknown intent, and
//                                  the settlement family <why>_<verdict>
//   • lookup refusal code        — what GET /api/idp/operations/{id} answers
//
// Missing evidence is never negative truth (blocker 2): every fact the wire
// ALWAYS carries is required — Go emits `priority` and `emailDomains`
// (nullable) without omitempty, a profile always carries exactly its own
// type's sub-config, a PRESENT legacy block always carries its identity and
// its bind-credential indicator. Only the indicator bits INSIDE a present
// sub-config keep Go's omitempty rule (absent ⇒ false), which the contract
// now declares explicitly (IdPOIDCRead / IdPSAMLRead / IdPLDAPRead).
//
// The operation record is a DISCRIMINATED UNION (blocker 3): each state has
// exactly the fields idp_operations.go Finish/MarkAudited/settleOperation
// give it; a contradictory record is refused whole, never partially rendered.
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
import { decodeObjectReferences } from "./policy";
import type { ObjectReferences } from "./policy";

function opt<T>(
  o: Record<string, unknown>,
  key: string,
  read: Decoder<T>,
  path: string,
): T | undefined {
  return readOptional(read)(o[key], `${path}.${key}`);
}

/** A REQUIRED nullable Go slice: the key must be on the wire; null ⇒ []. */
function requiredStringsOrNull(
  o: Record<string, unknown>,
  key: string,
  path: string,
): readonly string[] {
  if (!(key in o))
    throw new DecodeError(`${path}.${key}`, "array|null", undefined);
  const v = o[key];
  if (v === null) return [];
  return readArray(readString)(v, `${path}.${key}`);
}

/** An optional nullable Go slice (omitempty): absent / null ⇒ []. */
function optionalStringsOrNull(v: unknown, path: string): readonly string[] {
  if (v === undefined || v === null) return [];
  return readArray(readString)(v, path);
}

/** Refuse a key that is present with a non-null value. */
function refuseForeign(
  o: Record<string, unknown>,
  key: string,
  path: string,
  expected: string,
): void {
  if (key in o && o[key] !== null) {
    throw new DecodeError(`${path}.${key}`, expected, "[present]");
  }
}

// ── Vocabularies (server contract; mirrored from the Go constants) ─────────

export const IDP_TYPES = ["oidc", "saml", "ldap"] as const;
export type IdPType = (typeof IDP_TYPES)[number];

export const IDP_DEGRADED_REASONS = [
  "corrupt_quarantined",
  "corrupt_not_quarantined",
] as const;
export type IdPDegradedReason = (typeof IDP_DEGRADED_REASONS)[number];

export const IDP_CLUSTER_STATES = ["published", "pending"] as const;
export type IdPClusterState = (typeof IDP_CLUSTER_STATES)[number];

/** controlplane_snapshot.go publishReject* — the bounded class a rejected
 * fleet publication is reported as. */
export const IDP_FLEET_REJECTION_REASONS = [
  "identity_degraded",
  "snapshot_invalid",
  "marshal_failed",
  "wire_size_exceeded",
] as const;
export type IdPFleetRejectionReason =
  (typeof IDP_FLEET_REJECTION_REASONS)[number];

/** idp_operations.go newIdPOperationStore — the ledger's fail-closed posture. */
export const IDP_LEDGER_DEGRADED_REASONS = ["unreadable", "corrupt"] as const;
export type IdPLedgerDegradedReason =
  (typeof IDP_LEDGER_DEGRADED_REASONS)[number];

export const IDP_AUDIT_SINKS = ["memory", "file"] as const;
export type IdPAuditSink = (typeof IDP_AUDIT_SINKS)[number];

export const IDP_OPERATION_STATES = [
  "pending",
  "committed",
  "aborted",
  "outcome_unknown",
] as const;
export type IdPOperationState = (typeof IDP_OPERATION_STATES)[number];

export const IDP_OPERATION_ACTIONS = ["idp.create", "idp.update"] as const;
export type IdPOperationAction = (typeof IDP_OPERATION_ACTIONS)[number];

/** The refusal codes writeIdPRefusal (ui_auth.go) can record on an aborted
 * or outcome_unknown intent. */
export const IDP_OPERATION_REFUSAL_CODES = [
  "stale",
  "invalid_input",
  "provider_compile_failed",
  "operation_ledger_degraded",
  "operation_unsettled",
  "operation_ledger_full",
  "persist_failed",
  "vanished",
  "registry_degraded",
  "outcome_unknown",
] as const;

/** auth_idp.go settleOperation — `<why>_<verdict>`: why ∈ reconciled (boot),
 * lookup (the GET), settled_before_write (a later writer on the profile). */
export const IDP_SETTLEMENT_FAMILIES = [
  "reconciled",
  "lookup",
  "settled_before_write",
] as const;
export const IDP_SETTLEMENT_COMMITTED_CODES = IDP_SETTLEMENT_FAMILIES.map(
  (w) => `${w}_committed` as const,
);
export const IDP_SETTLEMENT_ABORTED_CODES = IDP_SETTLEMENT_FAMILIES.flatMap(
  (w) => [`${w}_absent` as const, `${w}_unproven` as const],
);

/** Every code an operation record may carry (the contract's closed enum). */
export const IDP_OPERATION_CODES: readonly string[] = [
  ...IDP_OPERATION_REFUSAL_CODES,
  ...IDP_SETTLEMENT_COMMITTED_CODES,
  ...IDP_SETTLEMENT_ABORTED_CODES,
];
/** Codes a COMMITTED record may carry (settlement verdicts only). */
const COMMITTED_CODES: readonly string[] = IDP_SETTLEMENT_COMMITTED_CODES;
/** Codes an ABORTED / OUTCOME_UNKNOWN record may carry. */
const TERMINAL_FAILURE_CODES: readonly string[] = [
  ...IDP_OPERATION_REFUSAL_CODES,
  ...IDP_SETTLEMENT_ABORTED_CODES,
];

/** What GET /api/idp/operations/{id} itself answers as a typed refusal
 * (ui_auth.go apiIdPOperations + requireRoleJSON + writeIdPRefusal on a
 * degraded ledger). Anything else is not a verdict this surface may name. */
export const IDP_LOOKUP_REFUSAL_CODES = [
  "invalid_input",
  "forbidden",
  "not_found",
  "operation_ledger_degraded",
] as const;
export type IdPLookupRefusalCode = (typeof IDP_LOOKUP_REFUSAL_CODES)[number];

export const LEGACY_CUTOVER_DURABILITY = [
  "not_retired",
  "durable",
  "pending_reconciliation",
] as const;
export type LegacyCutoverDurability =
  (typeof LEGACY_CUTOVER_DURABILITY)[number];

export const LEGACY_CUTOVER_TRIGGERS = ["admin_api", "observed"] as const;
export type LegacyCutoverTrigger = (typeof LEGACY_CUTOVER_TRIGGERS)[number];

// ── Secret sweep ───────────────────────────────────────────────────────────

/** Keys that name write-only or at-rest secret material. Matched EXACTLY
 * (case-sensitive) at every depth — the derived indicator keys
 * (`clientSecretConfigured`, `bindCredentialConfigured`,
 * `inlineMetadataConfigured`) are distinct and never match. */
export const IDP_SECRET_KEYS: readonly string[] = [
  "clientSecret",
  "client_secret",
  "bindPassword",
  "bind_password",
  "metadataXml",
  "metadata_xml",
  "password",
  "pass_hash",
  "passHash",
  "secret",
  "ciphertext",
  "sealed",
  "totpSecret",
  "totp_secret",
];

/** Fail-closed guard: refuse a record (recursively) that carries any secret
 * key. The path names the offending key for the DecodeError only — the
 * VALUE is deliberately not echoed. */
export function refuseSecretKeys(
  v: unknown,
  path: string,
  keys: readonly string[] = IDP_SECRET_KEYS,
): void {
  if (Array.isArray(v)) {
    v.forEach((el, i) => {
      refuseSecretKeys(el, `${path}[${String(i)}]`, keys);
    });
    return;
  }
  if (!isRecord(v)) return;
  for (const k of Object.keys(v)) {
    if (keys.includes(k)) {
      throw new DecodeError(
        `${path}.${k}`,
        "no secret material (never reaches the browser)",
        "[redacted]",
      );
    }
    refuseSecretKeys(v[k], `${path}.${k}`, keys);
  }
}

// ── Models ─────────────────────────────────────────────────────────────────

export interface IdPOIDCFacts {
  issuer: string;
  clientId: string;
  /** derived write-only-secret indicator — never the value */
  clientSecretConfigured: boolean;
  // FE-6A.2 — the remaining NON-SECRET settings publicIdPProfile emits (Go
  // omitempty on the endpoints: absent ⇒ "" by contract), so an edit can
  // re-send the complete candidate instead of wiping unseen fields.
  scopes: readonly string[];
  groupsClaim: string;
  requiredScope: string;
  requiredAudience: string;
  tlsSkipVerify: boolean;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  introspectionEndpoint: string;
  userinfoEndpoint: string;
  jwksUri: string;
}

export interface IdPSAMLFacts {
  metadataUrl: string;
  /** derived write-only indicator for the inline metadata upload */
  inlineMetadataConfigured: boolean;
  nameIdFormat: string;
  groupsAttribute: string;
  emailAttribute: string;
  nameAttribute: string;
}

export interface IdPLDAPFacts {
  url: string;
  bindDn: string;
  /** derived write-only-secret indicator — never the value */
  bindCredentialConfigured: boolean;
  // FE-6A.2 — Go omitempty on every one of these: absent ⇒ zero value.
  startTls: boolean;
  tlsSkipVerify: boolean;
  baseDn: string;
  userFilter: string;
  emailAttribute: string;
  nameAttribute: string;
  groupAttribute: string;
  requiredGroup: string;
  cacheTtlSeconds: number;
}

/** A profile carries exactly its own type's sub-config. */
export type IdPProfile = {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  /** server-minted ENTRY fencing token (≥1) */
  revision: number;
  /** provenance of the operation-identified create that produced the entry */
  operationId?: string;
  emailDomains: readonly string[];
  knownGroups: readonly string[];
} & (
  | { type: "oidc"; oidc: IdPOIDCFacts }
  | { type: "saml"; saml: IdPSAMLFacts }
  | { type: "ldap"; ldap: IdPLDAPFacts }
);

export interface IdPFleetRejection {
  reason: IdPFleetRejectionReason;
  at: string;
}

export interface IdPClusterFacts {
  state: IdPClusterState;
  publishedVersion: number;
  lastRejection?: IdPFleetRejection;
}

export interface IdPLedgerFacts {
  degraded: boolean;
  degradedReason?: IdPLedgerDegradedReason;
  retained: number;
  unresolved: number;
  capacity: number;
  auditSink: IdPAuditSink;
}

export interface IdPList {
  persisted: boolean;
  degraded: boolean;
  degradedReason?: IdPDegradedReason;
  /** base name of the quarantined file — PRESENCE is the rendered fact */
  quarantineEvidence?: string;
  /** content-derived registry DOCUMENT revision */
  revision: string;
  profiles: readonly IdPProfile[];
  scope: "cluster-synced";
  cluster: IdPClusterFacts;
  operations: IdPLedgerFacts;
}

interface IdPOperationBase {
  operationId: string;
  action: IdPOperationAction;
  actor: string;
  profileId: string;
  registryRevision: string;
  cutover: boolean;
  startedAt: string;
}

/** The discriminated union the ledger record actually takes. */
export type IdPOperation = IdPOperationBase &
  (
    | { state: "pending"; audited: false }
    | {
        state: "committed";
        audited: true;
        finishedAt: string;
        committedRevision: string;
        /** a settlement verdict, when the commit was settled rather than direct */
        code?: string;
      }
    | {
        state: "committed";
        audited: false;
        /** the durable success audit is still owed (recoverable) */
        auditState: "pending";
        finishedAt: string;
        committedRevision: string;
        code?: string;
      }
    | {
        state: "aborted" | "outcome_unknown";
        audited: false;
        finishedAt: string;
        /** the bounded refusal code, or the settlement verdict */
        code: string;
      }
  );

export interface LegacyCutover {
  operationId: string;
  profileId?: string;
  profileName?: string;
  registryRevision?: string;
  actor: string;
  trigger: LegacyCutoverTrigger;
  at: string;
  durable: boolean;
}

interface LegacyLDAPBase {
  /** the DURABLE authority cutover has happened */
  retired: boolean;
  scope: "node-local";
  cutoverDurability: LegacyCutoverDurability;
  cutover?: LegacyCutover;
}

/** The facts apiIdPLegacyLDAP emits ONLY when the YAML block is present —
 * every one of them, on every present answer (correction round 2, D1/D2). */
export interface LegacyLDAPPresentFacts {
  /** the legacy block is the live proxy-auth backend */
  active: boolean;
  /** retired OR an enabled registry LDAP profile exists */
  shadowed: boolean;
  url: string;
  baseDn: string;
  bindDn: string;
  /** derived write-only-secret indicator — never the value */
  bindCredentialConfigured: boolean;
  /** the user search filter ("" is a configured value, not absence) */
  userFilter: string;
  /** group membership required for authentication ("" = none) */
  requiredGroup: string;
  /** StartTLS is negotiated on a plain ldap:// connection */
  startTls: boolean;
  /** SECURITY-EFFECTIVE: the directory's certificate is NOT verified */
  tlsSkipVerify: boolean;
  /** authentication-result cache TTL in seconds */
  cacheTtlSeconds: number;
  /** FE-6A.2 — the SERVER-required confirmation value a cutover-bearing
   * write must echo as ?cutoverConfirm= (the legacy directory URL) */
  cutoverConfirmValue: string;
}

/** The keys that may appear ONLY on a present block. */
export const LEGACY_PRESENT_ONLY_KEYS = [
  "active",
  "shadowed",
  "url",
  "baseDn",
  "bindDn",
  "bindCredentialConfigured",
  "userFilter",
  "requiredGroup",
  "startTls",
  "tlsSkipVerify",
  "cacheTtlSeconds",
  "cutoverConfirmValue",
] as const satisfies readonly (keyof LegacyLDAPPresentFacts)[];

/** A RUNTIME discriminated union: `present:false` carries none of the
 * present-only facts (a record that does is refused whole), `present:true`
 * carries every one of them. */
export type LegacyLDAP = LegacyLDAPBase &
  ({ present: false } | ({ present: true } & LegacyLDAPPresentFacts));

// ── Decoders ───────────────────────────────────────────────────────────────

const optStr = (o: Record<string, unknown>, k: string, path: string): string =>
  opt(o, k, readString, path) ?? "";
const optBool = (
  o: Record<string, unknown>,
  k: string,
  path: string,
): boolean => opt(o, k, readBoolean, path) ?? false;

const decodeOIDCFacts: Decoder<IdPOIDCFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    issuer: optStr(o, "issuer", path),
    clientId: optStr(o, "clientId", path),
    // Go omitempty: absent ⇒ false (declared on IdPOIDCRead).
    clientSecretConfigured: optBool(o, "clientSecretConfigured", path),
    scopes: optionalStringsOrNull(o["scopes"], `${path}.scopes`),
    groupsClaim: optStr(o, "groupsClaim", path),
    requiredScope: optStr(o, "requiredScope", path),
    requiredAudience: optStr(o, "requiredAudience", path),
    tlsSkipVerify: optBool(o, "tlsSkipVerify", path),
    authorizationEndpoint: optStr(o, "authorizationEndpoint", path),
    tokenEndpoint: optStr(o, "tokenEndpoint", path),
    introspectionEndpoint: optStr(o, "introspectionEndpoint", path),
    userinfoEndpoint: optStr(o, "userinfoEndpoint", path),
    jwksUri: optStr(o, "jwksUri", path),
  };
};

const decodeSAMLFacts: Decoder<IdPSAMLFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    metadataUrl: optStr(o, "metadataUrl", path),
    // Go omitempty: absent ⇒ false (declared on IdPSAMLRead).
    inlineMetadataConfigured: optBool(o, "inlineMetadataConfigured", path),
    nameIdFormat: optStr(o, "nameIdFormat", path),
    groupsAttribute: optStr(o, "groupsAttribute", path),
    emailAttribute: optStr(o, "emailAttribute", path),
    nameAttribute: optStr(o, "nameAttribute", path),
  };
};

const decodeLDAPFacts: Decoder<IdPLDAPFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    url: optStr(o, "url", path),
    bindDn: optStr(o, "bindDn", path),
    // Go omitempty: absent ⇒ false (declared on IdPLDAPRead).
    bindCredentialConfigured: optBool(o, "bindCredentialConfigured", path),
    startTls: optBool(o, "startTls", path),
    tlsSkipVerify: optBool(o, "tlsSkipVerify", path),
    baseDn: optStr(o, "baseDn", path),
    userFilter: optStr(o, "userFilter", path),
    emailAttribute: optStr(o, "emailAttribute", path),
    nameAttribute: optStr(o, "nameAttribute", path),
    groupAttribute: optStr(o, "groupAttribute", path),
    requiredGroup: optStr(o, "requiredGroup", path),
    cacheTtlSeconds: opt(o, "cacheTtlSeconds", readNumber, path) ?? 0,
  };
};

export const decodeIdPProfile: Decoder<IdPProfile> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseSecretKeys(o, path);
  const type = field(o, "type", readEnum(IDP_TYPES), path);
  const operationId = opt(o, "operationId", readString, path);
  const base = {
    id: field(o, "id", readString, path),
    name: field(o, "name", readString, path),
    enabled: field(o, "enabled", readBoolean, path),
    priority: field(o, "priority", readNumber, path),
    revision: field(o, "revision", readNumber, path),
    ...(operationId !== undefined ? { operationId } : {}),
    emailDomains: requiredStringsOrNull(o, "emailDomains", path),
    knownGroups: optionalStringsOrNull(o["knownGroups"], `${path}.knownGroups`),
  };
  // Exactly the type's own sub-config is present; a foreign one is refused.
  for (const other of IDP_TYPES) {
    if (other !== type)
      refuseForeign(o, other, path, `absent (type is ${type})`);
  }
  switch (type) {
    case "oidc":
      return { ...base, type, oidc: field(o, "oidc", decodeOIDCFacts, path) };
    case "saml":
      return { ...base, type, saml: field(o, "saml", decodeSAMLFacts, path) };
    case "ldap":
      return { ...base, type, ldap: field(o, "ldap", decodeLDAPFacts, path) };
  }
};

const decodeFleetRejection: Decoder<IdPFleetRejection> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    reason: field(o, "reason", readEnum(IDP_FLEET_REJECTION_REASONS), path),
    at: field(o, "at", readString, path),
  };
};

const decodeClusterFacts: Decoder<IdPClusterFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  const lastRejection = opt(o, "lastRejection", decodeFleetRejection, path);
  return {
    state: field(o, "state", readEnum(IDP_CLUSTER_STATES), path),
    publishedVersion: field(o, "publishedVersion", readNumber, path),
    ...(lastRejection !== undefined ? { lastRejection } : {}),
  };
};

const decodeLedgerFacts: Decoder<IdPLedgerFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  const degraded = field(o, "degraded", readBoolean, path);
  const degradedReason = opt(
    o,
    "degradedReason",
    readEnum(IDP_LEDGER_DEGRADED_REASONS),
    path,
  );
  if (degraded && degradedReason === undefined) {
    throw new DecodeError(
      `${path}.degradedReason`,
      "bounded reason",
      undefined,
    );
  }
  return {
    degraded,
    ...(degradedReason !== undefined ? { degradedReason } : {}),
    retained: field(o, "retained", readNumber, path),
    unresolved: field(o, "unresolved", readNumber, path),
    capacity: field(o, "capacity", readNumber, path),
    auditSink: field(o, "auditSink", readEnum(IDP_AUDIT_SINKS), path),
  };
};

/** The quarantine evidence is a BASE NAME by server contract
 * (filepath.Base). A value that could be a path is refused — no file path
 * ever reaches the browser. */
const readEvidenceBaseName: Decoder<string> = (v, path = "$") => {
  const s = readString(v, path);
  if (s === "" || s.includes("/") || s.includes("\\") || s.includes("..")) {
    throw new DecodeError(path, "quarantine evidence base name", "[redacted]");
  }
  return s;
};

export const decodeIdPList: Decoder<IdPList> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseSecretKeys(o, path);
  const degradedReason = opt(
    o,
    "degradedReason",
    readEnum(IDP_DEGRADED_REASONS),
    path,
  );
  const quarantineEvidence = opt(
    o,
    "quarantineEvidence",
    readEvidenceBaseName,
    path,
  );
  // REQUIRED nullable Go slice (idpListReadModel always emits the key;
  // OpenAPI: required + nullable): a MISSING key is a decode failure, `null`
  // is the empty slice (correction round 2, D3).
  if (!("profiles" in o)) {
    throw new DecodeError(`${path}.profiles`, "array or null", undefined);
  }
  const rawProfiles = o["profiles"];
  const degraded = field(o, "degraded", readBoolean, path);
  if (degraded && degradedReason === undefined) {
    throw new DecodeError(
      `${path}.degradedReason`,
      "bounded reason",
      undefined,
    );
  }
  return {
    persisted: field(o, "persisted", readBoolean, path),
    degraded,
    ...(degradedReason !== undefined ? { degradedReason } : {}),
    ...(quarantineEvidence !== undefined ? { quarantineEvidence } : {}),
    revision: field(o, "revision", readString, path),
    profiles:
      rawProfiles === null
        ? []
        : readArray(decodeIdPProfile)(rawProfiles, `${path}.profiles`),
    scope: field(o, "scope", readEnum(["cluster-synced"] as const), path),
    cluster: field(o, "cluster", decodeClusterFacts, path),
    operations: field(o, "operations", decodeLedgerFacts, path),
  };
};

/** Refuse a key that is present on a record whose state forbids it. */
function forbid(
  o: Record<string, unknown>,
  key: string,
  path: string,
  state: string,
): void {
  if (key in o) {
    throw new DecodeError(
      `${path}.${key}`,
      `absent on a ${state} record`,
      "[present]",
    );
  }
}

export const decodeIdPOperation: Decoder<IdPOperation> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseSecretKeys(o, path);
  const base: IdPOperationBase = {
    operationId: field(o, "operationId", readString, path),
    action: field(o, "action", readEnum(IDP_OPERATION_ACTIONS), path),
    actor: field(o, "actor", readString, path),
    profileId: field(o, "profileId", readString, path),
    registryRevision: field(o, "registryRevision", readString, path),
    cutover: field(o, "cutover", readBoolean, path),
    startedAt: field(o, "startedAt", readString, path),
  };
  const state = field(o, "state", readEnum(IDP_OPERATION_STATES), path);
  const audited = field(o, "audited", readBoolean, path);
  const auditState = opt(o, "auditState", readEnum(["pending"] as const), path);
  switch (state) {
    case "pending": {
      if (audited)
        throw new DecodeError(
          `${path}.audited`,
          "false on a pending record",
          audited,
        );
      for (const k of [
        "auditState",
        "finishedAt",
        "code",
        "committedRevision",
        "result",
      ]) {
        forbid(o, k, path, "pending");
      }
      return { ...base, state, audited: false };
    }
    case "committed": {
      const finishedAt = field(o, "finishedAt", readString, path);
      const committedRevision = field(o, "committedRevision", readString, path);
      const code = opt(o, "code", readEnum(COMMITTED_CODES), path);
      if (audited) {
        forbid(o, "auditState", path, "committed+audited");
        return {
          ...base,
          state,
          audited: true,
          finishedAt,
          committedRevision,
          ...(code !== undefined ? { code } : {}),
        };
      }
      if (auditState !== "pending") {
        throw new DecodeError(
          `${path}.auditState`,
          "pending (audit owed on an unaudited commit)",
          auditState,
        );
      }
      return {
        ...base,
        state,
        audited: false,
        auditState,
        finishedAt,
        committedRevision,
        ...(code !== undefined ? { code } : {}),
      };
    }
    case "aborted":
    case "outcome_unknown": {
      if (audited)
        throw new DecodeError(
          `${path}.audited`,
          `false on an ${state} record`,
          audited,
        );
      for (const k of ["auditState", "committedRevision", "result"])
        forbid(o, k, path, state);
      return {
        ...base,
        state,
        audited: false,
        finishedAt: field(o, "finishedAt", readString, path),
        code: field(o, "code", readEnum(TERMINAL_FAILURE_CODES), path),
      };
    }
  }
};

const decodeLegacyCutover: Decoder<LegacyCutover> = (v, path = "$") => {
  const o = readRecord(v, path);
  const profileId = opt(o, "profileId", readString, path);
  const profileName = opt(o, "profileName", readString, path);
  const registryRevision = opt(o, "registryRevision", readString, path);
  return {
    operationId: field(o, "operationId", readString, path),
    ...(profileId !== undefined ? { profileId } : {}),
    ...(profileName !== undefined ? { profileName } : {}),
    ...(registryRevision !== undefined ? { registryRevision } : {}),
    actor: field(o, "actor", readString, path),
    trigger: field(o, "trigger", readEnum(LEGACY_CUTOVER_TRIGGERS), path),
    at: field(o, "at", readString, path),
    durable: field(o, "durable", readBoolean, path),
  };
};

export const decodeLegacyLDAP: Decoder<LegacyLDAP> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseSecretKeys(o, path);
  const cutover = opt(o, "cutover", decodeLegacyCutover, path);
  const base: LegacyLDAPBase = {
    retired: field(o, "retired", readBoolean, path),
    scope: field(o, "scope", readEnum(["node-local"] as const), path),
    cutoverDurability: field(
      o,
      "cutoverDurability",
      readEnum(LEGACY_CUTOVER_DURABILITY),
      path,
    ),
    ...(cutover !== undefined ? { cutover } : {}),
  };
  const present = field(o, "present", readBoolean, path);
  if (!present) {
    // A real union member: an absent block that ALSO carries a present-only
    // fact is contradictory evidence and is refused whole — never accepted
    // with the extra facts silently discarded (correction round 2, D1).
    for (const k of LEGACY_PRESENT_ONLY_KEYS) {
      forbid(o, k, path, "present:false");
    }
    return { ...base, present: false };
  }
  return {
    ...base,
    present: true,
    active: field(o, "active", readBoolean, path),
    shadowed: field(o, "shadowed", readBoolean, path),
    url: field(o, "url", readString, path),
    baseDn: field(o, "baseDn", readString, path),
    bindDn: field(o, "bindDn", readString, path),
    bindCredentialConfigured: field(
      o,
      "bindCredentialConfigured",
      readBoolean,
      path,
    ),
    // Always emitted by the handler on a present block; incomplete evidence
    // is refused, never rendered as a default (correction round 2, D2).
    userFilter: field(o, "userFilter", readString, path),
    requiredGroup: field(o, "requiredGroup", readString, path),
    startTls: field(o, "startTls", readBoolean, path),
    tlsSkipVerify: field(o, "tlsSkipVerify", readBoolean, path),
    cacheTtlSeconds: field(o, "cacheTtlSeconds", readNumber, path),
    cutoverConfirmValue: field(o, "cutoverConfirmValue", readString, path),
  };
};

// ── Reads (GET only) ───────────────────────────────────────────────────────

export function getIdPList(signal?: AbortSignal): Promise<IdPList> {
  return apiRequest(
    "/api/idp",
    decodeIdPList,
    signal !== undefined ? { signal } : {},
  );
}

export function getLegacyLDAP(signal?: AbortSignal): Promise<LegacyLDAP> {
  return apiRequest(
    "/api/idp/legacy-ldap",
    decodeLegacyLDAP,
    signal !== undefined ? { signal } : {},
  );
}

/** Admin-only (uiRoutes GET /api/idp/operations/ = admin: the record names
 * the actor). Callers below admin must not issue it. */
export function getIdPOperation(
  operationId: string,
  signal?: AbortSignal,
): Promise<IdPOperation> {
  return apiRequest(
    `/api/idp/operations/${encodeURIComponent(operationId)}`,
    decodeIdPOperation,
    signal !== undefined ? { signal } : {},
  );
}

/** Where-used walk for one provider: the authentication rules whose
 * SSORequired providerRefs name it (running + active draft candidate) —
 * exactly the set a delete would be refused on (409 referenced). */
export function getIdPReferences(
  id: string,
  signal?: AbortSignal,
): Promise<ObjectReferences> {
  const qs = new URLSearchParams({ type: "idp", name: id });
  return apiRequest(
    `/api/objects/references?${qs.toString()}`,
    decodeObjectReferences,
    signal !== undefined ? { signal } : {},
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// FE-6A.2 — WRITE client
// ═══════════════════════════════════════════════════════════════════════════

// ── Write specs (the exact wire body; secrets are WRITE-ONLY) ──────────────

export interface OIDCWrite {
  issuer: string;
  clientId: string;
  /** undefined = keep the stored secret (update) / none (create);
   * "" = EXPLICIT CLEAR; otherwise the new value, sent once in the body */
  clientSecret?: string | undefined;
  scopes: readonly string[];
  groupsClaim: string;
  requiredScope: string;
  requiredAudience: string;
  tlsSkipVerify: boolean;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  introspectionEndpoint?: string;
  userinfoEndpoint?: string;
  jwksUri?: string;
}

export interface SAMLWrite {
  metadataUrl: string;
  /** undefined = keep / none; "" = explicit clear; else the inline document */
  metadataXml?: string | undefined;
  nameIdFormat: string;
  groupsAttribute: string;
  emailAttribute: string;
  nameAttribute: string;
}

export interface LDAPWrite {
  url: string;
  startTls: boolean;
  tlsSkipVerify: boolean;
  bindDn: string;
  /** undefined = keep / none; "" = explicit clear (anonymous bind) */
  bindPassword?: string | undefined;
  baseDn: string;
  userFilter: string;
  emailAttribute: string;
  nameAttribute: string;
  groupAttribute: string;
  requiredGroup: string;
  cacheTtlSeconds: number;
}

interface IdPWriteBase {
  name: string;
  enabled: boolean;
  priority: number;
  emailDomains: readonly string[];
  knownGroups: readonly string[];
}

export type IdPWriteSpec = IdPWriteBase &
  (
    | { type: "oidc"; oidc: OIDCWrite }
    | { type: "saml"; saml: SAMLWrite }
    | { type: "ldap"; ldap: LDAPWrite }
  );

function withOptional(
  o: Record<string, unknown>,
  key: string,
  v: string | undefined,
): void {
  if (v !== undefined && v !== "") o[key] = v;
}

/** The exact request body: exactly one sub-config, secrets only when the
 * caller supplied them (a supplied "" is the contract's explicit clear),
 * never a read-only indicator, never id / revision / operationId. */
export function idpWriteBody(spec: IdPWriteSpec): Record<string, unknown> {
  const body: Record<string, unknown> = {
    name: spec.name,
    type: spec.type,
    enabled: spec.enabled,
    priority: spec.priority,
    emailDomains: [...spec.emailDomains],
    knownGroups: [...spec.knownGroups],
  };
  switch (spec.type) {
    case "oidc": {
      const o: Record<string, unknown> = {
        issuer: spec.oidc.issuer,
        clientId: spec.oidc.clientId,
        scopes: [...spec.oidc.scopes],
        groupsClaim: spec.oidc.groupsClaim,
        requiredScope: spec.oidc.requiredScope,
        requiredAudience: spec.oidc.requiredAudience,
        tlsSkipVerify: spec.oidc.tlsSkipVerify,
      };
      withOptional(o, "authorizationEndpoint", spec.oidc.authorizationEndpoint);
      withOptional(o, "tokenEndpoint", spec.oidc.tokenEndpoint);
      withOptional(o, "introspectionEndpoint", spec.oidc.introspectionEndpoint);
      withOptional(o, "userinfoEndpoint", spec.oidc.userinfoEndpoint);
      withOptional(o, "jwksUri", spec.oidc.jwksUri);
      if (spec.oidc.clientSecret !== undefined)
        o["clientSecret"] = spec.oidc.clientSecret;
      body["oidc"] = o;
      break;
    }
    case "saml": {
      const o: Record<string, unknown> = {
        metadataUrl: spec.saml.metadataUrl,
        nameIdFormat: spec.saml.nameIdFormat,
        groupsAttribute: spec.saml.groupsAttribute,
        emailAttribute: spec.saml.emailAttribute,
        nameAttribute: spec.saml.nameAttribute,
      };
      if (spec.saml.metadataXml !== undefined)
        o["metadataXml"] = spec.saml.metadataXml;
      body["saml"] = o;
      break;
    }
    case "ldap": {
      const o: Record<string, unknown> = {
        url: spec.ldap.url,
        startTls: spec.ldap.startTls,
        tlsSkipVerify: spec.ldap.tlsSkipVerify,
        bindDn: spec.ldap.bindDn,
        baseDn: spec.ldap.baseDn,
        userFilter: spec.ldap.userFilter,
        emailAttribute: spec.ldap.emailAttribute,
        nameAttribute: spec.ldap.nameAttribute,
        groupAttribute: spec.ldap.groupAttribute,
        requiredGroup: spec.ldap.requiredGroup,
        cacheTtlSeconds: spec.ldap.cacheTtlSeconds,
      };
      if (spec.ldap.bindPassword !== undefined)
        o["bindPassword"] = spec.ldap.bindPassword;
      body["ldap"] = o;
      break;
    }
  }
  return body;
}

function secretOf(spec: IdPWriteSpec): string | undefined {
  switch (spec.type) {
    case "oidc":
      return spec.oidc.clientSecret;
    case "saml":
      return spec.saml.metadataXml;
    case "ldap":
      return spec.ldap.bindPassword;
  }
}

/** True when the body will carry write-only MATERIAL (a clear carries none). */
export function specCarriesSecret(spec: IdPWriteSpec): boolean {
  const s = secretOf(spec);
  return s !== undefined && s !== "";
}

type SecretPosture = "keep" | "clear" | "present";
function secretPosture(spec: IdPWriteSpec): SecretPosture {
  const s = secretOf(spec);
  if (s === undefined) return "keep";
  return s === "" ? "clear" : "present";
}

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (isRecord(v)) {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

/** FNV-1a 64-bit over a canonical string — a stable, dependency-free
 * identity for a NON-SECRET candidate (never a cryptographic claim). */
function fnv1a64(s: string): string {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const mask = 0xffffffffffffffffn;
  for (const ch of new TextEncoder().encode(s)) {
    h ^= BigInt(ch);
    h = (h * prime) & mask;
  }
  return h.toString(16).padStart(16, "0");
}

/** The candidate's NON-SECRET canonical identity: every public fact plus the
 * secret's POSTURE (keep / clear / present) — never its value — so the same
 * candidate re-sent with a retyped secret keeps its operation, while any
 * public change or a presence change is a different candidate. */
export function candidateDigest(spec: IdPWriteSpec): string {
  const body = idpWriteBody(spec);
  const sub = body[spec.type];
  if (isRecord(sub)) {
    const clone: Record<string, unknown> = { ...sub };
    delete clone["clientSecret"];
    delete clone["metadataXml"];
    delete clone["bindPassword"];
    clone["secretPosture"] = secretPosture(spec);
    body[spec.type] = clone;
  }
  return fnv1a64(canonical(body));
}

// ── Fleet publication fact on every write ──────────────────────────────────

export type IdPPublication =
  | { publication: "published"; version: number }
  | { publication: "rejected"; reason: IdPFleetRejectionReason };

const decodeIdPPublication: Decoder<IdPPublication> = (v, path = "$") => {
  const o = readRecord(v, path);
  const publication = field(
    o,
    "publication",
    readEnum(["published", "rejected"] as const),
    path,
  );
  if (publication === "published") {
    return { publication, version: field(o, "version", readNumber, path) };
  }
  return {
    publication,
    reason: field(o, "reason", readEnum(IDP_FLEET_REJECTION_REASONS), path),
  };
};

// ── Action-bound write outcomes ────────────────────────────────────────────

const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SAFE_TOKEN = /^[A-Za-z0-9_.:-]{1,128}$/;
const QUARANTINE_RE = /^[A-Za-z0-9_.-]{1,200}$/;
const LDAP_URL_RE = /^ldaps?:\/\/[A-Za-z0-9.\-[\]:]{1,253}$/;

export type IdPWriteOutcome =
  | {
      kind: "written";
      profile: IdPProfile;
      cluster: IdPPublication;
      /** the dispatched operationId, echoed by the appliance */
      operationId?: string;
      /** the success audit is committed but not yet durable */
      auditState?: "pending";
    }
  | { kind: "replayed"; id: string; operationId: string };

interface WriteExpect {
  type: IdPType;
  name: string;
  id?: string;
  operationId?: string;
  /** the answer's entry revision must EXCEED this (the fence the write
   * carried); a create passes 0 */
  minRevision: number;
}

function writeOutcomeDecoder(expect: WriteExpect): Decoder<IdPWriteOutcome> {
  return (v, path = "$") => {
    const o = readRecord(v, path);
    refuseSecretKeys(o, path);
    const replayed = opt(o, "replayed", readBoolean, path) === true;
    if (replayed && !("type" in o)) {
      // The minimal settled shape {id, operationId, settled, replayed}.
      if (expect.operationId === undefined) {
        throw new DecodeError(
          `${path}.replayed`,
          "no replay was dispatched",
          true,
        );
      }
      const id = field(o, "id", readString, path);
      if (!SAFE_ID.test(id))
        throw new DecodeError(`${path}.id`, "profile id", id);
      const operationId = field(o, "operationId", readString, path);
      if (operationId !== expect.operationId) {
        throw new DecodeError(
          `${path}.operationId`,
          `the dispatched operation ${expect.operationId}`,
          operationId,
        );
      }
      return { kind: "replayed", id, operationId };
    }
    const profile = decodeIdPProfile(o, path);
    if (profile.type !== expect.type) {
      throw new DecodeError(
        `${path}.type`,
        `the submitted type ${expect.type}`,
        profile.type,
      );
    }
    if (profile.name !== expect.name) {
      throw new DecodeError(`${path}.name`, "the submitted name", profile.name);
    }
    if (expect.id !== undefined && profile.id !== expect.id) {
      throw new DecodeError(
        `${path}.id`,
        `the updated profile ${expect.id}`,
        profile.id,
      );
    }
    if (!(profile.revision > expect.minRevision)) {
      throw new DecodeError(
        `${path}.revision`,
        `> ${String(expect.minRevision)} (the write must have moved the entry)`,
        profile.revision,
      );
    }
    const cluster = field(o, "cluster", decodeIdPPublication, path);
    const out: IdPWriteOutcome = { kind: "written", profile, cluster };
    if (expect.operationId !== undefined) {
      const echoed = opt(o, "operationId", readString, path);
      if (echoed !== expect.operationId) {
        throw new DecodeError(
          `${path}.operationId`,
          `the dispatched operation ${expect.operationId}`,
          echoed,
        );
      }
      out.operationId = echoed;
    }
    const audit = opt(o, "auditState", readEnum(["pending"] as const), path);
    if (audit !== undefined) out.auditState = audit;
    return out;
  };
}

export interface IdPCreateArgs {
  /** IdPList.revision as loaded */
  documentRevision: string;
  /** the client-minted UUID persisted in the recovery marker BEFORE dispatch */
  operationId: string;
  /** the legacy block's cutoverConfirmValue when the write carries the cutover */
  cutoverConfirm?: string;
}

/** POST /api/idp — fenced on the DOCUMENT revision, operation-identified. */
export function createIdP(
  spec: IdPWriteSpec,
  args: IdPCreateArgs,
  signal?: AbortSignal,
): Promise<IdPWriteOutcome> {
  const qs = new URLSearchParams({
    documentRevision: args.documentRevision,
    operationId: args.operationId,
  });
  if (args.cutoverConfirm !== undefined)
    qs.set("cutoverConfirm", args.cutoverConfirm);
  return apiRequest(
    `/api/idp?${qs.toString()}`,
    writeOutcomeDecoder({
      type: spec.type,
      name: spec.name,
      operationId: args.operationId,
      minRevision: 0,
    }),
    {
      method: "POST",
      body: idpWriteBody(spec),
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

export interface IdPUpdateArgs {
  /** the ENTRY revision as loaded */
  revision: number;
  /** required (with cutoverConfirm) when the update carries the cutover */
  operationId?: string;
  cutoverConfirm?: string;
}

/** PUT /api/idp/{id} — fenced on the ENTRY revision. */
export function updateIdP(
  id: string,
  spec: IdPWriteSpec,
  args: IdPUpdateArgs,
  signal?: AbortSignal,
): Promise<IdPWriteOutcome> {
  const qs = new URLSearchParams({ revision: String(args.revision) });
  if (args.operationId !== undefined) qs.set("operationId", args.operationId);
  if (args.cutoverConfirm !== undefined)
    qs.set("cutoverConfirm", args.cutoverConfirm);
  return apiRequest(
    `/api/idp/${encodeURIComponent(id)}?${qs.toString()}`,
    writeOutcomeDecoder({
      type: spec.type,
      name: spec.name,
      id,
      minRevision: args.revision,
      ...(args.operationId !== undefined
        ? { operationId: args.operationId }
        : {}),
    }),
    {
      method: "PUT",
      body: idpWriteBody(spec),
      ...(signal !== undefined ? { signal } : {}),
    },
  );
}

export interface IdPDeleteResult {
  ok: true;
  deleted: true;
  id: string;
  /** the registry DOCUMENT revision after the delete */
  revision: string;
  persisted: boolean;
  cluster: IdPPublication;
}

/** DELETE /api/idp/{id}?revision= — bodiless, fenced on the ENTRY revision. */
export function deleteIdP(
  id: string,
  revision: number,
  signal?: AbortSignal,
): Promise<IdPDeleteResult> {
  const decoder: Decoder<IdPDeleteResult> = (v, path = "$") => {
    const o = readRecord(v, path);
    refuseSecretKeys(o, path);
    if (field(o, "ok", readBoolean, path) !== true)
      throw new DecodeError(`${path}.ok`, "true", o["ok"]);
    if (field(o, "deleted", readBoolean, path) !== true)
      throw new DecodeError(`${path}.deleted`, "true", o["deleted"]);
    const gotId = field(o, "id", readString, path);
    if (gotId !== id)
      throw new DecodeError(`${path}.id`, `the deleted profile ${id}`, gotId);
    return {
      ok: true,
      deleted: true,
      id: gotId,
      revision: field(o, "revision", readString, path),
      persisted: field(o, "persisted", readBoolean, path),
      cluster: field(o, "cluster", decodeIdPPublication, path),
    };
  };
  return apiRequest(
    `/api/idp/${encodeURIComponent(id)}?revision=${encodeURIComponent(String(revision))}`,
    decoder,
    { method: "DELETE", ...(signal !== undefined ? { signal } : {}) },
  );
}

// ── The LDAP directory test (bounded, transient credential) ────────────────

/** ui_auth_ldap.go: dial 5 s + whole-test watchdog 45 s ⇒ the client waits
 * at least 60 s before declaring the outcome UNPROVEN. */
export const IDP_TEST_TIMEOUT_MS = 60_000;
export const IDP_TEST_STEPS = [
  "reachable",
  "tls",
  "service_bind",
  "base_dn",
  "user_lookup",
  "user_auth",
] as const;
export type IdPTestStepName = (typeof IDP_TEST_STEPS)[number];
/** ldapTestErrText — the ONLY error classes the browser renders. */
export const IDP_TEST_STEP_ERRORS = [
  "timeout",
  "tls_failed",
  "unreachable",
  "invalid_credentials",
  "no_such_object",
  "insufficient_access",
  "directory_error",
] as const;
export type IdPTestStepError = (typeof IDP_TEST_STEP_ERRORS)[number];

export interface IdPTestStep {
  name: IdPTestStepName;
  ok: boolean;
  skipped: boolean;
  durationMs?: number;
  error?: IdPTestStepError;
}
export interface IdPTestReport {
  ok: boolean;
  steps: readonly IdPTestStep[];
  identity?: { sub: string; groupCount: number };
}

const decodeTestStep: Decoder<IdPTestStep> = (v, path = "$") => {
  const o = readRecord(v, path);
  const durationMs = opt(o, "durationMs", readNumber, path);
  const error = opt(o, "error", readEnum(IDP_TEST_STEP_ERRORS), path);
  return {
    name: field(o, "name", readEnum(IDP_TEST_STEPS), path),
    ok: field(o, "ok", readBoolean, path),
    skipped: opt(o, "skipped", readBoolean, path) ?? false,
    ...(durationMs !== undefined ? { durationMs } : {}),
    ...(error !== undefined ? { error } : {}),
    // `label`, `detail`, `action` are server prose: dropped at the boundary.
  };
};

const decodeTestReport: Decoder<IdPTestReport> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseSecretKeys(o, path);
  const identityRaw = o["identity"];
  let identity: { sub: string; groupCount: number } | undefined;
  if (identityRaw !== undefined && identityRaw !== null) {
    const i = readRecord(identityRaw, `${path}.identity`);
    identity = {
      sub: field(i, "sub", readString, `${path}.identity`),
      groupCount: field(i, "groupCount", readNumber, `${path}.identity`),
    };
  }
  return {
    ok: field(o, "ok", readBoolean, path),
    steps: field(o, "steps", readArray(decodeTestStep), path),
    ...(identity !== undefined ? { identity } : {}),
  };
};

/** POST /api/idp/test — a 200 with ok:false is a FAILED test; nothing is
 * persisted; the test credential rides the body once and is never stored. */
export function testIdP(
  profile: IdPWriteSpec & { id?: string },
  cred: { username?: string; password?: string },
  signal?: AbortSignal,
): Promise<IdPTestReport> {
  const body: Record<string, unknown> = {
    profile: {
      ...idpWriteBody(profile),
      ...(profile.id !== undefined ? { id: profile.id } : {}),
    },
  };
  if (cred.username !== undefined && cred.username !== "") {
    body["testUsername"] = cred.username;
    if (cred.password !== undefined) body["testPassword"] = cred.password;
  }
  return apiRequest("/api/idp/test", decodeTestReport, {
    method: "POST",
    body,
    timeoutMs: IDP_TEST_TIMEOUT_MS,
    ...(signal !== undefined ? { signal } : {}),
  });
}

// ── OIDC discovery (nothing persisted) ─────────────────────────────────────

export interface OIDCDiscovery {
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  introspectionEndpoint?: string;
  userinfoEndpoint?: string;
  jwksUri?: string;
}

const DISCOVERY_KEYS: ReadonlyArray<readonly [string, keyof OIDCDiscovery]> = [
  ["authorization_endpoint", "authorizationEndpoint"],
  ["token_endpoint", "tokenEndpoint"],
  ["introspection_endpoint", "introspectionEndpoint"],
  ["userinfo_endpoint", "userinfoEndpoint"],
  ["jwks_uri", "jwksUri"],
];

const decodeDiscovery: Decoder<OIDCDiscovery> = (v, path = "$") => {
  const o = readRecord(v, path);
  const out: OIDCDiscovery = {};
  for (const [wire, key] of DISCOVERY_KEYS) {
    const raw = o[wire];
    // Only an https URL is usable as an endpoint; everything else — including
    // any prose the document carries — is dropped at the boundary.
    if (typeof raw === "string" && /^https:\/\/[^\s"'<>]{1,2048}$/.test(raw))
      out[key] = raw;
  }
  return out;
};

export function discoverOIDC(
  issuer: string,
  signal?: AbortSignal,
): Promise<OIDCDiscovery> {
  return apiRequest("/api/idp/discover", decodeDiscovery, {
    method: "POST",
    body: { issuer },
    ...(signal !== undefined ? { signal } : {}),
  });
}

// ── Legacy import + registry repair ────────────────────────────────────────

/** POST /api/idp/legacy-ldap/import — bodiless; the appliance copies the
 * legacy block (bind credential included, server-side) into a DISABLED
 * managed profile. Bound: type ldap, enabled false. */
export function importLegacyLDAP(signal?: AbortSignal): Promise<IdPProfile> {
  const decoder: Decoder<IdPProfile> = (v, path = "$") => {
    const p = decodeIdPProfile(v, path);
    if (p.type !== "ldap")
      throw new DecodeError(`${path}.type`, "ldap", p.type);
    if (p.enabled)
      throw new DecodeError(
        `${path}.enabled`,
        "false (an import is created disabled)",
        true,
      );
    return p;
  };
  return apiRequest("/api/idp/legacy-ldap/import", decoder, {
    method: "POST",
    ...(signal !== undefined ? { signal } : {}),
  });
}

export interface IdPRepairResult {
  ok: true;
  repaired: true;
  /** the confirmed quarantine evidence (base name) */
  evidence: string;
  revision: string;
}

/** POST /api/idp/repair {confirm} — confirm = the quarantine evidence. */
export function repairIdPRegistry(
  confirm: string,
  signal?: AbortSignal,
): Promise<IdPRepairResult> {
  const decoder: Decoder<IdPRepairResult> = (v, path = "$") => {
    const o = readRecord(v, path);
    if (field(o, "ok", readBoolean, path) !== true)
      throw new DecodeError(`${path}.ok`, "true", o["ok"]);
    if (field(o, "repaired", readBoolean, path) !== true)
      throw new DecodeError(`${path}.repaired`, "true", o["repaired"]);
    const evidence = field(o, "evidence", readString, path);
    if (evidence !== confirm)
      throw new DecodeError(
        `${path}.evidence`,
        "the confirmed evidence",
        evidence,
      );
    return {
      ok: true,
      repaired: true,
      evidence,
      revision: field(o, "revision", readString, path),
    };
  };
  return apiRequest("/api/idp/repair", decoder, {
    method: "POST",
    body: { confirm },
    ...(signal !== undefined ? { signal } : {}),
  });
}

// ── Typed refusals (the mutation family) ───────────────────────────────────

export const IDP_COMPILE_REASONS = [
  "oidc_discovery",
  "saml_metadata",
  "ldap_provider",
  "unsupported",
] as const;
export type IdPCompileReason = (typeof IDP_COMPILE_REASONS)[number];
export const IDP_OUTCOME_UNKNOWN_DETAILS = [
  "registry_persisted_sentinel_not_durable",
  "operation_record_not_durable",
] as const;
export type IdPOutcomeUnknownDetail =
  (typeof IDP_OUTCOME_UNKNOWN_DETAILS)[number];

export interface IdPReference {
  consumerType: string;
  id: string;
  name: string;
  detail: string;
  view: string;
}

export interface IdPRefusalFacts {
  revision?: number;
  documentRevision?: string;
  reason?: IdPCompileReason;
  references?: readonly IdPReference[];
  confirmValue?: string;
  operationId?: string;
  state?: IdPOperationState;
  code?: string;
  detail?: IdPOutcomeUnknownDetail;
  id?: string;
}

type IdPFact = keyof IdPRefusalFacts;

/** code → contracted status + the facts that MUST be present for the
 * refusal to count as a verdict (ui_auth.go writeIdPRefusal / the gates). */
export const IDP_REFUSAL_CONTRACT = {
  invalid_input: { status: 400, required: [] },
  forbidden: { status: 403, required: [] },
  not_found: { status: 404, required: [] },
  vanished: { status: 404, required: [] },
  stale: { status: 409, required: ["fence"] },
  precondition_required: { status: 428, required: ["fence"] },
  persistence_not_configured: { status: 503, required: [] },
  provider_compile_failed: { status: 502, required: ["reason"] },
  operation_id_required: { status: 428, required: [] },
  cutover_confirm_required: { status: 428, required: ["confirmValue"] },
  operation_mismatch: { status: 409, required: ["operationId", "state"] },
  operation_in_progress: { status: 409, required: ["operationId", "state"] },
  operation_aborted: { status: 409, required: ["operationId", "state"] },
  operation_outcome_unknown: {
    status: 409,
    required: ["operationId", "state"],
  },
  operation_ledger_degraded: { status: 503, required: [] },
  operation_ledger_full: { status: 503, required: [] },
  operation_unsettled: { status: 503, required: [] },
  persist_failed: { status: 500, required: [] },
  outcome_unknown: { status: 500, required: ["detail"] },
  referenced: { status: 409, required: ["references"] },
  confirm_mismatch: { status: 409, required: ["confirmValue"] },
  not_degraded: { status: 409, required: [] },
  repair_unavailable: { status: 409, required: [] },
  registry_degraded: { status: 503, required: [] },
  upstream_error: { status: 502, required: [] },
  method_not_allowed: { status: 405, required: [] },
} as const satisfies Readonly<
  Record<string, { status: number; required: readonly (IdPFact | "fence")[] }>
>;

export type IdPRefusalCode = keyof typeof IDP_REFUSAL_CONTRACT;
export const IDP_REFUSAL_CODES: readonly IdPRefusalCode[] =
  Object.keys(IDP_REFUSAL_CONTRACT).filter(isRefusalCode);

export interface IdPRefusal {
  status: number;
  code: IdPRefusalCode;
  /** the ONLY things allowed into the DOM */
  facts: IdPRefusalFacts;
}

function isRefusalCode(c: string): c is IdPRefusalCode {
  return Object.prototype.hasOwnProperty.call(IDP_REFUSAL_CONTRACT, c);
}

function safeNumber(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : undefined;
}
function safeString(v: unknown, re: RegExp): string | undefined {
  return typeof v === "string" && re.test(v) ? v : undefined;
}
function safeEnum<T extends string>(
  v: unknown,
  allowed: readonly T[],
): T | undefined {
  return allowed.find((a) => a === v);
}
function safeReferences(v: unknown): readonly IdPReference[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: IdPReference[] = [];
  for (const el of v) {
    if (!isRecord(el)) return undefined;
    const consumerType = el["consumerType"];
    const id = el["id"];
    const name = el["name"];
    if (
      typeof consumerType !== "string" ||
      typeof id !== "string" ||
      typeof name !== "string"
    )
      return undefined;
    if (
      !SAFE_TOKEN.test(consumerType) ||
      !SAFE_ID.test(id) ||
      name.length > 200
    )
      return undefined;
    const detail =
      typeof el["detail"] === "string" ? el["detail"].slice(0, 120) : "";
    const view = safeString(el["view"], SAFE_TOKEN) ?? "";
    out.push({ consumerType, id, name, detail, view });
  }
  return out;
}

function refusalFacts(cur: Record<string, unknown>): IdPRefusalFacts {
  const f: IdPRefusalFacts = {};
  const revision = safeNumber(cur["revision"]);
  if (revision !== undefined) f.revision = revision;
  const documentRevision = safeString(cur["documentRevision"], SAFE_TOKEN);
  if (documentRevision !== undefined) f.documentRevision = documentRevision;
  const reason = safeEnum(cur["reason"], IDP_COMPILE_REASONS);
  if (reason !== undefined) f.reason = reason;
  const references = safeReferences(cur["references"]);
  if (references !== undefined) f.references = references;
  const confirmValue =
    safeString(cur["confirmValue"], QUARANTINE_RE) ??
    safeString(cur["confirmValue"], LDAP_URL_RE);
  if (confirmValue !== undefined) f.confirmValue = confirmValue;
  const operationId = safeString(cur["operationId"], UUID_RE);
  if (operationId !== undefined) f.operationId = operationId;
  const state = safeEnum(cur["state"], IDP_OPERATION_STATES);
  if (state !== undefined) f.state = state;
  const code =
    typeof cur["code"] === "string" && IDP_OPERATION_CODES.includes(cur["code"])
      ? cur["code"]
      : undefined;
  if (code !== undefined) f.code = code;
  const detail = safeEnum(cur["detail"], IDP_OUTCOME_UNKNOWN_DETAILS);
  if (detail !== undefined) f.detail = detail;
  const id = safeString(cur["id"], SAFE_ID);
  if (id !== undefined) f.id = id;
  return f;
}

function parsedBody(err: ApiError): Record<string, unknown> | null {
  if (err.bodyText === undefined) return null;
  try {
    const v: unknown = JSON.parse(err.bodyText);
    return isRecord(v) ? v : null;
  } catch {
    return null;
  }
}

/** A refusal is a VERDICT only when the code is contracted, the status is
 * exactly the contracted one and every required typed fact is present and
 * well-formed; otherwise null (⇒ UNPROVEN). The server's `error` line and
 * the raw `current` object never leave this function. */
export function asIdPRefusal(err: unknown): IdPRefusal | null {
  if (
    !(err instanceof ApiError) ||
    err.kind !== "http" ||
    err.status === undefined
  )
    return null;
  const body = parsedBody(err);
  if (body === null) return null;
  const code = body["code"];
  if (typeof code !== "string" || !isRefusalCode(code)) return null;
  const contract = IDP_REFUSAL_CONTRACT[code];
  if (contract.status !== err.status) return null;
  const cur = isRecord(body["current"]) ? body["current"] : {};
  const facts = refusalFacts(cur);
  for (const req of contract.required) {
    if (req === "fence") {
      if (facts.revision === undefined && facts.documentRevision === undefined)
        return null;
    } else if (facts[req] === undefined) {
      return null;
    }
  }
  return { status: err.status, code, facts };
}

/** True when the write MAY be durably applied but no trustworthy verdict
 * exists — transport loss, timeout, abort, wrong media type, a 2xx that
 * failed action binding, or a non-2xx outside the contract. 401 belongs to
 * the auth boundary; 403 was refused before anything was touched. */
export function idpUnproven(err: unknown): boolean {
  if (!(err instanceof ApiError)) return true;
  switch (err.kind) {
    case "target":
      return false;
    case "network":
    case "timeout":
    case "aborted":
    case "contenttype":
    case "decode":
    case "toolarge":
      return true;
    case "http":
      if (err.status === 401 || err.status === 403) return false;
      return asIdPRefusal(err) === null;
  }
}
