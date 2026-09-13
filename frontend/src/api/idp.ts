// FE-6A.1 — Identity Providers READ client: fail-closed runtime decoders
// over the frozen FE-6A.0 read models (ui_auth.go idpListReadModel /
// publicIdPProfile / idpClusterReadModel, idp_operations.go lookupReadModel
// / readModel, ui_auth_ldap.go apiIdPLegacyLDAP) and the where-used walk
// (policy_refs.go, type `idp`). READ ONLY: this module carries no create,
// update, delete, repair, test, import or credential call — the slice
// exposes none, and a read surface must not be able to reach one by accident.
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
import { apiRequest } from "./client";
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

export const IDP_OPERATION_ACTIONS = ["idp.create"] as const;
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
}

export interface IdPSAMLFacts {
  metadataUrl: string;
  /** derived write-only indicator for the inline metadata upload */
  inlineMetadataConfigured: boolean;
}

export interface IdPLDAPFacts {
  url: string;
  bindDn: string;
  /** derived write-only-secret indicator — never the value */
  bindCredentialConfigured: boolean;
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

/** A present legacy block always states its identity and its indicator. */
export type LegacyLDAP = LegacyLDAPBase &
  (
    | { present: false }
    | {
        present: true;
        /** the legacy block is the live proxy-auth backend */
        active: boolean;
        /** retired OR an enabled registry LDAP profile exists */
        shadowed: boolean;
        url: string;
        baseDn: string;
        bindDn: string;
        /** derived write-only-secret indicator — never the value */
        bindCredentialConfigured: boolean;
      }
  );

// ── Decoders ───────────────────────────────────────────────────────────────

const decodeOIDCFacts: Decoder<IdPOIDCFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    issuer: opt(o, "issuer", readString, path) ?? "",
    clientId: opt(o, "clientId", readString, path) ?? "",
    // Go omitempty: absent ⇒ false (declared on IdPOIDCRead).
    clientSecretConfigured:
      opt(o, "clientSecretConfigured", readBoolean, path) ?? false,
  };
};

const decodeSAMLFacts: Decoder<IdPSAMLFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    metadataUrl: opt(o, "metadataUrl", readString, path) ?? "",
    inlineMetadataConfigured:
      opt(o, "inlineMetadataConfigured", readBoolean, path) ?? false,
  };
};

const decodeLDAPFacts: Decoder<IdPLDAPFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    url: opt(o, "url", readString, path) ?? "",
    bindDn: opt(o, "bindDn", readString, path) ?? "",
    bindCredentialConfigured:
      opt(o, "bindCredentialConfigured", readBoolean, path) ?? false,
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
      rawProfiles === undefined || rawProfiles === null
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
  if (!present) return { ...base, present: false };
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
