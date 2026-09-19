// FE-6B.1 — Certificates & CA READ client: fail-closed runtime decoders over
// the frozen FE-6B.0 read models (ui_certificates.go apiCertificates /
// apiCAStatus / apiOCSPConfig / apiCACert / apiCAOperations,
// certificate_operations.go lookupReadModel / readModel, ui_config.go
// apiNetworkSettings) — the contract in api/openapi/openapi.yaml
// (CertificateInventory, CAStatus, OCSPStatus, CertOperation, UICertRead,
// NetworkSettings, CertRefusal). READ ONLY by directive: no mutation of any
// certificate object is issued from here (FE-6B.2).
//
// Rules this module enforces at the API boundary, so a page can only ever
// render what the appliance stated:
//   • every fact the wire ALWAYS carries is REQUIRED (missing evidence is
//     never negative truth); every bounded word (scope, pair state, CA
//     usability class, fault class, mTLS reason, OCSP source, ledger
//     degradation reason, audit sink, coverage path, operation state /
//     action / target / code) is decoded against the AUTHORITATIVE closed
//     set and REFUSED when unknown — a dependency's text never rides a
//     "class" field into the DOM;
//   • key material never decodes: a response carrying a secret-bearing key
//     at ANY depth (privateKey, key, pem, passphrase, password, secret,
//     bundle, …) is a DECODE FAILURE, never rendered, never cached; the raw
//     `ui_tls_fallback_reason` line and the ledger's free-text detail are
//     not part of the decoded models at all;
//   • contradictory states are refused whole: present ⇔ pairState complete,
//     the revision token matches its evidence class, usable ⇔ no
//     unusableClass, loadFailed ⇔ loadFailureClass, ready ⇔ a car1:<hex>
//     revision + identity, dualCAActive ⇔ secondaryCA, OCSP `enabled` ⇔
//     runtime.enabled, a record's target belongs to its action,
//     supersededBy rides ONLY the superseded code;
//   • the operation record is a DISCRIMINATED UNION (pending / committed +
//     owed audit / aborted / outcome_unknown) and its POSTURE is a pure
//     function: writer_evidence_superseded is TERMINAL UNKNOWN — the node
//     never learns whether the intent had committed and never guesses — and
//     is never presented as success, failure, cancellation or a safe retry.
import { ApiError, apiDownloadRequest, apiRequest } from "./client";
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

// ── Vocabularies (server contract; mirrored from the Go constants) ─────────

export const CERT_SCOPE = ["node-local"] as const;

/** caUnusableClass (ca_health.go) — why the live CA cannot sign. */
export const CA_UNUSABLE_CLASSES = [
  "expired",
  "not_yet_valid",
  "no_ca",
] as const;
export type CAUnusableClass = (typeof CA_UNUSABLE_CLASSES)[number];

/** CAFaultClass — the bounded class published in place of a path or text. */
export const CA_FAULT_CLASSES = [
  "permission_denied",
  "not_found",
  "read_only",
  "no_space",
  "not_a_file",
  "io_error",
  "write_failed",
  "decrypt_failed",
  "bundle_malformed",
  "load_failed",
  "init_failed",
  "expired",
] as const;
export type CAFaultClass = (typeof CA_FAULT_CLASSES)[number];

/** uiPairEvidenceNow (ui_tls_custom.go) — the pair's evidence class. */
export const UI_PAIR_STATES = [
  "complete",
  "absent",
  "incomplete",
  "unavailable",
] as const;
export type UIPairState = (typeof UI_PAIR_STATES)[number];

export const MTLS_REASONS = [
  "cert_file_missing",
  "key_file_missing",
  "load_failed",
] as const;
export type MTLSReason = (typeof MTLS_REASONS)[number];

export const OCSP_SOURCES = ["default", "yaml", "admin"] as const;
export type OCSPSource = (typeof OCSP_SOURCES)[number];

export const LEDGER_DEGRADED_REASONS = ["corrupt", "unreadable"] as const;
export type LedgerDegradedReason = (typeof LEDGER_DEGRADED_REASONS)[number];

export const AUDIT_SINKS = ["memory", "file"] as const;
export type AuditSink = (typeof AUDIT_SINKS)[number];

/** ocsp_coverage.go — which TLS-handshake paths consult the checker. */
export const OCSP_COVERAGE_PATHS = [
  "upstream_transport",
  "ssl_inspect_origin",
  "connect_bypass",
] as const;
export type OCSPCoveragePath = (typeof OCSP_COVERAGE_PATHS)[number];

export const CERT_OPERATION_STATES = [
  "pending",
  "committed",
  "aborted",
  "outcome_unknown",
] as const;
export type CertOperationState = (typeof CERT_OPERATION_STATES)[number];

export const CERT_OPERATION_ACTIONS = [
  "ca.rotate",
  "ca.import",
  "cert.ui.replace",
  "cert.ui.delete",
  "ocsp.set",
] as const;
export type CertOperationAction = (typeof CERT_OPERATION_ACTIONS)[number];

export const CERT_OPERATION_TARGETS = ["root_ca", "ui_cert", "ocsp"] as const;
export type CertOperationTarget = (typeof CERT_OPERATION_TARGETS)[number];

/** The target each action writes (certificate_operations.go). */
const ACTION_TARGET: Record<CertOperationAction, CertOperationTarget> = {
  "ca.rotate": "root_ca",
  "ca.import": "root_ca",
  "cert.ui.replace": "ui_cert",
  "cert.ui.delete": "ui_cert",
  "ocsp.set": "ocsp",
};

/** settleCertOperation `<why>_<verdict>`: why ∈ lookup (the GET), reconciled
 * (boot, or a recovered CA load), writer (a later writer of the object). */
export const CERT_SETTLEMENT_WHY = ["lookup", "reconciled", "writer"] as const;

/** The RECOVERABLE outcome_unknown suffixes — re-decided by every later
 * settlement (certOperation.recoverable). */
export const CERT_RECOVERABLE_SUFFIXES = [
  "evidence_unavailable",
  "evidence_invalid",
  "durability_unproven",
  "cleanup_incomplete",
] as const;

/** The terminal, never re-decided record of an intent whose invalid
 * evidence a repairing writer replaced (round 4, B1). */
export const CERT_SUPERSEDED_CODE = "writer_evidence_superseded";

const COMMITTED_CODES: readonly string[] = CERT_SETTLEMENT_WHY.map(
  (w) => `${w}_committed`,
);
/** certAbort records persist_failed; a settlement records <why>_absent. */
const ABORTED_CODES: readonly string[] = [
  "persist_failed",
  ...CERT_SETTLEMENT_WHY.map((w) => `${w}_absent`),
];
const UNKNOWN_RECOVERABLE_CODES: readonly string[] =
  CERT_SETTLEMENT_WHY.flatMap((w) =>
    CERT_RECOVERABLE_SUFFIXES.map((s) => `${w}_${s}`),
  );
const UNKNOWN_UNPROVEN_CODES: readonly string[] = CERT_SETTLEMENT_WHY.map(
  (w) => `${w}_unproven`,
);
const UNKNOWN_CODES: readonly string[] = [
  ...UNKNOWN_RECOVERABLE_CODES,
  ...UNKNOWN_UNPROVEN_CODES,
  CERT_SUPERSEDED_CODE,
];

/** What GET /api/ca/operations/{id} itself answers as a typed refusal
 * (apiCAOperations: requireRoleJSON, validIdPOperationID, certLedger,
 * certMethodRefusal). Anything else is not a verdict this surface may name. */
export const CERT_LOOKUP_REFUSAL_CODES = [
  "invalid_input",
  "forbidden",
  "not_found",
  "method_not_allowed",
  "operation_ledger_degraded",
] as const;
export type CertLookupRefusalCode = (typeof CERT_LOOKUP_REFUSAL_CODES)[number];

// ── Secret sweep ─────────────────────────────────────────────────────────────

/** Keys that name private-key material, passphrases or raw certificate
 * input. Matched EXACTLY (case-sensitive) at every depth — the derived
 * public keys (`keyProvider`, `fingerprint`, `encryptedAtRest`) are distinct
 * and never match. */
export const CERT_SECRET_KEYS: readonly string[] = [
  "privateKey",
  "private_key",
  "key",
  "keyPem",
  "key_pem",
  "certPem",
  "cert_pem",
  "pem",
  "passphrase",
  "password",
  "secret",
  "bundle",
  "ciphertext",
  "sealed",
];

export function refuseCertSecretKeys(v: unknown, path: string): void {
  if (Array.isArray(v)) {
    v.forEach((el, i) => {
      refuseCertSecretKeys(el, `${path}[${String(i)}]`);
    });
    return;
  }
  if (!isRecord(v)) return;
  for (const k of Object.keys(v)) {
    if (CERT_SECRET_KEYS.includes(k)) {
      throw new DecodeError(
        `${path}.${k}`,
        "no key material (never reaches the browser)",
        "[redacted]",
      );
    }
    refuseCertSecretKeys(v[k], `${path}.${k}`);
  }
}

// ── Small helpers ───────────────────────────────────────────────────────────

function opt<T>(
  o: Record<string, unknown>,
  key: string,
  read: Decoder<T>,
  path: string,
): T | undefined {
  return readOptional(read)(o[key], `${path}.${key}`);
}

function forbid(
  o: Record<string, unknown>,
  key: string,
  path: string,
  because: string,
): void {
  if (key in o && o[key] !== undefined && o[key] !== null) {
    throw new DecodeError(`${path}.${key}`, `absent (${because})`, "[present]");
  }
}

function contradiction(path: string, what: string): never {
  throw new DecodeError(
    path,
    `a consistent record (${what})`,
    "[contradiction]",
  );
}

const HEX64 = /^[0-9a-f]{64}$/;
const CA_REVISION = /^car1:([0-9a-f]{64}|none)$/;
const UI_REVISION = /^uic1:([0-9a-f]{64}|none|incomplete|unavailable)$/;
const OCSP_REVISION = /^ocr1:[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function readToken(re: RegExp, what: string): Decoder<string> {
  return (v, path = "$") => {
    const s = readString(v, path);
    if (!re.test(s)) throw new DecodeError(path, what, s);
    return s;
  };
}

const readCARevision = readToken(CA_REVISION, "car1:<64 hex>|car1:none");
const readUIRevision = readToken(
  UI_REVISION,
  "uic1:<64 hex>|uic1:none|uic1:incomplete|uic1:unavailable",
);
const readOCSPRevision = readToken(OCSP_REVISION, "ocr1:<64 hex>");
const readHex64 = readToken(HEX64, "64 hex digits");

// ── Models ───────────────────────────────────────────────────────────────────

export interface CAFacts {
  present: boolean;
  revision: string;
  keyProvider: string;
  dualCAActive: boolean;
  persistenceConfigured: boolean;
  encryptedAtRest: boolean;
  subject?: string;
  issuer?: string;
  notBefore?: string;
  notAfter?: string;
  fingerprint?: string;
  usable: boolean;
  unusableClass?: CAUnusableClass;
  persistDegraded: boolean;
  persistClass?: CAFaultClass;
  loadFailed: boolean;
  loadFailureClass?: CAFaultClass;
}

export interface UICertFacts {
  present: boolean;
  pairState: UIPairState;
  revision: string;
  /** the RUNNING listener loaded a pair at boot — the server's claim */
  active: boolean;
  /** the persisted pair did not parse as a matching pair */
  corrupt: boolean;
  fingerprint?: string;
  subject?: string;
  notAfter?: string;
}

export interface MTLSClientCertFacts {
  configured: boolean;
  loaded: boolean;
  reason?: MTLSReason;
  notAfter?: string;
  daysRemaining?: number;
}

export interface OCSPDesired {
  enabled: boolean;
  source: OCSPSource;
}

export interface OCSPPosture {
  revision: string;
  desired: OCSPDesired;
  runtime: { enabled: boolean };
  durable: boolean;
}

export interface LedgerFacts {
  degraded: boolean;
  degradedReason?: LedgerDegradedReason;
  retained: number;
  unresolved: number;
  capacity: number;
  auditSink: AuditSink;
}

export interface BackupFacts {
  caBundleArchived: true;
  caBundleEncrypted: boolean;
  uiCertArchived: false;
  operationsArchived: false;
  configVersionRollback: false;
}

/** FE-6B.1 correction round (B1) — the admin listener's ACTIVATION EVIDENCE,
 * recorded by the appliance from the listener's own successful bind, never
 * from a boot-time selection flag. `state` unknown = no bind observed (or the
 * listener is rebinding): activation that has not been observed is UNKNOWN,
 * never claimed. `servedCertificate` is the served leaf's public identity,
 * present iff the posture is a TLS posture; its fingerprint is in the
 * inventory format so it is comparable with the PERSISTED pair's — two
 * different facts. `servesPersistedPair` is derived at read time (tls_custom
 * AND a complete valid persisted pair AND equal fingerprints) and is the
 * meaning of the legacy `uiCert.active` / `ui_custom_cert_active`. */
export const LISTENER_STATES = ["serving", "unknown"] as const;
export type ListenerState = (typeof LISTENER_STATES)[number];
export const LISTENER_POSTURES = [
  "tls_custom",
  "tls_configured",
  "tls_self_signed",
  "plain_http",
  "unknown",
] as const;
export type ListenerPosture = (typeof LISTENER_POSTURES)[number];
const TLS_POSTURES: readonly ListenerPosture[] = [
  "tls_custom",
  "tls_configured",
  "tls_self_signed",
];

export interface ServedCertificate {
  /** upper-case colon-separated SHA-256 (UICertFacts.fingerprint format) */
  fingerprint: string;
  subject: string;
  notBefore: string;
  notAfter: string;
}

export interface AdminListener {
  state: ListenerState;
  posture: ListenerPosture;
  servedCertificate?: ServedCertificate;
  servesPersistedPair: boolean;
}

export interface CertificateInventory {
  scope: "node-local";
  ca: CAFacts;
  uiCert: UICertFacts;
  /** the listener's own evidence — the ONLY source of an activation claim */
  listener: AdminListener;
  mtlsClientCert: MTLSClientCertFacts;
  ocsp: OCSPPosture;
  operations: LedgerFacts;
  backup: BackupFacts;
}

export interface SecondaryCAFacts {
  subject?: string;
  notAfter?: string;
  overlapEnd?: string;
  expiresIn?: string;
}

export interface CAStatus {
  ready: boolean;
  revision: string;
  scope: "node-local";
  subject?: string;
  issuer?: string;
  notBefore?: string;
  notAfter?: string;
  fingerprint?: string;
  expiresIn?: string;
  cacheSize: number;
  cacheMax: number;
  cacheTTL: string;
  leafValidity: string;
  autoRotation: boolean;
  rotationOverlapDays: number;
  keyProvider: string;
  persistenceConfigured: boolean;
  usable: boolean;
  unusableClass?: CAUnusableClass;
  inspectBlocked: number;
  signRefused: number;
  rotationPersistFailures: number;
  rotationPersistDegraded: boolean;
  rotationPersistClass?: CAFaultClass;
  loadFailed: boolean;
  loadFailureClass?: CAFaultClass;
  inspectBypassed: number;
  loadRecoveryAttempts: number;
  loadRecoveryGaveUp: boolean;
  loadRecoveryClass?: CAFaultClass;
  dualCAActive: boolean;
  secondaryCA?: SecondaryCAFacts;
}

export interface OCSPCoverageRow {
  path: OCSPCoveragePath;
  checked: boolean;
}

export interface OCSPStatus {
  enabled: boolean;
  revision: string;
  scope: "node-local";
  desired: OCSPDesired;
  runtime: { enabled: boolean };
  durable: boolean;
  cacheLen: number;
  failClosedTotal: number;
  revokedTotal: number;
  /** RFC 3339, or "" when it never happened */
  lastFailClosedAt: string;
  mtlsClientCertConfigured: boolean;
  mtlsClientCertLoaded?: boolean;
  mtlsClientCertReason?: MTLSReason;
  mtlsClientCertNotAfter?: string;
  mtlsClientCertDaysRemaining?: number;
  coverage: readonly OCSPCoverageRow[];
  uncheckedEnforcingPaths: readonly OCSPCoveragePath[];
  notForCertificateTotal?: number;
  unauthorizedResponderTotal?: number;
  malformedResponseTotal?: number;
  staleResponseTotal?: number;
  unknownStatusTotal?: number;
  responderBlockedTotal?: number;
  respondersTruncatedTotal?: number;
}

/** The bounded LISTENER facts GET /api/settings/network contributes. The raw
 * `ui_tls_fallback_reason` line is deliberately NOT decoded. */
export interface ListenerFacts {
  tlsFallback: boolean;
  customCertUploaded: boolean;
  customCertActive: boolean;
  customCertCorrupt: boolean;
  /** the same evidence object the inventory carries (`ui_listener`) */
  listener: AdminListener;
}

interface CertOperationBase {
  operationId: string;
  action: CertOperationAction;
  actor: string;
  target: CertOperationTarget;
  fence: string;
  startedAt: string;
  /** hex SHA-256 of the certificate the operation installs; absent on a UI
   * delete and an OCSP set */
  candidateFingerprint?: string;
}

/** The discriminated union the ledger record actually takes. */
export type CertOperation = CertOperationBase &
  (
    | { state: "pending"; audited: false }
    | {
        state: "committed";
        audited: true;
        /** never present on an audited commit (the union's discriminant
         * partner of `audited`) */
        auditState?: undefined;
        finishedAt: string;
        committedRevision: string;
        /** a settlement verdict, when the commit was settled rather than direct */
        code?: string;
        result?: Record<string, unknown>;
      }
    | {
        state: "committed";
        audited: false;
        /** the durable success audit is still owed (recoverable) */
        auditState: "pending";
        finishedAt: string;
        committedRevision: string;
        code?: string;
        result?: Record<string, unknown>;
      }
    | { state: "aborted"; audited: false; finishedAt: string; code: string }
    | {
        state: "outcome_unknown";
        audited: false;
        finishedAt: string;
        code: string;
        /** writer_evidence_superseded only: the writer's identity */
        supersededBy?: string;
      }
  );

// ── Decoders ─────────────────────────────────────────────────────────────────

const readScope = readEnum(CERT_SCOPE);

function decodeCAFacts(v: unknown, path: string): CAFacts {
  const o = readRecord(v, path);
  const out: CAFacts = {
    present: field(o, "present", readBoolean, path),
    revision: field(o, "revision", readCARevision, path),
    keyProvider: field(o, "keyProvider", readString, path),
    dualCAActive: field(o, "dualCAActive", readBoolean, path),
    persistenceConfigured: field(o, "persistenceConfigured", readBoolean, path),
    encryptedAtRest: field(o, "encryptedAtRest", readBoolean, path),
    usable: field(o, "usable", readBoolean, path),
    persistDegraded: field(o, "persistDegraded", readBoolean, path),
    loadFailed: field(o, "loadFailed", readBoolean, path),
  };
  const identity = readIdentity(o, path, out.present);
  Object.assign(out, identity);
  applyUsability(out, o, path);
  applyLoadPosture(out, o, path, "loadFailureClass");
  const persistClass = opt(o, "persistClass", readEnum(CA_FAULT_CLASSES), path);
  if (persistClass !== undefined) {
    if (!out.persistDegraded)
      contradiction(
        `${path}.persistClass`,
        "a class on a non-degraded persistence",
      );
    out.persistClass = persistClass;
  }
  return out;
}

/** The CA's public identity: REQUIRED when present (CACertInfo emits every
 * field once the manager is ready), FORBIDDEN when not. */
function readIdentity(
  o: Record<string, unknown>,
  path: string,
  present: boolean,
): Pick<
  CAFacts,
  "subject" | "issuer" | "notBefore" | "notAfter" | "fingerprint"
> {
  const keys = [
    "subject",
    "issuer",
    "notBefore",
    "notAfter",
    "fingerprint",
  ] as const;
  if (!present) {
    for (const k of keys) forbid(o, k, path, "no CA is installed");
    if (o["revision"] !== "car1:none")
      contradiction(`${path}.revision`, "no CA yet a revision that names one");
    return {};
  }
  if (o["revision"] === "car1:none")
    contradiction(
      `${path}.revision`,
      "a CA is present yet the revision is car1:none",
    );
  return {
    subject: field(o, "subject", readString, path),
    issuer: field(o, "issuer", readString, path),
    notBefore: field(o, "notBefore", readString, path),
    notAfter: field(o, "notAfter", readString, path),
    fingerprint: field(o, "fingerprint", readString, path),
  };
}

function applyUsability(
  out: { usable: boolean; unusableClass?: CAUnusableClass },
  o: Record<string, unknown>,
  path: string,
): void {
  const cls = opt(o, "unusableClass", readEnum(CA_UNUSABLE_CLASSES), path);
  if (out.usable && cls !== undefined)
    contradiction(
      `${path}.unusableClass`,
      "usable yet carrying an unusable class",
    );
  if (!out.usable && cls === undefined)
    contradiction(
      `${path}.unusableClass`,
      "unusable without its bounded class",
    );
  if (cls !== undefined) out.unusableClass = cls;
}

function applyLoadPosture(
  out: { loadFailed: boolean; loadFailureClass?: CAFaultClass },
  o: Record<string, unknown>,
  path: string,
  key: "loadFailureClass",
): void {
  const cls = opt(o, key, readEnum(CA_FAULT_CLASSES), path);
  if (out.loadFailed !== (cls !== undefined))
    contradiction(`${path}.${key}`, "loadFailed and its class disagree");
  if (cls !== undefined) out.loadFailureClass = cls;
}

export const decodeUICertFacts: Decoder<UICertFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  const pairState = field(o, "pairState", readEnum(UI_PAIR_STATES), path);
  const present = field(o, "present", readBoolean, path);
  if (present !== (pairState === "complete"))
    contradiction(`${path}.present`, "present must mean a complete pair");
  const revision = field(o, "revision", readUIRevision, path);
  const expected: Record<UIPairState, (r: string) => boolean> = {
    complete: (r) => HEX64.test(r.slice("uic1:".length)),
    absent: (r) => r === "uic1:none",
    incomplete: (r) => r === "uic1:incomplete",
    unavailable: (r) => r === "uic1:unavailable",
  };
  if (!expected[pairState](revision))
    contradiction(`${path}.revision`, `a ${pairState} pair's revision token`);
  const out: UICertFacts = {
    present,
    pairState,
    revision,
    active: field(o, "active", readBoolean, path),
    corrupt: field(o, "corrupt", readBoolean, path),
  };
  if (pairState !== "complete") {
    for (const k of ["fingerprint", "subject", "notAfter"])
      forbid(o, k, path, "the pair is not complete");
    return out;
  }
  const fp = opt(o, "fingerprint", readString, path);
  const subject = opt(o, "subject", readString, path);
  const notAfter = opt(o, "notAfter", readString, path);
  if (fp !== undefined) out.fingerprint = fp;
  if (subject !== undefined) out.subject = subject;
  if (notAfter !== undefined) out.notAfter = notAfter;
  return out;
};

function decodeMTLS(v: unknown, path: string): MTLSClientCertFacts {
  const o = readRecord(v, path);
  const out: MTLSClientCertFacts = {
    configured: field(o, "configured", readBoolean, path),
    loaded: field(o, "loaded", readBoolean, path),
  };
  if (out.loaded && !out.configured)
    contradiction(`${path}.loaded`, "loaded without being configured");
  const reason = opt(o, "reason", readEnum(MTLS_REASONS), path);
  if (reason !== undefined) {
    if (!out.configured || out.loaded)
      contradiction(
        `${path}.reason`,
        "a not-loaded reason on a loaded or unconfigured cert",
      );
    out.reason = reason;
  }
  const notAfter = opt(o, "notAfter", readString, path);
  const days = opt(o, "daysRemaining", readNumber, path);
  if ((notAfter !== undefined || days !== undefined) && !out.loaded)
    contradiction(
      `${path}.notAfter`,
      "expiry facts on a certificate that is not loaded",
    );
  if (notAfter !== undefined) out.notAfter = notAfter;
  if (days !== undefined) out.daysRemaining = days;
  return out;
}

function decodeDesired(v: unknown, path: string): OCSPDesired {
  const o = readRecord(v, path);
  return {
    enabled: field(o, "enabled", readBoolean, path),
    source: field(o, "source", readEnum(OCSP_SOURCES), path),
  };
}

function decodeRuntime(v: unknown, path: string): { enabled: boolean } {
  const o = readRecord(v, path);
  return { enabled: field(o, "enabled", readBoolean, path) };
}

function decodeOCSPPosture(v: unknown, path: string): OCSPPosture {
  const o = readRecord(v, path);
  return {
    revision: field(o, "revision", readOCSPRevision, path),
    desired: decodeDesired(o["desired"], `${path}.desired`),
    runtime: decodeRuntime(o["runtime"], `${path}.runtime`),
    durable: field(o, "durable", readBoolean, path),
  };
}

function decodeLedger(v: unknown, path: string): LedgerFacts {
  const o = readRecord(v, path);
  const out: LedgerFacts = {
    degraded: field(o, "degraded", readBoolean, path),
    retained: field(o, "retained", readNumber, path),
    unresolved: field(o, "unresolved", readNumber, path),
    capacity: field(o, "capacity", readNumber, path),
    auditSink: field(o, "auditSink", readEnum(AUDIT_SINKS), path),
  };
  const reason = opt(
    o,
    "degradedReason",
    readEnum(LEDGER_DEGRADED_REASONS),
    path,
  );
  if (out.degraded !== (reason !== undefined))
    contradiction(`${path}.degradedReason`, "degraded and its reason disagree");
  if (reason !== undefined) out.degradedReason = reason;
  if (out.retained > out.capacity || out.unresolved > out.retained)
    contradiction(`${path}.retained`, "counts exceed their bound");
  // degradedDetail is fixed operator text on the wire; it is deliberately
  // not part of the model (the page renders the bounded reason only).
  return out;
}

function readLiteral<T extends boolean>(want: T): Decoder<T> {
  return (v, path = "$") => {
    const b = readBoolean(v, path);
    if (b !== want) throw new DecodeError(path, String(want), b);
    return want;
  };
}

function decodeBackup(v: unknown, path: string): BackupFacts {
  const o = readRecord(v, path);
  return {
    caBundleArchived: field(o, "caBundleArchived", readLiteral(true), path),
    caBundleEncrypted: field(o, "caBundleEncrypted", readBoolean, path),
    uiCertArchived: field(o, "uiCertArchived", readLiteral(false), path),
    operationsArchived: field(
      o,
      "operationsArchived",
      readLiteral(false),
      path,
    ),
    configVersionRollback: field(
      o,
      "configVersionRollback",
      readLiteral(false),
      path,
    ),
  };
}

const COLON_FINGERPRINT = /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/;
const readColonFingerprint = readToken(
  COLON_FINGERPRINT,
  "SHA-256 as 32 upper-case colon-separated hex bytes",
);

function decodeServedCertificate(v: unknown, path = "$"): ServedCertificate {
  const o = readRecord(v, path);
  refuseCertSecretKeys(o, path);
  return {
    fingerprint: field(o, "fingerprint", readColonFingerprint, path),
    subject: field(o, "subject", readString, path),
    notBefore: field(o, "notBefore", readString, path),
    notAfter: field(o, "notAfter", readString, path),
  };
}

export const decodeAdminListener: Decoder<AdminListener> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseCertSecretKeys(o, path);
  const state = field(o, "state", readEnum(LISTENER_STATES), path);
  const posture = field(o, "posture", readEnum(LISTENER_POSTURES), path);
  if ((state === "unknown") !== (posture === "unknown"))
    contradiction(
      `${path}.posture`,
      "an unobserved listener has no posture; an observed one has one",
    );
  const served = opt(o, "servedCertificate", decodeServedCertificate, path);
  if (TLS_POSTURES.includes(posture) !== (served !== undefined))
    contradiction(
      `${path}.servedCertificate`,
      "a served identity exists exactly for a TLS posture",
    );
  const servesPersistedPair = field(
    o,
    "servesPersistedPair",
    readBoolean,
    path,
  );
  if (servesPersistedPair && posture !== "tls_custom")
    contradiction(
      `${path}.servesPersistedPair`,
      "only the persisted GUI pair can be the served persisted pair",
    );
  const out: AdminListener = { state, posture, servesPersistedPair };
  if (served !== undefined) out.servedCertificate = served;
  return out;
};

/** The derived activation fact: the listener is observed serving the exact
 * pair that is persisted right now (complete, valid, same fingerprint). */
function derivedServesPersisted(ui: UICertFacts, l: AdminListener): boolean {
  return (
    l.state === "serving" &&
    l.posture === "tls_custom" &&
    l.servedCertificate !== undefined &&
    ui.pairState === "complete" &&
    !ui.corrupt &&
    ui.fingerprint !== undefined &&
    ui.fingerprint === l.servedCertificate.fingerprint
  );
}

export const decodeCertificateInventory: Decoder<CertificateInventory> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  refuseCertSecretKeys(o, path);
  const uiCert = decodeUICertFacts(o["uiCert"], `${path}.uiCert`);
  const listener = decodeAdminListener(o["listener"], `${path}.listener`);
  const derived = derivedServesPersisted(uiCert, listener);
  if (listener.servesPersistedPair !== derived)
    contradiction(
      `${path}.listener.servesPersistedPair`,
      "servesPersistedPair must equal served == persisted (complete, valid, same fingerprint)",
    );
  if (uiCert.active !== derived)
    contradiction(
      `${path}.uiCert.active`,
      "active is derived from the listener evidence, never asserted apart from it",
    );
  return {
    scope: field(o, "scope", readScope, path),
    ca: decodeCAFacts(o["ca"], `${path}.ca`),
    uiCert,
    listener,
    mtlsClientCert: decodeMTLS(o["mtlsClientCert"], `${path}.mtlsClientCert`),
    ocsp: decodeOCSPPosture(o["ocsp"], `${path}.ocsp`),
    operations: decodeLedger(o["operations"], `${path}.operations`),
    backup: decodeBackup(o["backup"], `${path}.backup`),
  };
};

function decodeSecondaryCA(v: unknown, path: string): SecondaryCAFacts {
  const o = readRecord(v, path);
  const out: SecondaryCAFacts = {};
  for (const k of ["subject", "notAfter", "overlapEnd", "expiresIn"] as const) {
    const s = opt(o, k, readString, path);
    if (s !== undefined) out[k] = s;
  }
  return out;
}

export const decodeCAStatus: Decoder<CAStatus> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseCertSecretKeys(o, path);
  const ready = field(o, "ready", readBoolean, path);
  const out: CAStatus = {
    ready,
    revision: field(o, "revision", readCARevision, path),
    scope: field(o, "scope", readScope, path),
    cacheSize: field(o, "cacheSize", readNumber, path),
    cacheMax: field(o, "cacheMax", readNumber, path),
    cacheTTL: field(o, "cacheTTL", readString, path),
    leafValidity: field(o, "leafValidity", readString, path),
    autoRotation: field(o, "autoRotation", readBoolean, path),
    rotationOverlapDays: field(o, "rotationOverlapDays", readNumber, path),
    keyProvider: field(o, "keyProvider", readString, path),
    persistenceConfigured: field(o, "persistenceConfigured", readBoolean, path),
    usable: field(o, "usable", readBoolean, path),
    inspectBlocked: field(o, "inspectBlocked", readNumber, path),
    signRefused: field(o, "signRefused", readNumber, path),
    rotationPersistFailures: field(
      o,
      "rotationPersistFailures",
      readNumber,
      path,
    ),
    rotationPersistDegraded: field(
      o,
      "rotationPersistDegraded",
      readBoolean,
      path,
    ),
    loadFailed: field(o, "loadFailed", readBoolean, path),
    inspectBypassed: field(o, "inspectBypassed", readNumber, path),
    loadRecoveryAttempts: field(o, "loadRecoveryAttempts", readNumber, path),
    loadRecoveryGaveUp: field(o, "loadRecoveryGaveUp", readBoolean, path),
    dualCAActive: field(o, "dualCAActive", readBoolean, path),
  };
  Object.assign(out, readIdentity(o, path, ready));
  const expiresIn = opt(o, "expiresIn", readString, path);
  if (expiresIn !== undefined) {
    if (!ready) contradiction(`${path}.expiresIn`, "an expiry without a CA");
    out.expiresIn = expiresIn;
  }
  applyUsability(out, o, path);
  applyLoadPosture(out, o, path, "loadFailureClass");
  const rpc = opt(o, "rotationPersistClass", readEnum(CA_FAULT_CLASSES), path);
  if (rpc !== undefined) {
    if (!out.rotationPersistDegraded)
      contradiction(
        `${path}.rotationPersistClass`,
        "a class on a non-degraded rotation persistence",
      );
    out.rotationPersistClass = rpc;
  }
  const lrc = opt(o, "loadRecoveryClass", readEnum(CA_FAULT_CLASSES), path);
  if (lrc !== undefined) out.loadRecoveryClass = lrc;
  const sec = o["secondaryCA"];
  if (out.dualCAActive !== (sec !== undefined && sec !== null))
    contradiction(
      `${path}.secondaryCA`,
      "dualCAActive and secondaryCA disagree",
    );
  if (sec !== undefined && sec !== null)
    out.secondaryCA = decodeSecondaryCA(sec, `${path}.secondaryCA`);
  return out;
};

const decodeCoverageRow: Decoder<OCSPCoverageRow> = (v, path = "$") => {
  const o = readRecord(v, path);
  // `detail` is fixed operator text by contract; it is read for shape only
  // and never part of the model.
  field(o, "detail", readString, path);
  return {
    path: field(o, "path", readEnum(OCSP_COVERAGE_PATHS), path),
    checked: field(o, "checked", readBoolean, path),
  };
};

export const decodeOCSPStatus: Decoder<OCSPStatus> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseCertSecretKeys(o, path);
  const runtime = decodeRuntime(o["runtime"], `${path}.runtime`);
  const enabled = field(o, "enabled", readBoolean, path);
  if (enabled !== runtime.enabled)
    contradiction(`${path}.enabled`, "enabled disagrees with runtime.enabled");
  const configured =
    opt(o, "mtlsClientCertConfigured", readBoolean, path) ?? false;
  const loaded = opt(o, "mtlsClientCertLoaded", readBoolean, path);
  const reason = opt(o, "mtlsClientCertReason", readEnum(MTLS_REASONS), path);
  const notAfter = opt(o, "mtlsClientCertNotAfter", readString, path);
  const days = opt(o, "mtlsClientCertDaysRemaining", readNumber, path);
  if (!configured && (loaded !== undefined || reason !== undefined))
    contradiction(
      `${path}.mtlsClientCertLoaded`,
      "mTLS facts without a configured certificate",
    );
  if (reason !== undefined && loaded !== false)
    contradiction(
      `${path}.mtlsClientCertReason`,
      "a not-loaded reason on a loaded certificate",
    );
  if ((notAfter !== undefined || days !== undefined) && loaded !== true)
    contradiction(
      `${path}.mtlsClientCertNotAfter`,
      "expiry facts on a certificate that is not loaded",
    );
  const out: OCSPStatus = {
    enabled,
    revision: field(o, "revision", readOCSPRevision, path),
    scope: field(o, "scope", readScope, path),
    desired: decodeDesired(o["desired"], `${path}.desired`),
    runtime,
    durable: field(o, "durable", readBoolean, path),
    cacheLen: field(o, "cacheLen", readNumber, path),
    failClosedTotal: field(o, "failClosedTotal", readNumber, path),
    revokedTotal: field(o, "revokedTotal", readNumber, path),
    lastFailClosedAt: field(o, "lastFailClosedAt", readString, path),
    mtlsClientCertConfigured: configured,
    coverage: opt(o, "coverage", readArray(decodeCoverageRow), path) ?? [],
    uncheckedEnforcingPaths:
      opt(
        o,
        "uncheckedEnforcingPaths",
        readArray(readEnum(OCSP_COVERAGE_PATHS)),
        path,
      ) ?? [],
  };
  if (loaded !== undefined) out.mtlsClientCertLoaded = loaded;
  if (reason !== undefined) out.mtlsClientCertReason = reason;
  if (notAfter !== undefined) out.mtlsClientCertNotAfter = notAfter;
  if (days !== undefined) out.mtlsClientCertDaysRemaining = days;
  for (const k of [
    "notForCertificateTotal",
    "unauthorizedResponderTotal",
    "malformedResponseTotal",
    "staleResponseTotal",
    "unknownStatusTotal",
    "responderBlockedTotal",
    "respondersTruncatedTotal",
  ] as const) {
    const n = opt(o, k, readNumber, path);
    if (n !== undefined) out[k] = n;
  }
  return out;
};

export const decodeListenerFacts: Decoder<ListenerFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  // Only the bounded booleans cross the boundary; ui_tls_fallback_reason is a
  // raw crypto/x509 line and is never decoded.
  const listener = decodeAdminListener(o["ui_listener"], `${path}.ui_listener`);
  const out: ListenerFacts = {
    tlsFallback: field(o, "ui_tls_fallback", readBoolean, path),
    customCertUploaded: field(o, "ui_custom_cert_uploaded", readBoolean, path),
    customCertActive: field(o, "ui_custom_cert_active", readBoolean, path),
    customCertCorrupt: field(o, "ui_custom_cert_corrupt", readBoolean, path),
    listener,
  };
  if (out.customCertActive !== listener.servesPersistedPair)
    contradiction(
      `${path}.ui_custom_cert_active`,
      "the legacy flag is derived from ui_listener.servesPersistedPair",
    );
  if (
    out.tlsFallback &&
    listener.state === "serving" &&
    listener.posture !== "plain_http"
  )
    contradiction(
      `${path}.ui_tls_fallback`,
      "a plain-HTTP fallback listener cannot be observed serving TLS",
    );
  return out;
};

/** Two spellings of one SHA-256: the inventory's upper-case colon form and
 * the ledger's bare lower-case hex (candidateFingerprint, revision digests). */
function digestKey(s: string): string {
  return s.replace(/:/g, "").toLowerCase();
}

function requireLiteralTrue(
  o: Record<string, unknown>,
  key: string,
  path: string,
): void {
  if (o[key] !== true)
    contradiction(
      `${path}.${key}`,
      `the action-bound discriminant ${key}: true`,
    );
}

/** `key` must be present and one of `allowed` (a frozen-contract enum). */
function requireEnum(
  o: Record<string, unknown>,
  key: string,
  allowed: readonly string[],
  path: string,
): void {
  const v = o[key];
  if (typeof v !== "string" || !allowed.includes(v))
    contradiction(`${path}.${key}`, `one of ${allowed.join(" | ")}`);
}

/** `key` may be absent; when present it must be one of `allowed`. */
function optionalEnum(
  o: Record<string, unknown>,
  key: string,
  allowed: readonly string[],
  path: string,
): void {
  if (o[key] !== undefined) requireEnum(o, key, allowed, path);
}

/** An object whose keys are bounded by the frozen schema
 * (`additionalProperties: false`). */
function requireBoundedKeys(
  o: Record<string, unknown>,
  allowed: readonly string[],
  path: string,
): void {
  for (const k of Object.keys(o))
    if (!allowed.includes(k))
      contradiction(`${path}.${k}`, `a key of ${allowed.join(" | ")}`);
}

const CA_PREVIOUS_KEYS = ["fingerprint", "revision"] as const;
const CA_INFO_KEYS = [
  "ready",
  "revision",
  "subject",
  "issuer",
  "notBefore",
  "notAfter",
  "fingerprint",
] as const;
const UI_CANDIDATE_KEYS = [
  "fingerprint",
  "subject",
  "issuer",
  "notBefore",
  "notAfter",
  "dnsNames",
  "chainLength",
] as const;
const UI_CLEANUPS = ["complete", "completed_at_settlement"] as const;
const UI_ACTIVATIONS = ["restart_required"] as const;

/** CAPrevious: the superseded CA's identity — both fields optional strings,
 * no other keys. */
function checkCAPrevious(v: unknown, path: string): void {
  const p = readRecord(v, path);
  requireBoundedKeys(p, CA_PREVIOUS_KEYS, path);
  opt(p, "fingerprint", readString, path);
  opt(p, "revision", readString, path);
}

/** UICertCandidate: the reviewed candidate's public facts (T2 material). */
function checkUICandidate(v: unknown, path: string): Record<string, unknown> {
  const c = readRecord(v, path);
  refuseCertSecretKeys(c, path);
  requireBoundedKeys(c, UI_CANDIDATE_KEYS, path);
  field(c, "fingerprint", readColonFingerprint, path);
  field(c, "subject", readString, path);
  field(c, "issuer", readString, path);
  field(c, "notBefore", readString, path);
  field(c, "notAfter", readString, path);
  const n = c["chainLength"];
  if (typeof n !== "number" || !Number.isInteger(n) || n < 1)
    contradiction(`${path}.chainLength`, "a positive integer");
  const dns = c["dnsNames"];
  if (
    dns !== undefined &&
    dns !== null &&
    !(Array.isArray(dns) && dns.every((d) => typeof d === "string"))
  )
    contradiction(`${path}.dnsNames`, "an array of strings or null");
  return c;
}

/** A committed record's action-specific `result` must agree with the outer
 * record and the frozen contract (FE-6B.1 correction round, B3): the same
 * operation, the same action, the revision it committed, the certificate it
 * installed, the action's own discriminant — and (correction round 2, B2)
 * every fact the frozen result schema makes mandatory or bounded: the
 * durability claim (`persisted` / `durable` are `enum: [true]` because the
 * mutation is persist-before-publish), the target the action writes, the
 * bounded cleanup / activation vocabulary, the superseded CA's identity and
 * the reviewed candidate — otherwise the record is contradictory and is
 * refused whole. Documented optionality is preserved; nothing is invented. */
function checkCommittedResult(
  base: CertOperationBase,
  committedRevision: string,
  r: Record<string, unknown>,
  path: string,
): void {
  refuseCertSecretKeys(r, path);
  const rid = opt(r, "operationId", readString, path);
  if (rid !== undefined && rid.toLowerCase() !== base.operationId.toLowerCase())
    contradiction(`${path}.operationId`, "the result names this operation");
  const raction = opt(r, "action", readString, path);
  if (raction !== undefined && raction !== base.action)
    contradiction(`${path}.action`, "the result names this action");
  const scope = opt(r, "scope", readString, path);
  if (scope !== undefined && scope !== "node-local")
    contradiction(`${path}.scope`, "node-local");
  const revDigest = committedRevision.replace(/^[a-z]+1:/, "");
  switch (base.action) {
    case "ca.rotate":
    case "ca.import": {
      requireLiteralTrue(
        r,
        base.action === "ca.rotate" ? "rotated" : "imported",
        path,
      );
      forbid(
        r,
        base.action === "ca.rotate" ? "imported" : "rotated",
        path,
        base.action,
      );
      requireLiteralTrue(r, "persisted", path);
      if (base.action === "ca.import") requireEnum(r, "target", ["mitm"], path);
      else optionalEnum(r, "target", ["mitm"], path);
      checkCAPrevious(r["previous"], `${path}.previous`);
      const ca = readRecord(r["ca"], `${path}.ca`);
      requireBoundedKeys(ca, CA_INFO_KEYS, `${path}.ca`);
      field(ca, "ready", readBoolean, `${path}.ca`);
      const rev = field(ca, "revision", readCARevision, `${path}.ca`);
      if (rev !== committedRevision)
        contradiction(`${path}.ca.revision`, "the committed revision");
      const fp = field(ca, "fingerprint", readString, `${path}.ca`);
      if (digestKey(fp) !== revDigest)
        contradiction(`${path}.ca.fingerprint`, "the committed certificate");
      if (
        base.candidateFingerprint !== undefined &&
        digestKey(base.candidateFingerprint) !== revDigest
      )
        contradiction(`${path}.ca`, "the candidate the record installs");
      return;
    }
    case "cert.ui.replace": {
      requireLiteralTrue(r, "replaced", path);
      forbid(r, "deleted", path, base.action);
      requireLiteralTrue(r, "persisted", path);
      requireEnum(r, "target", ["ui"], path);
      requireEnum(r, "activation", UI_ACTIVATIONS, path);
      const ui = decodeUICertFacts(r["uiCert"], `${path}.uiCert`);
      if (ui.revision !== committedRevision)
        contradiction(`${path}.uiCert.revision`, "the committed revision");
      if (ui.pairState !== "complete")
        contradiction(
          `${path}.uiCert.pairState`,
          "a replaced pair is complete",
        );
      const cand = checkUICandidate(r["candidate"], `${path}.candidate`);
      if (
        ui.fingerprint === undefined ||
        digestKey(String(cand["fingerprint"])) !== digestKey(ui.fingerprint)
      )
        contradiction(
          `${path}.candidate.fingerprint`,
          "the certificate the replaced pair now holds",
        );
      return;
    }
    case "cert.ui.delete": {
      requireLiteralTrue(r, "deleted", path);
      forbid(r, "replaced", path, base.action);
      requireEnum(r, "target", ["ui"], path);
      requireEnum(r, "cleanup", UI_CLEANUPS, path);
      optionalEnum(r, "activation", UI_ACTIVATIONS, path);
      const ui = decodeUICertFacts(r["uiCert"], `${path}.uiCert`);
      if (ui.pairState !== "absent" || ui.revision !== committedRevision)
        contradiction(
          `${path}.uiCert`,
          "a deleted pair is positively absent at the committed revision",
        );
      return;
    }
    case "ocsp.set": {
      requireLiteralTrue(r, "ok", path);
      requireLiteralTrue(r, "durable", path);
      const rev = field(r, "revision", readOCSPRevision, path);
      if (rev !== committedRevision)
        contradiction(`${path}.revision`, "the committed revision");
      const enabled = field(r, "enabled", readBoolean, path);
      const runtime = decodeRuntime(r["runtime"], `${path}.runtime`);
      decodeDesired(r["desired"], `${path}.desired`);
      if (enabled !== runtime.enabled)
        contradiction(`${path}.enabled`, "enabled agrees with runtime.enabled");
      return;
    }
  }
}

export const decodeCertOperation: Decoder<CertOperation> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseCertSecretKeys(o, path);
  const action = field(o, "action", readEnum(CERT_OPERATION_ACTIONS), path);
  const target = field(o, "target", readEnum(CERT_OPERATION_TARGETS), path);
  if (ACTION_TARGET[action] !== target)
    contradiction(
      `${path}.target`,
      `${action} writes ${ACTION_TARGET[action]}`,
    );
  const base: CertOperationBase = {
    operationId: field(o, "operationId", readString, path),
    action,
    actor: field(o, "actor", readString, path),
    target,
    fence: field(o, "fence", readString, path),
    startedAt: field(o, "startedAt", readString, path),
  };
  if (action === "cert.ui.delete" || action === "ocsp.set") {
    forbid(
      o,
      "candidateFingerprint",
      path,
      `${action} installs no certificate`,
    );
  } else {
    const fp = opt(o, "candidateFingerprint", readHex64, path);
    if (fp !== undefined) base.candidateFingerprint = fp;
  }
  const state = field(o, "state", readEnum(CERT_OPERATION_STATES), path);
  const audited = field(o, "audited", readBoolean, path);
  const auditState = opt(o, "auditState", readEnum(["pending"] as const), path);
  if (state !== CERT_OPERATION_STATES[3] || o["code"] !== CERT_SUPERSEDED_CODE)
    forbid(
      o,
      "supersededBy",
      path,
      "supersededBy rides only writer_evidence_superseded",
    );
  switch (state) {
    case "pending": {
      if (audited)
        contradiction(`${path}.audited`, "a pending record is never audited");
      for (const k of [
        "auditState",
        "finishedAt",
        "code",
        "committedRevision",
        "result",
      ])
        forbid(o, k, path, "pending");
      return { ...base, state, audited: false };
    }
    case "committed": {
      const finishedAt = field(o, "finishedAt", readString, path);
      const committedRevision = field(o, "committedRevision", readString, path);
      const code = opt(o, "code", readEnum(COMMITTED_CODES), path);
      const result = opt(o, "result", readRecord, path);
      if (result !== undefined)
        checkCommittedResult(base, committedRevision, result, `${path}.result`);
      const extra = {
        ...(code !== undefined ? { code } : {}),
        ...(result !== undefined ? { result } : {}),
      };
      if (audited) {
        forbid(o, "auditState", path, "committed+audited");
        return {
          ...base,
          state,
          audited: true,
          finishedAt,
          committedRevision,
          ...extra,
        };
      }
      if (auditState !== "pending")
        contradiction(
          `${path}.auditState`,
          "an unaudited commit owes its audit",
        );
      return {
        ...base,
        state,
        audited: false,
        auditState,
        finishedAt,
        committedRevision,
        ...extra,
      };
    }
    case "aborted": {
      if (audited)
        contradiction(`${path}.audited`, "an aborted record is never audited");
      for (const k of ["auditState", "committedRevision", "result"])
        forbid(o, k, path, state);
      return {
        ...base,
        state,
        audited: false,
        finishedAt: field(o, "finishedAt", readString, path),
        code: field(o, "code", readEnum(ABORTED_CODES), path),
      };
    }
    case "outcome_unknown": {
      if (audited)
        contradiction(`${path}.audited`, "an unknown outcome is never audited");
      for (const k of ["auditState", "committedRevision", "result"])
        forbid(o, k, path, state);
      const code = field(o, "code", readEnum(UNKNOWN_CODES), path);
      const finishedAt = field(o, "finishedAt", readString, path);
      if (code === CERT_SUPERSEDED_CODE) {
        return {
          ...base,
          state,
          audited: false,
          finishedAt,
          code,
          supersededBy: field(o, "supersededBy", readString, path),
        };
      }
      return { ...base, state, audited: false, finishedAt, code };
    }
  }
};

// ── Pure postures ────────────────────────────────────────────────────────────

export type OperationPosture =
  | { kind: "pending" }
  | { kind: "committed" }
  | { kind: "committed_audit_pending" }
  | { kind: "aborted"; code: string }
  /** re-decided by every later settlement (lookup, boot, a later writer) */
  | { kind: "unknown_recoverable"; code: string }
  /** the evidence did not prove the commit; no later settlement re-decides it */
  | { kind: "unknown_unproven"; code: string }
  /** TERMINAL: a repairing writer replaced the intent's invalid evidence
   * before it could be decided — the node never learns whether the intent had
   * committed, and never guesses */
  | { kind: "unknown_superseded"; supersededBy: string };

export function operationPosture(op: CertOperation): OperationPosture {
  switch (op.state) {
    case "pending":
      return { kind: "pending" };
    case "committed":
      return op.audited
        ? { kind: "committed" }
        : { kind: "committed_audit_pending" };
    case "aborted":
      return { kind: "aborted", code: op.code };
    case "outcome_unknown": {
      if (op.code === CERT_SUPERSEDED_CODE && op.supersededBy !== undefined)
        return { kind: "unknown_superseded", supersededBy: op.supersededBy };
      if (UNKNOWN_RECOVERABLE_CODES.includes(op.code))
        return { kind: "unknown_recoverable", code: op.code };
      return { kind: "unknown_unproven", code: op.code };
    }
  }
}

export type UIPairPosture =
  | "active_persisted"
  | "persisted_restart_required"
  | "active_not_persisted"
  | "absent"
  | "incomplete"
  | "unavailable"
  | "corrupt";

export function uiPairPosture(ui: UICertFacts): UIPairPosture {
  switch (ui.pairState) {
    case "unavailable":
      return "unavailable";
    case "incomplete":
      return "incomplete";
    case "absent":
      return ui.active ? "active_not_persisted" : "absent";
    case "complete":
      if (ui.corrupt) return "corrupt";
      return ui.active ? "active_persisted" : "persisted_restart_required";
  }
}

export function ocspAgreement(o: OCSPStatus | OCSPPosture): "agree" | "differ" {
  return o.desired.enabled === o.runtime.enabled ? "agree" : "differ";
}

export type ListenerContradiction =
  | "active_on_plain_http_listener"
  | "active_disagrees"
  | "present_disagrees"
  | "corrupt_disagrees";

/** Two independent reads describe the same listener; a disagreement is
 * reported as such, never rendered as either side's truth. */
export function listenerContradiction(
  ui: UICertFacts,
  l: ListenerFacts,
): ListenerContradiction | null {
  if (l.tlsFallback && ui.active) return "active_on_plain_http_listener";
  if (ui.active !== l.customCertActive) return "active_disagrees";
  if (ui.present !== l.customCertUploaded) return "present_disagrees";
  if (ui.corrupt !== l.customCertCorrupt) return "corrupt_disagrees";
  return null;
}

/** The activation posture of the persisted admin-UI pair, decided from the
 * listener's own evidence and the persisted identity — never from a flag. */
export type ActivationPosture =
  | { kind: "unknown" }
  | { kind: "plain_http"; persistedActivatesOnRestart: boolean }
  | { kind: "tls_configured"; served: ServedCertificate }
  | {
      kind: "self_signed";
      served: ServedCertificate;
      persistedActivatesOnRestart: boolean;
    }
  | { kind: "custom_matches"; served: ServedCertificate }
  | {
      kind: "custom_differs";
      served: ServedCertificate;
      persistedFingerprint: string;
    }
  | { kind: "custom_not_persisted"; served: ServedCertificate }
  | {
      kind: "custom_persisted_unusable";
      served: ServedCertificate;
      persistedState: "corrupt" | "incomplete" | "unavailable";
    };

export function activationPosture(
  inv: CertificateInventory,
): ActivationPosture {
  const l = inv.listener;
  const ui = inv.uiCert;
  const restartActivates = ui.pairState === "complete" && !ui.corrupt;
  if (l.state !== "serving" || l.servedCertificate === undefined) {
    if (l.state === "serving" && l.posture === "plain_http")
      return {
        kind: "plain_http",
        persistedActivatesOnRestart: restartActivates,
      };
    return { kind: "unknown" };
  }
  const served = l.servedCertificate;
  switch (l.posture) {
    case "tls_configured":
      return { kind: "tls_configured", served };
    case "tls_self_signed":
      return {
        kind: "self_signed",
        served,
        persistedActivatesOnRestart: restartActivates,
      };
    case "tls_custom":
      break;
    default:
      return { kind: "unknown" };
  }
  switch (ui.pairState) {
    case "absent":
      return { kind: "custom_not_persisted", served };
    case "incomplete":
    case "unavailable":
      return {
        kind: "custom_persisted_unusable",
        served,
        persistedState: ui.pairState,
      };
    case "complete":
      if (ui.corrupt)
        return {
          kind: "custom_persisted_unusable",
          served,
          persistedState: "corrupt",
        };
      if (ui.fingerprint === served.fingerprint)
        return { kind: "custom_matches", served };
      return {
        kind: "custom_differs",
        served,
        persistedFingerprint: ui.fingerprint ?? "",
      };
  }
}

function listenerKey(l: AdminListener): string {
  return JSON.stringify([
    l.state,
    l.posture,
    l.servesPersistedPair,
    l.servedCertificate?.fingerprint ?? null,
    l.servedCertificate?.subject ?? null,
    l.servedCertificate?.notBefore ?? null,
    l.servedCertificate?.notAfter ?? null,
  ]);
}

/** The two reads publish ONE evidence object; a disagreement is reported,
 * never resolved into either side. */
export function listenerReadsDisagree(
  inv: CertificateInventory,
  net: ListenerFacts,
): boolean {
  return listenerKey(inv.listener) !== listenerKey(net.listener);
}

/** The contracted HTTP status of every lookup refusal code. */
const LOOKUP_REFUSAL_STATUS: Record<CertLookupRefusalCode, number> = {
  invalid_input: 400,
  forbidden: 403,
  not_found: 404,
  method_not_allowed: 405,
  operation_ledger_degraded: 503,
};

/** A lookup refusal is a verdict ONLY when the failed response carried the
 * code's contracted HTTP status, the JSON media type and the bounded
 * CertRefusal shape ({error, code, current?} and nothing else). Anything else
 * — the right code on the wrong status, on text/plain, or inside a foreign
 * shape — is an UNVERIFIED lookup response (FE-6B.1 correction round, B3). */
export function certLookupRefusal(err: unknown): CertLookupRefusalCode | null {
  if (!(err instanceof ApiError) || err.kind !== "http") return null;
  if (err.status === undefined || err.bodyText === undefined) return null;
  if (err.mediaType !== "application/json") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(err.bodyText);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) return null;
  for (const k of Object.keys(parsed))
    if (k !== "error" && k !== "code" && k !== "current") return null;
  if (typeof parsed["error"] !== "string" || typeof parsed["code"] !== "string")
    return null;
  if (parsed["current"] !== undefined && !isRecord(parsed["current"]))
    return null;
  const code = CERT_LOOKUP_REFUSAL_CODES.find((c) => c === parsed["code"]);
  if (code === undefined) return null;
  return LOOKUP_REFUSAL_STATUS[code] === err.status ? code : null;
}

export function isValidOperationId(s: string): boolean {
  return UUID.test(s);
}

// ── Reads (GET only) ─────────────────────────────────────────────────────────

export function getCertificateInventory(
  signal?: AbortSignal,
): Promise<CertificateInventory> {
  return apiRequest(
    "/api/certificates",
    decodeCertificateInventory,
    signal !== undefined ? { signal } : {},
  );
}

export function getCAStatus(signal?: AbortSignal): Promise<CAStatus> {
  return apiRequest(
    "/api/ca/status",
    decodeCAStatus,
    signal !== undefined ? { signal } : {},
  );
}

export function getOCSPStatus(signal?: AbortSignal): Promise<OCSPStatus> {
  return apiRequest(
    "/api/ocsp",
    decodeOCSPStatus,
    signal !== undefined ? { signal } : {},
  );
}

export function getListenerFacts(signal?: AbortSignal): Promise<ListenerFacts> {
  return apiRequest(
    "/api/settings/network",
    decodeListenerFacts,
    signal !== undefined ? { signal } : {},
  );
}

/** Admin-only (uiRoutes GET /api/ca/operations/ = admin: the record names
 * the actor). Callers below admin must not issue it. The backend GET is not
 * a pure read: it SETTLES a pending intent from the object's own evidence
 * and completes an owed success audit exactly once — so it is issued only on
 * an operator's explicit action, never polled. */
export function getCertOperation(
  operationId: string,
  signal?: AbortSignal,
): Promise<CertOperation> {
  if (!isValidOperationId(operationId)) {
    return Promise.reject(
      new ApiError("target", "refused: an operation id is a UUID"),
    );
  }
  const want = operationId.toLowerCase();
  return apiRequest(
    `/api/ca/operations/${encodeURIComponent(want)}`,
    (v, path) => {
      const op = decodeCertOperation(v, path);
      // A request for X must never display Y's record (correction round, B3).
      if (op.operationId.toLowerCase() !== want)
        throw new DecodeError(
          `${path ?? "$"}.operationId`,
          `the requested operation ${want}`,
          "[another operation]",
        );
      return op;
    },
    signal !== undefined ? { signal } : {},
  );
}

export interface CACertDownload {
  blob: Blob;
  mediaType: string;
  /** deterministic client-side filename (2A-M §15 option B) */
  filename: string;
}

/** Viewer GET of the PUBLIC Root CA certificate as PEM (apiCACert's
 * download branch; Content-Type application/x-pem-file). A JSON answer or
 * any other media type is never a valid download. */
export async function downloadCACertPEM(
  signal?: AbortSignal,
): Promise<CACertDownload> {
  const res = await apiDownloadRequest(
    "/api/ca-cert",
    ["application/x-pem-file"],
    signal !== undefined ? { signal } : {},
  );
  return {
    blob: res.blob,
    mediaType: res.mediaType,
    filename: "culvert-ca.pem",
  };
}
