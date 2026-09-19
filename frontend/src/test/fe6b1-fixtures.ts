// FE-6B.1 fixtures — the frozen FE-6B.0 read models EXACTLY as the appliance
// answers them (ui_certificates.go apiCertificates / apiCAStatus /
// ocspReadModel / apiNetworkSettings, certificate_operations.go
// lookupReadModel / readModel), shared by the module matrix
// (fe6b1-red.test.ts) and the page matrix (fe6b1-red-page.test.tsx). Every
// value is a SERVER fact from the contract (api/openapi/openapi.yaml:
// CertificateInventory, CAStatus, OCSPStatus, CertOperation, UICertRead,
// NetworkSettings) — never a frontend re-wording.

export const HEX64 = "a".repeat(64);
export const HEX64_B = "b".repeat(64);
export const CA_FP =
  "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
export const UI_FP =
  "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00";
export const OP_ID = "6b1c0000-fe6b-4e2e-9f00-00000000c001";
export const OP_WRITER = "6b1c0000-fe6b-4e2e-9f00-00000000c0aa";
export const ACTOR = "admin@10.0.0.9";
export const RAW_CANARY = "RAWCANARY-/srv/culvert/data/ca.bundle-never-render";
export const SECRET_CANARY = "-----BEGIN EC PRIVATE KEY-----CANARY";

export const CA_HEALTHY = {
  present: true,
  revision: `car1:${HEX64}`,
  keyProvider: "local",
  dualCAActive: false,
  persistenceConfigured: true,
  encryptedAtRest: true,
  subject: "CULVERT Root CA",
  issuer: "CULVERT Root CA",
  notBefore: "2026-09-01",
  notAfter: "2036-09-01",
  fingerprint: CA_FP,
  usable: true,
  persistDegraded: false,
  loadFailed: false,
};

export const UI_PERSISTED_NOT_ACTIVE = {
  present: true,
  pairState: "complete",
  revision: `uic1:${HEX64_B}`,
  active: false,
  corrupt: false,
  fingerprint: UI_FP,
  subject: "ui.example",
  notAfter: "2027-09-01T00:00:00Z",
};

export const UI_ABSENT = {
  present: false,
  pairState: "absent",
  revision: "uic1:none",
  active: false,
  corrupt: false,
};

export const UI_INCOMPLETE = {
  present: false,
  pairState: "incomplete",
  revision: "uic1:incomplete",
  active: false,
  corrupt: false,
};

export const UI_UNAVAILABLE = {
  present: false,
  pairState: "unavailable",
  revision: "uic1:unavailable",
  active: false,
  corrupt: false,
};

export const UI_CORRUPT = {
  present: true,
  pairState: "complete",
  revision: `uic1:${HEX64_B}`,
  active: false,
  corrupt: true,
  fingerprint: UI_FP,
  subject: "ui.example",
  notAfter: "2027-09-01T00:00:00Z",
};

/** FE-6B.1 correction round: the former UI_ACTIVE_NOT_PERSISTED fixture
 * (absent pair, `active: true`) is a CONTRADICTION under the listener-evidence
 * contract — `active` is derived from served == persisted, so an absent pair
 * is never active. The deleted-while-served case is UI_ABSENT beside
 * LISTENER_CUSTOM_A(false). */

export const UI_ACTIVE_PERSISTED = {
  ...UI_PERSISTED_NOT_ACTIVE,
  active: true,
};

export const MTLS_UNCONFIGURED = { configured: false, loaded: false };
export const MTLS_LOADED = {
  configured: true,
  loaded: true,
  notAfter: "2027-01-01T00:00:00Z",
  daysRemaining: 120,
};
export const MTLS_NOT_LOADED = {
  configured: true,
  loaded: false,
  reason: "key_file_missing",
};

export const OCSP_INV_DEFAULT = {
  revision: `ocr1:${HEX64}`,
  desired: { enabled: false, source: "default" },
  runtime: { enabled: false },
  durable: false,
};

export const OCSP_INV_ADMIN_DIFFERS = {
  revision: `ocr1:${HEX64_B}`,
  desired: { enabled: true, source: "admin" },
  runtime: { enabled: false },
  durable: true,
};

export const LEDGER_OK = {
  degraded: false,
  retained: 4,
  unresolved: 1,
  capacity: 256,
  auditSink: "file",
};

export const LEDGER_DEGRADED = {
  degraded: true,
  degradedReason: "corrupt",
  degradedDetail: RAW_CANARY,
  retained: 0,
  unresolved: 0,
  capacity: 256,
  auditSink: "memory",
};

export const BACKUP_FACTS = {
  caBundleArchived: true,
  caBundleEncrypted: true,
  uiCertArchived: false,
  operationsArchived: false,
  configVersionRollback: false,
};

// ── FE-6B.1 correction round (B1): server-owned LISTENER evidence ───────────
// The RUNNING admin listener's posture and the certificate it actually
// serves, recorded from the bind (never from a boot-time selection flag), and
// carried on BOTH reads (`listener` on the inventory, `ui_listener` on the
// network settings). `uiCert.active` / `ui_custom_cert_active` are DERIVED:
// true only when the served certificate IS the persisted one.
export const UI_FP_B =
  "B0:B1:B2:B3:B4:B5:B6:B7:B8:B9:BA:BB:BC:BD:BE:BF:C0:C1:C2:C3:C4:C5:C6:C7:C8:C9:CA:CB:CC:CD:CE:CF";
export const SELF_FP =
  "5E:1F:5E:1F:5E:1F:5E:1F:5E:1F:5E:1F:5E:1F:5E:1F:5E:1F:5E:1F:5E:1F:5E:1F:5E:1F:5E:1F:5E:1F:5E:1F";
export const CONF_FP =
  "C0:4F:C0:4F:C0:4F:C0:4F:C0:4F:C0:4F:C0:4F:C0:4F:C0:4F:C0:4F:C0:4F:C0:4F:C0:4F:C0:4F:C0:4F:C0:4F";

export const LISTENER_UNKNOWN = {
  state: "unknown",
  posture: "unknown",
  servesPersistedPair: false,
};
export const LISTENER_PLAIN = {
  state: "serving",
  posture: "plain_http",
  servesPersistedPair: false,
};
export const LISTENER_SELF_SIGNED = {
  state: "serving",
  posture: "tls_self_signed",
  servedCertificate: {
    fingerprint: SELF_FP,
    subject: "culvert-admin-ui",
    notBefore: "2026-09-01T00:00:00Z",
    notAfter: "2027-09-01T00:00:00Z",
  },
  servesPersistedPair: false,
};
export const LISTENER_CONFIGURED = {
  state: "serving",
  posture: "tls_configured",
  servedCertificate: {
    fingerprint: CONF_FP,
    subject: "ui-configured.example",
    notBefore: "2026-09-01T00:00:00Z",
    notAfter: "2027-09-01T00:00:00Z",
  },
  servesPersistedPair: false,
};
/** The listener serves pair A (UI_FP) — the pair that is (or was) persisted. */
export const LISTENER_CUSTOM_A = (servesPersisted: boolean) => ({
  state: "serving",
  posture: "tls_custom",
  servedCertificate: {
    fingerprint: UI_FP,
    subject: "ui.example",
    notBefore: "2026-09-01T00:00:00Z",
    notAfter: "2027-09-01T00:00:00Z",
  },
  servesPersistedPair: servesPersisted,
});

/** Pair B persisted (complete, valid), not the pair the listener serves. */
export const UI_PERSISTED_B = {
  present: true,
  pairState: "complete",
  revision: `uic1:${HEX64_B}`,
  active: false,
  corrupt: false,
  fingerprint: UI_FP_B,
  subject: "ui-b.example",
  notAfter: "2027-09-01T00:00:00Z",
};

/** A network-settings read carrying the listener evidence beside the legacy flags. */
export const LISTENER_NET = (
  listener: Record<string, unknown>,
  uploaded: boolean,
  active: boolean,
  fallback = false,
) => ({
  base_url: "",
  ui_sans: null,
  trust_forwarded_headers: false,
  trusted_proxy_cidrs: null,
  ui_tls_fallback: fallback,
  ui_tls_fallback_reason: fallback ? `x509: ${RAW_CANARY}` : "",
  ui_custom_cert_uploaded: uploaded,
  ui_custom_cert_active: active,
  ui_custom_cert_corrupt: false,
  ui_listener: listener,
});

export const INVENTORY_HEALTHY = {
  scope: "node-local",
  ca: CA_HEALTHY,
  uiCert: UI_PERSISTED_NOT_ACTIVE,
  mtlsClientCert: MTLS_UNCONFIGURED,
  ocsp: OCSP_INV_DEFAULT,
  operations: LEDGER_OK,
  backup: BACKUP_FACTS,
  listener: LISTENER_SELF_SIGNED,
};

export const CA_DEGRADED = {
  present: false,
  revision: "car1:none",
  keyProvider: "local",
  dualCAActive: false,
  persistenceConfigured: true,
  encryptedAtRest: false,
  usable: false,
  unusableClass: "no_ca",
  persistDegraded: false,
  loadFailed: true,
  loadFailureClass: "bundle_malformed",
};

export const INVENTORY_DEGRADED = {
  scope: "node-local",
  ca: CA_DEGRADED,
  uiCert: UI_CORRUPT,
  mtlsClientCert: MTLS_NOT_LOADED,
  ocsp: OCSP_INV_ADMIN_DIFFERS,
  operations: LEDGER_DEGRADED,
  backup: { ...BACKUP_FACTS, caBundleEncrypted: false },
  listener: LISTENER_SELF_SIGNED,
};

export const CA_STATUS_HEALTHY = {
  ready: true,
  revision: `car1:${HEX64}`,
  scope: "node-local",
  subject: "CULVERT Root CA",
  issuer: "CULVERT Root CA",
  notBefore: "2026-09-01",
  notAfter: "2036-09-01",
  fingerprint: CA_FP,
  expiresIn: "87599h0m0s",
  cacheSize: 12,
  cacheMax: 10000,
  cacheTTL: "1h",
  leafValidity: "24h",
  autoRotation: true,
  rotationOverlapDays: 30,
  keyProvider: "local",
  persistenceConfigured: true,
  usable: true,
  inspectBlocked: 0,
  signRefused: 0,
  rotationPersistFailures: 0,
  rotationPersistDegraded: false,
  loadFailed: false,
  inspectBypassed: 0,
  loadRecoveryAttempts: 0,
  loadRecoveryGaveUp: false,
  dualCAActive: false,
};

export const CA_STATUS_DEGRADED = {
  ready: false,
  revision: "car1:none",
  scope: "node-local",
  cacheSize: 0,
  cacheMax: 10000,
  cacheTTL: "1h",
  leafValidity: "24h",
  autoRotation: true,
  rotationOverlapDays: 30,
  keyProvider: "local",
  persistenceConfigured: true,
  usable: false,
  unusableClass: "no_ca",
  inspectBlocked: 3,
  signRefused: 2,
  rotationPersistFailures: 1,
  rotationPersistDegraded: true,
  rotationPersistClass: "no_space",
  loadFailed: true,
  loadFailureClass: "bundle_malformed",
  inspectBypassed: 7,
  loadRecoveryAttempts: 4,
  loadRecoveryGaveUp: false,
  loadRecoveryClass: "bundle_malformed",
  dualCAActive: false,
};

export const CA_STATUS_DUAL = {
  ...CA_STATUS_HEALTHY,
  dualCAActive: true,
  secondaryCA: {
    subject: "CULVERT Root CA (previous)",
    notAfter: "2026-10-01",
    overlapEnd: "2026-10-01",
    expiresIn: "240h0m0s",
  },
};

export const OCSP_COVERAGE = [
  {
    path: "upstream_transport",
    checked: true,
    detail: "shared upstream transport (https:// parent proxy handshakes)",
  },
  {
    path: "ssl_inspect_origin",
    checked: false,
    detail:
      "inspected HTTPS origin handshakes build their own TLS config; revocation is NOT checked (CHAOS-65 OCSP-8)",
  },
  {
    path: "connect_bypass",
    checked: false,
    detail:
      "bypassed CONNECT tunnels are relayed raw; this proxy never sees the certificate",
  },
];

export const OCSP_STATUS_DEFAULT = {
  enabled: false,
  revision: `ocr1:${HEX64}`,
  scope: "node-local",
  desired: { enabled: false, source: "default" },
  runtime: { enabled: false },
  durable: false,
  cacheLen: 0,
  failClosedTotal: 0,
  revokedTotal: 0,
  lastFailClosedAt: "",
  coverage: OCSP_COVERAGE,
  uncheckedEnforcingPaths: ["ssl_inspect_origin"],
  notForCertificateTotal: 0,
  unauthorizedResponderTotal: 0,
  malformedResponseTotal: 0,
  staleResponseTotal: 0,
  unknownStatusTotal: 0,
  responderBlockedTotal: 0,
  respondersTruncatedTotal: 0,
};

export const OCSP_STATUS_ADMIN_DIFFERS = {
  ...OCSP_STATUS_DEFAULT,
  enabled: false,
  revision: `ocr1:${HEX64_B}`,
  desired: { enabled: true, source: "admin" },
  runtime: { enabled: false },
  durable: true,
  cacheLen: 5,
  failClosedTotal: 2,
  revokedTotal: 1,
  lastFailClosedAt: "2026-09-18T10:00:00Z",
  mtlsClientCertConfigured: true,
  mtlsClientCertLoaded: false,
  mtlsClientCertReason: "key_file_missing",
};

export const LISTENER_TLS = {
  base_url: "",
  ui_sans: null,
  trust_forwarded_headers: false,
  trusted_proxy_cidrs: null,
  ui_tls_fallback: false,
  ui_custom_cert_uploaded: true,
  ui_custom_cert_active: false,
  ui_custom_cert_corrupt: false,
  ui_listener: LISTENER_SELF_SIGNED,
};

/** The listener fell back to plain HTTP (self-signed setup failed); the
 * reason is a RAW crypto/x509 error line the browser must never render. */
export const LISTENER_FALLBACK = {
  base_url: "",
  ui_sans: null,
  trust_forwarded_headers: false,
  trusted_proxy_cidrs: null,
  ui_tls_fallback: true,
  ui_tls_fallback_reason: `x509: ${RAW_CANARY}`,
  ui_custom_cert_uploaded: false,
  ui_custom_cert_active: false,
  ui_custom_cert_corrupt: false,
  ui_listener: LISTENER_PLAIN,
};

const OP_BASE = {
  operationId: OP_ID,
  action: "ca.import",
  actor: ACTOR,
  target: "root_ca",
  fence: `car1:${HEX64}`,
  candidateFingerprint: HEX64_B,
  startedAt: "2026-09-18T10:00:00Z",
};

export const OP_PENDING = { ...OP_BASE, state: "pending", audited: false };

export const OP_COMMITTED = {
  ...OP_BASE,
  state: "committed",
  audited: true,
  finishedAt: "2026-09-18T10:00:02Z",
  committedRevision: `car1:${HEX64_B}`,
  result: {
    imported: true,
    target: "mitm",
    ca: { ready: true, revision: `car1:${HEX64_B}`, fingerprint: CA_FP },
    previous: { fingerprint: CA_FP, revision: `car1:${HEX64}` },
  },
};

export const OP_COMMITTED_SETTLED = {
  ...OP_COMMITTED,
  code: "lookup_committed",
};

export const OP_COMMITTED_AUDIT_PENDING = {
  ...OP_COMMITTED,
  audited: false,
  auditState: "pending",
  code: "reconciled_committed",
};

export const OP_ABORTED = {
  ...OP_BASE,
  state: "aborted",
  audited: false,
  finishedAt: "2026-09-18T10:00:02Z",
  code: "persist_failed",
};

export const OP_ABORTED_ABSENT = { ...OP_ABORTED, code: "lookup_absent" };

export const OP_UNKNOWN_RECOVERABLE = {
  ...OP_BASE,
  state: "outcome_unknown",
  audited: false,
  finishedAt: "2026-09-18T10:00:02Z",
  code: "reconciled_evidence_invalid",
};

export const OP_UNKNOWN_UNPROVEN = {
  ...OP_UNKNOWN_RECOVERABLE,
  code: "lookup_unproven",
};

export const OP_SUPERSEDED = {
  ...OP_BASE,
  state: "outcome_unknown",
  audited: false,
  finishedAt: "2026-09-18T10:00:02Z",
  code: "writer_evidence_superseded",
  supersededBy: OP_WRITER,
};

export const OP_SUPERSEDED_AUTO = {
  ...OP_SUPERSEDED,
  supersededBy: "auto_rotation",
};

export const OP_UI_DELETE_COMMITTED = {
  operationId: OP_ID,
  state: "committed",
  action: "cert.ui.delete",
  actor: ACTOR,
  target: "ui_cert",
  fence: `uic1:${HEX64_B}`,
  startedAt: "2026-09-18T10:00:00Z",
  finishedAt: "2026-09-18T10:00:01Z",
  audited: true,
  committedRevision: "uic1:none",
  result: { deleted: true, cleanup: "complete", uiCert: UI_ABSENT },
};

export function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

export function refusal(status: number, code: string): Promise<Response> {
  return okJSON({ error: `refused: ${RAW_CANARY}`, code }, status);
}
