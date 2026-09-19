// FE-6B.1 RED matrix (pure modules) — written against the frozen FE-6B.0
// entry baseline (c540b176) BEFORE any Certificates / CA Management frontend
// code exists. On that tree every test fails at import resolution
// (`src/api/certificates` does not exist; /security/certificates is absent
// from KNOWN_ROUTES). Each assertion pins a contract the read-only React
// surface must honour verbatim — the frozen FE-6B.0 backend read models
// exactly as the appliance answers them (ui_certificates.go apiCertificates
// / apiCAStatus / ocspReadModel / apiCAOperations, certificate_operations.go
// lookupReadModel / readModel, ui_config.go apiNetworkSettings), never a
// frontend re-wording:
//
//   A1  GET /api/certificates decodes every inventory fact (node-local scope,
//       CA identity + usability + persistence + bounded fault classes, the
//       UI pair's evidence class + revision token + activation, the mTLS
//       client certificate posture, OCSP desired vs runtime vs durable, the
//       operation-ledger posture, the backup facts) and REFUSES a missing
//       required fact and every unknown bounded word (scope, pairState,
//       unusableClass, fault class, mTLS reason, OCSP source, ledger
//       degradedReason, auditSink) — never a silent mapping.
//   A2  secret rejection: a read model carrying key material at ANY depth
//       (privateKey, key PEM, passphrase, password, secret, bundle, pem …)
//       is a DECODE FAILURE, never rendered; a RAW path in a free-text
//       field is never part of the decoded model.
//   A3  contradictions are refused whole: present ⇔ pairState complete;
//       a fingerprint on a non-complete pair; a revision token that does not
//       match its pairState; a usable CA carrying an unusableClass and an
//       unusable one without; present:false with an identity; loadFailed /
//       persistDegraded without / with their class; an mTLS `loaded` without
//       `configured`; a degraded ledger without its reason.
//   A4  GET /api/ca/status decodes the CA detail (readiness + revision form,
//       expiry, cache, auto-rotation, key provider, persistence, usability,
//       rotation-persist posture, load failure + recovery campaign, dual-CA
//       overlap + secondary CA) and refuses ready/revision, dualCAActive /
//       secondaryCA and class contradictions.
//   A5  GET /api/ocsp keeps DESIRED (enabled + source + durable) and RUNTIME
//       (enabled) distinct, refuses `enabled` disagreeing with runtime, and
//       decodes the CHAOS-65 coverage rows against the bounded path set —
//       "never consulted" is a fact the page can state, never inferred from
//       zero counters.
//   A6  GET /api/ca/operations/{id} is a DISCRIMINATED UNION: pending /
//       committed (+ owed audit) / aborted (persist_failed, <why>_absent) /
//       recoverable outcome_unknown (<why>_evidence_unavailable,
//       _evidence_invalid, _durability_unproven, _cleanup_incomplete) /
//       terminal <why>_unproven / terminal writer_evidence_superseded with a
//       REQUIRED supersededBy (forbidden elsewhere); an unknown state /
//       action / target / code, a target that does not belong to the action,
//       and a candidateFingerprint on a UI delete or OCSP set are refused.
//   A7  pure posture helpers: superseded is TERMINAL UNKNOWN — never mapped
//       to success, failure, cancelled or retry; an owed audit is a
//       committed record; recoverable vs terminal unknown are distinct
//       words; the UI pair's persisted / active / restart-required /
//       active-not-persisted postures are pure functions of the read model.
//   A8  listener facts: GET /api/settings/network contributes ONLY the
//       bounded booleans; the RAW `ui_tls_fallback_reason` line is never part
//       of the decoded model; a listener contradiction (custom pair active
//       while the listener fell back to plain HTTP, or the two reads
//       disagreeing on active / present / corrupt) is detected, never
//       rendered as truth.
//   A9  route intent: /security/certificates is a viewer route (uiRoutes:
//       GET /api/certificates, /api/ca/status, /api/ocsp,
//       /api/settings/network = viewer); every role's intent resolves to it.
//   A10 every read helper issues exactly one GET with no body against the
//       contracted path; the admin-only lookup encodes the id; the lookup's
//       refusal vocabulary is closed (invalid_input / forbidden / not_found /
//       method_not_allowed / operation_ledger_degraded); the PEM download is
//       a viewer GET with an exact media-type gate.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DecodeError } from "../api/decode";
import {
  CA_FAULT_CLASSES,
  CA_UNUSABLE_CLASSES,
  CERT_LOOKUP_REFUSAL_CODES,
  CERT_OPERATION_ACTIONS,
  CERT_OPERATION_STATES,
  CERT_SECRET_KEYS,
  CERT_SUPERSEDED_CODE,
  OCSP_COVERAGE_PATHS,
  UI_PAIR_STATES,
  decodeCAStatus,
  decodeCertOperation,
  decodeCertificateInventory,
  decodeListenerFacts,
  decodeOCSPStatus,
  downloadCACertPEM,
  getCAStatus,
  getCertOperation,
  getCertificateInventory,
  getListenerFacts,
  getOCSPStatus,
  isValidOperationId,
  listenerContradiction,
  ocspAgreement,
  operationPosture,
  uiPairPosture,
} from "../api/certificates";
import type { CertOperation } from "../api/certificates";
import { KNOWN_ROUTES, resolveRouteIntent } from "../auth/routeIntent";
import {
  CA_STATUS_DEGRADED,
  CA_STATUS_DUAL,
  CA_STATUS_HEALTHY,
  HEX64,
  HEX64_B,
  INVENTORY_DEGRADED,
  INVENTORY_HEALTHY,
  LISTENER_FALLBACK,
  LISTENER_TLS,
  OCSP_STATUS_ADMIN_DIFFERS,
  OCSP_STATUS_DEFAULT,
  OP_ABORTED,
  OP_ABORTED_ABSENT,
  OP_COMMITTED,
  OP_COMMITTED_AUDIT_PENDING,
  OP_COMMITTED_SETTLED,
  OP_ID,
  OP_PENDING,
  OP_SUPERSEDED,
  OP_SUPERSEDED_AUTO,
  OP_UI_DELETE_COMMITTED,
  OP_UNKNOWN_RECOVERABLE,
  OP_UNKNOWN_UNPROVEN,
  OP_WRITER,
  RAW_CANARY,
  SECRET_CANARY,
  UI_ABSENT,
  UI_ACTIVE_NOT_PERSISTED,
  UI_ACTIVE_PERSISTED,
  UI_CORRUPT,
  UI_INCOMPLETE,
  UI_PERSISTED_NOT_ACTIVE,
  UI_UNAVAILABLE,
  okJSON,
} from "./fe6b1-fixtures";

const omit = (o: Record<string, unknown>, k: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).filter(([key]) => key !== k));

const withCA = (ca: Record<string, unknown>): Record<string, unknown> => ({
  ...INVENTORY_HEALTHY,
  ca,
});
const withUI = (uiCert: Record<string, unknown>): Record<string, unknown> => ({
  ...INVENTORY_HEALTHY,
  uiCert,
});

// ── A1 inventory ────────────────────────────────────────────────────────────

describe("A1 GET /api/certificates decodes every fact and refuses unknown words", () => {
  it("decodes the healthy inventory verbatim", () => {
    const inv = decodeCertificateInventory(INVENTORY_HEALTHY);
    expect(inv.scope).toBe("node-local");
    expect(inv.ca.present).toBe(true);
    expect(inv.ca.revision).toBe(`car1:${HEX64}`);
    expect(inv.ca.subject).toBe("CULVERT Root CA");
    expect(inv.ca.fingerprint).toBe(INVENTORY_HEALTHY.ca.fingerprint);
    expect(inv.ca.usable).toBe(true);
    expect(inv.ca.encryptedAtRest).toBe(true);
    expect(inv.ca.persistenceConfigured).toBe(true);
    expect(inv.ca.keyProvider).toBe("local");
    expect(inv.uiCert.pairState).toBe("complete");
    expect(inv.uiCert.present).toBe(true);
    expect(inv.uiCert.active).toBe(false);
    expect(inv.uiCert.revision).toBe(`uic1:${HEX64_B}`);
    expect(inv.mtlsClientCert.configured).toBe(false);
    expect(inv.ocsp.desired.source).toBe("default");
    expect(inv.ocsp.desired.enabled).toBe(false);
    expect(inv.ocsp.runtime.enabled).toBe(false);
    expect(inv.ocsp.durable).toBe(false);
    expect(inv.operations.retained).toBe(4);
    expect(inv.operations.unresolved).toBe(1);
    expect(inv.operations.capacity).toBe(256);
    expect(inv.operations.auditSink).toBe("file");
    expect(inv.backup.uiCertArchived).toBe(false);
    expect(inv.backup.caBundleArchived).toBe(true);
  });

  it("decodes the degraded inventory: bounded classes, corrupt pair, ledger reason", () => {
    const inv = decodeCertificateInventory(INVENTORY_DEGRADED);
    expect(inv.ca.present).toBe(false);
    expect(inv.ca.usable).toBe(false);
    expect(inv.ca.unusableClass).toBe("no_ca");
    expect(inv.ca.loadFailed).toBe(true);
    expect(inv.ca.loadFailureClass).toBe("bundle_malformed");
    expect(inv.uiCert.corrupt).toBe(true);
    expect(inv.mtlsClientCert.reason).toBe("key_file_missing");
    expect(inv.ocsp.desired.source).toBe("admin");
    expect(inv.operations.degraded).toBe(true);
    expect(inv.operations.degradedReason).toBe("corrupt");
  });

  it("refuses every missing required fact", () => {
    for (const k of [
      "scope",
      "ca",
      "uiCert",
      "mtlsClientCert",
      "ocsp",
      "operations",
      "backup",
    ]) {
      expect(() =>
        decodeCertificateInventory(omit(INVENTORY_HEALTHY, k)),
      ).toThrow(DecodeError);
    }
    for (const k of [
      "present",
      "revision",
      "usable",
      "loadFailed",
      "persistDegraded",
    ]) {
      expect(() =>
        decodeCertificateInventory(withCA(omit(INVENTORY_HEALTHY.ca, k))),
      ).toThrow(DecodeError);
    }
    for (const k of ["present", "pairState", "revision", "active", "corrupt"]) {
      expect(() =>
        decodeCertificateInventory(withUI(omit(UI_PERSISTED_NOT_ACTIVE, k))),
      ).toThrow(DecodeError);
    }
  });

  it("refuses unknown bounded words instead of mapping them", () => {
    expect(() =>
      decodeCertificateInventory({
        ...INVENTORY_HEALTHY,
        scope: "cluster-synced",
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(
        withUI({ ...UI_ABSENT, pairState: "missing" }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(
        withCA({ ...INVENTORY_DEGRADED.ca, unusableClass: "broken" }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(
        withCA({ ...INVENTORY_DEGRADED.ca, loadFailureClass: "eaccess /data" }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory({
        ...INVENTORY_HEALTHY,
        mtlsClientCert: { configured: true, loaded: false, reason: "boom" },
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory({
        ...INVENTORY_HEALTHY,
        ocsp: {
          ...INVENTORY_HEALTHY.ocsp,
          desired: { enabled: true, source: "cli" },
        },
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory({
        ...INVENTORY_DEGRADED,
        operations: {
          ...INVENTORY_DEGRADED.operations,
          degradedReason: "gone",
        },
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory({
        ...INVENTORY_HEALTHY,
        operations: { ...INVENTORY_HEALTHY.operations, auditSink: "syslog" },
      }),
    ).toThrow(DecodeError);
    expect(UI_PAIR_STATES).toEqual([
      "complete",
      "absent",
      "incomplete",
      "unavailable",
    ]);
    expect(CA_UNUSABLE_CLASSES).toEqual(["expired", "not_yet_valid", "no_ca"]);
    expect(CA_FAULT_CLASSES).toEqual([
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
    ]);
  });
});

// ── A2 secret rejection ─────────────────────────────────────────────────────

describe("A2 key material never decodes", () => {
  it("refuses a secret-bearing key at any depth", () => {
    for (const k of CERT_SECRET_KEYS) {
      expect(() =>
        decodeCertificateInventory({
          ...INVENTORY_HEALTHY,
          ca: { ...INVENTORY_HEALTHY.ca, [k]: SECRET_CANARY },
        }),
      ).toThrow(DecodeError);
      expect(() =>
        decodeCAStatus({
          ...CA_STATUS_DUAL,
          secondaryCA: { ...CA_STATUS_DUAL.secondaryCA, [k]: SECRET_CANARY },
        }),
      ).toThrow(DecodeError);
      expect(() =>
        decodeCertOperation({
          ...OP_COMMITTED,
          result: { ...OP_COMMITTED.result, ca: { [k]: SECRET_CANARY } },
        }),
      ).toThrow(DecodeError);
    }
    expect(CERT_SECRET_KEYS).toEqual(
      expect.arrayContaining([
        "privateKey",
        "private_key",
        "key",
        "keyPem",
        "certPem",
        "pem",
        "passphrase",
        "password",
        "secret",
        "bundle",
      ]),
    );
  });

  it("a raw path in the ledger's free-text detail is not part of the decoded model", () => {
    const inv = decodeCertificateInventory(INVENTORY_DEGRADED);
    expect(JSON.stringify(inv)).not.toContain(RAW_CANARY);
  });
});

// ── A3 contradictions ───────────────────────────────────────────────────────

describe("A3 contradictory inventory states are refused whole", () => {
  it("present must agree with pairState", () => {
    expect(() =>
      decodeCertificateInventory(
        withUI({ ...UI_PERSISTED_NOT_ACTIVE, present: false }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(withUI({ ...UI_ABSENT, present: true })),
    ).toThrow(DecodeError);
  });
  it("a fingerprint / subject on a pair that is not complete is refused", () => {
    expect(() =>
      decodeCertificateInventory(
        withUI({
          ...UI_INCOMPLETE,
          fingerprint: UI_PERSISTED_NOT_ACTIVE.fingerprint,
        }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(withUI({ ...UI_UNAVAILABLE, subject: "x" })),
    ).toThrow(DecodeError);
  });
  it("the revision token must match the pairState", () => {
    expect(() =>
      decodeCertificateInventory(
        withUI({ ...UI_ABSENT, revision: "uic1:incomplete" }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(
        withUI({ ...UI_UNAVAILABLE, revision: "uic1:none" }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(
        withUI({ ...UI_PERSISTED_NOT_ACTIVE, revision: "uic1:unavailable" }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(
        withUI({ ...UI_PERSISTED_NOT_ACTIVE, revision: "uic1:zz" }),
      ),
    ).toThrow(DecodeError);
  });
  it("CA usability / identity / fault classes must be internally consistent", () => {
    expect(() =>
      decodeCertificateInventory(
        withCA({ ...INVENTORY_HEALTHY.ca, unusableClass: "expired" }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(
        withCA({ ...INVENTORY_HEALTHY.ca, usable: false }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(
        withCA({ ...INVENTORY_HEALTHY.ca, present: false }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(
        withCA({ ...INVENTORY_HEALTHY.ca, revision: "car1:none" }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(
        withCA({ ...INVENTORY_HEALTHY.ca, loadFailureClass: "not_found" }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(
        withCA({ ...INVENTORY_DEGRADED.ca, loadFailureClass: undefined }),
      ),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory(
        withCA({ ...INVENTORY_HEALTHY.ca, persistClass: "no_space" }),
      ),
    ).toThrow(DecodeError);
  });
  it("mTLS loaded requires configured; a reason rides only a configured-but-unloaded posture", () => {
    expect(() =>
      decodeCertificateInventory({
        ...INVENTORY_HEALTHY,
        mtlsClientCert: { configured: false, loaded: true },
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory({
        ...INVENTORY_HEALTHY,
        mtlsClientCert: {
          configured: true,
          loaded: true,
          reason: "load_failed",
        },
      }),
    ).toThrow(DecodeError);
  });
  it("a degraded ledger without its reason is refused; the reason without degraded too", () => {
    expect(() =>
      decodeCertificateInventory({
        ...INVENTORY_DEGRADED,
        operations: omit(INVENTORY_DEGRADED.operations, "degradedReason"),
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertificateInventory({
        ...INVENTORY_HEALTHY,
        operations: {
          ...INVENTORY_HEALTHY.operations,
          degradedReason: "corrupt",
        },
      }),
    ).toThrow(DecodeError);
  });
});

// ── A4 CA status ────────────────────────────────────────────────────────────

describe("A4 GET /api/ca/status", () => {
  it("decodes the healthy, degraded and dual-CA shapes", () => {
    const h = decodeCAStatus(CA_STATUS_HEALTHY);
    expect(h.ready).toBe(true);
    expect(h.revision).toBe(`car1:${HEX64}`);
    expect(h.expiresIn).toBe("87599h0m0s");
    expect(h.cacheSize).toBe(12);
    expect(h.cacheMax).toBe(10000);
    expect(h.autoRotation).toBe(true);
    expect(h.rotationOverlapDays).toBe(30);
    expect(h.persistenceConfigured).toBe(true);
    expect(h.dualCAActive).toBe(false);
    const d = decodeCAStatus(CA_STATUS_DEGRADED);
    expect(d.ready).toBe(false);
    expect(d.unusableClass).toBe("no_ca");
    expect(d.rotationPersistDegraded).toBe(true);
    expect(d.rotationPersistClass).toBe("no_space");
    expect(d.loadFailureClass).toBe("bundle_malformed");
    expect(d.loadRecoveryAttempts).toBe(4);
    expect(d.loadRecoveryGaveUp).toBe(false);
    expect(d.loadRecoveryClass).toBe("bundle_malformed");
    expect(d.inspectBypassed).toBe(7);
    const dual = decodeCAStatus(CA_STATUS_DUAL);
    expect(dual.dualCAActive).toBe(true);
    expect(dual.secondaryCA?.subject).toBe("CULVERT Root CA (previous)");
    expect(dual.secondaryCA?.overlapEnd).toBe("2026-10-01");
  });
  it("refuses missing required facts and unknown classes", () => {
    for (const k of [
      "ready",
      "revision",
      "scope",
      "usable",
      "loadFailed",
      "rotationPersistDegraded",
      "loadRecoveryAttempts",
      "loadRecoveryGaveUp",
      "dualCAActive",
      "persistenceConfigured",
    ]) {
      expect(() => decodeCAStatus(omit(CA_STATUS_HEALTHY, k))).toThrow(
        DecodeError,
      );
    }
    expect(() =>
      decodeCAStatus({
        ...CA_STATUS_DEGRADED,
        loadRecoveryClass: "/data/ca.bundle",
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCAStatus({ ...CA_STATUS_DEGRADED, unusableClass: "revoked" }),
    ).toThrow(DecodeError);
  });
  it("refuses ready/revision, dual-CA and class contradictions", () => {
    expect(() =>
      decodeCAStatus({ ...CA_STATUS_HEALTHY, revision: "car1:none" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCAStatus({ ...CA_STATUS_DEGRADED, revision: `car1:${HEX64}` }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCAStatus({
        ...CA_STATUS_DEGRADED,
        fingerprint: CA_STATUS_HEALTHY.fingerprint,
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCAStatus({ ...CA_STATUS_DUAL, dualCAActive: false }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCAStatus({ ...CA_STATUS_HEALTHY, dualCAActive: true }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCAStatus({
        ...CA_STATUS_HEALTHY,
        rotationPersistClass: "no_space",
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCAStatus({ ...CA_STATUS_HEALTHY, usable: false }),
    ).toThrow(DecodeError);
  });
});

// ── A5 OCSP ─────────────────────────────────────────────────────────────────

describe("A5 GET /api/ocsp keeps desired and runtime distinct", () => {
  it("decodes desired vs runtime vs durable and the coverage rows", () => {
    const o = decodeOCSPStatus(OCSP_STATUS_ADMIN_DIFFERS);
    expect(o.desired.enabled).toBe(true);
    expect(o.desired.source).toBe("admin");
    expect(o.durable).toBe(true);
    expect(o.runtime.enabled).toBe(false);
    expect(o.enabled).toBe(false);
    expect(ocspAgreement(o)).toBe("differ");
    expect(ocspAgreement(decodeOCSPStatus(OCSP_STATUS_DEFAULT))).toBe("agree");
    expect(o.coverage.map((c) => `${c.path}:${String(c.checked)}`)).toEqual([
      "upstream_transport:true",
      "ssl_inspect_origin:false",
      "connect_bypass:false",
    ]);
    expect(o.uncheckedEnforcingPaths).toEqual(["ssl_inspect_origin"]);
    expect(o.mtlsClientCertReason).toBe("key_file_missing");
    expect(o.lastFailClosedAt).toBe("2026-09-18T10:00:00Z");
    expect(OCSP_COVERAGE_PATHS).toEqual([
      "upstream_transport",
      "ssl_inspect_origin",
      "connect_bypass",
    ]);
  });
  it("refuses `enabled` disagreeing with runtime, unknown sources and unknown paths", () => {
    expect(() =>
      decodeOCSPStatus({ ...OCSP_STATUS_DEFAULT, enabled: true }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeOCSPStatus({
        ...OCSP_STATUS_DEFAULT,
        desired: { enabled: false, source: "env" },
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeOCSPStatus({
        ...OCSP_STATUS_DEFAULT,
        coverage: [{ path: "socks5", checked: false, detail: "x" }],
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeOCSPStatus({
        ...OCSP_STATUS_DEFAULT,
        uncheckedEnforcingPaths: ["dns"],
      }),
    ).toThrow(DecodeError);
    for (const k of [
      "enabled",
      "revision",
      "scope",
      "desired",
      "runtime",
      "durable",
    ]) {
      expect(() => decodeOCSPStatus(omit(OCSP_STATUS_DEFAULT, k))).toThrow(
        DecodeError,
      );
    }
    expect(() =>
      decodeOCSPStatus({
        ...OCSP_STATUS_ADMIN_DIFFERS,
        mtlsClientCertLoaded: true,
        mtlsClientCertReason: "load_failed",
      }),
    ).toThrow(DecodeError);
  });
});

// ── A6 operation union ──────────────────────────────────────────────────────

describe("A6 GET /api/ca/operations/{id} is a discriminated union", () => {
  it("decodes every state with exactly its own fields", () => {
    const p = decodeCertOperation(OP_PENDING);
    expect(p.state).toBe("pending");
    expect(p.audited).toBe(false);
    const c = decodeCertOperation(OP_COMMITTED);
    expect(c.state).toBe("committed");
    if (c.state === "committed") {
      expect(c.audited).toBe(true);
      expect(c.committedRevision).toBe(`car1:${HEX64_B}`);
      expect(c.result).toBeDefined();
    }
    const cs = decodeCertOperation(OP_COMMITTED_SETTLED);
    if (cs.state === "committed") expect(cs.code).toBe("lookup_committed");
    const ap = decodeCertOperation(OP_COMMITTED_AUDIT_PENDING);
    expect(ap.state).toBe("committed");
    if (ap.state === "committed") {
      expect(ap.audited).toBe(false);
      expect(ap.auditState).toBe("pending");
    }
    const a = decodeCertOperation(OP_ABORTED);
    if (a.state === "aborted") expect(a.code).toBe("persist_failed");
    const aa = decodeCertOperation(OP_ABORTED_ABSENT);
    if (aa.state === "aborted") expect(aa.code).toBe("lookup_absent");
    const u = decodeCertOperation(OP_UNKNOWN_RECOVERABLE);
    if (u.state === "outcome_unknown")
      expect(u.code).toBe("reconciled_evidence_invalid");
    const s = decodeCertOperation(OP_SUPERSEDED);
    if (s.state === "outcome_unknown") {
      expect(s.code).toBe(CERT_SUPERSEDED_CODE);
      expect(s.supersededBy).toBe(OP_WRITER);
    }
    const sa = decodeCertOperation(OP_SUPERSEDED_AUTO);
    if (sa.state === "outcome_unknown")
      expect(sa.supersededBy).toBe("auto_rotation");
    const d = decodeCertOperation(OP_UI_DELETE_COMMITTED);
    expect(d.target).toBe("ui_cert");
    expect(d.candidateFingerprint).toBeUndefined();
    expect(CERT_OPERATION_STATES).toEqual([
      "pending",
      "committed",
      "aborted",
      "outcome_unknown",
    ]);
    expect(CERT_OPERATION_ACTIONS).toEqual([
      "ca.rotate",
      "ca.import",
      "cert.ui.replace",
      "cert.ui.delete",
      "ocsp.set",
    ]);
  });

  it("refuses unknown state / action / target / code words", () => {
    expect(() => decodeCertOperation({ ...OP_PENDING, state: "done" })).toThrow(
      DecodeError,
    );
    expect(() =>
      decodeCertOperation({ ...OP_PENDING, action: "ca.delete" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertOperation({ ...OP_PENDING, target: "leaf" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertOperation({ ...OP_ABORTED, code: "boom /data" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertOperation({
        ...OP_UNKNOWN_RECOVERABLE,
        code: "lookup_committed",
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertOperation({ ...OP_COMMITTED_SETTLED, code: "lookup_absent" }),
    ).toThrow(DecodeError);
  });

  it("refuses contradictory records whole", () => {
    // pending carries no terminal fact
    expect(() =>
      decodeCertOperation({
        ...OP_PENDING,
        finishedAt: "2026-09-18T10:00:02Z",
      }),
    ).toThrow(DecodeError);
    expect(() => decodeCertOperation({ ...OP_PENDING, audited: true })).toThrow(
      DecodeError,
    );
    // committed needs its revision; an unaudited commit owes its audit
    expect(() =>
      decodeCertOperation(omit(OP_COMMITTED, "committedRevision")),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertOperation({ ...OP_COMMITTED, audited: false }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertOperation({ ...OP_COMMITTED, auditState: "pending" }),
    ).toThrow(DecodeError);
    // aborted / unknown never carry a commit
    expect(() =>
      decodeCertOperation({
        ...OP_ABORTED,
        committedRevision: `car1:${HEX64_B}`,
      }),
    ).toThrow(DecodeError);
    expect(() => decodeCertOperation({ ...OP_ABORTED, audited: true })).toThrow(
      DecodeError,
    );
    expect(() =>
      decodeCertOperation({
        ...OP_UNKNOWN_RECOVERABLE,
        result: { rotated: true },
      }),
    ).toThrow(DecodeError);
    // supersededBy is REQUIRED on the superseded code and forbidden elsewhere
    expect(() =>
      decodeCertOperation(omit(OP_SUPERSEDED, "supersededBy")),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertOperation({
        ...OP_UNKNOWN_RECOVERABLE,
        supersededBy: OP_WRITER,
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertOperation({ ...OP_COMMITTED, supersededBy: OP_WRITER }),
    ).toThrow(DecodeError);
    // the target must belong to the action
    expect(() =>
      decodeCertOperation({ ...OP_PENDING, action: "cert.ui.replace" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertOperation({ ...OP_UI_DELETE_COMMITTED, target: "root_ca" }),
    ).toThrow(DecodeError);
    // a UI delete and an OCSP set install nothing
    expect(() =>
      decodeCertOperation({
        ...OP_UI_DELETE_COMMITTED,
        candidateFingerprint: HEX64,
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeCertOperation({
        ...OP_UI_DELETE_COMMITTED,
        action: "ocsp.set",
        target: "ocsp",
        fence: `ocr1:${HEX64}`,
        committedRevision: `ocr1:${HEX64_B}`,
        candidateFingerprint: "enabled",
        result: { ok: true },
      }),
    ).toThrow(DecodeError);
  });
});

// ── A7 pure posture helpers ─────────────────────────────────────────────────

describe("A7 postures are pure functions of the read model", () => {
  const dec = (o: unknown): CertOperation => decodeCertOperation(o);
  it("superseded is TERMINAL UNKNOWN; recoverable and unproven unknowns are distinct; an owed audit is still a commit", () => {
    expect(operationPosture(dec(OP_PENDING)).kind).toBe("pending");
    expect(operationPosture(dec(OP_COMMITTED)).kind).toBe("committed");
    expect(operationPosture(dec(OP_COMMITTED_AUDIT_PENDING)).kind).toBe(
      "committed_audit_pending",
    );
    expect(operationPosture(dec(OP_ABORTED)).kind).toBe("aborted");
    expect(operationPosture(dec(OP_UNKNOWN_RECOVERABLE)).kind).toBe(
      "unknown_recoverable",
    );
    expect(operationPosture(dec(OP_UNKNOWN_UNPROVEN)).kind).toBe(
      "unknown_unproven",
    );
    const sup = operationPosture(dec(OP_SUPERSEDED));
    expect(sup.kind).toBe("unknown_superseded");
    if (sup.kind === "unknown_superseded")
      expect(sup.supersededBy).toBe(OP_WRITER);
    // The vocabulary the page may render for a superseded record: no
    // success, failure, cancellation or retry word exists in the posture.
    expect(JSON.stringify(sup).toLowerCase()).not.toMatch(
      /succe|fail|cancel|retry|safe/,
    );
  });
  it("UI pair postures: persisted / active / restart-required / active-not-persisted / evidence classes", () => {
    const inv = (ui: unknown): ReturnType<typeof uiPairPosture> =>
      uiPairPosture(
        decodeCertificateInventory(withUI(ui as Record<string, unknown>))
          .uiCert,
      );
    expect(inv(UI_PERSISTED_NOT_ACTIVE)).toBe("persisted_restart_required");
    expect(inv(UI_ACTIVE_PERSISTED)).toBe("active_persisted");
    expect(inv(UI_ACTIVE_NOT_PERSISTED)).toBe("active_not_persisted");
    expect(inv(UI_ABSENT)).toBe("absent");
    expect(inv(UI_INCOMPLETE)).toBe("incomplete");
    expect(inv(UI_UNAVAILABLE)).toBe("unavailable");
    expect(inv(UI_CORRUPT)).toBe("corrupt");
  });
  it("validates a client-typed operation id without a request", () => {
    expect(isValidOperationId(OP_ID)).toBe(true);
    expect(isValidOperationId(OP_ID.toUpperCase())).toBe(true);
    expect(isValidOperationId("not-a-uuid")).toBe(false);
    expect(isValidOperationId("")).toBe(false);
    expect(isValidOperationId(`${OP_ID}/../x`)).toBe(false);
  });
});

// ── A8 listener facts ───────────────────────────────────────────────────────

describe("A8 listener facts contribute bounded booleans only", () => {
  it("decodes the booleans and never carries the raw fallback reason", () => {
    const l = decodeListenerFacts(LISTENER_FALLBACK);
    expect(l.tlsFallback).toBe(true);
    expect(l.customCertActive).toBe(false);
    expect(l.customCertUploaded).toBe(false);
    expect(l.customCertCorrupt).toBe(false);
    expect(JSON.stringify(l)).not.toContain(RAW_CANARY);
    expect(JSON.stringify(l)).not.toContain("x509");
    const t = decodeListenerFacts(LISTENER_TLS);
    expect(t.tlsFallback).toBe(false);
    expect(t.customCertUploaded).toBe(true);
    expect(() =>
      decodeListenerFacts(omit(LISTENER_TLS, "ui_tls_fallback")),
    ).toThrow(DecodeError);
  });
  it("detects a listener contradiction and never renders it as truth", () => {
    const inv = decodeCertificateInventory(INVENTORY_HEALTHY);
    expect(
      listenerContradiction(inv.uiCert, decodeListenerFacts(LISTENER_TLS)),
    ).toBeNull();
    // the custom pair claims active while the listener fell back to plain HTTP
    const activeInv = decodeCertificateInventory(withUI(UI_ACTIVE_PERSISTED));
    expect(
      listenerContradiction(
        activeInv.uiCert,
        decodeListenerFacts({
          ...LISTENER_FALLBACK,
          ui_custom_cert_active: true,
          ui_custom_cert_uploaded: true,
        }),
      ),
    ).toBe("active_on_plain_http_listener");
    // the two reads disagree about active / present / corrupt
    expect(
      listenerContradiction(
        activeInv.uiCert,
        decodeListenerFacts({ ...LISTENER_TLS, ui_custom_cert_active: false }),
      ),
    ).toBe("active_disagrees");
    expect(
      listenerContradiction(
        inv.uiCert,
        decodeListenerFacts({
          ...LISTENER_TLS,
          ui_custom_cert_uploaded: false,
        }),
      ),
    ).toBe("present_disagrees");
    expect(
      listenerContradiction(
        inv.uiCert,
        decodeListenerFacts({ ...LISTENER_TLS, ui_custom_cert_corrupt: true }),
      ),
    ).toBe("corrupt_disagrees");
  });
});

// ── A9 route intent ─────────────────────────────────────────────────────────

describe("A9 route intent", () => {
  it("/security/certificates is a viewer route", () => {
    const r = KNOWN_ROUTES.find((k) => k.path === "/security/certificates");
    expect(r?.minRole).toBe("viewer");
    for (const role of ["viewer", "operator", "admin"] as const) {
      expect(resolveRouteIntent("/security/certificates", role)).toBe(
        "/security/certificates",
      );
    }
  });
});

// ── A10 read helpers ────────────────────────────────────────────────────────

describe("A10 every read helper is one GET against the contracted path", () => {
  let calls: Array<{ url: string; init: RequestInit | undefined }>;
  beforeEach(() => {
    calls = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: unknown, init?: RequestInit) => {
        const url = String(input);
        calls.push({ url, init });
        if (url.startsWith("/api/certificates"))
          return okJSON(INVENTORY_HEALTHY);
        if (url.startsWith("/api/ca/status")) return okJSON(CA_STATUS_HEALTHY);
        if (url.startsWith("/api/ocsp")) return okJSON(OCSP_STATUS_DEFAULT);
        if (url.startsWith("/api/settings/network"))
          return okJSON(LISTENER_TLS);
        if (url.startsWith("/api/ca/operations/")) return okJSON(OP_COMMITTED);
        if (url.startsWith("/api/ca-cert")) {
          return Promise.resolve(
            new Response(
              "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
              {
                status: 200,
                headers: {
                  "Content-Type": "application/x-pem-file",
                  "Content-Disposition":
                    'attachment; filename="culvert-ca.pem"',
                },
              },
            ),
          );
        }
        return Promise.reject(new TypeError(`unexpected ${url}`));
      }),
    );
  });

  it("issues the contracted GETs with no body", async () => {
    await getCertificateInventory();
    await getCAStatus();
    await getOCSPStatus();
    await getListenerFacts();
    await getCertOperation(OP_ID);
    expect(calls.map((c) => c.url)).toEqual([
      "/api/certificates",
      "/api/ca/status",
      "/api/ocsp",
      "/api/settings/network",
      `/api/ca/operations/${OP_ID}`,
    ]);
    for (const c of calls) {
      expect(c.init?.method ?? "GET").toBe("GET");
      expect(c.init?.body).toBeUndefined();
    }
  });

  it("encodes the lookup id and refuses a malformed one before any request", async () => {
    await expect(getCertOperation("../x")).rejects.toThrow();
    expect(calls).toEqual([]);
    await getCertOperation(OP_ID.toUpperCase());
    expect(calls[0]?.url).toBe(`/api/ca/operations/${OP_ID}`);
  });

  it("the lookup refusal vocabulary is closed", () => {
    expect([...CERT_LOOKUP_REFUSAL_CODES]).toEqual([
      "invalid_input",
      "forbidden",
      "not_found",
      "method_not_allowed",
      "operation_ledger_degraded",
    ]);
  });

  it("the PEM download is a viewer GET with an exact media-type gate", async () => {
    const res = await downloadCACertPEM();
    expect(calls[0]?.url).toBe("/api/ca-cert");
    expect(res.mediaType).toBe("application/x-pem-file");
    expect(res.filename).toBe("culvert-ca.pem");
    expect(await res.blob.text()).toContain("BEGIN CERTIFICATE");
    // a JSON answer on the download path is never a valid download
    vi.stubGlobal(
      "fetch",
      vi.fn(() => okJSON({ ready: true, revision: `car1:${HEX64}` })),
    );
    await expect(downloadCACertPEM()).rejects.toThrow();
  });
});
