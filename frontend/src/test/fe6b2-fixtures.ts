// FE-6B.2 fixtures — the WRITE side of the frozen FE-6B.0 contract, each
// shape exactly what the authoritative handler emits (ui_certificates.go
// apiCARotateChallenge / apiCARotate / apiCertsImportMITM /
// apiCertsReplaceUI / apiCertsUI / apiOCSPSet; certificate_operations.go
// caOperationResult / uiCertOperationResult / ocspOperationResult) — never
// a frontend re-wording. Reused by the RED rows and by the page matrix.
// A car1: token IS the CA DER digest, so every `previous.fingerprint` here is
// the colon form of the fence it stood at (the FE-6B.1 read fixture CA_FP is
// deliberately NOT used beside a car1:<HEX64> fence).
import {
  HEX64,
  HEX64_B,
  OP_ID,
  RAW_CANARY,
  UI_ABSENT,
  UI_FP_B,
  colonForm,
} from "./fe6b1-fixtures";

export const OP_ID_2 = "6b2e0000-fe6b-4e2e-9f00-00000000c002";
export const CHALLENGE = "c".repeat(64);

/** The digest the ledger records for a UI replace: sha256 over the exact
 * certificate PEM BYTES the browser sent (hexDigest(certPEM)) — here the
 * real digest of CERT_PEM_CANARY, so a page row that sends the canary
 * receives a result whose revision is what the appliance would record. */
export const PEM_DIGEST =
  "07d235e4e54670ab38e6de054215a781725709efdee0e81ce3d4d10717d8d098";

/** Canaries: the material a write carries ONCE in its body and nowhere else. */
export const CERT_PEM_CANARY =
  "-----BEGIN CERTIFICATE-----\nCERT-CANARY-fe6b2\n-----END CERTIFICATE-----\n";
export const KEY_PEM_CANARY =
  "-----BEGIN EC PRIVATE KEY-----\nKEY-CANARY-fe6b2-never-leaves-the-body\n-----END EC PRIVATE KEY-----\n";

/** POST /api/ca/rotate/challenge — CARotateChallenge. */
export const CHALLENGE_ANSWER = {
  challenge: CHALLENGE,
  operationId: OP_ID,
  action: "ca.rotate",
  caRevision: `car1:${HEX64}`,
  fingerprint: colonForm(HEX64),
  expiresInSeconds: 120,
  expiresAt: "2026-09-19T10:02:00Z",
  warning:
    "Rotating the Root CA invalidates every existing leaf certificate and the current trust chain. Every client workstation and device must trust the new CA certificate. This action cannot be undone.",
};

/** POST /api/ca/rotate — CARotateResult (fresh commit). */
export const ROTATE_RESULT = {
  rotated: true,
  persisted: true,
  operationId: OP_ID,
  action: "ca.rotate",
  scope: "node-local",
  ca: {
    ready: true,
    revision: `car1:${HEX64_B}`,
    subject: "CULVERT Root CA",
    issuer: "CULVERT Root CA",
    notBefore: "2026-09-19",
    notAfter: "2036-09-19",
    fingerprint: colonForm(HEX64_B),
  },
  previous: { fingerprint: colonForm(HEX64), revision: `car1:${HEX64}` },
  recordState: "committed",
};

/** ?dryRun=1 target=mitm — CertDryRunResult with CACertificateInfo. */
export const IMPORT_CANDIDATE = {
  subject: "Corp Inspection CA",
  issuer: "Corp Inspection CA",
  isCA: true,
  keyAlgorithm: "ECDSA P-256",
  notBefore: "2026-09-01T00:00:00Z",
  notAfter: "2036-09-01T00:00:00Z",
  fingerprint: colonForm(HEX64_B),
};
export const IMPORT_DRY_RUN = {
  dryRun: true,
  target: "mitm",
  action: "ca.import",
  candidate: IMPORT_CANDIDATE,
  current: { caRevision: `car1:${HEX64}` },
};

/** POST target=mitm — CAImportResult. */
export const IMPORT_RESULT = {
  imported: true,
  target: "mitm",
  persisted: true,
  operationId: OP_ID,
  action: "ca.import",
  scope: "node-local",
  ca: {
    ready: true,
    revision: `car1:${HEX64_B}`,
    subject: "Corp Inspection CA",
    issuer: "Corp Inspection CA",
    notBefore: "2026-09-01",
    notAfter: "2036-09-01",
    fingerprint: colonForm(HEX64_B),
  },
  previous: { fingerprint: colonForm(HEX64), revision: `car1:${HEX64}` },
  recordState: "committed",
};

/** ?dryRun=1 target=ui — CertDryRunResult with UICertCandidate. */
export const UI_CANDIDATE = {
  fingerprint: UI_FP_B,
  subject: "ui-b.example",
  issuer: "ui-b.example",
  notBefore: "2026-09-01T00:00:00Z",
  notAfter: "2027-09-01T00:00:00Z",
  dnsNames: ["ui-b.example"],
  chainLength: 1,
};
export const REPLACE_DRY_RUN = {
  dryRun: true,
  target: "ui",
  action: "cert.ui.replace",
  candidate: UI_CANDIDATE,
  current: { uiCertRevision: `uic1:${HEX64_B}` },
};

/** The persisted pair AFTER a replace: revision = uic1:<sha256 of the PEM
 * bytes sent>, the certificate's fingerprint = the reviewed candidate's. */
export const UI_PERSISTED_AFTER_REPLACE = {
  present: true,
  pairState: "complete",
  revision: `uic1:${PEM_DIGEST}`,
  active: false,
  corrupt: false,
  fingerprint: UI_FP_B,
  subject: "ui-b.example",
  notAfter: "2027-09-01T00:00:00Z",
};

/** POST target=ui — UICertReplaceResult. */
export const REPLACE_RESULT = {
  replaced: true,
  persisted: true,
  activation: "restart_required",
  target: "ui",
  operationId: OP_ID,
  action: "cert.ui.replace",
  scope: "node-local",
  uiCert: UI_PERSISTED_AFTER_REPLACE,
  candidate: UI_CANDIDATE,
  recordState: "committed",
};

/** DELETE /api/certs/ui — UICertDeleteResult. */
export const DELETE_RESULT = {
  deleted: true,
  target: "ui",
  cleanup: "complete",
  operationId: OP_ID,
  action: "cert.ui.delete",
  scope: "node-local",
  uiCert: UI_ABSENT,
  recordState: "committed",
};

/** POST /api/ocsp — OCSPSetResult (enable). */
export const OCSP_RESULT = {
  ok: true,
  enabled: true,
  durable: true,
  revision: `ocr1:${HEX64_B}`,
  scope: "node-local",
  operationId: OP_ID,
  action: "ocsp.set",
  desired: { enabled: true, source: "admin" },
  runtime: { enabled: true },
  recordState: "committed",
};

/** A typed refusal body exactly as writeRefusal emits it. The `error` line
 * carries a canary: it must never reach the DOM. */
export function refusalBody(
  code: string,
  current?: Record<string, unknown>,
): Record<string, unknown> {
  return {
    error: `refused: ${RAW_CANARY}`,
    code,
    ...(current !== undefined ? { current } : {}),
  };
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
export function plain(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain" },
  });
}
