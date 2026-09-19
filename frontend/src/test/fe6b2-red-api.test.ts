// FE-6B.2 RED matrix — the Certificates & CA WRITE client, written against
// the frozen FE-6B.1 baseline 212b1617 BEFORE any product change. The
// baseline exports no write function at all (READ ONLY by directive), so
// every row here fails on it at import; the corrected client must make each
// row pass without weakening the read-side decoders it lives beside.
//
//   A01 the rotation challenge decodes only when it is bound to the requested
//       operationId and the echoed caRevision; bounded shape; secrets refused.
//   A02 the challenge request carries operationId + caRevision in the query
//       and NO body; the confirm carries the challenge in the BODY only
//       (never a URL), plus operationId + caRevision in the query.
//   A03 a rotate 2xx is a verdict only when rotated/persisted are true, the
//       result names THIS operation and action, `previous` names the exact CA
//       the challenge showed at the fence revision, and `ca` is a NEW
//       revision whose fingerprint is its own digest — every contradiction
//       is UNPROVEN (a decode failure), never a success.
//   A04 a 2xx on text/plain, a 2xx naming another operation, or a 2xx
//       missing recordState is UNPROVEN.
//   A05 dry-run decoders (mitm / ui): bounded candidate facts, the fence to
//       echo captured from `current`, a secret-bearing answer refused.
//   A06 the dry run and the commit are the SAME multipart candidate: fields
//       cert/key/target, dryRun=1 on review, operationId + the fence on the
//       commit; the private key appears in the body once and never in a URL.
//   A07 an import 2xx binds ca.fingerprint to the REVIEWED candidate; a
//       replace 2xx binds candidate.fingerprint to the reviewed candidate AND
//       uiCert.revision to uic1:<digest of the PEM bytes sent>.
//   A08 a delete 2xx: deleted:true, target ui, positively absent pair,
//       bounded cleanup, optional bounded activation.
//   A09 an OCSP 2xx: ok + durable, a NEW revision, desired == the requested
//       posture with source admin, enabled == runtime.enabled.
//   A10 a replay (replayed:true + the recorded facts) decodes as a proven
//       outcome; a bare replay without the action facts is UNPROVEN.
//   A11 the refusal contract: every code is a verdict ONLY with its
//       contracted status, application/json and its required typed facts;
//       the server's error line never leaves the decoder.
//   A12 certUnproven: transport loss, a wrong media type, a failed action
//       binding and an uncontracted HTTP answer are UNPROVEN; 403 and a
//       contracted refusal are not.
//   A13 the non-terminal outcome_unknown (refusal_not_durable /
//       durability_unproven / transition_incomplete) is a contracted refusal
//       that PROVES NOTHING WAS DECIDED — it is never in the nothing-written
//       set; persist_failed (terminal) is.
//   A14 pemDigest is sha256 over the UTF-8 bytes (what hexDigest sees).
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import {
  CERT_TERMINAL_NOTHING_WRITTEN,
  asCertRefusal,
  certUnproven,
  confirmCARotation,
  deleteUICert,
  dryRunCAImport,
  dryRunUIReplace,
  importCA,
  pemDigest,
  replaceUICert,
  requestCARotationChallenge,
  setOCSPPosture,
} from "../api/certificates";
import type { CertRefusalCode } from "../api/certificates";
import {
  CA_FP,
  HEX64,
  HEX64_B,
  OP_ID,
  RAW_CANARY,
  SECRET_CANARY,
  colonForm,
} from "./fe6b1-fixtures";
import {
  CERT_PEM_CANARY,
  CHALLENGE,
  CHALLENGE_ANSWER,
  DELETE_RESULT,
  IMPORT_DRY_RUN,
  IMPORT_RESULT,
  KEY_PEM_CANARY,
  OCSP_RESULT,
  OP_ID_2,
  PEM_DIGEST,
  REPLACE_DRY_RUN,
  REPLACE_RESULT,
  ROTATE_RESULT,
  UI_CANDIDATE,
  json,
  plain,
  refusalBody,
} from "./fe6b2-fixtures";

interface Call {
  url: string;
  method: string;
  body: unknown;
  contentType: string | undefined;
}

function stub(answer: Response | (() => Response)): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const headers = init?.headers;
      const ct =
        headers !== undefined &&
        !(headers instanceof Headers) &&
        !Array.isArray(headers)
          ? headers["Content-Type"]
          : undefined;
      calls.push({
        url: String(input),
        method: init?.method ?? "GET",
        body: init?.body,
        contentType: ct,
      });
      return Promise.resolve(
        typeof answer === "function" ? answer() : answer.clone(),
      );
    }),
  );
  return calls;
}

/** A multipart field's content: a string entry, or the bytes of a FILE
 * part (the pair rides as file parts — byte-exact, no CRLF normalisation). */
async function formField(body: unknown, name: string): Promise<string | null> {
  if (!(body instanceof FormData)) return null;
  const v = body.get(name);
  if (typeof v === "string") return v;
  if (v instanceof Blob) return v.text();
  return null;
}
function isFilePart(body: unknown, name: string): boolean {
  return body instanceof FormData && body.get(name) instanceof Blob;
}

const FENCE = `car1:${HEX64}`;
const UI_FENCE = `uic1:${HEX64_B}`;
const OCSP_FENCE = `ocr1:${HEX64}`;
const PEM = { cert: CERT_PEM_CANARY, key: KEY_PEM_CANARY };

async function unproven(p: Promise<unknown>): Promise<void> {
  await expect(p).rejects.toSatisfy(
    (e: unknown) =>
      e instanceof ApiError &&
      (e.kind === "decode" || e.kind === "contenttype") &&
      certUnproven(e),
  );
}

describe("A01/A02 — the rotation challenge", () => {
  it("A01 decodes only when bound to the requested operation and fence", async () => {
    stub(json(CHALLENGE_ANSWER));
    const ch = await requestCARotationChallenge({
      operationId: OP_ID,
      caRevision: FENCE,
    });
    expect(ch.challenge).toBe(CHALLENGE);
    expect(ch.fingerprint).toBe(colonForm(HEX64));
    expect(ch.expiresAt).toBe("2026-09-19T10:02:00Z");
    stub(json({ ...CHALLENGE_ANSWER, operationId: OP_ID_2 }));
    await unproven(
      requestCARotationChallenge({ operationId: OP_ID, caRevision: FENCE }),
    );
    stub(json({ ...CHALLENGE_ANSWER, caRevision: `car1:${HEX64_B}` }));
    await unproven(
      requestCARotationChallenge({ operationId: OP_ID, caRevision: FENCE }),
    );
    stub(json({ ...CHALLENGE_ANSWER, challenge: "not-hex" }));
    await unproven(
      requestCARotationChallenge({ operationId: OP_ID, caRevision: FENCE }),
    );
    stub(json({ ...CHALLENGE_ANSWER, privateKey: SECRET_CANARY }));
    await unproven(
      requestCARotationChallenge({ operationId: OP_ID, caRevision: FENCE }),
    );
  });

  it("A02 request shapes: challenge = query only, no body; confirm = challenge in the body, never in a URL", async () => {
    const calls = stub(json(CHALLENGE_ANSWER));
    await requestCARotationChallenge({ operationId: OP_ID, caRevision: FENCE });
    const c = calls[0];
    expect(c?.method).toBe("POST");
    const u = new URL(c?.url ?? "", "http://x");
    expect(u.pathname).toBe("/api/ca/rotate/challenge");
    expect(u.searchParams.get("operationId")).toBe(OP_ID);
    expect(u.searchParams.get("caRevision")).toBe(FENCE);
    expect(c?.body).toBeUndefined();

    const calls2 = stub(json(ROTATE_RESULT));
    await confirmCARotation({
      operationId: OP_ID,
      caRevision: FENCE,
      challenge: CHALLENGE,
      previousFingerprint: colonForm(HEX64),
    });
    const r = calls2[0];
    const ru = new URL(r?.url ?? "", "http://x");
    expect(ru.pathname).toBe("/api/ca/rotate");
    expect(ru.searchParams.get("operationId")).toBe(OP_ID);
    expect(ru.searchParams.get("caRevision")).toBe(FENCE);
    expect(r?.url).not.toContain(CHALLENGE);
    expect(r?.contentType).toBe("application/json");
    expect(JSON.parse(String(r?.body))).toEqual({ challenge: CHALLENGE });
  });
});

describe("A03/A04 — a rotate 2xx is a verdict only when action-bound", () => {
  const args = {
    operationId: OP_ID,
    caRevision: FENCE,
    challenge: CHALLENGE,
    previousFingerprint: colonForm(HEX64),
  };
  it("A03 accepts the builder's result and binds previous/ca/identity", async () => {
    stub(json(ROTATE_RESULT));
    const out = await confirmCARotation(args);
    expect(out.kind).toBe("ca");
    expect(out.action).toBe("ca.rotate");
    expect(out.operationId).toBe(OP_ID);
    expect(out.ca.revision).toBe(`car1:${HEX64_B}`);
    expect(out.previous.fingerprint).toBe(colonForm(HEX64));
    expect(out.recordState).toBe("committed");
    expect(out.replayed).toBe(false);
  });
  const rows: Array<[string, Record<string, unknown>]> = [
    ["rotated:false", { ...ROTATE_RESULT, rotated: false }],
    ["persisted:false", { ...ROTATE_RESULT, persisted: false }],
    ["another operation", { ...ROTATE_RESULT, operationId: OP_ID_2 }],
    ["another action", { ...ROTATE_RESULT, action: "ca.import" }],
    [
      "previous is not the CA the challenge showed",
      {
        ...ROTATE_RESULT,
        previous: { fingerprint: colonForm(HEX64_B), revision: FENCE },
      },
    ],
    [
      "previous.revision is not the fence",
      {
        ...ROTATE_RESULT,
        previous: {
          fingerprint: colonForm(HEX64),
          revision: `car1:${HEX64_B}`,
        },
      },
    ],
    [
      "ca.revision did not move",
      {
        ...ROTATE_RESULT,
        ca: { ...ROTATE_RESULT.ca, revision: FENCE, fingerprint: CA_FP },
      },
    ],
    [
      "ca.fingerprint is not the revision's digest",
      { ...ROTATE_RESULT, ca: { ...ROTATE_RESULT.ca, fingerprint: CA_FP } },
    ],
    [
      "recordState missing",
      (() => {
        const { recordState: _r, ...rest } = ROTATE_RESULT;
        void _r;
        return rest;
      })(),
    ],
    ["recordState foreign", { ...ROTATE_RESULT, recordState: "done" }],
    ["a secret-bearing key", { ...ROTATE_RESULT, key: SECRET_CANARY }],
  ];
  for (const [name, body] of rows) {
    it(`A03 refuses: ${name}`, async () => {
      stub(json(body));
      await unproven(confirmCARotation(args));
    });
  }
  it("A04 text/plain 2xx is UNPROVEN", async () => {
    stub(plain("rotated"));
    await unproven(confirmCARotation(args));
  });
});

describe("A05/A06 — dry run and commit are the same multipart candidate", () => {
  it("A05 mitm dry run: bounded facts + the fence to echo", async () => {
    stub(json(IMPORT_DRY_RUN));
    const d = await dryRunCAImport(PEM);
    expect(d.target).toBe("mitm");
    expect(d.candidate.fingerprint).toBe(colonForm(HEX64_B));
    expect(d.candidate.isCA).toBe(true);
    expect(d.caRevision).toBe(FENCE);
    stub(json({ ...IMPORT_DRY_RUN, dryRun: false }));
    await unproven(dryRunCAImport(PEM));
    stub(json({ ...IMPORT_DRY_RUN, target: "ui" }));
    await unproven(dryRunCAImport(PEM));
    stub(
      json({
        ...IMPORT_DRY_RUN,
        candidate: { ...IMPORT_DRY_RUN.candidate, key: SECRET_CANARY },
      }),
    );
    await unproven(dryRunCAImport(PEM));
    stub(json({ ...IMPORT_DRY_RUN, current: {} }));
    await unproven(dryRunCAImport(PEM));
  });
  it("A05 ui dry run: bounded facts + the fence to echo", async () => {
    stub(json(REPLACE_DRY_RUN));
    const d = await dryRunUIReplace(PEM);
    expect(d.target).toBe("ui");
    expect(d.candidate.fingerprint).toBe(UI_CANDIDATE.fingerprint);
    expect(d.candidate.chainLength).toBe(1);
    expect(d.uiCertRevision).toBe(UI_FENCE);
    stub(json({ ...REPLACE_DRY_RUN, action: "ca.import" }));
    await unproven(dryRunUIReplace(PEM));
  });
  it("A06 review request: multipart cert/key/target + dryRun=1, no operationId, no fence, no key in the URL", async () => {
    const calls = stub(json(IMPORT_DRY_RUN));
    await dryRunCAImport(PEM);
    const c = calls[0];
    const u = new URL(c?.url ?? "", "http://x");
    expect(u.pathname).toBe("/api/certs/upload");
    expect(u.searchParams.get("dryRun")).toBe("1");
    expect(u.searchParams.get("target")).toBe("mitm");
    expect(u.searchParams.has("operationId")).toBe(false);
    expect(u.searchParams.has("caRevision")).toBe(false);
    expect(c?.contentType).toBeUndefined(); // the browser sets the multipart boundary
    expect(await formField(c?.body, "cert")).toBe(CERT_PEM_CANARY);
    expect(await formField(c?.body, "key")).toBe(KEY_PEM_CANARY);
    expect(await formField(c?.body, "target")).toBe("mitm");
    // byte-exact FILE parts, never string entries (CRLF normalisation)
    expect(isFilePart(c?.body, "cert")).toBe(true);
    expect(isFilePart(c?.body, "key")).toBe(true);
    expect(c?.url).not.toContain("KEY-CANARY");
  });
  it("A06 commit request: the SAME fields, plus operationId and the reviewed fence", async () => {
    const calls = stub(json(IMPORT_RESULT));
    await importCA({
      operationId: OP_ID,
      caRevision: FENCE,
      pem: PEM,
      candidateFingerprint: colonForm(HEX64_B),
    });
    const c = calls[0];
    const u = new URL(c?.url ?? "", "http://x");
    expect(u.pathname).toBe("/api/certs/upload");
    expect(u.searchParams.has("dryRun")).toBe(false);
    expect(u.searchParams.get("target")).toBe("mitm");
    expect(u.searchParams.get("operationId")).toBe(OP_ID);
    expect(u.searchParams.get("caRevision")).toBe(FENCE);
    expect(await formField(c?.body, "cert")).toBe(CERT_PEM_CANARY);
    expect(await formField(c?.body, "key")).toBe(KEY_PEM_CANARY);
    expect(isFilePart(c?.body, "cert")).toBe(true);
    expect(c?.url).not.toContain("KEY-CANARY");

    const calls2 = stub(json(REPLACE_RESULT));
    await replaceUICert({
      operationId: OP_ID,
      uiCertRevision: UI_FENCE,
      pem: PEM,
      candidateFingerprint: UI_CANDIDATE.fingerprint,
      certDigest: PEM_DIGEST,
    });
    const r = calls2[0];
    const ru = new URL(r?.url ?? "", "http://x");
    expect(ru.searchParams.get("target")).toBe("ui");
    expect(ru.searchParams.get("uiCertRevision")).toBe(UI_FENCE);
    expect(ru.searchParams.get("operationId")).toBe(OP_ID);
    expect(await formField(r?.body, "target")).toBe("ui");
    expect(isFilePart(r?.body, "cert")).toBe(true);
  });
});

describe("A07 — import / replace 2xx bound to the REVIEWED candidate", () => {
  it("import: ca.fingerprint must be the reviewed candidate; previous.revision the fence", async () => {
    stub(json(IMPORT_RESULT));
    const out = await importCA({
      operationId: OP_ID,
      caRevision: FENCE,
      pem: PEM,
      candidateFingerprint: colonForm(HEX64_B),
    });
    expect(out.kind).toBe("ca");
    expect(out.action).toBe("ca.import");
    expect(out.ca.fingerprint).toBe(colonForm(HEX64_B));
    stub(json(IMPORT_RESULT));
    await unproven(
      importCA({
        operationId: OP_ID,
        caRevision: FENCE,
        pem: PEM,
        candidateFingerprint: CA_FP, // reviewed another certificate
      }),
    );
    stub(json({ ...IMPORT_RESULT, imported: false }));
    await unproven(
      importCA({
        operationId: OP_ID,
        caRevision: FENCE,
        pem: PEM,
        candidateFingerprint: colonForm(HEX64_B),
      }),
    );
    stub(json({ ...IMPORT_RESULT, target: "ui" }));
    await unproven(
      importCA({
        operationId: OP_ID,
        caRevision: FENCE,
        pem: PEM,
        candidateFingerprint: colonForm(HEX64_B),
      }),
    );
  });
  it("replace: candidate.fingerprint reviewed AND uiCert.revision = uic1:<PEM digest>", async () => {
    const args = {
      operationId: OP_ID,
      uiCertRevision: UI_FENCE,
      pem: PEM,
      candidateFingerprint: UI_CANDIDATE.fingerprint,
      certDigest: PEM_DIGEST,
    };
    stub(json(REPLACE_RESULT));
    const out = await replaceUICert(args);
    expect(out.kind).toBe("ui.replace");
    expect(out.activation).toBe("restart_required");
    expect(out.uiCert.revision).toBe(`uic1:${PEM_DIGEST}`);
    expect(out.uiCert.active).toBe(false);
    stub(json(REPLACE_RESULT));
    await unproven(replaceUICert({ ...args, certDigest: HEX64 }));
    stub(json(REPLACE_RESULT));
    await unproven(replaceUICert({ ...args, candidateFingerprint: CA_FP }));
    stub(json({ ...REPLACE_RESULT, activation: "immediate" }));
    await unproven(replaceUICert(args));
    stub(json({ ...REPLACE_RESULT, persisted: false }));
    await unproven(replaceUICert(args));
    stub(
      json({
        ...REPLACE_RESULT,
        uiCert: { ...REPLACE_RESULT.uiCert, pairState: "incomplete" },
      }),
    );
    await unproven(replaceUICert(args));
  });
});

describe("A08/A09 — delete and OCSP 2xx", () => {
  it("A08 delete: positively absent, bounded cleanup, optional activation", async () => {
    stub(json(DELETE_RESULT));
    const out = await deleteUICert({
      operationId: OP_ID,
      uiCertRevision: UI_FENCE,
    });
    expect(out.kind).toBe("ui.delete");
    expect(out.cleanup).toBe("complete");
    expect(out.activation).toBeUndefined();
    stub(json({ ...DELETE_RESULT, activation: "restart_required" }));
    expect(
      (await deleteUICert({ operationId: OP_ID, uiCertRevision: UI_FENCE }))
        .activation,
    ).toBe("restart_required");
    for (const bad of [
      { ...DELETE_RESULT, deleted: false },
      { ...DELETE_RESULT, cleanup: "partial" },
      { ...DELETE_RESULT, target: "mitm" },
      { ...DELETE_RESULT, activation: "immediate" },
      { ...DELETE_RESULT, uiCert: REPLACE_RESULT.uiCert },
      { ...DELETE_RESULT, operationId: OP_ID_2 },
    ]) {
      stub(json(bad));
      await unproven(
        deleteUICert({ operationId: OP_ID, uiCertRevision: UI_FENCE }),
      );
    }
  });
  it("A08 delete request: DELETE with operationId + fence in the query, no body", async () => {
    const calls = stub(json(DELETE_RESULT));
    await deleteUICert({ operationId: OP_ID, uiCertRevision: UI_FENCE });
    const c = calls[0];
    expect(c?.method).toBe("DELETE");
    const u = new URL(c?.url ?? "", "http://x");
    expect(u.pathname).toBe("/api/certs/ui");
    expect(u.searchParams.get("operationId")).toBe(OP_ID);
    expect(u.searchParams.get("uiCertRevision")).toBe(UI_FENCE);
    expect(c?.body).toBeUndefined();
  });
  it("A09 OCSP: ok + durable, a NEW revision, desired == requested with source admin", async () => {
    const calls = stub(json(OCSP_RESULT));
    const out = await setOCSPPosture({
      operationId: OP_ID,
      ocspRevision: OCSP_FENCE,
      enabled: true,
    });
    expect(out.kind).toBe("ocsp");
    expect(out.desired).toEqual({ enabled: true, source: "admin" });
    expect(out.revision).toBe(`ocr1:${HEX64_B}`);
    const c = calls[0];
    const u = new URL(c?.url ?? "", "http://x");
    expect(u.pathname).toBe("/api/ocsp");
    expect(u.searchParams.get("operationId")).toBe(OP_ID);
    expect(u.searchParams.get("ocspRevision")).toBe(OCSP_FENCE);
    expect(JSON.parse(String(c?.body))).toEqual({ enabled: true });
    for (const bad of [
      { ...OCSP_RESULT, desired: { enabled: false, source: "admin" } },
      { ...OCSP_RESULT, desired: { enabled: true, source: "yaml" } },
      { ...OCSP_RESULT, durable: false },
      { ...OCSP_RESULT, ok: false },
      { ...OCSP_RESULT, revision: OCSP_FENCE },
      { ...OCSP_RESULT, enabled: false },
      { ...OCSP_RESULT, action: "ca.rotate" },
    ]) {
      stub(json(bad));
      await unproven(
        setOCSPPosture({
          operationId: OP_ID,
          ocspRevision: OCSP_FENCE,
          enabled: true,
        }),
      );
    }
  });
});

describe("A10 — replay", () => {
  it("a replay carrying the recorded facts is a proven outcome; a bare replay is UNPROVEN", async () => {
    stub(json({ ...OCSP_RESULT, replayed: true }));
    const out = await setOCSPPosture({
      operationId: OP_ID,
      ocspRevision: OCSP_FENCE,
      enabled: true,
    });
    expect(out.replayed).toBe(true);
    stub(json({ ...ROTATE_RESULT, replayed: true, auditState: "pending" }));
    const r = await confirmCARotation({
      operationId: OP_ID,
      caRevision: FENCE,
      challenge: CHALLENGE,
      previousFingerprint: colonForm(HEX64),
    });
    expect(r.replayed).toBe(true);
    expect(r.auditState).toBe("pending");
    stub(
      json({ replayed: true, operationId: OP_ID, recordState: "committed" }),
    );
    await unproven(
      confirmCARotation({
        operationId: OP_ID,
        caRevision: FENCE,
        challenge: CHALLENGE,
        previousFingerprint: colonForm(HEX64),
      }),
    );
  });
});

describe("A11/A12/A13 — the refusal contract", () => {
  function httpErr(
    status: number,
    body: unknown,
    mediaType = "application/json",
  ): ApiError {
    return new ApiError(
      "http",
      `x: HTTP ${String(status)}`,
      status,
      typeof body === "string" ? body : JSON.stringify(body),
      mediaType,
    );
  }
  const verdicts: Array<[CertRefusalCode, number, Record<string, unknown>]> = [
    ["stale", 409, { caRevision: FENCE }],
    ["stale", 409, { uiCertRevision: UI_FENCE }],
    ["stale", 409, { ocspRevision: OCSP_FENCE }],
    ["precondition_required", 428, { caRevision: FENCE }],
    ["challenge_stale", 409, { changed: ["expired"] }],
    ["challenge_stale", 409, { changed: ["ca_revision", "actor"] }],
    ["challenge_required", 428, {}],
    ["candidate_invalid", 400, { reason: "key_mismatch" }],
    ["candidate_duplicate", 409, { caRevision: FENCE, fingerprint: CA_FP }],
    ["operation_id_required", 428, {}],
    [
      "operation_mismatch",
      409,
      { operationId: OP_ID, action: "ca.import", state: "committed" },
    ],
    ["operation_in_progress", 409, { operationId: OP_ID, state: "pending" }],
    [
      "operation_aborted",
      409,
      { operationId: OP_ID, state: "aborted", code: "persist_failed" },
    ],
    [
      "operation_outcome_unknown",
      409,
      { operationId: OP_ID, state: "outcome_unknown", code: "lookup_unproven" },
    ],
    ["persist_failed", 500, { class: "not_a_file", operationId: OP_ID }],
    ["persist_failed", 500, { operationId: OP_ID }],
    [
      "outcome_unknown",
      500,
      { detail: "refusal_not_durable", state: "pending", operationId: OP_ID },
    ],
    [
      "outcome_unknown",
      500,
      { detail: "durability_unproven", state: "pending", operationId: OP_ID },
    ],
    [
      "outcome_unknown",
      500,
      { detail: "transition_incomplete", state: "pending", operationId: OP_ID },
    ],
    ["ca_generation_failed", 500, {}],
    ["operation_ledger_degraded", 503, { reason: "corrupt" }],
    ["operation_ledger_full", 503, {}],
    ["operation_unsettled", 503, { reason: "persist_failed" }],
    ["persistence_not_configured", 503, {}],
    ["ca_not_ready", 503, {}],
    ["evidence_unavailable", 503, { uiCertRevision: "uic1:unavailable" }],
    ["not_found", 404, {}],
    ["forbidden", 403, {}],
    ["invalid_input", 400, {}],
    ["method_not_allowed", 405, {}],
  ];
  for (const [code, status, current] of verdicts) {
    it(`A11 ${code} @ ${String(status)} with ${JSON.stringify(current)} is a verdict`, () => {
      const r = asCertRefusal(httpErr(status, refusalBody(code, current)));
      expect(r?.code).toBe(code);
      expect(r?.status).toBe(status);
      expect(JSON.stringify(r)).not.toContain(RAW_CANARY);
      expect(certUnproven(httpErr(status, refusalBody(code, current)))).toBe(
        false,
      );
    });
  }
  const notVerdicts: Array<[string, ApiError]> = [
    [
      "stale on the wrong status",
      httpErr(400, refusalBody("stale", { caRevision: FENCE })),
    ],
    ["stale without its fence", httpErr(409, refusalBody("stale"))],
    [
      "challenge_stale without changed",
      httpErr(409, refusalBody("challenge_stale")),
    ],
    [
      "challenge_stale with a foreign changed class",
      httpErr(409, refusalBody("challenge_stale", { changed: ["nonce"] })),
    ],
    [
      "candidate_invalid without a reason",
      httpErr(400, refusalBody("candidate_invalid")),
    ],
    [
      "candidate_invalid with a foreign reason",
      httpErr(400, refusalBody("candidate_invalid", { reason: RAW_CANARY })),
    ],
    [
      "outcome_unknown without a detail",
      httpErr(
        500,
        refusalBody("outcome_unknown", {
          state: "pending",
          operationId: OP_ID,
        }),
      ),
    ],
    [
      "outcome_unknown with a foreign detail",
      httpErr(
        500,
        refusalBody("outcome_unknown", {
          detail: "maybe",
          state: "pending",
          operationId: OP_ID,
        }),
      ),
    ],
    [
      "operation_mismatch without the state",
      httpErr(409, refusalBody("operation_mismatch", { operationId: OP_ID })),
    ],
    ["a foreign code", httpErr(409, refusalBody("nope"))],
    ["text/plain", httpErr(409, "stale", "text/plain")],
    ["a JSON body of another shape", httpErr(409, { message: "stale" })],
  ];
  for (const [name, err] of notVerdicts) {
    it(`A11 not a verdict: ${name}`, () => {
      expect(asCertRefusal(err)).toBeNull();
    });
  }
  it("A12 certUnproven classification", () => {
    expect(certUnproven(new ApiError("network", "x"))).toBe(true);
    expect(certUnproven(new ApiError("timeout", "x"))).toBe(true);
    expect(certUnproven(new ApiError("aborted", "x"))).toBe(true);
    expect(certUnproven(new ApiError("contenttype", "x", 200))).toBe(true);
    expect(certUnproven(new ApiError("decode", "x", 200))).toBe(true);
    expect(certUnproven(httpErr(409, refusalBody("nope")))).toBe(true);
    expect(certUnproven(httpErr(502, "bad gateway", "text/html"))).toBe(true);
    expect(certUnproven(httpErr(403, refusalBody("forbidden")))).toBe(false);
    expect(certUnproven(new ApiError("target", "x"))).toBe(false);
  });
  it("A13 the nothing-written set is terminal only", () => {
    expect(CERT_TERMINAL_NOTHING_WRITTEN).not.toContain("outcome_unknown");
    expect(CERT_TERMINAL_NOTHING_WRITTEN).not.toContain(
      "operation_in_progress",
    );
    expect(CERT_TERMINAL_NOTHING_WRITTEN).not.toContain(
      "operation_outcome_unknown",
    );
    for (const c of [
      "stale",
      "precondition_required",
      "challenge_stale",
      "challenge_required",
      "candidate_invalid",
      "candidate_duplicate",
      "operation_id_required",
      "operation_aborted",
      "persist_failed",
      "persistence_not_configured",
      "ca_not_ready",
      "evidence_unavailable",
      "operation_ledger_degraded",
      "operation_ledger_full",
      "operation_unsettled",
      "not_found",
      "forbidden",
      "invalid_input",
    ])
      expect(CERT_TERMINAL_NOTHING_WRITTEN).toContain(c);
  });
});

describe("A14 — pemDigest", () => {
  it("is sha256 over the UTF-8 bytes (hexDigest(certPEM))", async () => {
    expect(await pemDigest("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(await pemDigest(CERT_PEM_CANARY)).toMatch(/^[0-9a-f]{64}$/);
  });
});
