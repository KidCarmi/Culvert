// FE-6A.2 CORRECTION RED — API/decoding half, written against the frozen
// FE-6A.2 candidate 64da0df0 BEFORE any product change.
//
//   CA1  the legacy import is FENCED and OPERATION-IDENTIFIED: POST
//        /api/idp/legacy-ldap/import?documentRevision=&operationId= (bodiless).
//   CA2  its 2xx is ACTION-BOUND: imported:true, a DISABLED ldap identity,
//        the resulting documentRevision, the echoed operationId and the
//        legacy source identity (never a credential). An unrelated disabled
//        LDAP profile, a wrong operationId or an enabled profile is UNPROVEN.
//   CA3  a replay {replayed:true, id, operationId} is the replayed kind.
//   CA4  `preflight_failed` is a contracted 422 refusal carrying ONLY the
//        bounded step + reason facts; an unknown step is not a verdict.
//   CA5  the ledger action vocabulary carries `idp.import`.
//   CA6  the import candidate digest is deterministic, non-secret and moves
//        with the legacy source identity.
//
// On 64da0df0 this file fails at type-check/import resolution
// (importLegacyLDAP takes no fence, the outcome/refusal/digest exports do not
// exist).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import {
  IDP_OPERATION_ACTIONS,
  IDP_REFUSAL_CONTRACT,
  asIdPRefusal,
  idpUnproven,
  importCandidateDigest,
  importLegacyLDAP,
} from "../api/idp";
import {
  LEGACY_PRESENT,
  LEGACY_URL,
  OP_ID,
  RAW,
  SOURCE_TOKEN,
  jsonResponse,
  ldapProfileAnswer,
} from "./fe6a2-fixtures";

interface Call {
  url: string;
  method: string;
  rawBody: unknown;
}
let calls: Call[];
let answer: (c: Call) => Response | Promise<Response>;

beforeEach(() => {
  calls = [];
  answer = () => jsonResponse({}, 500);
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const c: Call = {
        url: String(input),
        method: init?.method ?? "GET",
        rawBody: init?.body,
      };
      calls.push(c);
      return Promise.resolve(answer(c));
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const httpErr = (status: number, body: unknown): ApiError =>
  new ApiError("http", `HTTP ${String(status)}`, status, JSON.stringify(body));

const IMPORTED = {
  imported: true,
  id: "imp000000001",
  name: "Imported legacy LDAP",
  type: "ldap",
  enabled: false,
  revision: 1,
  documentRevision: "r-doc-2",
  operationId: OP_ID,
  importSourceRevision: SOURCE_TOKEN,
  source: { url: LEGACY_URL, baseDn: "DC=legacy", bindDn: "cn=svc,dc=legacy" },
  cluster: { publication: "published", version: 9 },
};

describe("CA1 fenced, operation-identified import", () => {
  it("POSTs bodiless with the document fence and the operationId in the query", async () => {
    answer = () => jsonResponse(IMPORTED);
    await importLegacyLDAP({
      documentRevision: "r-doc-1",
      operationId: OP_ID,
      importSourceRevision: SOURCE_TOKEN,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.url).toBe(
      `/api/idp/legacy-ldap/import?documentRevision=r-doc-1&operationId=${OP_ID}&importSourceRevision=${encodeURIComponent(SOURCE_TOKEN)}`,
    );
    expect(calls[0]?.rawBody).toBeUndefined();
  });
});

describe("CA2 action-bound import outcome", () => {
  it("accepts only an answer that proves THIS import", async () => {
    answer = () => jsonResponse(IMPORTED);
    const out = await importLegacyLDAP({
      documentRevision: "r-doc-1",
      operationId: OP_ID,
      importSourceRevision: SOURCE_TOKEN,
    });
    expect(out).toEqual({
      kind: "imported",
      id: "imp000000001",
      name: "Imported legacy LDAP",
      revision: 1,
      documentRevision: "r-doc-2",
      operationId: OP_ID,
      importSourceRevision: SOURCE_TOKEN,
      source: { url: LEGACY_URL },
    });
  });
  it("an unrelated DISABLED ldap profile is not proof of this import (UNPROVEN)", async () => {
    answer = () =>
      jsonResponse(
        ldapProfileAnswer("imp000000001", 1, { name: "Imported legacy LDAP" }),
      );
    const err = await importLegacyLDAP({
      documentRevision: "r-doc-1",
      operationId: OP_ID,
      importSourceRevision: SOURCE_TOKEN,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(idpUnproven(err)).toBe(true);
  });
  it("a wrong operationId, an enabled profile, a missing source or a credential is refused", async () => {
    for (const bad of [
      { ...IMPORTED, operationId: "6a2e0000-0000-4000-8000-00000000dead" },
      { ...IMPORTED, enabled: true },
      { ...IMPORTED, source: undefined },
      { ...IMPORTED, source: { url: LEGACY_URL, bindPassword: "x" } },
      { ...IMPORTED, imported: false },
      { ...IMPORTED, type: "oidc" },
    ]) {
      answer = () => jsonResponse(bad);
      await expect(
        importLegacyLDAP({
          documentRevision: "r-doc-1",
          operationId: OP_ID,
          importSourceRevision: SOURCE_TOKEN,
        }),
      ).rejects.toBeInstanceOf(ApiError);
    }
  });
});

describe("CA3 replay", () => {
  it("a replayed record bound to the dispatched operation is the replayed kind", async () => {
    answer = () =>
      jsonResponse({
        id: "imp000000001",
        operationId: OP_ID,
        importSourceRevision: SOURCE_TOKEN,
        settled: true,
        replayed: true,
      });
    const out = await importLegacyLDAP({
      documentRevision: "r-doc-1",
      operationId: OP_ID,
      importSourceRevision: SOURCE_TOKEN,
    });
    expect(out).toEqual({
      kind: "replayed",
      id: "imp000000001",
      importSourceRevision: SOURCE_TOKEN,
      operationId: OP_ID,
    });
  });
});

describe("CA4 preflight_failed is a bounded refusal", () => {
  it("is contracted at 422 with step + reason facts only", () => {
    expect(IDP_REFUSAL_CONTRACT.preflight_failed).toEqual({
      status: 422,
      required: ["step", "reason"],
    });
    const r = asIdPRefusal(
      httpErr(422, {
        error: RAW,
        code: "preflight_failed",
        current: { step: "reachable", reason: "unreachable", detail: RAW },
      }),
    );
    expect(r?.code).toBe("preflight_failed");
    expect(r?.facts.step).toBe("reachable");
    expect(r?.facts.reason).toBe("unreachable");
    expect(JSON.stringify(r)).not.toContain(RAW);
  });
  it("an unknown step, an unknown reason or the wrong status is not a verdict", () => {
    for (const bad of [
      httpErr(422, {
        code: "preflight_failed",
        current: { step: "smoke", reason: "unreachable" },
      }),
      httpErr(422, {
        code: "preflight_failed",
        current: { step: "reachable", reason: RAW },
      }),
      httpErr(400, {
        code: "preflight_failed",
        current: { step: "reachable", reason: "unreachable" },
      }),
    ]) {
      expect(asIdPRefusal(bad)).toBeNull();
      expect(idpUnproven(bad)).toBe(true);
    }
  });
});

describe("CA5 ledger action vocabulary", () => {
  it("carries idp.import", () => {
    expect(IDP_OPERATION_ACTIONS).toContain("idp.import");
  });
});

describe("CA6 import candidate digest", () => {
  it("is deterministic, hex, and moves with the source identity", () => {
    const a = importCandidateDigest(LEGACY_PRESENT);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
    expect(importCandidateDigest({ ...LEGACY_PRESENT })).toBe(a);
    expect(
      importCandidateDigest({
        ...LEGACY_PRESENT,
        url: "ldap://other.corp.example:389",
      }),
    ).not.toBe(a);
    // The bind-credential PRESENCE indicator is not identity: the digest
    // never encodes anything about the credential.
    expect(
      importCandidateDigest({
        ...LEGACY_PRESENT,
        bindCredentialConfigured: false,
      }),
    ).toBe(a);
  });
});
