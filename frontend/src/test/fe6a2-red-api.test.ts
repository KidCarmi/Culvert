// FE-6A.2 RED matrix — Identity Provider MUTATION API rows, written against
// the frozen FE-6A.1 baseline 98d4a6c8 BEFORE any product change. Every row
// fails at import resolution today (api/idp.ts is GET-only by construction).
//
//   A1  every mutation sends the contracted verb, path, fence and body —
//       secrets ride in the body ONCE, never in the URL; explicit clear is
//       the empty string; an omitted secret key means "keep".
//   A2  success is ACTION-BOUND: identity (id / type / name), revision
//       movement and durability facts are required; a wrong identity, a
//       missing commit fact or a contradictory result is a decode failure
//       (⇒ UNPROVEN), never success.
//   A3  a replayed answer is accepted ONLY when it names the dispatched
//       operationId; the replay's minimal settled shape is bound the same way.
//   A4  unknown / malformed refusal codes are not verdicts: asIdPRefusal is
//       null and the outcome is UNPROVEN; a recognised refusal with its
//       contracted status and required facts is a verdict.
//   A5  wrong Content-Type and transport loss are UNPROVEN; nothing retries.
//   A6  the LDAP directory test: client deadline ≥ the 45 s server bound;
//       ok:false is a FAILED test; a 2xx without `ok` is never "passed";
//       step errors are a closed vocabulary; the test credential never
//       reaches the URL.
//   A7  discovery decodes only the endpoint URLs; import is bound to a
//       DISABLED ldap profile; repair is bound to the confirmed evidence.
//   A8  the candidate identity is NON-SECRET (independent of secret values,
//       sensitive to every public fact) and the wire body carries no read-only
//       indicator keys.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { DecodeError, isRecord } from "../api/decode";

const rec = (v: unknown): Record<string, unknown> => {
  if (!isRecord(v)) throw new Error("not a record");
  return v;
};
import {
  IDP_OPERATION_ACTIONS,
  IDP_TEST_STEP_ERRORS,
  IDP_TEST_TIMEOUT_MS,
  asIdPRefusal,
  candidateDigest,
  createIdP,
  deleteIdP,
  discoverOIDC,
  idpUnproven,
  idpWriteBody,
  importLegacyLDAP,
  repairIdPRegistry,
  specCarriesSecret,
  testIdP,
  updateIdP,
} from "../api/idp";
import type { IdPWriteSpec } from "../api/idp";
import {
  BIND_PASSWORD,
  CLIENT_SECRET,
  LDAP_SPEC,
  LEGACY_URL,
  OIDC_SPEC,
  OP_ID,
  QUARANTINE,
  RAW,
  SOURCE_TOKEN,
  SAML_SPEC,
  TEST_PASSWORD,
  jsonResponse,
  ldapProfileAnswer,
  oidcProfileAnswer,
} from "./fe6a2-fixtures";

interface Call {
  url: string;
  method: string;
  body: unknown;
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
      const raw = init?.body;
      const c: Call = {
        url: String(input),
        method: init?.method ?? "GET",
        body: typeof raw === "string" ? JSON.parse(raw) : undefined,
        rawBody: raw,
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

describe("A1 verbs, fences and bodies", () => {
  it("create: POST /api/idp?documentRevision&operationId, secret once in the body", async () => {
    answer = () =>
      jsonResponse(
        oidcProfileAnswer("a1b2c3d4e5f6", 1, { operationId: OP_ID }),
      );
    await createIdP(OIDC_SPEC, {
      documentRevision: "r-doc-1",
      operationId: OP_ID,
    });
    expect(calls).toHaveLength(1);
    const c = calls[0];
    expect(c?.method).toBe("POST");
    expect(c?.url).toBe(
      `/api/idp?documentRevision=r-doc-1&operationId=${OP_ID}`,
    );
    expect(c?.url).not.toContain(CLIENT_SECRET);
    expect(c?.body).toEqual(idpWriteBody(OIDC_SPEC));
    const body = rec(c?.body);
    const oidc = rec(body["oidc"]);
    expect(oidc["clientSecret"]).toBe(CLIENT_SECRET);
    expect("clientSecretConfigured" in oidc).toBe(false);
    expect("id" in body).toBe(false);
    expect("revision" in body).toBe(false);
    expect("operationId" in body).toBe(false);
  });

  it("create carrying the cutover adds the server confirm value to the query", async () => {
    const spec: IdPWriteSpec = { ...LDAP_SPEC, enabled: true };
    answer = () =>
      jsonResponse(
        ldapProfileAnswer("ldap00000001", 1, {
          enabled: true,
          operationId: OP_ID,
        }),
      );
    await createIdP(spec, {
      documentRevision: "r-doc-1",
      operationId: OP_ID,
      cutoverConfirm: LEGACY_URL,
    });
    expect(calls[0]?.url).toBe(
      `/api/idp?documentRevision=r-doc-1&operationId=${OP_ID}&cutoverConfirm=${encodeURIComponent(LEGACY_URL)}`,
    );
    expect(calls[0]?.url).not.toContain(BIND_PASSWORD);
  });

  it("update: PUT /api/idp/{id}?revision — omitted secret keeps, empty string clears", async () => {
    const keep: IdPWriteSpec = {
      ...OIDC_SPEC,
      oidc: { ...OIDC_SPEC.oidc, clientSecret: undefined },
    };
    answer = () => jsonResponse(oidcProfileAnswer("a1b2c3d4e5f6", 4));
    await updateIdP("a1b2c3d4e5f6", keep, { revision: 3 });
    expect(calls[0]?.method).toBe("PUT");
    expect(calls[0]?.url).toBe("/api/idp/a1b2c3d4e5f6?revision=3");
    const body1 = rec(calls[0]?.body);
    expect("clientSecret" in rec(body1["oidc"])).toBe(false);
    const clear: IdPWriteSpec = {
      ...OIDC_SPEC,
      oidc: { ...OIDC_SPEC.oidc, clientSecret: "" },
    };
    answer = () =>
      jsonResponse(
        oidcProfileAnswer("a1b2c3d4e5f6", 5, {
          oidc: { issuer: "https://issuer.example", clientId: "culvert" },
        }),
      );
    await updateIdP("a1b2c3d4e5f6", clear, { revision: 4 });
    expect(rec(calls[1]?.body)["oidc"]).toMatchObject({
      clientSecret: "",
    });
  });

  it("update carrying the cutover adds operationId and cutoverConfirm", async () => {
    const spec: IdPWriteSpec = {
      ...LDAP_SPEC,
      enabled: true,
      ldap: { ...LDAP_SPEC.ldap, bindPassword: undefined },
    };
    answer = () =>
      jsonResponse(
        ldapProfileAnswer("ldap00000001", 2, {
          enabled: true,
          operationId: OP_ID,
        }),
      );
    await updateIdP("ldap00000001", spec, {
      revision: 1,
      operationId: OP_ID,
      cutoverConfirm: LEGACY_URL,
    });
    expect(calls[0]?.url).toBe(
      `/api/idp/ldap00000001?revision=1&operationId=${OP_ID}&cutoverConfirm=${encodeURIComponent(LEGACY_URL)}`,
    );
  });

  it("delete: DELETE /api/idp/{id}?revision, bodiless", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        deleted: true,
        id: "a1b2c3d4e5f6",
        revision: "r-doc-2",
        persisted: true,
        cluster: { publication: "published", version: 9 },
      });
    await deleteIdP("a1b2c3d4e5f6", 3);
    expect(calls[0]?.method).toBe("DELETE");
    expect(calls[0]?.url).toBe("/api/idp/a1b2c3d4e5f6?revision=3");
    expect(calls[0]?.rawBody).toBeUndefined();
  });

  it("repair: POST /api/idp/repair {confirm}; import: bodiless POST; discover: POST {issuer}", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        repaired: true,
        evidence: QUARANTINE,
        revision: "r-doc-0",
      });
    await repairIdPRegistry(QUARANTINE);
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.url).toBe("/api/idp/repair");
    expect(calls[0]?.body).toEqual({ confirm: QUARANTINE });
    // FE-6A.2 correction: the import is fenced + operation-identified and its
    // answer is action-bound (see fe6a2c-red-api.test.ts).
    answer = () =>
      jsonResponse({
        ...ldapProfileAnswer("imp000000001", 1, {
          name: "Imported legacy LDAP",
        }),
        imported: true,
        documentRevision: "r-doc-2",
        operationId: OP_ID,
        importSourceRevision: SOURCE_TOKEN,
        source: { url: LEGACY_URL },
      });
    await importLegacyLDAP({
      documentRevision: "r-doc-1",
      operationId: OP_ID,
      importSourceRevision: SOURCE_TOKEN,
    });
    expect(calls[1]?.method).toBe("POST");
    expect(calls[1]?.url).toBe(
      `/api/idp/legacy-ldap/import?documentRevision=r-doc-1&operationId=${OP_ID}&importSourceRevision=${encodeURIComponent(SOURCE_TOKEN)}`,
    );
    expect(calls[1]?.rawBody).toBeUndefined();
    answer = () =>
      jsonResponse({ authorization_endpoint: "https://issuer.example/auth" });
    await discoverOIDC("https://issuer.example");
    expect(calls[2]?.method).toBe("POST");
    expect(calls[2]?.url).toBe("/api/idp/discover");
    expect(calls[2]?.body).toEqual({ issuer: "https://issuer.example" });
  });
});

describe("A2 success is action-bound", () => {
  it("create binds identity, type, name, revision ≥ 1 and the fleet fact", async () => {
    answer = () =>
      jsonResponse(
        oidcProfileAnswer("a1b2c3d4e5f6", 1, { operationId: OP_ID }),
      );
    const out = await createIdP(OIDC_SPEC, {
      documentRevision: "r-doc-1",
      operationId: OP_ID,
    });
    expect(out.kind).toBe("written");
    if (out.kind !== "written") throw new Error("unreachable");
    expect(out.profile.id).toBe("a1b2c3d4e5f6");
    expect(out.profile.revision).toBe(1);
    expect(out.cluster).toEqual({ publication: "published", version: 7 });
    expect(out.operationId).toBe(OP_ID);
  });

  it("create REFUSES a wrong type, a wrong name, a missing cluster fact, a foreign operationId", async () => {
    const cases: Array<Record<string, unknown>> = [
      oidcProfileAnswer("x", 1, {
        type: "ldap",
        oidc: undefined,
        ldap: { url: "ldaps://x", bindDn: "", baseDn: "dc=x" },
        operationId: OP_ID,
      }),
      oidcProfileAnswer("x", 1, { name: "Somebody else", operationId: OP_ID }),
      oidcProfileAnswer("x", 1, { cluster: undefined, operationId: OP_ID }),
      oidcProfileAnswer("x", 1, {
        operationId: "6a2e0000-0000-4000-8000-0000deadbeef",
      }),
      oidcProfileAnswer("x", 1), // dispatched with an operationId, answer carries none
    ];
    for (const body of cases) {
      calls = [];
      answer = () => jsonResponse(body);
      await expect(
        createIdP(OIDC_SPEC, {
          documentRevision: "r-doc-1",
          operationId: OP_ID,
        }),
      ).rejects.toBeInstanceOf(ApiError);
      expect(calls).toHaveLength(1); // never retried
    }
  });

  it("update binds the path id and requires the revision to have MOVED past the fence", async () => {
    answer = () => jsonResponse(oidcProfileAnswer("other0000000", 4));
    await expect(
      updateIdP("a1b2c3d4e5f6", OIDC_SPEC, { revision: 3 }),
    ).rejects.toBeInstanceOf(ApiError);
    answer = () => jsonResponse(oidcProfileAnswer("a1b2c3d4e5f6", 3));
    await expect(
      updateIdP("a1b2c3d4e5f6", OIDC_SPEC, { revision: 3 }),
    ).rejects.toBeInstanceOf(ApiError);
    answer = () => jsonResponse(oidcProfileAnswer("a1b2c3d4e5f6", 4));
    const out = await updateIdP("a1b2c3d4e5f6", OIDC_SPEC, { revision: 3 });
    expect(out.kind).toBe("written");
  });

  it("delete requires ok+deleted+the same id; a contradictory answer is unproven", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        deleted: true,
        id: "someone-else",
        revision: "r",
        persisted: true,
        cluster: { publication: "published", version: 1 },
      });
    await expect(deleteIdP("a1b2c3d4e5f6", 3)).rejects.toBeInstanceOf(ApiError);
    answer = () =>
      jsonResponse({
        ok: true,
        deleted: false,
        id: "a1b2c3d4e5f6",
        revision: "r",
        persisted: true,
        cluster: { publication: "published", version: 1 },
      });
    await expect(deleteIdP("a1b2c3d4e5f6", 3)).rejects.toBeInstanceOf(ApiError);
    answer = () =>
      jsonResponse({
        ok: true,
        deleted: true,
        id: "a1b2c3d4e5f6",
        persisted: true,
        cluster: { publication: "published", version: 1 },
      });
    await expect(deleteIdP("a1b2c3d4e5f6", 3)).rejects.toBeInstanceOf(ApiError); // no revision fact
    answer = () =>
      jsonResponse({
        ok: true,
        deleted: true,
        id: "a1b2c3d4e5f6",
        revision: "r-doc-2",
        persisted: true,
        cluster: { publication: "rejected", reason: "snapshot_invalid" },
      });
    const out = await deleteIdP("a1b2c3d4e5f6", 3);
    expect(out.cluster).toEqual({
      publication: "rejected",
      reason: "snapshot_invalid",
    });
    answer = () =>
      jsonResponse({
        ok: true,
        deleted: true,
        id: "a1b2c3d4e5f6",
        revision: "r",
        persisted: true,
        cluster: { publication: "rejected", reason: RAW },
      });
    await expect(deleteIdP("a1b2c3d4e5f6", 3)).rejects.toBeInstanceOf(ApiError); // unbounded reason
  });

  it("a 2xx that is not JSON, or whose profile carries secret material, is unproven", async () => {
    answer = () => jsonResponse("not an object");
    await expect(
      createIdP(OIDC_SPEC, { documentRevision: "r", operationId: OP_ID }),
    ).rejects.toBeInstanceOf(ApiError);
    answer = () =>
      jsonResponse(
        oidcProfileAnswer("a1b2c3d4e5f6", 1, {
          operationId: OP_ID,
          oidc: {
            issuer: "https://issuer.example",
            clientId: "culvert",
            clientSecret: CLIENT_SECRET,
          },
        }),
      );
    await expect(
      createIdP(OIDC_SPEC, { documentRevision: "r", operationId: OP_ID }),
    ).rejects.toBeInstanceOf(ApiError);
  });
});

describe("A3 replay", () => {
  it("accepts the minimal settled shape only for the dispatched operationId", async () => {
    answer = () =>
      jsonResponse({
        id: "a1b2c3d4e5f6",
        operationId: OP_ID,
        settled: "lookup",
        replayed: true,
      });
    const out = await createIdP(OIDC_SPEC, {
      documentRevision: "r",
      operationId: OP_ID,
    });
    expect(out).toEqual({
      kind: "replayed",
      id: "a1b2c3d4e5f6",
      operationId: OP_ID,
    });
    answer = () =>
      jsonResponse({
        id: "a1b2c3d4e5f6",
        operationId: "6a2e0000-0000-4000-8000-0000deadbeef",
        replayed: true,
      });
    await expect(
      createIdP(OIDC_SPEC, { documentRevision: "r", operationId: OP_ID }),
    ).rejects.toBeInstanceOf(ApiError);
    answer = () => jsonResponse({ operationId: OP_ID, replayed: true }); // no id ⇒ no identity
    await expect(
      createIdP(OIDC_SPEC, { documentRevision: "r", operationId: OP_ID }),
    ).rejects.toBeInstanceOf(ApiError);
  });
  it("a full replayed profile is a written outcome that still names the operation", async () => {
    answer = () =>
      jsonResponse(
        oidcProfileAnswer("a1b2c3d4e5f6", 1, {
          operationId: OP_ID,
          replayed: true,
        }),
      );
    const out = await createIdP(OIDC_SPEC, {
      documentRevision: "r",
      operationId: OP_ID,
    });
    expect(out.kind === "written" ? out.operationId : null).toBe(OP_ID);
  });
});

describe("A4 refusals are verdicts only inside the contract", () => {
  it("recognised codes with their contracted status and facts", () => {
    const stale = asIdPRefusal(
      httpErr(409, { error: RAW, code: "stale", current: { revision: 7 } }),
    );
    expect(stale?.code).toBe("stale");
    expect(stale?.facts.revision).toBe(7);
    const doc = asIdPRefusal(
      httpErr(409, {
        error: RAW,
        code: "stale",
        current: { documentRevision: "r-doc-9" },
      }),
    );
    expect(doc?.facts.documentRevision).toBe("r-doc-9");
    const pre = asIdPRefusal(
      httpErr(428, {
        error: RAW,
        code: "precondition_required",
        current: { documentRevision: "r-doc-1" },
      }),
    );
    expect(pre?.facts.documentRevision).toBe("r-doc-1");
    const compile = asIdPRefusal(
      httpErr(502, {
        error: RAW,
        code: "provider_compile_failed",
        current: { reason: "oidc_discovery" },
      }),
    );
    expect(compile?.facts.reason).toBe("oidc_discovery");
    const referenced = asIdPRefusal(
      httpErr(409, {
        error: RAW,
        code: "referenced",
        current: {
          revision: 3,
          references: [
            {
              consumerType: "auth-rule",
              id: "01RULE",
              name: "SSO staff",
              detail: "providerRefs",
              view: "authpolicy",
            },
          ],
        },
      }),
    );
    expect(referenced?.facts.references).toEqual([
      {
        consumerType: "auth-rule",
        id: "01RULE",
        name: "SSO staff",
        detail: "providerRefs",
        view: "authpolicy",
      },
    ]);
    const confirm = asIdPRefusal(
      httpErr(409, {
        error: RAW,
        code: "confirm_mismatch",
        current: { confirmValue: QUARANTINE },
      }),
    );
    expect(confirm?.facts.confirmValue).toBe(QUARANTINE);
    const cut = asIdPRefusal(
      httpErr(428, {
        error: RAW,
        code: "cutover_confirm_required",
        current: { confirmValue: LEGACY_URL },
      }),
    );
    expect(cut?.facts.confirmValue).toBe(LEGACY_URL);
    const mismatch = asIdPRefusal(
      httpErr(409, {
        error: RAW,
        code: "operation_mismatch",
        current: { operationId: OP_ID, state: "committed" },
      }),
    );
    expect(mismatch?.facts.operationId).toBe(OP_ID);
    const unknown = asIdPRefusal(
      httpErr(500, {
        error: RAW,
        code: "outcome_unknown",
        current: {
          detail: "operation_record_not_durable",
          operationId: OP_ID,
          id: "a1b2c3d4e5f6",
        },
      }),
    );
    expect(unknown?.facts.detail).toBe("operation_record_not_durable");
    for (const r of [
      stale,
      doc,
      pre,
      compile,
      referenced,
      confirm,
      cut,
      mismatch,
      unknown,
    ]) {
      expect(r).not.toBeNull();
      expect(JSON.stringify(r?.facts)).not.toContain(RAW);
    }
  });
  it("unknown codes, wrong statuses, missing facts and raw reasons are NOT verdicts (⇒ unproven)", () => {
    const bad = [
      httpErr(409, { error: RAW, code: "made_up_code" }),
      httpErr(200, { error: RAW, code: "stale", current: { revision: 7 } }),
      httpErr(500, { error: RAW, code: "stale", current: { revision: 7 } }), // wrong status
      httpErr(409, { error: RAW, code: "stale" }), // no fence fact
      httpErr(428, { error: RAW, code: "precondition_required" }),
      httpErr(502, {
        error: RAW,
        code: "provider_compile_failed",
        current: { reason: RAW },
      }),
      httpErr(409, {
        error: RAW,
        code: "referenced",
        current: { revision: 3, references: "nope" },
      }),
      httpErr(409, {
        error: RAW,
        code: "confirm_mismatch",
        current: { confirmValue: "/data/idp_profiles.json.corrupt.1" },
      }),
      httpErr(500, RAW),
    ];
    for (const e of bad) {
      expect(asIdPRefusal(e), e.bodyText).toBeNull();
      expect(idpUnproven(e), e.bodyText).toBe(true);
    }
    expect(
      idpUnproven(
        httpErr(409, { error: RAW, code: "stale", current: { revision: 7 } }),
      ),
    ).toBe(false);
    expect(
      idpUnproven(
        new ApiError("http", "forbidden", 403, '{"code":"forbidden"}'),
      ),
    ).toBe(false);
    expect(
      idpUnproven(new ApiError("http", "unauthorized", 401, "Unauthorized")),
    ).toBe(false);
  });
});

describe("A5 wrong media type and transport loss", () => {
  it("a 200 text/plain answer is contenttype ⇒ unproven, sent exactly once", async () => {
    answer = () =>
      new Response("ok", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    const err = await createIdP(OIDC_SPEC, {
      documentRevision: "r",
      operationId: OP_ID,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err instanceof ApiError ? err.kind : null).toBe("contenttype");
    expect(idpUnproven(err)).toBe(true);
    expect(calls).toHaveLength(1);
  });
  it("a network death is unproven and is never retried", async () => {
    answer = () => Promise.reject(new TypeError("Failed to fetch"));
    const err = await deleteIdP("a1b2c3d4e5f6", 3).catch((e: unknown) => e);
    expect(idpUnproven(err)).toBe(true);
    expect(calls).toHaveLength(1);
  });
});

describe("A6 the LDAP directory test", () => {
  it("client deadline is at least 60 s (server watchdog 45 s + dial 5 s)", () => {
    expect(IDP_TEST_TIMEOUT_MS).toBeGreaterThanOrEqual(60_000);
  });
  it("sends the candidate and the transient credential in the body only", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        steps: [
          { name: "reachable", label: "Reachable", ok: true, durationMs: 3 },
        ],
      });
    await testIdP(
      { ...LDAP_SPEC, id: "ldap00000001" },
      { username: "alice", password: TEST_PASSWORD },
    );
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.url).toBe("/api/idp/test");
    expect(calls[0]?.url).not.toContain(TEST_PASSWORD);
    const body = rec(calls[0]?.body);
    expect(body["testUsername"]).toBe("alice");
    expect(body["testPassword"]).toBe(TEST_PASSWORD);
    expect(rec(body["profile"])["id"]).toBe("ldap00000001");
    expect(rec(body["profile"])["type"]).toBe("ldap");
  });
  it("ok:false is a FAILED test; a 2xx without ok, or with an unknown step error, is unproven", async () => {
    answer = () =>
      jsonResponse({
        ok: false,
        steps: [
          {
            name: "service_bind",
            label: "Bind",
            ok: false,
            error: "invalid_credentials",
            detail: RAW,
          },
        ],
      });
    const rep = await testIdP(LDAP_SPEC, {});
    expect(rep.ok).toBe(false);
    expect(rep.steps[0]?.error).toBe("invalid_credentials");
    expect(JSON.stringify(rep)).not.toContain(RAW); // server prose is dropped at the boundary
    answer = () => jsonResponse({ steps: [] });
    await expect(testIdP(LDAP_SPEC, {})).rejects.toBeInstanceOf(ApiError);
    answer = () =>
      jsonResponse({
        ok: true,
        steps: [{ name: "reachable", label: "x", ok: false, error: RAW }],
      });
    await expect(testIdP(LDAP_SPEC, {})).rejects.toBeInstanceOf(ApiError);
    expect(IDP_TEST_STEP_ERRORS).toEqual([
      "timeout",
      "tls_failed",
      "unreachable",
      "invalid_credentials",
      "no_such_object",
      "insufficient_access",
      "directory_error",
    ]);
  });
});

describe("A7 discovery, import, repair", () => {
  it("discovery decodes only https endpoint URLs and drops everything else", async () => {
    answer = () =>
      jsonResponse({
        authorization_endpoint: "https://issuer.example/auth",
        token_endpoint: "https://issuer.example/token",
        jwks_uri: "https://issuer.example/jwks",
        foo: RAW,
        userinfo_endpoint: "http://plain.example/u",
      });
    const d = await discoverOIDC("https://issuer.example");
    expect(d).toEqual({
      authorizationEndpoint: "https://issuer.example/auth",
      tokenEndpoint: "https://issuer.example/token",
      jwksUri: "https://issuer.example/jwks",
    });
    expect(JSON.stringify(d)).not.toContain(RAW);
  });
  it("import is bound to a DISABLED ldap profile", async () => {
    const fence = {
      documentRevision: "r-doc-1",
      operationId: OP_ID,
      importSourceRevision: SOURCE_TOKEN,
    };
    const bound = {
      imported: true,
      documentRevision: "r-doc-2",
      operationId: OP_ID,
      importSourceRevision: SOURCE_TOKEN,
      source: { url: LEGACY_URL },
    };
    answer = () =>
      jsonResponse({
        ...ldapProfileAnswer("imp000000001", 1, { enabled: true }),
        ...bound,
      });
    await expect(importLegacyLDAP(fence)).rejects.toBeInstanceOf(ApiError);
    answer = () =>
      jsonResponse({ ...oidcProfileAnswer("imp000000001", 1), ...bound });
    await expect(importLegacyLDAP(fence)).rejects.toBeInstanceOf(ApiError);
    answer = () =>
      jsonResponse({ ...ldapProfileAnswer("imp000000001", 1), ...bound });
    const out = await importLegacyLDAP(fence);
    expect(out.kind).toBe("imported");
    if (out.kind === "imported") expect(out.source.url).toBe(LEGACY_URL);
  });
  it("repair is bound to ok+repaired+the confirmed evidence", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        repaired: true,
        evidence: "idp_profiles.json.corrupt.999",
        revision: "r",
      });
    await expect(repairIdPRegistry(QUARANTINE)).rejects.toBeInstanceOf(
      ApiError,
    );
    answer = () =>
      jsonResponse({
        ok: true,
        repaired: false,
        evidence: QUARANTINE,
        revision: "r",
      });
    await expect(repairIdPRegistry(QUARANTINE)).rejects.toBeInstanceOf(
      ApiError,
    );
    answer = () =>
      jsonResponse({
        ok: true,
        repaired: true,
        evidence: QUARANTINE,
        revision: "r-doc-0",
      });
    const r = await repairIdPRegistry(QUARANTINE);
    expect(r.evidence).toBe(QUARANTINE);
  });
});

describe("A8 candidate identity and body hygiene", () => {
  it("the candidate digest ignores secret VALUES, tracks secret PRESENCE and every public fact", () => {
    const a = candidateDigest(OIDC_SPEC);
    expect(a).toMatch(/^[0-9a-f]{16,64}$/);
    expect(
      candidateDigest({
        ...OIDC_SPEC,
        oidc: { ...OIDC_SPEC.oidc, clientSecret: "another-value" },
      }),
    ).toBe(a);
    expect(
      candidateDigest({
        ...OIDC_SPEC,
        oidc: { ...OIDC_SPEC.oidc, clientSecret: undefined },
      }),
    ).not.toBe(a);
    expect(candidateDigest({ ...OIDC_SPEC, name: "Corp OIDC 2" })).not.toBe(a);
    expect(candidateDigest({ ...OIDC_SPEC, enabled: false })).not.toBe(a);
    expect(candidateDigest(LDAP_SPEC)).not.toBe(
      candidateDigest({
        ...LDAP_SPEC,
        ldap: { ...LDAP_SPEC.ldap, bindPassword: undefined },
      }),
    );
    expect(a).not.toContain(CLIENT_SECRET);
    expect(specCarriesSecret(OIDC_SPEC)).toBe(true);
    expect(
      specCarriesSecret({
        ...OIDC_SPEC,
        oidc: { ...OIDC_SPEC.oidc, clientSecret: undefined },
      }),
    ).toBe(false);
    expect(
      specCarriesSecret({
        ...OIDC_SPEC,
        oidc: { ...OIDC_SPEC.oidc, clientSecret: "" },
      }),
    ).toBe(false); // a clear carries no material
    expect(specCarriesSecret(SAML_SPEC)).toBe(true);
    expect(specCarriesSecret(LDAP_SPEC)).toBe(true);
  });
  it("the write body never carries read-only indicator keys and sends exactly one sub-config", () => {
    for (const spec of [OIDC_SPEC, SAML_SPEC, LDAP_SPEC]) {
      const body = idpWriteBody(spec);
      const sub = ["oidc", "saml", "ldap"].filter((k) => k in body);
      expect(sub).toEqual([spec.type]);
      const s = JSON.stringify(body);
      for (const k of [
        "clientSecretConfigured",
        "inlineMetadataConfigured",
        "bindCredentialConfigured",
        "revision",
        "operationId",
      ]) {
        expect(s).not.toContain(`"${k}"`);
      }
    }
    expect(IDP_OPERATION_ACTIONS).toEqual([
      "idp.create",
      "idp.update",
      "idp.import",
    ]);
    expect(() => new DecodeError("$", "x", 1)).not.toThrow();
  });
});
