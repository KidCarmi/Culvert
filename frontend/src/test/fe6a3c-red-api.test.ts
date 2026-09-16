// FE-6A.2 CORRECTION ROUND 3 RED — API/decoder half, written against the
// frozen corrected candidate eb90ebc5 BEFORE any product change (Blocker 1:
// the import must be bound to the legacy source the administrator REVIEWED).
//
//   CB1  the legacy read model's present block carries the server-owned
//        `importSourceRevision` (keyed, non-disclosing commitment over every
//        security-effective imported field); a present block WITHOUT it is
//        refused (incomplete evidence, never a default).
//   CB2  the import fence carries the reviewed token: the POST query sends
//        it, and a 2xx is proven ONLY when it echoes the exact token — a
//        different token (the server imported a different source) is
//        UNPROVEN on both the imported and the replayed branch.
//   CB3  the reviewed token is part of the marker's non-secret candidate
//        identity: two legacy blocks differing only in the token differ.
//   CB4  the two structured refusals are in the contract: 428
//        import_source_required and 409 import_source_stale carrying the
//        current token as a typed fact (never a server string).
//
// On eb90ebc5 every row fails: the decoder has no such field, the fence
// has no such member, the digest ignores it, the codes are unknown.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { isRecord } from "../api/decode";
import {
  IDP_REFUSAL_CONTRACT,
  asIdPRefusal,
  decodeLegacyLDAP,
  idpUnproven,
  importCandidateDigest,
  importLegacyLDAP,
} from "../api/idp";
import {
  LEGACY_PRESENT,
  LEGACY_URL,
  OP_ID,
  OTHER_SOURCE_TOKEN,
  RAW,
  SOURCE_TOKEN,
  jsonResponse,
} from "./fe6a2-fixtures";

interface Call {
  url: string;
  method: string;
}
let calls: Call[];
let answer: (c: Call) => Response | Promise<Response>;

beforeEach(() => {
  calls = [];
  answer = () => jsonResponse({}, 500);
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const c: Call = { url: String(input), method: init?.method ?? "GET" };
      calls.push(c);
      return Promise.resolve(answer(c));
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const rec = (v: unknown): Record<string, unknown> => {
  if (!isRecord(v)) throw new Error("not a record");
  return v;
};

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

const FENCE = {
  documentRevision: "r-doc-1",
  operationId: OP_ID,
  importSourceRevision: SOURCE_TOKEN,
} as const;

describe("CB1 the legacy read model publishes the reviewed-source token", () => {
  it("a present block carries importSourceRevision", () => {
    const l = decodeLegacyLDAP(LEGACY_PRESENT);
    expect(l.present).toBe(true);
    if (l.present) expect(l.importSourceRevision).toBe(SOURCE_TOKEN);
  });
  it("a present block WITHOUT the token is refused as incomplete evidence", () => {
    const without = Object.fromEntries(
      Object.entries(LEGACY_PRESENT).filter(
        ([k]) => k !== "importSourceRevision",
      ),
    );
    expect(() => decodeLegacyLDAP(without)).toThrow();
  });
  it("a token that is not a keyed commitment is refused", () => {
    expect(() =>
      decodeLegacyLDAP({ ...LEGACY_PRESENT, importSourceRevision: RAW }),
    ).toThrow();
    expect(() =>
      decodeLegacyLDAP({ ...LEGACY_PRESENT, importSourceRevision: "" }),
    ).toThrow();
  });
});

describe("CB2 the import is dispatched with, and proven by, the reviewed token", () => {
  it("the POST query carries importSourceRevision", async () => {
    answer = () => jsonResponse(IMPORTED);
    await importLegacyLDAP(FENCE);
    expect(calls).toHaveLength(1);
    const q = new URL(calls[0]?.url ?? "", "http://x").searchParams;
    expect(q.get("importSourceRevision")).toBe(SOURCE_TOKEN);
    expect(q.get("documentRevision")).toBe("r-doc-1");
    expect(q.get("operationId")).toBe(OP_ID);
  });
  it("a 2xx echoing the exact token is the proven import and carries it", async () => {
    answer = () => jsonResponse(IMPORTED);
    const out = await importLegacyLDAP(FENCE);
    expect(out.kind).toBe("imported");
    expect(rec(out)["importSourceRevision"]).toBe(SOURCE_TOKEN);
  });
  it("a 2xx echoing a DIFFERENT token is UNPROVEN (a different source was imported)", async () => {
    answer = () =>
      jsonResponse({ ...IMPORTED, importSourceRevision: OTHER_SOURCE_TOKEN });
    const err = await importLegacyLDAP(FENCE).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(idpUnproven(err)).toBe(true);
  });
  it("a 2xx WITHOUT the token is UNPROVEN", async () => {
    const without = Object.fromEntries(
      Object.entries(IMPORTED).filter(([k]) => k !== "importSourceRevision"),
    );
    answer = () => jsonResponse(without);
    const err = await importLegacyLDAP(FENCE).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(idpUnproven(err)).toBe(true);
  });
  it("a replay is proven only when it echoes the reviewed token", async () => {
    answer = () =>
      jsonResponse({
        replayed: true,
        id: "imp000000001",
        operationId: OP_ID,
        importSourceRevision: SOURCE_TOKEN,
      });
    const out = await importLegacyLDAP(FENCE);
    expect(out.kind).toBe("replayed");
    answer = () =>
      jsonResponse({
        replayed: true,
        id: "imp000000001",
        operationId: OP_ID,
        importSourceRevision: OTHER_SOURCE_TOKEN,
      });
    const err = await importLegacyLDAP(FENCE).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(idpUnproven(err)).toBe(true);
  });
});

describe("CB3 the reviewed token is part of the marker's candidate identity", () => {
  it("two legacy blocks differing only in importSourceRevision differ", () => {
    const a = decodeLegacyLDAP(LEGACY_PRESENT);
    const b = decodeLegacyLDAP({
      ...LEGACY_PRESENT,
      importSourceRevision: OTHER_SOURCE_TOKEN,
    });
    if (!a.present || !b.present) throw new Error("fixtures must be present");
    expect(importCandidateDigest(a)).not.toBe(importCandidateDigest(b));
    expect(importCandidateDigest(a)).toBe(importCandidateDigest(a));
  });
});

describe("CB4 the structured source refusals are contracted", () => {
  it("import_source_required is a 428 and import_source_stale a 409 with the current token", () => {
    const c: Readonly<
      Record<string, { status: number; required: readonly string[] }>
    > = IDP_REFUSAL_CONTRACT;
    expect(c["import_source_required"]?.status).toBe(428);
    expect(c["import_source_stale"]?.status).toBe(409);
    expect(c["import_source_stale"]?.required).toContain(
      "importSourceRevision",
    );
    const stale = asIdPRefusal(
      new ApiError(
        "http",
        "HTTP 409",
        409,
        JSON.stringify({
          error: RAW,
          code: "import_source_stale",
          current: { importSourceRevision: OTHER_SOURCE_TOKEN, detail: RAW },
        }),
      ),
    );
    expect(stale?.code).toBe("import_source_stale");
    expect(rec(stale?.facts)["importSourceRevision"]).toBe(OTHER_SOURCE_TOKEN);
    expect(JSON.stringify(stale?.facts)).not.toContain(RAW);
    // A stale token without the current one is not a verdict.
    expect(
      asIdPRefusal(
        new ApiError(
          "http",
          "HTTP 409",
          409,
          JSON.stringify({ error: RAW, code: "import_source_stale" }),
        ),
      ),
    ).toBeNull();
  });
});
