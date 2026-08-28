// 2D-A.1 — shared-object decoder proofs (§25): full field decode of the
// category-group and decryption-profile list envelopes (incl. the durable
// store generation), the InspectHTTP2 tri-state fidelity, STRICT security-enum
// handling with the controlled per-profile DEGRADED state (an unknown value is
// never coerced — in particular never into inherit or fail-open), and the
// structured reference-block 409 recognizer.
import { describe, expect, it } from "vitest";
import {
  CERT_VERIFICATION_VALUES,
  ON_INSPECT_ERROR_VALUES,
  ON_UNSUPPORTED_VALUES,
  TLS_VERSION_VALUES,
  asReferenceBlock,
  decodeCategoryGroupList,
  decodeProfileList,
} from "../api/objects";
import { ApiError } from "../api/client";
import { DecodeError } from "../api/decode";

describe("category group decoding", () => {
  it("decodes the full envelope including the fence version", () => {
    const out = decodeCategoryGroupList({
      groups: [
        {
          id: "abc123def456",
          name: "Prod Allowed",
          categories: ["ai", "news"],
          created_at: "2026-08-01T00:00:00Z",
          updated_at: "2026-08-02T00:00:00Z",
        },
      ],
      names: ["Prod Allowed"],
      version: 7,
    });
    expect(out.version).toBe(7);
    expect(out.groups).toHaveLength(1);
    const g = out.groups[0];
    expect(g?.id).toBe("abc123def456");
    expect(g?.categories).toEqual(["ai", "news"]);
    expect(g?.updatedAt).toBe("2026-08-02T00:00:00Z");
  });

  it("tolerates null/absent groups and missing timestamps; requires id, name, version", () => {
    expect(
      decodeCategoryGroupList({ groups: null, names: null, version: 0 }),
    ).toEqual({
      groups: [],
      version: 0,
    });
    const out = decodeCategoryGroupList({
      groups: [{ id: "x", name: "N" }],
      names: [],
      version: 1,
    });
    expect(out.groups[0]?.categories).toEqual([]);
    expect(out.groups[0]?.createdAt).toBe("");
    expect(() => decodeCategoryGroupList({ groups: [], names: [] })).toThrow(
      DecodeError,
    );
    expect(() =>
      decodeCategoryGroupList({
        groups: [{ name: "no-id" }],
        names: [],
        version: 1,
      }),
    ).toThrow(DecodeError);
  });
});

describe("decryption profile decoding", () => {
  const base = {
    id: "p-1",
    name: "prof",
    created_at: "2026-08-01T00:00:00Z",
    updated_at: "2026-08-01T00:00:00Z",
  };

  it("keeps the InspectHTTP2 tri-state: absent and null are inherit, never false", () => {
    const absent = decodeProfileList({
      profiles: [base],
      names: [],
      version: 1,
    });
    expect(absent.profiles[0]?.inspectHttp2).toBeNull();
    const explicitNull = decodeProfileList({
      profiles: [{ ...base, inspectHttp2: null }],
      names: [],
      version: 1,
    });
    expect(explicitNull.profiles[0]?.inspectHttp2).toBeNull();
    const on = decodeProfileList({
      profiles: [{ ...base, inspectHttp2: true }],
      names: [],
      version: 1,
    });
    expect(on.profiles[0]?.inspectHttp2).toBe(true);
    const off = decodeProfileList({
      profiles: [{ ...base, inspectHttp2: false }],
      names: [],
      version: 1,
    });
    expect(off.profiles[0]?.inspectHttp2).toBe(false);
  });

  it("decodes every declared enum value; absent enum fields read as inherit", () => {
    for (const cv of CERT_VERIFICATION_VALUES) {
      for (const ou of ON_UNSUPPORTED_VALUES) {
        for (const oe of ON_INSPECT_ERROR_VALUES) {
          const out = decodeProfileList({
            profiles: [
              {
                ...base,
                certVerification: cv,
                onUnsupported: ou,
                onInspectError: oe,
                minTlsVersion: TLS_VERSION_VALUES[1],
                maxTlsVersion: TLS_VERSION_VALUES[2],
                stallTimeoutSecs: 30,
              },
            ],
            names: [],
            version: 3,
          });
          expect(out.degraded).toEqual([]);
          expect(out.profiles[0]?.certVerification).toBe(cv);
          expect(out.profiles[0]?.onInspectError).toBe(oe);
        }
      }
    }
    const inherit = decodeProfileList({
      profiles: [base],
      names: [],
      version: 1,
    });
    expect(inherit.profiles[0]?.certVerification).toBe("");
    expect(inherit.profiles[0]?.stallTimeoutSecs).toBe(0);
  });

  it("never offers or accepts the retired permissive value", () => {
    expect(CERT_VERIFICATION_VALUES).not.toContain("permissive");
    const out = decodeProfileList({
      profiles: [{ ...base, certVerification: "permissive" }],
      names: [],
      version: 1,
    });
    expect(out.profiles).toEqual([]);
    expect(out.degraded).toHaveLength(1);
  });

  it("surfaces an unknown security enum as a DEGRADED entry — never coerced", () => {
    const out = decodeProfileList({
      profiles: [
        {
          ...base,
          id: "bad-1",
          name: "weird",
          onInspectError: "fail-sideways",
        },
        { ...base, id: "ok-1", name: "fine", onInspectError: "fail-close" },
      ],
      names: [],
      version: 5,
    });
    expect(out.profiles).toHaveLength(1);
    expect(out.profiles[0]?.id).toBe("ok-1");
    expect(out.degraded).toHaveLength(1);
    expect(out.degraded[0]).toMatchObject({ id: "bad-1", name: "weird" });
    expect(out.degraded[0]?.reason).toContain("onInspectError");
    expect(out.version).toBe(5);
  });

  it("requires the fence version on the envelope", () => {
    expect(() => decodeProfileList({ profiles: [], names: [] })).toThrow(
      DecodeError,
    );
  });
});

describe("reference-block 409 recognizer", () => {
  const body = JSON.stringify({
    error: 'cannot delete category-group "G": referenced by policy rule "r1"',
    object: { type: "category-group", name: "G" },
    referencedBy: [
      {
        consumerType: "access-rule",
        id: "01J3ZV9E3JD0AAAAAAAAAAAAAA",
        name: "r1",
        detail: "destCategoryGroup",
        view: "policy",
      },
    ],
  });

  it("recognizes the structured shape", () => {
    const err = new ApiError("http", "conflict", 409, body);
    const block = asReferenceBlock(err);
    expect(block).not.toBeNull();
    expect(block?.object).toEqual({ type: "category-group", name: "G" });
    expect(block?.referencedBy[0]?.id).toBe("01J3ZV9E3JD0AAAAAAAAAAAAAA");
    expect(block?.error).toContain("referenced by policy rule");
  });

  it("returns null for non-409s, unstructured bodies, and the version-conflict shape", () => {
    expect(
      asReferenceBlock(new ApiError("http", "nope", 500, body)),
    ).toBeNull();
    expect(
      asReferenceBlock(new ApiError("http", "nope", 409, "plain text")),
    ).toBeNull();
    expect(
      asReferenceBlock(
        new ApiError(
          "http",
          "conflict",
          409,
          JSON.stringify({ error: "e", currentVersion: 2, yourVersion: 1 }),
        ),
      ),
    ).toBeNull();
    expect(asReferenceBlock(new Error("not api"))).toBeNull();
  });
});
