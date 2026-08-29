// 2D-C — File Profile + Header Rewrite decoder/helper proofs: coherent-state
// decode (profiles + rewrite rules WITH the content-derived revision fence),
// built-in derivation from the deterministic ID prefix, EVALUATION-ORDER
// preservation for rewrite rules (order is semantics — the decoder must never
// sort), the normalization preview mirror, the structured-editor line
// parsers, and the shared structured revision-409 recognizer against the 2D-C
// bodies.
import { describe, expect, it } from "vitest";
import {
  decodeFileProfileState,
  decodeRewriteState,
  previewNormalizedExtensions,
  summarizeOps,
} from "../api/dcobjects";
import {
  parseHeaderMapLines,
  parseHeaderNameLines,
} from "../features/policy/HeaderRewritePage";
import { asRevisionConflict } from "../api/urlcat";
import { ApiError } from "../api/client";
import { DecodeError } from "../api/decode";

describe("file profile state decoding", () => {
  it("decodes profiles with the revision fence and derives builtIn from the ID", () => {
    const out = decodeFileProfileState({
      profiles: [
        {
          id: "builtin-executables",
          name: "Executables",
          extensions: [".exe", ".msi"],
        },
        { id: "a1b2c3d4-0000-1111-2222-333344445555", name: "Custom Set" },
      ],
      revision: "fpv1:abc123",
    });
    expect(out.revision).toBe("fpv1:abc123");
    expect(out.profiles).toHaveLength(2);
    expect(out.profiles[0]?.builtIn).toBe(true);
    expect(out.profiles[0]?.extensions).toEqual([".exe", ".msi"]);
    expect(out.profiles[1]?.builtIn).toBe(false);
    expect(out.profiles[1]?.extensions).toEqual([]);
  });

  it("tolerates null/absent profiles but requires id and revision", () => {
    expect(decodeFileProfileState({ profiles: null, revision: "r" })).toEqual({
      profiles: [],
      revision: "r",
    });
    expect(decodeFileProfileState({ revision: "r" }).profiles).toEqual([]);
    expect(() => decodeFileProfileState({ profiles: [] })).toThrow(DecodeError);
    expect(() =>
      decodeFileProfileState({
        profiles: [{ name: "no-id" }],
        revision: "r",
      }),
    ).toThrow(DecodeError);
  });
});

describe("rewrite state decoding", () => {
  const ruleA = {
    id: 1,
    stableId: "11111111-aaaa-bbbb-cccc-000000000001",
    host: "*.example.com",
    req_set: { "X-Env": "prod" },
    req_add: { "X-Trace": "on" },
    req_remove: ["X-Debug"],
    resp_set: { Server: "culvert" },
    resp_add: {},
    resp_remove: ["X-Powered-By"],
  };
  const ruleB = {
    id: 2,
    stableId: "11111111-aaaa-bbbb-cccc-000000000002",
    host: "",
  };

  it("decodes full rules and preserves EVALUATION order verbatim", () => {
    const out = decodeRewriteState({
      rules: [ruleB, ruleA],
      revision: "rwv1:deadbeef",
    });
    expect(out.revision).toBe("rwv1:deadbeef");
    // Order is semantics: B was first on the wire, B stays first.
    expect(out.rules.map((r) => r.stableId)).toEqual([
      ruleB.stableId,
      ruleA.stableId,
    ]);
    const a = out.rules[1];
    expect(a?.legacyId).toBe(1);
    expect(a?.host).toBe("*.example.com");
    expect(a?.reqSet).toEqual({ "X-Env": "prod" });
    expect(a?.reqAdd).toEqual({ "X-Trace": "on" });
    expect(a?.reqRemove).toEqual(["X-Debug"]);
    expect(a?.respSet).toEqual({ Server: "culvert" });
    expect(a?.respRemove).toEqual(["X-Powered-By"]);
    // Absent maps/lists decode to empty, never throw.
    const b = out.rules[0];
    expect(b?.host).toBe("");
    expect(b?.reqSet).toEqual({});
    expect(b?.respRemove).toEqual([]);
  });

  it("tolerates a pre-backfill rule without stableId (renders, not addressable)", () => {
    const out = decodeRewriteState({
      rules: [{ id: 7, host: "h" }],
      revision: "r",
    });
    expect(out.rules[0]?.stableId).toBe("");
    expect(out.rules[0]?.legacyId).toBe(7);
  });

  it("requires the revision and the legacy numeric id", () => {
    expect(() => decodeRewriteState({ rules: [] })).toThrow(DecodeError);
    expect(() =>
      decodeRewriteState({ rules: [{ stableId: "s" }], revision: "r" }),
    ).toThrow(DecodeError);
  });
});

describe("extension normalization preview (UX mirror; server authoritative)", () => {
  it("lowercases, adds the leading dot, dedupes, drops empties", () => {
    expect(
      previewNormalizedExtensions([" EXE ", ".exe", "Msi", "", ".", "  "]),
    ).toEqual([".exe", ".msi"]);
  });
});

describe("header line parsers (structured editor)", () => {
  it("parses Header-Name: value lines and flags malformed lines", () => {
    const out = parseHeaderMapLines(
      "X-Env: prod\n\n X-Trace :  on \nbroken-line\n: novalue",
    );
    expect(out.map).toEqual({ "X-Env": "prod", "X-Trace": "on" });
    expect(out.errors).toHaveLength(2);
  });

  it("parses one header name per line for Remove sections", () => {
    expect(parseHeaderNameLines(" X-Debug \n\nX-Powered-By")).toEqual([
      "X-Debug",
      "X-Powered-By",
    ]);
  });
});

describe("ops summary", () => {
  it("summarizes set/add/remove compactly and renders — when empty", () => {
    expect(summarizeOps({ A: "1" }, { B: "2" }, ["C"])).toBe(
      "set A, add B, remove C",
    );
    expect(summarizeOps({}, {}, [])).toBe("—");
  });
});

describe("shared revision-409 recognizer against the 2D-C bodies", () => {
  it("recognizes the structured conflict from both surfaces", () => {
    const err = new ApiError(
      "http",
      "conflict",
      409,
      JSON.stringify({
        error: "revision conflict",
        currentRevision: "rwv1:new",
        yourRevision: "rwv1:old",
      }),
    );
    const c = asRevisionConflict(err);
    expect(c?.currentRevision).toBe("rwv1:new");
    expect(c?.yourRevision).toBe("rwv1:old");
  });
});
