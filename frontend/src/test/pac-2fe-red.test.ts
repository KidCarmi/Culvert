// 2F-E RED matrix (pure modules) — written against the merged 2F-E entry
// gate head (e8ae527a, frozen 2F-D d6bdd622 + origin/main 290e3768) BEFORE
// any PAC frontend code exists. On that tree every test fails at import
// resolution (`src/api/pac`, `src/features/network/pac/*` do not exist).
// Each assertion pins a contract the React surface must honour verbatim:
//
//   A1  the lifecycle GET decodes with every 2F-A/2F-B field and REJECTS an
//       unknown state / historyState enum (never silently maps).
//   A2  the 2F-A fence (428 precondition_required / 409 stale) is decoded
//       structurally with the server-owned `current` token — never parsed
//       from prose.
//   A3  the bound DIRECT challenge (409 confirm_required / challenge_stale)
//       is decoded with challenge, confirmValue, newDirectPaths and the
//       `changed` list, and the `binding` is preserved VERBATIM for echo.
//   A4  publish sends action/operationId/draft/expectedActiveRevision and,
//       on retry, the confirm echo {challenge, value, binding} BYTE-EQUAL to
//       what the server issued; the retired `confirmDirect` is never sent.
//   A5  DELETEs carry the token in the QUERY only (no body).
//   A6  the recovery classifier is total over the lifecycle GET: landed
//       (CORRECTED in the 2F-E correction round — see the case comment)
//       (decided op with our id), pending (pendingOp is ours), ambiguous
//       (ambiguous.op is ours), not_landed (absent) with baseMoved when the
//       expected active tokens no longer hold.
//   A7  the durable recovery marker: write-before-dispatch verified by
//       read-back, subject-bound, UUID grammar, unreadable ≠ none.
import { describe, expect, it, beforeEach, vi } from "vitest";
import { DecodeError } from "../api/decode";
import {
  asPacChallenge,
  asPacFence,
  asPacHistoryReset,
  decodePacLifecycle,
  deletePacProfile,
  mintPacOperationId,
  publishPacProfile,
} from "../api/pac";
import { classifyRecovery } from "../features/network/pac/pacLifecycle";
import {
  PAC_RECOVERY_KEY,
  clearPacRecovery,
  readPacRecovery,
  writePacRecovery,
} from "../features/network/pac/pacRecovery";
import { ApiError } from "../api/client";

const RULE = {
  kind: "domain",
  pattern: "intranet.example",
  action: "direct",
};
const ACTIVE = {
  id: "hq",
  name: "HQ",
  description: "",
  enabled: true,
  poolId: "p1",
  rules: [],
  privateNetworks: "proxy",
  availabilityMode: "secure",
  revision: 3,
};
const DRAFT = { ...ACTIVE, rules: [RULE], revision: 0 };
const OP_ID = "8c1f2b9e-6f3a-4c1d-9b0e-3a2f1d4c5b6a";
const LC = {
  profileId: "hq",
  activeExists: true,
  active: ACTIVE,
  draft: DRAFT,
  draftDirty: true,
  activeN: 2,
  revisions: [
    {
      n: 1,
      spec: ACTIVE,
      digest: "a1",
      author: "admin",
      ts: "2026-09-04T10:00:00Z",
      operationId: "11111111-1111-4111-8111-111111111111",
      specDigest: "sha256:aaaa",
      poolDigest: "sha256:pppp",
    },
    {
      n: 2,
      spec: ACTIVE,
      digest: "a2",
      author: "admin",
      ts: "2026-09-04T11:00:00Z",
      specDigest: "sha256:bbbb",
      poolDigest: "sha256:pppp",
    },
  ],
  draftDiff: {
    rulesAdded: ["rule 1: direct domain intranet.example"],
    rulesReordered: false,
    poolChanged: false,
    newDirectPaths: ["rule: direct domain intranet.example"],
    securitySensitive: true,
  },
  draftRevision: 4,
  activeRevision: 3,
  collectionEtag: "sha256:coll",
  state: "idle",
  historyState: "recorded",
  pendingOp: null,
  ambiguous: null,
  operations: [
    {
      operationId: "11111111-1111-4111-8111-111111111111",
      action: "publish",
      state: "recorded",
      ts: "2026-09-04T10:00:00Z",
      status: 200,
      result: null,
    },
  ],
  activeSpecDigest: "sha256:bbbb",
  poolChangedSince: false,
  scope: "node-local",
  historyIncarnation: "a1a1a1a1-0000-4000-8000-000000000001",
  previousRevision: 1,
};

function apiErr(status: number, body: unknown): ApiError {
  return new ApiError("http", "refused", status, JSON.stringify(body));
}

describe("A1 lifecycle decoder", () => {
  it("decodes every field and keeps operations/revisions/diff", () => {
    const lc = decodePacLifecycle(LC);
    expect(lc.profileId).toBe("hq");
    expect(lc.activeExists).toBe(true);
    expect(lc.active?.revision).toBe(3);
    expect(lc.draft?.rules).toHaveLength(1);
    expect(lc.draftRevision).toBe(4);
    expect(lc.activeRevision).toBe(3);
    expect(lc.collectionEtag).toBe("sha256:coll");
    expect(lc.state).toBe("idle");
    expect(lc.historyState).toBe("recorded");
    expect(lc.operations[0]?.operationId).toBe(
      "11111111-1111-4111-8111-111111111111",
    );
    expect(lc.revisions.map((r) => r.n)).toEqual([1, 2]);
    expect(lc.draftDiff?.newDirectPaths).toEqual([
      "rule: direct domain intranet.example",
    ]);
    expect(lc.activeSpecDigest).toBe("sha256:bbbb");
    expect(lc.scope).toBe("node-local");
    expect(lc.previousRevision).toBe(1);
  });
  it("rejects an unknown state enum instead of mapping it", () => {
    expect(() => decodePacLifecycle({ ...LC, state: "settled" })).toThrow(
      DecodeError,
    );
    expect(() => decodePacLifecycle({ ...LC, historyState: "fine" })).toThrow(
      DecodeError,
    );
  });
});

describe("A2 fence decoder", () => {
  it("decodes 428 precondition_required and 409 stale with the server token", () => {
    const pre = asPacFence(
      apiErr(428, {
        error:
          "precondition required: echo the current revision you loaded (3)",
        code: "precondition_required",
        current: { revision: 3 },
      }),
    );
    expect(pre).toEqual({
      status: 428,
      code: "precondition_required",
      current: { revision: 3 },
      message:
        "precondition required: echo the current revision you loaded (3)",
    });
    const stale = asPacFence(
      apiErr(409, {
        error: "stale revision 2 (current 3)",
        code: "stale",
        current: { revision: 3 },
      }),
    );
    expect(stale?.code).toBe("stale");
    expect(stale?.current["revision"]).toBe(3);
  });
  it("is null for non-fence refusals", () => {
    expect(asPacFence(apiErr(409, { code: "confirm_required" }))).toBeNull();
    expect(asPacFence(new ApiError("network", "lost"))).toBeNull();
  });
});

const BINDING = {
  profileId: "hq",
  action: "publish",
  targetN: 0,
  candidateSpecDigest: "sha256:1a2b3c4d5e6f",
  expectedActiveRevision: 3,
  expectedActiveSpecDigest: "sha256:bbbb",
  poolDigest: "sha256:pppp",
  artifactDigest: "sha256:arti",
  newDirectPaths: ["rule: direct domain intranet.example"],
};
const CHALLENGE = {
  error: "this change introduces new DIRECT paths",
  code: "confirm_required",
  confirmField: "confirm",
  challenge: "v1:deadbeef",
  confirmValue: "hq:1a2b3c4d",
  binding: BINDING,
};

describe("A3 challenge decoder", () => {
  it("decodes confirm_required with the binding preserved verbatim", () => {
    const c = asPacChallenge(apiErr(409, CHALLENGE));
    expect(c?.code).toBe("confirm_required");
    expect(c?.challenge).toBe("v1:deadbeef");
    expect(c?.confirmValue).toBe("hq:1a2b3c4d");
    expect(c?.newDirectPaths).toEqual(BINDING.newDirectPaths);
    expect(c?.binding).toEqual(BINDING);
    expect(c?.changed).toEqual([]);
  });
  it("decodes challenge_stale with the changed list", () => {
    const c = asPacChallenge(
      apiErr(409, {
        ...CHALLENGE,
        code: "challenge_stale",
        changed: ["poolDigest", "artifactDigest"],
      }),
    );
    expect(c?.code).toBe("challenge_stale");
    expect(c?.changed).toEqual(["poolDigest", "artifactDigest"]);
  });
  it("decodes the history_reset refusal with the ack binding", () => {
    const r = asPacHistoryReset(
      apiErr(409, {
        error: "history quarantined",
        code: "history_reset",
        historyState: "history_reset",
        ackAction: "acknowledge_history_reset",
        current: { revision: 3, activeSpecDigest: "sha256:bbbb" },
        historyReset: {
          at: "2026-09-04T09:00:00Z",
          quarantinedTo: "/data/pac_profiles_lifecycle.json.corrupt.1",
          cause: "decode",
          scoped: true,
          activeAtReset: ["hq"],
          acknowledgedProfiles: 0,
          ackAction: "acknowledge_history_reset",
        },
      }),
    );
    expect(r?.activeRevision).toBe(3);
    expect(r?.activeSpecDigest).toBe("sha256:bbbb");
    expect(r?.reset.quarantinedTo).toContain(".corrupt.");
  });
});

describe("A4/A5 request shapes", () => {
  let calls: Array<{ method: string; url: string; body: unknown }>;
  beforeEach(() => {
    calls = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: unknown, init?: RequestInit) => {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        calls.push({ method: init?.method ?? "GET", url: String(input), body });
        return Promise.resolve(
          new Response(
            JSON.stringify({
              operationId: OP_ID,
              activeRevision: 4,
              activeSpecDigest: "sha256:1a2b3c4d5e6f",
              digest: "arti",
              draftRevision: 4,
              historyState: "recorded",
              scope: "node-local-history",
              published: true,
              revision: 3,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          ),
        );
      }),
    );
  });
  it("publish carries the client operationId, the reviewed draft and the fence; the confirm echo is verbatim", async () => {
    const res = await publishPacProfile("hq", {
      operationId: OP_ID,
      draft: DRAFT,
      expectedActiveRevision: 3,
      collectionEtag: "sha256:coll",
      historyIncarnation: "a1a1a1a1-0000-4000-8000-000000000001",
      reason: "rollout",
      confirm: {
        challenge: "v1:deadbeef",
        value: "hq:1a2b3c4d",
        binding: BINDING,
      },
    });
    expect(res.published).toBe(true);
    expect(res.historyState).toBe("recorded");
    const c = calls[0];
    expect(c?.method).toBe("POST");
    expect(c?.url).toBe("/api/pac/profiles/hq/lifecycle");
    const b = c?.body;
    if (typeof b !== "object" || b === null) throw new Error("no body");
    const rec = b;
    expect(rec).toMatchObject({
      action: "publish",
      operationId: OP_ID,
      expectedActiveRevision: 3,
      collectionEtag: "sha256:coll",
      reason: "rollout",
      confirm: {
        challenge: "v1:deadbeef",
        value: "hq:1a2b3c4d",
        binding: BINDING,
      },
    });
    expect("confirmDirect" in rec).toBe(false);
    expect("draft" in rec).toBe(true);
  });
  it("delete profile carries the revision as a query parameter and no body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: unknown, init?: RequestInit) => {
        calls.push({
          method: init?.method ?? "GET",
          url: String(input),
          body: init?.body,
        });
        return Promise.resolve(new Response(null, { status: 204 }));
      }),
    );
    await deletePacProfile("hq", 3);
    expect(calls[0]?.url).toBe("/api/pac/profiles/hq?revision=3");
    expect(calls[0]?.method).toBe("DELETE");
    expect(calls[0]?.body).toBeUndefined();
  });
  it("mints RFC 4122 UUIDs for operation identity (the server requires a UUID)", () => {
    const id = mintPacOperationId();
    expect(id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(mintPacOperationId()).not.toBe(id);
  });
});

describe("A6 recovery classifier", () => {
  const marker = {
    operationId: OP_ID,
    action: "publish" as const,
    profileId: "hq",
    expectedActiveRevision: 3,
    expectedActiveSpecDigest: "sha256:bbbb",
    candidateSpecDigest: "sha256:1a2b3c4d5e6f",
    targetN: 0,
    startedAt: 1,
    // fixture completion (2F-E correction round 2): the continuity bindings
    collectionEtag: "sha256:coll",
    historyIncarnation: "a1a1a1a1-0000-4000-8000-000000000001",
  };
  it("landed when a decided operation carries our id", () => {
    const lc = decodePacLifecycle({
      ...LC,
      activeRevision: 4,
      activeSpecDigest: "sha256:1a2b3c4d5e6f",
      operations: [
        {
          operationId: OP_ID,
          action: "publish",
          state: "recorded",
          ts: "t",
          status: 200,
          result: null,
        },
      ],
    });
    // CORRECTED ASSERTION (2F-E correction round): the landed resolution now
    // also states whether the candidate reached the store (committed), the
    // history revision it produced (revisionN — 0 here: the fixture's
    // revisions carry other operation ids) and whether that revision is the
    // one served right now (currentlyActive) — "committed historically" is
    // distinguished from "currently active". The original expectation was
    // exactly {kind:"landed", state:"recorded", status:200}; those three
    // values are unchanged.
    expect(classifyRecovery(marker, lc)).toEqual({
      kind: "landed",
      state: "recorded",
      status: 200,
      committed: true,
      revisionN: 0,
      currentlyActive: false,
    });
  });
  it("pending when the pending op is ours; ambiguous when the ambiguity names us", () => {
    const pending = decodePacLifecycle({
      ...LC,
      state: "pending",
      historyState: "pending_reconciliation",
      pendingOp: { operationId: OP_ID, action: "publish", state: "committed" },
    });
    expect(classifyRecovery(marker, pending).kind).toBe("pending");
    const amb = decodePacLifecycle({
      ...LC,
      state: "ambiguous",
      historyState: "ambiguous",
      ambiguous: {
        op: { operationId: OP_ID, action: "publish", state: "ambiguous" },
        observedRevision: 9,
        observedSpecDigest: "sha256:zzzz",
        observedAt: "t",
      },
    });
    expect(classifyRecovery(marker, amb).kind).toBe("ambiguous");
  });
  // CORRECTED ASSERTION (2F-E correction round). As committed in b976566c
  // this case endorsed "absent from the lifecycle GET ⇒ not_landed" in both
  // branches. That rule was WRONG: the GET lists only the 20 most recent
  // decided operations (the appliance retains 64), a history reset empties
  // the ring, and a request that has not yet reached intent persistence is
  // absent while it can still commit. Absence is therefore evidence of
  // nothing on its own. The corrected contract: with the base UNCHANGED an
  // absent operation stays UNRESOLVED (not_observed); only a COMPLETE ring
  // plus a MOVED fence (the appliance can no longer commit it) proves
  // non-commit. The original expected values are recorded here verbatim so
  // the change is transparent: {kind:"not_landed", baseMoved:false} and
  // {kind:"not_landed", baseMoved:true}.
  it("absent + base unchanged is UNRESOLVED; absent + complete ring + moved fence is the only proven non-commit", () => {
    expect(classifyRecovery(marker, decodePacLifecycle(LC))).toEqual({
      kind: "unresolved",
      reason: "not_observed",
    });
    expect(
      classifyRecovery(
        marker,
        decodePacLifecycle({
          ...LC,
          activeRevision: 7,
          activeSpecDigest: "sha256:other",
        }),
      ),
    ).toEqual({ kind: "not_landed", proof: "fence_moved" });
  });
});

describe("A7 recovery marker", () => {
  const m = {
    operationId: OP_ID,
    action: "publish" as const,
    profileId: "hq",
    expectedActiveRevision: 3,
    expectedActiveSpecDigest: "sha256:bbbb",
    candidateSpecDigest: "sha256:1a2b3c4d5e6f",
    targetN: 0,
    startedAt: 1700000000000,
    // fixture completion (2F-E correction round 2): the continuity bindings
    collectionEtag: "sha256:coll",
    historyIncarnation: "a1a1a1a1-0000-4000-8000-000000000001",
  };
  beforeEach(() => {
    sessionStorage.clear();
    vi.restoreAllMocks();
  });
  it("write verifies by read-back and is subject-bound", () => {
    expect(writePacRecovery("admin", m)).toBe(true);
    expect(readPacRecovery("admin")).toEqual({ kind: "valid", marker: m });
    expect(readPacRecovery("someone-else")).toEqual({ kind: "none" });
    // 2F-E correction (finding 2): the clear is ownership-matched — it names
    // the operation it resolves. The expected outcome is unchanged.
    clearPacRecovery(m.operationId);
    expect(readPacRecovery("admin")).toEqual({ kind: "none" });
  });
  it("a corrupting storage fails the write (no marker ⇒ no dispatch)", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (
      this: Storage,
      k: string,
      v: string,
    ) {
      Object.defineProperty(this, k, {
        value: v.replace(OP_ID, "x"),
        configurable: true,
        writable: true,
      });
    });
    expect(writePacRecovery("admin", m)).toBe(false);
  });
  it("non-UUID operation ids and unreadable payloads are refused / typed", () => {
    expect(writePacRecovery("admin", { ...m, operationId: "not-a-uuid" })).toBe(
      false,
    );
    sessionStorage.setItem(PAC_RECOVERY_KEY, "{not json");
    expect(readPacRecovery("admin")).toEqual({ kind: "unreadable" });
    sessionStorage.setItem(PAC_RECOVERY_KEY, JSON.stringify({ version: 99 }));
    expect(readPacRecovery("admin")).toEqual({ kind: "unreadable" });
  });
});
