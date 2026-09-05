// 2F-E CORRECTION RED matrix — pure modules (external freeze review of the
// candidate 39e2cfdb: findings 1–3 + the client half of 5).
//
// Written and executed on the UNTOUCHED candidate before any product change;
// every case below fails there for the reason the review names:
//
//   C1  recovery evidence — absence from a BOUNDED (20 shown / 64 retained)
//       or RESET history is never "not landed"; only a complete ring plus a
//       moved fence proves non-commit; a base that has NOT moved keeps the
//       operation unresolved (the request may not have reached intent
//       persistence yet); "committed historically" is distinguished from
//       "currently active" (revision n vs activeN); the server-side
//       `?operationId=` lookup (retained ring of 64, not the 20 shown) is
//       consumed when present.
//   C2  marker ownership — one outstanding operation across the PAC surface:
//       a write never overwrites a different operation's marker, never
//       succeeds over unreadable/unavailable storage, and a clear is
//       ownership-matched (a late completion cannot erase another marker).
//   C3  unproven responses — a 2xx that cannot be decoded, a wrong content
//       type, and an intermediary 5xx without an authoritative PAC decision
//       are UNRESOLVED (marker kept); a decoded result must carry the
//       dispatched operationId AND the action's positive commit flag.
//   C5  contract — the lifecycle GET carries the recovery-evidence limits
//       (draftSpecDigest, operationsRetained/Cap, operation lookup) and the
//       client can ask for one operation.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import {
  decodePacLifecycle,
  decodePacOperationResult,
  getPacLifecycle,
} from "../api/pac";
import {
  classifyDispatchFailure,
  classifyRecovery,
  failureKeepsMarker,
  verifyOperationResult,
} from "../features/network/pac/pacLifecycle";
import {
  PAC_RECOVERY_KEY,
  clearPacRecovery,
  readPacRecovery,
  writePacRecovery,
} from "../features/network/pac/pacRecovery";

const OP_ID = "8c1f2b9e-6f3a-4c1d-9b0e-3a2f1d4c5b6a";
const OTHER_ID = "2d7c0f5e-9b1a-4c3d-8e2f-6a5b4c3d2e1f";
// Fixture completion (2F-E correction round 2): the lifecycle now carries
// the durable history-epoch identity and the marker records the one it was
// dispatched in; every case below runs within ONE epoch unless it says so.
const INC = "a1a1a1a1-0000-4000-8000-000000000001";
const INC_AFTER_RESET = "b2b2b2b2-0000-4000-8000-000000000002";
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
const DRAFT = {
  ...ACTIVE,
  rules: [{ kind: "domain", pattern: "intranet.example", action: "direct" }],
  revision: 0,
};

function decided(id: string, state = "recorded", status = 200): unknown {
  return {
    operationId: id,
    action: "publish",
    state,
    ts: "t",
    status,
    result: null,
  };
}
function revision(n: number, opId: string, specDigest: string): unknown {
  return {
    n,
    spec: ACTIVE,
    digest: `a${String(n)}`,
    author: "admin",
    ts: "2026-09-04T10:00:00Z",
    operationId: opId,
    specDigest,
    poolDigest: "sha256:pppp",
  };
}
function base(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    profileId: "hq",
    activeExists: true,
    active: ACTIVE,
    draft: DRAFT,
    draftDirty: true,
    activeN: 2,
    revisions: [
      revision(1, "11111111-1111-4111-8111-111111111111", "sha256:aaaa"),
      revision(2, "22222222-2222-4222-8222-222222222222", "sha256:bbbb"),
    ],
    draftRevision: 4,
    activeRevision: 3,
    collectionEtag: "sha256:coll",
    state: "idle",
    historyState: "recorded",
    operations: [decided("22222222-2222-4222-8222-222222222222")],
    activeSpecDigest: "sha256:bbbb",
    poolChangedSince: false,
    scope: "node-local",
    historyIncarnation: INC,
    ...over,
  };
}
const MARKER = {
  operationId: OP_ID,
  action: "publish" as const,
  profileId: "hq",
  expectedActiveRevision: 3,
  expectedActiveSpecDigest: "sha256:bbbb",
  candidateSpecDigest: "sha256:cand",
  targetN: 0,
  startedAt: Date.parse("2026-09-05T12:00:00Z"),
  collectionEtag: "sha256:coll",
  historyIncarnation: INC,
};
function twentyForeignOps(): unknown[] {
  return Array.from({ length: 20 }, (_, i) =>
    decided(
      `0000000${String(i).padStart(1, "0")}-0000-4000-8000-${String(i).padStart(12, "0")}`,
    ),
  );
}

// ── C1 ──────────────────────────────────────────────────────────────────────

describe("C1 recovery evidence", () => {
  it("C1a absence from a TRUNCATED shown ring (20 listed) is unresolved, never not_landed — even when the base moved", () => {
    const lc = decodePacLifecycle(
      base({
        operations: twentyForeignOps(),
        activeRevision: 9,
        activeSpecDigest: "sha256:zz",
      }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "unresolved",
      reason: "history_bounded",
    });
  });
  it("C1b absence from a FULL retained ring (server lookup: retained == cap, not found) is unresolved", () => {
    const lc = decodePacLifecycle(
      base({
        operations: twentyForeignOps(),
        operationsRetained: 64,
        operationsCap: 64,
        operation: { operationId: OP_ID, found: false, revisionN: 0 },
        activeRevision: 9,
        activeSpecDigest: "sha256:zz",
      }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "unresolved",
      reason: "history_bounded",
    });
  });
  it("C1c a history reset at or after the dispatch, or an unacknowledged reset, makes absence unresolved", () => {
    const reset = {
      at: "2026-09-05T12:30:00Z",
      quarantinedTo: "/data/pac_profiles_lifecycle.json.corrupt.1",
      cause: "decode",
      scoped: true,
      activeAtReset: ["hq"],
      acknowledgedProfiles: 1,
      ackAction: "acknowledge_history_reset",
    };
    // ASSERTION CORRECTED in the 2F-E correction round 2 (transparently; the
    // original commit is preserved in history). The original expectation for
    // an ACKNOWLEDGED reset was {kind:"unresolved", reason:"history_reset"},
    // reached by comparing the server-stamped reset time with the
    // browser-stamped dispatch (a 15-minute skew allowance). The external
    // review showed that rule is unsound: a server clock sufficiently behind
    // the browser stamps a reset that happened AFTER the dispatch as older
    // than it, and the candidate then answered not_landed. A reset starts a
    // NEW history epoch (the record is quarantined), so the durable epoch
    // identity — never a clock — is what the classifier consults: the
    // acknowledged reset reads as broken continuity.
    const acknowledged = decodePacLifecycle(
      base({
        historyReset: reset,
        activeRevision: 9,
        activeSpecDigest: "sha256:zz",
        operations: [],
        historyIncarnation: INC_AFTER_RESET,
      }),
    );
    expect(classifyRecovery(MARKER, acknowledged)).toEqual({
      kind: "unresolved",
      reason: "history_discontinuity",
    });
    const unacked = decodePacLifecycle(
      base({
        historyState: "history_reset",
        historyReset: {
          ...reset,
          at: "2026-09-01T00:00:00Z",
          acknowledgedProfiles: 0,
        },
      }),
    );
    expect(classifyRecovery(MARKER, unacked)).toEqual({
      kind: "unresolved",
      reason: "history_reset",
    });
  });
  it("C1d absent from a COMPLETE ring with the base UNCHANGED stays unresolved (the request may still reach intent persistence)", () => {
    expect(classifyRecovery(MARKER, decodePacLifecycle(base()))).toEqual({
      kind: "unresolved",
      reason: "not_observed",
    });
    const withLookup = decodePacLifecycle(
      base({
        operationsRetained: 1,
        operationsCap: 64,
        operation: { operationId: OP_ID, found: false, revisionN: 0 },
      }),
    );
    expect(classifyRecovery(MARKER, withLookup)).toEqual({
      kind: "unresolved",
      reason: "not_observed",
    });
  });
  it("C1e absent from a COMPLETE ring with the fence MOVED is the only proven non-commit", () => {
    const lc = decodePacLifecycle(
      base({
        activeRevision: 7,
        activeSpecDigest: "sha256:other",
        operationsRetained: 1,
        operationsCap: 64,
        operation: { operationId: OP_ID, found: false, revisionN: 0 },
      }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "not_landed",
      proof: "fence_moved",
    });
  });
  it("C1f a decided+recorded operation is landed with its history revision; currently active only while activeN is that revision", () => {
    const committedActive = decodePacLifecycle(
      base({
        activeN: 3,
        activeRevision: 4,
        activeSpecDigest: "sha256:cand",
        revisions: [
          revision(1, "11111111-1111-4111-8111-111111111111", "sha256:aaaa"),
          revision(2, "22222222-2222-4222-8222-222222222222", "sha256:bbbb"),
          revision(3, OP_ID, "sha256:cand"),
        ],
        operations: [decided(OP_ID)],
      }),
    );
    expect(classifyRecovery(MARKER, committedActive)).toEqual({
      kind: "landed",
      state: "recorded",
      status: 200,
      committed: true,
      revisionN: 3,
      currentlyActive: true,
    });
    const superseded = decodePacLifecycle(
      base({
        activeN: 5,
        activeRevision: 6,
        activeSpecDigest: "sha256:later",
        revisions: [
          revision(3, OP_ID, "sha256:cand"),
          revision(4, OTHER_ID, "sha256:x"),
          revision(5, "33333333-3333-4333-8333-333333333333", "sha256:later"),
        ],
        operations: [decided(OP_ID), decided(OTHER_ID)],
      }),
    );
    expect(classifyRecovery(MARKER, superseded)).toEqual({
      kind: "landed",
      state: "recorded",
      status: 200,
      committed: true,
      revisionN: 3,
      currentlyActive: false,
    });
  });
  it("C1g the server-side lookup decides when the operation is beyond the 20 shown", () => {
    const lc = decodePacLifecycle(
      base({
        operations: twentyForeignOps(),
        operationsRetained: 40,
        operationsCap: 64,
        operation: {
          operationId: OP_ID,
          found: true,
          state: "recorded",
          status: 200,
          ts: "t",
          revisionN: 3,
        },
        activeN: 30,
        activeRevision: 31,
        activeSpecDigest: "sha256:zz",
      }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "landed",
      state: "recorded",
      status: 200,
      committed: true,
      revisionN: 3,
      currentlyActive: false,
    });
  });
  it("C1h an aborted decision is landed but NOT committed", () => {
    const lc = decodePacLifecycle(
      base({ operations: [decided(OP_ID, "aborted", 500)] }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "landed",
      state: "aborted",
      status: 500,
      committed: false,
      revisionN: 0,
      currentlyActive: false,
    });
  });
  it("C1i a profile whose active spec and history are gone cannot prove anything", () => {
    const lc = decodePacLifecycle(
      base({
        activeExists: false,
        active: {},
        activeN: 0,
        revisions: [],
        operations: [],
        activeRevision: 0,
        activeSpecDigest: "",
        // fixture completion: with neither a profile nor a record the
        // appliance reports no history epoch at all
        historyIncarnation: "",
      }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "unresolved",
      reason: "history_missing",
    });
  });
});

// ── C2 ──────────────────────────────────────────────────────────────────────

describe("C2 marker ownership", () => {
  beforeEach(() => {
    sessionStorage.clear();
  });
  it("C2a a write never overwrites a DIFFERENT outstanding operation", () => {
    expect(writePacRecovery("admin", MARKER)).toBe(true);
    const b = { ...MARKER, operationId: OTHER_ID, profileId: "branch" };
    expect(writePacRecovery("admin", b)).toBe(false);
    const read = readPacRecovery("admin");
    expect(read.kind === "valid" && read.marker.operationId).toBe(OP_ID);
  });
  it("C2b the SAME operation may be re-persisted (a resolved re-send)", () => {
    expect(writePacRecovery("admin", MARKER)).toBe(true);
    expect(writePacRecovery("admin", MARKER)).toBe(true);
  });
  it("C2c unreadable storage refuses a write and keeps the unreadable content", () => {
    sessionStorage.setItem(PAC_RECOVERY_KEY, "{not json");
    expect(writePacRecovery("admin", MARKER)).toBe(false);
    expect(sessionStorage.getItem(PAC_RECOVERY_KEY)).toBe("{not json");
    expect(readPacRecovery("admin").kind).toBe("unreadable");
  });
  it("C2d unavailable storage refuses a write", () => {
    const spy = vi
      .spyOn(Storage.prototype, "getItem")
      .mockImplementation(() => {
        throw new Error("storage disabled");
      });
    try {
      expect(writePacRecovery("admin", MARKER)).toBe(false);
    } finally {
      spy.mockRestore();
    }
  });
  it("C2e a clear is ownership-matched: a late completion of another operation cannot erase the marker", () => {
    expect(writePacRecovery("admin", MARKER)).toBe(true);
    expect(clearPacRecovery(OTHER_ID)).toBe(false);
    expect(readPacRecovery("admin").kind).toBe("valid");
    expect(clearPacRecovery(OP_ID)).toBe(true);
    expect(readPacRecovery("admin").kind).toBe("none");
  });
});

// ── C3 ──────────────────────────────────────────────────────────────────────

describe("C3 unproven responses", () => {
  it("C3a an undecodable or wrongly-typed 2xx is UNRESOLVED (marker kept)", () => {
    for (const err of [
      new ApiError("decode", "/x: response body is not valid JSON", 200),
      new ApiError("decode", "/x: $.operationId: expected string", 200),
      new ApiError("contenttype", "/x: unexpected Content-Type text/html", 200),
    ]) {
      const f = classifyDispatchFailure(err);
      expect(f.kind).toBe("unknown");
      expect(failureKeepsMarker(f)).toBe(true);
    }
  });
  it("C3b an intermediary 5xx without an authoritative PAC decision is UNRESOLVED", () => {
    for (const [status, text] of [
      [502, "Bad Gateway"],
      [503, "<html>upstream unavailable</html>"],
      [504, "Gateway Timeout"],
      [500, "internal error"],
    ] as const) {
      const f = classifyDispatchFailure(
        new ApiError("http", `/x: HTTP ${String(status)}`, status, text),
      );
      expect(f.kind, `status ${String(status)}`).toBe("unknown");
      expect(failureKeepsMarker(f)).toBe(true);
    }
  });
  it("C3c an authoritative structured decision stays a decision", () => {
    const failed = classifyDispatchFailure(
      new ApiError(
        "http",
        "/x: HTTP 500",
        500,
        JSON.stringify({
          error: "active profile write failed; nothing was changed",
          code: "active_write_failed",
          operationId: OP_ID,
        }),
      ),
    );
    expect(failed.kind).toBe("server_outcome");
    expect(failureKeepsMarker(failed)).toBe(false);
    const unknown = classifyDispatchFailure(
      new ApiError(
        "http",
        "/x: HTTP 500",
        500,
        JSON.stringify({
          error: "x",
          code: "outcome_unknown",
          operationId: OP_ID,
          state: "pending",
        }),
      ),
    );
    expect(unknown.kind).toBe("server_outcome");
    expect(failureKeepsMarker(unknown)).toBe(true);
    const refused = classifyDispatchFailure(
      new ApiError(
        "http",
        "/x: HTTP 409",
        409,
        "PAC profiles are managed by the control plane on this node",
      ),
    );
    expect(refused.kind).toBe("refused");
    expect(failureKeepsMarker(refused)).toBe(false);
  });
  it("C3d a decoded result must carry the dispatched identity and the action's positive commit flag", () => {
    const ok = decodePacOperationResult({
      operationId: OP_ID,
      activeRevision: 4,
      activeSpecDigest: "sha256:cand",
      digest: "arti",
      draftRevision: 5,
      historyState: "recorded",
      scope: "node-local-history",
      published: true,
      revision: 3,
    });
    expect(
      verifyOperationResult(ok, { operationId: OP_ID, action: "publish" }),
    ).toEqual({
      ok: true,
      pendingReconciliation: false,
    });
    expect(
      verifyOperationResult(ok, { operationId: OTHER_ID, action: "publish" }),
    ).toEqual({
      ok: false,
      reason: "identity",
    });
    expect(
      verifyOperationResult(ok, { operationId: OP_ID, action: "rollback" }),
    ).toEqual({
      ok: false,
      reason: "no_commit_evidence",
    });
    const noFlag = decodePacOperationResult({
      operationId: OP_ID,
      activeRevision: 4,
      historyState: "recorded",
      published: false,
      rolledBack: false,
    });
    expect(
      verifyOperationResult(noFlag, { operationId: OP_ID, action: "publish" }),
    ).toEqual({
      ok: false,
      reason: "no_commit_evidence",
    });
    const pending = decodePacOperationResult({
      operationId: OP_ID,
      activeRevision: 4,
      historyState: "pending_reconciliation",
      rolledBack: true,
      toRevision: 1,
      newRevision: 3,
    });
    expect(
      verifyOperationResult(pending, {
        operationId: OP_ID,
        action: "rollback",
      }),
    ).toEqual({
      ok: true,
      pendingReconciliation: true,
    });
  });
});

// ── C5 ──────────────────────────────────────────────────────────────────────

describe("C5 recovery-evidence contract", () => {
  it("C5a the lifecycle decoder keeps draftSpecDigest, the retained/cap counts and the operation lookup", () => {
    const lc = decodePacLifecycle(
      base({
        draftSpecDigest: "sha256:cand",
        operationsRetained: 7,
        operationsCap: 64,
        operation: {
          operationId: OP_ID,
          found: true,
          state: "recorded",
          status: 200,
          ts: "t",
          revisionN: 3,
        },
      }),
    );
    expect(lc.draftSpecDigest).toBe("sha256:cand");
    expect(lc.operationsRetained).toBe(7);
    expect(lc.operationsCap).toBe(64);
    expect(lc.operation).toEqual({
      operationId: OP_ID,
      found: true,
      state: "recorded",
      status: 200,
      ts: "t",
      revisionN: 3,
      // fixture completion (2F-E correction round 2): the lookup now also
      // carries the committed identity (absent here ⇒ "" / 0)
      specDigest: "",
      storeRevision: 0,
    });
  });
  it("C5b the client asks the appliance for ONE operation by id", async () => {
    const fetchSpy = vi.fn<
      (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
    >(() =>
      Promise.resolve(
        new Response(
          JSON.stringify(
            base({
              operation: { operationId: OP_ID, found: false, revisionN: 0 },
            }),
          ),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
      ),
    );
    vi.stubGlobal("fetch", fetchSpy);
    try {
      const lc = await getPacLifecycle("hq", undefined, { operationId: OP_ID });
      const calledWith = fetchSpy.mock.calls[0]?.[0];
      expect(typeof calledWith === "string" ? calledWith : "").toBe(
        `/api/pac/profiles/hq/lifecycle?operationId=${OP_ID}`,
      );
      expect(lc.operation?.found).toBe(false);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
