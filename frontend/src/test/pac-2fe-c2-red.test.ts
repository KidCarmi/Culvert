// 2F-E CORRECTION ROUND 2 RED matrix — pure modules (external freeze review
// of the candidate db6f4d35: findings 1–3).
//
// Written and executed on the UNTOUCHED candidate before any product change;
// every D-case below fails there for the reason the review names (the two
// CONTROL cases pass on both sides and pin the direction of the fix):
//
//   D1  HISTORY CONTINUITY (clock skew): an ACKNOWLEDGED reset whose server
//       stamp is older than the browser-stamped dispatch — the server clock
//       runs behind — must NOT be dismissed by timestamp arithmetic; the
//       history that could carry the decision is gone. The candidate
//       answered not_landed/fence_moved. Continuity is a durable server
//       IDENTITY of the history epoch (`historyIncarnation`), never a clock.
//   D2  HISTORY CONTINUITY (delete + recreate reaching a HIGHER revision):
//       a recreated profile whose active revision climbed to or past the
//       marker's expected revision bypassed `history_missing`; its EMPTY
//       new ring is not evidence about the old epoch's operation.
//   D3  HISTORY CONTINUITY (delete + recreate reproducing the ORIGINAL
//       revision/spec): the base looks unchanged, so the candidate said
//       not_observed and OFFERED the re-send — the original operationId
//       has no decision record in the new epoch, so a re-send would run it
//       AGAIN. A different incarnation keeps it unresolved (and the page
//       refuses the re-send).
//   D4  a marker without continuity evidence (pre-round-2 marker, no
//       incarnation) never proves non-commit.
//   D5  CURRENTLY ACTIVE from the AUTHORITATIVE active store: a direct
//       profile PUT advances the active revision (and possibly the spec)
//       without moving the history pointer `activeN`; "It is the active
//       revision" must be derived from the committed revision's identity
//       (its spec digest + the store revision it produced) against
//       activeRevision/activeSpecDigest — never from activeN alone.
//   D6  MARKER IMMUTABILITY: a second write under the SAME operationId with
//       different binding fields (candidate digest, dispatch time, fences)
//       is REFUSED and the original evidence survives; an identical
//       re-persist stays allowed.
//   D7  CONTRACT: the lifecycle GET carries `historyIncarnation`, every
//       revision carries the store revision it produced (`storeRevision`),
//       and the operation lookup carries the committed identity
//       (`specDigest`, `storeRevision`).
//   D8  DISPATCH FENCE: publish/rollback carry the reviewed
//       `expectedHistoryIncarnation` so the appliance can refuse a request
//       (a re-send above all) against a different history epoch.
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  decodePacLifecycle,
  publishPacProfile,
  rollbackPacProfile,
} from "../api/pac";
import { classifyRecovery } from "../features/network/pac/pacLifecycle";
import {
  PAC_RECOVERY_KEY,
  readPacRecovery,
  writePacRecovery,
} from "../features/network/pac/pacRecovery";
import { isRecord } from "../api/decode";

/** A decoded value viewed as a plain record (test-side, guarded read). */
function rec(v: unknown): Record<string, unknown> {
  return isRecord(v) ? v : {};
}

const OP_ID = "8c1f2b9e-6f3a-4c1d-9b0e-3a2f1d4c5b6a";
const INC_A = "a1a1a1a1-0000-4000-8000-000000000001";
const INC_B = "b2b2b2b2-0000-4000-8000-000000000002";
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
function revision(
  n: number,
  opId: string,
  specDigest: string,
  extra: Record<string, unknown> = {},
): unknown {
  return {
    n,
    spec: ACTIVE,
    digest: `a${String(n)}`,
    author: "admin",
    ts: "2026-09-04T10:00:00Z",
    operationId: opId,
    specDigest,
    poolDigest: "sha256:pppp",
    ...extra,
  };
}
const REV1_OP = "11111111-1111-4111-8111-111111111111";
const REV2_OP = "22222222-2222-4222-8222-222222222222";
function base(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    profileId: "hq",
    activeExists: true,
    active: ACTIVE,
    draft: DRAFT,
    draftDirty: true,
    activeN: 2,
    revisions: [
      revision(1, REV1_OP, "sha256:aaaa"),
      revision(2, REV2_OP, "sha256:bbbb"),
    ],
    draftRevision: 4,
    activeRevision: 3,
    collectionEtag: "sha256:coll",
    state: "idle",
    historyState: "recorded",
    operations: [decided(REV2_OP)],
    activeSpecDigest: "sha256:bbbb",
    draftSpecDigest: "sha256:cand",
    operationsRetained: 1,
    operationsCap: 64,
    poolChangedSince: false,
    scope: "node-local",
    historyIncarnation: INC_A,
    ...over,
  };
}
const STARTED_AT = Date.parse("2026-09-05T12:00:00Z");
// The round-2 marker: the base tokens the candidate was reviewed against
// PLUS the history epoch identity it was reviewed in.
const MARKER = {
  operationId: OP_ID,
  action: "publish" as const,
  profileId: "hq",
  expectedActiveRevision: 3,
  expectedActiveSpecDigest: "sha256:bbbb",
  candidateSpecDigest: "sha256:cand",
  targetN: 0,
  startedAt: STARTED_AT,
  collectionEtag: "sha256:coll",
  historyIncarnation: INC_A,
};
function notFound(): Record<string, unknown> {
  return { operationId: OP_ID, found: false, revisionN: 0 };
}

// ── D1–D4: continuity ───────────────────────────────────────────────────────

describe("D1–D4 recovery declares non-commit only with proven history continuity", () => {
  it("D1 an ACKNOWLEDGED reset stamped by a server clock that runs BEHIND the browser is not dismissed by arithmetic — the epoch changed, so the operation stays unresolved", () => {
    const lc = decodePacLifecycle(
      base({
        // the appliance's clock is 90 minutes behind: the reset it recorded
        // AFTER the dispatch carries a stamp 75 minutes BEFORE it
        historyReset: {
          at: new Date(STARTED_AT - 75 * 60 * 1000).toISOString(),
          quarantinedTo: "/data/pac_profiles_lifecycle.json.corrupt.1",
          cause: "parse failed",
          scoped: true,
          activeAtReset: ["hq"],
          acknowledgedProfiles: 1,
          ackAction: "acknowledge_history_reset",
          acknowledged: {
            operationId: "33333333-3333-4333-8333-333333333333",
            by: "admin",
            at: new Date(STARTED_AT - 70 * 60 * 1000).toISOString(),
            activeRevision: 4,
            activeSpecDigest: "sha256:post",
          },
        },
        historyState: "recorded",
        // after the reset the history is empty and the base has moved
        activeN: 0,
        revisions: [],
        operations: [],
        operationsRetained: 0,
        activeRevision: 4,
        activeSpecDigest: "sha256:post",
        historyIncarnation: INC_B,
        operation: notFound(),
      }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "unresolved",
      reason: "history_discontinuity",
    });
  });

  it("D2 delete + recreate whose active revision climbed PAST the reviewed one: the empty new ring is no evidence — unresolved, never not_landed", () => {
    const lc = decodePacLifecycle(
      base({
        activeN: 2,
        revisions: [
          revision(1, "44444444-4444-4444-8444-444444444444", "sha256:n1"),
          revision(2, "55555555-5555-4555-8555-555555555555", "sha256:n2"),
        ],
        operations: [],
        operationsRetained: 2,
        activeRevision: 5,
        activeSpecDigest: "sha256:n2",
        historyIncarnation: INC_B,
        operation: notFound(),
      }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "unresolved",
      reason: "history_discontinuity",
    });
  });

  it("D3 delete + recreate reproducing the ORIGINAL revision and spec: the base looks unchanged but the epoch is new — unresolved (a re-send would run the operation again)", () => {
    const lc = decodePacLifecycle(
      base({
        activeN: 0,
        revisions: [],
        operations: [],
        operationsRetained: 0,
        activeRevision: 3,
        activeSpecDigest: "sha256:bbbb",
        draftSpecDigest: "sha256:cand",
        historyIncarnation: INC_B,
        operation: notFound(),
      }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "unresolved",
      reason: "history_discontinuity",
    });
  });

  it("D4 a marker WITHOUT continuity evidence (no incarnation) never proves non-commit, even against a complete ring and a moved fence", () => {
    const legacy = { ...MARKER, historyIncarnation: "" };
    const lc = decodePacLifecycle(
      base({
        operations: [],
        operationsRetained: 0,
        activeRevision: 4,
        activeSpecDigest: "sha256:moved",
        operation: notFound(),
      }),
    );
    expect(classifyRecovery(legacy, lc)).toEqual({
      kind: "unresolved",
      reason: "history_discontinuity",
    });
  });

  it("D4b CONTROL — same epoch, complete ring, absent, fence moved ⇒ not_landed is still provable", () => {
    const lc = decodePacLifecycle(
      base({
        operations: [],
        operationsRetained: 0,
        activeRevision: 4,
        activeSpecDigest: "sha256:moved",
        operation: notFound(),
      }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "not_landed",
      proof: "fence_moved",
    });
  });
});

// ── D5: currently active ────────────────────────────────────────────────────

describe("D5 'currently active' follows the authoritative active store, not the history pointer", () => {
  const found = (): Record<string, unknown> => ({
    operationId: OP_ID,
    found: true,
    state: "recorded",
    status: 200,
    ts: "t",
    revisionN: 2,
    specDigest: "sha256:bbbb",
    storeRevision: 3,
  });
  const committed = (over: Record<string, unknown>): Record<string, unknown> =>
    base({
      activeN: 2,
      revisions: [
        revision(1, REV1_OP, "sha256:aaaa", { storeRevision: 2 }),
        revision(2, OP_ID, "sha256:bbbb", { storeRevision: 3 }),
      ],
      operations: [decided(OP_ID)],
      operation: found(),
      ...over,
    });

  it("D5a a direct profile PUT replaced the spec (activeRevision 4, another digest) while activeN still points at the committed revision ⇒ committed, NOT currently active", () => {
    const lc = decodePacLifecycle(
      committed({ activeRevision: 4, activeSpecDigest: "sha256:put-spec" }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "landed",
      state: "recorded",
      status: 200,
      committed: true,
      revisionN: 2,
      currentlyActive: false,
    });
  });

  it("D5b a direct PUT that re-saved the IDENTICAL spec still moved the store revision past the commit ⇒ NOT currently active", () => {
    const lc = decodePacLifecycle(
      committed({ activeRevision: 4, activeSpecDigest: "sha256:bbbb" }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "landed",
      state: "recorded",
      status: 200,
      committed: true,
      revisionN: 2,
      currentlyActive: false,
    });
  });

  it("D5c CONTROL — the store still serves exactly what the commit produced ⇒ currently active", () => {
    const lc = decodePacLifecycle(
      committed({ activeRevision: 3, activeSpecDigest: "sha256:bbbb" }),
    );
    expect(classifyRecovery(MARKER, lc)).toEqual({
      kind: "landed",
      state: "recorded",
      status: 200,
      committed: true,
      revisionN: 2,
      currentlyActive: true,
    });
  });
});

// ── D6: marker immutability ─────────────────────────────────────────────────

describe("D6 the recovery marker's bindings are immutable under the same operationId", () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  it("D6a a rewrite with a different candidate digest / dispatch time / fences is REFUSED and the original evidence survives", () => {
    expect(writePacRecovery("admin", MARKER)).toBe(true);
    const rebound = {
      ...MARKER,
      candidateSpecDigest: "sha256:other",
      startedAt: STARTED_AT + 60_000,
      expectedActiveRevision: 9,
    };
    expect(writePacRecovery("admin", rebound)).toBe(false);
    const back = readPacRecovery("admin");
    expect(back.kind).toBe("valid");
    if (back.kind !== "valid") throw new Error("marker lost");
    expect(back.marker.candidateSpecDigest).toBe("sha256:cand");
    expect(back.marker.startedAt).toBe(STARTED_AT);
    expect(back.marker.expectedActiveRevision).toBe(3);
    const raw: unknown = JSON.parse(
      sessionStorage.getItem(PAC_RECOVERY_KEY) ?? "null",
    );
    expect(raw).toMatchObject({
      operationId: OP_ID,
      candidateSpecDigest: "sha256:cand",
      startedAt: STARTED_AT,
    });
  });

  it("D6b CONTROL — an identical re-persist of the same operation is allowed", () => {
    expect(writePacRecovery("admin", MARKER)).toBe(true);
    expect(writePacRecovery("admin", { ...MARKER })).toBe(true);
  });

  it("D6c the marker records the history epoch and the collection fence it was reviewed in (a reload must recover them)", () => {
    expect(writePacRecovery("admin", MARKER)).toBe(true);
    const back = readPacRecovery("admin");
    if (back.kind !== "valid") throw new Error("marker lost");
    const m = rec(back.marker);
    expect(m["historyIncarnation"]).toBe(INC_A);
    expect(m["collectionEtag"]).toBe("sha256:coll");
  });
});

// ── D7 / D8: contract ───────────────────────────────────────────────────────

describe("D7 the lifecycle GET carries the continuity + active-identity evidence", () => {
  it("D7a historyIncarnation, revision storeRevision, lookup specDigest/storeRevision decode", () => {
    const lc = rec(
      decodePacLifecycle(
        base({
          revisions: [
            revision(1, REV1_OP, "sha256:aaaa", { storeRevision: 2 }),
          ],
          operation: {
            operationId: OP_ID,
            found: true,
            state: "recorded",
            status: 200,
            ts: "t",
            revisionN: 1,
            specDigest: "sha256:aaaa",
            storeRevision: 2,
          },
        }),
      ),
    );
    expect(lc["historyIncarnation"]).toBe(INC_A);
    const revs = lc["revisions"];
    const r0: unknown = Array.isArray(revs) ? revs[0] : undefined;
    expect(r0).toMatchObject({ n: 1, storeRevision: 2 });
    expect(lc["operation"]).toMatchObject({
      found: true,
      specDigest: "sha256:aaaa",
      storeRevision: 2,
    });
  });
});

describe("D8 publish / rollback carry the reviewed history epoch to the appliance", () => {
  let fetchSpy: ReturnType<
    typeof vi.fn<
      (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
    >
  >;
  beforeEach(() => {
    fetchSpy = vi.fn<
      (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
    >(() =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            operationId: OP_ID,
            activeRevision: 4,
            historyState: "recorded",
            published: true,
            rolledBack: true,
            revision: 3,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    vi.stubGlobal("fetch", fetchSpy);
  });

  function sentBody(): Record<string, unknown> {
    const init = fetchSpy.mock.calls[0]?.[1];
    const body: unknown =
      typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    if (!isRecord(body)) throw new Error("no JSON body");
    return body;
  }

  it("D8a publish sends expectedHistoryIncarnation", async () => {
    const args = {
      operationId: OP_ID,
      draft: DRAFT,
      expectedActiveRevision: 3,
      collectionEtag: "sha256:coll",
      reason: "r",
      historyIncarnation: INC_A,
    };
    await publishPacProfile("hq", args);
    expect(sentBody()["expectedHistoryIncarnation"]).toBe(INC_A);
  });

  it("D8b rollback sends expectedHistoryIncarnation", async () => {
    const args = {
      operationId: OP_ID,
      targetN: 1,
      expectedActiveRevision: 3,
      collectionEtag: "sha256:coll",
      reason: "r",
      historyIncarnation: INC_A,
    };
    await rollbackPacProfile("hq", args);
    expect(sentBody()["expectedHistoryIncarnation"]).toBe(INC_A);
  });
});
