// 2F-E CORRECTION ROUND 3 RED matrix — pure modules (external freeze review
// of the candidate 33f6f21c: finding 1, the spec digest as an INDEPENDENT
// dispatch fence).
//
// Written and executed on the UNTOUCHED candidate before any product change;
// every D-case below fails there for the reason the review names:
//
//   D9  DISPATCH FENCE (spec digest): a replace-mode import or a config
//       rollback can install a DIFFERENT spec at the SAME active revision
//       without changing the history epoch, so a delayed request passes the
//       revision fence and the epoch check. The reviewed active spec digest
//       — already bound in the marker — must ALSO travel to the appliance
//       (`expectedActiveSpecDigest`) on publish and rollback so it is
//       enforced there as its own fence.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { publishPacProfile, rollbackPacProfile } from "../api/pac";
import { isRecord } from "../api/decode";

const OP_ID = "8c1f2b9e-6f3a-4c1d-9b0e-3a2f1d4c5b6a";
const INC_A = "a1a1a1a1-0000-4000-8000-000000000001";
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

describe("D9 publish / rollback carry the reviewed active spec digest to the appliance", () => {
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

  it("D9a publish sends expectedActiveSpecDigest", async () => {
    const args = {
      operationId: OP_ID,
      draft: DRAFT,
      expectedActiveRevision: 3,
      expectedActiveSpecDigest: "sha256:bbbb",
      collectionEtag: "sha256:coll",
      reason: "r",
      historyIncarnation: INC_A,
    };
    await publishPacProfile("hq", args);
    expect(sentBody()["expectedActiveSpecDigest"]).toBe("sha256:bbbb");
  });

  it("D9b rollback sends expectedActiveSpecDigest", async () => {
    const args = {
      operationId: OP_ID,
      targetN: 1,
      expectedActiveRevision: 3,
      expectedActiveSpecDigest: "sha256:bbbb",
      collectionEtag: "sha256:coll",
      reason: "r",
      historyIncarnation: INC_A,
    };
    await rollbackPacProfile("hq", args);
    expect(sentBody()["expectedActiveSpecDigest"]).toBe("sha256:bbbb");
  });
});
