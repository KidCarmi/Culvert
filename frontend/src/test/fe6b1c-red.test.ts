// FE-6B.1 CORRECTION ROUND — RED matrix (API client), committed on the
// reviewed candidate 935891f4 BEFORE any product change. Fails there at
// import resolution (the listener-evidence decoder, the activation posture and
// the bound refusal recogniser do not exist) and, once they do, pins:
//
//   B1 — activation is decided from the SERVER-OWNED listener evidence only.
//   A1  the inventory REQUIRES `listener` ({state, posture, servedCertificate?,
//       servesPersistedPair}); unknown posture/state words are refused; a TLS
//       posture without a served identity and a non-TLS posture with one are
//       contradictions; `servesPersistedPair` must equal (tls_custom AND a
//       complete persisted pair AND served fingerprint == persisted
//       fingerprint); the legacy `uiCert.active` must equal it.
//   A2  activationPosture(inventory): unknown / plain_http / tls_configured /
//       self_signed / custom_matches / custom_differs (A served, B persisted)
//       / custom_not_persisted (deleted while served) — every branch names
//       the served identity where one exists and claims nothing when the
//       listener has not been observed.
//   A3  the network settings REQUIRE `ui_listener` and the two reads are
//       compared as objects (a disagreement is reported, never resolved).
//
//   B3 — the operation lookup accepts only BOUND, consistent evidence.
//   A4  a record whose operationId is not the requested UUID is REFUSED (a
//       request for X can never display Y).
//   A5  a committed record's action-specific `result` must agree with the
//       outer record and the frozen contract (operationId, action, the
//       committedRevision it names, the candidate fingerprint it installs,
//       ok/deleted/imported/rotated/replaced discriminants) — a
//       contradiction is a decode refusal; consistent results are accepted.
//   A6  a refusal is a verdict ONLY with the contracted HTTP status AND the
//       JSON media type AND the bounded {error, code, current?} shape;
//       not_found on a 500, on text/plain, or in a foreign shape is NOT
//       "no retained record" — it is an unverified lookup response.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  LISTENER_POSTURES,
  LISTENER_STATES,
  activationPosture,
  certLookupRefusal,
  decodeAdminListener,
  decodeCertificateInventory,
  decodeCertOperation,
  decodeListenerFacts,
  getCertOperation,
  listenerReadsDisagree,
} from "../api/certificates";
import type { CertificateInventory } from "../api/certificates";
import {
  CONF_FP,
  HEX64,
  HEX64_B,
  INVENTORY_HEALTHY,
  LISTENER_CONFIGURED,
  LISTENER_CUSTOM_A,
  LISTENER_NET,
  LISTENER_PLAIN,
  LISTENER_SELF_SIGNED,
  LISTENER_UNKNOWN,
  OP_COMMITTED,
  OP_ID,
  OP_UI_DELETE_COMMITTED,
  SELF_FP,
  UI_ABSENT,
  UI_ACTIVE_PERSISTED,
  UI_CORRUPT,
  UI_FP,
  UI_FP_B,
  UI_INCOMPLETE,
  UI_PERSISTED_B,
  UI_PERSISTED_NOT_ACTIVE,
  UI_UNAVAILABLE,
  okJSON,
} from "./fe6b1-fixtures";

function inv(
  uiCert: Record<string, unknown>,
  listener: Record<string, unknown>,
): CertificateInventory {
  return decodeCertificateInventory({ ...INVENTORY_HEALTHY, uiCert, listener });
}

// ── A1 decoder ──────────────────────────────────────────────────────────────

describe("A1 the inventory carries server-owned listener evidence", () => {
  it("requires `listener` and refuses unknown words", () => {
    const { listener: _drop, ...noListener } = INVENTORY_HEALTHY;
    void _drop;
    expect(() => decodeCertificateInventory(noListener)).toThrow();
    expect(LISTENER_STATES).toEqual(["serving", "unknown"]);
    expect(LISTENER_POSTURES).toEqual([
      "tls_custom",
      "tls_configured",
      "tls_self_signed",
      "plain_http",
      "unknown",
    ]);
    expect(() =>
      decodeAdminListener({ ...LISTENER_PLAIN, posture: "https" }),
    ).toThrow();
    expect(() =>
      decodeAdminListener({ ...LISTENER_PLAIN, state: "bound" }),
    ).toThrow();
  });

  it("a TLS posture names a served identity; a non-TLS or unknown posture never does", () => {
    expect(() =>
      decodeAdminListener({
        state: "serving",
        posture: "tls_custom",
        servesPersistedPair: false,
      }),
    ).toThrow();
    expect(() =>
      decodeAdminListener({
        ...LISTENER_PLAIN,
        servedCertificate: LISTENER_SELF_SIGNED.servedCertificate,
      }),
    ).toThrow();
    expect(() =>
      decodeAdminListener({
        ...LISTENER_UNKNOWN,
        servedCertificate: LISTENER_SELF_SIGNED.servedCertificate,
      }),
    ).toThrow();
    expect(() =>
      decodeAdminListener({ ...LISTENER_UNKNOWN, state: "serving" }),
    ).toThrow(); // serving with an unknown posture is not evidence
    expect(
      decodeAdminListener(LISTENER_SELF_SIGNED).servedCertificate?.fingerprint,
    ).toBe(SELF_FP);
  });

  it("servesPersistedPair and the legacy `active` are DERIVED — contradictions are refused", () => {
    // served A == persisted A ⇒ true/true
    expect(
      inv(UI_ACTIVE_PERSISTED, LISTENER_CUSTOM_A(true)).uiCert.active,
    ).toBe(true);
    // served A, persisted B ⇒ the flag may not claim it
    expect(() =>
      inv({ ...UI_PERSISTED_B, active: true }, LISTENER_CUSTOM_A(true)),
    ).toThrow();
    expect(() => inv(UI_PERSISTED_B, LISTENER_CUSTOM_A(true))).toThrow();
    // an absent pair is never active, whatever the listener serves
    expect(() =>
      inv({ ...UI_ABSENT, active: true }, LISTENER_CUSTOM_A(false)),
    ).toThrow();
    expect(() => inv(UI_ABSENT, LISTENER_CUSTOM_A(true))).toThrow();
    // legacy flag vs derived fact
    expect(() =>
      inv(UI_PERSISTED_NOT_ACTIVE, LISTENER_CUSTOM_A(true)),
    ).toThrow();
    expect(() =>
      inv({ ...UI_PERSISTED_NOT_ACTIVE, active: true }, LISTENER_SELF_SIGNED),
    ).toThrow();
    // a self-signed / plain / configured / unknown listener never serves the persisted pair
    expect(() =>
      inv(UI_PERSISTED_NOT_ACTIVE, {
        ...LISTENER_SELF_SIGNED,
        servesPersistedPair: true,
      }),
    ).toThrow();
    expect(() =>
      inv(UI_PERSISTED_NOT_ACTIVE, {
        ...LISTENER_PLAIN,
        servesPersistedPair: true,
      }),
    ).toThrow();
    expect(() =>
      inv(UI_PERSISTED_NOT_ACTIVE, {
        ...LISTENER_UNKNOWN,
        servesPersistedPair: true,
      }),
    ).toThrow();
    // a corrupt persisted pair is never the served pair
    expect(() =>
      inv({ ...UI_CORRUPT, active: true }, { ...LISTENER_CUSTOM_A(true) }),
    ).toThrow();
  });
});

// ── A2 activation posture ───────────────────────────────────────────────────

describe("A2 activationPosture is decided from listener evidence + persisted identity", () => {
  it("unknown listener ⇒ unknown; nothing is claimed", () => {
    const p = activationPosture(inv(UI_PERSISTED_NOT_ACTIVE, LISTENER_UNKNOWN));
    expect(p.kind).toBe("unknown");
  });
  it("plain HTTP ⇒ the persisted pair is not in use", () => {
    const p = activationPosture(inv(UI_PERSISTED_NOT_ACTIVE, LISTENER_PLAIN));
    expect(p.kind).toBe("plain_http");
  });
  it("an explicitly configured certificate is served; the persisted pair is never used", () => {
    const p = activationPosture(
      inv(UI_PERSISTED_NOT_ACTIVE, LISTENER_CONFIGURED),
    );
    expect(p.kind).toBe("tls_configured");
    if (p.kind === "tls_configured") expect(p.served.fingerprint).toBe(CONF_FP);
  });
  it("self-signed served; a complete valid persisted pair activates on restart", () => {
    const p = activationPosture(
      inv(UI_PERSISTED_NOT_ACTIVE, LISTENER_SELF_SIGNED),
    );
    expect(p.kind).toBe("self_signed");
    if (p.kind === "self_signed") {
      expect(p.served.fingerprint).toBe(SELF_FP);
      expect(p.persistedActivatesOnRestart).toBe(true);
    }
    for (const ui of [UI_ABSENT, UI_INCOMPLETE, UI_UNAVAILABLE, UI_CORRUPT]) {
      const q = activationPosture(inv(ui, LISTENER_SELF_SIGNED));
      expect(q.kind).toBe("self_signed");
      if (q.kind === "self_signed")
        expect(q.persistedActivatesOnRestart).toBe(false);
    }
  });
  it("served == persisted ⇒ custom_matches", () => {
    const p = activationPosture(
      inv(UI_ACTIVE_PERSISTED, LISTENER_CUSTOM_A(true)),
    );
    expect(p.kind).toBe("custom_matches");
    if (p.kind === "custom_matches") expect(p.served.fingerprint).toBe(UI_FP);
  });
  it("A served, B persisted ⇒ custom_differs naming both", () => {
    const p = activationPosture(inv(UI_PERSISTED_B, LISTENER_CUSTOM_A(false)));
    expect(p.kind).toBe("custom_differs");
    if (p.kind === "custom_differs") {
      expect(p.served.fingerprint).toBe(UI_FP);
      expect(p.persistedFingerprint).toBe(UI_FP_B);
    }
  });
  it("deleted while served ⇒ custom_not_persisted naming the served pair", () => {
    const p = activationPosture(inv(UI_ABSENT, LISTENER_CUSTOM_A(false)));
    expect(p.kind).toBe("custom_not_persisted");
    if (p.kind === "custom_not_persisted")
      expect(p.served.fingerprint).toBe(UI_FP);
  });
  it("a corrupt / incomplete / unavailable persisted pair beside a served custom pair is stated as such", () => {
    for (const [ui, state] of [
      [UI_CORRUPT, "corrupt"],
      [UI_INCOMPLETE, "incomplete"],
      [UI_UNAVAILABLE, "unavailable"],
    ] as const) {
      const p = activationPosture(inv(ui, LISTENER_CUSTOM_A(false)));
      expect(p.kind).toBe("custom_persisted_unusable");
      if (p.kind === "custom_persisted_unusable")
        expect(p.persistedState).toBe(state);
    }
  });
});

// ── A3 two reads ────────────────────────────────────────────────────────────

describe("A3 the network settings carry the same evidence object", () => {
  it("requires ui_listener and compares the two reads as objects", () => {
    const net = decodeListenerFacts(
      LISTENER_NET(LISTENER_CUSTOM_A(true), true, true),
    );
    expect(net.listener.posture).toBe("tls_custom");
    const { ui_listener: _drop, ...bare } = LISTENER_NET(
      LISTENER_PLAIN,
      false,
      false,
    );
    void _drop;
    expect(() => decodeListenerFacts(bare)).toThrow();
    const a = inv(UI_ACTIVE_PERSISTED, LISTENER_CUSTOM_A(true));
    expect(listenerReadsDisagree(a, net)).toBe(false);
    const plain = decodeListenerFacts(
      LISTENER_NET(LISTENER_PLAIN, true, false, true),
    );
    expect(listenerReadsDisagree(a, plain)).toBe(true);
    // the legacy flags must also agree with the evidence they derive from
    expect(() =>
      decodeListenerFacts(LISTENER_NET(LISTENER_CUSTOM_A(true), true, false)),
    ).toThrow();
    expect(() =>
      decodeListenerFacts(LISTENER_NET(LISTENER_PLAIN, false, true)),
    ).toThrow();
  });
});

// ── B3: A4 identity binding ─────────────────────────────────────────────────

let requests: string[];
let route: (url: string) => Promise<Response>;

beforeEach(() => {
  requests = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown) => {
      const url = String(input);
      requests.push(url);
      return route(url);
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const OTHER_ID = "6b1c0000-fe6b-4e2e-9f00-00000000dddd";

describe("A4 the returned record must be the requested operation", () => {
  it("a request for X that answers Y's record is refused", async () => {
    route = () => okJSON({ ...OP_COMMITTED, operationId: OTHER_ID });
    await expect(getCertOperation(OP_ID)).rejects.toThrow();
    expect(requests).toEqual([`/api/ca/operations/${OP_ID}`]);
  });
  it("the requested id is matched case-insensitively against the lowercased request", async () => {
    route = () => okJSON(OP_COMMITTED);
    const op = await getCertOperation(OP_ID.toUpperCase());
    expect(op.operationId).toBe(OP_ID);
  });
});

// ── B3: A5 result consistency ───────────────────────────────────────────────

describe("A5 a committed result must agree with its record and the frozen contract", () => {
  const good = OP_COMMITTED; // ca.import: imported + target + ca{revision == committedRevision} + previous
  it("accepts consistent results (control)", () => {
    expect(decodeCertOperation(good).state).toBe("committed");
    expect(decodeCertOperation(OP_UI_DELETE_COMMITTED).state).toBe("committed");
  });
  const cases: Array<[string, Record<string, unknown>]> = [
    [
      "result.operationId names another operation",
      { ...good.result, operationId: OTHER_ID },
    ],
    ["result.action disagrees", { ...good.result, action: "ca.rotate" }],
    [
      "result.ca.revision is not the committedRevision",
      { ...good.result, ca: { ...good.result.ca, revision: `car1:${HEX64}` } },
    ],
    [
      "result.ca.fingerprint is not the candidate",
      { ...good.result, ca: { ...good.result.ca, fingerprint: SELF_FP } },
    ],
    [
      "the discriminant is missing",
      (() => {
        const { imported: _i, ...rest } = good.result;
        void _i;
        return rest;
      })(),
    ],
    [
      "a rotate discriminant on an import",
      { ...good.result, imported: undefined, rotated: true },
    ],
    ["imported is not true", { ...good.result, imported: false }],
  ];
  for (const [name, result] of cases) {
    it(`refuses: ${name}`, () => {
      expect(() => decodeCertOperation({ ...good, result })).toThrow();
    });
  }
  it("a ui delete result must say deleted:true with an absent persisted pair", () => {
    expect(() =>
      decodeCertOperation({
        ...OP_UI_DELETE_COMMITTED,
        result: { ...OP_UI_DELETE_COMMITTED.result, deleted: false },
      }),
    ).toThrow();
    expect(() =>
      decodeCertOperation({
        ...OP_UI_DELETE_COMMITTED,
        result: {
          ...OP_UI_DELETE_COMMITTED.result,
          uiCert: UI_ACTIVE_PERSISTED,
        },
      }),
    ).toThrow();
  });
  it("an ocsp.set result must name the committedRevision and ok:true", () => {
    const op = {
      operationId: OP_ID,
      action: "ocsp.set",
      actor: "admin@10.0.0.9",
      target: "ocsp",
      fence: `ocr1:${HEX64}`,
      startedAt: "2026-09-18T10:00:00Z",
      state: "committed",
      audited: true,
      finishedAt: "2026-09-18T10:00:01Z",
      committedRevision: `ocr1:${HEX64_B}`,
      result: {
        ok: true,
        enabled: false,
        durable: true,
        revision: `ocr1:${HEX64_B}`,
        scope: "node-local",
        operationId: OP_ID,
        action: "ocsp.set",
        desired: { enabled: false, source: "admin" },
        runtime: { enabled: false },
      },
    };
    expect(decodeCertOperation(op).state).toBe("committed");
    expect(() =>
      decodeCertOperation({
        ...op,
        result: { ...op.result, revision: `ocr1:${HEX64}` },
      }),
    ).toThrow();
    expect(() =>
      decodeCertOperation({ ...op, result: { ...op.result, ok: false } }),
    ).toThrow();
    expect(() =>
      decodeCertOperation({
        ...op,
        result: { ...op.result, runtime: { enabled: true } },
      }),
    ).toThrow(); // enabled disagrees with runtime.enabled
  });
});

// ── B3: A6 refusal binding ──────────────────────────────────────────────────

describe("A6 a refusal is a verdict only with the contracted status, media type and shape", () => {
  async function failing(
    status: number,
    body: string,
    type: string,
  ): Promise<unknown> {
    route = () =>
      Promise.resolve(
        new Response(body, { status, headers: { "Content-Type": type } }),
      );
    try {
      await getCertOperation(OP_ID);
    } catch (err) {
      return err;
    }
    throw new Error("expected a rejection");
  }
  const body = JSON.stringify({
    error: "no such operation",
    code: "not_found",
  });
  it("404 + application/json + {error, code} ⇒ not_found (control)", async () => {
    expect(
      certLookupRefusal(await failing(404, body, "application/json")),
    ).toBe("not_found");
    expect(
      certLookupRefusal(
        await failing(
          503,
          JSON.stringify({
            error: "ledger",
            code: "operation_ledger_degraded",
            current: { reason: "corrupt" },
          }),
          "application/json; charset=utf-8",
        ),
      ),
    ).toBe("operation_ledger_degraded");
  });
  it("the code on the WRONG status is not a verdict", async () => {
    expect(
      certLookupRefusal(await failing(500, body, "application/json")),
    ).toBeNull();
    expect(
      certLookupRefusal(await failing(200, body, "application/json")),
    ).toBeNull();
    expect(
      certLookupRefusal(
        await failing(
          404,
          JSON.stringify({ error: "x", code: "operation_ledger_degraded" }),
          "application/json",
        ),
      ),
    ).toBeNull();
  });
  it("the code on the wrong media type is not a verdict", async () => {
    expect(
      certLookupRefusal(await failing(404, body, "text/plain")),
    ).toBeNull();
    expect(certLookupRefusal(await failing(404, body, "text/json"))).toBeNull();
  });
  it("a foreign shape is not a verdict", async () => {
    expect(
      certLookupRefusal(
        await failing(
          404,
          JSON.stringify({ code: "not_found" }),
          "application/json",
        ),
      ),
    ).toBeNull();
    expect(
      certLookupRefusal(
        await failing(
          404,
          JSON.stringify({ error: 1, code: "not_found" }),
          "application/json",
        ),
      ),
    ).toBeNull();
    expect(
      certLookupRefusal(
        await failing(
          404,
          JSON.stringify({ error: "x", code: "not_found", detail: "raw" }),
          "application/json",
        ),
      ),
    ).toBeNull();
    expect(
      certLookupRefusal(await failing(404, "[]", "application/json")),
    ).toBeNull();
  });
});
