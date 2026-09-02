// 2E-C — CDR API client proofs: fail-closed decoders (required fields
// throw; unknown enum-ish strings are preserved verbatim, never normalized),
// the delete response's orphaned-trust fingerprint contract, the enroll
// request shape (token sent once, absent from every read DTO), and the raw
// (non-JSON) test upload.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  decodeCDRConfig,
  decodeCDRHealth,
  decodeCDRInstances,
  decodeCDRPolicies,
  deleteCDRInstance,
  enrollCDRInstance,
  testCDRFile,
} from "../api/cdr";
import { DecodeError } from "../api/decode";

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

describe("decodeCDRConfig", () => {
  const FULL = {
    enabled: true,
    endpoint: "sluice:8443",
    failMode: "open",
    defaultProfile: "default",
    defaultMode: "ENFORCE",
    timeoutSec: 35,
    maxFileSizeMB: 50,
    chunkSizeKB: 64,
    serverFingerprint: "ab".repeat(32),
    certsDir: "",
    clientActive: true,
    failOpen: true,
  };

  it("decodes the full shape", () => {
    const c = decodeCDRConfig(FULL, "$");
    expect(c.enabled).toBe(true);
    expect(c.failMode).toBe("open");
    expect(c.failOpen).toBe(true);
    expect(c.clientActive).toBe(true);
  });

  it("fails closed on a missing derived failOpen", () => {
    const rest: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(FULL)) {
      if (k !== "failOpen") rest[k] = v;
    }
    expect(() => decodeCDRConfig(rest, "$")).toThrow(DecodeError);
  });

  it("preserves an unknown failMode string verbatim", () => {
    const c = decodeCDRConfig({ ...FULL, failMode: "definitely-new" }, "$");
    expect(c.failMode).toBe("definitely-new");
  });
});

describe("decodeCDRInstances", () => {
  it("decodes entries with and without enrichment; enabled defaults true", () => {
    const d = decodeCDRInstances(
      {
        instances: [
          {
            name: "a",
            endpoint: "h:1",
            serverFingerprint: "ff",
            clientCertFingerprint: "sha256:abc",
            enrolledAt: "2026-08-30T00:00:00Z",
            clientCertDaysRemaining: 42,
            cbState: "closed",
            poolHealthy: true,
          },
          {
            name: "legacy",
            endpoint: "h:2",
            serverFingerprint: "ee",
            enrolledAt: "2026-08-30T00:00:00Z",
            enabled: false,
          },
        ],
        count: 2,
        version: 7,
        updatedAt: "2026-08-30T01:00:00Z",
      },
      "$",
    );
    expect(d.instances[0]?.clientCertFingerprint).toBe("sha256:abc");
    expect(d.instances[0]?.enabled).toBe(true);
    expect(d.instances[0]?.poolHealthy).toBe(true);
    // Pre-2E-C entry: fingerprint honestly empty, never invented.
    expect(d.instances[1]?.clientCertFingerprint).toBe("");
    expect(d.instances[1]?.enabled).toBe(false);
    expect(d.instances[1]?.poolHealthy).toBeUndefined();
  });

  it("fails closed on an entry without a name", () => {
    expect(() =>
      decodeCDRInstances(
        { instances: [{ endpoint: "h:1" }], count: 1, version: 1 },
        "$",
      ),
    ).toThrow(DecodeError);
  });
});

describe("decodeCDRPolicies", () => {
  it("preserves an unknown mode verbatim", () => {
    const d = decodeCDRPolicies(
      {
        rules: [{ priority: 5, name: "r1", mode: "FUTURE_MODE" }],
        count: 1,
        version: 3,
        epoch: 9,
        integrity: { ok: true, issues: [] },
      },
      "$",
    );
    expect(d.rules[0]?.mode).toBe("FUTURE_MODE");
    expect(d.epoch).toBe(9);
  });
});

describe("decodeCDRHealth", () => {
  it("decodes the aggregate + live poller fields", () => {
    const h = decodeCDRHealth(
      {
        healthy: true,
        version: "v0.2.0",
        supportedTypes: ["pdf"],
        activeWorkers: 1,
        maxWorkers: 4,
        queueDepth: 0,
        filesProcessed: 10,
        threatsRemoved: 2,
        profiles: [{ name: "default", maxFileSizeBytes: 1024 }],
        lastSeen: "2026-08-30T00:00:00Z",
        consecutiveFailures: 2,
        liveHealthy: false,
      },
      "$",
    );
    expect(h.healthy).toBe(true);
    expect(h.consecutiveFailures).toBe(2);
    expect(h.liveHealthy).toBe(false);
    expect(h.profiles[0]?.name).toBe("default");
  });

  it("fails closed when the engine claim is absent", () => {
    expect(() => decodeCDRHealth({ version: "x" }, "$")).toThrow(DecodeError);
  });
});

describe("request shapes (fetch stub)", () => {
  let calls: Array<{ url: string; init: RequestInit | undefined }>;
  let respond: () => Promise<Response>;

  beforeEach(() => {
    calls = [];
    respond = () => okJSON({});
    vi.stubGlobal(
      "fetch",
      vi.fn((input: unknown, init?: RequestInit) => {
        calls.push({ url: String(input), init });
        return respond();
      }),
    );
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("deleteCDRInstance requires the orphaned-trust fingerprint in the response", async () => {
    // Pre-2E-C response shape (no fingerprint) must be a decode FAILURE,
    // not a silently-lossy success — the fingerprint is the only remaining
    // handle for revoking the still-trusted credential.
    respond = () => okJSON({ removed: "a" });
    await expect(deleteCDRInstance("a")).rejects.toMatchObject({
      kind: "decode",
    });
    // The 2E-C trust-lifecycle shape names EVERY still-trusted generation.
    respond = () =>
      okJSON({ removed: "a", clientCertFingerprint: "sha256:ff" });
    await expect(deleteCDRInstance("a")).rejects.toMatchObject({
      kind: "decode",
    });
    respond = () =>
      okJSON({
        removed: "a",
        clientCertFingerprint: "sha256:ff",
        clientCertFingerprints: ["sha256:ff", "sha256:ee"],
      });
    const res = await deleteCDRInstance("a");
    expect(res.clientCertFingerprint).toBe("sha256:ff");
    expect(res.clientCertFingerprints).toEqual(["sha256:ff", "sha256:ee"]);
    expect(calls[2]?.url).toBe("/api/cdr/instances?name=a");
    expect(calls[2]?.init?.method).toBe("DELETE");
  });

  it("enrollCDRInstance sends the token once and returns a token-free DTO", async () => {
    respond = () =>
      okJSON({
        name: "n1",
        endpoint: "h:1",
        serverFingerprint: "ab",
        clientCertFingerprint: "sha256:cc",
        enrolledAt: "2026-08-30T00:00:00Z",
      });
    const inst = await enrollCDRInstance({
      name: "n1",
      endpoint: "h:1",
      serverFingerprint: "ab",
      token: "one-time-secret",
      operationId: "0123456789abcdef0123456789abcdef",
    });
    const sent = calls[0]?.init?.body;
    if (typeof sent !== "string") throw new Error("body was not JSON text");
    expect(sent).toContain("one-time-secret");
    expect(sent).toContain("0123456789abcdef0123456789abcdef");
    // The read DTO carries no token-shaped field at all.
    expect(JSON.stringify(inst)).not.toContain("one-time-secret");
    expect(inst.clientCertFingerprint).toBe("sha256:cc");
  });

  it("testCDRFile uploads raw bytes (no JSON header) with the filename query", async () => {
    respond = () => okJSON({ status: "CLEAN" });
    const file = new File([new Uint8Array([1, 2, 3])], "sample bin.pdf", {
      type: "application/pdf",
    });
    const res = await testCDRFile(file);
    expect(res.status).toBe("CLEAN");
    expect(calls[0]?.url).toBe("/api/cdr/test?filename=sample%20bin.pdf");
    const headers = calls[0]?.init?.headers;
    expect(JSON.stringify(headers)).toContain("application/pdf");
    expect(calls[0]?.init?.body).toBe(file);
  });
});
