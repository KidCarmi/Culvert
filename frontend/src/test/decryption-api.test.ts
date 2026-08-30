// 2E-B — Decryption Operations API proofs: fail-closed decoders (a pre-2E-B
// appliance without key_id/revision/tunables_revision fails decode instead of
// silently mounting unfenced writes), verbatim taxonomy preservation, fence
// transport (privacy body ifRevision / tunables query ?ifRevision=), rotation
// payload exactness (rotate_key only — never a posture field), bounded
// exclusion reads, and the relax-detection matrix for the tunables ceremony.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  clearAutoExclusions,
  decodeAutoExclusions,
  decodeDecryptionHealth,
  decodeDestinationPrivacy,
  decodeTunablesMeta,
  evictAutoExclusion,
  getAutoExclusions,
  mintRotationOperationId,
  putDestinationPrivacy,
  putTunables,
  rotatePseudonymKey,
} from "../api/decryption";
import { tunablesRelax } from "../features/security/AutoExclusionsTab";
import { DecodeError, isRecord } from "../api/decode";

afterEach(() => {
  vi.unstubAllGlobals();
});

const HEALTH = {
  sessions: {
    total: 12,
    by_outcome: { inspected: 8, bypass_manual: 3, "future-outcome": 1 },
    by_decision_source: { policy_inspect: 8 },
    by_tls_version: { "1.3": 12 },
  },
  failures: {
    total: 2,
    by_category: { handshake: 2 },
    by_stage: { client_hello: 2 },
    top: [{ category: "handshake", stage: "client_hello", count: 2 }],
  },
  coverage: { inspected: 8, bypassed: 3, failed: 1, inspected_ratio: 0.7272 },
  trend: [
    { ts: 1700000000000, inspected: 2, bypassed: 1, failed: 0, ratio: 0.66 },
  ],
  autoexclude: {
    active: 1,
    pending: 0,
    hit_total: 4,
    rescue_total: 1,
    surge_total: 0,
    fail_open_profiles: 1,
    fail_open_rules: 2,
  },
};

describe("decryption health decoding", () => {
  it("decodes the aggregate and preserves unknown taxonomy keys verbatim", () => {
    const h = decodeDecryptionHealth(HEALTH);
    expect(h.inspected).toBe(8);
    expect(h.byOutcome["future-outcome"]).toBe(1); // never coerced or dropped
    expect(h.topFailures[0]?.category).toBe("handshake");
    expect(h.trend[0]?.ratio).toBe(0.66);
    expect(h.failOpenRules).toBe(2);
  });

  it("fails closed on a missing section", () => {
    expect(() => decodeDecryptionHealth({ sessions: HEALTH.sessions })).toThrow(
      DecodeError,
    );
  });
});

describe("destination privacy decoding", () => {
  const PRIVACY = {
    redact_hosts: true,
    scope: "traffic_destination",
    scope_fields: ["host", "uri"],
    key_provisioned: true,
    key_id: "a1b2c3d4e5f60708",
    rotation_seq: 3,
    rotation_receipts: [
      {
        operation_id: "op-1",
        key_id: "a1b2c3d4e5f60708",
        seq: 3,
        ts: "2026-08-30T10:00:00Z",
      },
    ],
    revision: "sha256:r",
    note: "…",
  };

  it("decodes the coherent snapshot including the rotation identity truth", () => {
    const p = decodeDestinationPrivacy(PRIVACY);
    expect(p.redactHosts).toBe(true);
    expect(p.keyId).toBe("a1b2c3d4e5f60708");
    expect(p.rotationSeq).toBe(3);
    expect(p.receipts[0]?.operationId).toBe("op-1");
    expect(p.receipts[0]?.seq).toBe(3);
    expect(p.revision).toBe("sha256:r");
  });

  it("fails closed when key_id, revision, or the rotation identity is missing (pre-correction appliance)", () => {
    for (const missing of [
      "key_id",
      "revision",
      "rotation_seq",
      "rotation_receipts",
    ]) {
      const copy: Record<string, unknown> = { ...PRIVACY };
      delete copy[missing];
      expect(() => decodeDestinationPrivacy(copy)).toThrow(DecodeError);
    }
  });
});

// ── transport ───────────────────────────────────────────────────────────────

interface Sent {
  url: string;
  method: string;
  body: unknown;
}

function stubFetch(respond: (url: string) => unknown): Sent[] {
  const sent: Sent[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      sent.push({
        url,
        method: init?.method ?? "GET",
        body:
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
      });
      return Promise.resolve(
        new Response(JSON.stringify(respond(url)), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }),
  );
  return sent;
}

const WRITE_RESULT = {
  redact_hosts: true,
  key_rotated: false,
  key_id: "gen1",
  rotation_seq: 3,
  revision: "sha256:new",
};

it("privacy PUT asserts the fence and never carries a rotation", async () => {
  const sent = stubFetch(() => WRITE_RESULT);
  await putDestinationPrivacy(true, "revA");
  const put = sent[0];
  if (put === undefined || !isRecord(put.body)) throw new Error("no PUT body");
  expect(put.method).toBe("PUT");
  expect(put.url).toBe("/api/decryption/redaction");
  expect(put.body["ifRevision"]).toBe("revA");
  expect(put.body["redact_hosts"]).toBe(true);
  expect(put.body["rotate_key"]).toBeUndefined();
});

it("rotation sends rotate_key + operation identity + the fence and NO posture field", async () => {
  const sent = stubFetch(() => ({
    ...WRITE_RESULT,
    key_rotated: true,
    already_applied: false,
    operation_id: "op-a1",
    rotation_seq: 4,
  }));
  const res = await rotatePseudonymKey("op-a1", "revA");
  const put = sent[0];
  if (put === undefined || !isRecord(put.body)) throw new Error("no PUT body");
  expect(put.body["rotate_key"]).toBe(true);
  expect(put.body["operation_id"]).toBe("op-a1");
  expect(put.body["ifRevision"]).toBe("revA");
  expect("redact_hosts" in put.body).toBe(false);
  expect(res.keyRotated).toBe(true);
  expect(res.alreadyApplied).toBe(false);
  expect(res.operationId).toBe("op-a1");
  expect(res.rotationSeq).toBe(4);
  expect(res.keyId).toBe("gen1");
});

it("mintRotationOperationId mints fresh 16-hex identities (never reused)", () => {
  const a = mintRotationOperationId();
  const b = mintRotationOperationId();
  expect(a).toMatch(/^[0-9a-f]{16}$/);
  expect(b).toMatch(/^[0-9a-f]{16}$/);
  expect(a).not.toBe(b);
});

// ── auto-exclusions ─────────────────────────────────────────────────────────

const EXCLUSIONS = {
  exclusions: [
    {
      scope_id: "prof-1",
      scope_name: "fail-open",
      host: "pinned.example",
      reason: "client_pinned",
      learned_at: "2026-08-30T10:00:00Z",
      expires_at: "2026-08-30T11:00:00Z",
      hits: 3,
      client_count: 2,
    },
  ],
  truncated: true,
  stats: {
    active: 7,
    pending: 1,
    confirm_n: 2,
    ttl_secs: 43200,
    pinned_ttl_secs: 3600,
    window_secs: 600,
    max_entries: 4096,
  },
  tunables_revision: "sha256:t",
  fail_open_profiles: 1,
  fail_open_rules: 2,
  scope_rule_counts: { "prof-1": 2 },
  scope_names: { "prof-1": "fail-open (renamed)" },
};

describe("auto-exclusions decoding", () => {
  it("decodes entries, stats, and the coherent tunables revision", () => {
    const d = decodeAutoExclusions(EXCLUSIONS);
    expect(d.exclusions[0]?.host).toBe("pinned.example");
    expect(d.exclusions[0]?.reason).toBe("client_pinned"); // verbatim
    expect(d.truncated).toBe(true);
    expect(d.stats.active).toBe(7);
    expect(d.tunablesRevision).toBe("sha256:t");
    expect(d.scopeNames["prof-1"]).toBe("fail-open (renamed)");
  });

  it("fails closed when tunables_revision is missing (pre-2E-B appliance)", () => {
    const noRev: Record<string, unknown> = { ...EXCLUSIONS };
    delete noRev["tunables_revision"];
    expect(() => decodeAutoExclusions(noRev)).toThrow(DecodeError);
  });
});

it("exclusion reads are bounded; evict/clear address the volatile cache truthfully", async () => {
  const sent = stubFetch((url) => {
    if (url.includes("scope=")) return { ok: true, removed: false };
    if (url.includes("limit=")) return EXCLUSIONS;
    return { ok: true, cleared: 4 };
  });
  await getAutoExclusions(500);
  expect(sent[0]?.url).toBe("/api/decryption-exclusions?limit=500");
  const evicted = await evictAutoExclusion("prof-1", "pinned.example");
  expect(sent[1]?.method).toBe("DELETE");
  expect(sent[1]?.url).toBe(
    "/api/decryption-exclusions?scope=prof-1&host=pinned.example",
  );
  expect(evicted.removed).toBe(false); // absent entry is a truthful success
  const cleared = await clearAutoExclusions();
  expect(sent[2]?.url).toBe("/api/decryption-exclusions");
  expect(cleared.cleared).toBe(4);
});

// ── tunables ────────────────────────────────────────────────────────────────

it("decodes tunables meta (server-owned defaults + bounds)", () => {
  const meta = decodeTunablesMeta({
    defaults: {
      confirm_n: 2,
      ttl_secs: 43200,
      pinned_ttl_secs: 3600,
      window_secs: 600,
      max_entries: 4096,
    },
    bounds: { confirm_n: { min: 2, max: 10 } },
    note: "…",
    current_values_source: "/api/decryption-exclusions (stats)",
  });
  expect(meta.defaults.confirmN).toBe(2);
  expect(meta.bounds["confirm_n"]?.max).toBe(10);
});

it("tunables PUT asserts the fence in the query and snake_case values in the body", async () => {
  const sent = stubFetch(() => ({
    confirm_n: 3,
    ttl_secs: 43200,
    pinned_ttl_secs: 3600,
    window_secs: 600,
    max_entries: 4096,
    revision: "sha256:t2",
  }));
  const res = await putTunables(
    {
      confirmN: 3,
      ttlSecs: 43200,
      pinnedTtlSecs: 3600,
      windowSecs: 600,
      maxEntries: 4096,
    },
    "sha256:t",
  );
  const put = sent[0];
  if (put === undefined || !isRecord(put.body)) throw new Error("no PUT body");
  expect(put.url).toBe(
    "/api/decryption-exclusions/tunables?ifRevision=sha256%3At",
  );
  expect(put.body["confirm_n"]).toBe(3);
  expect(put.body["revision"]).toBeUndefined(); // server-owned, never submitted
  expect(res.revision).toBe("sha256:t2");
});

it("tunablesRelax flags only protection-reducing changes", () => {
  const cur = {
    confirmN: 3,
    ttlSecs: 43200,
    pinnedTtlSecs: 3600,
    windowSecs: 600,
    maxEntries: 4096,
  };
  expect(tunablesRelax(cur, { ...cur, confirmN: 2 })).toBe(true); // easier to learn
  expect(tunablesRelax(cur, { ...cur, ttlSecs: 86400 })).toBe(true); // longer bypass
  expect(tunablesRelax(cur, { ...cur, maxEntries: 8192 })).toBe(true); // wider blast radius
  expect(tunablesRelax(cur, { ...cur, confirmN: 4 })).toBe(false); // tightening
  expect(tunablesRelax(cur, { ...cur, ttlSecs: 3600 })).toBe(false);
  expect(tunablesRelax(cur, cur)).toBe(false);
});
