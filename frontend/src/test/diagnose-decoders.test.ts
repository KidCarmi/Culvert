// FE-4 hardening §8: per-verb diagnose decoder matrix. For EVERY verb in the
// backend's fixed registry: a valid real-shape fixture (mirroring the Go
// response structs in diagnose.go) passes; a missing required field fails; a
// wrong-typed field fails; an unsupported schema_version fails; and a bare
// {"schema_version":1} fails. Nested contract-required data (storage checks,
// upstream proxies, config sizes/utilization, the "all" sub-results) fails
// closed when malformed.
import { describe, expect, it } from "vitest";
import { DIAGNOSE_VERBS, decodeDiagnose } from "../api/diagnose";
import type { DiagnoseVerb } from "../api/diagnose";
import { DecodeError } from "../api/decode";

const GEN = "2026-08-22T13:00:00Z";

const storageFixture = {
  schema_version: 1,
  generated_at: GEN,
  ok: true,
  data_dir: "/data",
  free_bytes: 52_000_000_000,
  total_bytes: 100_000_000_000,
  used_pct: 48.0,
  checks: [
    { name: "data_dir_writable", path: "/data", ok: true },
    {
      name: "config_versions",
      path: "/data/config_versions",
      ok: true,
      detail: "",
    },
  ],
};

const upstreamFixture = {
  schema_version: 1,
  generated_at: GEN,
  enabled: true,
  ok: true,
  count: 2,
  healthy_count: 2,
  usable_count: 1,
  proxies: [
    {
      url: "proxy-a.internal:3128",
      healthy: true,
      circuit: "closed",
      failures: 0,
    },
    {
      url: "proxy-b.internal:3128",
      healthy: true,
      circuit: "open",
      failures: 7,
      retry_after_ms: 41_000,
    },
  ],
};

const dnsFixture = {
  schema_version: 1,
  generated_at: GEN,
  host: "example.com",
  resolved: true,
  blocked: false,
  ok: true,
  addresses: ["93.184.216.34"],
  duration_ms: 12,
};

const tlsFixture = {
  schema_version: 1,
  generated_at: GEN,
  host: "example.com",
  port: "443",
  blocked: false,
  ok: true,
  handshake_ok: true,
  version: "TLS 1.3",
  cipher_suite: "TLS_AES_128_GCM_SHA256",
  chain_verified: true,
  expired: false,
  days_until_expiry: 87,
  leaf: {
    subject: "CN=example.com",
    issuer: "CN=DigiCert TLS RSA SHA256 2020 CA1",
    not_before: "2026-01-01T00:00:00Z",
    not_after: "2026-11-17T23:59:59Z",
    dns_names: ["example.com", "www.example.com"],
  },
  duration_ms: 180,
};

const clusterFixture = {
  schema_version: 1,
  generated_at: GEN,
  role: "standalone",
  ok: true,
  ha_enabled: false,
  auto_failover: false,
  lease_mode: "none",
  write_authority: true,
  nodes_total: 0,
  nodes_connected: 0,
};

const etcdFixture = {
  schema_version: 1,
  generated_at: GEN,
  configured: false,
  ok: true,
  status: "n/a",
  note: "no etcd fencing lease configured on this node",
};

const configFixture = {
  schema_version: 1,
  generated_at: GEN,
  ok: true,
  status: "ok",
  syncing: false,
  policy_version: 12,
  epoch: 3,
  sizes: [
    { name: "policy_rules", size: 14 },
    { name: "blocklist", size: 120 },
  ],
  utilization: [{ name: "policy_rules", size: 14, cap: 5000 }],
  max_util_percent: 1,
  max_util_slice: "policy_rules",
};

const supportFixture = {
  schema_version: 1,
  generated_at: GEN,
  ok: true,
  bundle_count: 2,
  pending_count: 1,
  total_bytes: 5_400_000,
  oldest_age_hours: 40,
  newest_age_hours: 2,
  retention_keep: 10,
  retention_max_age_days: 30,
  retention_evicted_total: 4,
  retention_last_sweep: GEN,
  checks: [{ name: "bundle_store_writable", path: "/data/support", ok: true }],
};

const allFixture = {
  schema_version: 1,
  generated_at: GEN,
  ok: true,
  storage: storageFixture,
  upstream: upstreamFixture,
  cluster: clusterFixture,
  config: configFixture,
};

const fixtures: Record<DiagnoseVerb, Record<string, unknown>> = {
  storage: storageFixture,
  upstream: upstreamFixture,
  dns: dnsFixture,
  tls: tlsFixture,
  cluster: clusterFixture,
  etcd: etcdFixture,
  config: configFixture,
  support: supportFixture,
  all: allFixture,
};

// One contract-REQUIRED field per verb (used by the missing/wrong-type
// matrix; each is required by the Go struct — no omitempty).
const requiredField: Record<DiagnoseVerb, string> = {
  storage: "data_dir",
  upstream: "usable_count",
  dns: "resolved",
  tls: "chain_verified",
  cluster: "role",
  etcd: "status",
  config: "utilization",
  support: "bundle_count",
  all: "config",
};

const omit = (o: Record<string, unknown>, k: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).filter(([key]) => key !== k));

describe.each(DIAGNOSE_VERBS)("diagnose decoder: %s", (verb) => {
  const decode = decodeDiagnose(verb);
  const fixture = fixtures[verb];

  it("accepts the real v1 shape and normalizes it", () => {
    const view = decode(fixture);
    expect(view.verb).toBe(verb);
    expect(view.ok).toBe(true);
    expect(view.generatedAt).toBe(GEN);
    expect(view.summary.length).toBeGreaterThan(0);
  });

  it("fails closed on a missing required field", () => {
    expect(() => decode(omit(fixture, requiredField[verb]))).toThrow(
      DecodeError,
    );
    expect(() => decode(omit(fixture, "ok"))).toThrow(DecodeError);
    expect(() => decode(omit(fixture, "generated_at"))).toThrow(DecodeError);
  });

  it("fails closed on a wrong-typed required field", () => {
    expect(() =>
      decode({ ...fixture, [requiredField[verb]]: { bad: true } }),
    ).toThrow(DecodeError);
    expect(() => decode({ ...fixture, ok: "yes" })).toThrow(DecodeError);
  });

  it("rejects an unsupported schema_version and a missing one", () => {
    expect(() => decode({ ...fixture, schema_version: 2 })).toThrow(
      DecodeError,
    );
    expect(() => decode(omit(fixture, "schema_version"))).toThrow(DecodeError);
  });

  it("rejects a bare {schema_version: 1}", () => {
    expect(() => decode({ schema_version: 1 })).toThrow(DecodeError);
  });
});

describe("nested contract data", () => {
  it("storage: a malformed check row fails closed", () => {
    expect(() =>
      decodeDiagnose("storage")({
        ...storageFixture,
        checks: [{ name: "x" }], // missing path/ok
      }),
    ).toThrow(DecodeError);
  });

  it("upstream: a malformed proxy row fails closed", () => {
    expect(() =>
      decodeDiagnose("upstream")({
        ...upstreamFixture,
        proxies: [
          { url: "p:3128", healthy: "yes", circuit: "closed", failures: 0 },
        ],
      }),
    ).toThrow(DecodeError);
  });

  it("config: a malformed utilization row fails closed", () => {
    expect(() =>
      decodeDiagnose("config")({
        ...configFixture,
        utilization: [{ name: "policy_rules", size: 14 }], // missing cap
      }),
    ).toThrow(DecodeError);
  });

  it("all: a malformed nested sub-result fails closed", () => {
    expect(() =>
      decodeDiagnose("all")({
        ...allFixture,
        storage: { schema_version: 1 },
      }),
    ).toThrow(DecodeError);
  });

  it("go nil-slice empties (null) decode as empty for present arrays", () => {
    const view = decodeDiagnose("upstream")({
      ...upstreamFixture,
      enabled: false,
      count: 0,
      healthy_count: 0,
      usable_count: 0,
      proxies: null,
    });
    expect(view.tables).toHaveLength(0);
  });

  it("all: normalizes nested sub-results into sections", () => {
    const view = decodeDiagnose("all")(allFixture);
    expect(view.sub.map((s) => s.verb)).toEqual([
      "storage",
      "upstream",
      "cluster",
      "config",
    ]);
    // Nested tables survive normalization (checks/proxies/utilization).
    expect(view.sub[0]?.tables[0]?.rows.length).toBe(2);
    expect(view.sub[1]?.tables[0]?.rows.length).toBe(2);
    expect(view.sub[3]?.tables.length).toBe(2);
  });
});
