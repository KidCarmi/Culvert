// 2E-A — Content Security API proofs: decoder matrices (status across
// local/remote shapes, verbatim-preserved posture strings, absent-field
// honesty), fence transport (ifRevision in the write BODY, the "new" create
// sentinel), read/write DTO separation (server-owned `revision` never
// submitted), canonical /api/dpi use with ZERO deprecated-alias requests,
// and the shared structured revision-409 recognizer against the 2E-A bodies.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  addDpiPattern,
  createYaraRule,
  clearScanCache,
  decodeDomainAllowlist,
  decodeDpiBypass,
  decodeDpiConfig,
  decodeScanCache,
  decodeScanExclusions,
  decodeScanSvc,
  decodeSecScanStatus,
  decodeYaraInventory,
  decodeYaraSettings,
  decodeYaraValidateResult,
  getDpi,
  getDpiBypass,
  getSecScanStatus,
  putDomainAllowlist,
  putDpiBypass,
  putScanExclusions,
  putYaraSettings,
  removeDpiPattern,
  syncThreatFeeds,
  updateYaraRule,
  validateYaraSource,
} from "../api/contentsec";
import { asRevisionConflict } from "../api/urlcat";
import { ApiError } from "../api/client";
import { DecodeError, isRecord } from "../api/decode";

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── decoders ────────────────────────────────────────────────────────────────

describe("scan status decoding", () => {
  it("decodes a local-mode snapshot and keeps absent fields absent", () => {
    const out = decodeSecScanStatus({
      enabled: true,
      scan_svc_mode: "local",
      clamav_status: "disabled",
      yara_rules: 3,
      yara_enabled: true,
      threat_feed_entries: 120,
      threat_feed_sync_ok: false,
      threat_feed_sync_error: "fetch failed",
      cache_size: 10,
    });
    expect(out.scanSvcMode).toBe("local");
    expect(out.clamavStatus).toBe("disabled");
    expect(out.yaraRules).toBe(3);
    expect(out.threatFeedSyncOk).toBe(false);
    expect(out.threatFeedSyncError).toBe("fetch failed");
    // Absent means absent — never defaulted to a healthy value.
    expect(out.clamavVersion).toBeUndefined();
    expect(out.scanSvcDegraded).toBeUndefined();
  });

  it("preserves an unrecognized scan mode VERBATIM (never coerced)", () => {
    const out = decodeSecScanStatus({
      enabled: false,
      scan_svc_mode: "hybrid-experimental",
    });
    expect(out.scanSvcMode).toBe("hybrid-experimental");
  });

  it("requires the two identity fields", () => {
    expect(() => decodeSecScanStatus({ enabled: true })).toThrow(DecodeError);
    expect(() => decodeSecScanStatus({ scan_svc_mode: "local" })).toThrow(
      DecodeError,
    );
  });
});

describe("allowlist / exclusions / bypass decoding", () => {
  it("decodes lists with the revision fence; requires the revision", () => {
    expect(
      decodeDomainAllowlist({ domains: ["a.example"], revision: "sha256:x" }),
    ).toEqual({ domains: ["a.example"], revision: "sha256:x" });
    expect(decodeDomainAllowlist({ domains: null, revision: "r" })).toEqual({
      domains: [],
      revision: "r",
    });
    expect(() => decodeDomainAllowlist({ domains: [] })).toThrow(DecodeError);

    expect(
      decodeScanExclusions({
        hashes: ["aa"],
        hosts: ["h.example"],
        revision: "r2",
      }),
    ).toEqual({ hashes: ["aa"], hosts: ["h.example"], revision: "r2" });
    expect(() => decodeScanExclusions({ hashes: [], hosts: [] })).toThrow(
      DecodeError,
    );

    expect(decodeDpiBypass({ hosts: null, revision: "r3" })).toEqual({
      hosts: [],
      revision: "r3",
    });
  });
});

describe("yara decoding", () => {
  it("decodes the inventory incl. file→rules map", () => {
    const out = decodeYaraInventory({
      directory: "/data/yara",
      files: ["a", "b"],
      file_rules: { a: ["r1", "r2"], b: null },
      rules: ["r1", "r2"],
      warnings: [],
      count: 2,
    });
    expect(out.files).toEqual(["a", "b"]);
    expect(out.fileRules["a"]).toEqual(["r1", "r2"]);
    expect(out.fileRules["b"]).toEqual([]);
  });

  it("preserves unknown posture strings on settings VERBATIM", () => {
    const out = decodeYaraSettings({
      enabled: true,
      timeout_secs: 5,
      max_inflight: 32,
      on_timeout: "quantum_posture",
      on_saturation: "fail_closed",
      alert_degraded: true,
      revision: "sha256:s",
    });
    expect(out.onTimeout).toBe("quantum_posture");
    expect(out.revision).toBe("sha256:s");
  });

  it("decodes both validate outcomes", () => {
    expect(
      decodeYaraValidateResult({
        valid: true,
        rule_names: ["x"],
        warnings: [],
      }).valid,
    ).toBe(true);
    const bad = decodeYaraValidateResult({
      valid: false,
      error: "syntax error",
      warnings: ["w"],
    });
    expect(bad.valid).toBe(false);
    expect(bad.error).toBe("syntax error");
  });
});

describe("svc / cache / dpi decoding", () => {
  it("decodes svc and the disabled cache honestly", () => {
    expect(
      decodeScanSvc({ remote_enabled: false, remote_url: "" }).remoteEnabled,
    ).toBe(false);
    expect(decodeScanCache({ enabled: false })).toEqual({ enabled: false });
    expect(
      decodeScanCache({ enabled: true, cache_size: 4, cache_hits: 1 }),
    ).toEqual({ enabled: true, cacheSize: 4, cacheHits: 1 });
  });

  it("decodes DPI config", () => {
    expect(
      decodeDpiConfig({ patterns: ["p1"], count: 1, blocked_total: 9 }),
    ).toEqual({ patterns: ["p1"], count: 1, blockedTotal: 9 });
  });
});

// ── transport: fences, canonical paths, DTO separation ──────────────────────

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
      const body = respond(url);
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }),
  );
  return sent;
}

it("every write asserts its fence in the body; reads never submit one", async () => {
  const sent = stubFetch((url) => {
    if (url.includes("allowlist")) return { count: 1, revision: "r2" };
    if (url.includes("exclusions"))
      return { hashes: [], hosts: [], revision: "r2" };
    if (url.includes("bypass")) return { hosts: [], revision: "r2" };
    if (url.includes("settings"))
      return {
        enabled: true,
        timeout_secs: 5,
        max_inflight: 32,
        on_timeout: "fail_closed",
        on_saturation: "fail_closed",
        alert_degraded: false,
        revision: "r2",
      };
    return { name: "n", warnings: [], yara_rules: 1, cache_cleared: true };
  });

  await putDomainAllowlist(["a.example"], "revA");
  await putScanExclusions(["aa"], ["h.example"], "revB");
  await putDpiBypass(["b.example"], "revC");
  await putYaraSettings(
    {
      enabled: true,
      timeoutSecs: 5,
      maxInflight: 32,
      onTimeout: "fail_closed",
      onSaturation: "fail_closed",
      alertDegraded: false,
    },
    "revD",
  );
  await createYaraRule("newrule", "rule x { condition: true }");
  await updateYaraRule("oldrule", "rule y { condition: true }", "revE");

  const bodyOf = (url: string): Record<string, unknown> => {
    const s = sent.find((x) => x.url === url);
    if (s === undefined || !isRecord(s.body)) {
      throw new Error(`no JSON body sent to ${url}`);
    }
    return s.body;
  };
  expect(
    bodyOf("/api/security-scan/feeds/domain-allowlist")["ifRevision"],
  ).toBe("revA");
  expect(bodyOf("/api/security-scan/exclusions")["ifRevision"]).toBe("revB");
  expect(bodyOf("/api/dpi/bypass")["ifRevision"]).toBe("revC");
  const settingsBody = bodyOf("/api/security-scan/yara/settings");
  expect(settingsBody["ifRevision"]).toBe("revD");
  // Write DTO separation: snake_case wire fields; the server-owned read-view
  // `revision` is NEVER submitted.
  expect(settingsBody["timeout_secs"]).toBe(5);
  expect(settingsBody["revision"]).toBeUndefined();
  // Fenced CREATE asserts the sentinel; fenced UPDATE asserts the content rev.
  expect(bodyOf("/api/security-scan/yara/rules")["ifRevision"]).toBe("new");
  expect(bodyOf("/api/security-scan/yara/rules/oldrule")["ifRevision"]).toBe(
    "revE",
  );
});

it("uses ONLY canonical /api/dpi paths — never the deprecated aliases", async () => {
  const sent = stubFetch((url) => {
    if (url.includes("/api/dpi/bypass")) return { hosts: [], revision: "r" };
    if (url.startsWith("/api/dpi"))
      return { patterns: [], count: 0, blocked_total: 0 };
    if (url.includes("yara/validate"))
      return { valid: true, rule_names: ["x"], warnings: [] };
    return {
      enabled: true,
      scan_svc_mode: "local",
    };
  });
  await getDpi();
  await getDpiBypass();
  await addDpiPattern("abc");
  await removeDpiPattern("abc");
  await putDpiBypass([], "r");
  await getSecScanStatus();
  await syncThreatFeeds();
  await validateYaraSource("rule x { condition: true }");
  await clearScanCache();
  for (const s of sent) {
    expect(s.url).not.toContain("/api/content-scan");
  }
  // The DELETE addresses the pattern by query param on the canonical path.
  const del = sent.find((s) => s.method === "DELETE" && s.url.includes("dpi"));
  expect(del?.url).toBe("/api/dpi?pattern=abc");
});

it("recognizes the shared structured revision 409 from the 2E-A surfaces", () => {
  const err = new ApiError(
    "http",
    "conflict",
    409,
    JSON.stringify({
      error: "scan exclusions changed since you loaded it — refresh and retry",
      currentRevision: "sha256:current",
      yourRevision: "sha256:stale",
    }),
  );
  const conflict = asRevisionConflict(err);
  expect(conflict).not.toBeNull();
  expect(conflict?.currentRevision).toBe("sha256:current");
});
