// 2D-B decoder matrix: URL-category state + revision, the structured
// revision-conflict recognizer, compact feed status (UT1 corpus semantics),
// full signed status (null semantics — absence is never zero; unknown state
// stays unknown), settings (resolved/resolve_error, cluster_publish_rejected),
// overrides ({} = empty set), and the manual-refresh outcome mapping.
import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import {
  SAAS_FEED_STATES,
  asRevisionConflict,
  decodeSaasFeedSettings,
  decodeSaasFeedStatus,
  decodeSaasOverrides,
  decodeUrlCatFeedStatus,
  decodeUrlCategoryLookup,
  decodeUrlCategoryState,
  isKnownSaasState,
} from "../api/urlcat";

describe("decodeUrlCategoryState", () => {
  it("decodes categories + the server-owned revision", () => {
    const out = decodeUrlCategoryState({
      categories: [
        { name: "Social", hosts: ["a.example"], builtIn: false, feedBacked: true },
        { name: "Baseline", hosts: [], builtIn: true, feedBacked: false },
      ],
      revision: "abc123",
    });
    expect(out.revision).toBe("abc123");
    expect(out.categories).toHaveLength(2);
    expect(out.categories[0]?.feedBacked).toBe(true);
    expect(out.categories[1]?.builtIn).toBe(true);
  });

  it("refuses a payload without a revision (fail-closed)", () => {
    expect(() => decodeUrlCategoryState({ categories: [] })).toThrow();
  });
});

describe("asRevisionConflict", () => {
  it("recognizes the structured 409", () => {
    const err = new ApiError(
      "http",
      "conflict",
      409,
      JSON.stringify({
        error: "taxonomy revision conflict",
        currentRevision: "cur",
        yourRevision: "mine",
      }),
    );
    const c = asRevisionConflict(err);
    expect(c).not.toBeNull();
    expect(c?.currentRevision).toBe("cur");
    expect(c?.yourRevision).toBe("mine");
  });

  it("returns null for a plain-text 409 (e.g. strict-create name collision)", () => {
    const err = new ApiError("http", "conflict", 409, "category name already exists\n");
    expect(asRevisionConflict(err)).toBeNull();
  });

  it("returns null for non-409s and non-ApiErrors", () => {
    expect(asRevisionConflict(new Error("x"))).toBeNull();
    expect(
      asRevisionConflict(new ApiError("http", "bad", 400, "{}")),
    ).toBeNull();
  });
});

describe("decodeUrlCategoryLookup", () => {
  it("keeps an empty category as taxonomy truth (never reinterpreted)", () => {
    const out = decodeUrlCategoryLookup({
      host: "x.example",
      category: "",
      tier: "",
      matchedBy: "",
      blocked: false,
      blockSource: "",
    });
    expect(out.category).toBe("");
    expect(out.blocked).toBe(false);
  });
});

describe("decodeUrlCatFeedStatus", () => {
  it("keeps UT1 unconfigured fields null — never fabricated zeros", () => {
    const out = decodeUrlCatFeedStatus({
      ut1: { configured: false },
      saas: {
        configured: false,
        enabled: false,
        state: "disabled",
        activeFeedVersion: null,
        provenance: "",
        lastSuccess: "",
        syncFailures: 0,
        stale: false,
      },
    });
    expect(out.ut1.entries).toBeNull();
    expect(out.ut1.lastSync).toBeNull();
    expect(out.saas.activeFeedVersion).toBeNull();
    expect(out.saas.lastSuccess).toBeNull();
  });
});

describe("decodeSaasFeedStatus", () => {
  const base = {
    state: "fresh",
    configured: true,
    enabled: true,
    managed: true,
    authority: "standalone",
    protocol: "signed_manifest_v1",
    url: "",
    active_source: "downloaded",
    provenance: "downloaded",
    signature_status: "verified",
    compiled_trusted: false,
    stale: false,
    host_count: 10,
    category_count: 2,
    override_count: 0,
    not_modified: false,
    failures_since_start: 0,
    consecutive_failures: 0,
    never_succeeded: false,
    syncing: false,
    waiting_for_authority: false,
    recovering: false,
    critical: false,
  };

  it("null facts stay null — never version 0 / epoch / '0 hosts changed'", () => {
    const out = decodeSaasFeedStatus({
      ...base,
      never_succeeded: true,
      active_feed_version: null,
      generated_at: null,
      manifest_expires_at: null,
      last_successful_activation: null,
      last_activation_delta: null,
      last_outcome: null,
      last_http_status: null,
    });
    expect(out.activeFeedVersion).toBeNull();
    expect(out.generatedAt).toBeNull();
    expect(out.lastSuccessfulActivation).toBeNull();
    expect(out.lastActivationDelta).toBeNull();
    expect(out.lastOutcome).toBeNull();
  });

  it("decodes a full activation delta when present", () => {
    const out = decodeSaasFeedStatus({
      ...base,
      active_feed_version: 42,
      last_activation_delta: {
        hosts_added: 3,
        hosts_removed: 1,
        hosts_changed: 2,
      },
    });
    expect(out.activeFeedVersion).toBe(42);
    expect(out.lastActivationDelta?.hostsAdded).toBe(3);
  });

  it("passes an unknown state through for degraded rendering — never coerced", () => {
    const out = decodeSaasFeedStatus({ ...base, state: "brand_new_state" });
    expect(out.state).toBe("brand_new_state");
    expect(isKnownSaasState(out.state)).toBe(false);
  });

  it("the bounded vocabulary matches the server's nine states", () => {
    expect(SAAS_FEED_STATES).toHaveLength(9);
    for (const s of SAAS_FEED_STATES) expect(isKnownSaasState(s)).toBe(true);
  });
});

describe("decodeSaasFeedSettings", () => {
  const base = {
    managed: true,
    enabled: true,
    url: "",
    protocol: "signed_manifest_v1",
    refresh_seconds: 0,
    official_url:
      "https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json",
    editable: true,
    revision: "rev1",
  };

  it("decodes the resolved branch", () => {
    const out = decodeSaasFeedSettings({
      ...base,
      resolved: {
        url: base.official_url,
        protocol: "signed_manifest_v1",
        enabled: true,
        refresh_seconds: 86400,
      },
    });
    expect(out.resolved?.refreshSeconds).toBe(86400);
    expect(out.resolveError).toBeNull();
    expect(out.revision).toBe("rev1");
  });

  it("decodes the resolve_error branch and cluster_publish_rejected", () => {
    const out = decodeSaasFeedSettings({
      ...base,
      resolve_error: "invalid url: nope",
      cluster_publish_rejected: "snapshot too large",
    });
    expect(out.resolved).toBeNull();
    expect(out.resolveError).toBe("invalid url: nope");
    expect(out.clusterPublishRejected).toBe("snapshot too large");
  });

  it("refuses a payload without a revision (fail-closed fence input)", () => {
    const { revision, ...noRev } = base;
    void revision;
    expect(() => decodeSaasFeedSettings(noRev)).toThrow();
  });
});

describe("decodeSaasOverrides", () => {
  it("treats {} overrides as the legitimate empty set", () => {
    const out = decodeSaasOverrides({
      overrides: {},
      editable: true,
      revision: "none",
    });
    expect(Object.keys(out.added)).toHaveLength(0);
    expect(out.tombstones).toHaveLength(0);
    expect(out.revision).toBe("none");
  });

  it("decodes all three kinds with subtree keys", () => {
    const out = decodeSaasOverrides({
      overrides: {
        added: { "work.example.com": "business" },
        recategorized: { "chat.example.com": "social" },
        tombstones: ["ads.example.com"],
      },
      editable: false,
      revision: "abc",
    });
    expect(out.added["work.example.com"]).toBe("business");
    expect(out.recategorized["chat.example.com"]).toBe("social");
    expect(out.tombstones).toEqual(["ads.example.com"]);
    expect(out.editable).toBe(false);
  });
});
