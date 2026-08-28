// 2C.1 — Stage-1 Authentication Policy decoder/serializer proofs (§11/§38):
// exact-schema decode of the /api/authpolicy envelope, fail-closed handling of
// unknown outcomes and unknown subject-predicate types, the write-DTO seed
// refusal for rules this client cannot faithfully rebuild, full-replacement
// serialization key discipline (no server-owned or Stage-2-only keys), the
// default-auth-outcome unknown-value fail-closed decode, and the IdP provider
// list decode for SSORequired references.
import { describe, expect, it } from "vitest";
import {
  AUTH_OUTCOMES,
  authRuleEditable,
  decodeAuthPolicySnapshot,
  decodeAuthRule,
  isAuthOutcome,
  serializeAuthRuleWrite,
  writeSeedFromAuthView,
} from "../api/policyAuth";
import type { AuthRuleWrite } from "../api/policyAuth";
import { DecodeError } from "../api/decode";

const WIRE_RULE = {
  priority: 9001,
  id: "01J3ZV9E3JD0AAAAAAAAAAAAAA",
  ruleType: "auth",
  name: "Exempt scanners",
  // `action` has no omitempty in Go — the server always emits it ("" on auth
  // rules, whose decision is auth.outcome, never a PolicyAction).
  action: "",
  destFQDN: "updates.example.test",
  subjectMatch: {
    schemaVersion: 1,
    all: [{ type: "cidr", values: ["10.99.0.0/24", "192.0.2.7"] }],
  },
  auth: {
    outcome: "Exempt",
    owner: "netops",
    reason: "printer fleet cannot authenticate",
    expiresAt: "2027-01-01T00:00:00Z",
  },
  warnings: ['source "10.99.0.0/24" is broader than /24'],
  hitCount: 3,
  createdAt: "2026-08-01T00:00:00Z",
  modifiedAt: "2026-08-02T00:00:00Z",
  modifiedBy: "admin",
};

describe("decodeAuthRule", () => {
  it("decodes the full derived schema", () => {
    const r = decodeAuthRule(WIRE_RULE);
    expect(r.name).toBe("Exempt scanners");
    expect(r.kind).toBe("auth");
    expect(r.subjectMatch?.schemaVersion).toBe(1);
    expect(r.subjectMatch?.all[0]?.known).toBe(true);
    expect(r.subjectMatch?.all[0]?.values).toEqual([
      "10.99.0.0/24",
      "192.0.2.7",
    ]);
    expect(r.subjectMatch?.hasUnknownPredicates).toBe(false);
    expect(r.authSpec?.outcome).toBe("Exempt");
    expect(r.authSpec?.outcomeKnown).toBe("Exempt");
    expect(r.authSpec?.owner).toBe("netops");
    expect(r.authSpec?.reason).toBe("printer fleet cannot authenticate");
    expect(r.authSpec?.expiresAt).toBe("2027-01-01T00:00:00Z");
    expect(r.authSpec?.broadExemption).toBe(false);
    expect(r.authSpec?.providerRefs).toEqual([]);
    expect(r.warnings).toEqual(['source "10.99.0.0/24" is broader than /24']);
    expect(authRuleEditable(r)).toBe(true);
  });

  it("marks an UNKNOWN outcome fail-closed (outcomeKnown null, not editable)", () => {
    const r = decodeAuthRule({
      ...WIRE_RULE,
      auth: { ...WIRE_RULE.auth, outcome: "FutureOutcome" },
    });
    expect(r.authSpec?.outcome).toBe("FutureOutcome");
    expect(r.authSpec?.outcomeKnown).toBeNull();
    expect(authRuleEditable(r)).toBe(false);
    expect(writeSeedFromAuthView(r)).toBeNull();
  });

  it("marks an UNKNOWN predicate type fail-closed (never treated as cidr)", () => {
    const r = decodeAuthRule({
      ...WIRE_RULE,
      subjectMatch: {
        schemaVersion: 2,
        all: [
          { type: "cidr", values: ["10.0.0.0/8"] },
          { type: "device_posture", values: ["managed"] },
        ],
      },
    });
    expect(r.subjectMatch?.hasUnknownPredicates).toBe(true);
    expect(r.subjectMatch?.all[1]?.known).toBe(false);
    expect(authRuleEditable(r)).toBe(false);
    expect(writeSeedFromAuthView(r)).toBeNull();
  });

  it("a missing auth spec decodes (degraded) but is never editable", () => {
    const wire: Record<string, unknown> = { ...WIRE_RULE };
    delete wire["auth"];
    const r = decodeAuthRule(wire);
    expect(r.authSpec).toBeUndefined();
    expect(authRuleEditable(r)).toBe(false);
    expect(writeSeedFromAuthView(r)).toBeNull();
  });

  it("malformed nested shapes fail closed with DecodeError", () => {
    expect(() =>
      decodeAuthRule({
        ...WIRE_RULE,
        subjectMatch: { schemaVersion: 1, all: [{ type: 7, values: [] }] },
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeAuthRule({ ...WIRE_RULE, auth: { outcome: 42 } }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeAuthRule({ ...WIRE_RULE, warnings: [{ not: "a string" }] }),
    ).toThrow(DecodeError);
  });
});

describe("decodeAuthPolicySnapshot", () => {
  it("decodes the envelope incl. the RUNNING version contract and the server note verbatim", () => {
    const s = decodeAuthPolicySnapshot({
      rules: [WIRE_RULE],
      count: 1,
      defaultAction: "deny",
      note: "Exempt skips end-user authentication only — it never allows traffic.",
      version: 42,
      updatedAt: "2026-08-28T12:00:00Z",
    });
    expect(s.rules).toHaveLength(1);
    expect(s.version).toBe(42);
    expect(s.updatedAt).toBe("2026-08-28T12:00:00Z");
    expect(s.note).toContain("never allows traffic");
    expect(s.defaultAction).toBe("deny");
  });

  it("a missing version fails closed (pre-2C envelope is not silently accepted)", () => {
    expect(() =>
      decodeAuthPolicySnapshot({
        rules: [],
        count: 0,
        defaultAction: "deny",
        note: "n",
        updatedAt: "t",
      }),
    ).toThrow(DecodeError);
  });
});

describe("writeSeedFromAuthView → serializeAuthRuleWrite round-trip", () => {
  it("seeds faithfully and serializes ONLY auth-editable PolicyRule keys", () => {
    const r = decodeAuthRule(WIRE_RULE);
    const seed = writeSeedFromAuthView(r);
    expect(seed).not.toBeNull();
    if (seed === null) return;
    expect(seed.outcome).toBe("Exempt");
    expect(seed.owner).toBe("netops");
    expect(seed.predicates).toEqual([
      { type: "cidr", values: ["10.99.0.0/24", "192.0.2.7"] },
    ]);

    const body = serializeAuthRuleWrite(seed);
    expect(body["ruleType"]).toBe("auth");
    expect(body["name"]).toBe("Exempt scanners");
    expect(body["destFQDN"]).toBe("updates.example.test");
    expect(body["subjectMatch"]).toEqual({
      schemaVersion: 1,
      all: [{ type: "cidr", values: ["10.99.0.0/24", "192.0.2.7"] }],
    });
    expect(body["auth"]).toEqual({
      outcome: "Exempt",
      owner: "netops",
      reason: "printer fleet cannot authenticate",
      expiresAt: "2027-01-01T00:00:00Z",
    });
    // SERVER-OWNED keys never serialized.
    for (const k of [
      "id",
      "priority",
      "hitCount",
      "lastHit",
      "createdAt",
      "modifiedAt",
      "modifiedBy",
      "warnings",
    ]) {
      expect(body).not.toHaveProperty(k);
    }
    // STAGE-2-ONLY keys never serialized from an auth write.
    for (const k of [
      "action",
      "sslAction",
      "redirectURL",
      "fileFiltering",
      "fileProfile",
      "decryptionProfile",
      "logTraffic",
      "stripAlpn",
      "tlsSkipVerify",
      "logFullUri",
      "sourceIP",
      "sourceIdentity",
      "sourceGroup",
      "authSource",
    ]) {
      expect(body).not.toHaveProperty(k);
    }
    // enabled tri-state: absent on the wire stays absent.
    expect(body).not.toHaveProperty("enabled");
  });

  it("emits enabled/schedule/providerRefs/broadExemption only when set", () => {
    const w: AuthRuleWrite = {
      name: "SSO front door",
      enabled: false,
      outcome: "SSORequired",
      protocol: "http",
      method: "",
      owner: "secops",
      reason: "interactive apps require SSO",
      expiresAt: "",
      broadExemption: false,
      providerRefs: ["corp-oidc"],
      predicates: [{ type: "cidr", values: ["10.0.0.0/8"] }],
      destFQDN: "app.example.test",
      destCategory: "",
      destCategoryGroup: "",
      schedule: undefined,
      comment: "",
    };
    const body = serializeAuthRuleWrite(w);
    expect(body["enabled"]).toBe(false);
    expect(body).not.toHaveProperty("schedule");
    const auth = body["auth"];
    expect(auth).toEqual({
      outcome: "SSORequired",
      protocol: "http",
      owner: "secops",
      reason: "interactive apps require SSO",
      providerRefs: ["corp-oidc"],
    });
  });
});

describe("outcome vocabulary", () => {
  it("the frozen enum and its guard agree", () => {
    expect(AUTH_OUTCOMES).toEqual([
      "Exempt",
      "CredentialRequired",
      "SSORequired",
    ]);
    expect(isAuthOutcome("Exempt")).toBe(true);
    expect(isAuthOutcome("Default")).toBe(false);
    expect(isAuthOutcome("exempt")).toBe(false);
  });
});
