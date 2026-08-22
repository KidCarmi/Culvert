// Slice 2A §27: policy envelope / tester / where-used decoder matrix + the
// deep-link parameter gate. Fixtures mirror the Go handlers exactly
// (ui_policy.go apiPolicy GET + apiPolicyTest, ui_authpolicy.go
// simulateAuthOutcome, policy_refs.go apiObjectReferences).
import { describe, expect, it } from "vitest";
import {
  classifyRuleType,
  decodeObjectReferences,
  decodePolicySnapshot,
  decodeTesterResult,
  isPlausibleRuleID,
  MAX_RULE_LINK_ID_LENGTH,
} from "../api/policy";
import { DecodeError } from "../api/decode";

const accessRule = {
  priority: 1,
  name: "Allow intranet",
  sourceIP: "10.0.0.0/8",
  sourceIdentity: "",
  sourceGroup: "",
  authSource: "",
  destFQDN: "*.intra.example",
  destCategory: "",
  destCategoryGroup: "",
  destCountry: null, // Go nil slice serializes as null
  sslAction: "Bypass",
  fileFiltering: false,
  fileProfile: "",
  logFullUri: false,
  tlsSkipVerify: false,
  action: "Allow",
  redirectURL: "",
  hitCount: 42,
  id: "01J3ZV9E3JD0AAAABBBBCCCCDD",
  lastHit: "2026-08-22T12:00:00Z",
  createdAt: "2026-08-01T00:00:00Z",
  modifiedAt: "2026-08-10T00:00:00Z",
  modifiedBy: "admin",
  comment: "seed",
};

const authRule = {
  ...accessRule,
  priority: 9001,
  name: "Exempt printers",
  id: "01J3ZV9E3JD0EEEEFFFFGGGGHH",
  ruleType: "auth",
  auth: {
    outcome: "Exempt",
    owner: "netops",
    reason: "printer fleet",
    broadExemption: false,
  },
};

const omit = (o: Record<string, unknown>, k: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).filter(([key]) => key !== k));

function envelope(rules: unknown[], draft = false): Record<string, unknown> {
  return {
    rules,
    count: rules.length,
    version: 7,
    updatedAt: "2026-08-22T12:34:56Z",
    draft,
  };
}

describe("policy envelope decoder (§27)", () => {
  it("decodes a valid running envelope", () => {
    const snap = decodePolicySnapshot(envelope([accessRule]));
    expect(snap.draft).toBe(false);
    expect(snap.version).toBe(7);
    expect(snap.accessRules).toHaveLength(1);
    expect(snap.accessRules[0]?.destCountry).toEqual([]);
    expect(snap.accessRules[0]?.enabled).toBe(true); // absent *bool ⇒ enabled
  });

  it("decodes a valid draft envelope", () => {
    const snap = decodePolicySnapshot(envelope([accessRule], true));
    expect(snap.draft).toBe(true);
  });

  it("fails closed on an invalid version", () => {
    expect(() =>
      decodePolicySnapshot({ ...envelope([accessRule]), version: "7" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodePolicySnapshot(omit(envelope([accessRule]), "draft")),
    ).toThrow(DecodeError);
  });

  it("fails closed on a malformed rule", () => {
    expect(() =>
      decodePolicySnapshot(envelope([{ ...accessRule, priority: "one" }])),
    ).toThrow(DecodeError);
    expect(() =>
      decodePolicySnapshot(envelope([{ ...accessRule, name: 7 }])),
    ).toThrow(DecodeError);
    expect(() =>
      decodePolicySnapshot(envelope([{ ...accessRule, enabled: "yes" }])),
    ).toThrow(DecodeError);
  });

  it("classifies access rules (both spellings) as access", () => {
    expect(classifyRuleType("")).toBe("access");
    expect(classifyRuleType("access")).toBe("access");
    const snap = decodePolicySnapshot(
      envelope([
        accessRule,
        { ...accessRule, priority: 2, ruleType: "access" },
      ]),
    );
    expect(snap.accessRules).toHaveLength(2);
  });

  it("excludes Stage-1 auth rules from the access surface", () => {
    const snap = decodePolicySnapshot(envelope([accessRule, authRule]));
    expect(snap.accessRules).toHaveLength(1);
    expect(snap.authRuleCount).toBe(1);
    expect(snap.accessRules[0]?.name).toBe("Allow intranet");
  });

  it("handles an unknown future rule type fail-closed (never an access rule)", () => {
    expect(classifyRuleType("quantum")).toBe("unknown");
    const snap = decodePolicySnapshot(
      envelope([accessRule, { ...accessRule, priority: 3, ruleType: "v99" }]),
    );
    expect(snap.accessRules).toHaveLength(1);
    expect(snap.unknownKindCount).toBe(1);
  });

  it("does not equate server count with rules.length", () => {
    const snap = decodePolicySnapshot({
      ...envelope([accessRule, authRule]),
      count: 2,
    });
    // count is the server's mixed-envelope count; the access surface derives
    // its own number.
    expect(snap.count).toBe(2);
    expect(snap.accessRules).toHaveLength(1);
  });
});

// ── tester (§27) ───────────────────────────────────────────────────────────

const authBlock = {
  outcome: "Exempt",
  runtimeOutcome: "Exempt",
  defaultAuthOutcome: "Exempt",
  fromDefault: true,
  killSwitch: false,
  credentialsPresented: false,
  stage2AuthSource: "unauth",
  stage2Reached: true,
  stage2Note: "",
  note: "Open unmatched traffic …",
};

const traceRow = { priority: 1, name: "Allow intranet", skipReason: "host" };

const matchedFixture = {
  matched: true,
  rule: accessRule,
  action: "Allow",
  trace: [traceRow],
  hostCategory: { category: "Business", tier: "admin", matchedBy: "*.x" },
  auth: authBlock,
  rulebase: "running",
};

const noMatchFixture = {
  matched: false,
  defaultAction: "deny",
  trace: [traceRow],
  hostCategory: { category: "", tier: "", matchedBy: "" },
  auth: { ...authBlock, rule: { id: "01X", name: "waiver", owner: "sec" } },
  rulebase: "draft",
};

describe("tester result decoder (§27)", () => {
  it("decodes the matched union", () => {
    const r = decodeTesterResult(matchedFixture);
    expect(r.matched).toBe(true);
    if (r.matched) {
      expect(r.rule.name).toBe("Allow intranet");
      expect(r.action).toBe("Allow");
    }
    expect(r.rulebase).toBe("running");
  });

  it("decodes the no-match union with defaultAction", () => {
    const r = decodeTesterResult(noMatchFixture);
    expect(r.matched).toBe(false);
    if (!r.matched) expect(r.defaultAction).toBe("deny");
    expect(r.rulebase).toBe("draft");
    expect(r.auth.rule?.name).toBe("waiver");
  });

  it("accepts only the supported rulebase values", () => {
    expect(() =>
      decodeTesterResult({ ...matchedFixture, rulebase: "candidate" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeTesterResult({ ...matchedFixture, rulebase: 3 }),
    ).toThrow(DecodeError);
  });

  it("fails closed on a malformed trace", () => {
    expect(() =>
      decodeTesterResult({
        ...matchedFixture,
        trace: [{ priority: "1", name: "x" }],
      }),
    ).toThrow(DecodeError);
  });

  it("fails closed on a malformed auth block", () => {
    expect(() =>
      decodeTesterResult({
        ...matchedFixture,
        auth: { ...authBlock, credentialsPresented: "no" },
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeTesterResult({
        ...matchedFixture,
        auth: { outcome: "Exempt" },
      }),
    ).toThrow(DecodeError);
  });

  it("rejects a matched payload missing its rule/action contract", () => {
    expect(() => decodeTesterResult(omit(matchedFixture, "rule"))).toThrow(
      DecodeError,
    );
    expect(() => decodeTesterResult(omit(matchedFixture, "action"))).toThrow(
      DecodeError,
    );
  });

  it("rejects a no-match payload missing defaultAction, and bare payloads", () => {
    expect(() =>
      decodeTesterResult(omit(noMatchFixture, "defaultAction")),
    ).toThrow(DecodeError);
    expect(() => decodeTesterResult({ matched: true })).toThrow(DecodeError);
    expect(() => decodeTesterResult({})).toThrow(DecodeError);
  });
});

// ── where-used (§27) ───────────────────────────────────────────────────────

describe("object references decoder (§27)", () => {
  it("decodes a valid empty reference set", () => {
    const refs = decodeObjectReferences({
      object: { type: "category-group", name: "Media" },
      referencedBy: [],
    });
    expect(refs.referencedBy).toHaveLength(0);
    expect(refs.object.name).toBe("Media");
  });

  it("decodes an access-rule reference", () => {
    const refs = decodeObjectReferences({
      object: { type: "file-profile", name: "Executables" },
      referencedBy: [
        {
          consumerType: "access-rule",
          id: "01J3ZV9E3JD0AAAABBBBCCCCDD",
          name: "Allow intranet",
          detail: "fileProfile",
          view: "policy",
        },
      ],
    });
    expect(refs.referencedBy[0]?.consumerType).toBe("access-rule");
  });

  it("decodes an auth-rule reference (non-navigable surface before 2C)", () => {
    const refs = decodeObjectReferences({
      object: { type: "category", name: "News" },
      referencedBy: [
        {
          consumerType: "auth-rule",
          id: "01X",
          name: "waiver",
          detail: "destCategory",
          view: "authpolicy",
        },
      ],
    });
    expect(refs.referencedBy[0]?.view).toBe("authpolicy");
  });

  it("fails closed on a malformed reference row", () => {
    expect(() =>
      decodeObjectReferences({
        object: { type: "category", name: "News" },
        referencedBy: [{ consumerType: "access-rule" }], // missing name
      }),
    ).toThrow(DecodeError);
    expect(() => decodeObjectReferences({ referencedBy: [] })).toThrow(
      DecodeError,
    );
  });
});

// ── deep-link parameter gate (§27) ─────────────────────────────────────────

describe("rule deep-link parameter gate (§10/§27)", () => {
  it("accepts a plausible ULID", () => {
    expect(isPlausibleRuleID("01J3ZV9E3JD0AAAABBBBCCCCDD")).toBe(true);
  });

  it("rejects malformed and oversized values", () => {
    expect(isPlausibleRuleID("")).toBe(false);
    expect(isPlausibleRuleID("a".repeat(MAX_RULE_LINK_ID_LENGTH + 1))).toBe(
      false,
    );
    expect(isPlausibleRuleID("<img src=x>")).toBe(false);
    expect(isPlausibleRuleID("tr[data-x]")).toBe(false);
    expect(isPlausibleRuleID("a b")).toBe(false);
    expect(isPlausibleRuleID("java script")).toBe(false);
  });
});
