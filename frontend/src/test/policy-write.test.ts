// 2B.1 — write-DTO / conflict / draft-state decoder proofs.
//
// The load-bearing test is field preservation (§11): PUT /api/policy is FULL
// REPLACEMENT, so decode → seed → serialize must round-trip every
// client-authoritative field — including the tri-states whose ABSENT wire
// value is distinct from an explicit boolean — and must NEVER emit
// server-owned fields (id, hit counters, metadata stamps, object-link ids).
import { describe, expect, it } from "vitest";
import { decodePolicyRule } from "../api/policy";
import {
  asPolicyConflict,
  serializeAccessRuleWrite,
  writeSeedFromView,
} from "../api/policyWrite";
import { decodeDraftState } from "../api/policyDraft";
import { ApiError } from "../api/client";
import { DecodeError } from "../api/decode";

// A wire rule with EVERY editable field at a non-default value, plus every
// server-owned field populated so leakage is detectable.
const fullWireRule = {
  priority: 7,
  id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  ruleType: "access",
  name: "full-rule",
  enabled: false,
  sourceIP: "10.0.0.0/8",
  sourceIdentity: "alice",
  sourceGroup: "engineering",
  authSource: "okta",
  destFQDN: "*.example.com",
  destCategory: "News",
  destCategoryGroup: "Media",
  destCategoryGroupId: "grp-123",
  destCountry: ["DE", "FR"],
  schedule: {
    days: ["Mon", "Tue"],
    timeStart: "09:00",
    timeEnd: "17:30",
    timezone: "Europe/Berlin",
  },
  sslAction: "Inspect",
  fileFiltering: true,
  fileProfile: "Executables",
  logFullUri: true,
  logTraffic: false,
  stripAlpn: false,
  tlsSkipVerify: true,
  decryptionProfile: "strict",
  decryptionProfileId: "prof-456",
  action: "Redirect",
  redirectURL: "https://blocked.example.com",
  comment: "why this rule exists",
  hitCount: 42,
  lastHit: "2026-08-01T00:00:00Z",
  createdAt: "2026-01-01T00:00:00Z",
  modifiedAt: "2026-08-01T00:00:00Z",
  modifiedBy: "bob",
};

const SERVER_OWNED_KEYS = [
  "id",
  "hitCount",
  "lastHit",
  "createdAt",
  "modifiedAt",
  "modifiedBy",
  "destCategoryGroupId",
  "decryptionProfileId",
  "auth",
  "subjectMatch",
];

describe("AccessRuleWrite serialization (§10/§11)", () => {
  it("preserves every editable field on edit and never emits server-owned data", () => {
    const view = decodePolicyRule(fullWireRule, "$");
    const body = serializeAccessRuleWrite(writeSeedFromView(view), true);

    expect(body).toMatchObject({
      name: "full-rule",
      enabled: false,
      sourceIP: "10.0.0.0/8",
      sourceIdentity: "alice",
      sourceGroup: "engineering",
      authSource: "okta",
      destFQDN: "*.example.com",
      destCategory: "News",
      destCategoryGroup: "Media",
      destCountry: ["DE", "FR"],
      schedule: {
        days: ["Mon", "Tue"],
        timeStart: "09:00",
        timeEnd: "17:30",
        timezone: "Europe/Berlin",
      },
      sslAction: "Inspect",
      fileFiltering: true,
      fileProfile: "Executables",
      logFullUri: true,
      logTraffic: false,
      stripAlpn: false,
      tlsSkipVerify: true,
      decryptionProfile: "strict",
      action: "Redirect",
      redirectURL: "https://blocked.example.com",
      comment: "why this rule exists",
      ruleType: "access",
    });
    for (const k of SERVER_OWNED_KEYS) {
      expect(
        body,
        `server-owned key ${k} must never be serialized`,
      ).not.toHaveProperty(k);
    }
    // Position is reorder-owned: an edit body never carries priority.
    expect(body).not.toHaveProperty("priority");
  });

  it("tri-states absent on the wire stay absent in the replacement body", () => {
    const wire: Record<string, unknown> = { ...fullWireRule };
    delete wire["enabled"];
    delete wire["logTraffic"];
    delete wire["stripAlpn"];
    delete wire["schedule"];
    const view = decodePolicyRule(wire, "$");
    // Display convenience collapses absent enabled to true…
    expect(view.enabled).toBe(true);
    // …but the wire fidelity is preserved and round-trips as ABSENT.
    const body = serializeAccessRuleWrite(writeSeedFromView(view), true);
    expect(body).not.toHaveProperty("enabled");
    expect(body).not.toHaveProperty("logTraffic");
    expect(body).not.toHaveProperty("stripAlpn");
    expect(body).not.toHaveProperty("schedule");
  });

  it("create carries the requested priority hint; zero means server-assigned", () => {
    const view = decodePolicyRule(fullWireRule, "$");
    const seed = writeSeedFromView(view);
    expect(serializeAccessRuleWrite(seed, false)["priority"]).toBe(7);
    expect(
      serializeAccessRuleWrite({ ...seed, priority: 0 }, false),
    ).not.toHaveProperty("priority");
  });

  it("refuses to seed from auth rules, unknown ruleTypes, and unsupported actions", () => {
    const auth = decodePolicyRule({ ...fullWireRule, ruleType: "auth" }, "$");
    expect(() => writeSeedFromView(auth)).toThrow(/not an access rule/);
    const unknown = decodePolicyRule(
      { ...fullWireRule, ruleType: "future-kind" },
      "$",
    );
    expect(() => writeSeedFromView(unknown)).toThrow(/not an access rule/);
    const badAction = decodePolicyRule(
      { ...fullWireRule, action: "Quarantine" },
      "$",
    );
    expect(() => writeSeedFromView(badAction)).toThrow(/unsupported action/);
  });

  it("a legacy rule with no ruleType round-trips without inventing one", () => {
    const wire: Record<string, unknown> = { ...fullWireRule };
    delete wire["ruleType"];
    const body = serializeAccessRuleWrite(
      writeSeedFromView(decodePolicyRule(wire, "$")),
      true,
    );
    expect(body).not.toHaveProperty("ruleType");
  });
});

describe("structured policy version conflict (§24)", () => {
  const conflictJSON = JSON.stringify({
    error:
      "the rulebase changed since you loaded it (your version 5, current 7) — reload and reapply your change",
    currentVersion: 7,
    yourVersion: 5,
  });

  it("decodes the structured 409", () => {
    const err = new ApiError("http", "x", 409, conflictJSON);
    const c = asPolicyConflict(err);
    expect(c).not.toBeNull();
    expect(c?.currentVersion).toBe(7);
    expect(c?.yourVersion).toBe(5);
    expect(c?.error).toContain("rulebase changed");
  });

  it("returns null for non-409, plain-text 409, and wrong-shape JSON", () => {
    expect(
      asPolicyConflict(new ApiError("http", "x", 500, conflictJSON)),
    ).toBeNull();
    expect(
      asPolicyConflict(
        new ApiError("http", "x", 409, "a draft with pending changes exists"),
      ),
    ).toBeNull();
    expect(
      asPolicyConflict(
        new ApiError("http", "x", 409, JSON.stringify({ error: "e" })),
      ),
    ).toBeNull();
    expect(asPolicyConflict(new Error("not api"))).toBeNull();
    expect(asPolicyConflict(new ApiError("network", "x"))).toBeNull();
  });
});

describe("draft state decoder (§17)", () => {
  it("inactive: common truth only, no invented candidate fields", () => {
    const st = decodeDraftState(
      { requireCommit: true, active: false, actor: "", startedAt: "" },
      "$",
    );
    expect(st.active).toBe(false);
    expect(st.requireCommit).toBe(true);
    expect(st).not.toHaveProperty("diff");
    expect(st).not.toHaveProperty("version");
  });

  it("active: requires diff/pendingCount/version; tolerates null shadows", () => {
    const st = decodeDraftState(
      {
        requireCommit: true,
        active: true,
        actor: "admin",
        startedAt: "2026-08-28T00:00:00Z",
        diff: { added: ["a"], modified: null, removed: [] },
        pendingCount: 1,
        version: 12,
        shadows: null,
      },
      "$",
    );
    if (!st.active) throw new Error("expected active");
    expect(st.diff.added).toEqual(["a"]);
    expect(st.diff.modified).toEqual([]);
    expect(st.version).toBe(12);
    expect(st.shadows).toEqual([]);
    expect(st.actor).toBe("admin");
  });

  it("active missing candidate fields fails closed", () => {
    expect(() =>
      decodeDraftState(
        { requireCommit: true, active: true, actor: "a", startedAt: "t" },
        "$",
      ),
    ).toThrow(DecodeError);
  });

  it("stranded recovery shape decodes: active draft with requireCommit OFF", () => {
    const st = decodeDraftState(
      {
        requireCommit: false,
        active: true,
        actor: "admin",
        startedAt: "2026-08-28T00:00:00Z",
        diff: { added: [], modified: ["m"], removed: [] },
        pendingCount: 1,
        version: 4,
        shadows: [{ rule: "b", shadowedBy: "a" }],
      },
      "$",
    );
    if (!st.active) throw new Error("expected active");
    expect(st.requireCommit).toBe(false);
    expect(st.shadows[0]).toEqual({ rule: "b", shadowedBy: "a" });
  });
});
