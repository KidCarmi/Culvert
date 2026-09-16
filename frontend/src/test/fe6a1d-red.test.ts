// FE-6A.1 CORRECTION ROUND 2 — RED matrix, written against the frozen
// candidate b9336de0 BEFORE any product change. External review found the
// fail-closed read boundary incomplete in two places:
//
//   D1 `decodeLegacyLDAP` returned as soon as `present:false`, so a record
//      that ALSO carried present-only facts (active, url, bindDn, …) was
//      accepted and those facts silently discarded — not a runtime union.
//   D2 `present:true` required only six of the eleven non-secret settings the
//      handler always emits (ui_auth_ldap.go apiIdPLegacyLDAP): userFilter,
//      requiredGroup, startTls, tlsSkipVerify and cacheTtlSeconds were
//      neither represented nor required, so incomplete evidence was accepted
//      and the security-effective legacy configuration was absent from the
//      read surface.
//   D3 `decodeIdPList` mapped a MISSING `profiles` key to [] (the handler
//      always emits the key; OpenAPI marks it required). `null` stays the
//      legitimate empty-slice wire form; absence must be a decode failure.
//   D4 `decodeLockouts` mapped a MISSING `lockouts` key to [] — a malformed
//      response rendered "No active lockouts". Same rule as D3.
import { describe, expect, it } from "vitest";
import { DecodeError } from "../api/decode";
import { decodeIdPList, decodeLegacyLDAP } from "../api/idp";
import { decodeLockouts } from "../api/admins";
import { LEGACY_ABSENT, LEGACY_PRESENT } from "./fe6a1d-fixtures";

const omit = (o: Record<string, unknown>, k: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).filter(([key]) => key !== k));

const PRESENT_ONLY_FIELDS = [
  "active",
  "shadowed",
  "url",
  "baseDn",
  "bindDn",
  "bindCredentialConfigured",
  "userFilter",
  "requiredGroup",
  "startTls",
  "tlsSkipVerify",
  "cacheTtlSeconds",
  "cutoverConfirmValue",
  "importSourceRevision",
] as const;

const NEWLY_REQUIRED = [
  "userFilter",
  "requiredGroup",
  "startTls",
  "tlsSkipVerify",
  "cacheTtlSeconds",
] as const;

describe("D1 present:false is a real union member", () => {
  it("accepts the absent block with and without its cutover record (control)", () => {
    expect(decodeLegacyLDAP(LEGACY_ABSENT).present).toBe(false);
    const bare = decodeLegacyLDAP(omit(LEGACY_ABSENT, "cutover"));
    expect(bare.present).toBe(false);
    expect(bare.cutover).toBeUndefined();
  });

  it("REFUSES an absent block that carries any present-only fact", () => {
    for (const k of PRESENT_ONLY_FIELDS) {
      const contradictory = {
        ...LEGACY_ABSENT,
        [k]: LEGACY_PRESENT[k],
      };
      expect(() => decodeLegacyLDAP(contradictory), k).toThrow(DecodeError);
    }
  });
});

describe("D2 present:true requires every always-emitted non-secret setting", () => {
  it("decodes and EXPOSES the security-effective configuration", () => {
    const l = decodeLegacyLDAP(LEGACY_PRESENT);
    expect(l.present).toBe(true);
    if (!l.present) throw new Error("unreachable");
    expect(l.userFilter).toBe("(uid=%s)");
    expect(l.requiredGroup).toBe("cn=proxy-users,dc=legacy,dc=example");
    expect(l.startTls).toBe(true);
    expect(l.tlsSkipVerify).toBe(true);
    expect(l.cacheTtlSeconds).toBe(300);
    expect(l.baseDn).toBe("dc=legacy,dc=example");
  });

  it("REFUSES a present block missing any of the five previously unrepresented settings", () => {
    for (const k of NEWLY_REQUIRED) {
      expect(() => decodeLegacyLDAP(omit(LEGACY_PRESENT, k)), k).toThrow(
        DecodeError,
      );
    }
  });

  it("REFUSES a present block whose settings carry the wrong type", () => {
    expect(() =>
      decodeLegacyLDAP({ ...LEGACY_PRESENT, cacheTtlSeconds: "300" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeLegacyLDAP({ ...LEGACY_PRESENT, tlsSkipVerify: "false" }),
    ).toThrow(DecodeError);
    expect(() => decodeLegacyLDAP({ ...LEGACY_PRESENT, startTls: 1 })).toThrow(
      DecodeError,
    );
    expect(() =>
      decodeLegacyLDAP({ ...LEGACY_PRESENT, requiredGroup: null }),
    ).toThrow(DecodeError);
  });

  it("an empty filter / group is a legitimate configured value, not absence", () => {
    const l = decodeLegacyLDAP({
      ...LEGACY_PRESENT,
      userFilter: "",
      requiredGroup: "",
    });
    if (!l.present) throw new Error("unreachable");
    expect(l.userFilter).toBe("");
    expect(l.requiredGroup).toBe("");
  });
});

const LIST = {
  persisted: true,
  degraded: false,
  revision: "r-abc123",
  profiles: [],
  scope: "cluster-synced",
  cluster: { state: "published", publishedVersion: 42 },
  operations: {
    degraded: false,
    retained: 0,
    unresolved: 0,
    capacity: 256,
    auditSink: "file",
  },
};

describe("D3 IdPList.profiles: absence fails closed, null is the empty slice", () => {
  it("accepts [] and null as empty (control)", () => {
    expect(decodeIdPList(LIST).profiles).toEqual([]);
    expect(decodeIdPList({ ...LIST, profiles: null }).profiles).toEqual([]);
  });
  it("REFUSES a list without the profiles key", () => {
    expect(() => decodeIdPList(omit(LIST, "profiles"))).toThrow(DecodeError);
  });
});

const LOCKS = { lockouts: [], generation: 7, scope: "node-local" };

describe("D4 LockoutsList.lockouts: absence fails closed, null is the empty slice", () => {
  it("accepts [] and null as empty (control)", () => {
    expect(decodeLockouts(LOCKS).lockouts).toEqual([]);
    expect(decodeLockouts({ ...LOCKS, lockouts: null }).lockouts).toEqual([]);
  });
  it("REFUSES a lock set without the lockouts key", () => {
    expect(() => decodeLockouts(omit(LOCKS, "lockouts"))).toThrow(DecodeError);
  });
});
