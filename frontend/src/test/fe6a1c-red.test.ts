// FE-6A.1 CORRECTION RED matrix (pure modules) — written against the frozen
// FE-6A.1 candidate 6ab24a1e BEFORE any product change. Each row pins one of
// the five review blockers against the AUTHORITATIVE vocabularies and wire
// rules (controlplane_snapshot.go publishReject*, idp_operations.go
// degradation reasons + Finish/settleOperation, ui_refusal.go refusal codes,
// ui_auth.go apiIdPOperations, store.go UIUserInfo, ui_auth_ldap.go
// apiIdPLegacyLDAP, auth_idp.go publicIdPProfile):
//
//   C1  bounded classes are ENUMS, never strings: an out-of-vocabulary fleet
//       rejection reason, ledger degradation reason, operation action,
//       operation code (refusal or settlement) or lookup refusal code is
//       REFUSED — a raw dependency error can never ride one of these fields
//       into the DOM.
//   C2  missing evidence is never negative truth: a roster without `users`,
//       a user without `totpEnabled`, a present legacy block without
//       `bindCredentialConfigured`, a profile without its type-specific
//       object (or carrying another type's object), a profile without
//       `priority` / `emailDomains` (always on the wire — Go emits them
//       without omitempty, nullable) all FAIL CLOSED. The indicator bits
//       INSIDE a present sub-config keep Go's omitempty rule (absent ⇒ false)
//       because the authoritative schema now declares exactly that.
//   C3  the operation record is a DISCRIMINATED UNION: pending carries no
//       terminal field; committed requires finishedAt + committedRevision
//       and either audited:true (no auditState) or audited:false +
//       auditState:pending; aborted / outcome_unknown require finishedAt +
//       a bounded code and carry no committedRevision / auditState; a
//       contradictory record is refused whole, never partially rendered.
//   C5  the roster posture is THREE explicit states (none / last_admin /
//       multiple) — zero administrators is never "more than one".
import { describe, expect, it } from "vitest";
import { DecodeError } from "../api/decode";
import { ApiError } from "../api/client";
import {
  IDP_FLEET_REJECTION_REASONS,
  IDP_LEDGER_DEGRADED_REASONS,
  IDP_OPERATION_ACTIONS,
  IDP_OPERATION_CODES,
  IDP_LOOKUP_REFUSAL_CODES,
  decodeIdPList,
  decodeIdPOperation,
  decodeIdPProfile,
  decodeLegacyLDAP,
} from "../api/idp";
import { decodeAdminRoster, rosterFacts } from "../api/admins";
import { refusalCodeOf } from "../shared/readErrorSummary";

const RAW = "dial tcp /data/private: permission denied";

const omit = (o: Record<string, unknown>, k: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).filter(([key]) => key !== k));

const OIDC = {
  id: "oidc-corp",
  name: "Corp OIDC",
  type: "oidc",
  emailDomains: ["corp.example"],
  enabled: true,
  priority: 10,
  revision: 3,
  oidc: {
    issuer: "https://issuer.example",
    clientId: "c",
    clientSecretConfigured: true,
  },
};
const LDAP = {
  id: "ldap-dc",
  name: "DC LDAP",
  type: "ldap",
  emailDomains: null,
  enabled: true,
  priority: 5,
  revision: 2,
  ldap: {
    url: "ldaps://dc.example:636",
    bindDn: "cn=svc",
    bindCredentialConfigured: true,
    baseDn: "dc=example",
  },
};
const LIST = {
  persisted: true,
  degraded: false,
  revision: "r-abc123",
  profiles: [OIDC, LDAP],
  scope: "cluster-synced",
  cluster: {
    state: "pending",
    publishedVersion: 41,
    lastRejection: { reason: "snapshot_invalid", at: "2026-09-12T10:00:00Z" },
  },
  operations: {
    degraded: true,
    degradedReason: "corrupt",
    retained: 0,
    unresolved: 0,
    capacity: 256,
    auditSink: "memory",
  },
};
const OP_BASE = {
  operationId: "0b6f9a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b",
  action: "idp.create",
  actor: "admin@10.0.0.9",
  profileId: "ldap-dc",
  registryRevision: "r-prev",
  cutover: true,
  startedAt: "2026-09-12T09:59:00Z",
};
const PENDING = { ...OP_BASE, state: "pending", audited: false };
const COMMITTED = {
  ...OP_BASE,
  state: "committed",
  audited: true,
  finishedAt: "t",
  committedRevision: "r-abc123",
  result: { id: "ldap-dc" },
};
const COMMITTED_OWED = { ...COMMITTED, audited: false, auditState: "pending" };
const ABORTED = {
  ...OP_BASE,
  state: "aborted",
  audited: false,
  finishedAt: "t",
  code: "stale",
};
const UNKNOWN = {
  ...OP_BASE,
  state: "outcome_unknown",
  audited: false,
  finishedAt: "t",
  code: "outcome_unknown",
};

describe("C1 bounded classes are enums", () => {
  it("pins the authoritative vocabularies", () => {
    expect([...IDP_FLEET_REJECTION_REASONS]).toEqual([
      "identity_degraded",
      "snapshot_invalid",
      "marshal_failed",
      "wire_size_exceeded",
    ]);
    expect([...IDP_LEDGER_DEGRADED_REASONS]).toEqual(["unreadable", "corrupt"]);
    expect([...IDP_OPERATION_ACTIONS]).toEqual(["idp.create"]);
    // Refusal codes writeIdPRefusal can record on an aborted/unknown intent
    // + the three settlement families × three verdicts.
    for (const c of [
      "stale",
      "invalid_input",
      "provider_compile_failed",
      "operation_ledger_degraded",
      "operation_unsettled",
      "operation_ledger_full",
      "persist_failed",
      "vanished",
      "registry_degraded",
      "outcome_unknown",
      "reconciled_committed",
      "reconciled_absent",
      "reconciled_unproven",
      "lookup_committed",
      "lookup_absent",
      "lookup_unproven",
      "settled_before_write_committed",
      "settled_before_write_absent",
      "settled_before_write_unproven",
    ]) {
      expect(IDP_OPERATION_CODES, c).toContain(c);
    }
    expect(IDP_OPERATION_CODES).not.toContain(RAW);
    expect([...IDP_LOOKUP_REFUSAL_CODES]).toEqual([
      "invalid_input",
      "forbidden",
      "not_found",
      "operation_ledger_degraded",
    ]);
  });

  it("refuses a raw fleet rejection reason and an unknown ledger reason", () => {
    expect(decodeIdPList(LIST).cluster.lastRejection?.reason).toBe(
      "snapshot_invalid",
    );
    expect(() =>
      decodeIdPList({
        ...LIST,
        cluster: { ...LIST.cluster, lastRejection: { reason: RAW, at: "t" } },
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeIdPList({
        ...LIST,
        operations: { ...LIST.operations, degradedReason: RAW },
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeIdPList({
        ...LIST,
        operations: { ...LIST.operations, degradedReason: "torn" },
      }),
    ).toThrow(DecodeError);
    for (const r of IDP_FLEET_REJECTION_REASONS) {
      expect(
        decodeIdPList({
          ...LIST,
          cluster: { ...LIST.cluster, lastRejection: { reason: r, at: "t" } },
        }).cluster.lastRejection?.reason,
      ).toBe(r);
    }
  });

  it("refuses an unknown operation action and an out-of-vocabulary code", () => {
    expect(() =>
      decodeIdPOperation({ ...COMMITTED, action: "idp.delete" }),
    ).toThrow(DecodeError);
    expect(() => decodeIdPOperation({ ...ABORTED, code: RAW })).toThrow(
      DecodeError,
    );
    expect(() =>
      decodeIdPOperation({ ...ABORTED, code: "made_up_code" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeIdPOperation({ ...COMMITTED, code: "reconciled_absent" }),
    ).toThrow(DecodeError); // a committed record never carries an absent verdict
    expect(
      decodeIdPOperation({ ...COMMITTED, code: "lookup_committed" }).code,
    ).toBe("lookup_committed");
    expect(
      decodeIdPOperation({ ...ABORTED, code: "settled_before_write_unproven" })
        .code,
    ).toBe("settled_before_write_unproven");
  });

  it("the lookup refusal code is a verdict only inside the lookup vocabulary", () => {
    const err = (code: string): ApiError =>
      new ApiError("http", "x", 503, JSON.stringify({ error: RAW, code }));
    expect(
      refusalCodeOf(err("operation_ledger_degraded"), IDP_LOOKUP_REFUSAL_CODES),
    ).toBe("operation_ledger_degraded");
    expect(
      refusalCodeOf(err("made_up_code"), IDP_LOOKUP_REFUSAL_CODES),
    ).toBeNull();
    expect(refusalCodeOf(err("stale"), IDP_LOOKUP_REFUSAL_CODES)).toBeNull(); // a real code, but not one this endpoint answers
    expect(
      refusalCodeOf(
        new ApiError("http", "x", 503, RAW),
        IDP_LOOKUP_REFUSAL_CODES,
      ),
    ).toBeNull();
  });
});

describe("C2 missing evidence fails closed", () => {
  const ROSTER = {
    users: [
      {
        username: "admin",
        role: "admin",
        totpEnabled: false,
        securityGeneration: 4,
      },
    ],
    revision: 7,
    scope: "node-local",
  };
  it("roster: users and totpEnabled are required", () => {
    expect(() => decodeAdminRoster(omit(ROSTER, "users"))).toThrow(DecodeError);
    expect(() => decodeAdminRoster({ ...ROSTER, users: null })).toThrow(
      DecodeError,
    );
    expect(() =>
      decodeAdminRoster({
        ...ROSTER,
        users: [{ username: "admin", role: "admin", securityGeneration: 4 }],
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeAdminRoster({
        ...ROSTER,
        users: [{ username: "admin", role: "admin", totpEnabled: false }],
      }),
    ).toThrow(DecodeError);
    expect(decodeAdminRoster({ ...ROSTER, users: [] }).users).toEqual([]);
  });

  it("legacy LDAP: a present block must state its credential indicator", () => {
    const present = {
      present: true,
      active: true,
      retired: false,
      shadowed: false,
      scope: "node-local",
      cutoverDurability: "not_retired",
      url: "ldaps://x:636",
      bindDn: "cn=svc",
      bindCredentialConfigured: true,
    };
    expect(decodeLegacyLDAP(present).bindCredentialConfigured).toBe(true);
    expect(() =>
      decodeLegacyLDAP(omit(present, "bindCredentialConfigured")),
    ).toThrow(DecodeError);
    expect(() => decodeLegacyLDAP(omit(present, "active"))).toThrow(
      DecodeError,
    );
    expect(() => decodeLegacyLDAP(omit(present, "url"))).toThrow(DecodeError);
    // absent block: those fields are legitimately not on the wire
    expect(
      decodeLegacyLDAP({
        present: false,
        retired: false,
        scope: "node-local",
        cutoverDurability: "not_retired",
      }).present,
    ).toBe(false);
  });

  it("profile: the type-specific object must be present and must be the type's own", () => {
    expect(() => decodeIdPProfile(omit(OIDC, "oidc"))).toThrow(DecodeError);
    expect(() =>
      decodeIdPProfile({
        ...omit(OIDC, "oidc"),
        saml: { inlineMetadataConfigured: true },
      }),
    ).toThrow(DecodeError);
    expect(() => decodeIdPProfile({ ...OIDC, oidc: null })).toThrow(
      DecodeError,
    );
    expect(() => decodeIdPProfile({ ...LDAP, oidc: { issuer: "x" } })).toThrow(
      DecodeError,
    ); // a foreign sub-config
    expect(() => decodeIdPProfile(omit(OIDC, "priority"))).toThrow(DecodeError);
    expect(() => decodeIdPProfile(omit(OIDC, "emailDomains"))).toThrow(
      DecodeError,
    );
    // Go omitempty on the indicator bits INSIDE a present sub-config: absent ⇒ false (declared on the contract)
    expect(
      decodeIdPProfile({
        ...OIDC,
        oidc: { issuer: "https://i", clientId: "c" },
      }).oidc?.clientSecretConfigured,
    ).toBe(false);
    expect(decodeIdPProfile(LDAP).ldap?.bindCredentialConfigured).toBe(true);
  });
});

describe("C3 operation record is a discriminated union", () => {
  it("accepts every coherent shape", () => {
    expect(decodeIdPOperation(PENDING).state).toBe("pending");
    expect(decodeIdPOperation(COMMITTED).audited).toBe(true);
    expect(decodeIdPOperation(COMMITTED_OWED).auditState).toBe("pending");
    expect(decodeIdPOperation(ABORTED).code).toBe("stale");
    expect(decodeIdPOperation({ ...ABORTED, code: "lookup_absent" }).code).toBe(
      "lookup_absent",
    );
    expect(decodeIdPOperation(UNKNOWN).state).toBe("outcome_unknown");
  });

  it("refuses contradictory records whole", () => {
    const bad: Array<[string, Record<string, unknown>]> = [
      ["pending audited", { ...PENDING, audited: true }],
      ["pending finished", { ...PENDING, finishedAt: "t" }],
      ["pending with code", { ...PENDING, code: "stale" }],
      [
        "pending with committedRevision",
        { ...PENDING, committedRevision: "r" },
      ],
      ["pending with auditState", { ...PENDING, auditState: "pending" }],
      [
        "committed unaudited without owed marker",
        { ...COMMITTED, audited: false },
      ],
      [
        "committed audited with owed marker",
        { ...COMMITTED, auditState: "pending" },
      ],
      [
        "committed without committedRevision",
        omit(COMMITTED, "committedRevision"),
      ],
      ["committed without finishedAt", omit(COMMITTED, "finishedAt")],
      ["aborted without code", omit(ABORTED, "code")],
      ["aborted without finishedAt", omit(ABORTED, "finishedAt")],
      [
        "aborted with committedRevision",
        { ...ABORTED, committedRevision: "r" },
      ],
      ["aborted audited", { ...ABORTED, audited: true }],
      ["aborted with auditState", { ...ABORTED, auditState: "pending" }],
      ["outcome_unknown without code", omit(UNKNOWN, "code")],
      [
        "outcome_unknown with committedRevision",
        { ...UNKNOWN, committedRevision: "r" },
      ],
      ["outcome_unknown audited", { ...UNKNOWN, audited: true }],
    ];
    for (const [name, rec] of bad) {
      expect(() => decodeIdPOperation(rec), name).toThrow(DecodeError);
    }
  });
});

describe("C5 roster posture is three explicit states", () => {
  const mk = (roles: string[]): ReturnType<typeof decodeAdminRoster> =>
    decodeAdminRoster({
      users: roles.map((r, i) => ({
        username: `u${String(i)}`,
        role: r,
        totpEnabled: false,
        securityGeneration: 1,
      })),
      revision: 1,
      scope: "node-local",
    });
  it("distinguishes none / last_admin / multiple", () => {
    expect(rosterFacts(mk([])).posture).toBe("none");
    expect(rosterFacts(mk(["viewer", "operator"])).posture).toBe("none");
    expect(rosterFacts(mk(["admin", "viewer"])).posture).toBe("last_admin");
    expect(rosterFacts(mk(["admin", "viewer"])).lastAdmin).toBe("u0");
    expect(rosterFacts(mk(["admin", "admin"])).posture).toBe("multiple");
    expect(rosterFacts(mk(["admin", "admin"])).lastAdmin).toBeNull();
  });
});
