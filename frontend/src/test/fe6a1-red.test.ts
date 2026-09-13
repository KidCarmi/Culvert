// FE-6A.1 RED matrix (pure modules) — written against the merged FE-6A.1
// baseline (3b6ba325: FE-6A.0 frozen at 8be90030 + origin/main@de2a4584)
// BEFORE any Identity Providers / Administrators frontend code exists. On
// that tree every test fails at import resolution (`src/api/idp`,
// `src/api/admins` do not exist; the two routes are absent from
// KNOWN_ROUTES). Each assertion pins a contract the read-only React surfaces
// must honour verbatim — the frozen FE-6A.0 backend read models exactly as
// the appliance answers them (ui_auth.go idpListReadModel /
// publicIdPProfile / idpClusterReadModel, idp_operations.go
// lookupReadModel / readModel, ui_auth_ldap.go apiIdPLegacyLDAP,
// store.go UIUserInfo, internal/lockout LockedEntry), never a frontend
// re-wording:
//
//   A1  GET /api/idp decodes every list fact (persisted, degraded posture,
//       content-derived document revision, cluster-synced scope, fleet
//       publication state + last rejection, the operation-ledger posture)
//       and REJECTS an unknown scope / type / degradedReason / cluster
//       state / auditSink (never silently maps).
//   A2  a profile decodes its identity, type, enabled state, ENTRY revision,
//       provenance operationId and the derived write-only-secret INDICATORS
//       only (clientSecretConfigured / inlineMetadataConfigured /
//       bindCredentialConfigured) — a read model carrying any secret key
//       (clientSecret, bindPassword, metadataXml, password, ciphertext,
//       sealed, secret — at ANY depth) is REFUSED as a decode failure, so a
//       misbehaving server can never put a secret into the DOM.
//   A3  the quarantine evidence is a BASE NAME by contract; a value carrying
//       a path separator is refused (no file path ever reaches the browser).
//   A4  GET /api/idp/operations/{id} decodes the four bounded states,
//       `audited` + the `auditState: pending` owed-audit marker, the bounded
//       refusal `code`, and rejects an unknown state — the page never turns
//       pending / outcome_unknown into a success or failure guess.
//   A5  GET /api/idp/legacy-ldap decodes the absent-block shape, the
//       present shape with bindCredentialConfigured (never bindPassword),
//       the node-local scope, the bounded cutoverDurability word and the
//       operation-identified cutover record (trigger enum).
//   A6  GET /api/auth/users decodes username / durable role / TOTP presence
//       / per-user securityGeneration / roster revision / node-local scope
//       and REFUSES pass_hash / totp_secret / backup_codes / password /
//       totp_last_counter material; an unknown role is refused.
//   A7  GET /api/auth/lockouts decodes the null-tolerant lock set with tier
//       enum, generation and node-local scope.
//   A8  derived roster facts are pure functions of the decoded roster:
//       administrator count and the last-admin posture (exactly one admin).
//   A9  route intent: /objects/identity-providers is a viewer route and
//       /administrators an admin route (uiRoutes: GET /api/idp = viewer,
//       GET /api/auth/users = admin); a viewer's intent for /administrators
//       resolves to Overview.
//   A10 every read helper issues exactly one GET with no body against the
//       contracted path; the operation lookup encodes the id.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DecodeError } from "../api/decode";
import {
  IDP_OPERATION_STATES,
  IDP_TYPES,
  decodeIdPList,
  decodeIdPOperation,
  decodeIdPProfile,
  decodeLegacyLDAP,
  getIdPList,
  getIdPOperation,
  getIdPReferences,
  getLegacyLDAP,
} from "../api/idp";
import {
  decodeAdminRoster,
  decodeLockouts,
  getAdminRoster,
  getLockouts,
  rosterFacts,
} from "../api/admins";
import { KNOWN_ROUTES, resolveRouteIntent } from "../auth/routeIntent";

const omit = (o: Record<string, unknown>, k: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).filter(([key]) => key !== k));

const OIDC = {
  id: "oidc-corp",
  name: "Corp OIDC",
  type: "oidc",
  emailDomains: ["corp.example"],
  enabled: true,
  priority: 10,
  knownGroups: ["eng"],
  revision: 3,
  operationId: "0b6f9a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b",
  oidc: {
    issuer: "https://issuer.example",
    clientId: "client-a",
    clientSecretConfigured: true,
    scopes: ["openid"],
    groupsClaim: "groups",
    requiredScope: "",
    requiredAudience: "",
  },
};
const SAML = {
  id: "saml-hr",
  name: "HR SAML",
  type: "saml",
  emailDomains: null,
  enabled: false,
  priority: 0,
  revision: 1,
  saml: {
    metadataUrl: "https://idp.example/metadata",
    inlineMetadataConfigured: false,
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
    bindDn: "cn=svc,dc=example",
    bindCredentialConfigured: true,
    baseDn: "dc=example",
    userFilter: "(uid=%s)",
  },
};
const LIST = {
  persisted: true,
  degraded: false,
  revision: "r-abc123",
  profiles: [OIDC, SAML, LDAP],
  scope: "cluster-synced",
  cluster: { state: "published", publishedVersion: 42 },
  operations: {
    degraded: false,
    retained: 3,
    unresolved: 1,
    capacity: 256,
    auditSink: "file",
  },
};
const DEGRADED = {
  persisted: true,
  degraded: true,
  degradedReason: "corrupt_quarantined",
  degradedDetail:
    "the identity-provider registry file was corrupt and has been moved aside",
  quarantineEvidence: "idp_profiles.json.corrupt.1757600000000000000",
  revision: "r-empty",
  profiles: null,
  scope: "cluster-synced",
  cluster: {
    state: "pending",
    publishedVersion: 41,
    lastRejection: { reason: "publish_rejected", at: "2026-09-12T10:00:00Z" },
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

describe("A1 decodeIdPList", () => {
  it("decodes the populated cluster-synced list with every fact", () => {
    const l = decodeIdPList(LIST);
    expect(l.persisted).toBe(true);
    expect(l.degraded).toBe(false);
    expect(l.revision).toBe("r-abc123");
    expect(l.scope).toBe("cluster-synced");
    expect(l.profiles.map((p) => p.id)).toEqual([
      "oidc-corp",
      "saml-hr",
      "ldap-dc",
    ]);
    expect(l.cluster).toEqual({ state: "published", publishedVersion: 42 });
    expect(l.operations).toEqual({
      degraded: false,
      retained: 3,
      unresolved: 1,
      capacity: 256,
      auditSink: "file",
    });
  });

  it("decodes the degraded / quarantined posture with bounded reasons", () => {
    const l = decodeIdPList(DEGRADED);
    expect(l.degraded).toBe(true);
    expect(l.degradedReason).toBe("corrupt_quarantined");
    expect(l.quarantineEvidence).toBe(
      "idp_profiles.json.corrupt.1757600000000000000",
    );
    expect(l.profiles).toEqual([]);
    expect(l.cluster.state).toBe("pending");
    expect(l.cluster.lastRejection).toEqual({
      reason: "publish_rejected",
      at: "2026-09-12T10:00:00Z",
    });
    expect(l.operations.degraded).toBe(true);
    expect(l.operations.degradedReason).toBe("corrupt");
    expect(l.operations.auditSink).toBe("memory");
  });

  it("rejects an unknown scope, cluster state, degradedReason and auditSink", () => {
    expect(() => decodeIdPList({ ...LIST, scope: "node-local" })).toThrow(
      DecodeError,
    );
    expect(() =>
      decodeIdPList({
        ...LIST,
        cluster: { state: "synced", publishedVersion: 1 },
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeIdPList({ ...DEGRADED, degradedReason: "corrupt_maybe" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeIdPList({
        ...LIST,
        operations: { ...LIST.operations, auditSink: "cloud" },
      }),
    ).toThrow(DecodeError);
  });

  it("fails closed on a missing required fact", () => {
    expect(() => decodeIdPList(omit(LIST, "revision"))).toThrow(DecodeError);
    expect(() => decodeIdPList(omit(LIST, "persisted"))).toThrow(DecodeError);
  });
});

describe("A2 decodeIdPProfile", () => {
  it("decodes identity, type, enabled, entry revision, provenance and indicators", () => {
    const p = decodeIdPProfile(OIDC);
    expect(p.id).toBe("oidc-corp");
    expect(p.type).toBe("oidc");
    expect(p.enabled).toBe(true);
    expect(p.revision).toBe(3);
    expect(p.priority).toBe(10);
    expect(p.operationId).toBe("0b6f9a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b");
    expect(p.emailDomains).toEqual(["corp.example"]);
    expect(p.knownGroups).toEqual(["eng"]);
    expect(p.oidc?.clientSecretConfigured).toBe(true);
    expect(p.oidc?.issuer).toBe("https://issuer.example");
    expect(decodeIdPProfile(SAML).saml?.inlineMetadataConfigured).toBe(false);
    expect(decodeIdPProfile(SAML).emailDomains).toEqual([]);
    expect(decodeIdPProfile(SAML).operationId).toBeUndefined();
    expect(decodeIdPProfile(LDAP).ldap?.bindCredentialConfigured).toBe(true);
    expect(decodeIdPProfile(LDAP).ldap?.bindDn).toBe("cn=svc,dc=example");
    expect(IDP_TYPES).toEqual(["oidc", "saml", "ldap"]);
  });

  it("rejects an unknown type", () => {
    expect(() => decodeIdPProfile({ ...OIDC, type: "kerberos" })).toThrow(
      DecodeError,
    );
  });

  it("REFUSES a read model carrying secret material at any depth", () => {
    const cases: Array<Record<string, unknown>> = [
      { ...OIDC, oidc: { ...OIDC.oidc, clientSecret: "CANARY-secret" } },
      { ...OIDC, oidc: { ...OIDC.oidc, client_secret: "CANARY-secret" } },
      { ...LDAP, ldap: { ...LDAP.ldap, bindPassword: "CANARY-bind" } },
      { ...LDAP, ldap: { ...LDAP.ldap, bind_password: "CANARY-bind" } },
      { ...SAML, saml: { ...SAML.saml, metadataXml: "<EntityDescriptor/>" } },
      { ...OIDC, password: "x" },
      { ...OIDC, secret: "x" },
      { ...OIDC, ciphertext: "x" },
      { ...OIDC, sealed: { k: 1 } },
      {
        ...OIDC,
        oidc: { ...OIDC.oidc, nested: { deeper: { clientSecret: "x" } } },
      },
    ];
    for (const c of cases) {
      expect(() => decodeIdPProfile(c), JSON.stringify(c)).toThrow(DecodeError);
    }
    // ...and the list decoder refuses the whole document when one profile does.
    expect(() =>
      decodeIdPList({
        ...LIST,
        profiles: [
          OIDC,
          { ...LDAP, ldap: { ...LDAP.ldap, bindPassword: "x" } },
        ],
      }),
    ).toThrow(DecodeError);
  });
});

describe("A3 quarantine evidence is a base name", () => {
  it("refuses a path-bearing evidence value", () => {
    expect(() =>
      decodeIdPList({
        ...DEGRADED,
        quarantineEvidence: "/data/idp_profiles.json.corrupt.1",
      }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeIdPList({ ...DEGRADED, quarantineEvidence: "..\\idp.corrupt" }),
    ).toThrow(DecodeError);
  });
});

describe("A4 decodeIdPOperation", () => {
  const BASE = {
    operationId: "0b6f9a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b",
    state: "committed",
    action: "idp.create",
    actor: "admin@10.0.0.9",
    profileId: "ldap-dc",
    registryRevision: "r-prev",
    cutover: true,
    startedAt: "2026-09-12T09:59:00Z",
    audited: true,
    finishedAt: "2026-09-12T09:59:01Z",
    committedRevision: "r-abc123",
    result: { id: "ldap-dc" },
  };
  it("decodes committed / pending / aborted / outcome_unknown truthfully", () => {
    expect(IDP_OPERATION_STATES).toEqual([
      "pending",
      "committed",
      "aborted",
      "outcome_unknown",
    ]);
    const c = decodeIdPOperation(BASE);
    expect(c.state).toBe("committed");
    expect(c.audited).toBe(true);
    expect(c.auditState).toBeUndefined();
    expect(c.committedRevision).toBe("r-abc123");
    expect(c.cutover).toBe(true);
    const owed = decodeIdPOperation({
      ...BASE,
      audited: false,
      auditState: "pending",
    });
    expect(owed.auditState).toBe("pending");
    const intent = omit(
      omit(omit(BASE, "finishedAt"), "committedRevision"),
      "result",
    );
    const p = decodeIdPOperation({
      ...intent,
      state: "pending",
      audited: false,
    });
    expect(p.state).toBe("pending");
    expect(p.finishedAt).toBeUndefined();
    const terminal = omit(omit(BASE, "committedRevision"), "result");
    const a = decodeIdPOperation({
      ...terminal,
      state: "aborted",
      audited: false,
      code: "stale",
    });
    expect(a.code).toBe("stale");
    expect(a.finishedAt).toBe("2026-09-12T09:59:01Z");
    const u = decodeIdPOperation({
      ...terminal,
      state: "outcome_unknown",
      audited: false,
      code: "outcome_unknown",
    });
    expect(u.state).toBe("outcome_unknown");
  });
  it("rejects an unknown state or auditState", () => {
    expect(() => decodeIdPOperation({ ...BASE, state: "succeeded" })).toThrow(
      DecodeError,
    );
    expect(() => decodeIdPOperation({ ...BASE, auditState: "done" })).toThrow(
      DecodeError,
    );
  });
});

describe("A5 decodeLegacyLDAP", () => {
  it("decodes the absent block", () => {
    const l = decodeLegacyLDAP({
      present: false,
      retired: false,
      scope: "node-local",
      cutoverDurability: "not_retired",
    });
    expect(l.present).toBe(false);
    expect(l.retired).toBe(false);
    expect(l.scope).toBe("node-local");
    expect(l.cutoverDurability).toBe("not_retired");
    expect(l.cutover).toBeUndefined();
  });
  it("decodes the present block with the indicator only and the cutover record", () => {
    const l = decodeLegacyLDAP({
      present: true,
      active: false,
      scope: "node-local",
      retired: true,
      shadowed: true,
      url: "ldaps://legacy.example:636",
      baseDn: "dc=legacy",
      bindDn: "cn=svc,dc=legacy",
      bindCredentialConfigured: true,
      userFilter: "(uid=%s)",
      requiredGroup: "",
      startTls: false,
      tlsSkipVerify: false,
      cacheTtlSeconds: 300,
      cutoverDurability: "pending_reconciliation",
      cutover: {
        operationId: "0b6f9a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b",
        profileId: "ldap-dc",
        profileName: "DC LDAP",
        registryRevision: "r-abc123",
        actor: "admin@10.0.0.9",
        trigger: "admin_api",
        at: "2026-09-12T09:59:01Z",
        durable: false,
      },
    });
    expect(l.present).toBe(true);
    expect(l.active).toBe(false);
    expect(l.retired).toBe(true);
    expect(l.shadowed).toBe(true);
    expect(l.bindCredentialConfigured).toBe(true);
    expect(l.url).toBe("ldaps://legacy.example:636");
    expect(l.cutoverDurability).toBe("pending_reconciliation");
    expect(l.cutover?.trigger).toBe("admin_api");
    expect(l.cutover?.durable).toBe(false);
    expect(l.cutover?.profileName).toBe("DC LDAP");
  });
  it("refuses a bind password and unknown durability / trigger words", () => {
    const base = {
      present: true,
      retired: false,
      scope: "node-local",
      cutoverDurability: "not_retired",
    };
    expect(() => decodeLegacyLDAP({ ...base, bindPassword: "x" })).toThrow(
      DecodeError,
    );
    expect(() => decodeLegacyLDAP({ ...base, bind_password: "x" })).toThrow(
      DecodeError,
    );
    expect(() =>
      decodeLegacyLDAP({ ...base, cutoverDurability: "durable_maybe" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeLegacyLDAP({ ...base, scope: "cluster-synced" }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeLegacyLDAP({
        ...base,
        cutover: {
          operationId: "x",
          actor: "a",
          trigger: "cron",
          at: "t",
          durable: true,
        },
      }),
    ).toThrow(DecodeError);
  });
});

const ROSTER = {
  users: [
    {
      username: "admin",
      role: "admin",
      totpEnabled: false,
      securityGeneration: 4,
    },
    {
      username: "op-user",
      role: "operator",
      totpEnabled: false,
      securityGeneration: 1,
    },
    {
      username: "view-user",
      role: "viewer",
      totpEnabled: true,
      securityGeneration: 2,
    },
  ],
  revision: 7,
  scope: "node-local",
};

describe("A6 decodeAdminRoster", () => {
  it("decodes the roster read model", () => {
    const r = decodeAdminRoster(ROSTER);
    expect(r.revision).toBe(7);
    expect(r.scope).toBe("node-local");
    expect(r.users.map((u) => u.username)).toEqual([
      "admin",
      "op-user",
      "view-user",
    ]);
    expect(r.users[2]?.totpEnabled).toBe(true);
    expect(r.users[0]?.securityGeneration).toBe(4);
    expect(r.users[1]?.role).toBe("operator");
  });
  it("refuses credential / TOTP material and unknown roles", () => {
    const u = ROSTER.users[0];
    const withKey = (k: string): unknown => ({
      ...ROSTER,
      users: [{ ...u, [k]: "x" }],
    });
    for (const k of [
      "pass_hash",
      "passHash",
      "password",
      "totp_secret",
      "totpSecret",
      "backup_codes",
      "backupCodes",
      "totp_last_counter",
      "secret",
    ]) {
      expect(() => decodeAdminRoster(withKey(k)), k).toThrow(DecodeError);
    }
    expect(() =>
      decodeAdminRoster({ ...ROSTER, users: [{ ...u, role: "root" }] }),
    ).toThrow(DecodeError);
    expect(() =>
      decodeAdminRoster({ ...ROSTER, scope: "cluster-synced" }),
    ).toThrow(DecodeError);
    expect(() => decodeAdminRoster(omit(ROSTER, "revision"))).toThrow(
      DecodeError,
    );
  });
});

describe("A7 decodeLockouts", () => {
  it("decodes the null-tolerant lock set", () => {
    expect(
      decodeLockouts({ lockouts: null, generation: 3, scope: "node-local" }),
    ).toEqual({
      lockouts: [],
      generation: 3,
      scope: "node-local",
    });
    const l = decodeLockouts({
      lockouts: [
        { tier: "account", username: "op-user", seconds_remaining: 120 },
        {
          tier: "pair",
          username: "op-user",
          ip: "10.0.0.9",
          seconds_remaining: 30,
        },
      ],
      generation: 9,
      scope: "node-local",
    });
    expect(l.lockouts[0]).toEqual({
      tier: "account",
      username: "op-user",
      secondsRemaining: 120,
    });
    expect(l.lockouts[1]?.ip).toBe("10.0.0.9");
  });
  it("rejects an unknown tier", () => {
    expect(() =>
      decodeLockouts({
        lockouts: [{ tier: "global", username: "x", seconds_remaining: 1 }],
        generation: 1,
        scope: "node-local",
      }),
    ).toThrow(DecodeError);
  });
});

describe("A8 rosterFacts", () => {
  it("counts administrators and names the last admin only when exactly one remains", () => {
    const r = decodeAdminRoster(ROSTER);
    expect(rosterFacts(r)).toEqual({
      total: 3,
      adminCount: 1,
      lastAdmin: "admin",
      posture: "last_admin",
    });
    const two = decodeAdminRoster({
      ...ROSTER,
      users: [
        ...ROSTER.users,
        {
          username: "root2",
          role: "admin",
          totpEnabled: true,
          securityGeneration: 1,
        },
      ],
    });
    expect(rosterFacts(two)).toEqual({
      total: 4,
      adminCount: 2,
      lastAdmin: null,
      posture: "multiple",
    });
    expect(rosterFacts(decodeAdminRoster({ ...ROSTER, users: [] }))).toEqual({
      total: 0,
      adminCount: 0,
      lastAdmin: null,
      posture: "none",
    });
  });
});

describe("A9 route intent", () => {
  it("registers the two read routes at the approved minimum roles", () => {
    expect(KNOWN_ROUTES).toContainEqual({
      path: "/objects/identity-providers",
      minRole: "viewer",
    });
    expect(KNOWN_ROUTES).toContainEqual({
      path: "/administrators",
      minRole: "admin",
    });
    expect(resolveRouteIntent("/objects/identity-providers", "viewer")).toBe(
      "/objects/identity-providers",
    );
    expect(resolveRouteIntent("/administrators", "admin")).toBe(
      "/administrators",
    );
    expect(resolveRouteIntent("/administrators", "operator")).toBe("/");
    expect(resolveRouteIntent("/administrators", "viewer")).toBe("/");
  });
});

describe("A10 read helpers issue exactly one bodiless GET", () => {
  let calls: Array<{ url: string; method: string; body: unknown }>;
  beforeEach(() => {
    calls = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: unknown, init?: RequestInit) => {
        const url = String(input);
        calls.push({
          url,
          method: init?.method ?? "GET",
          body: init?.body ?? null,
        });
        let body: unknown = {};
        if (url.includes("/api/idp/legacy-ldap")) {
          body = {
            present: false,
            retired: false,
            scope: "node-local",
            cutoverDurability: "not_retired",
          };
        } else if (url.includes("/api/idp/operations/")) {
          body = {
            operationId: "0b6f9a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b",
            state: "pending",
            action: "idp.create",
            actor: "a",
            profileId: "p",
            registryRevision: "r",
            cutover: false,
            startedAt: "t",
            audited: false,
          };
        } else if (url.includes("/api/objects/references")) {
          body = {
            object: { type: "idp", name: "oidc-corp" },
            referencedBy: [],
          };
        } else if (url.includes("/api/idp")) {
          body = LIST;
        } else if (url.includes("/api/auth/users")) {
          body = ROSTER;
        } else if (url.includes("/api/auth/lockouts")) {
          body = { lockouts: null, generation: 1, scope: "node-local" };
        }
        return Promise.resolve(
          new Response(JSON.stringify(body), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }),
    );
  });

  it("targets the contracted paths", async () => {
    await getIdPList();
    await getLegacyLDAP();
    await getIdPOperation("0b6f9a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b");
    await getIdPReferences("oidc-corp");
    await getAdminRoster();
    await getLockouts();
    expect(calls.map((c) => c.method)).toEqual([
      "GET",
      "GET",
      "GET",
      "GET",
      "GET",
      "GET",
    ]);
    expect(calls.every((c) => c.body === null)).toBe(true);
    expect(calls[0]?.url.endsWith("/api/idp")).toBe(true);
    expect(calls[1]?.url.endsWith("/api/idp/legacy-ldap")).toBe(true);
    expect(
      calls[2]?.url.endsWith(
        "/api/idp/operations/0b6f9a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b",
      ),
    ).toBe(true);
    expect(calls[3]?.url).toContain("/api/objects/references?");
    expect(calls[3]?.url).toContain("type=idp");
    expect(calls[3]?.url).toContain("name=oidc-corp");
    expect(calls[4]?.url.endsWith("/api/auth/users")).toBe(true);
    expect(calls[5]?.url.endsWith("/api/auth/lockouts")).toBe(true);
  });

  it("encodes the operation id into the path (never a raw interpolation)", async () => {
    await getIdPOperation("a/b?c");
    expect(calls[0]?.url.endsWith("/api/idp/operations/a%2Fb%3Fc")).toBe(true);
  });
});
