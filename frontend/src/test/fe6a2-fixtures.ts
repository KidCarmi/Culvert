// FE-6A.2 RED matrix — shared wire fixtures (plain module; never a *.test file).
import type { IdPWriteSpec } from "../api/idp";

export const RAW = "dial tcp /data/private: permission denied";
export const OP_ID = "6a2e0000-0000-4000-8000-00000000c0de";
export const OP_ID_2 = "6a2e0000-0000-4000-8000-00000000c0df";
export const CLIENT_SECRET = "OIDC-CLIENT-SECRET-CANARY-never-stored";
export const BIND_PASSWORD = "LDAP-BIND-CANARY-never-stored";
export const TEST_PASSWORD = "TEST-CRED-CANARY-never-stored";
export const METADATA_XML =
  '<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/SAML-XML-CANARY"></EntityDescriptor>';
export const LEGACY_URL = "ldap://legacy.corp.example:389";
export const QUARANTINE = "idp_profiles.json.corrupt.1757600000000000000";

export const OIDC_SPEC: Extract<IdPWriteSpec, { type: "oidc" }> = {
  type: "oidc",
  name: "Corp OIDC",
  enabled: true,
  priority: 10,
  emailDomains: ["corp.example"],
  knownGroups: [],
  oidc: {
    issuer: "https://issuer.example",
    clientId: "culvert",
    clientSecret: CLIENT_SECRET,
    scopes: ["openid", "email"],
    groupsClaim: "groups",
    requiredScope: "",
    requiredAudience: "",
    tlsSkipVerify: false,
  },
};

export const LDAP_SPEC: Extract<IdPWriteSpec, { type: "ldap" }> = {
  type: "ldap",
  name: "DC LDAP",
  enabled: false,
  priority: 0,
  emailDomains: [],
  knownGroups: [],
  ldap: {
    url: "ldaps://dc.example:636",
    startTls: false,
    tlsSkipVerify: false,
    bindDn: "cn=svc,dc=example",
    bindPassword: BIND_PASSWORD,
    baseDn: "dc=example",
    userFilter: "(uid=%s)",
    emailAttribute: "mail",
    nameAttribute: "cn",
    groupAttribute: "memberOf",
    requiredGroup: "",
    cacheTtlSeconds: 300,
  },
};

export const SAML_SPEC: Extract<IdPWriteSpec, { type: "saml" }> = {
  type: "saml",
  name: "Corp SAML",
  enabled: false,
  priority: 0,
  emailDomains: ["saml.example"],
  knownGroups: [],
  saml: {
    metadataUrl: "",
    metadataXml: METADATA_XML,
    nameIdFormat: "",
    groupsAttribute: "groups",
    emailAttribute: "email",
    nameAttribute: "name",
  },
};

/** the profile read model the appliance answers for a committed OIDC create */
export function oidcProfileAnswer(
  id = "a1b2c3d4e5f6",
  revision = 1,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id,
    name: "Corp OIDC",
    type: "oidc",
    emailDomains: ["corp.example"],
    enabled: true,
    priority: 10,
    revision,
    oidc: {
      issuer: "https://issuer.example",
      clientId: "culvert",
      clientSecretConfigured: true,
    },
    cluster: { publication: "published", version: 7 },
    ...extra,
  };
}

export function ldapProfileAnswer(
  id = "ldap00000001",
  revision = 1,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id,
    name: "DC LDAP",
    type: "ldap",
    emailDomains: null,
    enabled: false,
    priority: 0,
    revision,
    ldap: {
      url: "ldaps://dc.example:636",
      bindDn: "cn=svc,dc=example",
      baseDn: "dc=example",
      bindCredentialConfigured: true,
    },
    cluster: { publication: "published", version: 8 },
    ...extra,
  };
}

export const LIST = {
  persisted: true,
  degraded: false,
  revision: "r-doc-1",
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

export const LEGACY_PRESENT = {
  present: true,
  active: true,
  scope: "node-local",
  retired: false,
  shadowed: false,
  url: LEGACY_URL,
  baseDn: "DC=legacy",
  bindDn: "cn=svc,dc=legacy",
  bindCredentialConfigured: true,
  userFilter: "(sAMAccountName=%s)",
  requiredGroup: "",
  startTls: false,
  tlsSkipVerify: false,
  cacheTtlSeconds: 300,
  cutoverConfirmValue: LEGACY_URL,
  cutoverDurability: "not_retired",
};

export const LEGACY_ABSENT = {
  present: false,
  retired: false,
  scope: "node-local",
  cutoverDurability: "not_retired",
};

export const ROSTER = {
  users: [
    {
      username: "admin",
      role: "admin",
      totpEnabled: false,
      securityGeneration: 3,
    },
    {
      username: "bob",
      role: "operator",
      totpEnabled: true,
      securityGeneration: 5,
    },
  ],
  revision: 4,
  scope: "node-local",
};

export const LOCKS = {
  lockouts: [{ tier: "account", username: "bob", seconds_remaining: 120 }],
  generation: 12,
  scope: "node-local",
};

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
