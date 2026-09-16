// FE-6A.1 correction round 2 — shared wire fixtures for the fe6a1d RED matrix
// (a plain module: importing a *.test.ts file from another test file would
// re-collect its suites).

export const CUTOVER = {
  operationId: "HBVfpgASPQEYE1ZaJo8H1g",
  profileId: "ldap-dc",
  profileName: "DC LDAP",
  registryRevision: "r-abc123",
  actor: "admin@10.0.0.9",
  trigger: "admin_api",
  at: "2026-09-12T09:59:01Z",
  durable: true,
};

/** exactly what apiIdPLegacyLDAP emits when the YAML block is present */
export const LEGACY_PRESENT: Record<string, unknown> = {
  present: true,
  active: true,
  scope: "node-local",
  retired: false,
  shadowed: false,
  url: "ldaps://legacy-dc.example:636",
  baseDn: "dc=legacy,dc=example",
  bindDn: "cn=svc,dc=legacy,dc=example",
  bindCredentialConfigured: true,
  userFilter: "(uid=%s)",
  requiredGroup: "cn=proxy-users,dc=legacy,dc=example",
  startTls: true,
  tlsSkipVerify: true,
  cacheTtlSeconds: 300,
  cutoverConfirmValue: "ldaps://legacy-dc.example:636",
  importSourceRevision: "isr1:" + "a".repeat(64),
  cutoverDurability: "not_retired",
};

/** exactly what it emits when the block is absent (cutover optional) */
export const LEGACY_ABSENT = {
  present: false,
  retired: true,
  scope: "node-local",
  cutoverDurability: "durable",
  cutover: CUTOVER,
};
