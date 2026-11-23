# Local proxy users — design proposal

**Status:** proposal, not implemented. Follow-up to owner Decision 2
(2026-11-23): admin-console credentials no longer authenticate proxy traffic
(`proxy_credential.go`, CHANGELOG "Changed (breaking)").

**Problem.** After Decision 2 a node can authenticate proxy users only through
an external provider: an LDAP or OIDC IdP profile, or a legacy `ldap`/`oidc`
block. Small installations, labs and appliances without a directory previously
relied on the admin pair for proxy authentication and now have no local
option. They can only run credential-free (`Exempt`) or stand up a directory.

**Goal.** A dedicated local proxy-user store, separate from the admin roster
in storage, API, UI, audit and lifecycle. It plugs into the shared in-band
resolver as one more password-verifying provider, so HTTP Basic and SOCKS5
USER/PASS accept the same local proxy users, with the same identity, groups
and auth source.

## Non-goals

- Reusing or linking admin-console accounts. An admin who also needs proxy
  access gets a separate proxy-user record. No "also a proxy user" checkbox on
  an admin.
- Interactive login (captive portal form) in the first slice. RFC 1929 and
  Basic are both non-interactive; a portal form can follow, through the same
  verifier.
- Group sync from a directory. Local groups are operator-assigned labels.

## Storage

- Own file under the data directory: `proxy_users.json` (0600), written with
  the same atomic temp-file + fsync + rename + directory-fsync discipline as
  `ui_users.json` (CHAOS-70 durability: a refused write is reported, not
  silently lost). It is NOT inside `ui_users.json`, so the admin-roster
  setup anchor (`IsConfigured`, SEC-SETUPANCHOR-1), `AuthEnabled`
  (SEC-AUTHENABLED-1), the break-glass and the roster durability row stay
  about admin accounts only.
- Record: `{username, hash, groups[], enabled, created, updated, passwordChangedAt}`.
  Username: same length bound as the proxy path (`maxUsernameLen`) and a
  conservative charset; case-sensitive, matching the existing resolvers.
- Owner: a new `internal/proxyusers` package (domain state, validation,
  persistence codec and white-box tests), injected into main. Main keeps the
  HTTP adapter and the wiring, per AGENTS.md ownership rules. Record the
  boundary in `roadmap/PACKAGE-ISOLATION.md` and an ADR.
- Cluster: a Control Plane-owned surface replicated to Data Plane nodes like
  `idp_profiles` (hashes only, never plaintext). Registered in
  `config_surfaces.go` as Sensitive.

## Hashing and verification cost

- bcrypt at `bcrypt.DefaultCost` (matching admin hashes), password policy from
  `validatePasswordComplexity` (8..72 bytes).
- Verification MUST go through the CHAOS-57 governor (`internal/authcost`),
  with the exact ordering `verifyAuthFrom` documents: result cache first,
  username-independent admission, refusal is a deny, the slot held across
  both comparison branches, and the RISK-008 dummy comparison on an unknown
  username. Reuse the governor and cache, do not fork them. Since
  Decision 2 the governor, its `credential_verification` row,
  `culvert_auth_verify_*` series and `auth_verify_saturated` alert are idle;
  this feature makes them live again. `docs/operator/credential-verification-cost.md`
  then drops its "dormant" note.
- Cache keyed by the client fairness key (CHAOS-76) and invalidated by a
  store revision counter on every write (the `authRevision` pattern), so a
  disabled or re-keyed user stops authenticating on the next request.

## Resolver integration

- A `localProxyUserProvider` implementing `IdentityProvider`,
  `clientAttributedResolver` and a password-verifying marker, so it is returned
  by both `EnabledCredentialProviders` (HTTP Basic) and
  `EnabledPasswordProviders` (SOCKS5). Do not add a second engine or a new
  branch in `resolveRequestAuth`/`socks5Negotiate`. `resolvePresentedCredential`
  is the only entry.
- Identity: `Sub` = username, `Groups` = the record's groups,
  `Provider` = `proxy-local`. That is a new auth source, distinct from the
  reserved `local` label (historically "admin pair", now only the fallback
  label of the legacy LDAP provider). Reserve `proxy-local` in
  `reservedAuthSourceNames`.
- Order: after registry profiles and before the legacy provider, or as an
  explicit position in the registry. Decide in the ADR. A username that exists
  both locally and in a directory resolves to the first provider that accepts
  it; document that order, as for multiple profiles.
- Predicates: `hasCredentialCapableProvider` and `passwordProviderConfigured`
  gain "store has at least one enabled user". The probe must stay
  allocation-free (benchgate) because it runs per request.
- Fail-closed rules unchanged: an unreadable store loads as empty and the node
  reports it; it never accepts all credentials.

## Admin API and UI parity

- Routes, admin role, handler-level `requireRole(w, r, RoleAdmin)` plus
  `uiRoutes` metadata: `GET /api/proxy-users` (viewer may list usernames,
  groups and enabled only; never hashes), `POST /api/proxy-users`,
  `PUT /api/proxy-users/{name}` (groups/enabled), `POST
  /api/proxy-users/{name}/password`, `DELETE /api/proxy-users/{name}`.
- OpenAPI entries, regenerated `openapi.json` and frontend types, and an
  apicontract conformance slice.
- UI: a **Proxy Users** panel under Objects, beside Identity Providers, in the
  React frontend, with the legacy panel only if the migration contract still
  requires it. Copy states that admin accounts are not proxy users.
- Bulk import (CSV) is a later slice.

## Audit and configuration versioning

- Every mutation: `auditEvent` with the actor, action
  (`proxyuser.create|update|password|delete`) and username. Never the
  password or hash.
- Credential writes (create with password, password change) must NOT call
  `saveConfigVersion`: a rollback must never restore an old password hash. Same
  reasoning and the same kind of regression test as
  `auth_password_change_no_versioning_test.go`. Record the exclusion in
  `config_surfaces.go` (beside `admin_users`) and in
  `roadmap/CONFIG-VERSIONING-TRIAGE.md`.
- Non-credential edits (groups, enabled) are policy-relevant. Whether they
  version needs a decision. Recommendation: exclude the whole store from
  rollback, like `admin_users`, and keep audit as the record. A rollback that
  re-enables a disabled user is the same class of regression.

## Tests the feature must carry

- HTTP and SOCKS5 parity for the same local proxy user: identity, groups and
  auth source equal (extend `proxy_credential_parity_test.go`).
- Admin accounts still never authenticate proxy traffic with proxy users
  present (`TestProxyAuthNoAdmin_*` stay green, plus an admin/proxy-user
  username collision case).
- Disable and delete take effect on the next request (cache invalidation).
- Governor: the CHAOS-57 gates driven through the proxy path again.
- No-versioning regression for credential writes, audit-content assertions on
  unique entries (bounded audit ring).
- Store corruption: quarantine, fail closed, report.
