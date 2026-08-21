# ADR-0025: LDAP / Active Directory as a first-class Identity Provider

- **Status**: Accepted (2026-08-21)
- **Deciders**: maintainer + engineering session
- **Relates to**: ADR-0007 (secret containment), `roadmap/AUTHENTICATION-POLICY-SPEC.md`,
  `roadmap/AUTH-POLICY-DEFAULTAUTHOUTCOME-SPEC.md`,
  `roadmap/LDAP-IDP-MODERNIZATION-PLAN.md` (the Slice 0 freeze — data model,
  precedence matrix, threat model live there)

## Context

LDAP/AD authentication exists only as a legacy startup-scoped provider: a
boolean `AuthProvider` wired from `FileConfig.LDAP` at boot, restart-required,
YAML-only, identity-free (Stage-2 sees `Sub = <basic username>`,
`authSource = "local"`, no groups). Meanwhile the `IdPRegistry` is the
GUI/API-managed, cluster-synced, restart-free authority for OIDC and SAML.
Customer-facing configuration is GUI/API-first; YAML is bootstrap/compat only.

Two structural hazards block simply adding `"ldap"` to the registry:

1. **Capability conflation.** Several per-request predicates equate "enabled
   registry profile" with "interactive SSO provider" (`ssoCapable :=
   idpRegistry.HasEnabledProviders()`, captive-portal iteration over
   `EnabledProviders()`), and "OIDC profile" with "credential validator"
   (`HasEnabledOIDC`). True only while the registry holds OIDC/SAML.
2. **Dual authority.** A registry LDAP profile beside a legacy YAML LDAP
   provider invites field-merging or double authentication paths.

## Decision

1. **LDAP joins the IdP Registry as `IdPTypeLDAP`** with its own
   `LDAPProfileConfig`, managed exclusively through the existing `/api/idp`
   surface and Identity Providers GUI. The GUI never writes YAML; no second
   LDAP store is introduced.
2. **Capabilities become a declared function of `IdPType`** —
   `Interactive()` (OIDC, SAML) and `CredentialCapable()` (OIDC, LDAP) — and
   every SSO/credential predicate consumes them via capability-explicit
   registry accessors (`HasEnabledInteractiveProvider`,
   `HasEnabledCredentialProvider`, `EnabledInteractiveProviders`,
   `EnabledCredentialProviders`). LDAP is structurally excluded from every
   interactive surface (selector, captive URL, ssoCapable, SSORequired refs)
   and included in the Basic-credential chain.
3. **The registry LDAP provider is a new `IdentityProvider` adapter over the
   existing hardened `auth_ldap.go` engine** (two-step bind, CHAOS-47 gating,
   authoritative-only caching preserved verbatim). It produces a full
   `Identity`: Sub = user DN, Email/Name/Groups from configurable attributes
   (defaults `mail`/`displayName`/`memberOf`, full group DNs, direct
   membership only), `authSource = "ldap:<profile-id>"`.
4. **The legacy YAML provider stays boolean-only and is retired by a durable
   cutover, never merged** (hardening round P1-2): the first time an enabled
   registry LDAP profile is observed on a node carrying a legacy YAML `ldap:`
   block, the node records the node-local `legacy_ldap_retired` sentinel in
   `admin_settings.json` (the established AdminDurable sentinel pattern;
   OFF export/import, version-rollback, and CP→DP — a config restore must
   never resurrect a retired authenticator) and deactivates the legacy
   provider. After cutover the YAML block is bootstrap/import source
   material only — across registry disable/delete, restarts, and CP/DP
   restarts. Authority is deliberately NOT keyed on `HasEnabledLDAP()`
   alone (enable/disable is runtime state, not source-of-truth ownership).
   There is exactly ONE operational LDAP authenticator at all times: no
   guarded exceptions, no field merging, no hidden legacy fallback — a
   credential the registry rejects is denied, never retried against the
   YAML provider. The setup gate is decoupled from the proxy backend:
   `cfg.IsConfigured()` counts the retirement sentinel, so deactivating the
   legacy provider can never flip first-time setup open (unauthenticated
   RoleAdmin), even on a node with no local admin account. Break-glass
   revert is an explicit offline edit of `admin_settings.json` (documented
   in the operator guide); there is intentionally no API for it. Migration
   remains an explicit, admin-driven import creating a disabled profile for
   test-then-enable; the legacy `LDAPAuth` deliberately does NOT gain
   `ResolveIdentity` — that would silently flip existing deployments'
   Stage-2 identity (username→DN) and authSource ("local"→"ldap").
5. **Bind credential follows the OIDC ClientSecret containment pattern**
   (write-only input, preserve-on-omit, blank in every read/audit projection,
   `bindCredentialConfigured` metadata only, 0600 store). Generic IdP
   secret-at-rest encryption is recorded as a separate slice; an LDAP-only
   scheme is rejected.
6. **CredentialRequired providerRefs stays RESERVED** (hardening round P1-1
   reverted an earlier draft activation). Presented Proxy-Authorization
   credentials resolve through the GLOBAL validator chain before the
   no-credentials Stage-1 branch, so a per-rule provider subset was only
   half-enforced — another OIDC/LDAP provider or local/legacy credentials
   could satisfy the rule, and stale refs failed closed only on the
   no-credential path. Partial pinning is worse than none: validation
   rejects CR providerRefs again. LDAP is fully usable with ordinary
   CredentialRequired; provider-specific authorization is expressed in
   Stage 2 (`AuthSource = <LDAP profile>`, `SourceGroup = <group DN>`). A
   future fully-scoped design must cover presented credentials, sessions,
   local auth, legacy providers, stale/deleted refs, multi-provider
   ordering, and failure semantics as ONE coherent contract (recorded in
   `roadmap/LDAP-IDP-MODERNIZATION-PLAN.md` §12). SSORequired continues to
   reject non-interactive refs at the write door and at runtime.
7. **IdPRegistry mutations are transactional** (hardening round P1-3):
   Upsert/Delete/ReplaceAll build the candidate on copies, validate,
   compile the next live set, PERSIST atomically, and only then publish —
   a persistence failure leaves the old profiles, live providers, and
   credentials authoritative, with no success audit and no cluster
   snapshot publication (API reports 500). The deliberate in-memory mode
   (no profiles file) keeps its explicit warning + publish behavior.

## Consequences

- Administrators configure AD from the GUI without restart; identities carry
  groups usable in Access Rules immediately; cluster nodes receive LDAP
  profiles over the existing Sensitive `IdPProfiles` snapshot path with
  compile-gated atomic apply and last-known-good behavior.
- A pre-LDAP binary fails closed on an LDAP profile (compile error; DP keeps
  last-known-good; file preserved). Documented downgrade boundary; no YAML
  write-back.
- The capability seam is the load-bearing safety property; it is pinned by
  regression tests (LDAP can never leak into interactive SSO behavior) and
  parity tests (OIDC/SAML behavior byte-identical).

## Alternatives considered

1. *Teach the legacy LDAPAuth `ResolveIdentity` and keep YAML authority.*
   Rejected: silent Stage-2 semantic change; keeps LDAP restart-scoped and
   YAML-first, violating the product authority model.
2. *A separate `/api/ldap/config` + LDAP settings screen.* Rejected: a second
   configuration store beside the IdP Registry; contradicts the single
   provider-management experience.
3. *Automatic YAML→registry migration at boot.* Rejected: not provably
   deterministic-and-safe (attribute settings absent in YAML; authSource /
   identity semantics change); explicit test-then-enable import instead.
4. *Nested/recursive AD group resolution in v1.* Deferred: needs its own
   design (cycle bounds, latency, caching); direct membership preserved.
