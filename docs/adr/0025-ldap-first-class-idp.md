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
4. **The legacy YAML provider stays boolean-only and is shadowed, not merged**:
   when an enabled registry LDAP profile exists, the legacy provider is not
   wired (one warning). Migration is an explicit, admin-driven import that
   creates a disabled profile for test-then-enable. The legacy `LDAPAuth`
   deliberately does NOT gain `ResolveIdentity` — that would silently flip
   existing deployments' Stage-2 identity (username→DN) and authSource
   ("local"→"ldap").
5. **Bind credential follows the OIDC ClientSecret containment pattern**
   (write-only input, preserve-on-omit, blank in every read/audit projection,
   `bindCredentialConfigured` metadata only, 0600 store). Generic IdP
   secret-at-rest encryption is recorded as a separate slice; an LDAP-only
   scheme is rejected.
6. **CredentialRequired providerRefs activate** for credential-capable
   providers (the reserved seam), with fail-closed challenge suppression when
   a rule's refs resolve to zero eligible providers. Runtime credential
   validation remains the global chain (recorded limitation; per-rule
   validator scoping is a future seam). SSORequired continues to reject
   non-interactive refs at the write door and at runtime.

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
