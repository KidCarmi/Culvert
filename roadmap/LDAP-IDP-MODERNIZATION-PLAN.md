# LDAP / Active Directory IdP Modernization — Slice 0 Architecture Freeze

Status: **FROZEN** (Slice 0 complete — verified against `main` @ b697cf3, 2026-08-21).
Authority: this document + `docs/adr/0025-ldap-first-class-idp.md`. Where roadmap
status text and runtime code disagreed, the runtime code was treated as authoritative.

## 1. Verified current state (discovery report)

Every claim below was verified against live code, not roadmap prose.

| # | Expected fact | Verified? | Evidence |
|---|---------------|-----------|----------|
| 1 | LDAP loads through the legacy startup path from `FileConfig.LDAP` | **Yes** | `legacy_auth_providers_startup.go:17` (`loadLegacyAuthProviders`), resolver reads `fc.LDAP` |
| 2 | Legacy precedence: LDAP > legacy OIDC introspection > local bcrypt | **Yes** | `loadLegacyAuthProviders` — first non-empty `LDAP.URL` wins |
| 3 | `LDAPAuth` has strong fail-closed / backend-health behavior | **Yes** | CHAOS-47 `authProbeGate`, `errLDAPAccountRejected` blast-radius split (`auth_ldap.go:15-72,210-239`), authoritative-only caching |
| 4 | `LDAPAuth` is boolean-only (`AuthProvider`), not `IdentityProvider` | **Yes** | Implements only `Verify`/`Name`. `resolveAuthIdentityWithSnapshot` (store.go:522) falls back to `&Identity{Sub: user, Provider: "local"}` — legacy LDAP authSource is **"local"**, not "ldap". Preserving this is a compatibility constraint. |
| 5 | `IdPRegistry` is the runtime authority for identity providers | **Yes** | `auth_idp.go:108-119`; live compile map, atomic `ReplaceAll` |
| 6 | Registry supports OIDC and SAML only | **Yes** | `IdPTypeOIDC`/`IdPTypeSAML`; `compileIdPProfile` switch; validators reject other types |
| 7 | IdP profile persistence is atomic | **Yes** | `save()` → `atomicWriteFile` (temp+fsync+rename), 0600 |
| 8 | IdP writes publish the cluster snapshot | **Yes** | `apiIdPList`/`apiIdPItem` call `publishCurrentConfigSnapshot()` after `Upsert`/`Delete` |
| 9 | IdP profiles are Sensitive on CP→DP sync | **Yes** | `config_surfaces.go` row `idp_profiles` (`Sensitive: true`, `semValidatedSkip`, cap `maxSnapIdPProfiles`); redacted for unenrolled `GetConfig` callers |
| 10 | OIDC secrets have write-only / preserve-on-omit semantics | **Yes** | `publicIdPProfile` (blank `ClientSecret`), `preserveOIDCClientSecret` + `oidcClientSecretPresent` raw-body presence check (`ui_auth.go:588-666`) |
| 11 | Stage-1 auth policy and Stage-2 access policy are separate | **Yes** | `resolveAuthOutcome` (Stage-1, identity-free) vs `PolicyStore.Evaluate` (Stage-2, identity/groups/authSource) |
| 12 | Stage-1 never uses identity | **Yes** | `rejectIdentityPredicates` / `identityPredicateTypes` (authpolicy.go:844) |
| 13 | Stage 2 consumes Sub/Groups/authSource | **Yes** | `matchSourceAddr` → `SourceIdentity`/`SourceGroup`/`AuthSource`; `matchAuthSource` + `splitIdPSource` alias `oidc:`/`saml:` prefixes only |
| 14 | SSORequired targets interactive providers only | **Yes** | `eligibleSSOProviders` filters `Type ∈ {oidc,saml}`; `validateSSOProviderRefsLive` rejects non-interactive refs |
| 15 | LDAP is credential-capable, not interactive | **Yes** (by design) | SAML's `Verify` returns false / `CaptiveLoginURL` drives SSO; LDAP is the inverse |
| 16 | Predicates assume registry == OIDC/SAML | **Yes — the P0 hazard** | `ssoCapable := idpRegistry.HasEnabledProviders()` (proxy.go:181) counts **any** enabled profile as SSO-capable; `hasCredentialCapableProvider` (diagnostics.go:1176) uses `HasEnabledOIDC` as the credential predicate; `resolveCaptivePortalURL`/`authSelectProvider` iterate `EnabledProviders()`; `splitIdPSource`/`stripIdPPrefix` know only `oidc:`/`saml:`. |

Additional verified facts that shape the design:

- **CredentialRequired providerRefs are validation-rejected today**
  (`validateAuthOutcomeAndProviders`: "deferred and cannot be set yet") — the
  activation seam this program uses was reserved for exactly this purpose.
- Startup order: `initUIAccessPolicy` (loads the IdP registry) runs **before**
  `initLegacyAuthProviders` (main.go:198,200) — so the legacy loader can
  consult the registry for the shadowing rule with no ordering change.
- Reserved authSource namespace `{exempt, unauth, local, system}` is enforced
  at every registry ingress (`validateReservedIdPNaming`).
- `internal/secret` (ADR-0007) exists for KEK material; IdP secrets (OIDC
  `ClientSecret`) are stored plaintext in the 0600 `idp_profiles.json`.
- The auth cache key is an HMAC-SHA256 tag (`cacheKey`, store.go:310) — never
  plaintext credentials.
- The Basic-auth arm iterates `idpRegistry.EnabledProviders()` sequentially;
  SAML's `ResolveIdentity` returns `(nil,false)` so it is a cheap no-op there.

## 2. Provider capability model (frozen)

Capabilities are a **pure function of `IdPType`** — declared once, consumed by
every predicate. No scattered type switches.

```go
func (t IdPType) Interactive() bool       // browser SSO:      oidc ✓  saml ✓  ldap ✗
func (t IdPType) CredentialCapable() bool // Basic validation: oidc ✓  saml ✗  ldap ✓
// Full-Identity capable: all three (LDAP via the new registry provider).
```

Registry accessors become capability-explicit:

| Old predicate | Meaning it actually carried | New authority |
|---|---|---|
| `HasEnabledProviders()` (proxy ssoCapable) | "an interactive IdP exists" | `HasEnabledInteractiveProvider()` |
| `HasEnabledOIDC()` (credCapable) | "a registry credential validator exists" | `HasEnabledCredentialProvider()` |
| `EnabledProviders()` in Basic-auth arm | "credential validators to try" | `EnabledCredentialProviders()` |
| `EnabledProviders()` in captive portal / `/auth/select` | "interactive providers to offer" | `EnabledInteractiveProviders()` |
| `eligibleSSOProviders` type filter | interactive filter | `p.Type.Interactive()` |

`HasEnabledProviders`/`EnabledProviders`/`HasEnabledOIDC` remain (other callers,
tests) but no security decision may treat "enabled profile" as "SSO-capable"
once LDAP exists. All five swaps keep today's behavior byte-identical for
OIDC/SAML-only registries (proven by parity tests).

Guarantees (regression-tested):
- An LDAP profile never appears on `/auth/select`, never yields a captive-login
  URL (`CaptiveLoginURL` returns `""`), never counts toward `ssoCapable`, never
  satisfies an SSORequired providerRef (write door AND runtime).
- An enabled LDAP profile makes `credCapable` true and participates in the
  Basic-auth chain ahead of the legacy fallback.

## 3. Data model

`IdPTypeLDAP IdPType = "ldap"`, `IdPProfile.LDAP *LDAPProfileConfig`.

```go
type LDAPProfileConfig struct {
    URL            string `json:"url"`                 // ldap:// or ldaps:// (canonical transport)
    StartTLS       bool   `json:"startTls,omitempty"`
    TLSSkipVerify  bool   `json:"tlsSkipVerify,omitempty"` // Advanced/unsafe, warned
    BindDN         string `json:"bindDn,omitempty"`        // empty = anonymous bind
    BindPassword   string `json:"bindPassword,omitempty"`  // WRITE-ONLY (redacted like OIDC ClientSecret)
    BaseDN         string `json:"baseDn"`
    UserFilter     string `json:"userFilter,omitempty"`     // default (sAMAccountName=%s); exactly one %s
    EmailAttribute string `json:"emailAttribute,omitempty"` // default mail
    NameAttribute  string `json:"nameAttribute,omitempty"`  // default displayName
    GroupAttribute string `json:"groupAttribute,omitempty"` // default memberOf
    RequiredGroup  string `json:"requiredGroup,omitempty"`  // legacy provider-level gate (Advanced)
    CacheTTLSeconds int   `json:"cacheTtlSeconds,omitempty"` // default 300, bounded
}
```

The GUI presents Server + Connection security (LDAPS/StartTLS/Plain) + Port and
derives the canonical URL/StartTLS pair; the API keeps the canonical fields.

Identity mapping (canonical): `Sub` = full user DN; `Email` = EmailAttribute;
`Name` = NameAttribute with CN → username fallback; `Groups` = GroupAttribute
values verbatim (full group DNs — the collision-safe authorization value);
`Provider` = profile ID; machine authSource `ldap:<profile-id>` (added to
`splitIdPSource`/`stripIdPPrefix` beside `oidc:`/`saml:`). Direct membership
only; **no** recursive/nested AD group resolution in v1 (future capability,
explicitly out of scope).

## 4. Runtime composition

`LDAPIdPProvider` (new) implements `IdentityProvider` for registry profiles. It
wraps the **same battle-tested two-step-bind engine** as `LDAPAuth` (shared
`ldapDirectory` core extracted from `auth_ldap.go` — dial/StartTLS/service
bind/search/user bind/CHAOS-47 gating are not rewritten). Differences:

- search requests the configured identity attributes, not just `dn, memberOf`;
- the authoritative-result cache stores the resolved `*Identity` (key stays the
  HMAC `cacheKey`; never plaintext);
- `Name() = "ldap:"+profileID`, `DisplayName() = profile.Name`,
  `CaptiveLoginURL(...) = ""` (never interactive), `Verify` delegates to
  `ResolveIdentity`.

The **legacy** `LDAPAuth` stays boolean-only on purpose: making it an
`IdentityProvider` would silently change existing deployments' Stage-2
semantics (identity user → DN, authSource "local" → "ldap"). Migration to the
registry is the supported path to full identity.

## 5. Authority / precedence matrix (legacy YAML vs registry)

One deterministic authority; never field-by-field merging.

| # | State | Behavior |
|---|-------|----------|
| 1 | No LDAP anywhere | Unchanged. |
| 2 | Legacy YAML only | Legacy provider wired exactly as today (boolean, authSource "local"). Startup logs a bounded migration hint; `/api/idp/legacy-ldap` exposes non-secret summary + one-click import. |
| 3 | Registry LDAP only | Registry is the sole authority (full Identity, authSource `ldap:<id>`). |
| 4/5 | Both present (identical or different) | **Registry wins.** The legacy YAML LDAP provider is not wired (startup) / is deactivated (runtime create): one clear warning, no repeated spam, zero merging. Deactivation falls back to local bcrypt exactly as if `ldap.url` were unset. |
| 6 | Malformed legacy YAML LDAP | Unchanged: startup fails with "LDAP config error:" (existing contract). |
| 7 | Missing registry file | Unchanged: first-run no-op. |
| 8 | Unwritable registry persistence | Unchanged: `save()` error propagates to the API caller; in-memory warning when no path configured. |
| 9 | Standalone node | Full feature; no cluster interaction. |
| 10 | Control Plane | LDAP profiles ride the existing `IdPProfiles` snapshot surface (Sensitive, validated, compile-gated `ReplaceAll`). |
| 11 | Enrolled Data Plane | Same as any IdP profile: rejected candidate aborts extended state, last-known-good preserved, secrets redacted for unenrolled callers. |
| 12 | Downgrade to a pre-LDAP binary | See §6. |

Migration is **explicit import** (admin-driven), not automatic: the legacy
config lacks identity-attribute settings, and an automatic flip would change
authSource/identity semantics for running traffic. Import copies every
security-effective field (URL, StartTLS, TLSSkipVerify, BindDN, BindPassword,
BaseDN, UserFilter, RequiredGroup, CacheTTL) into a **disabled** profile the
admin then tests and enables. The YAML file is never read back, modified, or
deleted; repository precedent (BlocklistFeedsSaved/UpstreamProxiesSaved
"sentinel: saved list is authoritative") supports registry-wins-once-present.

## 6. Downgrade boundary

A pre-LDAP binary's `IdPRegistry.Load` runs `validateReservedIdPNaming` only at
load (type is not validated on load), but `compile` fails for unknown type
`"ldap"` → logged compile error, profile inert but preserved on disk (Load does
not rewrite the file); a DP running the old binary rejects a snapshot carrying
an LDAP profile at `ReplaceAll` (compile error) and **keeps its last-known-good
config** — fail-closed, not fail-broken. Legacy YAML deployments are untouched
by downgrade. This boundary is documented in the operator doc; no YAML
write-back is used to "solve" downgrade.

## 7. Secret lifecycle (bind credential)

- Write-only API input; `publicIdPProfile` blanks it (GET/LIST/audit
  diff use the public projection).
- Omitted on update ⇒ preserve stored value (raw-body presence check, the OIDC
  pattern); explicit empty string ⇒ clear (distinguishable); no sentinel values.
- Read surface exposes only `bindCredentialConfigured: true|false`.
- Never logged (existing `auth_ldap.go` discipline), never in metrics/errors.
- At rest: same 0600 `idp_profiles.json` posture as OIDC `ClientSecret`. A
  generic IdP-credential at-rest envelope (OIDC + LDAP together, on
  `internal/secret` primitives) is recorded as a **separate** security slice —
  an LDAP-only encryption scheme is explicitly rejected (asymmetric secret
  models across IdP types).
- Test-user passwords (POST /api/idp/test) are transient: never persisted,
  logged, audited, or cached.

## 8. Threat model (delta)

| Threat | Control |
|---|---|
| LDAP injection via username | `ldap.EscapeFilter` (preserved); user filter validated to exactly one `%s`, no `\n`, bounded length |
| SSRF via admin-configured LDAP URL | Dedicated validator: `ldap://`/`ldaps://` schemes only, host/port syntax bounds. RFC1918 targets are **allowed by design** (enterprise directories are internal) — an Admin-only, rate-limited, bounded-timeout test endpoint is the only actuated probe, and it is audited. |
| Downgrade-to-plaintext | Transport is explicit; plain LDAP and TLSSkipVerify carry GUI warnings + existing log warnings; no automatic downgrade on test failure |
| Account-driven outage amplification (CHAOS-47) | `errLDAPAccountRejected` split preserved verbatim in the shared engine |
| Credential disclosure | §7; `bindCredentialConfigured` metadata only; server diagnostic text passes `sanitizeLog` |
| Cross-provider authSource confusion | `ldap:` prefix joins the scheme-aware `matchAuthSource` rules; reserved-namespace guard unchanged |
| SSO surface leak | Capability model (§2) + regression tests |
| Multi-directory lockout amplification | Sequential provider iteration preserved; boolean `resolved` contract cannot distinguish "not my user" from "authoritative reject" — **documented limitation**; the minimal seam (per-provider authoritative-reject signal) is recorded for a future slice, not built now |

## 9. Test matrix

See mission §27 — implemented across slice test files:
`auth_ldap_provider_test.go` (identity/groups/capability), `auth_idp_ldap_test.go`
(registry/validation/redaction/clone), `ui_auth_ldap_api_test.go` (API/RBAC/
secret semantics/test endpoint), `authpolicy_ldap_test.go` (CR/SSO refs),
`controlplane` snapshot tests (LDAP profile sync/reject), interop
(`auth_ldap_openldap_integration_test.go`, env-gated).

## 10. Slices and gates

Slices 1–6 per the mission brief; each lands as its own commit(s) with fmt /
vet / build / targeted `-race` tests green before moving on. Gate for Slice 0:
- Source-of-truth ambiguity: **resolved** (§5 registry-wins, explicit import).
- SSO-vs-credential capability ambiguity: **resolved** (§2 type-derived model).
- Secret lifecycle ambiguity: **resolved** (§7 OIDC-pattern parity; at-rest
  hardening recorded separately).

## 11. Expected files touched

`auth_idp.go`, `auth_ldap.go` (engine seam only), `auth_ldap_provider.go` (new),
`identity.go` (none — interface unchanged), `proxy.go` (capability probe swap),
`proxy_portal.go`, `ui_auth.go` (+ `ui_auth_ldap.go` new: test/import handlers),
`ui_routes_meta.go`, `diagnostics.go` / `diagnostics_auth_sso.go`,
`authpolicy.go` (CR providerRefs activation), `policy.go` (`ldap:` prefix),
`legacy_auth_providers_startup.go` (shadowing), `config.example.yaml`,
`api/openapi/openapi.yaml`, `api/route-classification.yaml`,
`static/index.html`, `.github/workflows/auth-idp-interop.yml` + `.github/idp/openldap/`,
`docs/adr/0025-ldap-first-class-idp.md`, `docs/operator/ldap-identity-provider.md`,
plus test files.
