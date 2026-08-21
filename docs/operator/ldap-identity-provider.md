# LDAP / Active Directory Identity Provider

LDAP/AD is a first-class identity provider (ADR-0025): managed from
**Objects → Identity Providers**, no restarts, cluster-synced, producing full
identities for Access Rules. This guide covers setup, migration from the
legacy YAML block, policy integration, failure behavior, and the downgrade
boundary.

## Quick start

1. **Objects → Identity Providers → + Add Provider → Microsoft Active
   Directory** (or LDAP/OpenLDAP, FreeIPA — presets only change defaults).
2. Enter the essentials:
   - **Server** — a domain controller / directory host (e.g. `dc01.corp.example`).
   - **Connection security** — LDAPS (recommended, port 636), StartTLS
     (port 389), or Plain LDAP (unsafe; development only, visibly warned).
   - **Base DN** — e.g. `DC=corp,DC=example`.
   - **Service account** — a low-privilege bind DN + credential used to locate
     users. The credential is write-only: it never returns to the browser and
     is preserved when you edit other fields.
3. **Test connection** — staged feedback: reachability, TLS, service bind,
   Base DN search; optionally supply a test username/password for a full
   identity test (the test password is transient — never stored or logged).
4. Enable and save. Enabling runs the same connection preflight server-side
   (`?preflight=connection`): a failing candidate can never replace a working
   configuration — on failure the API returns 422 with the staged report and
   the current provider stays active.

Proxy users then authenticate with their directory username/password via
proxy Basic authentication. No restart is required at any point.

## What a directory provider is (and is not)

- **Credential provider**: validates presented proxy Basic credentials and is
  eligible for `CredentialRequired` authentication rules (including scoped
  `providerRefs`).
- **Never interactive SSO**: an LDAP profile never appears on the browser
  sign-in selector, never mints captive-portal URLs, and can never satisfy an
  `SSORequired` rule — the API rejects such refs and the runtime fails closed.
- **Identity source**: a successful authentication produces
  - `Identity.Sub` — the full user DN (stable, unambiguous),
  - `Email` / `Name` — from configurable attributes (defaults `mail`,
    `displayName`),
  - `Groups` — the group attribute values verbatim (default `memberOf`, full
    group DNs, **direct membership only** — nested/recursive AD group
    resolution is not performed),
  - authSource `ldap:<profile-id>` (the bare profile ID also matches in
    rules).

### Authorization model

Use **Access Rules** over the resolved identity:

- *Source Group* = the full group DN (e.g.
  `CN=Engineering,OU=Groups,DC=corp,DC=example`),
- *Auth Source* = the LDAP profile.

The provider-level **Required group** (Advanced) is a legacy gate kept for
compatibility: it denies authentication itself unless the user is a direct
member. Prefer Access Rules.

## Migrating from the legacy YAML block

`config.yaml`'s `ldap:` block is bootstrap/compatibility only. The Identity
Providers screen shows a banner when it is present:

1. Click **Import legacy LDAP configuration** (or
   `POST /api/idp/legacy-ldap/import`). Every security-effective field —
   including the bind credential — is copied into a **disabled** profile.
   (The one normalization: `start_tls: true` on an `ldaps://` URL, which the
   legacy schema silently ignored, is dropped — the profile schema rejects
   the contradiction.)
2. Test the imported profile, then enable it.
3. The moment an enabled registry LDAP profile exists, the legacy YAML
   provider is deactivated (one warning; the YAML file is **never**
   modified). Remove the `ldap:` block at your convenience.

Authority rules:

- Registry LDAP profile enabled ⇒ the registry is the sole operational LDAP
  authority; the YAML block is ignored (at startup and at runtime). There is
  never field-by-field merging.
- Deleting/disabling the registry profile does **not** silently re-arm the
  YAML provider; a restart restores the YAML bootstrap behavior.
- Edge case: on an appliance with **no local admin account** and the
  fail-closed default authentication, the legacy provider stays wired as the
  setup-gate anchor (deactivating it would reopen first-time setup). The
  registry still takes precedence in the credential chain; create a local
  admin account and restart to retire the YAML provider.

## Failure behavior

The hardened legacy semantics are preserved (CHAOS-47):

- Directory unreachable ⇒ authentication fails **closed**; the backend arms a
  3s probe cooldown so an outage costs one probe per window, not a dial
  timeout per request; recovery is detected on the first answered probe.
- A locked/disabled/expired **account** rejection is authoritative (the
  directory answered) — it never arms the provider-wide cooldown, so one
  abused account cannot deny service to everyone else.
- Authoritative results (yes or wrong-password/not-found/required-group
  no) are cached for the profile's cache TTL (default 300 s); reachability
  failures are never cached. Cache keys are HMAC tags — plaintext
  credentials are never stored.

Observability: `culvert_auth_backend_unavailable{,_total}` and gated-denial
counters carry backend `ldap:<profile-id>`; the `identity_backend` operator
contract row reports outages/recovery; diagnostics add
`ldap_plaintext_transport`, `ldap_tls_unverified`,
`ldap_legacy_config_shadowed`, `auth_cr_no_eligible_provider`, and
`auth_cr_providerref_unavailable`.

## Cluster

LDAP profiles ride the existing Sensitive `IdPProfiles` CP→DP snapshot
surface: enrolled Data Planes receive the full profile (including the bind
credential — required for DP-local authentication) over mTLS; unenrolled
callers get a redacted snapshot with no IdP profiles at all. A malformed
profile rejects the whole IdP candidate on the DP — the previous provider set
and last-known-good config stay active.

## Downgrade boundary

A binary that predates `type: "ldap"`:

- keeps the profile on disk (the registry file is never rewritten on load)
  but logs a compile error and leaves the profile inert;
- as a DP, **rejects** any snapshot carrying an LDAP profile at the
  compile-gated apply and keeps its last-known-good configuration.

LDAP authentication therefore stops on downgrade (fail-closed, not
fail-broken). Deployments that must keep a downgrade path can retain the
legacy YAML block until the fleet is fully upgraded — the YAML file is never
modified by the GUI, so it remains valid bootstrap input for old binaries.

## Secrets

- The bind credential is write-only at the API: omitted on update = keep,
  present-and-empty = clear. Reads expose only `bindCredentialConfigured`.
- It is stored in the 0600 `idp_profiles.json` alongside OIDC client secrets
  (the same at-rest posture; a generic IdP-credential at-rest envelope is
  tracked as separate hardening).
- Test-user passwords are transient: never persisted, logged, audited, or
  cached.

## Interop CI

`.github/workflows/auth-idp-interop.yml` runs the `TestOpenLDAPInterop_*`
suite against a pinned OpenLDAP container seeded from
`.github/idp/openldap/bootstrap.ldif` (service bind, user search, valid and
invalid credentials, group membership, identity mapping, RequiredGroup,
staged test pipeline, LDAPS and StartTLS).
