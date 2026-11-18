# OIDC profiles as proxy credentials: `requiredScope` and `requiredAudience`

**Audience:** administrators who let non-browser clients (CLI tools, agents,
scripts) authenticate to the proxy with an OIDC token, and anyone setting the
`requiredScope` or `requiredAudience` field on an OIDC identity provider profile.

**Applies to:** OIDC profiles in the IdP registry (`idp_profiles.json`,
`OIDCProfileConfig` in `auth_idp.go`, runtime in `auth_oidc_flow.go`). The
legacy single-provider YAML block (`oidc:` → `OIDCConfig` in `auth_oidc.go`) is
covered only where stated.

Browser sign-in (Auth-Code + PKCE at `/auth/oidc/callback`) is a separate path;
see [What the filters do not cover](#what-the-filters-do-not-cover).

## How a token is checked on the proxy-credential path

A client presents a token as the password in `Proxy-Authorization: Basic`
(the username is ignored for identity). For a registry OIDC profile,
`OIDCFlowProvider.ResolveIdentityFrom` has two ways to admit it:

| Step | When it runs | What it checks |
|---|---|---|
| 1. Local JWT validation | **Only when both `requiredScope` and `requiredAudience` are empty** | RSA signature against the discovered `jwks_uri`, `iss` = the discovered issuer, `aud` contains the profile `clientId`, `exp` present and not past (60 s leeway), non-empty `sub` |
| 2. RFC 7662 introspection | When step 1 is skipped or fails, **and** discovery returned an `introspection_endpoint` | `active:true`; `exp` (if present) in the future; then `requiredScope` and `requiredAudience`; non-empty `sub` (falls back to `username`) |

If neither step admits the token, the request is denied (fail-closed). There is
no third path.

## The enforcement filters

| Field (API JSON) | Default | Matched against | Rule |
|---|---|---|---|
| `oidc.requiredScope` | empty = no check | the introspection response's `scope` string | The configured value must appear as one space-delimited token. Set **one** scope (for example `proxy:access`); a value containing spaces is matched as that exact adjacent sequence, not as "all of these scopes". |
| `oidc.requiredAudience` | empty = no check | the introspection response's `aud` (string or array) | The configured value must be one of the audiences. |

Both filters are evaluated **only on the introspection response**
(`identityFromIntrospectionClaims`). That is why setting either one disables
step 1: a locally valid JWT cannot answer them, and before the fix recorded in
the CHANGELOG (*"An OIDC profile's `requiredScope` / `requiredAudience` are now
enforced for every token presented as a proxy credential"*) any token the IdP
had signed for the profile's client id — including an ID token, which carries
no scope — was admitted regardless of the filters
(`TestOIDCFlowCredential_RequiredFiltersApplyToLocallyValidJWT`).

### Consequences you must plan for

- **A filter requires a reachable introspection endpoint.** With either filter
  set and no `introspection_endpoint` in the IdP's discovery document, the
  profile admits **no** proxy-credential token. Browser sign-in is unaffected.
  Check the read-only `oidc.introspectionEndpoint` field returned by
  `GET /api/idp` before you set a filter.
- **Every request costs an introspection round trip** unless a verdict is
  cached. Verdicts from an endpoint that answered (including "scope missing")
  are cached for 2 minutes, clamped to the token's `exp`. Non-200 answers
  and transport failures are never cached; they deny the request. A 4xx
  token-side rejection logs `auth DENY (introspection 4xx)` and leaves the
  backend healthy; a transport failure, timeout, 5xx, 401, 408 or 429 arms the
  backend cooldown described in
  [identity backend availability](identity-backend-availability.md). A refusal
  by `requiredScope`/`requiredAudience` writes no log line.
- **The introspection request authenticates with `clientId`/`clientSecret`**
  (HTTP Basic). An IdP that refuses introspection for that client returns a
  401, which Culvert treats as a provider-wide outage, not a token verdict.
- **Clients that previously worked with a locally valid JWT** (typically an ID
  token) are now refused on a profile with a filter if their token does not
  carry the required scope/audience at introspection. Issue those clients an
  access token that does, or remove the filter.

### Recommended configuration

- Use a filter when the IdP issues tokens for other purposes under the same
  client id and only some of them should open the proxy. Create a dedicated
  scope (for example `proxy:access`) and grant it only to proxy clients.
- Leave both filters empty when every token the IdP signs for this client id
  may use the proxy; step 1 then avoids an IdP round trip per new token.
- Do not rely on the filters for authorization decisions between users; use
  Access Rules on identity groups (`groupsClaim`, default `groups`).

## Where to set them

| Surface | Status |
|---|---|
| Admin UI (**Objects → Identity Providers**) | **Not editable.** The OIDC form carries both values in hidden inputs so an edit preserves what is stored, but offers no control to set or clear them. |
| Admin API | `PUT /api/idp/{id}` (Admin role) with the profile body; `POST /api/idp` on create. Send the full profile as returned by `GET /api/idp` with the `oidc.requiredScope` / `oidc.requiredAudience` fields changed — an omitted field is stored empty. `clientSecret` may be omitted; the stored secret is preserved. |
| Legacy YAML (`oidc.required_scope`, `oidc.required_audience`) | The legacy backend is introspection-only, so it has always applied both filters to every token. |

Changes take effect without a restart: the registry recompiles the profile and
cluster nodes receive it through the configuration snapshot.

## What the filters do not cover

- **Browser SSO.** The Auth-Code + PKCE callback validates the ID token
  (issuer, audience = `clientId`, nonce, expiry) and never consults
  `requiredScope` or `requiredAudience`. A user who completes browser sign-in
  is admitted whatever the filters say. Restrict browser users with IdP-side
  application assignment and Access Rules.
- **Group extraction.** Filters admit or refuse; they do not change which
  groups the identity carries.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| All token clients refused on one profile after setting a filter; browser login still works | No `introspection_endpoint` was discovered | Confirm `oidc.introspectionEndpoint` in `GET /api/idp`; enable introspection at the IdP for this client, or clear the filter |
| Refused only for some clients | Their token's introspected `scope`/`aud` lacks the configured value | Introspect the token at the IdP with the profile's client credentials and compare; a value with spaces in `requiredScope` is the most common mistake |
| Clients refused and the backend shows `unreachable`/`degraded` | Introspection endpoint unreachable, or 401 for the client credentials | See [identity backend availability](identity-backend-availability.md) |
| A token fixed at the IdP is still refused for up to 2 minutes | The previous "not admitted" verdict is cached | Wait for the cache TTL (bounded by the token's `exp`) |

Related: [identity backend availability](identity-backend-availability.md),
[IdP metadata availability](idp-metadata-availability.md),
[identity provider revocation](identity-provider-revocation.md),
[identity and access deployment](../enterprise/IDENTITY-AND-ACCESS-DEPLOYMENT.md).
