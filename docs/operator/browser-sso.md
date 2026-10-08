# Browser SSO (OIDC / SAML) — sign-in flow, requirements and scope

**Applies to:** deployments with an interactive identity provider (OIDC or
SAML) enabled under Settings → Identity Providers.

---

## Requirement: `proxy.base_url`

Every browser sign-in starts on the **admin UI host**, at
`<proxy.base_url>/auth/select`. When the proxy challenges an unauthenticated
browser (captive portal, or a rule that requires SSO), it redirects there.

Set `proxy.base_url` (Settings → Network) to the URL browsers use to reach the
admin UI, e.g. `https://culvert.corp.example:9090`. Without it there is no
admin-UI origin to send the browser to — the request's own host is the site
the user was trying to visit — so the redirect is **withheld**: the browser
gets the ordinary proxy challenge (407), or a 403 for a rule that requires SSO,
and the log says why (rate-limited):

```
WARN SSO captive redirect withheld: proxy.base_url is not set ...
```

Before this change the redirect was still sent without `base_url`, but to an
address on the destination site, where the login could never complete.

## The sign-in flow

1. `/auth/select` sets a short-lived **login-binding cookie** and records its
   hash in the login state it mints. With one eligible provider it continues
   straight to the IdP; with several it shows the selection page. The cookie
   is HttpOnly, SameSite=Lax, `Path=/`, host-only:
   - admin UI on **HTTPS**: `__Host-ps_login_bind` (Secure). Only this name is
     accepted, and a browser accepts a `__Host-` cookie only from the UI host
     itself over HTTPS — so a sibling subdomain or a plain-HTTP origin cannot
     plant one.
   - admin UI on **plain HTTP**: `ps_login_bind`. Anyone who can set cookies
     for the UI host (a sibling subdomain, or a network position on HTTP) can
     plant their own binding and defeat it. **Run the admin UI on HTTPS** for
     this protection. HTTPS is detected from the connection, or from
     `X-Forwarded-Proto: https` set by a TLS-terminating reverse proxy.
2. **OIDC:** the IdP returns to `/auth/oidc/callback`. The callback refuses a
   browser that does not hold the binding cookie of the browser that started
   the login — before the authorization code is redeemed.
3. **SAML:** the IdP posts to `/auth/saml/callback` (the ACS; unchanged in SP
   metadata — no IdP-side change). The ACS validates the signed assertion,
   then sends the browser to `/auth/saml/complete`, which checks the binding
   cookie before issuing the session. (The ACS cannot check it itself: the
   IdP's cross-site POST does not carry a SameSite=Lax cookie, and
   SameSite=None would need HTTPS on the admin UI.)

A login started in one browser can therefore never be completed in another.

**Post-login destination.** The proxy's redirect carries the page the user was
trying to reach, **signed** by the appliance (15-minute expiry). `/auth/select`
honours only a signed destination; a hand-made link such as
`/auth/select?relay=https://elsewhere.example` signs in and lands on the admin
UI root instead. Without this, the sign-in page would be a zero-click open
redirect starting from the trusted UI host.

**Path prefix.** If `proxy.base_url` carries a path (`https://host/culvert`
behind a prefix-stripping reverse proxy), the SAML hop to `/auth/saml/complete`
stays under that prefix.

**Two tabs.** If two sign-in pages open at the same moment in a browser that has
no binding cookie yet, each sets its own value and the last one wins; the other
tab's login is refused (403, "start again"). Starting again works.
This closes **login CSRF**, where an attacker who begins a login with their own
IdP account makes a victim's browser finish it, so the victim ends up signed in
as the attacker.

Symptom if the binding is missing (cookies blocked for the admin UI host, or
more than 10 minutes between sign-in and the IdP's response): *"login was not
started by this browser — start again from the sign-in page"* (403). Start
again from the sign-in page.

## Scope: what a browser SSO session authenticates

The session cookie is set on the admin UI host. A browser presents it only on
requests to that host — never on requests to other sites, and never inside an
HTTPS (CONNECT) tunnel. **On its own, a browser SSO sign-in therefore does not
authenticate a user's ordinary proxied traffic** (F-SSO-SCOPE-1, #1528). Proxy
authentication for general traffic uses a credential-capable provider (local
users, LDAP, OIDC token introspection via `Proxy-Authorization`), or IP-bound
sign-in below.

### IP-bound sign-in (opt-in, off by default)

Settings → Identity Providers → **IP-bound sign-in**
(`GET/PUT /api/sso-ip-binding`, bindings at `/api/sso-ip-binding/bindings`).

When enabled, a **completed** interactive sign-in (OIDC or SAML, after the
browser-binding check above) binds the client address the admin UI saw to the
signed-in identity for the binding lifetime (default 60 minutes, 5–1440). The
proxy then attributes requests from that address to that identity — groups
included, so group-scoped policy rules apply — for every request that presents
no credential of its own.

**The trade-off is the address itself.** Everyone behind one address — a NAT
gateway, a terminal server, a shared jump host, a VPN concentrator that does
not preserve client addresses — becomes the same user. Before enabling:

- list those ranges under **Never bind these sources**; their logins are not
  bound, and the proxy does not send their browsers to sign in (they get the
  challenge with an explanation, not a sign-in loop);
- make sure the admin UI sees real client addresses: behind a reverse proxy,
  configure it as a trusted proxy so `X-Forwarded-For` is honoured, or every
  login binds the reverse proxy's address.

- the admin UI host and the IdP must be reached **directly**, not through the
  proxy (PAC/bypass list) — a sign-in that arrives from the appliance's own
  address identifies no browser and is not bound;
- the trusted-proxy ranges become part of identity: a host inside a trusted
  range talking to the admin UI directly can name the address bound to its
  sign-in through `X-Forwarded-For`. Keep that list to the reverse proxies
  themselves.

Rules:

| | |
|---|---|
| What a binding is | Evidence of an earlier browser sign-in on that address — weaker than a credential on the request. |
| Presented credentials | Always win. A wrong `Proxy-Authorization` from a bound address is refused. |
| CredentialRequired rules | Never satisfied by a binding — they demand a credential on the request itself. |
| SSORequired rules | Satisfied only when the sign-in came from one of the rule's `providerRefs` (any provider when none are listed). |
| Policy and logs | Attributed requests carry the user and groups, with auth source **`sso-ip:<provider>`** (not `<provider>`): logs and SIEM show the identity was inferred from an address, and a rule scoped to `authSource: <provider>` does not accept it. |
| Same address, another user | The newest sign-in wins and takes the address over — counted as `rebound` and logged as a WARN naming both users. On a NAT or shared host that is the signal to exclude the address. A re-leased DHCP address works the same way: the next device to sign in on it takes it over. Until then, a device that receives a departed user's address is attributed to that user for the rest of the lifetime — keep the lifetime short on networks with fast address reuse. |
| Lifetime | The configured lifetime, never longer than the sign-in session (8 h by default), so a binding cannot outlive what sign-out revokes. |
| Sign-out | `POST /auth/logout` removes **every** binding of that user (provider + subject). |
| IdP disabled or deleted | Its bindings stop counting immediately. |
| Settings change | Bindings inside a newly excluded range are removed and every expiry is shortened to a newly lowered lifetime. |
| Turning it off | Takes effect immediately and removes every binding — even if saving the setting fails (the API then says it was not saved). Re-enabling starts from an empty table. |
| Own / loopback addresses | Never bound. |
| Capacity | 65,536 live bindings. A full table refuses new bindings; it never evicts a live one. |
| Restart | Bindings are volatile — users sign in again. |
| Cluster | Node-local: a binding exists on the node that served the sign-in (the `proxy.base_url` node). Traffic through another node is not identified by it. |
| SOCKS5 | Not consulted — SOCKS5 clients authenticate with their own credentials. |
| Persistence | Settings are saved in `admin_settings.json` on this node; they are not exported, rolled back or synced to data-plane nodes. |

A login that cannot be bound while the transport is on (excluded or loopback
address, full table) gets a page that says so, instead of a redirect back
into a challenge.

**With it off (the default)** the proxy does not redirect browsers to sign in
at all — a redirect could only end in a loop. Browsers get the ordinary
challenge (407), or a 403 for a rule that requires SSO, with a body that says
browser sign-in cannot authenticate the connection. When no credential-capable
provider exists at all (for example SAML only), the answer is a 403 rather
than a Basic prompt that could never succeed.

Evidence: `ui_sso_ip_binding_e2e_test.go` (real Chromium through Culvert's
proxy: sign-in, policy allow/deny by group, sign-out, transport off) and
`sso_surrogate_test.go`.

Metrics (enabled gauge always; the rest only while enabled):
`culvert_sso_ip_binding_{enabled,bindings,binds_total{outcome},hits_total}`.
