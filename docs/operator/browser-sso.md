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
authenticate a user's ordinary proxied traffic.** Proxy authentication for
general traffic uses a credential-capable provider (local users, LDAP, OIDC
token introspection via `Proxy-Authorization`).

Tracked as F-SSO-SCOPE-1 (#1528). A defined browser-to-proxy identity transport
is being added as an opt-in; this section will document it when it lands.
