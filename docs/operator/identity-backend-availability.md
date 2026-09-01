# Identity-backend availability (LDAP / OIDC / JWKS)

*Relevant to any node with an external identity backend configured: the
legacy LDAP directory or OIDC token-introspection providers
(`auth.ldap`/`auth.oidc` in `config.yaml`), an ADR-0027 LDAP profile, or an
OIDC registry profile (Authorization Code + PKCE, `auth_oidc_flow.go`). The
`/api/diagnostics` rows and `/metrics` series below are always present (they
report `ok`/`0` when nothing is wrong or nothing is configured); the alert
only ever fires when a real backend outage is detected.*

Culvert authenticates on every proxied/admin request against whichever
identity backend is configured, so a directory or IdP outage is not a rare
event to plan for once — it is ordinary operational reality every gateway
eventually hits. This page is what to do when that happens.

---

## The two failure classes, and why they are different

| Class | Example | What Culvert does | Cached? |
|---|---|---|---|
| **Authoritative answer** | Wrong password, inactive token, user not in the required group | Denies this request | Yes — 5 min (LDAP) / 2 min (OIDC), so the same bad credential is not re-checked every request |
| **Infrastructure failure** | TCP dial refused, STARTTLS error, service-account bind failure, introspection transport error, non-200 from the introspection endpoint | Denies this request (fail-closed — the posture never changes) | **No** — an infrastructure failure is never written into the cache |

The distinction matters because of what would happen if it were collapsed:
before this contract existed (CHAOS-47), a directory or IdP that was down for
even one second denied every user who authenticated during that second for
the **full cache TTL** afterward — on a per-request-auth gateway that is very
nearly the entire active user population, and it looked identical to a green
directory dashboard plus a spike in login failures (indistinguishable from a
brute-force attempt).

Not caching the infrastructure failure, on its own, would trade that bug for a
stampede: every request would pay a full dial/introspection timeout against a
backend that is already down. So each backend carries a **probe gate**: the
first infrastructure failure arms a 3-second cooldown during which requests
are denied *without* contacting the backend at all, and exactly one probe is
let through per cooldown window. **Recovery is driven by an observed
successful reach, never by elapsed time** — the moment one probe succeeds,
every waiting caller is released. In practice this means an outage that clears
in the time it takes to restart a directory service recovers within
**seconds**, not within the multi-minute cache TTL.

**There is nothing to do when this self-heals.** Once a backend answers again,
authentication resumes immediately for everyone — the gate does not need to be
reset, and no cached denial needs to expire.

---

## Where it shows up

**`GET /api/diagnostics`** (viewer role) carries two relevant rows:

- **`identity_backend`** — reachability of the LDAP directory / OIDC
  introspection backend currently in use. `ok` if no outage has been observed
  since startup; `fail` while a backend is presently unreachable (proxy
  authentication is failing closed); `warn` if an earlier outage has since
  recovered. The `fail`/`warn` messages carry the outage count and the number
  of requests denied without a probe (`GatedDenials`) — the outage's blast
  radius. The backend **name** and counts are shown; the underlying cause text
  (the LDAP URL, the introspection host) is deliberately withheld from this
  viewer-role surface and goes only to the process log and the alert payload.
- **`oidc_jwks_trust`** — see [JWKS stale-trust ceiling](#the-jwks-stale-trust-ceiling-oidc-only)
  below. `ok` unless a registry OIDC provider's key set is past its 24-hour
  ceiling.

Both rows are memory-only reads — checking them issues no probe of its own.

**`GET /metrics`** — always present (unlike some other health series in this
codebase, these are not gated on a backend being configured; they simply stay
at `0` when there is nothing to report):

| Series | Meaning |
|---|---|
| `culvert_auth_backend_unavailable_total` | Cumulative count of DETECTED unreachable outcomes (one per failed probe — not one per denied request; the gate suppresses the rest) |
| `culvert_auth_backend_unavailable` | `1` while at least one backend is currently gated (cooldown active); cleared only by an observed successful reach |
| `culvert_auth_backend_gated_denials_total` | Requests denied during a cooldown *without* contacting the backend — the outage's blast radius |

There is currently **no dedicated metric** for the JWKS stale-trust ceiling
below — it surfaces only via the `oidc_jwks_trust` diagnostics row and the
rate-limited log line. If you page on identity-backend metrics, the
diagnostics endpoint is the only automatable signal for that specific
condition today.

**Alert** — `identity_backend_unreachable`, rate-limited to at most one
delivery per backend per 5 minutes (a down directory fails *every*
authentication, so an ungated alert would fire once per request). Subscribe to
it in the webhook editor: *"External identity backend unreachable"*. A
webhook configured under the retired name `idp_unreachable` still receives
this alert — the rename is carried forward automatically.

### Suggested paging rule

```
culvert_auth_backend_unavailable == 1
```

The gauge stays `0` on a node with no identity backend configured (or one
that has never seen an outage), so this never fires on an appliance using
local auth only.

---

## Identifying which backend is affected

The backend name shown in the diagnostics row, the alert `Source` field, and
the log line follows this convention:

| Name | Backend |
|---|---|
| `ldap` | The legacy boolean-YAML LDAP provider (`auth_ldap.go`) |
| `ldap:<profile-id>` | An ADR-0027 first-class LDAP IdP profile |
| `oidc` | The legacy RFC 7662 token-introspection provider (`auth_oidc.go`) |
| `oidc:<profile-id>` | An OIDC registry profile (Authorization Code + PKCE, `auth_oidc_flow.go`) |

A multi-profile estate can have several backends gated independently — each
carries its own cooldown, so one down LDAP profile does not block a healthy
OIDC profile (or vice versa). The diagnostics row and the `/metrics` gauge
aggregate across all of them; check the process log for the specific
backend name if more than one identity source is configured.

---

## Reading the logs

The unavailable line is rate-limited to at most once per backend per 5
minutes:

```
Auth: identity backend "ldap:corp" UNREACHABLE (3 since boot) — authentication is failing closed and the result is NOT cached: "dial tcp 10.0.4.12:636: connect: connection refused"
```

A 4xx from an OIDC introspection endpoint is a client/token problem, not an
outage, and is logged distinctly — it does not arm the cooldown and clears any
cooldown a prior *real* outage armed:

```
OIDC[corp-okta] auth DENY (introspection 4xx) — client/token error, not a backend outage; the endpoint answered, so any cooldown is cleared
```

---

## The JWKS stale-trust ceiling (OIDC registry providers only)

Every OIDC registry provider caches its IdP's JWKS signing-key document (15
minute TTL, refreshed at most once per minute) so that verifying an ID token
does not cost a fetch per request. If the JWKS endpoint becomes unreachable,
Culvert keeps serving the **last known-good key set** for up to **24 hours**
past its last successful fetch — a deliberate availability trade, since
withdrawing a signing key from the JWKS document is the IdP's only way to
revoke an already-minted token, so trusting a stale key set forever would let
a revoked token keep authenticating indefinitely.

**Past that 24-hour ceiling, ID-token validation starts failing CLOSED** for
that provider — logins via it fail until the JWKS endpoint answers again. This
is reported on the `oidc_jwks_trust` diagnostics row and via a rate-limited
log line:

```
OIDC: JWKS for "https://idp.example.com/.well-known/jwks.json" has been unrefreshable for 24h6m0s (ceiling 24h0m0s) — FAILING ID-token validation CLOSED. A signing key withdrawn at the IdP could otherwise keep authenticating here. Restore reachability to the JWKS endpoint.
```

**Recovery is automatic and immediate** on the next successful fetch — no
operator action beyond restoring reachability to the JWKS endpoint (DNS,
route, firewall, TLS). There is no override for the 24-hour ceiling; it is a
fixed security bound, not an operator-tunable.

---

## What NOT to do

- **Do not restart the node to "fix" a gated identity backend.** The gate
  self-heals on the first successful reach; a restart does not speed recovery
  and discards nothing that needed discarding.
- **Do not treat a `warn`-state `identity_backend` row as still broken.** `warn`
  means the outage has already ended — it is a record of what happened, not a
  live condition. Only `fail` means authentication is presently failing
  closed.
- **Do not confuse this with a brute-force spike.** Both surface as a rise in
  authentication failures; the `identity_backend`/`oidc_jwks_trust` rows and
  the `identity_backend_unreachable` alert exist specifically so the two are
  no longer indistinguishable — check them first.

---

## See also

- `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-03.md` — the CHAOS-47
  finding (legacy LDAP/OIDC backend availability)
- `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-11.md` — the CHAOS-49
  finding (OIDC registry availability + JWKS integrity)
- `docs/engineering/security-reviews/2026-08-18-mcp-pr12-and-idp-registry-window.md` —
  the SEC-JWKS-1 stale-trust ceiling
- `docs/operator/ldap-identity-provider.md` — configuring an ADR-0027 LDAP IdP
  profile
- `auth_backend_health.go`, `auth_oidc_flow.go` — implementation
