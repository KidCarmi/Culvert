# Identity & Access Deployment

How to deploy authentication, authorization, and administrator recovery — and where the enterprise gates are.

> **Enterprise-readiness verdict:** **Not enterprise-ready for identity without compensating controls.** Administrator recovery is not achievable through any SSH-free, file-edit-free, source-free path; the only recovery is the host CLI `--reset-password`. Provisioning ≥2 admins and retaining container-exec access are mandatory operational compensations that the product neither enforces nor documents. Proxy-user authentication (LDAP/OIDC/SAML) is solid and fail-closed.

---

## 1. The load-bearing architectural fact

**The admin UI/API authenticates LOCAL bcrypt accounts only. External IdPs (LDAP/OIDC/SAML) authenticate PROXY end-users, never admin operators.**

- Admin login → `VerifyUIUser` (local bcrypt) only; admin cookie `ps_ui_session` (`ui_auth.go:65,114`).
- IdP callbacks → proxy cookie `ps_session` (`session.go:119`); they never issue an admin session.

Consequences:
- **An IdP outage does not lock admins out of the admin UI** (fail-safe for that scenario).
- **There is no admin SSO** and **no IdP-group→admin-role mapping** (GAP-IAM-02). Admin RBAC is provisioned locally and lives outside the IdP lifecycle.

---

## 2. Local authentication (admin)

- First admin via the setup wizard; further admins/roles via `GET/POST/DELETE /api/auth/users` (admin-only). Roles: admin / operator / viewer, enforced by `requireRole` plus the C2 metadata middleware.
- Passwords: complexity-enforced, bcrypt at rest in `/data/ui_users.json` (0600). TOTP 2FA available with backup codes.
- **Last-admin protection:** the API refuses to delete the final admin (`DeleteUIUser`, `store.go:693-710`).
- **Brute-force lockout:** IP + user lockout after 5 failures (15-min cooldown) + a 20-failure account-wide tier. Lockout state is **in-memory** — a process restart clears it. A previously-successful login IP is trusted for 30 days and bypasses the tier-2 account lock.

## 3. Proxy-user authentication (LDAP / OIDC / SAML)

Configure via admin UI → IdP profiles (persisted to `idp_profiles.json`). Multi-IdP with email-domain routing is supported.

| Provider | Misconfig / outage behaviour | Evidence |
|---|---|---|
| LDAP/AD | **Fail-closed** — dial/bind/search error ⇒ auth denied | `auth_ldap.go:132-180` |
| OIDC introspection (RFC 7662) | **Fail-closed** — any HTTP/parse error or `active:false` ⇒ denied | `auth_oidc.go:145-176` |
| OIDC Auth-Code + PKCE | **Fail-closed** — discovery/token/state errors ⇒ denied | `auth_oidc_flow.go` |
| SAML 2.0 SP | **Fail-closed** — invalid metadata ⇒ profile excluded from the live registry; signature/conditions/replay enforced; IdP-initiated disabled | `auth_saml.go:45-88`, `auth_idp.go:159-165` |

**Before enabling production OIDC/SAML:** set `proxy.base_url` to the externally reachable UI URL. For SAML this is the SP Entity ID / Audience; the ACS URL is `base_url + /auth/saml/callback`. In a cluster, give the login callback paths load-balancer affinity (SAML RelayState / OIDC PKCE state are node-local).

**What happens when it breaks:**
- *LDAP misconfigured* → proxy users fail auth (closed); admins are unaffected (local). Fix the profile and re-test with the built-in test action.
- *SAML metadata invalid* → the profile never goes live; other IdPs and local admin login keep working; the error is logged.
- *IdP down* → new proxy-user logins fail; existing signed sessions keep validating (cluster-synced HMAC); admin UI is unaffected.

## 4. Authorization / PBAC (proxy policy)

Proxy authorization is the policy engine (see [POLICY-ROLLOUT-GUIDE.md](POLICY-ROLLOUT-GUIDE.md)). IdP **group membership** and **auth source** are first-class match dimensions (`SourceGroup`, `AuthSource`), so least-privilege egress policy *can* be driven by IdP groups — this is the correct place to express "only the finance AD group may reach X." Admin RBAC is separate and local.

## 5. Administrator recovery / break-glass — the critical gap

**There is no in-band (GUI/API/network) administrator recovery.** The only supported recovery from a lost sole-admin password is the host CLI one-shot:

```bash
# On the host, with the stack up or down:
docker compose run --rm proxy --reset-password admin:NewStr0ngPass
#   or, against a running container:
docker exec culvert ./culvert --reset-password admin:NewStr0ngPass --ui-users-file /data/ui_users.json
```

This rewrites `ui_users.json` and exits (`main.go:381-404`). It requires host/container shell access — exactly what a no-SSH model forbids.

**There is no:** default/emergency credential, email/SMS reset, in-band reset endpoint, or IdP-based admin recovery.

**Mandatory compensating controls (adopt these at go-live):**
1. **Always provision ≥2 admin accounts.** A second admin recovers the first with no shell.
2. **Retain container-exec access** (or a break-glass jump host) for `--reset-password`.
3. **Keep a current encrypted `/data` backup** (contains `ui_users.json`).
4. If lockout (not password loss) is the issue: **restart the process** to clear in-memory locks, or wait out the 15-min cooldown; a trusted-IP admin can bypass the account-wide tier.

See [OPERATIONS-RUNBOOK.md](OPERATIONS-RUNBOOK.md) §Administrator recovery for the step-by-step runbook.

## 6. Auditability

Every admin action is audited (`auth.login[.fail]`, `auth.totp.fail`, `auth.lockout[.clear]`, `auth.users.set/delete`, `auth.password_change`, `setup.complete`, `idp.*`), enriched with the authenticated actor and real client IP. Storage: a 500-entry in-memory ring plus **optional** append-only JSONL (`-audit-log`, which the shipped compose sets). The admin API surfaces the ring and, with `?source=file`, the full JSONL. Audit events also forward to syslog/SIEM in real time when syslog is configured. **Enable persistent audit** for any deployment with compliance requirements (GAP-IAM-04).

## 7. Fail-open / fail-closed summary

| Scenario | Behaviour | Posture |
|---|---|---|
| Proxy IdP misconfigured/down | Proxy-user auth denied | Fail-closed ✅ |
| Admin IdP down | N/A — admin is local | Independent ✅ |
| Sole admin password lost | Unrecoverable without host shell | **Availability risk** ⚠ (GAP-IAM-01) |
| Brute-force lockout | Cleared by restart / 15-min cooldown / trusted-IP bypass | Self-healing ✅ |
| Fresh install, no policy | Passthrough (allow) until a rule or `default_action: deny` | Explicit hardening required ⚠ |

## 8. Deployment checklist

- [ ] First admin created; **second admin created**; TOTP enabled.
- [ ] `-audit-log` confirmed active; syslog/SIEM forwarding configured.
- [ ] `proxy.base_url` set before enabling OIDC/SAML.
- [ ] Each proxy IdP profile tested (built-in test action) and confirmed fail-closed.
- [ ] Break-glass documented: host-exec access retained, `--reset-password` procedure in the runbook, `/data` backup current.
- [ ] Least-privilege egress policy expressed via IdP groups where required.
