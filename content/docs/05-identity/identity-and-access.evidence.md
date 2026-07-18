# Claim-Evidence Ledger — "Identity & access"

Article: [`identity-and-access.md`](identity-and-access.md). Verified against repo
revision `ca60d83`.

| Claim | Type | Evidence |
|---|---|---|
| Local auth with bcrypt | src | `store.go:436` (`bcrypt.GenerateFromPassword`), verify `:497` |
| OIDC Auth-Code + PKCE (S256) and introspection (RFC 7662) | src | `auth_oidc_flow.go:386-387`; introspection `auth_oidc_flow.go:367-371` |
| SAML 2.0 SP (crewjam/saml) | src/test | `auth_saml.go:45`; `TestSAMLProvider_DisplayName` |
| LDAP/AD bind + search + single-group check | src | `auth_ldap.go:162` (`memberOf`), `:194-196` (`isMember`), `:42` (`RequiredGroup`) |
| Multi-IdP registry, email-domain routing | src/test | `auth_idp.go:487-501` (`RouteByDomain`), `:31` (`EmailDomains`); `TestIdPRegistry_RouteByDomain_NoMatch` |
| IdP API: list/create, OIDC discovery, item CRUD, groups | src | `ui_auth.go:950-952` |
| TOTP 2FA (RFC 6238) in-repo, stdlib only | src | `internal/totp/totp.go:1-15`, `VerifyTOTPReturnCounter :43` |
| TOTP step-up login flow (`totp_required`), 6-digit or backup code, replay-protected | src | `ui_auth.go:30-94` |
| Admin RBAC: admin / operator / viewer | src/test | `store.go:318-323`; enforcement `ui_policy.go:39,45`; `TestSlice8_ViewerAndOperatorWritesBlocked` |
| Two-layer RBAC (metadata middleware + per-handler `requireRole`) | src | `ui_metadata_enforcement.go`; `requireRole` in handlers |
| User mgmt routes: users (admin), change-password (any), lockouts (admin) | src | `ui_auth.go:945-947` |
| Session HMAC-SHA256, per-session `jti`, TTL 8h default, disk revocation | src | `internal/session/session.go:427,362,311,242-253` |
| Brute-force lockout: (IP,user) 5/15min; account-wide tier + trusted-IP bypass | src | `internal/lockout/lockout.go:42,49,25,44` |
| Password complexity 8+/mixed-case/digit | src | `store.go:644-663` |
| Session key + IdP secrets redacted to non-enrolled cluster nodes | src | `controlplane_server.go:91-100` |

## Notes

- The article scopes LDAP group handling honestly: membership is checked against
  one `RequiredGroup` DN, not a full group-list extraction — surfaced as a known
  limitation and consistent with the overview's identity row.
